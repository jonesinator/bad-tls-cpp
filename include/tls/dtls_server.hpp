/**
 * DTLS 1.2 server — RFC 6347.
 *
 * Provides dtls_server<Transport, RNG> that performs a full ECDHE
 * handshake over datagrams with cookie exchange and sends/receives
 * encrypted application data.
 *
 * Supports ECDSA and RSA server keys, and mutual DTLS.
 */

#pragma once

#include "dtls_connection.hpp"
#include "dtls_handshake.hpp"
#include "private_key.hpp"
#include "session_cache.hpp"
#include <crypto/ecdsa.hpp>
#include <crypto/hmac.hpp>
#include <crypto/rsa.hpp>
#include <crypto/random.hpp>
#include <asn1/der/codegen.hpp>
#include <x509/basic_constraints_verifier.hpp>
#include <x509/key_usage_verifier.hpp>
#include <x509/time_verifier.hpp>
#include <x509/trust_store.hpp>
#include <span>
#include <vector>

namespace tls {

struct dtls_server_config {
    std::span<const std::vector<uint8_t>> certificate_chain;
    tls_private_key private_key;
    NamedCurve private_key_curve = NamedCurve::secp256r1;

    std::array<CipherSuite, 4> cipher_suites = {
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    };
    size_t num_cipher_suites = 4;

    std::array<NamedCurve, 2> curves = {NamedCurve::secp256r1, NamedCurve::secp384r1};
    size_t num_curves = 2;

    const asn1::x509::trust_store* client_ca = nullptr;
    bool require_client_cert = false;

    // Cookie secret for HelloVerifyRequest HMAC
    std::array<uint8_t, 32> cookie_secret{};

    // ALPN protocol names (empty = don't negotiate ALPN) — RFC 7301
    std::span<const std::string_view> alpn_protocols;

    // Session resumption — pointer to external session cache (nullptr = no caching)
    session_cache* session_store = nullptr;
};

template <transport Transport, random_generator RNG>
class dtls_server {
    dtls_record_io<Transport> rio_;
    RNG& rng_;
    dtls_server_config config_;

    Random client_random_{};
    Random server_random_{};
    CipherSuite negotiated_suite_{};
    std::array<uint8_t, 48> master_secret_{};
    bool handshake_complete_ = false;
    bool client_authenticated_ = false;
    std::string negotiated_protocol_;
    uint16_t next_send_seq_ = 0;

public:
    dtls_server(Transport& t, RNG& rng, const dtls_server_config& cfg)
        : rio_(t, tls_role::server), rng_(rng), config_(cfg) {}

    // Handshake starting from the initial ClientHello datagram that was already
    // received by the listener. Pass it as initial_data.
    tls_result<void> handshake(std::span<const uint8_t> initial_data = {}) {
        // --- Phase 1: Receive initial ClientHello ---
        // If initial_data was provided (from listener), buffer it so recv_record can parse
        if (!initial_data.empty())
            rio_.buffer_initial_data(initial_data);

        auto first_res = rio_.recv_record();
        if (!first_res) return {first_res.error};
        auto first_rec = first_res.value;

        if (first_rec.type != ContentType::handshake)
            return {tls_error::unexpected_message};

        // Parse DTLS handshake header
        TlsReader ch1_r(std::span<const uint8_t>(
            first_rec.fragment.data.data(), first_rec.fragment.size()));
        auto ch1_dtls_hdr = read_dtls_handshake_header(ch1_r);
        if (ch1_dtls_hdr.type != HandshakeType::client_hello)
            return {tls_error::unexpected_message};

        auto ch1_body_data = ch1_r.read_bytes(ch1_dtls_hdr.fragment_length);
        TlsReader ch1_body_r(ch1_body_data);
        auto ch1 = read_dtls_client_hello(ch1_body_r);

        // --- Phase 2: Send HelloVerifyRequest with cookie ---
        // Generate cookie: HMAC-SHA256(cookie_secret, client_random)
        auto cookie_tag = hmac<sha256_state>(
            std::span<const uint8_t>(config_.cookie_secret),
            std::span<const uint8_t>(ch1.random));

        HelloVerifyRequest hvr;
        hvr.server_version = DTLS_1_2;
        for (size_t i = 0; i < 32; ++i)
            hvr.cookie.push_back(cookie_tag[i]);

        TlsWriter<256> hvr_w;
        write_hello_verify_request(hvr_w, 0, hvr);  // message_seq 0
        auto hvr_err = rio_.send_record(ContentType::handshake, hvr_w.data());
        if (!hvr_err) return {hvr_err.error};

        // --- Phase 3: Receive ClientHello with cookie ---
        // The client may retransmit the initial ClientHello (no cookie) before
        // sending the second one. Loop until we get a valid cookie.
        DtlsClientHello ch2{};
        std::vector<uint8_t> ch2_msg_storage;  // full DTLS handshake message (12-byte header + body)
        for (int attempts = 0; attempts < 30; ++attempts) {
            auto ch2_rec = rio_.recv_record();
            if (!ch2_rec) {
                if (ch2_rec.error == tls_error::transport_closed) continue;
                return {ch2_rec.error};
            }
            if (ch2_rec.value.type != ContentType::handshake) continue;

            auto frag_ptr = ch2_rec.value.fragment.data.data();
            auto frag_len = ch2_rec.value.fragment.size();
            TlsReader ch2_r(std::span<const uint8_t>(frag_ptr, frag_len));
            auto ch2_dtls_hdr = read_dtls_handshake_header(ch2_r);
            if (ch2_dtls_hdr.type != HandshakeType::client_hello) continue;

            auto ch2_body_data = ch2_r.read_bytes(ch2_dtls_hdr.fragment_length);
            TlsReader ch2_body_r(ch2_body_data);
            ch2 = read_dtls_client_hello(ch2_body_r);
            // Save the full DTLS handshake message (12-byte header + body)
            ch2_msg_storage.assign(frag_ptr, frag_ptr + DTLS_HANDSHAKE_HEADER_LENGTH + ch2_dtls_hdr.fragment_length);

            auto expected_cookie = hmac<sha256_state>(
                std::span<const uint8_t>(config_.cookie_secret),
                std::span<const uint8_t>(ch2.random));
            if (ch2.cookie.size() == 32) {
                bool ok = true;
                for (size_t i = 0; i < 32; ++i)
                    if (ch2.cookie[i] != expected_cookie[i]) { ok = false; break; }
                if (ok) break;
            }
            // Retransmit — re-send HVR
            rio_.send_record(ContentType::handshake, hvr_w.data());
        }
        if (ch2.cookie.size() != 32) return {tls_error::handshake_failure};

        client_random_ = ch2.random;

        // Per RFC 6347 Section 4.2.1, the server's handshake message numbering
        // continues after the client's second ClientHello (message_seq=1).
        next_send_seq_ = 1;

        // Select cipher suite
        bool is_rsa_key = std::holds_alternative<rsa_private_key<rsa_num>>(config_.private_key);
        bool suite_found = false;
        for (size_t i = 0; i < config_.num_cipher_suites && !suite_found; ++i) {
            auto suite = config_.cipher_suites[i];
            bool suite_is_rsa = (suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
                                 suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
            if (suite_is_rsa != is_rsa_key) continue;
            for (size_t j = 0; j < ch2.cipher_suites.size(); ++j) {
                if (suite == ch2.cipher_suites[j]) {
                    negotiated_suite_ = suite;
                    suite_found = true;
                    break;
                }
            }
        }
        if (!suite_found) return {tls_error::handshake_failure};

        // Parse ClientHello extensions for ALPN (RFC 7301)
        if (!config_.alpn_protocols.empty() && ch2.extensions.size() > 0) {
            TlsReader ext_r(std::span<const uint8_t>(
                ch2.extensions.data.data(), ch2.extensions.len));
            while (ext_r.remaining() >= 4) {
                uint16_t ext_type = ext_r.read_u16();
                uint16_t ext_len = ext_r.read_u16();
                if (ext_type == static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation) && ext_len >= 2) {
                    auto alpn_data = ext_r.read_bytes(ext_len);
                    TlsReader alpn_r(alpn_data);
                    uint16_t list_len = alpn_r.read_u16();
                    size_t consumed = 0;
                    while (consumed < list_len && alpn_r.remaining() > 0) {
                        uint8_t name_len = alpn_r.read_u8();
                        consumed += 1 + name_len;
                        if (name_len == 0 || name_len > alpn_r.remaining()) break;
                        auto name_bytes = alpn_r.read_bytes(name_len);
                        std::string_view client_proto(
                            reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());
                        for (size_t k = 0; k < config_.alpn_protocols.size(); ++k) {
                            if (config_.alpn_protocols[k] == client_proto) {
                                negotiated_protocol_ = std::string(client_proto);
                                goto dtls_alpn_done;
                            }
                        }
                    }
                    // Client sent ALPN but no match — fatal error per RFC 7301
                    return {tls_error::handshake_failure};
                } else {
                    if (ext_len > 0) ext_r.read_bytes(ext_len);
                }
            }
        }
        dtls_alpn_done:

        // Check for session resumption (RFC 5246 Section 7.4.1.2)
        if (config_.session_store && ch2.session_id.length > 0) {
            auto* cached = config_.session_store->find(ch2.session_id);
            if (cached) {
                // Verify client still offers the cached cipher suite
                bool cached_suite_ok = false;
                for (size_t j = 0; j < ch2.cipher_suites.size(); ++j) {
                    if (cached->cipher_suite == ch2.cipher_suites[j]) {
                        cached_suite_ok = true;
                        break;
                    }
                }
                if (cached_suite_ok) {
                    negotiated_suite_ = cached->cipher_suite;
                    return dispatch_cipher_suite(negotiated_suite_, [&]<typename Traits>() {
                        return handshake_abbreviated<Traits>(
                            std::span<const uint8_t>(ch2_msg_storage), *cached);
                    });
                }
            }
        }

        // Build transcript with full DTLS ClientHello message (12-byte header + body)
        return dispatch_cipher_suite(negotiated_suite_, [&]<typename Traits>() {
            return handshake_continue<Traits>(
                std::span<const uint8_t>(ch2_msg_storage));
        });
    }

    tls_result<size_t> send(std::span<const uint8_t> data) {
        if (!handshake_complete_) return {{}, tls_error::internal_error};
        size_t sent = 0;
        while (sent < data.size()) {
            size_t chunk = data.size() - sent;
            if (chunk > MAX_PLAINTEXT_LENGTH) chunk = MAX_PLAINTEXT_LENGTH;
            auto err = rio_.send_record(ContentType::application_data, data.subspan(sent, chunk));
            if (!err) return {{}, err.error};
            sent += chunk;
        }
        return {sent, tls_error::ok};
    }

    tls_result<size_t> recv(std::span<uint8_t> buf) {
        if (!handshake_complete_) return {{}, tls_error::internal_error};
        auto rec = rio_.recv_record();
        if (!rec) return {{}, rec.error};
        if (rec.value.type == ContentType::alert)
            return {{}, tls_error::transport_closed};
        if (rec.value.type != ContentType::application_data)
            return {{}, tls_error::unexpected_message};
        size_t n = buf.size() < rec.value.fragment.size() ? buf.size() : rec.value.fragment.size();
        for (size_t i = 0; i < n; ++i)
            buf[i] = rec.value.fragment[i];
        return {n, tls_error::ok};
    }

    tls_result<void> close() {
        std::array<uint8_t, 2> alert = {
            static_cast<uint8_t>(AlertLevel::warning),
            static_cast<uint8_t>(AlertDescription::close_notify)};
        return rio_.send_record(ContentType::alert, alert);
    }

    bool is_connected() const { return handshake_complete_; }
    bool client_authenticated() const { return client_authenticated_; }
    CipherSuite negotiated_suite() const { return negotiated_suite_; }
    std::string_view negotiated_protocol() const { return negotiated_protocol_; }

private:
    template <typename Num>
    static asn1::der::Integer num_to_integer(const Num& n) {
        auto bytes = n.to_bytes(std::endian::big);
        size_t start = 0;
        while (start < bytes.size() - 1 && bytes[start] == 0) ++start;
        asn1::der::Integer result;
        if (bytes[start] & 0x80) result.bytes.push_back(0x00);
        result.bytes.insert(result.bytes.end(), bytes.begin() + start, bytes.end());
        return result;
    }

    template <typename TCurve>
    static std::vector<uint8_t> encode_ecdsa_signature(const ecdsa_signature<TCurve>& sig) {
        asn1::der::Type<detail::EccMod, "ECDSA-Sig-Value"> der_sig;
        der_sig.template get<"r">() = num_to_integer(sig.r);
        der_sig.template get<"s">() = num_to_integer(sig.s);
        asn1::der::Writer w;
        asn1::der::encode<detail::EccMod, detail::EccMod.find_type("ECDSA-Sig-Value")>(w, der_sig);
        return std::move(w).finish();
    }

    template <typename TCurve, random_generator R>
    static auto generate_ecdhe_keypair(R& rng) {
        using num = typename TCurve::number_type;
        auto priv = random_scalar<TCurve>(rng);
        auto kp = ecdh_keypair_from_private<TCurve>(priv);

        constexpr size_t actual_coord_len = [] {
            if constexpr (std::is_same_v<TCurve, asn1::x509::p256_curve>) return size_t{32};
            else return size_t{48};
        }();

        asn1::FixedVector<uint8_t, 133> point_bytes;
        point_bytes.push_back(0x04);
        auto x_bytes = kp.public_key.x().value().to_bytes(std::endian::big);
        auto y_bytes = kp.public_key.y().value().to_bytes(std::endian::big);
        size_t x_off = x_bytes.size() - actual_coord_len;
        size_t y_off = y_bytes.size() - actual_coord_len;
        for (size_t i = 0; i < actual_coord_len; ++i)
            point_bytes.push_back(x_bytes[x_off + i]);
        for (size_t i = 0; i < actual_coord_len; ++i)
            point_bytes.push_back(y_bytes[y_off + i]);

        struct result { num private_key; asn1::FixedVector<uint8_t, 133> public_key_bytes; };
        return result{priv, point_bytes};
    }

    static auto build_ske_signed_data(
        const Random& client_random, const Random& server_random,
        NamedCurve curve, const asn1::FixedVector<uint8_t, 133>& ecdhe_pub)
    {
        std::array<uint8_t, 201> signed_data{};
        size_t pos = 0;
        for (size_t i = 0; i < 32; ++i) signed_data[pos++] = client_random[i];
        for (size_t i = 0; i < 32; ++i) signed_data[pos++] = server_random[i];
        signed_data[pos++] = static_cast<uint8_t>(ECCurveType::named_curve);
        signed_data[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(curve) >> 8);
        signed_data[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(curve));
        signed_data[pos++] = static_cast<uint8_t>(ecdhe_pub.size());
        for (size_t i = 0; i < ecdhe_pub.size(); ++i)
            signed_data[pos++] = ecdhe_pub[i];
        struct result { std::array<uint8_t, 201> data; size_t length; };
        return result{signed_data, pos};
    }

    template <typename TCurve, typename THash>
    ServerKeyExchangeEcdhe build_server_key_exchange_ecdsa(
        NamedCurve curve, const asn1::FixedVector<uint8_t, 133>& ecdhe_pub,
        const typename TCurve::number_type& signing_key)
    {
        ServerKeyExchangeEcdhe ske{};
        ske.named_curve = curve;
        ske.public_key = ecdhe_pub;
        auto [signed_data, pos] = build_ske_signed_data(client_random_, server_random_, curve, ecdhe_pub);
        auto data_span = std::span<const uint8_t>(signed_data.data(), pos);
        THash h; h.init(); h.update(data_span); auto hash = h.finalize();
        auto sig = ecdsa_sign<TCurve, THash>(signing_key, hash);
        auto der_sig = encode_ecdsa_signature(sig);
        if constexpr (THash::digest_size == 32)
            ske.sig_algorithm = {HashAlgorithm::sha256, SignatureAlgorithm::ecdsa};
        else
            ske.sig_algorithm = {HashAlgorithm::sha384, SignatureAlgorithm::ecdsa};
        for (auto b : der_sig) ske.signature.push_back(b);
        return ske;
    }

    template <typename THash>
    ServerKeyExchangeEcdhe build_server_key_exchange_rsa(
        NamedCurve curve, const asn1::FixedVector<uint8_t, 133>& ecdhe_pub,
        const rsa_private_key<asn1::x509::rsa_num>& signing_key)
    {
        ServerKeyExchangeEcdhe ske{};
        ske.named_curve = curve;
        ske.public_key = ecdhe_pub;
        auto [signed_data, pos] = build_ske_signed_data(client_random_, server_random_, curve, ecdhe_pub);
        auto data_span = std::span<const uint8_t>(signed_data.data(), pos);
        THash h; h.init(); h.update(data_span); auto hash = h.finalize();
        auto sig = rsa_pkcs1_v1_5_sign<asn1::x509::rsa_num, THash>(signing_key, hash);
        if constexpr (THash::digest_size == 32)
            ske.sig_algorithm = {HashAlgorithm::sha256, SignatureAlgorithm::rsa};
        else
            ske.sig_algorithm = {HashAlgorithm::sha384, SignatureAlgorithm::rsa};
        auto sig_bytes = sig.value.to_bytes(std::endian::big);
        size_t mod_bytes = (signing_key.n.bit_width() + 7) / 8;
        size_t offset = sig_bytes.size() - mod_bytes;
        for (size_t i = 0; i < mod_bytes; ++i)
            ske.signature.push_back(sig_bytes[offset + i]);
        return ske;
    }

    template <typename TCurve>
    tls_result<pre_master_secret> compute_server_ecdh(
        const typename TCurve::number_type& eph_priv,
        std::span<const uint8_t> client_point_bytes)
    {
        using fe = field_element<TCurve>;
        using num = typename TCurve::number_type;
        if (client_point_bytes.size() < 3 || client_point_bytes[0] != 0x04)
            return {{}, tls_error::invalid_server_key};
        size_t coord_len = (client_point_bytes.size() - 1) / 2;
        auto x = num::from_bytes(client_point_bytes.subspan(1, coord_len));
        auto y = num::from_bytes(client_point_bytes.subspan(1 + coord_len, coord_len));
        point<TCurve> client_point{fe{x}, fe{y}};
        if (!ecdh_validate_public_key(client_point))
            return {{}, tls_error::invalid_server_key};
        auto secret_opt = ecdh_raw_shared_secret<TCurve>(eph_priv, client_point);
        if (!secret_opt) return {{}, tls_error::internal_error};
        pre_master_secret pms{};
        auto secret_bytes = secret_opt->to_bytes(std::endian::big);
        pms.length = coord_len;
        size_t offset = secret_bytes.size() - coord_len;
        for (size_t i = 0; i < coord_len; ++i)
            pms.data[i] = secret_bytes[offset + i];
        return {pms, tls_error::ok};
    }

    // Helper to add a DTLS handshake message to transcript.
    // Hashes the full 12-byte DTLS handshake header + body, matching OpenSSL's
    // DTLS transcript computation.
    template <hash_function THash, size_t Cap>
    void transcript_add(TranscriptHash<THash>& transcript, TlsWriter<Cap>& dtls_w) {
        transcript.update(dtls_w.data());
    }

    template <typename Traits>
    tls_result<void> handshake_continue(
        std::span<const uint8_t> client_hello_msg)
    {
        using Hash = typename Traits::hash_type;

        TranscriptHash<Hash> transcript;

        // Add ClientHello to transcript — full DTLS handshake message
        // (12-byte DTLS header + body), matching OpenSSL's transcript.
        transcript.update(client_hello_msg);

        // --- Send ServerHello ---
        server_random_ = random_bytes<32>(rng_);

        // Generate session ID for caching (if cache configured)
        SessionId new_session_id{};
        if (config_.session_store) {
            new_session_id.data = random_bytes<32>(rng_);
            new_session_id.length = 32;
        }

        ServerHello sh{};
        sh.server_version = DTLS_1_2;
        sh.random = server_random_;
        sh.session_id = new_session_id;
        sh.cipher_suite = negotiated_suite_;
        sh.compression_method = CompressionMethod::null;

        // Build ServerHello extensions
        {
            TlsWriter<128> ext_w;
            size_t ext_list_pos = ext_w.position();
            ext_w.write_u16(0); // placeholder for total extensions length

            // renegotiation_info (RFC 5746)
            ext_w.write_u16(static_cast<uint16_t>(ExtensionType::renegotiation_info));
            ext_w.write_u16(1);
            ext_w.write_u8(0);

            // ALPN (RFC 7301) — echo selected protocol if negotiated
            if (!negotiated_protocol_.empty()) {
                ext_w.write_u16(static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation));
                uint16_t name_len = static_cast<uint16_t>(negotiated_protocol_.size());
                ext_w.write_u16(static_cast<uint16_t>(2 + 1 + name_len));
                ext_w.write_u16(static_cast<uint16_t>(1 + name_len));
                ext_w.write_u8(static_cast<uint8_t>(name_len));
                ext_w.write_bytes(std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(negotiated_protocol_.data()),
                    negotiated_protocol_.size()));
            }

            // Patch total extensions length
            uint16_t total = static_cast<uint16_t>(ext_w.position() - ext_list_pos - 2);
            ext_w.patch_u16(ext_list_pos, total);

            for (size_t i = 0; i < ext_w.size(); ++i)
                sh.extensions.push_back(ext_w.data()[i]);
        }

        TlsWriter<256> sh_w;
        write_dtls_server_hello(sh_w, next_send_seq_++, sh);
        transcript_add(transcript, sh_w);
        auto sh_err = rio_.send_record(ContentType::handshake, sh_w.data());
        if (!sh_err) return {sh_err.error};

        // --- Send Certificate ---
        CertificateMessage cert_msg{};
        for (auto& cert_der : config_.certificate_chain) {
            asn1::FixedVector<uint8_t, 8192> cert;
            for (auto b : cert_der) cert.push_back(b);
            cert_msg.certificate_list.push_back(cert);
        }

        TlsWriter<32768> cert_w;
        write_dtls_certificate(cert_w, next_send_seq_++, cert_msg);
        transcript_add(transcript, cert_w);
        auto cert_err = rio_.send_record(ContentType::handshake, cert_w.data());
        if (!cert_err) return {cert_err.error};

        // --- Send ServerKeyExchange ---
        bool is_rsa_key = std::holds_alternative<rsa_private_key<rsa_num>>(config_.private_key);
        NamedCurve ecdhe_curve = is_rsa_key ? NamedCurve::secp256r1 : config_.private_key_curve;

        ServerKeyExchangeEcdhe ske;
        std::variant<asn1::x509::p256_curve::number_type, asn1::x509::p384_curve::number_type> eph_priv;

        if (ecdhe_curve == NamedCurve::secp256r1) {
            auto kp = generate_ecdhe_keypair<asn1::x509::p256_curve>(rng_);
            eph_priv = kp.private_key;
            if (is_rsa_key) {
                auto* rsa_key = std::get_if<rsa_private_key<rsa_num>>(&config_.private_key);
                if (!rsa_key) return {tls_error::internal_error};
                ske = build_server_key_exchange_rsa<Hash>(ecdhe_curve, kp.public_key_bytes, *rsa_key);
            } else {
                auto* signing_key = std::get_if<asn1::x509::p256_curve::number_type>(&config_.private_key);
                if (!signing_key) return {tls_error::internal_error};
                ske = build_server_key_exchange_ecdsa<asn1::x509::p256_curve, Hash>(
                    ecdhe_curve, kp.public_key_bytes, *signing_key);
            }
        } else if (ecdhe_curve == NamedCurve::secp384r1) {
            auto kp = generate_ecdhe_keypair<asn1::x509::p384_curve>(rng_);
            eph_priv = kp.private_key;
            if (is_rsa_key) {
                auto* rsa_key = std::get_if<rsa_private_key<rsa_num>>(&config_.private_key);
                if (!rsa_key) return {tls_error::internal_error};
                ske = build_server_key_exchange_rsa<Hash>(ecdhe_curve, kp.public_key_bytes, *rsa_key);
            } else {
                auto* signing_key = std::get_if<asn1::x509::p384_curve::number_type>(&config_.private_key);
                if (!signing_key) return {tls_error::internal_error};
                ske = build_server_key_exchange_ecdsa<asn1::x509::p384_curve, Hash>(
                    ecdhe_curve, kp.public_key_bytes, *signing_key);
            }
        } else {
            return {tls_error::unsupported_curve};
        }

        TlsWriter<1024> ske_w;
        write_dtls_server_key_exchange(ske_w, next_send_seq_++, ske);
        transcript_add(transcript, ske_w);
        auto ske_err = rio_.send_record(ContentType::handshake, ske_w.data());
        if (!ske_err) return {ske_err.error};

        // --- Send CertificateRequest (if mTLS) ---
        bool cert_requested = false;
        if (config_.client_ca) {
            cert_requested = true;
            CertificateRequest cr{};
            cr.certificate_types.push_back(1);   // rsa_sign
            cr.certificate_types.push_back(64);  // ecdsa_sign
            cr.supported_signature_algorithms.push_back({HashAlgorithm::sha256, SignatureAlgorithm::rsa});
            cr.supported_signature_algorithms.push_back({HashAlgorithm::sha384, SignatureAlgorithm::rsa});
            cr.supported_signature_algorithms.push_back({HashAlgorithm::sha256, SignatureAlgorithm::ecdsa});
            cr.supported_signature_algorithms.push_back({HashAlgorithm::sha384, SignatureAlgorithm::ecdsa});

            TlsWriter<4096> cr_w;
            write_dtls_certificate_request(cr_w, next_send_seq_++, cr);
            transcript_add(transcript, cr_w);
            auto cr_err = rio_.send_record(ContentType::handshake, cr_w.data());
            if (!cr_err) return {cr_err.error};
        }

        // --- Send ServerHelloDone ---
        TlsWriter<64> shd_w;
        write_dtls_server_hello_done(shd_w, next_send_seq_++);
        transcript_add(transcript, shd_w);
        auto shd_err = rio_.send_record(ContentType::handshake, shd_w.data());
        if (!shd_err) return {shd_err.error};

        // --- Receive client messages ---
        dtls_handshake_reader<Transport> hs_reader(rio_);

        // If CertificateRequest was sent, expect client Certificate first
        asn1::x509::x509_public_key client_pub_key{};
        bool client_sent_cert = false;
        if (cert_requested) {
            auto ccert_msg = hs_reader.next_message(transcript);
            if (!ccert_msg) return {ccert_msg.error};
            auto [ccert_hdr, ccert_body] = ccert_msg.value;
            if (ccert_hdr.type != HandshakeType::certificate)
                return {tls_error::unexpected_message};

            TlsReader ccert_r(ccert_body);
            auto ccert = read_certificate(ccert_r);

            if (ccert.certificate_list.size() > 0) {
                client_sent_cert = true;
                std::vector<std::vector<uint8_t>> chain_der_vec;
                for (size_t ci = 0; ci < ccert.certificate_list.size(); ++ci) {
                    auto& c = ccert.certificate_list[ci];
                    chain_der_vec.emplace_back(c.data.data(), c.data.data() + c.len);
                }
                try {
                    asn1::x509::time_verifier tv{};
                    asn1::x509::key_usage_verifier kuv{};
                    asn1::x509::basic_constraints_verifier bcv{};
                    if (!asn1::x509::verify_chain(chain_der_vec, *config_.client_ca, tv, kuv, bcv))
                        return {tls_error::bad_certificate};
                } catch (...) {
                    return {tls_error::bad_certificate};
                }
                auto& leaf_der = ccert.certificate_list[0];
                auto leaf_cert = asn1::x509::parse_certificate(
                    std::span<const uint8_t>(leaf_der.data.data(), leaf_der.len));
                client_pub_key = asn1::x509::extract_public_key(leaf_cert);
            } else if (config_.require_client_cert) {
                return {tls_error::bad_certificate};
            }
        }

        // --- Receive ClientKeyExchange ---
        auto cke_msg = hs_reader.next_message(transcript);
        if (!cke_msg) return {cke_msg.error};
        auto [cke_hdr, cke_body] = cke_msg.value;
        if (cke_hdr.type != HandshakeType::client_key_exchange)
            return {tls_error::unexpected_message};

        TlsReader cke_r(cke_body);
        auto cke = read_client_key_exchange_ecdhe(cke_r);

        // Compute ECDH shared secret
        pre_master_secret pms{};
        if (ecdhe_curve == NamedCurve::secp256r1) {
            auto* priv = std::get_if<asn1::x509::p256_curve::number_type>(&eph_priv);
            auto pms_res = compute_server_ecdh<asn1::x509::p256_curve>(
                *priv, std::span<const uint8_t>(cke.public_key.data.data(), cke.public_key.len));
            if (!pms_res) return {pms_res.error};
            pms = pms_res.value;
        } else {
            auto* priv = std::get_if<asn1::x509::p384_curve::number_type>(&eph_priv);
            auto pms_res = compute_server_ecdh<asn1::x509::p384_curve>(
                *priv, std::span<const uint8_t>(cke.public_key.data.data(), cke.public_key.len));
            if (!pms_res) return {pms_res.error};
            pms = pms_res.value;
        }

        // --- Receive CertificateVerify (if client sent a cert) ---
        if (client_sent_cert) {
            auto pre_cv_hash = transcript.current_hash();
            auto cv_msg = hs_reader.next_message(transcript);
            if (!cv_msg) return {cv_msg.error};
            auto [cv_hdr, cv_body] = cv_msg.value;
            if (cv_hdr.type != HandshakeType::certificate_verify)
                return {tls_error::unexpected_message};

            TlsReader cv_r(cv_body);
            SignatureAndHashAlgorithm cv_alg;
            cv_alg.hash = static_cast<HashAlgorithm>(cv_r.read_u8());
            cv_alg.signature = static_cast<SignatureAlgorithm>(cv_r.read_u8());
            uint16_t sig_len = cv_r.read_u16();
            auto sig_data = cv_r.read_bytes(sig_len);

            bool sig_ok = false;
            if (cv_alg.signature == SignatureAlgorithm::ecdsa) {
                if (auto* key = std::get_if<point<asn1::x509::p256_curve>>(&client_pub_key)) {
                    auto sig = asn1::x509::detail::parse_ecdsa_signature<asn1::x509::p256_curve>(
                        std::span<const uint8_t>(sig_data.data(), sig_len));
                    sig_ok = ecdsa_verify<asn1::x509::p256_curve, Hash>(*key, pre_cv_hash, sig);
                } else if (auto* key = std::get_if<point<asn1::x509::p384_curve>>(&client_pub_key)) {
                    auto sig = asn1::x509::detail::parse_ecdsa_signature<asn1::x509::p384_curve>(
                        std::span<const uint8_t>(sig_data.data(), sig_len));
                    sig_ok = ecdsa_verify<asn1::x509::p384_curve, Hash>(*key, pre_cv_hash, sig);
                }
            } else if (cv_alg.signature == SignatureAlgorithm::rsa) {
                auto* key = std::get_if<rsa_public_key<asn1::x509::rsa_num>>(&client_pub_key);
                if (key) {
                    rsa_signature<asn1::x509::rsa_num> sig{
                        asn1::x509::rsa_num::from_bytes(std::span<const uint8_t>(sig_data.data(), sig_len))};
                    sig_ok = rsa_pkcs1_v1_5_verify<asn1::x509::rsa_num, Hash>(*key, pre_cv_hash, sig);
                }
            }
            if (!sig_ok) return {tls_error::signature_verification_failed};
            client_authenticated_ = true;
        }

        // --- Key derivation ---
        auto master = derive_master_secret<Hash>(
            std::span<const uint8_t>(pms.data.data(), pms.length),
            client_random_, server_random_);
        master_secret_ = master;
        auto params = get_cipher_suite_params(negotiated_suite_);
        auto kb = derive_key_block<Hash>(master, client_random_, server_random_, params);

        // --- Receive ChangeCipherSpec ---
        auto client_ccs = rio_.recv_record();
        if (!client_ccs) return {client_ccs.error};
        if (client_ccs.value.type != ContentType::change_cipher_spec)
            return {tls_error::unexpected_message};

        rio_.activate_read_cipher(kb, negotiated_suite_);

        // --- Receive client Finished ---
        auto expected_client_vd = compute_verify_data<Hash>(master, true, transcript.current_hash());

        auto cfin_rec = rio_.recv_record();
        if (!cfin_rec) return {cfin_rec.error};
        if (cfin_rec.value.type != ContentType::handshake)
            return {tls_error::unexpected_message};

        TlsReader cfin_r(std::span<const uint8_t>(
            cfin_rec.value.fragment.data.data(), cfin_rec.value.fragment.size()));
        auto cfin_dtls_hdr = read_dtls_handshake_header(cfin_r);
        if (cfin_dtls_hdr.type != HandshakeType::finished)
            return {tls_error::unexpected_message};
        auto client_fin = read_finished(cfin_r);

        if (client_fin.verify_data != expected_client_vd)
            return {tls_error::handshake_failure};

        // Add client Finished to transcript — full DTLS handshake message from the record
        transcript.update(std::span<const uint8_t>(
            cfin_rec.value.fragment.data.data(), cfin_rec.value.fragment.size()));

        // --- Send ChangeCipherSpec ---
        std::array<uint8_t, 1> ccs = {CHANGE_CIPHER_SPEC_MESSAGE};
        auto ccs_err = rio_.send_record(ContentType::change_cipher_spec, ccs);
        if (!ccs_err) return {ccs_err.error};

        rio_.activate_write_cipher(kb, negotiated_suite_);

        // --- Send server Finished ---
        auto server_vd = compute_verify_data<Hash>(master, false, transcript.current_hash());
        Finished server_fin{};
        server_fin.verify_data = server_vd;
        TlsWriter<64> fin_w;
        write_dtls_finished(fin_w, next_send_seq_++, server_fin);
        auto fin_err = rio_.send_record(ContentType::handshake, fin_w.data());
        if (!fin_err) return {fin_err.error};

        // Store session for future resumption
        if (config_.session_store && new_session_id.length > 0) {
            session_data sd;
            sd.session_id = new_session_id;
            sd.cipher_suite = negotiated_suite_;
            sd.master_secret = master_secret_;
            sd.negotiated_protocol = negotiated_protocol_;
            config_.session_store->store(sd);
        }

        handshake_complete_ = true;
        return {tls_error::ok};
    }

    // Abbreviated handshake for session resumption (RFC 5246 Section 7.4.1.2)
    // Server sends: ServerHello → CCS → Finished, then receives: CCS → Finished
    template <typename Traits>
    tls_result<void> handshake_abbreviated(
        std::span<const uint8_t> client_hello_msg,
        const session_data& cached)
    {
        using Hash = typename Traits::hash_type;

        TranscriptHash<Hash> transcript;
        transcript.update(client_hello_msg);

        // Reuse cached master secret
        master_secret_ = cached.master_secret;
        server_random_ = random_bytes<32>(rng_);

        // --- Send ServerHello echoing session_id ---
        ServerHello sh{};
        sh.server_version = DTLS_1_2;
        sh.random = server_random_;
        sh.session_id = cached.session_id;
        sh.cipher_suite = negotiated_suite_;
        sh.compression_method = CompressionMethod::null;

        // Build ServerHello extensions
        {
            TlsWriter<128> ext_w;
            size_t ext_list_pos = ext_w.position();
            ext_w.write_u16(0);

            ext_w.write_u16(static_cast<uint16_t>(ExtensionType::renegotiation_info));
            ext_w.write_u16(1);
            ext_w.write_u8(0);

            if (!cached.negotiated_protocol.empty()) {
                ext_w.write_u16(static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation));
                uint16_t name_len = static_cast<uint16_t>(cached.negotiated_protocol.size());
                ext_w.write_u16(static_cast<uint16_t>(2 + 1 + name_len));
                ext_w.write_u16(static_cast<uint16_t>(1 + name_len));
                ext_w.write_u8(static_cast<uint8_t>(name_len));
                ext_w.write_bytes(std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(cached.negotiated_protocol.data()),
                    cached.negotiated_protocol.size()));
            }

            uint16_t total = static_cast<uint16_t>(ext_w.position() - ext_list_pos - 2);
            ext_w.patch_u16(ext_list_pos, total);

            for (size_t i = 0; i < ext_w.size(); ++i)
                sh.extensions.push_back(ext_w.data()[i]);
        }

        TlsWriter<256> sh_w;
        write_dtls_server_hello(sh_w, next_send_seq_++, sh);
        transcript_add(transcript, sh_w);
        auto sh_err = rio_.send_record(ContentType::handshake, sh_w.data());
        if (!sh_err) return {sh_err.error};

        // Derive fresh key block with new randoms
        auto params = get_cipher_suite_params(negotiated_suite_);
        auto kb = derive_key_block<Hash>(master_secret_, client_random_, server_random_, params);

        // --- Send ChangeCipherSpec ---
        std::array<uint8_t, 1> ccs = {CHANGE_CIPHER_SPEC_MESSAGE};
        auto ccs_err = rio_.send_record(ContentType::change_cipher_spec, ccs);
        if (!ccs_err) return {ccs_err.error};

        rio_.activate_write_cipher(kb, negotiated_suite_);

        // --- Send server Finished (encrypted) ---
        auto server_vd = compute_verify_data<Hash>(master_secret_, false, transcript.current_hash());
        Finished server_fin{};
        server_fin.verify_data = server_vd;
        TlsWriter<64> fin_w;
        write_dtls_finished(fin_w, next_send_seq_++, server_fin);
        transcript_add(transcript, fin_w);
        auto fin_err = rio_.send_record(ContentType::handshake, fin_w.data());
        if (!fin_err) return {fin_err.error};

        // --- Receive client ChangeCipherSpec ---
        auto client_ccs = rio_.recv_record();
        if (!client_ccs) return {client_ccs.error};
        if (client_ccs.value.type != ContentType::change_cipher_spec)
            return {tls_error::unexpected_message};

        rio_.activate_read_cipher(kb, negotiated_suite_);

        // --- Receive client Finished (encrypted) ---
        auto expected_client_vd = compute_verify_data<Hash>(master_secret_, true, transcript.current_hash());

        auto cfin_rec = rio_.recv_record();
        if (!cfin_rec) return {cfin_rec.error};
        if (cfin_rec.value.type != ContentType::handshake)
            return {tls_error::unexpected_message};

        TlsReader cfin_r(std::span<const uint8_t>(
            cfin_rec.value.fragment.data.data(), cfin_rec.value.fragment.size()));
        auto cfin_dtls_hdr = read_dtls_handshake_header(cfin_r);
        if (cfin_dtls_hdr.type != HandshakeType::finished)
            return {tls_error::unexpected_message};
        auto client_fin = read_finished(cfin_r);

        if (client_fin.verify_data != expected_client_vd)
            return {tls_error::handshake_failure};

        negotiated_protocol_ = cached.negotiated_protocol;
        handshake_complete_ = true;
        return {tls_error::ok};
    }
};

} // namespace tls
