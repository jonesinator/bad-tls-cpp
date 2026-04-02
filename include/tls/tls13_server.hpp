/**
 * TLS 1.3 server — RFC 8446.
 *
 * Provides tls13_server<Transport, RNG> that performs a 1-RTT ECDHE
 * handshake and sends/receives encrypted application data.
 *
 * Supports three cipher suites:
 *   TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
 *   TLS_CHACHA20_POLY1305_SHA256
 *
 * Key exchange groups: x25519, secp256r1, secp384r1.
 * No PSK, 0-RTT, HelloRetryRequest, or client certificates.
 */

#pragma once

#include "tls13_connection.hpp"
#include "tls13_extensions.hpp"
#include "tls13_handshake.hpp"
#include "tls13_key_schedule.hpp"
#include "keylog.hpp"
#include "private_key.hpp"
#include <crypto/ecdh.hpp>
#include <crypto/ecdsa.hpp>
#include <crypto/random.hpp>
#include <crypto/rsa.hpp>
#include <crypto/x25519.hpp>
#include <asn1/der/codegen.hpp>
#include <span>
#include <vector>

namespace tls {

struct tls13_server_config {
    // Certificate chain DER bytes (leaf first)
    std::span<const std::vector<uint8_t>> certificate_chain;

    // Private key (EC or RSA)
    tls_private_key private_key;
    NamedCurve private_key_curve = NamedCurve::secp256r1;

    std::array<Tls13CipherSuite, 3> cipher_suites = {
        Tls13CipherSuite::TLS_AES_256_GCM_SHA384,
        Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        Tls13CipherSuite::TLS_AES_128_GCM_SHA256,
    };
    size_t num_cipher_suites = 3;

    // ALPN protocol names (empty = don't negotiate ALPN) — RFC 7301
    std::span<const std::string_view> alpn_protocols;
};

template <transport Transport, random_generator RNG>
class tls13_server {
    tls13_record_io<Transport> rio_;
    RNG& rng_;
    tls13_server_config config_;

    Random client_random_{};
    Tls13CipherSuite negotiated_suite_{};
    bool handshake_complete_ = false;
    std::string negotiated_protocol_;

public:
    tls13_server(Transport& t, RNG& rng, const tls13_server_config& cfg)
        : rio_(t), rng_(rng), config_(cfg) {}

    tls_result<void> handshake() {
        // Phase 1: Receive ClientHello
        auto ch_rec = rio_.recv_record();
        if (!ch_rec) return {ch_rec.error};
        if (ch_rec.value.content_type != ContentType::handshake)
            return {tls_error::unexpected_message};

        auto& ch_frag = ch_rec.value.fragment;
        TlsReader ch_r{std::span<const uint8_t>(ch_frag)};
        auto ch_hdr = read_handshake_header(ch_r);
        if (ch_hdr.type != HandshakeType::client_hello)
            return {tls_error::unexpected_message};

        size_t ch_msg_len = 4 + ch_hdr.length;

        auto ch_body = ch_r.read_bytes(ch_hdr.length);
        TlsReader ch_body_r(ch_body);
        auto client_hello = read_client_hello(ch_body_r);
        client_random_ = client_hello.random;

        // Parse TLS 1.3 extensions
        auto ext_13 = parse_client_hello_extensions_13(
            std::span<const uint8_t>(
                client_hello.extensions.data.data(), client_hello.extensions.len));

        if (!ext_13.has_supported_versions || !ext_13.offers_tls13)
            return {tls_error::handshake_failure};

        // Negotiate cipher suite (server preference)
        bool suite_found = false;
        for (size_t i = 0; i < config_.num_cipher_suites && !suite_found; ++i) {
            auto suite = config_.cipher_suites[i];
            auto suite_val = static_cast<CipherSuite>(static_cast<uint16_t>(suite));
            for (size_t j = 0; j < client_hello.cipher_suites.size(); ++j) {
                if (suite_val == client_hello.cipher_suites[j]) {
                    negotiated_suite_ = suite;
                    suite_found = true;
                    break;
                }
            }
        }
        if (!suite_found) return {tls_error::handshake_failure};

        // Find a client key share we support
        const KeyShareEntry* selected_share = nullptr;
        static constexpr NamedCurve preferred_groups[] = {
            NamedCurve::x25519, NamedCurve::secp256r1, NamedCurve::secp384r1,
        };
        for (auto group : preferred_groups) {
            for (auto& share : ext_13.client_shares) {
                if (share.group == group) {
                    selected_share = &share;
                    break;
                }
            }
            if (selected_share) break;
        }
        if (!selected_share) return {tls_error::handshake_failure};

        // Negotiate ALPN
        if (!config_.alpn_protocols.empty() && !ext_13.alpn_protocols.empty()) {
            for (auto& server_proto : config_.alpn_protocols) {
                for (auto& client_proto : ext_13.alpn_protocols) {
                    if (server_proto == client_proto) {
                        negotiated_protocol_ = std::string(server_proto);
                        goto alpn_done;
                    }
                }
            }
            return {tls_error::handshake_failure};
        }
        alpn_done:

        // Buffer ClientHello for transcript
        std::vector<uint8_t> early_transcript(ch_frag.begin(),
            ch_frag.begin() + ch_msg_len);

        // Phase 2: Dispatch on cipher suite
        return dispatch_tls13_cipher_suite(negotiated_suite_,
            [&]<typename Traits>() {
                return handshake_continue<Traits>(early_transcript, *selected_share);
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
        for (;;) {
            auto rec = rio_.recv_record();
            if (!rec) return {{}, rec.error};
            if (rec.value.content_type == ContentType::alert)
                return {{}, tls_error::transport_closed};
            if (rec.value.content_type == ContentType::handshake)
                continue; // skip post-handshake messages
            if (rec.value.content_type != ContentType::application_data)
                return {{}, tls_error::unexpected_message};
            size_t n = buf.size() < rec.value.fragment.size()
                ? buf.size() : rec.value.fragment.size();
            for (size_t i = 0; i < n; ++i)
                buf[i] = rec.value.fragment[i];
            return {n, tls_error::ok};
        }
    }

    tls_result<void> close() {
        std::array<uint8_t, 2> alert = {
            static_cast<uint8_t>(AlertLevel::warning),
            static_cast<uint8_t>(AlertDescription::close_notify)};
        return rio_.send_record(ContentType::alert, alert);
    }

    bool is_connected() const { return handshake_complete_; }
    Tls13CipherSuite negotiated_suite() const { return negotiated_suite_; }
    std::string_view negotiated_protocol() const { return negotiated_protocol_; }

private:
    // --- ECDSA signature DER encoding ---

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

    // --- Uncompressed point serialization ---

    template <typename TCurve>
    static void serialize_uncompressed_point(
        const point<TCurve>& pt, size_t coord_len,
        asn1::FixedVector<uint8_t, 133>& out)
    {
        out.push_back(0x04);
        auto x_bytes = pt.x().value().to_bytes(std::endian::big);
        auto y_bytes = pt.y().value().to_bytes(std::endian::big);
        size_t x_off = x_bytes.size() - coord_len;
        size_t y_off = y_bytes.size() - coord_len;
        for (size_t i = 0; i < coord_len; ++i) out.push_back(x_bytes[x_off + i]);
        for (size_t i = 0; i < coord_len; ++i) out.push_back(y_bytes[y_off + i]);
    }

    // --- ECDH shared secret computation (server side) ---

    template <typename TCurve>
    tls_result<std::vector<uint8_t>> compute_ecdh_shared(
        const typename TCurve::number_type& priv,
        const asn1::FixedVector<uint8_t, 133>& peer_key_bytes,
        size_t coord_len)
    {
        using fe = field_element<TCurve>;
        using num = typename TCurve::number_type;

        if (peer_key_bytes.size() < 3 || peer_key_bytes[0] != 0x04)
            return {{}, tls_error::invalid_server_key};

        auto x = num::from_bytes(std::span<const uint8_t>(
            peer_key_bytes.data.data() + 1, coord_len));
        auto y = num::from_bytes(std::span<const uint8_t>(
            peer_key_bytes.data.data() + 1 + coord_len, coord_len));
        point<TCurve> client_point{fe{x}, fe{y}};

        if (!ecdh_validate_public_key(client_point))
            return {{}, tls_error::invalid_server_key};

        auto secret_x = ecdh_raw_shared_secret<TCurve>(priv, client_point);
        if (!secret_x) return {{}, tls_error::internal_error};

        auto secret_bytes = secret_x->to_bytes(std::endian::big);
        size_t offset = secret_bytes.size() - coord_len;
        std::vector<uint8_t> result(coord_len);
        for (size_t i = 0; i < coord_len; ++i)
            result[i] = secret_bytes[offset + i];
        return {std::move(result), tls_error::ok};
    }

    // --- CertificateVerify signing ---

    CertificateVerify sign_certificate_verify(std::span<const uint8_t> verify_content) {
        CertificateVerify cv{};

        if (auto* p256_key = std::get_if<p256_curve::number_type>(&config_.private_key)) {
            auto hash = sha256(verify_content);
            auto sig = ecdsa_sign<p256_curve, sha256_state>(*p256_key, hash);
            auto der_sig = encode_ecdsa_signature(sig);
            cv.algorithm = to_signature_and_hash(SignatureScheme::ecdsa_secp256r1_sha256);
            for (auto b : der_sig) cv.signature.push_back(b);
        } else if (auto* p384_key = std::get_if<p384_curve::number_type>(&config_.private_key)) {
            auto hash = sha384(verify_content);
            auto sig = ecdsa_sign<p384_curve, sha384_state>(*p384_key, hash);
            auto der_sig = encode_ecdsa_signature(sig);
            cv.algorithm = to_signature_and_hash(SignatureScheme::ecdsa_secp384r1_sha384);
            for (auto b : der_sig) cv.signature.push_back(b);
        } else if (auto* p521_key = std::get_if<p521_curve::number_type>(&config_.private_key)) {
            auto hash = sha512(verify_content);
            auto sig = ecdsa_sign<p521_curve, sha512_state>(*p521_key, hash);
            auto der_sig = encode_ecdsa_signature(sig);
            cv.algorithm = to_signature_and_hash(SignatureScheme::ecdsa_secp521r1_sha512);
            for (auto b : der_sig) cv.signature.push_back(b);
        } else if (auto* rsa_key = std::get_if<rsa_private_key<rsa_num>>(&config_.private_key)) {
            auto hash = sha256(verify_content);
            auto salt = random_bytes<sha256_state::digest_size>(rng_);
            auto sig = rsa_pss_sign<rsa_num, sha256_state>(*rsa_key, hash, salt);
            cv.algorithm = to_signature_and_hash(SignatureScheme::rsa_pss_rsae_sha256);
            auto sig_bytes = sig.value.to_bytes(std::endian::big);
            size_t mod_bytes = (rsa_key->n.bit_width() + 7) / 8;
            size_t offset = sig_bytes.size() - mod_bytes;
            for (size_t i = 0; i < mod_bytes; ++i)
                cv.signature.push_back(sig_bytes[offset + i]);
        }

        return cv;
    }

    // --- Handshake continuation (after cipher suite dispatch) ---

    template <typename Traits>
    tls_result<void> handshake_continue(
        const std::vector<uint8_t>& early_bytes,
        const KeyShareEntry& client_share)
    {
        using Hash = typename Traits::hash_type;

        // Initialize transcript with ClientHello
        TranscriptHash<Hash> transcript;
        transcript.update(std::span<const uint8_t>(early_bytes));

        // Generate server ephemeral keypair and compute shared secret
        KeyShareEntry server_share;
        server_share.group = client_share.group;
        std::vector<uint8_t> shared_secret;

        if (client_share.group == NamedCurve::x25519) {
            auto priv = random_bytes<32>(rng_);
            auto pub = x25519_public_key<asn1::x509::uint512>(priv);
            for (size_t i = 0; i < 32; ++i)
                server_share.key_exchange.push_back(pub[i]);

            std::array<uint8_t, 32> peer_key{};
            for (size_t i = 0; i < 32 && i < client_share.key_exchange.size(); ++i)
                peer_key[i] = client_share.key_exchange[i];
            auto secret = x25519_shared_secret<asn1::x509::uint512>(priv, peer_key);
            if (!secret) return {tls_error::internal_error};
            shared_secret.assign(secret->begin(), secret->end());
        } else if (client_share.group == NamedCurve::secp256r1) {
            auto priv = random_scalar<asn1::x509::p256_curve>(rng_);
            auto kp = ecdh_keypair_from_private<asn1::x509::p256_curve>(priv);
            serialize_uncompressed_point(kp.public_key, 32, server_share.key_exchange);
            auto dhe_res = compute_ecdh_shared<asn1::x509::p256_curve>(
                priv, client_share.key_exchange, 32);
            if (!dhe_res) return {dhe_res.error};
            shared_secret = std::move(dhe_res.value);
        } else if (client_share.group == NamedCurve::secp384r1) {
            auto priv = random_scalar<asn1::x509::p384_curve>(rng_);
            auto kp = ecdh_keypair_from_private<asn1::x509::p384_curve>(priv);
            serialize_uncompressed_point(kp.public_key, 48, server_share.key_exchange);
            auto dhe_res = compute_ecdh_shared<asn1::x509::p384_curve>(
                priv, client_share.key_exchange, 48);
            if (!dhe_res) return {dhe_res.error};
            shared_secret = std::move(dhe_res.value);
        } else {
            return {tls_error::unsupported_curve};
        }

        // Build and send ServerHello
        Random server_random = random_bytes<32>(rng_);
        ServerHello sh{};
        sh.server_version = TLS_1_2;  // legacy (RFC 8446 Section 4.1.3)
        sh.random = server_random;
        sh.session_id = client_hello_session_id(early_bytes);
        sh.cipher_suite = static_cast<CipherSuite>(
            static_cast<uint16_t>(negotiated_suite_));
        sh.compression_method = CompressionMethod::null;

        // ServerHello extensions: supported_versions + key_share
        // Must include 2-byte total length prefix (write_server_hello writes raw bytes)
        {
            TlsWriter<256> ext_w;
            size_t ext_list_pos = ext_w.position();
            ext_w.write_u16(0); // placeholder for total extensions length
            write_supported_versions_server(ext_w, TLS_1_3);
            write_key_share_server(ext_w, server_share);
            auto total = static_cast<uint16_t>(ext_w.position() - ext_list_pos - 2);
            ext_w.patch_u16(ext_list_pos, total);
            auto ext_data = ext_w.data();
            for (size_t i = 0; i < ext_data.size(); ++i)
                sh.extensions.push_back(ext_data[i]);
        }

        TlsWriter<512> sh_w;
        write_server_hello(sh_w, sh);
        auto sh_bytes = sh_w.data();

        // Update transcript with ServerHello
        transcript.update(sh_bytes);

        // Send ServerHello (plaintext)
        auto send_err = rio_.send_record(ContentType::handshake, sh_bytes);
        if (!send_err) return {send_err.error};

        // Derive handshake secrets
        Tls13KeySchedule<Hash> ks;
        ks.derive_early_secret();
        ks.derive_handshake_secrets(
            std::span<const uint8_t>(shared_secret),
            transcript.current_hash());

        log_tls13_secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            client_random_, ks.client_handshake_traffic_secret);
        log_tls13_secret("SERVER_HANDSHAKE_TRAFFIC_SECRET",
            client_random_, ks.server_handshake_traffic_secret);

        // Send middlebox CCS (unencrypted)
        auto ccs_err = rio_.send_ccs();
        if (!ccs_err) return {ccs_err.error};

        // Activate server handshake write keys
        rio_.activate_write_keys(negotiated_suite_, ks.server_handshake_traffic_secret);

        // Send EncryptedExtensions
        {
            TlsWriter<512> ee_w;
            if (!negotiated_protocol_.empty()) {
                TlsWriter<256> alpn_ext;
                alpn_ext.write_u16(static_cast<uint16_t>(
                    ExtensionType::application_layer_protocol_negotiation));
                auto proto_len = static_cast<uint16_t>(negotiated_protocol_.size());
                alpn_ext.write_u16(static_cast<uint16_t>(2 + 1 + proto_len));
                alpn_ext.write_u16(static_cast<uint16_t>(1 + proto_len));
                alpn_ext.write_u8(static_cast<uint8_t>(proto_len));
                alpn_ext.write_bytes(std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(negotiated_protocol_.data()),
                    negotiated_protocol_.size()));
                write_tls13_encrypted_extensions(ee_w, alpn_ext.data());
            } else {
                write_tls13_encrypted_extensions(ee_w, std::span<const uint8_t>{});
            }
            transcript.update(ee_w.data());
            auto err = rio_.send_record(ContentType::handshake, ee_w.data());
            if (!err) return {err.error};
        }

        // Send Certificate
        {
            TlsWriter<16384> cert_w;
            write_tls13_certificate(cert_w,
                std::span<const uint8_t>{},
                config_.certificate_chain);
            transcript.update(cert_w.data());
            auto err = rio_.send_record(ContentType::handshake, cert_w.data());
            if (!err) return {err.error};
        }

        // Send CertificateVerify
        {
            auto pre_cv_hash = transcript.current_hash();
            auto verify_content = build_tls13_certificate_verify_content(
                /*is_server=*/true, pre_cv_hash);
            auto cv = sign_certificate_verify(verify_content);

            TlsWriter<1024> cv_w;
            write_tls13_certificate_verify(cv_w, cv);
            transcript.update(cv_w.data());
            auto err = rio_.send_record(ContentType::handshake, cv_w.data());
            if (!err) return {err.error};
        }

        // Send Finished
        {
            auto pre_fin_hash = transcript.current_hash();
            auto server_vd = ks.compute_finished_verify_data(
                ks.server_handshake_traffic_secret, pre_fin_hash);

            TlsWriter<128> fin_w;
            write_tls13_finished(fin_w, server_vd);
            transcript.update(fin_w.data());
            auto err = rio_.send_record(ContentType::handshake, fin_w.data());
            if (!err) return {err.error};
        }

        // Derive application traffic secrets
        auto server_finished_hash = transcript.current_hash();
        ks.derive_master_secrets(server_finished_hash);

        log_tls13_secret("CLIENT_TRAFFIC_SECRET_0",
            client_random_, ks.client_application_traffic_secret);
        log_tls13_secret("SERVER_TRAFFIC_SECRET_0",
            client_random_, ks.server_application_traffic_secret);
        log_tls13_secret("EXPORTER_SECRET",
            client_random_, ks.exporter_master_secret);

        // Activate client handshake read keys (to receive client Finished)
        rio_.activate_read_keys(negotiated_suite_, ks.client_handshake_traffic_secret);

        // Receive client Finished
        {
            tls13_handshake_reader<Transport> hs_reader(rio_);
            auto fin_msg_raw = hs_reader.next_message(transcript);
            if (!fin_msg_raw) return {fin_msg_raw.error};

            TlsReader r(std::span<const uint8_t>(fin_msg_raw.value));
            auto hdr = read_handshake_header(r);
            if (hdr.type != HandshakeType::finished)
                return {tls_error::unexpected_message};
            auto fin = read_tls13_finished(r, Hash::digest_size);

            auto expected_vd = ks.compute_finished_verify_data(
                ks.client_handshake_traffic_secret, server_finished_hash);
            if (fin.verify_data.size() != expected_vd.size())
                return {tls_error::handshake_failure};
            for (size_t i = 0; i < expected_vd.size(); ++i) {
                if (fin.verify_data[i] != expected_vd[i])
                    return {tls_error::handshake_failure};
            }
        }

        // Activate application traffic keys
        rio_.activate_write_keys(negotiated_suite_, ks.server_application_traffic_secret);
        rio_.activate_read_keys(negotiated_suite_, ks.client_application_traffic_secret);

        handshake_complete_ = true;
        return {tls_error::ok};
    }

    // Extract the legacy session_id from raw ClientHello bytes for echoing in ServerHello.
    static SessionId client_hello_session_id(const std::vector<uint8_t>& ch_bytes) {
        // ClientHello: 4-byte header + 2 version + 32 random + session_id_len + session_id
        if (ch_bytes.size() < 4 + 2 + 32 + 1) return {};
        size_t pos = 4 + 2 + 32; // skip header + version + random
        uint8_t sid_len = ch_bytes[pos];
        if (sid_len == 0 || sid_len > 32) return {};
        SessionId sid{};
        sid.length = sid_len;
        for (size_t i = 0; i < sid_len; ++i)
            sid.data[i] = ch_bytes[pos + 1 + i];
        return sid;
    }
};

} // namespace tls
