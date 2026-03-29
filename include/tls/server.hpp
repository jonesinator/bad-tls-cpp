/**
 * TLS 1.2 server — RFC 5246.
 *
 * Provides tls_server<Transport, RNG> that performs a full ECDHE
 * handshake and sends/receives encrypted application data.
 *
 * Supports ECDSA cipher suites:
 *   TLS_ECDHE_ECDSA_WITH_AES_{128,256}_GCM_SHA{256,384}
 */

#pragma once

#include "connection.hpp"
#include "private_key.hpp"
#include <crypto/ecdsa.hpp>
#include <crypto/random.hpp>
#include <asn1/der/codegen.hpp>
#include <span>
#include <vector>

namespace tls {

struct server_config {
    // Certificate chain DER bytes (leaf first)
    std::span<const std::vector<uint8_t>> certificate_chain;

    // EC private key
    ec_private_key private_key;
    NamedCurve private_key_curve = NamedCurve::secp256r1;

    // Cipher suites the server supports (ECDSA only)
    std::array<CipherSuite, 2> cipher_suites = {
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    };
    size_t num_cipher_suites = 2;

    // Supported curves for ECDHE
    std::array<NamedCurve, 2> curves = {NamedCurve::secp256r1, NamedCurve::secp384r1};
    size_t num_curves = 2;
};

template <transport Transport, random_generator RNG>
class tls_server {
    record_io<Transport> rio_;
    RNG& rng_;
    server_config config_;

    Random client_random_{};
    Random server_random_{};
    CipherSuite negotiated_suite_{};
    std::array<uint8_t, 48> master_secret_{};
    bool handshake_complete_ = false;

public:
    tls_server(Transport& t, RNG& rng, const server_config& cfg)
        : rio_(t, tls_role::server), rng_(rng), config_(cfg) {}

    tls_result<void> handshake() {
        // Phase 1: Receive ClientHello
        auto ch_rec = rio_.recv_record();
        if (!ch_rec) return {ch_rec.error};
        if (ch_rec.value.type != ContentType::handshake)
            return {tls_error::unexpected_message};

        auto ch_frag = std::span<const uint8_t>(
            ch_rec.value.fragment.data.data(), ch_rec.value.fragment.size());
        TlsReader ch_r(ch_frag);
        auto ch_hdr = read_handshake_header(ch_r);
        if (ch_hdr.type != HandshakeType::client_hello)
            return {tls_error::unexpected_message};

        auto ch_body = ch_r.read_bytes(ch_hdr.length);
        TlsReader ch_body_r(ch_body);
        auto client_hello = read_client_hello(ch_body_r);
        client_random_ = client_hello.random;

        // Select cipher suite: first server-preferred suite offered by client
        bool suite_found = false;
        for (size_t i = 0; i < config_.num_cipher_suites && !suite_found; ++i) {
            for (size_t j = 0; j < client_hello.cipher_suites.size(); ++j) {
                if (config_.cipher_suites[i] == client_hello.cipher_suites[j]) {
                    negotiated_suite_ = config_.cipher_suites[i];
                    suite_found = true;
                    break;
                }
            }
        }
        if (!suite_found) return {tls_error::handshake_failure};

        // Buffer ClientHello for transcript (full handshake message including header)
        size_t ch_msg_len = 4 + ch_hdr.length;

        // Phase 2: dispatch into templated continuation
        return dispatch_cipher_suite(negotiated_suite_, [&]<typename Traits>() {
            return handshake_continue<Traits>(
                std::span<const uint8_t>(ch_frag.data(), ch_msg_len));
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
    CipherSuite negotiated_suite() const { return negotiated_suite_; }

private:
    // DER-encode an ECDSA signature (r, s) as ECDSA-Sig-Value
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

    // Generate ephemeral ECDH keypair and serialize public key as uncompressed point
    template <typename TCurve, random_generator R>
    static auto generate_ecdhe_keypair(R& rng) {
        using num = typename TCurve::number_type;
        auto priv = random_scalar<TCurve>(rng);
        auto kp = ecdh_keypair_from_private<TCurve>(priv);

        // Serialize public key: 0x04 || x || y
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

        struct result {
            num private_key;
            asn1::FixedVector<uint8_t, 133> public_key_bytes;
        };
        return result{priv, point_bytes};
    }

    // Sign the ServerKeyExchange parameters
    template <typename TCurve, typename THash>
    ServerKeyExchangeEcdhe build_server_key_exchange(
        NamedCurve curve,
        const asn1::FixedVector<uint8_t, 133>& ecdhe_pub,
        const typename TCurve::number_type& signing_key)
    {
        ServerKeyExchangeEcdhe ske{};
        ske.named_curve = curve;
        ske.public_key = ecdhe_pub;

        // Build signed data: client_random || server_random || server_params
        std::array<uint8_t, 201> signed_data{};
        size_t pos = 0;
        for (size_t i = 0; i < 32; ++i) signed_data[pos++] = client_random_[i];
        for (size_t i = 0; i < 32; ++i) signed_data[pos++] = server_random_[i];
        signed_data[pos++] = static_cast<uint8_t>(ECCurveType::named_curve);
        signed_data[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(curve) >> 8);
        signed_data[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(curve));
        signed_data[pos++] = static_cast<uint8_t>(ecdhe_pub.size());
        for (size_t i = 0; i < ecdhe_pub.size(); ++i)
            signed_data[pos++] = ecdhe_pub[i];
        auto data_span = std::span<const uint8_t>(signed_data.data(), pos);

        // Hash and sign
        THash h;
        h.init();
        h.update(data_span);
        auto hash = h.finalize();
        auto sig = ecdsa_sign<TCurve, THash>(signing_key, hash);
        auto der_sig = encode_ecdsa_signature(sig);

        // Set signature algorithm
        if constexpr (THash::digest_size == 32) {
            ske.sig_algorithm = {HashAlgorithm::sha256, SignatureAlgorithm::ecdsa};
        } else {
            ske.sig_algorithm = {HashAlgorithm::sha384, SignatureAlgorithm::ecdsa};
        }

        for (auto b : der_sig)
            ske.signature.push_back(b);

        return ske;
    }

    // Compute ECDH shared secret from server's ephemeral private key and client's public point
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

    template <typename Traits>
    tls_result<void> handshake_continue(std::span<const uint8_t> client_hello_bytes) {
        using Hash = typename Traits::hash_type;

        // Initialize transcript with ClientHello
        TranscriptHash<Hash> transcript;
        transcript.update(client_hello_bytes);

        // --- Send ServerHello ---
        server_random_ = random_bytes<32>(rng_);

        ServerHello sh{};
        sh.server_version = TLS_1_2;
        sh.random = server_random_;
        sh.session_id.length = 0;
        sh.cipher_suite = negotiated_suite_;
        sh.compression_method = CompressionMethod::null;

        // Add renegotiation_info extension (RFC 5746) — required by modern clients
        {
            TlsWriter<32> ext_w;
            ext_w.write_u16(5); // total extensions length
            ext_w.write_u16(static_cast<uint16_t>(ExtensionType::renegotiation_info));
            ext_w.write_u16(1); // extension data length
            ext_w.write_u8(0);  // empty renegotiated_connection
            for (size_t i = 0; i < ext_w.size(); ++i)
                sh.extensions.push_back(ext_w.data()[i]);
        }

        TlsWriter<256> sh_w;
        write_server_hello(sh_w, sh);
        transcript.update(sh_w.data());
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
        write_certificate(cert_w, cert_msg);
        transcript.update(cert_w.data());
        auto cert_err = rio_.send_record(ContentType::handshake, cert_w.data());
        if (!cert_err) return {cert_err.error};

        // --- Send ServerKeyExchange ---
        // Determine ECDHE curve (use private key curve)
        NamedCurve ecdhe_curve = config_.private_key_curve;

        // Generate ephemeral ECDH and sign, dispatching on curve
        ServerKeyExchangeEcdhe ske;
        // We need to store the ephemeral private key for later ECDH
        // Use a variant to hold it
        std::variant<
            asn1::x509::p256_curve::number_type,
            asn1::x509::p384_curve::number_type
        > eph_priv;

        if (ecdhe_curve == NamedCurve::secp256r1) {
            auto kp = generate_ecdhe_keypair<asn1::x509::p256_curve>(rng_);
            eph_priv = kp.private_key;

            auto* signing_key = std::get_if<asn1::x509::p256_curve::number_type>(&config_.private_key);
            if (!signing_key) return {tls_error::internal_error};
            ske = build_server_key_exchange<asn1::x509::p256_curve, Hash>(
                ecdhe_curve, kp.public_key_bytes, *signing_key);
        } else if (ecdhe_curve == NamedCurve::secp384r1) {
            auto kp = generate_ecdhe_keypair<asn1::x509::p384_curve>(rng_);
            eph_priv = kp.private_key;

            auto* signing_key = std::get_if<asn1::x509::p384_curve::number_type>(&config_.private_key);
            if (!signing_key) return {tls_error::internal_error};
            ske = build_server_key_exchange<asn1::x509::p384_curve, Hash>(
                ecdhe_curve, kp.public_key_bytes, *signing_key);
        } else {
            return {tls_error::unsupported_curve};
        }

        TlsWriter<1024> ske_w;
        write_server_key_exchange_ecdhe(ske_w, ske);
        transcript.update(ske_w.data());
        auto ske_err = rio_.send_record(ContentType::handshake, ske_w.data());
        if (!ske_err) return {ske_err.error};

        // --- Send ServerHelloDone ---
        TlsWriter<64> shd_w;
        write_server_hello_done(shd_w);
        transcript.update(shd_w.data());
        auto shd_err = rio_.send_record(ContentType::handshake, shd_w.data());
        if (!shd_err) return {shd_err.error};

        // --- Receive ClientKeyExchange ---
        handshake_reader<Transport> hs_reader(rio_);

        auto cke_msg_res = hs_reader.next_message(transcript);
        if (!cke_msg_res) return {cke_msg_res.error};
        TlsReader cke_r(cke_msg_res.value);
        {
            auto hdr = read_handshake_header(cke_r);
            if (hdr.type != HandshakeType::client_key_exchange)
                return {tls_error::unexpected_message};
        }
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
        auto cfin_hdr = read_handshake_header(cfin_r);
        if (cfin_hdr.type != HandshakeType::finished)
            return {tls_error::unexpected_message};
        auto client_fin = read_finished(cfin_r);

        if (client_fin.verify_data != expected_client_vd)
            return {tls_error::handshake_failure};

        // Add client Finished to transcript for server Finished computation
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
        write_finished(fin_w, server_fin);
        auto fin_err = rio_.send_record(ContentType::handshake, fin_w.data());
        if (!fin_err) return {fin_err.error};

        handshake_complete_ = true;
        return {tls_error::ok};
    }
};

} // namespace tls
