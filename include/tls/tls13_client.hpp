/**
 * TLS 1.3 client — RFC 8446.
 *
 * Provides tls13_client<Transport, RNG> that performs a 1-RTT ECDHE
 * handshake and sends/receives encrypted application data.
 *
 * Supports three cipher suites:
 *   TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
 *   TLS_CHACHA20_POLY1305_SHA256
 *
 * Key exchange groups: x25519, secp256r1, secp384r1.
 * No PSK, 0-RTT, or HelloRetryRequest.
 */

#pragma once

#include "tls13_connection.hpp"
#include "tls13_extensions.hpp"
#include "tls13_handshake.hpp"
#include "tls13_key_schedule.hpp"
#include "keylog.hpp"
#include <crypto/ecdh.hpp>
#include <crypto/ecdsa.hpp>
#include <crypto/random.hpp>
#include <crypto/rsa.hpp>
#include <crypto/x25519.hpp>
#include <x509/basic_constraints_verifier.hpp>
#include <x509/hostname_verifier.hpp>
#include <x509/key_usage_verifier.hpp>
#include <x509/time_verifier.hpp>
#include <x509/trust_store.hpp>
#include <vector>

namespace tls {

struct tls13_client_config {
    std::array<Tls13CipherSuite, 3> cipher_suites = {
        Tls13CipherSuite::TLS_AES_256_GCM_SHA384,
        Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        Tls13CipherSuite::TLS_AES_128_GCM_SHA256,
    };
    size_t num_cipher_suites = 3;

    std::array<NamedCurve, 3> groups = {
        NamedCurve::x25519, NamedCurve::secp256r1, NamedCurve::secp384r1,
    };
    size_t num_groups = 3;

    std::array<SignatureScheme, 6> sig_schemes = {{
        SignatureScheme::ecdsa_secp256r1_sha256,
        SignatureScheme::ecdsa_secp384r1_sha384,
        SignatureScheme::ecdsa_secp521r1_sha512,
        SignatureScheme::rsa_pss_rsae_sha256,
        SignatureScheme::rsa_pss_rsae_sha384,
        SignatureScheme::rsa_pss_rsae_sha512,
    }};
    size_t num_sig_schemes = 6;

    const asn1::x509::trust_store* trust = nullptr;
    std::string_view hostname;
    std::span<const std::string_view> alpn_protocols;
};

// Verify a TLS 1.3 CertificateVerify signature (RFC 8446 Section 4.4.3).
inline bool verify_tls13_certificate_verify(
    const CertificateVerify& cv,
    std::span<const uint8_t> verify_content,
    const asn1::x509::x509_public_key& server_pub_key)
{
    auto scheme = to_signature_scheme(cv.algorithm);
    auto sig_span = std::span<const uint8_t>(cv.signature.data.data(), cv.signature.len);

    if (scheme == SignatureScheme::ecdsa_secp256r1_sha256) {
        auto* key = std::get_if<point<asn1::x509::p256_curve>>(&server_pub_key);
        if (!key) return false;
        auto hash = sha256(verify_content);
        auto sig = asn1::x509::detail::parse_ecdsa_signature<asn1::x509::p256_curve>(sig_span);
        return ecdsa_verify<asn1::x509::p256_curve, sha256_state>(*key, hash, sig);
    }
    if (scheme == SignatureScheme::ecdsa_secp384r1_sha384) {
        auto* key = std::get_if<point<asn1::x509::p384_curve>>(&server_pub_key);
        if (!key) return false;
        auto hash = sha384(verify_content);
        auto sig = asn1::x509::detail::parse_ecdsa_signature<asn1::x509::p384_curve>(sig_span);
        return ecdsa_verify<asn1::x509::p384_curve, sha384_state>(*key, hash, sig);
    }
    if (scheme == SignatureScheme::ecdsa_secp521r1_sha512) {
        auto* key = std::get_if<point<asn1::x509::p521_curve>>(&server_pub_key);
        if (!key) return false;
        auto hash = sha512(verify_content);
        auto sig = asn1::x509::detail::parse_ecdsa_signature<asn1::x509::p521_curve>(sig_span);
        return ecdsa_verify<asn1::x509::p521_curve, sha512_state>(*key, hash, sig);
    }
    if (scheme == SignatureScheme::rsa_pss_rsae_sha256) {
        auto* key = std::get_if<rsa_public_key<asn1::x509::rsa_num>>(&server_pub_key);
        if (!key) return false;
        rsa_signature<asn1::x509::rsa_num> sig{
            asn1::x509::rsa_num::from_bytes(sig_span)};
        return rsa_pss_verify<asn1::x509::rsa_num, sha256_state>(*key, sha256(verify_content), sig);
    }
    if (scheme == SignatureScheme::rsa_pss_rsae_sha384) {
        auto* key = std::get_if<rsa_public_key<asn1::x509::rsa_num>>(&server_pub_key);
        if (!key) return false;
        rsa_signature<asn1::x509::rsa_num> sig{
            asn1::x509::rsa_num::from_bytes(sig_span)};
        return rsa_pss_verify<asn1::x509::rsa_num, sha384_state>(*key, sha384(verify_content), sig);
    }
    if (scheme == SignatureScheme::rsa_pss_rsae_sha512) {
        auto* key = std::get_if<rsa_public_key<asn1::x509::rsa_num>>(&server_pub_key);
        if (!key) return false;
        rsa_signature<asn1::x509::rsa_num> sig{
            asn1::x509::rsa_num::from_bytes(sig_span)};
        return rsa_pss_verify<asn1::x509::rsa_num, sha512_state>(*key, sha512(verify_content), sig);
    }
    return false;
}

template <transport Transport, random_generator RNG>
class tls13_client {
    tls13_record_io<Transport> rio_;
    RNG& rng_;
    tls13_client_config config_;

    Random client_random_{};
    Tls13CipherSuite negotiated_suite_{};
    bool handshake_complete_ = false;
    std::string negotiated_protocol_;

    // Ephemeral private keys (generated before ClientHello)
    std::array<uint8_t, 32> x25519_priv_{};
    asn1::x509::p256_curve::number_type p256_priv_{};
    asn1::x509::p384_curve::number_type p384_priv_{};

public:
    tls13_client(Transport& t, RNG& rng, const tls13_client_config& cfg = {})
        : rio_(t), rng_(rng), config_(cfg) {}

    tls_result<void> handshake() {
        // Phase 1: Generate ephemeral keys and build ClientHello
        client_random_ = random_bytes<32>(rng_);

        // Generate key shares for each offered group
        asn1::FixedVector<KeyShareEntry, 3> key_shares;
        for (size_t i = 0; i < config_.num_groups; ++i) {
            KeyShareEntry entry;
            entry.group = config_.groups[i];

            if (config_.groups[i] == NamedCurve::x25519) {
                x25519_priv_ = random_bytes<32>(rng_);
                auto pub = x25519_public_key<asn1::x509::uint512>(x25519_priv_);
                for (size_t j = 0; j < 32; ++j)
                    entry.key_exchange.push_back(pub[j]);
            } else if (config_.groups[i] == NamedCurve::secp256r1) {
                p256_priv_ = random_scalar<asn1::x509::p256_curve>(rng_);
                auto kp = ecdh_keypair_from_private<asn1::x509::p256_curve>(p256_priv_);
                serialize_uncompressed_point(kp.public_key, 32, entry.key_exchange);
            } else if (config_.groups[i] == NamedCurve::secp384r1) {
                p384_priv_ = random_scalar<asn1::x509::p384_curve>(rng_);
                auto kp = ecdh_keypair_from_private<asn1::x509::p384_curve>(p384_priv_);
                serialize_uncompressed_point(kp.public_key, 48, entry.key_exchange);
            }
            key_shares.push_back(entry);
        }

        // Build ClientHello
        ClientHello ch{};
        ch.client_version = TLS_1_2; // legacy (RFC 8446 Section 4.1.2)
        ch.random = client_random_;
        // Random 32-byte legacy session_id for middlebox compatibility
        ch.session_id.data = random_bytes<32>(rng_);
        ch.session_id.length = 32;
        // Include TLS 1.3 cipher suites (wire format is same uint16)
        for (size_t i = 0; i < config_.num_cipher_suites; ++i)
            ch.cipher_suites.push_back(static_cast<CipherSuite>(
                static_cast<uint16_t>(config_.cipher_suites[i])));
        ch.compression_methods.push_back(CompressionMethod::null);

        // Build TLS 1.3 extensions
        TlsWriter<1024> ext_w;
        write_tls13_client_hello_extensions(ext_w,
            std::span<const NamedCurve>(config_.groups.data(), config_.num_groups),
            std::span<const SignatureScheme>(config_.sig_schemes.data(), config_.num_sig_schemes),
            std::span<const KeyShareEntry>(key_shares.data.data(), key_shares.len),
            config_.hostname,
            config_.alpn_protocols);
        for (size_t i = 0; i < ext_w.size(); ++i)
            ch.extensions.push_back(ext_w.data()[i]);

        // Serialize and send ClientHello
        TlsWriter<2048> ch_w;
        write_client_hello(ch_w, ch);
        auto ch_bytes = ch_w.data();

        auto send_err = rio_.send_record(ContentType::handshake, ch_bytes);
        if (!send_err) return {send_err.error};

        // Buffer raw ClientHello for transcript
        std::vector<uint8_t> early_transcript(ch_bytes.begin(), ch_bytes.end());

        // Phase 2: Receive ServerHello
        auto sh_rec = rio_.recv_record();
        if (!sh_rec) return {sh_rec.error};
        if (sh_rec.value.content_type != ContentType::handshake)
            return {tls_error::unexpected_message};

        auto& sh_frag = sh_rec.value.fragment;
        TlsReader sh_r{std::span<const uint8_t>(sh_frag)};
        auto sh_hdr = read_handshake_header(sh_r);
        if (sh_hdr.type != HandshakeType::server_hello)
            return {tls_error::unexpected_message};

        // Buffer ServerHello for transcript
        size_t sh_msg_len = 4 + sh_hdr.length;
        early_transcript.insert(early_transcript.end(),
            sh_frag.begin(), sh_frag.begin() + sh_msg_len);

        auto sh_body = sh_r.read_bytes(sh_hdr.length);
        TlsReader sh_body_r(sh_body);
        auto server_hello = read_server_hello(sh_body_r);

        // Parse TLS 1.3 extensions from ServerHello
        auto ext_13 = parse_server_hello_extensions_13(
            std::span<const uint8_t>(
                server_hello.extensions.data.data(), server_hello.extensions.len));

        if (!ext_13.has_supported_versions || ext_13.selected_version != TLS_1_3)
            return {tls_error::handshake_failure};
        if (!ext_13.has_key_share)
            return {tls_error::handshake_failure};

        negotiated_suite_ = static_cast<Tls13CipherSuite>(
            static_cast<uint16_t>(server_hello.cipher_suite));

        // Phase 3: Dispatch on cipher suite
        return dispatch_tls13_cipher_suite(negotiated_suite_,
            [&]<typename Traits>() {
                return handshake_continue<Traits>(early_transcript, ext_13.server_share);
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
            // Skip post-handshake messages (NewSessionTicket etc.)
            if (rec.value.content_type == ContentType::handshake)
                continue;
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

    // Compute ECDH shared secret from pre-generated private key + server's key_share.
    tls_result<std::vector<uint8_t>> compute_shared_secret(const KeyShareEntry& server_share) {
        if (server_share.group == NamedCurve::x25519) {
            if (server_share.key_exchange.size() != 32)
                return {{}, tls_error::invalid_server_key};
            std::array<uint8_t, 32> peer_key{};
            for (size_t i = 0; i < 32; ++i)
                peer_key[i] = server_share.key_exchange[i];
            auto secret = x25519_shared_secret<asn1::x509::uint512>(x25519_priv_, peer_key);
            if (!secret) return {{}, tls_error::internal_error};
            return {std::vector<uint8_t>(secret->begin(), secret->end()), tls_error::ok};
        }
        if (server_share.group == NamedCurve::secp256r1) {
            return compute_ecdh_shared<asn1::x509::p256_curve>(
                p256_priv_, server_share.key_exchange, 32);
        }
        if (server_share.group == NamedCurve::secp384r1) {
            return compute_ecdh_shared<asn1::x509::p384_curve>(
                p384_priv_, server_share.key_exchange, 48);
        }
        return {{}, tls_error::unsupported_curve};
    }

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
        point<TCurve> server_point{fe{x}, fe{y}};

        if (!ecdh_validate_public_key(server_point))
            return {{}, tls_error::invalid_server_key};

        auto secret_x = ecdh_raw_shared_secret<TCurve>(priv, server_point);
        if (!secret_x) return {{}, tls_error::internal_error};

        auto secret_bytes = secret_x->to_bytes(std::endian::big);
        size_t offset = secret_bytes.size() - coord_len;
        std::vector<uint8_t> result(coord_len);
        for (size_t i = 0; i < coord_len; ++i)
            result[i] = secret_bytes[offset + i];
        return {std::move(result), tls_error::ok};
    }

    template <typename Traits>
    tls_result<void> handshake_continue(
        const std::vector<uint8_t>& early_bytes,
        const KeyShareEntry& server_share)
    {
        using Hash = typename Traits::hash_type;

        // Initialize transcript with ClientHello + ServerHello
        TranscriptHash<Hash> transcript;
        transcript.update(std::span<const uint8_t>(early_bytes));

        // Step 5: Compute ECDH shared secret
        auto dhe_res = compute_shared_secret(server_share);
        if (!dhe_res) return {dhe_res.error};

        // Step 6: Derive handshake secrets
        Tls13KeySchedule<Hash> ks;
        ks.derive_early_secret(); // no PSK
        ks.derive_handshake_secrets(
            std::span<const uint8_t>(dhe_res.value),
            transcript.current_hash());

        log_tls13_secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            client_random_, ks.client_handshake_traffic_secret);
        log_tls13_secret("SERVER_HANDSHAKE_TRAFFIC_SECRET",
            client_random_, ks.server_handshake_traffic_secret);

        // Step 7: Activate server handshake read keys
        rio_.activate_read_keys(negotiated_suite_, ks.server_handshake_traffic_secret);

        // Step 8: Send middlebox CCS (unencrypted, not in transcript)
        auto ccs_err = rio_.send_ccs();
        if (!ccs_err) return {ccs_err.error};

        // Step 9: Receive encrypted handshake messages
        tls13_handshake_reader<Transport> hs_reader(rio_);

        // 9a: EncryptedExtensions
        auto ee_msg = hs_reader.next_message(transcript);
        if (!ee_msg) return {ee_msg.error};
        {
            TlsReader r(std::span<const uint8_t>(ee_msg.value));
            auto hdr = read_handshake_header(r);
            if (hdr.type != HandshakeType::encrypted_extensions)
                return {tls_error::unexpected_message};
            auto ee = read_tls13_encrypted_extensions(r);
            negotiated_protocol_ = parse_alpn_from_extensions(ee.extensions);
        }

        // 9b: Certificate
        auto cert_msg_raw = hs_reader.next_message(transcript);
        if (!cert_msg_raw) return {cert_msg_raw.error};

        asn1::x509::x509_public_key server_pub_key;
        {
            TlsReader r(std::span<const uint8_t>(cert_msg_raw.value));
            auto hdr = read_handshake_header(r);
            if (hdr.type != HandshakeType::certificate)
                return {tls_error::unexpected_message};
            auto cert_msg = read_tls13_certificate(r);
            if (cert_msg.entries.empty())
                return {tls_error::bad_certificate};

            // Parse leaf certificate
            auto& leaf_der = cert_msg.entries[0].cert_data;
            auto leaf_cert = asn1::x509::parse_certificate(
                std::span<const uint8_t>(leaf_der));
            server_pub_key = asn1::x509::extract_public_key(leaf_cert);

            // Verify certificate chain
            if (config_.trust) {
                std::vector<std::vector<uint8_t>> chain_der_vec;
                for (auto& entry : cert_msg.entries)
                    chain_der_vec.push_back(entry.cert_data);
                try {
                    bool chain_ok = false;
                    asn1::x509::time_verifier tv{};
                    asn1::x509::key_usage_verifier kuv{};
                    asn1::x509::basic_constraints_verifier bcv{};
                    if (!config_.hostname.empty()) {
                        asn1::x509::hostname_verifier hv{config_.hostname};
                        chain_ok = asn1::x509::verify_chain(
                            chain_der_vec, *config_.trust, hv, tv, kuv, bcv);
                    } else {
                        chain_ok = asn1::x509::verify_chain(
                            chain_der_vec, *config_.trust, tv, kuv, bcv);
                    }
                    if (!chain_ok) return {tls_error::bad_certificate};
                } catch (...) {
                    return {tls_error::bad_certificate};
                }
            }
        }

        // 9c: CertificateVerify
        auto pre_cv_hash = transcript.current_hash();
        auto cv_msg_raw = hs_reader.next_message(transcript);
        if (!cv_msg_raw) return {cv_msg_raw.error};
        {
            TlsReader r(std::span<const uint8_t>(cv_msg_raw.value));
            auto hdr = read_handshake_header(r);
            if (hdr.type != HandshakeType::certificate_verify)
                return {tls_error::unexpected_message};
            auto cv = read_tls13_certificate_verify(r);

            auto verify_content = build_tls13_certificate_verify_content(
                /*is_server=*/true, pre_cv_hash);
            if (!verify_tls13_certificate_verify(cv, verify_content, server_pub_key))
                return {tls_error::signature_verification_failed};
        }

        // 9d: Server Finished
        auto pre_fin_hash = transcript.current_hash();
        auto fin_msg_raw = hs_reader.next_message(transcript);
        if (!fin_msg_raw) return {fin_msg_raw.error};
        {
            TlsReader r(std::span<const uint8_t>(fin_msg_raw.value));
            auto hdr = read_handshake_header(r);
            if (hdr.type != HandshakeType::finished)
                return {tls_error::unexpected_message};
            auto fin = read_tls13_finished(r, Hash::digest_size);

            auto expected_vd = ks.compute_finished_verify_data(
                ks.server_handshake_traffic_secret, pre_fin_hash);
            if (fin.verify_data.size() != expected_vd.size())
                return {tls_error::handshake_failure};
            for (size_t i = 0; i < expected_vd.size(); ++i) {
                if (fin.verify_data[i] != expected_vd[i])
                    return {tls_error::handshake_failure};
            }
        }

        // Step 10: Derive application traffic secrets
        auto server_finished_hash = transcript.current_hash();
        ks.derive_master_secrets(server_finished_hash);

        log_tls13_secret("CLIENT_TRAFFIC_SECRET_0",
            client_random_, ks.client_application_traffic_secret);
        log_tls13_secret("SERVER_TRAFFIC_SECRET_0",
            client_random_, ks.server_application_traffic_secret);
        log_tls13_secret("EXPORTER_SECRET",
            client_random_, ks.exporter_master_secret);

        // Step 11: Send client Finished
        rio_.activate_write_keys(negotiated_suite_, ks.client_handshake_traffic_secret);

        auto client_vd = ks.compute_finished_verify_data(
            ks.client_handshake_traffic_secret, server_finished_hash);
        TlsWriter<128> fin_w;
        write_tls13_finished(fin_w, client_vd);
        transcript.update(fin_w.data());
        auto fin_err = rio_.send_record(ContentType::handshake, fin_w.data());
        if (!fin_err) return {fin_err.error};

        // Step 12: Activate application traffic keys
        rio_.activate_write_keys(negotiated_suite_, ks.client_application_traffic_secret);
        rio_.activate_read_keys(negotiated_suite_, ks.server_application_traffic_secret);

        handshake_complete_ = true;
        return {tls_error::ok};
    }
};

} // namespace tls
