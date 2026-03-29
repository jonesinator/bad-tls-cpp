/**
 * TLS 1.2 client — RFC 5246.
 *
 * Provides tls_client<Transport, RNG> that performs a full ECDHE
 * handshake and sends/receives encrypted application data.
 *
 * Supports four cipher suites:
 *   TLS_ECDHE_{RSA,ECDSA}_WITH_AES_{128,256}_GCM_SHA{256,384}
 */

#pragma once

#include "connection.hpp"
#include <crypto/random.hpp>
#include <x509/trust_store.hpp>
#include <vector>

namespace tls {

struct client_config {
    std::array<CipherSuite, 4> cipher_suites = {
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    };
    size_t num_cipher_suites = 4;

    std::array<NamedCurve, 2> curves = {NamedCurve::secp256r1, NamedCurve::secp384r1};
    size_t num_curves = 2;

    std::array<SignatureAndHashAlgorithm, 4> sig_algs = {{
        {HashAlgorithm::sha256, SignatureAlgorithm::ecdsa},
        {HashAlgorithm::sha384, SignatureAlgorithm::ecdsa},
        {HashAlgorithm::sha256, SignatureAlgorithm::rsa},
        {HashAlgorithm::sha384, SignatureAlgorithm::rsa},
    }};
    size_t num_sig_algs = 4;

    // Optional trust store for certificate chain verification (nullptr to skip)
    const asn1::x509::trust_store* trust = nullptr;
};

template <transport Transport, random_generator RNG>
class tls_client {
    record_io<Transport> rio_;
    RNG& rng_;
    client_config config_;

    Random client_random_{};
    Random server_random_{};
    CipherSuite negotiated_suite_{};
    std::array<uint8_t, 48> master_secret_{};
    bool handshake_complete_ = false;

public:
    constexpr tls_client(Transport& t, RNG& rng, const client_config& cfg = {})
        : rio_(t), rng_(rng), config_(cfg) {}

    constexpr tls_result<void> handshake() {
        // Phase 1: ClientHello (before cipher suite is known)
        client_random_ = random_bytes<32>(rng_);

        ClientHello ch{};
        ch.client_version = TLS_1_2;
        ch.random = client_random_;
        ch.session_id.length = 0;
        for (size_t i = 0; i < config_.num_cipher_suites; ++i)
            ch.cipher_suites.push_back(config_.cipher_suites[i]);
        ch.compression_methods.push_back(CompressionMethod::null);

        // Build extensions
        TlsWriter<512> ext_w;
        write_client_hello_extensions(ext_w,
            std::span<const NamedCurve>(config_.curves.data(), config_.num_curves),
            std::span<const SignatureAndHashAlgorithm>(config_.sig_algs.data(), config_.num_sig_algs));
        for (size_t i = 0; i < ext_w.size(); ++i)
            ch.extensions.push_back(ext_w.data()[i]);

        // Serialize ClientHello
        TlsWriter<1024> ch_w;
        write_client_hello(ch_w, ch);
        auto ch_bytes = ch_w.data();

        auto send_err = rio_.send_record(ContentType::handshake, ch_bytes);
        if (!send_err) return {send_err.error};

        // Buffer for transcript (fed after cipher suite is known)
        asn1::FixedVector<uint8_t, 4096> early_transcript;
        for (size_t i = 0; i < ch_bytes.size(); ++i)
            early_transcript.push_back(ch_bytes[i]);

        // Phase 1b: Receive ServerHello
        auto sh_rec = rio_.recv_record();
        if (!sh_rec) return {sh_rec.error};
        if (sh_rec.value.type != ContentType::handshake)
            return {tls_error::unexpected_message};

        // Buffer full ServerHello fragment for transcript
        auto sh_frag = std::span<const uint8_t>(
            sh_rec.value.fragment.data.data(), sh_rec.value.fragment.size());
        for (size_t i = 0; i < sh_frag.size(); ++i)
            early_transcript.push_back(sh_frag[i]);

        // Parse ServerHello (skip handshake header)
        TlsReader sh_r(sh_frag);
        auto sh_hdr = read_handshake_header(sh_r);
        if (sh_hdr.type != HandshakeType::server_hello)
            return {tls_error::unexpected_message};

        auto sh_body = sh_r.read_bytes(sh_hdr.length);
        TlsReader sh_body_r(sh_body);
        auto server_hello = read_server_hello(sh_body_r);
        server_random_ = server_hello.random;
        negotiated_suite_ = server_hello.cipher_suite;

        // Phase 2: dispatch into templated continuation
        return dispatch_cipher_suite(negotiated_suite_, [&]<typename Traits>() {
            return handshake_continue<Traits>(early_transcript);
        });
    }

    constexpr tls_result<size_t> send(std::span<const uint8_t> data) {
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

    constexpr tls_result<size_t> recv(std::span<uint8_t> buf) {
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

    constexpr tls_result<void> close() {
        std::array<uint8_t, 2> alert = {
            static_cast<uint8_t>(AlertLevel::warning),
            static_cast<uint8_t>(AlertDescription::close_notify)};
        return rio_.send_record(ContentType::alert, alert);
    }

    constexpr bool is_connected() const { return handshake_complete_; }
    constexpr CipherSuite negotiated_suite() const { return negotiated_suite_; }

private:
    template <typename Traits>
    constexpr tls_result<void> handshake_continue(
        const asn1::FixedVector<uint8_t, 4096>& early_bytes)
    {
        using Hash = typename Traits::hash_type;

        // Initialize transcript with early bytes
        TranscriptHash<Hash> transcript;
        transcript.update(std::span<const uint8_t>(early_bytes.data.data(), early_bytes.len));

        // Handshake reader for message framing
        handshake_reader<Transport> hs_reader(rio_);

        // --- Certificate ---
        auto cert_msg_res = hs_reader.next_message(transcript);
        if (!cert_msg_res) return {cert_msg_res.error};
        {
            TlsReader r(cert_msg_res.value);
            auto hdr = read_handshake_header(r);
            if (hdr.type != HandshakeType::certificate)
                return {tls_error::unexpected_message};
        }
        // Re-parse body for certificate extraction
        TlsReader cert_r(cert_msg_res.value);
        cert_r.read_u8(); cert_r.read_u24(); // skip handshake header
        auto cert_msg = read_certificate(cert_r);
        if (cert_msg.certificate_list.size() == 0)
            return {tls_error::bad_certificate};

        // Parse leaf certificate and extract public key
        auto& leaf_der = cert_msg.certificate_list[0];
        auto leaf_cert = asn1::x509::parse_certificate(
            std::span<const uint8_t>(leaf_der.data.data(), leaf_der.len));
        auto server_pub_key = asn1::x509::extract_public_key(leaf_cert);

        // Verify certificate chain if trust store provided
        if (config_.trust) {
            std::vector<std::vector<uint8_t>> chain_der_vec;
            for (size_t i = 0; i < cert_msg.certificate_list.size(); ++i) {
                auto& c = cert_msg.certificate_list[i];
                chain_der_vec.emplace_back(c.data.data(), c.data.data() + c.len);
            }
            if (!asn1::x509::verify_chain(chain_der_vec, *config_.trust))
                return {tls_error::bad_certificate};
        }

        // --- ServerKeyExchange ---
        auto ske_msg_res = hs_reader.next_message(transcript);
        if (!ske_msg_res) return {ske_msg_res.error};
        TlsReader ske_r(ske_msg_res.value);
        {
            auto hdr = read_handshake_header(ske_r);
            if (hdr.type != HandshakeType::server_key_exchange)
                return {tls_error::unexpected_message};
        }
        auto ske = read_server_key_exchange_ecdhe(ske_r);

        if (!verify_server_key_exchange(ske, client_random_, server_random_, server_pub_key))
            return {tls_error::signature_verification_failed};

        // --- ServerHelloDone ---
        auto shd_msg_res = hs_reader.next_message(transcript);
        if (!shd_msg_res) return {shd_msg_res.error};
        {
            TlsReader shd_r(shd_msg_res.value);
            auto hdr = read_handshake_header(shd_r);
            if (hdr.type != HandshakeType::server_hello_done)
                return {tls_error::unexpected_message};
        }

        // --- ECDH key exchange ---
        auto ecdh_res = compute_ecdh_exchange(
            ske.named_curve,
            std::span<const uint8_t>(ske.public_key.data.data(), ske.public_key.len),
            rng_);
        if (!ecdh_res) return {ecdh_res.error};

        // --- Send ClientKeyExchange ---
        TlsWriter<256> cke_w;
        write_client_key_exchange_ecdhe(cke_w, ecdh_res.value.cke);
        transcript.update(cke_w.data());
        auto cke_err = rio_.send_record(ContentType::handshake, cke_w.data());
        if (!cke_err) return {cke_err.error};

        // --- Key derivation ---
        auto& pms = ecdh_res.value.pms;
        auto master = derive_master_secret<Hash>(
            std::span<const uint8_t>(pms.data.data(), pms.length),
            client_random_, server_random_);
        master_secret_ = master;

        auto params = get_cipher_suite_params(negotiated_suite_);
        auto kb = derive_key_block<Hash>(master, client_random_, server_random_, params);

        // --- Send ChangeCipherSpec (not in transcript) ---
        std::array<uint8_t, 1> ccs = {CHANGE_CIPHER_SPEC_MESSAGE};
        auto ccs_err = rio_.send_record(ContentType::change_cipher_spec, ccs);
        if (!ccs_err) return {ccs_err.error};

        rio_.activate_write_cipher(kb, negotiated_suite_);

        // --- Send Finished (encrypted) ---
        auto client_vd = compute_verify_data<Hash>(master, true, transcript.current_hash());
        Finished client_fin{};
        client_fin.verify_data = client_vd;
        TlsWriter<64> fin_w;
        write_finished(fin_w, client_fin);
        transcript.update(fin_w.data());
        auto fin_err = rio_.send_record(ContentType::handshake, fin_w.data());
        if (!fin_err) return {fin_err.error};

        // --- Receive server ChangeCipherSpec ---
        auto server_ccs = rio_.recv_record();
        if (!server_ccs) return {server_ccs.error};
        if (server_ccs.value.type != ContentType::change_cipher_spec)
            return {tls_error::unexpected_message};

        rio_.activate_read_cipher(kb, negotiated_suite_);

        // --- Receive server Finished (decrypted automatically) ---
        // Compute expected verify_data BEFORE adding server Finished to transcript
        auto expected_vd = compute_verify_data<Hash>(master, false, transcript.current_hash());

        auto sfin_rec = rio_.recv_record();
        if (!sfin_rec) return {sfin_rec.error};
        if (sfin_rec.value.type != ContentType::handshake)
            return {tls_error::unexpected_message};

        TlsReader sfin_r(std::span<const uint8_t>(
            sfin_rec.value.fragment.data.data(), sfin_rec.value.fragment.size()));
        auto sfin_hdr = read_handshake_header(sfin_r);
        if (sfin_hdr.type != HandshakeType::finished)
            return {tls_error::unexpected_message};
        auto server_fin = read_finished(sfin_r);

        if (server_fin.verify_data != expected_vd)
            return {tls_error::handshake_failure};

        handshake_complete_ = true;
        return {tls_error::ok};
    }
};

} // namespace tls
