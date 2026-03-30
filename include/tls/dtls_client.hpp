/**
 * DTLS 1.2 client — RFC 6347.
 *
 * Provides dtls_client<Transport, RNG> that performs a full ECDHE
 * handshake over datagrams with cookie exchange and sends/receives
 * encrypted application data.
 *
 * Supports the same four cipher suites as the TLS 1.2 client.
 */

#pragma once

#include "dtls_connection.hpp"
#include "dtls_handshake.hpp"
#include "private_key.hpp"
#include <crypto/ecdsa.hpp>
#include <crypto/random.hpp>
#include <asn1/der/codegen.hpp>
#include <x509/basic_constraints_verifier.hpp>
#include <x509/hostname_verifier.hpp>
#include <x509/key_usage_verifier.hpp>
#include <x509/time_verifier.hpp>
#include <x509/trust_store.hpp>
#include <vector>

namespace tls {

struct dtls_client_config {
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

    const asn1::x509::trust_store* trust = nullptr;
    std::string_view hostname;

    // Client certificate for mTLS
    std::span<const std::vector<uint8_t>> client_certificate_chain;
    tls_private_key client_private_key;
    NamedCurve client_key_curve = NamedCurve::secp256r1;

    // ALPN protocol names (empty = don't send ALPN extension) — RFC 7301
    std::span<const std::string_view> alpn_protocols;
};

template <transport Transport, random_generator RNG>
class dtls_client {
    dtls_record_io<Transport> rio_;
    RNG& rng_;
    dtls_client_config config_;

    Random client_random_{};
    Random server_random_{};
    CipherSuite negotiated_suite_{};
    std::array<uint8_t, 48> master_secret_{};
    bool handshake_complete_ = false;
    std::string negotiated_protocol_;
    uint16_t next_send_seq_ = 0;  // outgoing handshake message_seq

public:
    dtls_client(Transport& t, RNG& rng, const dtls_client_config& cfg = {})
        : rio_(t), rng_(rng), config_(cfg) {}

    tls_result<void> handshake() {
        client_random_ = random_bytes<32>(rng_);

        // Build extensions
        TlsWriter<512> ext_w;
        write_client_hello_extensions(ext_w,
            std::span<const NamedCurve>(config_.curves.data(), config_.num_curves),
            std::span<const SignatureAndHashAlgorithm>(config_.sig_algs.data(), config_.num_sig_algs),
            config_.hostname,
            config_.alpn_protocols);

        // --- Phase 1: Send initial ClientHello (no cookie) ---
        DtlsClientHello ch{};
        ch.client_version = DTLS_1_2;
        ch.random = client_random_;
        ch.session_id.length = 0;
        for (size_t i = 0; i < config_.num_cipher_suites; ++i)
            ch.cipher_suites.push_back(config_.cipher_suites[i]);
        ch.compression_methods.push_back(CompressionMethod::null);
        for (size_t i = 0; i < ext_w.size(); ++i)
            ch.extensions.push_back(ext_w.data()[i]);

        TlsWriter<2048> ch_w;
        write_dtls_client_hello(ch_w, next_send_seq_++, ch);
        auto send_err = rio_.send_record(ContentType::handshake, ch_w.data());
        if (!send_err) return {send_err.error};

        // --- Phase 1b: Receive HelloVerifyRequest or ServerHello ---
        dtls_handshake_reader<Transport> hs_reader(rio_);
        auto first_msg = hs_reader.next_message_no_transcript();
        if (!first_msg) return {first_msg.error};
        auto [first_hdr, first_body] = first_msg.value;
        // Raw DTLS message (12-byte header + body) from reassembly buffer
        auto first_raw = std::vector<uint8_t>(hs_reader.reasm_buf);

        if (first_hdr.type == HandshakeType::hello_verify_request) {
            // Parse HelloVerifyRequest
            TlsReader hvr_r(first_body);
            auto hvr = read_hello_verify_request(hvr_r);

            // --- Phase 2: Re-send ClientHello with cookie ---
            // Keep next_send_seq_=1 (second ClientHello gets message_seq=1)
            ch.cookie = hvr.cookie;

            TlsWriter<2048> ch2_w;
            write_dtls_client_hello(ch2_w, next_send_seq_++, ch);
            auto send2_err = rio_.send_record(ContentType::handshake, ch2_w.data());
            if (!send2_err) return {send2_err.error};

            // Buffer ClientHello (with cookie) for transcript
            // Now read ServerHello
            hs_reader.reset();

            // Add ClientHello with cookie to transcript later (after we know the cipher suite)
            // Save the serialized ClientHello for early transcript
            auto ch2_bytes = ch2_w.data();

            auto sh_msg = hs_reader.next_message_no_transcript();
            if (!sh_msg) return {sh_msg.error};
            auto [sh_hdr, sh_body] = sh_msg.value;
            // Raw ServerHello DTLS message from reassembly buffer
            auto sh_raw = std::vector<uint8_t>(hs_reader.reasm_buf);
            if (sh_hdr.type != HandshakeType::server_hello)
                return {tls_error::unexpected_message};

            TlsReader sh_r(sh_body);
            auto server_hello = read_server_hello(sh_r);
            server_random_ = server_hello.random;
            negotiated_suite_ = server_hello.cipher_suite;

            bool use_ems = false;
            if (server_hello.extensions.size() > 0) {
                TlsReader ext_r(std::span<const uint8_t>(
                    server_hello.extensions.data.data(), server_hello.extensions.len));
                while (ext_r.remaining() >= 4) {
                    uint16_t ext_type = ext_r.read_u16();
                    uint16_t ext_len = ext_r.read_u16();
                    if (ext_type == static_cast<uint16_t>(ExtensionType::extended_master_secret)) {
                        use_ems = true;
                    } else if (ext_type == static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation) && ext_len >= 4) {
                        auto alpn_data = ext_r.read_bytes(ext_len);
                        TlsReader alpn_r(alpn_data);
                        uint16_t list_len = alpn_r.read_u16();
                        if (list_len >= 2 && list_len <= alpn_r.remaining()) {
                            uint8_t name_len = alpn_r.read_u8();
                            if (name_len > 0 && name_len <= alpn_r.remaining()) {
                                auto name_bytes = alpn_r.read_bytes(name_len);
                                negotiated_protocol_.assign(
                                    reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());
                            }
                        }
                        continue;
                    }
                    if (ext_len > 0) ext_r.read_bytes(ext_len);
                }
            }

            // Build early transcript with full DTLS handshake messages (12-byte header + body)
            return dispatch_cipher_suite(negotiated_suite_, [&]<typename Traits>() {
                using Hash = typename Traits::hash_type;
                TranscriptHash<Hash> transcript;

                // Add ClientHello to transcript — full DTLS handshake message
                transcript.update(std::span<const uint8_t>(ch2_bytes.data(), ch2_bytes.size()));

                // Add ServerHello to transcript — full DTLS handshake message
                transcript.update(std::span<const uint8_t>(sh_raw));

                return handshake_continue<Traits>(transcript, hs_reader, use_ems);
            });
        } else if (first_hdr.type == HandshakeType::server_hello) {
            // No cookie exchange — server sent ServerHello directly
            TlsReader sh_r(first_body);
            auto server_hello = read_server_hello(sh_r);
            server_random_ = server_hello.random;
            negotiated_suite_ = server_hello.cipher_suite;

            bool use_ems = false;
            if (server_hello.extensions.size() > 0) {
                TlsReader ext_r(std::span<const uint8_t>(
                    server_hello.extensions.data.data(), server_hello.extensions.len));
                while (ext_r.remaining() >= 4) {
                    uint16_t ext_type = ext_r.read_u16();
                    uint16_t ext_len = ext_r.read_u16();
                    if (ext_type == static_cast<uint16_t>(ExtensionType::extended_master_secret)) {
                        use_ems = true;
                    } else if (ext_type == static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation) && ext_len >= 4) {
                        auto alpn_data = ext_r.read_bytes(ext_len);
                        TlsReader alpn_r(alpn_data);
                        uint16_t list_len = alpn_r.read_u16();
                        if (list_len >= 2 && list_len <= alpn_r.remaining()) {
                            uint8_t name_len = alpn_r.read_u8();
                            if (name_len > 0 && name_len <= alpn_r.remaining()) {
                                auto name_bytes = alpn_r.read_bytes(name_len);
                                negotiated_protocol_.assign(
                                    reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());
                            }
                        }
                        continue;
                    }
                    if (ext_len > 0) ext_r.read_bytes(ext_len);
                }
            }

            return dispatch_cipher_suite(negotiated_suite_, [&]<typename Traits>() {
                using Hash = typename Traits::hash_type;
                TranscriptHash<Hash> transcript;

                // Add ClientHello to transcript — full DTLS handshake message
                transcript.update(ch_w.data());

                // Add ServerHello to transcript — full DTLS handshake message
                transcript.update(std::span<const uint8_t>(first_raw));

                return handshake_continue<Traits>(transcript, hs_reader, use_ems);
            });
        } else {
            return {tls_error::unexpected_message};
        }
    }

    tls_result<size_t> send(std::span<const uint8_t> data) {
        if (!handshake_complete_) return {{}, tls_error::internal_error};
        // DTLS sends each chunk as a separate datagram
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

    template <typename Traits>
    tls_result<void> handshake_continue(
        TranscriptHash<typename Traits::hash_type>& transcript,
        dtls_handshake_reader<Transport>& hs_reader,
        bool use_ems)
    {
        using Hash = typename Traits::hash_type;

        // --- Certificate ---
        auto cert_msg_res = hs_reader.next_message(transcript);
        if (!cert_msg_res) return {cert_msg_res.error};
        auto [cert_hdr, cert_body] = cert_msg_res.value;
        if (cert_hdr.type != HandshakeType::certificate)
            return {tls_error::unexpected_message};

        TlsReader cert_r(cert_body);
        auto cert_msg = read_certificate(cert_r);
        if (cert_msg.certificate_list.size() == 0)
            return {tls_error::bad_certificate};

        auto& leaf_der = cert_msg.certificate_list[0];
        auto leaf_cert = asn1::x509::parse_certificate(
            std::span<const uint8_t>(leaf_der.data.data(), leaf_der.len));
        auto server_pub_key = asn1::x509::extract_public_key(leaf_cert);

        if (config_.trust) {
            std::vector<std::vector<uint8_t>> chain_der_vec;
            for (size_t i = 0; i < cert_msg.certificate_list.size(); ++i) {
                auto& c = cert_msg.certificate_list[i];
                chain_der_vec.emplace_back(c.data.data(), c.data.data() + c.len);
            }
            try {
                bool chain_ok = false;
                asn1::x509::time_verifier tv{};
                asn1::x509::key_usage_verifier kuv{};
                asn1::x509::basic_constraints_verifier bcv{};
                if (!config_.hostname.empty()) {
                    asn1::x509::hostname_verifier hv{config_.hostname};
                    chain_ok = asn1::x509::verify_chain(chain_der_vec, *config_.trust, hv, tv, kuv, bcv);
                } else {
                    chain_ok = asn1::x509::verify_chain(chain_der_vec, *config_.trust, tv, kuv, bcv);
                }
                if (!chain_ok) return {tls_error::bad_certificate};
            } catch (...) {
                return {tls_error::bad_certificate};
            }
        }

        // --- ServerKeyExchange ---
        auto ske_msg_res = hs_reader.next_message(transcript);
        if (!ske_msg_res) return {ske_msg_res.error};
        auto [ske_hdr, ske_body] = ske_msg_res.value;
        if (ske_hdr.type != HandshakeType::server_key_exchange)
            return {tls_error::unexpected_message};

        TlsReader ske_r(ske_body);
        auto ske = read_server_key_exchange_ecdhe(ske_r);

        if (!verify_server_key_exchange(ske, client_random_, server_random_, server_pub_key))
            return {tls_error::signature_verification_failed};

        // --- CertificateRequest (optional) or ServerHelloDone ---
        bool cert_requested = false;
        auto next_msg_res = hs_reader.next_message(transcript);
        if (!next_msg_res) return {next_msg_res.error};
        auto [next_hdr, next_body] = next_msg_res.value;

        if (next_hdr.type == HandshakeType::certificate_request) {
            cert_requested = true;
            TlsReader cr_r(next_body);
            read_certificate_request(cr_r);

            auto shd_msg_res = hs_reader.next_message(transcript);
            if (!shd_msg_res) return {shd_msg_res.error};
            auto [shd_hdr, shd_body] = shd_msg_res.value;
            if (shd_hdr.type != HandshakeType::server_hello_done)
                return {tls_error::unexpected_message};
        } else if (next_hdr.type == HandshakeType::server_hello_done) {
            // ok
        } else {
            return {tls_error::unexpected_message};
        }

        // --- Send client Certificate (if requested) ---
        bool sent_client_cert = false;
        if (cert_requested) {
            CertificateMessage client_cert_msg{};
            if (!config_.client_certificate_chain.empty()) {
                sent_client_cert = true;
                for (auto& cert_der : config_.client_certificate_chain) {
                    asn1::FixedVector<uint8_t, 8192> cert;
                    for (auto b : cert_der) cert.push_back(b);
                    client_cert_msg.certificate_list.push_back(cert);
                }
            }
            TlsWriter<32768> ccert_w;
            write_dtls_certificate(ccert_w, next_send_seq_++, client_cert_msg);
            // Add to transcript — full DTLS handshake message
            transcript.update(ccert_w.data());
            auto ccert_err = rio_.send_record(ContentType::handshake, ccert_w.data());
            if (!ccert_err) return {ccert_err.error};
        }

        // --- ECDH key exchange ---
        auto ecdh_res = compute_ecdh_exchange(
            ske.named_curve,
            std::span<const uint8_t>(ske.public_key.data.data(), ske.public_key.len),
            rng_);
        if (!ecdh_res) return {ecdh_res.error};

        // --- Send ClientKeyExchange ---
        TlsWriter<256> cke_w;
        write_dtls_client_key_exchange(cke_w, next_send_seq_++, ecdh_res.value.cke);
        // Add to transcript — full DTLS handshake message
        transcript.update(cke_w.data());
        auto cke_err = rio_.send_record(ContentType::handshake, cke_w.data());
        if (!cke_err) return {cke_err.error};

        auto session_hash = transcript.current_hash();

        // --- Send CertificateVerify (if client cert was sent) ---
        if (sent_client_cert) {
            auto cv_hash = transcript.current_hash();
            CertificateVerify cv{};

            if (auto* rsa_key = std::get_if<rsa_private_key<rsa_num>>(&config_.client_private_key)) {
                if constexpr (Hash::digest_size == 32)
                    cv.algorithm = {HashAlgorithm::sha256, SignatureAlgorithm::rsa};
                else
                    cv.algorithm = {HashAlgorithm::sha384, SignatureAlgorithm::rsa};

                auto sig = rsa_pkcs1_v1_5_sign<asn1::x509::rsa_num, Hash>(*rsa_key, cv_hash);
                auto sig_bytes = sig.value.to_bytes(std::endian::big);
                size_t mod_bytes = (rsa_key->n.bit_width() + 7) / 8;
                size_t offset = sig_bytes.size() - mod_bytes;
                for (size_t i = 0; i < mod_bytes; ++i)
                    cv.signature.push_back(sig_bytes[offset + i]);
            } else {
                if constexpr (Hash::digest_size == 32)
                    cv.algorithm = {HashAlgorithm::sha256, SignatureAlgorithm::ecdsa};
                else
                    cv.algorithm = {HashAlgorithm::sha384, SignatureAlgorithm::ecdsa};

                auto encode_sig = [&](const auto& sig) {
                    asn1::der::Type<detail::EccMod, "ECDSA-Sig-Value"> der_sig;
                    der_sig.template get<"r">() = num_to_integer(sig.r);
                    der_sig.template get<"s">() = num_to_integer(sig.s);
                    asn1::der::Writer dw;
                    asn1::der::encode<detail::EccMod, detail::EccMod.find_type("ECDSA-Sig-Value")>(dw, der_sig);
                    auto der_bytes = std::move(dw).finish();
                    for (auto b : der_bytes) cv.signature.push_back(b);
                };

                if (config_.client_key_curve == NamedCurve::secp256r1) {
                    auto* d = std::get_if<asn1::x509::p256_curve::number_type>(&config_.client_private_key);
                    if (!d) return {tls_error::internal_error};
                    encode_sig(ecdsa_sign<asn1::x509::p256_curve, Hash>(*d, cv_hash));
                } else {
                    auto* d = std::get_if<asn1::x509::p384_curve::number_type>(&config_.client_private_key);
                    if (!d) return {tls_error::internal_error};
                    encode_sig(ecdsa_sign<asn1::x509::p384_curve, Hash>(*d, cv_hash));
                }
            }

            TlsWriter<1024> cv_w;
            write_dtls_certificate_verify(cv_w, next_send_seq_++, cv);
            // Add to transcript — full DTLS handshake message
            transcript.update(cv_w.data());
            auto cv_err = rio_.send_record(ContentType::handshake, cv_w.data());
            if (!cv_err) return {cv_err.error};
        }

        // --- Key derivation ---
        auto& pms = ecdh_res.value.pms;
        auto pms_span = std::span<const uint8_t>(pms.data.data(), pms.length);
        std::array<uint8_t, 48> master;
        if (use_ems) {
            master = derive_extended_master_secret<Hash>(pms_span, session_hash);
        } else {
            master = derive_master_secret<Hash>(pms_span, client_random_, server_random_);
        }
        master_secret_ = master;

        auto params = get_cipher_suite_params(negotiated_suite_);
        auto kb = derive_key_block<Hash>(master, client_random_, server_random_, params);

        // --- Send ChangeCipherSpec ---
        std::array<uint8_t, 1> ccs = {CHANGE_CIPHER_SPEC_MESSAGE};
        auto ccs_err = rio_.send_record(ContentType::change_cipher_spec, ccs);
        if (!ccs_err) return {ccs_err.error};

        rio_.activate_write_cipher(kb, negotiated_suite_);

        // --- Send Finished (encrypted) ---
        auto client_vd = compute_verify_data<Hash>(master, true, transcript.current_hash());
        Finished client_fin{};
        client_fin.verify_data = client_vd;
        TlsWriter<64> fin_w;
        write_dtls_finished(fin_w, next_send_seq_++, client_fin);
        // Add to transcript — full DTLS handshake message
        transcript.update(fin_w.data());
        auto fin_err = rio_.send_record(ContentType::handshake, fin_w.data());
        if (!fin_err) return {fin_err.error};

        // --- Receive server ChangeCipherSpec ---
        // Skip retransmitted server flight records (epoch 0 handshake)
        while (true) {
            auto server_ccs = rio_.recv_record();
            if (!server_ccs) return {server_ccs.error};
            if (server_ccs.value.type == ContentType::change_cipher_spec) break;
            if (server_ccs.value.type == ContentType::handshake &&
                server_ccs.value.epoch == 0) continue;
            return {tls_error::unexpected_message};
        }

        rio_.activate_read_cipher(kb, negotiated_suite_);

        // --- Receive server Finished ---
        auto expected_vd = compute_verify_data<Hash>(master, false, transcript.current_hash());

        auto sfin_rec = rio_.recv_record();
        if (!sfin_rec) return {sfin_rec.error};
        if (sfin_rec.value.type != ContentType::handshake)
            return {tls_error::unexpected_message};

        // Parse DTLS handshake header from Finished
        TlsReader sfin_r(std::span<const uint8_t>(
            sfin_rec.value.fragment.data.data(), sfin_rec.value.fragment.size()));
        auto sfin_hdr = read_dtls_handshake_header(sfin_r);
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
