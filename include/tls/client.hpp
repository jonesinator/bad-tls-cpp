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
#include "private_key.hpp"
#include "session_cache.hpp"
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

    // Optional hostname for SAN/CN verification (empty to skip)
    std::string_view hostname;

    // Client certificate for mTLS (empty span = no client cert)
    std::span<const std::vector<uint8_t>> client_certificate_chain;
    tls_private_key client_private_key;
    NamedCurve client_key_curve = NamedCurve::secp256r1;  // only meaningful for EC keys

    // ALPN protocol names (empty = don't send ALPN extension) — RFC 7301
    std::span<const std::string_view> alpn_protocols;

    // Session resumption — RFC 5246 Section 7.4.1.2
    session_cache* session_store = nullptr;         // store sessions after full handshake
    const session_data* resume_session = nullptr;   // session to attempt resuming

    // Session tickets (RFC 5077) — ticket data for resumption (empty = signal support only)
    std::span<const uint8_t> session_ticket;
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
    std::string negotiated_protocol_;
    SessionId server_hello_session_id_{};
    SessionId ticket_session_id_{};  // random session_id sent when resuming via ticket
    std::vector<uint8_t> received_ticket_;
    bool server_will_send_ticket_ = false;

public:
    constexpr tls_client(Transport& t, RNG& rng, const client_config& cfg = {})
        : rio_(t), rng_(rng), config_(cfg) {}

    constexpr tls_result<void> handshake() {
        // Phase 1: ClientHello (before cipher suite is known)
        client_random_ = random_bytes<32>(rng_);

        ClientHello ch{};
        ch.client_version = TLS_1_2;
        ch.random = client_random_;
        if (config_.resume_session && config_.resume_session->session_id.length > 0) {
            ch.session_id = config_.resume_session->session_id;
        } else if (!config_.session_ticket.empty()) {
            // RFC 5077 §3.4: include a non-empty session_id when sending a ticket
            // so the server can echo it back to signal resumption acceptance
            ticket_session_id_.data = random_bytes<32>(rng_);
            ticket_session_id_.length = 32;
            ch.session_id = ticket_session_id_;
        } else {
            ch.session_id.length = 0;
        }
        for (size_t i = 0; i < config_.num_cipher_suites; ++i)
            ch.cipher_suites.push_back(config_.cipher_suites[i]);
        ch.compression_methods.push_back(CompressionMethod::null);

        // Build extensions
        TlsWriter<768> ext_w;
        write_client_hello_extensions(ext_w,
            std::span<const NamedCurve>(config_.curves.data(), config_.num_curves),
            std::span<const SignatureAndHashAlgorithm>(config_.sig_algs.data(), config_.num_sig_algs),
            config_.hostname,
            config_.alpn_protocols,
            config_.session_ticket);
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

        // Parse ServerHello from the record fragment.
        // The fragment may contain additional handshake messages after ServerHello.
        auto sh_frag = std::span<const uint8_t>(
            sh_rec.value.fragment.data.data(), sh_rec.value.fragment.size());
        TlsReader sh_r(sh_frag);
        auto sh_hdr = read_handshake_header(sh_r);
        if (sh_hdr.type != HandshakeType::server_hello)
            return {tls_error::unexpected_message};

        // Buffer only the ServerHello handshake message for early transcript
        size_t sh_msg_len = 4 + sh_hdr.length; // header(4) + body
        for (size_t i = 0; i < sh_msg_len; ++i)
            early_transcript.push_back(sh_frag[i]);

        auto sh_body = sh_r.read_bytes(sh_hdr.length);
        TlsReader sh_body_r(sh_body);
        auto server_hello = read_server_hello(sh_body_r);
        server_random_ = server_hello.random;
        negotiated_suite_ = server_hello.cipher_suite;
        server_hello_session_id_ = server_hello.session_id;

        // Check if server echoed extended_master_secret extension
        bool use_ems = false;
        if (server_hello.extensions.size() > 0) {
            TlsReader ext_r(std::span<const uint8_t>(
                server_hello.extensions.data.data(), server_hello.extensions.len));
            while (ext_r.remaining() >= 4) {
                uint16_t ext_type = ext_r.read_u16();
                uint16_t ext_len = ext_r.read_u16();
                if (ext_type == static_cast<uint16_t>(ExtensionType::extended_master_secret)) {
                    use_ems = true;
                } else if (ext_type == static_cast<uint16_t>(ExtensionType::session_ticket)) {
                    server_will_send_ticket_ = true;
                    if (ext_len > 0) ext_r.read_bytes(ext_len);
                    continue;
                } else if (ext_type == static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation) && ext_len >= 4) {
                    // RFC 7301: ProtocolNameList with exactly one entry
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

        // Detect abbreviated handshake:
        // 1. Session ticket resumption (RFC 5077): we sent a ticket and server echoed
        //    back our session_id (or indicated via session_ticket extension)
        // 2. Session ID resumption (RFC 5246): server echoed our session_id
        bool resuming_ticket = !config_.session_ticket.empty() &&
            (server_will_send_ticket_ ||
             (ticket_session_id_.length > 0 &&
              server_hello.session_id == ticket_session_id_));
        bool resuming_id = config_.resume_session &&
            server_hello.session_id.length > 0 &&
            server_hello.session_id == config_.resume_session->session_id;
        bool resuming = resuming_ticket || resuming_id;

        // For ticket resumption, build a session_data from the ticket config
        session_data ticket_resume_data;
        if (resuming_ticket && config_.resume_session) {
            ticket_resume_data = *config_.resume_session;
            ticket_resume_data.cipher_suite = negotiated_suite_;
        } else if (resuming_ticket) {
            // Resuming via ticket without resume_session — shouldn't happen in normal flow,
            // but the master_secret etc. must come from somewhere (the server decrypts the ticket)
            // The client must have stored this data alongside the ticket.
        }

        const session_data& resume_data = resuming_ticket
            ? (config_.resume_session ? *config_.resume_session : ticket_resume_data)
            : (config_.resume_session ? *config_.resume_session : ticket_resume_data);

        // Collect any leftover bytes in the record (additional handshake messages)
        asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH> leftover;
        while (sh_r.remaining() > 0) {
            leftover.push_back(sh_r.read_u8());
        }

        // Phase 2: dispatch into templated continuation
        return dispatch_cipher_suite(negotiated_suite_, [&]<typename Traits>() {
            if (resuming)
                return handshake_abbreviated<Traits>(early_transcript, resume_data);
            return handshake_continue<Traits>(early_transcript, leftover, use_ems);
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
    std::string_view negotiated_protocol() const { return negotiated_protocol_; }
    const std::vector<uint8_t>& received_ticket() const { return received_ticket_; }
    const std::array<uint8_t, 48>& master_secret() const { return master_secret_; }

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
    constexpr tls_result<void> handshake_continue(
        const asn1::FixedVector<uint8_t, 4096>& early_bytes,
        const asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH>& leftover,
        bool use_ems = false)
    {
        using Hash = typename Traits::hash_type;

        // Initialize transcript with early bytes
        TranscriptHash<Hash> transcript;
        transcript.update(std::span<const uint8_t>(early_bytes.data.data(), early_bytes.len));

        // Handshake reader for message framing, seeded with leftover bytes
        handshake_reader<Transport> hs_reader(rio_);
        for (size_t i = 0; i < leftover.size(); ++i)
            hs_reader.buf.push_back(leftover[i]);

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
            } catch (const std::exception&) {
                return {tls_error::bad_certificate};
            } catch (...) {
                return {tls_error::bad_certificate};
            }
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

        // --- CertificateRequest (optional) or ServerHelloDone ---
        bool cert_requested = false;
        auto next_msg_res = hs_reader.next_message(transcript);
        if (!next_msg_res) return {next_msg_res.error};
        {
            TlsReader next_r(next_msg_res.value);
            auto hdr = read_handshake_header(next_r);
            if (hdr.type == HandshakeType::certificate_request) {
                cert_requested = true;
                // Parse CertificateRequest (we don't use the contents, just note it)
                read_certificate_request(next_r);

                // Now read ServerHelloDone
                auto shd_msg_res = hs_reader.next_message(transcript);
                if (!shd_msg_res) return {shd_msg_res.error};
                TlsReader shd_r(shd_msg_res.value);
                auto shd_hdr = read_handshake_header(shd_r);
                if (shd_hdr.type != HandshakeType::server_hello_done)
                    return {tls_error::unexpected_message};
            } else if (hdr.type == HandshakeType::server_hello_done) {
                // No CertificateRequest
            } else {
                return {tls_error::unexpected_message};
            }
        }

        // --- Send client Certificate immediately (if requested) ---
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
            write_certificate(ccert_w, client_cert_msg);
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
        write_client_key_exchange_ecdhe(cke_w, ecdh_res.value.cke);
        transcript.update(cke_w.data());
        auto cke_err = rio_.send_record(ContentType::handshake, cke_w.data());
        if (!cke_err) return {cke_err.error};

        // Save session hash for EMS derivation (transcript up to ClientKeyExchange)
        auto session_hash = transcript.current_hash();

        // --- Send CertificateVerify (if client cert was sent) ---
        if (sent_client_cert) {
            auto cv_hash = transcript.current_hash();

            CertificateVerify cv{};

            if (auto* rsa_key = std::get_if<rsa_private_key<rsa_num>>(&config_.client_private_key)) {
                // RSA client key: PKCS#1 v1.5 signature
                if constexpr (Hash::digest_size == 32) {
                    cv.algorithm = {HashAlgorithm::sha256, SignatureAlgorithm::rsa};
                } else {
                    cv.algorithm = {HashAlgorithm::sha384, SignatureAlgorithm::rsa};
                }

                auto sig = rsa_pkcs1_v1_5_sign<asn1::x509::rsa_num, Hash>(*rsa_key, cv_hash);
                auto sig_bytes = sig.value.to_bytes(std::endian::big);
                size_t mod_bytes = (rsa_key->n.bit_width() + 7) / 8;
                size_t offset = sig_bytes.size() - mod_bytes;
                for (size_t i = 0; i < mod_bytes; ++i)
                    cv.signature.push_back(sig_bytes[offset + i]);
            } else {
                // EC client key: ECDSA signature
                if constexpr (Hash::digest_size == 32) {
                    cv.algorithm = {HashAlgorithm::sha256, SignatureAlgorithm::ecdsa};
                } else {
                    cv.algorithm = {HashAlgorithm::sha384, SignatureAlgorithm::ecdsa};
                }

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
            write_certificate_verify(cv_w, cv);
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

        // --- Receive NewSessionTicket (RFC 5077) if server indicated support ---
        if (server_will_send_ticket_) {
            auto nst_rec = rio_.recv_record();
            if (!nst_rec) return {nst_rec.error};
            if (nst_rec.value.type != ContentType::handshake)
                return {tls_error::unexpected_message};

            auto nst_frag = std::span<const uint8_t>(
                nst_rec.value.fragment.data.data(), nst_rec.value.fragment.size());
            TlsReader nst_r(nst_frag);
            auto nst_hdr = read_handshake_header(nst_r);
            if (nst_hdr.type != HandshakeType::new_session_ticket)
                return {tls_error::unexpected_message};
            auto nst = read_new_session_ticket(nst_r);
            received_ticket_ = std::move(nst.ticket);
            transcript.update(nst_frag);
        }

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

        // Store session for future resumption
        if (config_.session_store && server_hello_session_id_.length > 0) {
            session_data sd;
            sd.session_id = server_hello_session_id_;
            sd.cipher_suite = negotiated_suite_;
            sd.master_secret = master_secret_;
            sd.use_extended_master_secret = use_ems;
            sd.negotiated_protocol = negotiated_protocol_;
            sd.ticket = received_ticket_;
            config_.session_store->store(sd);
        }

        handshake_complete_ = true;
        return {tls_error::ok};
    }

    // Abbreviated handshake for session resumption (RFC 5246 Section 7.4.1.2, RFC 5077)
    // Server sends [NewSessionTicket] → CCS → Finished first, then client sends CCS → Finished
    template <typename Traits>
    constexpr tls_result<void> handshake_abbreviated(
        const asn1::FixedVector<uint8_t, 4096>& early_bytes,
        const session_data& cached)
    {
        using Hash = typename Traits::hash_type;

        // Verify cipher suite matches cached session
        if (cached.cipher_suite != negotiated_suite_)
            return {tls_error::handshake_failure};

        // Reuse master secret from cached session
        master_secret_ = cached.master_secret;

        // Initialize transcript with ClientHello + ServerHello
        TranscriptHash<Hash> transcript;
        transcript.update(std::span<const uint8_t>(early_bytes.data.data(), early_bytes.len));

        // --- Receive optional NewSessionTicket (RFC 5077) then ChangeCipherSpec ---
        // The server MAY send a NewSessionTicket before CCS during abbreviated
        // handshake. We must handle both cases: NST+CCS or just CCS.
        {
            auto rec = rio_.recv_record();
            if (!rec) return {rec.error};

            if (rec.value.type == ContentType::handshake) {
                // Should be NewSessionTicket — process it, then read CCS
                auto nst_frag = std::span<const uint8_t>(
                    rec.value.fragment.data.data(), rec.value.fragment.size());
                TlsReader nst_r(nst_frag);
                auto nst_hdr = read_handshake_header(nst_r);
                if (nst_hdr.type != HandshakeType::new_session_ticket)
                    return {tls_error::unexpected_message};
                auto nst = read_new_session_ticket(nst_r);
                received_ticket_ = std::move(nst.ticket);
                transcript.update(nst_frag);

                // Now read CCS
                auto ccs_rec = rio_.recv_record();
                if (!ccs_rec) return {ccs_rec.error};
                if (ccs_rec.value.type != ContentType::change_cipher_spec)
                    return {tls_error::unexpected_message};
            } else if (rec.value.type != ContentType::change_cipher_spec) {
                return {tls_error::unexpected_message};
            }
        }

        // Derive fresh key block with new randoms
        auto params = get_cipher_suite_params(negotiated_suite_);
        auto kb = derive_key_block<Hash>(master_secret_, client_random_, server_random_, params);

        rio_.activate_read_cipher(kb, negotiated_suite_);

        // --- Receive server Finished (encrypted) ---
        auto expected_server_vd = compute_verify_data<Hash>(
            master_secret_, false, transcript.current_hash());

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

        if (server_fin.verify_data != expected_server_vd)
            return {tls_error::handshake_failure};

        // Add server Finished to transcript for client Finished computation
        transcript.update(std::span<const uint8_t>(
            sfin_rec.value.fragment.data.data(), sfin_rec.value.fragment.size()));

        // --- Send client ChangeCipherSpec ---
        std::array<uint8_t, 1> ccs = {CHANGE_CIPHER_SPEC_MESSAGE};
        auto ccs_err = rio_.send_record(ContentType::change_cipher_spec, ccs);
        if (!ccs_err) return {ccs_err.error};

        rio_.activate_write_cipher(kb, negotiated_suite_);

        // --- Send client Finished (encrypted) ---
        auto client_vd = compute_verify_data<Hash>(
            master_secret_, true, transcript.current_hash());
        Finished client_fin{};
        client_fin.verify_data = client_vd;
        TlsWriter<64> fin_w;
        write_finished(fin_w, client_fin);
        auto fin_err = rio_.send_record(ContentType::handshake, fin_w.data());
        if (!fin_err) return {fin_err.error};

        // Restore ALPN from cached session
        negotiated_protocol_ = cached.negotiated_protocol;

        handshake_complete_ = true;
        return {tls_error::ok};
    }
};

} // namespace tls
