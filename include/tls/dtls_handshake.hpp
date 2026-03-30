/**
 * DTLS 1.2 handshake messages — RFC 6347 Section 4.2.
 *
 * DTLS adds:
 *   - HelloVerifyRequest (cookie exchange for DoS protection)
 *   - DTLS ClientHello (includes cookie field)
 *   - Fragment reassembly for handshake messages
 *
 * Reuses TLS 1.2 handshake message types (ServerHello, Certificate, etc.)
 * since their body format is identical.
 */

#pragma once

#include "dtls_record.hpp"
#include "handshake.hpp"
#include "record.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace tls {

// Maximum cookie size per RFC 6347 Section 4.2.1
inline constexpr size_t DTLS_MAX_COOKIE_LENGTH = 255;

// --- HelloVerifyRequest (RFC 6347 Section 4.2.1) ---

struct HelloVerifyRequest {
    ProtocolVersion server_version{};
    asn1::FixedVector<uint8_t, DTLS_MAX_COOKIE_LENGTH> cookie;
};

template <size_t Cap>
void write_hello_verify_request(
    TlsWriter<Cap>& w,
    uint16_t message_seq,
    const HelloVerifyRequest& msg)
{
    // Compute body length: version(2) + cookie_length(1) + cookie
    uint32_t body_len = 2 + 1 + static_cast<uint32_t>(msg.cookie.size());

    // DTLS handshake header (12 bytes): unfragmented
    write_dtls_handshake_header(w,
        HandshakeType::hello_verify_request,
        body_len, message_seq, 0, body_len);

    // Body
    w.write_u8(msg.server_version.major);
    w.write_u8(msg.server_version.minor);
    w.write_u8(static_cast<uint8_t>(msg.cookie.size()));
    w.write_bytes(std::span<const uint8_t>(msg.cookie.data.data(), msg.cookie.len));
}

inline HelloVerifyRequest read_hello_verify_request(TlsReader& r) {
    HelloVerifyRequest msg;
    msg.server_version.major = r.read_u8();
    msg.server_version.minor = r.read_u8();
    uint8_t cookie_len = r.read_u8();
    auto cookie_data = r.read_bytes(cookie_len);
    for (size_t i = 0; i < cookie_len; ++i)
        msg.cookie.push_back(cookie_data[i]);
    return msg;
}

// --- DTLS ClientHello (includes cookie field) ---
// Wire format: same as TLS ClientHello but with cookie after session_id.

struct DtlsClientHello {
    ProtocolVersion client_version;
    Random random;
    SessionId session_id;
    asn1::FixedVector<uint8_t, DTLS_MAX_COOKIE_LENGTH> cookie;
    asn1::FixedVector<CipherSuite, 32> cipher_suites;
    asn1::FixedVector<CompressionMethod, 4> compression_methods;
    asn1::FixedVector<uint8_t, 512> extensions;
};

template <size_t Cap>
void write_dtls_client_hello(
    TlsWriter<Cap>& w,
    uint16_t message_seq,
    const DtlsClientHello& msg)
{
    // Write header placeholder
    size_t hdr_pos = w.position();
    write_dtls_handshake_header(w,
        HandshakeType::client_hello,
        0, message_seq, 0, 0);  // placeholders

    size_t body_start = w.position();

    // ProtocolVersion
    w.write_u8(msg.client_version.major);
    w.write_u8(msg.client_version.minor);

    // Random
    w.write_bytes(msg.random);

    // SessionID
    w.write_u8(msg.session_id.length);
    w.write_bytes(std::span<const uint8_t>(msg.session_id.data.data(), msg.session_id.length));

    // Cookie (DTLS-specific)
    w.write_u8(static_cast<uint8_t>(msg.cookie.size()));
    if (msg.cookie.size() > 0)
        w.write_bytes(std::span<const uint8_t>(msg.cookie.data.data(), msg.cookie.len));

    // CipherSuites
    w.write_u16(static_cast<uint16_t>(msg.cipher_suites.size() * 2));
    for (size_t i = 0; i < msg.cipher_suites.size(); ++i)
        w.write_u16(static_cast<uint16_t>(msg.cipher_suites[i]));

    // CompressionMethods
    w.write_u8(static_cast<uint8_t>(msg.compression_methods.size()));
    for (size_t i = 0; i < msg.compression_methods.size(); ++i)
        w.write_u8(static_cast<uint8_t>(msg.compression_methods[i]));

    // Extensions
    if (msg.extensions.size() > 0)
        w.write_bytes(std::span<const uint8_t>(msg.extensions.data.data(), msg.extensions.len));

    // Backpatch lengths
    uint32_t body_len = static_cast<uint32_t>(w.position() - body_start);
    // Patch length field (offset 1 from header start, 3 bytes)
    w.patch_u24(hdr_pos + 1, body_len);
    // Patch fragment_length (offset 9 from header start, 3 bytes)
    w.patch_u24(hdr_pos + 9, body_len);
}

inline DtlsClientHello read_dtls_client_hello(TlsReader& r) {
    DtlsClientHello msg;

    msg.client_version.major = r.read_u8();
    msg.client_version.minor = r.read_u8();

    auto random_bytes = r.read_bytes(32);
    for (size_t i = 0; i < 32; ++i)
        msg.random[i] = random_bytes[i];

    msg.session_id.length = r.read_u8();
    if (msg.session_id.length > 32) throw "DtlsClientHello: session_id too long";
    auto sid = r.read_bytes(msg.session_id.length);
    for (size_t i = 0; i < msg.session_id.length; ++i)
        msg.session_id.data[i] = sid[i];

    // Cookie (DTLS-specific)
    uint8_t cookie_len = r.read_u8();
    if (cookie_len > 0) {
        auto cookie_data = r.read_bytes(cookie_len);
        for (size_t i = 0; i < cookie_len; ++i)
            msg.cookie.push_back(cookie_data[i]);
    }

    uint16_t suites_len = r.read_u16();
    size_t num_suites = suites_len / 2;
    for (size_t i = 0; i < num_suites; ++i)
        msg.cipher_suites.push_back(static_cast<CipherSuite>(r.read_u16()));

    uint8_t comp_len = r.read_u8();
    for (size_t i = 0; i < comp_len; ++i)
        msg.compression_methods.push_back(static_cast<CompressionMethod>(r.read_u8()));

    if (!r.at_end()) {
        uint16_t ext_len = r.read_u16();
        auto ext_data = r.read_bytes(ext_len);
        for (size_t i = 0; i < ext_len; ++i)
            msg.extensions.push_back(ext_data[i]);
    }

    return msg;
}

// --- DTLS handshake message writer helpers ---
// Wraps a TLS body in a DTLS handshake header (unfragmented).

template <size_t Cap>
void write_dtls_handshake_message(
    TlsWriter<Cap>& w,
    HandshakeType type,
    uint16_t message_seq,
    std::span<const uint8_t> body)
{
    uint32_t body_len = static_cast<uint32_t>(body.size());
    write_dtls_handshake_header(w, type, body_len, message_seq, 0, body_len);
    w.write_bytes(body);
}

// Serialize a ServerHello into a DTLS handshake message with DTLS header
template <size_t Cap>
void write_dtls_server_hello(TlsWriter<Cap>& w, uint16_t message_seq, const ServerHello& msg) {
    // Serialize body only (without TLS handshake header)
    TlsWriter<256> body_w;
    body_w.write_u8(msg.server_version.major);
    body_w.write_u8(msg.server_version.minor);
    body_w.write_bytes(msg.random);
    body_w.write_u8(msg.session_id.length);
    body_w.write_bytes(std::span<const uint8_t>(msg.session_id.data.data(), msg.session_id.length));
    body_w.write_u16(static_cast<uint16_t>(msg.cipher_suite));
    body_w.write_u8(static_cast<uint8_t>(msg.compression_method));
    if (msg.extensions.size() > 0)
        body_w.write_bytes(std::span<const uint8_t>(msg.extensions.data.data(), msg.extensions.len));

    write_dtls_handshake_message(w, HandshakeType::server_hello, message_seq, body_w.data());
}

// Wrap Certificate message body with DTLS handshake header
template <size_t Cap>
void write_dtls_certificate(TlsWriter<Cap>& w, uint16_t message_seq, const CertificateMessage& msg) {
    TlsWriter<32768> body_w;
    // Total certs length placeholder
    size_t certs_len_pos = body_w.position();
    body_w.write_u24(0);
    size_t certs_start = body_w.position();
    for (size_t i = 0; i < msg.certificate_list.size(); ++i) {
        auto& cert = msg.certificate_list[i];
        body_w.write_u24(static_cast<uint32_t>(cert.size()));
        body_w.write_bytes(std::span<const uint8_t>(cert.data.data(), cert.len));
    }
    body_w.patch_u24(certs_len_pos, static_cast<uint32_t>(body_w.position() - certs_start));
    write_dtls_handshake_message(w, HandshakeType::certificate, message_seq, body_w.data());
}

template <size_t Cap>
void write_dtls_server_key_exchange(TlsWriter<Cap>& w, uint16_t message_seq,
                                     const ServerKeyExchangeEcdhe& msg)
{
    TlsWriter<1024> body_w;
    body_w.write_u8(static_cast<uint8_t>(ECCurveType::named_curve));
    body_w.write_u16(static_cast<uint16_t>(msg.named_curve));
    body_w.write_u8(static_cast<uint8_t>(msg.public_key.size()));
    body_w.write_bytes(std::span<const uint8_t>(msg.public_key.data.data(), msg.public_key.len));
    body_w.write_u8(static_cast<uint8_t>(msg.sig_algorithm.hash));
    body_w.write_u8(static_cast<uint8_t>(msg.sig_algorithm.signature));
    body_w.write_u16(static_cast<uint16_t>(msg.signature.size()));
    body_w.write_bytes(std::span<const uint8_t>(msg.signature.data.data(), msg.signature.len));
    write_dtls_handshake_message(w, HandshakeType::server_key_exchange, message_seq, body_w.data());
}

template <size_t Cap>
void write_dtls_server_hello_done(TlsWriter<Cap>& w, uint16_t message_seq) {
    write_dtls_handshake_message(w, HandshakeType::server_hello_done, message_seq, {});
}

template <size_t Cap>
void write_dtls_certificate_request(TlsWriter<Cap>& w, uint16_t message_seq,
                                     const CertificateRequest& msg)
{
    TlsWriter<4096> body_w;
    body_w.write_u8(static_cast<uint8_t>(msg.certificate_types.size()));
    for (size_t i = 0; i < msg.certificate_types.size(); ++i)
        body_w.write_u8(msg.certificate_types[i]);
    body_w.write_u16(static_cast<uint16_t>(msg.supported_signature_algorithms.size() * 2));
    for (size_t i = 0; i < msg.supported_signature_algorithms.size(); ++i) {
        body_w.write_u8(static_cast<uint8_t>(msg.supported_signature_algorithms[i].hash));
        body_w.write_u8(static_cast<uint8_t>(msg.supported_signature_algorithms[i].signature));
    }
    // CA list (empty)
    body_w.write_u16(0);
    write_dtls_handshake_message(w, HandshakeType::certificate_request, message_seq, body_w.data());
}

template <size_t Cap>
void write_dtls_client_key_exchange(TlsWriter<Cap>& w, uint16_t message_seq,
                                     const ClientKeyExchangeEcdhe& msg)
{
    TlsWriter<256> body_w;
    body_w.write_u8(static_cast<uint8_t>(msg.public_key.size()));
    body_w.write_bytes(std::span<const uint8_t>(msg.public_key.data.data(), msg.public_key.len));
    write_dtls_handshake_message(w, HandshakeType::client_key_exchange, message_seq, body_w.data());
}

template <size_t Cap>
void write_dtls_certificate_verify(TlsWriter<Cap>& w, uint16_t message_seq,
                                    const CertificateVerify& msg)
{
    TlsWriter<1024> body_w;
    body_w.write_u8(static_cast<uint8_t>(msg.algorithm.hash));
    body_w.write_u8(static_cast<uint8_t>(msg.algorithm.signature));
    body_w.write_u16(static_cast<uint16_t>(msg.signature.size()));
    body_w.write_bytes(std::span<const uint8_t>(msg.signature.data.data(), msg.signature.len));
    write_dtls_handshake_message(w, HandshakeType::certificate_verify, message_seq, body_w.data());
}

template <size_t Cap>
void write_dtls_finished(TlsWriter<Cap>& w, uint16_t message_seq, const Finished& msg) {
    write_dtls_handshake_message(w, HandshakeType::finished, message_seq,
        std::span<const uint8_t>(msg.verify_data));
}

// Strip the DTLS cookie field from a ClientHello body to produce a
// TLS-compatible body for transcript hashing. The DTLS ClientHello body
// has a cookie_len+cookie between session_id and cipher_suites which
// TLS ClientHello does not. Both peers must agree on this for verify_data.
inline std::vector<uint8_t> strip_cookie_from_client_hello(std::span<const uint8_t> body) {
    std::vector<uint8_t> result;
    size_t pos = 0;
    // version(2) + random(32) = 34 bytes
    for (size_t i = 0; i < 34 && pos < body.size(); ++i)
        result.push_back(body[pos++]);
    // session_id_len(1) + session_id(N)
    if (pos >= body.size()) return result;
    uint8_t sid_len = body[pos];
    result.push_back(sid_len);
    pos++;
    for (size_t i = 0; i < sid_len && pos < body.size(); ++i)
        result.push_back(body[pos++]);
    // cookie_len(1) + cookie(M) — skip, write cookie_len=0
    if (pos >= body.size()) return result;
    uint8_t cookie_len = body[pos++];
    pos += cookie_len;
    result.push_back(0);
    // rest (cipher_suites, compression, extensions)
    while (pos < body.size())
        result.push_back(body[pos++]);
    return result;
}

} // namespace tls
