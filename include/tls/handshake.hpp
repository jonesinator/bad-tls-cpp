/**
 * TLS 1.2 handshake message types and serialization — RFC 5246 Section 7.4, RFC 4492.
 *
 * Structs for all handshake messages and functions to serialize (write_*)
 * and deserialize (read_*) them. Client-sent messages get write functions;
 * server-sent messages get read functions; Finished gets both.
 *
 * Fully constexpr.
 */

#pragma once

#include "record.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <span>

namespace tls {

// --- Handshake header ---

struct HandshakeHeader {
    HandshakeType type;
    uint32_t length; // 24-bit on wire
};

constexpr HandshakeHeader read_handshake_header(TlsReader& r) {
    HandshakeHeader hdr;
    hdr.type = static_cast<HandshakeType>(r.read_u8());
    hdr.length = r.read_u24();
    return hdr;
}

template <size_t Cap>
constexpr void write_handshake_header(TlsWriter<Cap>& w, HandshakeType type, uint32_t length) {
    w.write_u8(static_cast<uint8_t>(type));
    w.write_u24(length);
}

// --- Message structs ---

struct ClientHello {
    ProtocolVersion client_version;
    Random random;
    SessionId session_id;
    asn1::FixedVector<CipherSuite, 32> cipher_suites;
    asn1::FixedVector<CompressionMethod, 4> compression_methods;
    // Extensions serialized as opaque bytes
    asn1::FixedVector<uint8_t, 512> extensions;
};

struct ServerHello {
    ProtocolVersion server_version;
    Random random;
    SessionId session_id;
    CipherSuite cipher_suite;
    CompressionMethod compression_method;
    asn1::FixedVector<uint8_t, 256> extensions;
};

struct CertificateMessage {
    asn1::FixedVector<asn1::FixedVector<uint8_t, 8192>, 8> certificate_list;
};

// RFC 4492 Section 5.4 — ServerKeyExchange for ECDHE
struct ServerKeyExchangeEcdhe {
    NamedCurve named_curve;
    asn1::FixedVector<uint8_t, 133> public_key; // 0x04 || x || y
    SignatureAndHashAlgorithm sig_algorithm;
    asn1::FixedVector<uint8_t, 512> signature;
};

struct ServerHelloDone {};

// RFC 4492 Section 5.7
struct ClientKeyExchangeEcdhe {
    asn1::FixedVector<uint8_t, 133> public_key;
};

struct CertificateVerify {
    SignatureAndHashAlgorithm algorithm;
    asn1::FixedVector<uint8_t, 512> signature;
};

struct Finished {
    std::array<uint8_t, 12> verify_data{};
};

// --- Extension helpers ---

// Build the mandatory ClientHello extensions for ECDHE:
//   - supported_groups (RFC 4492 Section 5.1.1)
//   - ec_point_formats (RFC 4492 Section 5.1.2)
//   - signature_algorithms (RFC 5246 Section 7.4.1.4.1)
template <size_t Cap>
constexpr void write_client_hello_extensions(
    TlsWriter<Cap>& w,
    std::span<const NamedCurve> curves,
    std::span<const SignatureAndHashAlgorithm> sig_algs)
{
    // We'll write extensions into the writer, prefixed with total extensions length.
    // Save position for the outer length, then patch it.
    size_t ext_list_pos = w.position();
    w.write_u16(0); // placeholder for total extensions length

    // supported_groups (type 10)
    {
        w.write_u16(static_cast<uint16_t>(ExtensionType::supported_groups));
        uint16_t data_len = static_cast<uint16_t>(2 + curves.size() * 2); // curve_list length prefix + curves
        w.write_u16(data_len);
        w.write_u16(static_cast<uint16_t>(curves.size() * 2));
        for (size_t i = 0; i < curves.size(); ++i)
            w.write_u16(static_cast<uint16_t>(curves[i]));
    }

    // ec_point_formats (type 11)
    {
        w.write_u16(static_cast<uint16_t>(ExtensionType::ec_point_formats));
        w.write_u16(2); // extension data length
        w.write_u8(1);  // formats length
        w.write_u8(static_cast<uint8_t>(ECPointFormat::uncompressed));
    }

    // signature_algorithms (type 13)
    {
        w.write_u16(static_cast<uint16_t>(ExtensionType::signature_algorithms));
        uint16_t data_len = static_cast<uint16_t>(2 + sig_algs.size() * 2);
        w.write_u16(data_len);
        w.write_u16(static_cast<uint16_t>(sig_algs.size() * 2));
        for (size_t i = 0; i < sig_algs.size(); ++i) {
            w.write_u8(static_cast<uint8_t>(sig_algs[i].hash));
            w.write_u8(static_cast<uint8_t>(sig_algs[i].signature));
        }
    }

    // Patch total extensions length
    uint16_t total = static_cast<uint16_t>(w.position() - ext_list_pos - 2);
    w.patch_u16(ext_list_pos, total);
}

// --- Serialization: ClientHello ---

template <size_t Cap>
constexpr void write_client_hello(TlsWriter<Cap>& w, const ClientHello& msg) {
    // Save position to backpatch handshake header length
    size_t hdr_pos = w.position();
    w.write_u8(static_cast<uint8_t>(HandshakeType::client_hello));
    w.write_u24(0); // placeholder

    size_t body_start = w.position();

    // ProtocolVersion
    w.write_u8(msg.client_version.major);
    w.write_u8(msg.client_version.minor);

    // Random (32 bytes)
    w.write_bytes(msg.random);

    // SessionID (length-prefixed with 1 byte)
    w.write_u8(msg.session_id.length);
    w.write_bytes(std::span<const uint8_t>(msg.session_id.data.data(), msg.session_id.length));

    // CipherSuites (length-prefixed with 2 bytes, each suite is 2 bytes)
    w.write_u16(static_cast<uint16_t>(msg.cipher_suites.size() * 2));
    for (size_t i = 0; i < msg.cipher_suites.size(); ++i)
        w.write_u16(static_cast<uint16_t>(msg.cipher_suites[i]));

    // CompressionMethods (length-prefixed with 1 byte)
    w.write_u8(static_cast<uint8_t>(msg.compression_methods.size()));
    for (size_t i = 0; i < msg.compression_methods.size(); ++i)
        w.write_u8(static_cast<uint8_t>(msg.compression_methods[i]));

    // Extensions (already serialized as opaque bytes)
    if (msg.extensions.size() > 0)
        w.write_bytes(std::span<const uint8_t>(msg.extensions.data.data(), msg.extensions.len));

    // Backpatch handshake length
    uint32_t body_len = static_cast<uint32_t>(w.position() - body_start);
    w.patch_u24(hdr_pos + 1, body_len);
}

// --- Deserialization: ServerHello ---

constexpr ServerHello read_server_hello(TlsReader& r) {
    ServerHello msg;

    msg.server_version.major = r.read_u8();
    msg.server_version.minor = r.read_u8();

    auto random_bytes = r.read_bytes(32);
    for (size_t i = 0; i < 32; ++i)
        msg.random[i] = random_bytes[i];

    msg.session_id.length = r.read_u8();
    if (msg.session_id.length > 32) throw "ServerHello: session_id too long";
    auto sid = r.read_bytes(msg.session_id.length);
    for (size_t i = 0; i < msg.session_id.length; ++i)
        msg.session_id.data[i] = sid[i];

    msg.cipher_suite = static_cast<CipherSuite>(r.read_u16());
    msg.compression_method = static_cast<CompressionMethod>(r.read_u8());

    // Extensions (if any remain)
    if (!r.at_end()) {
        uint16_t ext_len = r.read_u16();
        auto ext_data = r.read_bytes(ext_len);
        for (size_t i = 0; i < ext_len; ++i)
            msg.extensions.push_back(ext_data[i]);
    }

    return msg;
}

// --- Deserialization: Certificate ---

constexpr CertificateMessage read_certificate(TlsReader& r) {
    CertificateMessage msg;

    uint32_t total_len = r.read_u24();
    auto certs_reader = r.sub_reader(total_len);

    while (!certs_reader.at_end()) {
        uint32_t cert_len = certs_reader.read_u24();
        auto cert_data = certs_reader.read_bytes(cert_len);

        asn1::FixedVector<uint8_t, 8192> cert;
        for (size_t i = 0; i < cert_len; ++i)
            cert.push_back(cert_data[i]);
        msg.certificate_list.push_back(cert);
    }

    return msg;
}

// --- Deserialization: ServerKeyExchange (ECDHE) ---

constexpr ServerKeyExchangeEcdhe read_server_key_exchange_ecdhe(TlsReader& r) {
    ServerKeyExchangeEcdhe msg;

    uint8_t curve_type = r.read_u8();
    if (curve_type != static_cast<uint8_t>(ECCurveType::named_curve))
        throw "ServerKeyExchange: expected named_curve";

    msg.named_curve = static_cast<NamedCurve>(r.read_u16());

    uint8_t point_len = r.read_u8();
    auto point_data = r.read_bytes(point_len);
    for (size_t i = 0; i < point_len; ++i)
        msg.public_key.push_back(point_data[i]);

    msg.sig_algorithm.hash = static_cast<HashAlgorithm>(r.read_u8());
    msg.sig_algorithm.signature = static_cast<SignatureAlgorithm>(r.read_u8());

    uint16_t sig_len = r.read_u16();
    auto sig_data = r.read_bytes(sig_len);
    for (size_t i = 0; i < sig_len; ++i)
        msg.signature.push_back(sig_data[i]);

    return msg;
}

// --- Deserialization: ServerHelloDone ---

constexpr ServerHelloDone read_server_hello_done(TlsReader&) {
    return {};
}

// --- Serialization: ClientKeyExchange (ECDHE) ---

template <size_t Cap>
constexpr void write_client_key_exchange_ecdhe(TlsWriter<Cap>& w, const ClientKeyExchangeEcdhe& msg) {
    size_t hdr_pos = w.position();
    w.write_u8(static_cast<uint8_t>(HandshakeType::client_key_exchange));
    w.write_u24(0); // placeholder

    size_t body_start = w.position();

    // EC point length + point
    w.write_u8(static_cast<uint8_t>(msg.public_key.size()));
    w.write_bytes(std::span<const uint8_t>(msg.public_key.data.data(), msg.public_key.len));

    uint32_t body_len = static_cast<uint32_t>(w.position() - body_start);
    w.patch_u24(hdr_pos + 1, body_len);
}

// --- Serialization: CertificateVerify ---

template <size_t Cap>
constexpr void write_certificate_verify(TlsWriter<Cap>& w, const CertificateVerify& msg) {
    size_t hdr_pos = w.position();
    w.write_u8(static_cast<uint8_t>(HandshakeType::certificate_verify));
    w.write_u24(0);

    size_t body_start = w.position();

    w.write_u8(static_cast<uint8_t>(msg.algorithm.hash));
    w.write_u8(static_cast<uint8_t>(msg.algorithm.signature));
    w.write_u16(static_cast<uint16_t>(msg.signature.size()));
    w.write_bytes(std::span<const uint8_t>(msg.signature.data.data(), msg.signature.len));

    uint32_t body_len = static_cast<uint32_t>(w.position() - body_start);
    w.patch_u24(hdr_pos + 1, body_len);
}

// --- Serialization: Finished ---

template <size_t Cap>
constexpr void write_finished(TlsWriter<Cap>& w, const Finished& msg) {
    w.write_u8(static_cast<uint8_t>(HandshakeType::finished));
    w.write_u24(12);
    w.write_bytes(msg.verify_data);
}

// --- Deserialization: Finished ---

constexpr Finished read_finished(TlsReader& r) {
    Finished msg;
    auto data = r.read_bytes(12);
    for (size_t i = 0; i < 12; ++i)
        msg.verify_data[i] = data[i];
    return msg;
}

// --- Change Cipher Spec ---

inline constexpr uint8_t CHANGE_CIPHER_SPEC_MESSAGE = 1;

} // namespace tls
