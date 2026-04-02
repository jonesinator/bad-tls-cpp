/**
 * TLS 1.3 handshake message types and serialization — RFC 8446 Section 4.
 *
 * Structs and read/write functions for TLS 1.3-specific handshake messages:
 *   - EncryptedExtensions (Section 4.3.1)
 *   - Certificate with CertificateEntry list (Section 4.4.2)
 *   - CertificateVerify content construction (Section 4.4.3)
 *   - Finished with variable-length verify_data (Section 4.4.4)
 */

#pragma once

#include "handshake.hpp"
#include "record.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tls {

// --- EncryptedExtensions (RFC 8446 Section 4.3.1) ---

struct Tls13EncryptedExtensions {
    // Raw extension bytes for further parsing (ALPN, etc.)
    std::vector<uint8_t> extensions;
};

inline Tls13EncryptedExtensions read_tls13_encrypted_extensions(TlsReader& r) {
    Tls13EncryptedExtensions msg;
    uint16_t ext_len = r.read_u16();
    auto ext_data = r.read_bytes(ext_len);
    msg.extensions.assign(ext_data.begin(), ext_data.end());
    return msg;
}

template <size_t Cap>
constexpr void write_tls13_encrypted_extensions(
    TlsWriter<Cap>& w,
    std::span<const uint8_t> extensions)
{
    size_t hdr_pos = w.position();
    w.write_u8(static_cast<uint8_t>(HandshakeType::encrypted_extensions));
    w.write_u24(0); // placeholder

    size_t body_start = w.position();
    w.write_u16(static_cast<uint16_t>(extensions.size()));
    w.write_bytes(extensions);

    w.patch_u24(hdr_pos + 1, static_cast<uint32_t>(w.position() - body_start));
}

// Extract ALPN from EncryptedExtensions extension bytes.
inline std::string parse_alpn_from_extensions(std::span<const uint8_t> ext_data) {
    TlsReader r(ext_data);
    while (!r.at_end()) {
        auto ext_type = static_cast<ExtensionType>(r.read_u16());
        uint16_t ext_len = r.read_u16();
        if (ext_type == ExtensionType::application_layer_protocol_negotiation) {
            auto body = r.sub_reader(ext_len);
            uint16_t list_len = body.read_u16();
            (void)list_len;
            uint8_t proto_len = body.read_u8();
            auto proto_data = body.read_bytes(proto_len);
            return std::string(reinterpret_cast<const char*>(proto_data.data()), proto_len);
        }
        r.read_bytes(ext_len); // skip
    }
    return {};
}

// --- TLS 1.3 Certificate (RFC 8446 Section 4.4.2) ---

struct Tls13CertificateEntry {
    std::vector<uint8_t> cert_data;         // DER-encoded certificate
    std::vector<uint8_t> extensions;        // per-certificate extensions
};

struct Tls13CertificateMessage {
    std::vector<uint8_t> certificate_request_context;   // opaque<0..255>
    std::vector<Tls13CertificateEntry> entries;
};

inline Tls13CertificateMessage read_tls13_certificate(TlsReader& r) {
    Tls13CertificateMessage msg;

    uint8_t ctx_len = r.read_u8();
    if (ctx_len > 0) {
        auto ctx = r.read_bytes(ctx_len);
        msg.certificate_request_context.assign(ctx.begin(), ctx.end());
    }

    uint32_t list_len = r.read_u24();
    auto list_reader = r.sub_reader(list_len);

    while (!list_reader.at_end()) {
        Tls13CertificateEntry entry;
        uint32_t cert_len = list_reader.read_u24();
        auto cert_data = list_reader.read_bytes(cert_len);
        entry.cert_data.assign(cert_data.begin(), cert_data.end());

        uint16_t ext_len = list_reader.read_u16();
        if (ext_len > 0) {
            auto ext_data = list_reader.read_bytes(ext_len);
            entry.extensions.assign(ext_data.begin(), ext_data.end());
        }
        msg.entries.push_back(std::move(entry));
    }

    return msg;
}

template <size_t Cap>
void write_tls13_certificate(
    TlsWriter<Cap>& w,
    std::span<const uint8_t> request_context,
    std::span<const std::vector<uint8_t>> cert_chain)
{
    size_t hdr_pos = w.position();
    w.write_u8(static_cast<uint8_t>(HandshakeType::certificate));
    w.write_u24(0); // placeholder

    size_t body_start = w.position();

    // certificate_request_context
    w.write_u8(static_cast<uint8_t>(request_context.size()));
    w.write_bytes(request_context);

    // certificate_list
    size_t list_len_pos = w.position();
    w.write_u24(0); // placeholder
    size_t list_start = w.position();

    for (size_t i = 0; i < cert_chain.size(); ++i) {
        w.write_u24(static_cast<uint32_t>(cert_chain[i].size()));
        w.write_bytes(std::span<const uint8_t>(cert_chain[i]));
        w.write_u16(0); // no per-cert extensions
    }

    w.patch_u24(list_len_pos, static_cast<uint32_t>(w.position() - list_start));
    w.patch_u24(hdr_pos + 1, static_cast<uint32_t>(w.position() - body_start));
}

// --- CertificateVerify content (RFC 8446 Section 4.4.3) ---

// Builds the content to be signed/verified for CertificateVerify:
//   0x20 repeated 64 times || context_string || 0x00 || transcript_hash
//
// context_string is "TLS 1.3, server CertificateVerify" or
//                    "TLS 1.3, client CertificateVerify"
inline std::vector<uint8_t> build_tls13_certificate_verify_content(
    bool is_server,
    std::span<const uint8_t> transcript_hash)
{
    // 64 spaces + context string + NUL + transcript hash
    constexpr const char server_ctx[] = "TLS 1.3, server CertificateVerify";
    constexpr const char client_ctx[] = "TLS 1.3, client CertificateVerify";

    const char* ctx = is_server ? server_ctx : client_ctx;
    size_t ctx_len = 33; // both strings are 33 chars

    std::vector<uint8_t> content;
    content.reserve(64 + ctx_len + 1 + transcript_hash.size());

    // 64 spaces (0x20)
    for (size_t i = 0; i < 64; ++i)
        content.push_back(0x20);

    // Context string
    for (size_t i = 0; i < ctx_len; ++i)
        content.push_back(static_cast<uint8_t>(ctx[i]));

    // Separator
    content.push_back(0x00);

    // Transcript hash
    for (size_t i = 0; i < transcript_hash.size(); ++i)
        content.push_back(transcript_hash[i]);

    return content;
}

// Read CertificateVerify — wire format is identical to TLS 1.2:
// SignatureScheme (2 bytes) + signature length (2 bytes) + signature.
inline CertificateVerify read_tls13_certificate_verify(TlsReader& r) {
    CertificateVerify msg;
    msg.algorithm.hash = static_cast<HashAlgorithm>(r.read_u8());
    msg.algorithm.signature = static_cast<SignatureAlgorithm>(r.read_u8());
    uint16_t sig_len = r.read_u16();
    auto sig_data = r.read_bytes(sig_len);
    for (size_t i = 0; i < sig_len; ++i)
        msg.signature.push_back(sig_data[i]);
    return msg;
}

// Write CertificateVerify with handshake header.
template <size_t Cap>
void write_tls13_certificate_verify(TlsWriter<Cap>& w, const CertificateVerify& msg) {
    size_t hdr_pos = w.position();
    w.write_u8(static_cast<uint8_t>(HandshakeType::certificate_verify));
    w.write_u24(0); // placeholder

    size_t body_start = w.position();
    w.write_u8(static_cast<uint8_t>(msg.algorithm.hash));
    w.write_u8(static_cast<uint8_t>(msg.algorithm.signature));
    w.write_u16(static_cast<uint16_t>(msg.signature.size()));
    w.write_bytes(std::span<const uint8_t>(msg.signature.data.data(), msg.signature.len));

    w.patch_u24(hdr_pos + 1, static_cast<uint32_t>(w.position() - body_start));
}

// --- TLS 1.3 Finished (RFC 8446 Section 4.4.4) ---

// TLS 1.3 Finished has Hash.length bytes of verify_data (32 for SHA-256,
// 48 for SHA-384), unlike TLS 1.2's fixed 12 bytes.
struct Tls13Finished {
    std::vector<uint8_t> verify_data;
};

inline Tls13Finished read_tls13_finished(TlsReader& r, size_t hash_length) {
    Tls13Finished msg;
    auto data = r.read_bytes(hash_length);
    msg.verify_data.assign(data.begin(), data.end());
    return msg;
}

template <size_t Cap>
void write_tls13_finished(TlsWriter<Cap>& w, std::span<const uint8_t> verify_data) {
    w.write_u8(static_cast<uint8_t>(HandshakeType::finished));
    w.write_u24(static_cast<uint32_t>(verify_data.size()));
    w.write_bytes(verify_data);
}

} // namespace tls
