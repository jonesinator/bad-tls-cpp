/**
 * DTLS 1.2 record layer — RFC 6347 Section 4.1.
 *
 * Provides DtlsRecord for framing and serialize/deserialize functions.
 * DTLS records have a 13-byte header (vs. TLS's 5-byte header):
 *   type(1) + version(2) + epoch(2) + sequence_number(6) + length(2)
 *
 * Also provides the DTLS handshake header (12 bytes):
 *   type(1) + length(3) + message_seq(2) + fragment_offset(3) + fragment_length(3)
 */

#pragma once

#include "record.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <cstdint>
#include <optional>
#include <span>

namespace tls {

// RFC 6347 Section 4.1
inline constexpr size_t DTLS_RECORD_HEADER_LENGTH = 13;
inline constexpr size_t DTLS_HANDSHAKE_HEADER_LENGTH = 12;

// A single DTLS record
struct DtlsRecord {
    ContentType type{};
    ProtocolVersion version{};
    uint16_t epoch = 0;
    uint64_t sequence_number = 0;  // only lower 48 bits used on wire
    asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> fragment;
};

// DTLS handshake message header — RFC 6347 Section 4.2.2
struct DtlsHandshakeHeader {
    HandshakeType type{};
    uint32_t length = 0;           // 24-bit: total message length
    uint16_t message_seq = 0;      // handshake message sequence number
    uint32_t fragment_offset = 0;  // 24-bit
    uint32_t fragment_length = 0;  // 24-bit
};

// --- Record serialization ---

// Write a 48-bit (6-byte) sequence number in big-endian
template <size_t Cap>
constexpr void write_u48(TlsWriter<Cap>& w, uint64_t val) {
    w.write_u8(static_cast<uint8_t>((val >> 40) & 0xFF));
    w.write_u8(static_cast<uint8_t>((val >> 32) & 0xFF));
    w.write_u8(static_cast<uint8_t>((val >> 24) & 0xFF));
    w.write_u8(static_cast<uint8_t>((val >> 16) & 0xFF));
    w.write_u8(static_cast<uint8_t>((val >> 8) & 0xFF));
    w.write_u8(static_cast<uint8_t>(val & 0xFF));
}

constexpr uint64_t read_u48(TlsReader& r) {
    uint64_t val = 0;
    for (int i = 5; i >= 0; --i)
        val |= static_cast<uint64_t>(r.read_u8()) << (i * 8);
    return val;
}

template <size_t Cap>
constexpr void write_dtls_record(TlsWriter<Cap>& w, const DtlsRecord& rec) {
    w.write_u8(static_cast<uint8_t>(rec.type));
    w.write_u8(rec.version.major);
    w.write_u8(rec.version.minor);
    w.write_u16(rec.epoch);
    write_u48(w, rec.sequence_number);
    w.write_u16(static_cast<uint16_t>(rec.fragment.size()));
    w.write_bytes(std::span<const uint8_t>(rec.fragment.data.data(), rec.fragment.len));
}

constexpr std::optional<DtlsRecord> read_dtls_record(TlsReader& r) {
    if (r.remaining() < DTLS_RECORD_HEADER_LENGTH) return std::nullopt;

    DtlsRecord rec;
    rec.type = static_cast<ContentType>(r.read_u8());
    rec.version.major = r.read_u8();
    rec.version.minor = r.read_u8();
    rec.epoch = r.read_u16();
    rec.sequence_number = read_u48(r);
    uint16_t frag_len = r.read_u16();

    if (r.remaining() < frag_len) return std::nullopt;
    auto frag_data = r.read_bytes(frag_len);
    for (size_t i = 0; i < frag_len; ++i)
        rec.fragment.push_back(frag_data[i]);

    return rec;
}

// --- Handshake header serialization ---

template <size_t Cap>
constexpr void write_dtls_handshake_header(
    TlsWriter<Cap>& w,
    HandshakeType type,
    uint32_t length,
    uint16_t message_seq,
    uint32_t fragment_offset,
    uint32_t fragment_length)
{
    w.write_u8(static_cast<uint8_t>(type));
    w.write_u24(length);
    w.write_u16(message_seq);
    w.write_u24(fragment_offset);
    w.write_u24(fragment_length);
}

constexpr DtlsHandshakeHeader read_dtls_handshake_header(TlsReader& r) {
    DtlsHandshakeHeader hdr;
    hdr.type = static_cast<HandshakeType>(r.read_u8());
    hdr.length = r.read_u24();
    hdr.message_seq = r.read_u16();
    hdr.fragment_offset = r.read_u24();
    hdr.fragment_length = r.read_u24();
    return hdr;
}

} // namespace tls
