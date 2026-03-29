/**
 * TLS 1.2 record layer — RFC 5246 Section 6.2.
 *
 * Provides TlsReader/TlsWriter for big-endian binary serialization,
 * TlsRecord for framing, and record serialize/deserialize.
 *
 * Fully constexpr.
 */

#pragma once

#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <cstdint>
#include <optional>
#include <span>

namespace tls {

// RFC 5246 Section 6.2.1
inline constexpr size_t MAX_PLAINTEXT_LENGTH  = 16384;        // 2^14
inline constexpr size_t MAX_CIPHERTEXT_LENGTH = 16384 + 2048; // 2^14 + 2048
inline constexpr size_t RECORD_HEADER_LENGTH  = 5;            // type(1) + version(2) + length(2)

// A single TLS record
struct TlsRecord {
    ContentType type{};
    ProtocolVersion version{};
    asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> fragment;
};

// Binary reader for TLS wire format (big-endian, position-tracked).
// Throws on truncation (becomes a compile-time error in constexpr contexts).
class TlsReader {
    std::span<const uint8_t> data_;
    size_t pos_ = 0;

public:
    explicit constexpr TlsReader(std::span<const uint8_t> data) : data_(data) {}

    constexpr uint8_t read_u8() {
        if (pos_ >= data_.size()) throw "TlsReader: truncated read_u8";
        return data_[pos_++];
    }

    constexpr uint16_t read_u16() {
        if (pos_ + 2 > data_.size()) throw "TlsReader: truncated read_u16";
        uint16_t val = static_cast<uint16_t>(data_[pos_] << 8) | data_[pos_ + 1];
        pos_ += 2;
        return val;
    }

    constexpr uint32_t read_u24() {
        if (pos_ + 3 > data_.size()) throw "TlsReader: truncated read_u24";
        uint32_t val = (static_cast<uint32_t>(data_[pos_]) << 16) |
                       (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                       data_[pos_ + 2];
        pos_ += 3;
        return val;
    }

    constexpr std::span<const uint8_t> read_bytes(size_t n) {
        if (pos_ + n > data_.size()) throw "TlsReader: truncated read_bytes";
        auto result = data_.subspan(pos_, n);
        pos_ += n;
        return result;
    }

    constexpr void read_into(std::span<uint8_t> out) {
        auto src = read_bytes(out.size());
        for (size_t i = 0; i < out.size(); ++i)
            out[i] = src[i];
    }

    constexpr size_t remaining() const { return data_.size() - pos_; }
    constexpr size_t position() const { return pos_; }
    constexpr bool at_end() const { return pos_ >= data_.size(); }

    constexpr TlsReader sub_reader(size_t n) {
        auto span = read_bytes(n);
        return TlsReader(span);
    }
};

// Binary writer for TLS wire format.
template <size_t Cap>
class TlsWriter {
    asn1::FixedVector<uint8_t, Cap> buf_;

public:
    constexpr TlsWriter() = default;

    constexpr void write_u8(uint8_t v) {
        buf_.push_back(v);
    }

    constexpr void write_u16(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>(v >> 8));
        buf_.push_back(static_cast<uint8_t>(v));
    }

    constexpr void write_u24(uint32_t v) {
        buf_.push_back(static_cast<uint8_t>(v >> 16));
        buf_.push_back(static_cast<uint8_t>(v >> 8));
        buf_.push_back(static_cast<uint8_t>(v));
    }

    constexpr void write_bytes(std::span<const uint8_t> data) {
        for (size_t i = 0; i < data.size(); ++i)
            buf_.push_back(data[i]);
    }

    constexpr std::span<const uint8_t> data() const {
        return std::span<const uint8_t>(buf_.data.data(), buf_.len);
    }

    constexpr size_t size() const { return buf_.size(); }

    constexpr const asn1::FixedVector<uint8_t, Cap>& buffer() const { return buf_; }

    // Returns the current write position (useful for backpatching lengths)
    constexpr size_t position() const { return buf_.len; }

    // Overwrite a u16 at a previously-recorded position
    constexpr void patch_u16(size_t pos, uint16_t v) {
        buf_[pos]     = static_cast<uint8_t>(v >> 8);
        buf_[pos + 1] = static_cast<uint8_t>(v);
    }

    // Overwrite a u24 at a previously-recorded position
    constexpr void patch_u24(size_t pos, uint32_t v) {
        buf_[pos]     = static_cast<uint8_t>(v >> 16);
        buf_[pos + 1] = static_cast<uint8_t>(v >> 8);
        buf_[pos + 2] = static_cast<uint8_t>(v);
    }
};

// Serialize a TLS record to wire bytes
template <size_t Cap>
constexpr void write_record(TlsWriter<Cap>& w, const TlsRecord& rec) {
    w.write_u8(static_cast<uint8_t>(rec.type));
    w.write_u8(rec.version.major);
    w.write_u8(rec.version.minor);
    w.write_u16(static_cast<uint16_t>(rec.fragment.size()));
    w.write_bytes(std::span<const uint8_t>(rec.fragment.data.data(), rec.fragment.len));
}

// Deserialize a TLS record from wire bytes.
// Returns nullopt if the data is incomplete.
constexpr std::optional<TlsRecord> read_record(TlsReader& r) {
    if (r.remaining() < RECORD_HEADER_LENGTH)
        return std::nullopt;

    TlsRecord rec;
    rec.type = static_cast<ContentType>(r.read_u8());
    rec.version.major = r.read_u8();
    rec.version.minor = r.read_u8();
    uint16_t length = r.read_u16();

    if (r.remaining() < length)
        return std::nullopt;

    auto fragment = r.read_bytes(length);
    for (size_t i = 0; i < length; ++i)
        rec.fragment.push_back(fragment[i]);

    return rec;
}

} // namespace tls
