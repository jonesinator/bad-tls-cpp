#pragma once

#include <asn1/der/tag.hpp>
#include <asn1/der/types.hpp>
#include <cstdint>
#include <span>
#include <vector>

namespace asn1::der {

class Writer {
    std::vector<uint8_t> buf_;

public:
    void write_tag(uint8_t class_bits, bool constructed, uint32_t number) {
        uint8_t first = class_bits;
        if (constructed) first |= Constructed;

        if (number < 31) {
            buf_.push_back(first | static_cast<uint8_t>(number));
        } else {
            buf_.push_back(first | 0x1F);
            // Multi-byte tag number in base-128
            write_base128(number);
        }
    }

    void write_length(std::size_t len) {
        if (len < 128) {
            buf_.push_back(static_cast<uint8_t>(len));
        } else {
            // Count bytes needed
            std::size_t tmp = len;
            uint8_t nbytes = 0;
            while (tmp > 0) { ++nbytes; tmp >>= 8; }
            buf_.push_back(0x80 | nbytes);
            for (int i = nbytes - 1; i >= 0; --i)
                buf_.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
        }
    }

    void write_bytes(std::span<const uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    // Constructed: serialize contents via callback, then write tag+length+contents
    template <typename F>
    void write_constructed(uint8_t tag_byte, F&& write_contents) {
        Writer inner;
        write_contents(inner);
        auto content = std::move(inner).finish();
        buf_.push_back(tag_byte);
        write_length(content.size());
        write_bytes(content);
    }

    // --- Primitive TLV encoders ---

    void write(const Integer& v) { write_integer_with_tag(TagInteger, v); }
    void write(const Integer& v, uint8_t tag) { write_integer_with_tag(tag, v); }

    void write(const Boolean& v) {
        buf_.push_back(TagBoolean);
        write_length(1);
        buf_.push_back(v.value ? 0xFF : 0x00);
    }

    void write(const Boolean& v, uint8_t tag) {
        buf_.push_back(tag);
        write_length(1);
        buf_.push_back(v.value ? 0xFF : 0x00);
    }

    void write(const Null&) {
        buf_.push_back(TagNull);
        write_length(0);
    }

    void write(const Null&, uint8_t tag) {
        buf_.push_back(tag);
        write_length(0);
    }

    void write(const BitString& v) { write_bitstring_with_tag(TagBitString, v); }
    void write(const BitString& v, uint8_t tag) { write_bitstring_with_tag(tag, v); }

    void write(const OctetString& v) { write_octetstring_with_tag(TagOctetString, v); }
    void write(const OctetString& v, uint8_t tag) { write_octetstring_with_tag(tag, v); }

    void write(const ObjectIdentifier& v) {
        write_oid_with_tag(TagOID, v);
    }
    void write(const ObjectIdentifier& v, uint8_t tag) {
        write_oid_with_tag(tag, v);
    }

    void write(const AnyValue& v) {
        // Copy raw TLV verbatim
        write_bytes(v.raw_tlv);
    }

    auto finish() && -> std::vector<uint8_t> { return std::move(buf_); }
    auto data() const -> std::span<const uint8_t> { return buf_; }

private:
    void write_base128(uint32_t value) {
        // Encode value in base-128, high bit set on all but last byte
        uint8_t tmp[5];
        int n = 0;
        tmp[n++] = value & 0x7F;
        value >>= 7;
        while (value > 0) {
            tmp[n++] = 0x80 | (value & 0x7F);
            value >>= 7;
        }
        // Write in reverse (MSB first)
        for (int i = n - 1; i >= 0; --i)
            buf_.push_back(tmp[i]);
    }

    void write_integer_with_tag(uint8_t tag, const Integer& v) {
        buf_.push_back(tag);
        write_length(v.bytes.size());
        write_bytes(v.bytes);
    }

    void write_bitstring_with_tag(uint8_t tag, const BitString& v) {
        buf_.push_back(tag);
        write_length(1 + v.bytes.size());
        buf_.push_back(v.unused_bits);
        write_bytes(v.bytes);
    }

    void write_octetstring_with_tag(uint8_t tag, const OctetString& v) {
        buf_.push_back(tag);
        write_length(v.bytes.size());
        write_bytes(v.bytes);
    }

    void write_oid_with_tag(uint8_t tag, const ObjectIdentifier& v) {
        // Encode OID content
        std::vector<uint8_t> content;
        if (v.components.size() >= 2) {
            // First two arcs encoded as 40*first + second
            uint32_t combined = 40 * v.components[0] + v.components[1];
            encode_oid_subid(content, combined);
            for (std::size_t i = 2; i < v.components.size(); ++i)
                encode_oid_subid(content, v.components[i]);
        } else if (v.components.size() == 1) {
            encode_oid_subid(content, 40 * v.components[0]);
        }
        buf_.push_back(tag);
        write_length(content.size());
        write_bytes(content);
    }

    static void encode_oid_subid(std::vector<uint8_t>& out, uint32_t value) {
        uint8_t tmp[5];
        int n = 0;
        tmp[n++] = value & 0x7F;
        value >>= 7;
        while (value > 0) {
            tmp[n++] = 0x80 | (value & 0x7F);
            value >>= 7;
        }
        for (int i = n - 1; i >= 0; --i)
            out.push_back(tmp[i]);
    }
};

} // namespace asn1::der
