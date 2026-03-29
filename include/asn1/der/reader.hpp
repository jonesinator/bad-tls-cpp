#pragma once

#include <asn1/der/tag.hpp>
#include <asn1/der/types.hpp>
#include <cstdint>
#include <span>
#include <vector>

namespace asn1::der {

struct TlvHeader {
    uint8_t class_bits = 0;
    bool constructed = false;
    uint32_t tag_number = 0;
    std::size_t length = 0;
    std::size_t header_size = 0;
};

class Reader {
    std::span<const uint8_t> data_;
    std::size_t pos_ = 0;

public:
    explicit Reader(std::span<const uint8_t> data) : data_{data} {}

    bool at_end() const { return pos_ >= data_.size(); }
    auto remaining() const -> std::size_t { return data_.size() - pos_; }
    auto position() const -> std::size_t { return pos_; }

    auto peek_header() const -> TlvHeader {
        if (pos_ >= data_.size())
            throw DecodeError{"unexpected end of data"};

        TlvHeader h;
        std::size_t p = pos_;

        uint8_t first = data_[p++];
        h.class_bits = first & 0xC0;
        h.constructed = (first & Constructed) != 0;

        if ((first & 0x1F) == 0x1F) {
            // Long-form tag number
            h.tag_number = 0;
            while (p < data_.size()) {
                uint8_t b = data_[p++];
                h.tag_number = (h.tag_number << 7) | (b & 0x7F);
                if (!(b & 0x80)) break;
            }
        } else {
            h.tag_number = first & 0x1F;
        }

        if (p >= data_.size())
            throw DecodeError{"unexpected end of data in tag"};

        uint8_t len_byte = data_[p++];
        if (len_byte < 0x80) {
            h.length = len_byte;
        } else if (len_byte == 0x80) {
            throw DecodeError{"indefinite length not supported in DER"};
        } else {
            uint8_t nbytes = len_byte & 0x7F;
            if (nbytes > 8)
                throw DecodeError{"length too large"};
            h.length = 0;
            for (uint8_t i = 0; i < nbytes; ++i) {
                if (p >= data_.size())
                    throw DecodeError{"unexpected end of data in length"};
                h.length = (h.length << 8) | data_[p++];
            }
        }

        h.header_size = p - pos_;
        return h;
    }

    bool peek_matches(uint8_t class_bits, bool constructed, uint32_t number) const {
        if (at_end()) return false;
        auto h = peek_header();
        return h.class_bits == class_bits &&
               h.constructed == constructed &&
               h.tag_number == number;
    }

    bool peek_matches(uint8_t class_bits, uint32_t number) const {
        if (at_end()) return false;
        auto h = peek_header();
        return h.class_bits == class_bits && h.tag_number == number;
    }

    auto read_header() -> TlvHeader {
        auto h = peek_header();
        pos_ += h.header_size;
        return h;
    }

    auto read_content(std::size_t length) -> std::span<const uint8_t> {
        if (pos_ + length > data_.size())
            throw DecodeError{"content extends past end of data"};
        auto result = data_.subspan(pos_, length);
        pos_ += length;
        return result;
    }

    auto scoped(std::size_t length) -> Reader {
        if (pos_ + length > data_.size())
            throw DecodeError{"scoped reader extends past end of data"};
        Reader sub{data_.subspan(pos_, length)};
        pos_ += length;
        return sub;
    }

    // --- Typed decoders ---

    auto read_integer() -> Integer {
        auto h = read_header();
        if (h.tag_number != TagInteger && h.tag_number != TagEnumerated)
            throw DecodeError{"expected INTEGER tag"};
        auto content = read_content(h.length);
        Integer result;
        result.bytes.assign(content.begin(), content.end());
        return result;
    }

    auto read_integer_implicit(uint8_t /*class_bits*/, uint32_t /*number*/) -> Integer {
        auto h = read_header();
        auto content = read_content(h.length);
        Integer result;
        result.bytes.assign(content.begin(), content.end());
        return result;
    }

    auto read_boolean() -> Boolean {
        auto h = read_header();
        if (h.tag_number != TagBoolean)
            throw DecodeError{"expected BOOLEAN tag"};
        auto content = read_content(h.length);
        if (h.length != 1)
            throw DecodeError{"BOOLEAN must be 1 byte"};
        return Boolean{content[0] != 0};
    }

    auto read_null() -> Null {
        auto h = read_header();
        if (h.tag_number != TagNull)
            throw DecodeError{"expected NULL tag"};
        if (h.length != 0)
            throw DecodeError{"NULL must have zero length"};
        return Null{};
    }

    auto read_bit_string() -> BitString {
        auto h = read_header();
        auto content = read_content(h.length);
        if (h.length < 1)
            throw DecodeError{"BIT STRING must have at least 1 byte"};
        BitString result;
        result.unused_bits = content[0];
        result.bytes.assign(content.begin() + 1, content.end());
        return result;
    }

    auto read_bit_string_implicit(uint8_t /*class_bits*/, uint32_t /*number*/) -> BitString {
        auto h = read_header();
        auto content = read_content(h.length);
        if (h.length < 1)
            throw DecodeError{"BIT STRING must have at least 1 byte"};
        BitString result;
        result.unused_bits = content[0];
        result.bytes.assign(content.begin() + 1, content.end());
        return result;
    }

    auto read_octet_string() -> OctetString {
        auto h = read_header();
        auto content = read_content(h.length);
        OctetString result;
        result.bytes.assign(content.begin(), content.end());
        return result;
    }

    auto read_octet_string_implicit(uint8_t /*class_bits*/, uint32_t /*number*/) -> OctetString {
        auto h = read_header();
        auto content = read_content(h.length);
        OctetString result;
        result.bytes.assign(content.begin(), content.end());
        return result;
    }

    auto read_oid() -> ObjectIdentifier {
        auto h = read_header();
        if (h.tag_number != TagOID)
            throw DecodeError{"expected OID tag"};
        auto content = read_content(h.length);
        return decode_oid_content(content);
    }

    auto read_any() -> AnyValue {
        auto start = pos_;
        auto h = read_header();
        read_content(h.length); // skip content
        AnyValue result;
        result.raw_tlv.assign(data_.begin() + start, data_.begin() + pos_);
        return result;
    }

    auto enter_sequence() -> Reader {
        auto h = read_header();
        if (h.class_bits != ClassUniversal || h.tag_number != 0x10)
            throw DecodeError{"expected SEQUENCE tag"};
        return scoped(h.length);
    }

    auto enter_set() -> Reader {
        auto h = read_header();
        if (h.class_bits != ClassUniversal || h.tag_number != 0x11)
            throw DecodeError{"expected SET tag"};
        return scoped(h.length);
    }

    auto enter_explicit_tag(uint8_t class_bits, uint32_t number) -> Reader {
        auto h = read_header();
        if (h.class_bits != class_bits || h.tag_number != number)
            throw DecodeError{"explicit tag mismatch"};
        return scoped(h.length);
    }

    auto enter_implicit_constructed(uint8_t /*class_bits*/, uint32_t /*number*/) -> Reader {
        auto h = read_header();
        return scoped(h.length);
    }

private:
    static auto decode_oid_content(std::span<const uint8_t> content) -> ObjectIdentifier {
        ObjectIdentifier oid;
        if (content.empty()) return oid;

        // Decode first subidentifier (encodes first two arcs: 40*a + b)
        std::size_t p = 0;
        uint32_t first_sub = 0;
        while (p < content.size()) {
            uint8_t b = content[p++];
            first_sub = (first_sub << 7) | (b & 0x7F);
            if (!(b & 0x80)) break;
        }
        if (first_sub < 40) {
            oid.components.push_back(0);
            oid.components.push_back(first_sub);
        } else if (first_sub < 80) {
            oid.components.push_back(1);
            oid.components.push_back(first_sub - 40);
        } else {
            oid.components.push_back(2);
            oid.components.push_back(first_sub - 80);
        }

        // Remaining subidentifiers
        while (p < content.size()) {
            uint32_t sub = 0;
            while (p < content.size()) {
                uint8_t b = content[p++];
                sub = (sub << 7) | (b & 0x7F);
                if (!(b & 0x80)) break;
            }
            oid.components.push_back(sub);
        }

        return oid;
    }
};

} // namespace asn1::der
