#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace asn1::der {

struct DecodeError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Integer {
    std::vector<uint8_t> bytes; // big-endian, minimal, signed two's complement

    auto to_int64() const -> int64_t {
        if (bytes.empty()) return 0;
        // Sign-extend from the MSB
        int64_t result = (bytes[0] & 0x80) ? -1 : 0;
        for (auto b : bytes)
            result = (result << 8) | b;
        return result;
    }

    static auto from_int64(int64_t v) -> Integer {
        Integer result;
        if (v == 0) {
            result.bytes.push_back(0);
            return result;
        }
        // Build all 8 bytes big-endian from two's complement
        uint64_t u = static_cast<uint64_t>(v);
        std::vector<uint8_t> tmp;
        for (int i = 7; i >= 0; --i)
            tmp.push_back(static_cast<uint8_t>((u >> (i * 8)) & 0xFF));

        // DER minimal encoding: strip redundant leading bytes
        // For positive: strip leading 0x00 unless next byte has high bit set
        // For negative: strip leading 0xFF unless next byte has high bit clear
        uint8_t pad = (v < 0) ? 0xFF : 0x00;
        while (tmp.size() > 1 && tmp[0] == pad) {
            bool next_sign = (tmp[1] & 0x80) != 0;
            // Keep this byte if removing it would change the sign
            if (v >= 0 && next_sign) break;   // need 0x00 to keep positive
            if (v < 0 && !next_sign) break;   // need 0xFF to keep negative
            tmp.erase(tmp.begin());
        }
        result.bytes = std::move(tmp);
        return result;
    }

    bool operator==(const Integer&) const = default;
};

struct Boolean {
    bool value = false;
    bool operator==(const Boolean&) const = default;
};

struct Null {
    bool operator==(const Null&) const = default;
};

struct BitString {
    std::vector<uint8_t> bytes;
    uint8_t unused_bits = 0;

    auto bit_count() const -> std::size_t {
        return bytes.size() * 8 - unused_bits;
    }

    bool operator==(const BitString&) const = default;
};

struct OctetString {
    std::vector<uint8_t> bytes;
    bool operator==(const OctetString&) const = default;
};

struct ObjectIdentifier {
    std::vector<uint32_t> components;

    auto to_string() const -> std::string {
        std::string result;
        for (std::size_t i = 0; i < components.size(); ++i) {
            if (i > 0) result += '.';
            result += std::to_string(components[i]);
        }
        return result;
    }

    static auto from_string(std::string_view sv) -> ObjectIdentifier {
        ObjectIdentifier oid;
        std::size_t pos = 0;
        while (pos < sv.size()) {
            auto dot = sv.find('.', pos);
            auto part = sv.substr(pos, dot == std::string_view::npos ? dot : dot - pos);
            uint32_t val = 0;
            for (char c : part) val = val * 10 + (c - '0');
            oid.components.push_back(val);
            pos = (dot == std::string_view::npos) ? sv.size() : dot + 1;
        }
        return oid;
    }

    bool operator==(const ObjectIdentifier&) const = default;
};

// Opaque DER blob for ANY DEFINED BY
struct AnyValue {
    std::vector<uint8_t> raw_tlv; // complete TLV including tag and length

    bool operator==(const AnyValue&) const = default;
};

} // namespace asn1::der
