#pragma once

#include <asn1/based.hpp>
#include <asn1/der/codegen.hpp>
#include <asn1/der/reader.hpp>
#include <asn1/der/writer.hpp>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace asn1::pem {

struct PemError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Block {
    std::string label;
    std::vector<uint8_t> der;
};

inline auto decode(std::string_view pem) -> Block {
    // Find -----BEGIN <label>-----
    constexpr std::string_view begin_prefix = "-----BEGIN ";
    constexpr std::string_view end_prefix = "-----END ";
    constexpr std::string_view dashes = "-----";

    auto begin_pos = pem.find(begin_prefix);
    if (begin_pos == std::string_view::npos)
        throw PemError{"missing BEGIN line"};

    auto label_start = begin_pos + begin_prefix.size();
    auto label_end = pem.find(dashes, label_start);
    if (label_end == std::string_view::npos)
        throw PemError{"malformed BEGIN line"};

    std::string label{pem.substr(label_start, label_end - label_start)};

    // Find the newline after BEGIN line
    auto content_start = pem.find('\n', label_end);
    if (content_start == std::string_view::npos)
        throw PemError{"missing content after BEGIN line"};
    ++content_start;

    // Find -----END <label>-----
    auto end_pos = pem.find(end_prefix, content_start);
    if (end_pos == std::string_view::npos)
        throw PemError{"missing END line"};

    auto b64_text = pem.substr(content_start, end_pos - content_start);

    // Strip whitespace from base64 text
    std::string b64_clean;
    b64_clean.reserve(b64_text.size());
    for (char c : b64_text) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
            b64_clean.push_back(c);
    }

    // Decode base64
    auto result = based::decode<based::base64, std::vector>(
        std::span<const char>{b64_clean.data(), b64_clean.size()});
    if (!result.has_value())
        throw PemError{"base64 decode failed"};

    // Convert vector<byte> to vector<uint8_t>
    auto& bytes = result.value();
    std::vector<uint8_t> der(bytes.size());
    for (std::size_t i = 0; i < bytes.size(); ++i)
        der[i] = static_cast<uint8_t>(bytes[i]);

    return Block{std::move(label), std::move(der)};
}

inline auto encode(std::string_view label, std::span<const uint8_t> der) -> std::string {
    // Convert uint8_t span to byte span for based
    std::vector<std::byte> bytes(der.size());
    for (std::size_t i = 0; i < der.size(); ++i)
        bytes[i] = static_cast<std::byte>(der[i]);

    auto b64 = based::encode<based::base64, std::basic_string>(
        std::span<const std::byte>{bytes.data(), bytes.size()});

    // Build PEM with 64-char line wrapping
    std::string result;
    result.reserve(b64.size() + label.size() * 2 + 40 + b64.size() / 64);

    result += "-----BEGIN ";
    result += label;
    result += "-----\n";

    for (std::size_t i = 0; i < b64.size(); i += 64) {
        auto chunk = std::string_view{b64}.substr(i, 64);
        result += chunk;
        result += '\n';
    }

    result += "-----END ";
    result += label;
    result += "-----\n";

    return result;
}

// --- Convenience: PEM ↔ typed values ---

template <auto M, std::size_t I>
auto decode_to(std::string_view pem,
               std::string_view expected_label = {}) -> der::Mapped<M, I> {
    auto block = decode(pem);
    if (!expected_label.empty() && block.label != expected_label)
        throw PemError{
            "expected PEM label \"" + std::string{expected_label} +
            "\" but got \"" + block.label + "\""};
    der::Reader r{block.der};
    return der::decode<M, I>(r);
}

template <auto M, std::size_t I>
auto encode_from(std::string_view label, const der::Mapped<M, I>& value) -> std::string {
    der::Writer w;
    der::encode<M, I>(w, value);
    auto der = std::move(w).finish();
    return encode(label, der);
}

} // namespace asn1::pem
