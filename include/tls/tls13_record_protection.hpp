/**
 * TLS 1.3 record protection — RFC 8446 Section 5.
 *
 * Implements per-record AEAD encryption and decryption for TLS 1.3.
 * Key differences from TLS 1.2:
 *   - Nonce: write_iv XOR padded sequence number (all ciphers)
 *   - AAD: 5-byte record header only (no sequence number)
 *   - Inner content type appended to plaintext before encryption
 *   - Outer record always says application_data / TLS 1.2 version
 *
 * Fully constexpr.
 */

#pragma once

#include "tls13_cipher_suite.hpp"
#include "record_protection.hpp"
#include "record.hpp"
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace tls {

// Result of decrypting a TLS 1.3 record: the real content type
// (extracted from inside the encrypted payload) and the plaintext.
struct Tls13DecryptedRecord {
    ContentType content_type;
    asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH> plaintext;
};

// RFC 8446 Section 5.3: nonce = write_iv XOR padded_sequence_number.
// Identical to the ChaCha20 nonce construction from TLS 1.2 (RFC 7905),
// but in TLS 1.3 this applies to ALL AEAD ciphers including AES-GCM.
constexpr std::array<uint8_t, 12> build_tls13_nonce(
    std::span<const uint8_t, 12> write_iv,
    uint64_t sequence_number)
{
    return build_chacha_nonce(write_iv, sequence_number);
}

// RFC 8446 Section 5.2: AAD is the 5-byte TLS record header.
// Content type is always application_data (0x17), version is always
// legacy TLS 1.2 (0x0303). Length is the encrypted record length
// (ciphertext + tag).
constexpr std::array<uint8_t, 5> build_tls13_additional_data(
    uint16_t record_length)
{
    return {
        static_cast<uint8_t>(ContentType::application_data),
        0x03, 0x03,
        static_cast<uint8_t>(record_length >> 8),
        static_cast<uint8_t>(record_length & 0xFF),
    };
}

// Encrypt a TLS 1.3 record.
//
// Builds inner plaintext (content || content_type), encrypts with the
// suite's AEAD, and returns ciphertext || tag.
//
// The caller is responsible for framing this into a TLS record with
// outer type application_data and version TLS 1.2.
template <typename Traits>
constexpr asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> tls13_encrypt_record(
    std::span<const uint8_t, Traits::key_length> key,
    std::span<const uint8_t, 12> write_iv,
    uint64_t sequence_number,
    ContentType inner_content_type,
    std::span<const uint8_t> plaintext)
{
    // Build inner plaintext: content || content_type(1)
    size_t inner_len = plaintext.size() + 1;
    asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH + 1> inner;
    for (size_t i = 0; i < plaintext.size(); ++i)
        inner.push_back(plaintext[i]);
    inner.push_back(static_cast<uint8_t>(inner_content_type));

    // Encrypted record length = inner plaintext length + tag
    auto record_length = static_cast<uint16_t>(inner_len + Traits::tag_length);
    auto aad = build_tls13_additional_data(record_length);
    auto nonce = build_tls13_nonce(write_iv, sequence_number);

    // Allocate output: ciphertext || tag
    asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> result;
    for (size_t i = 0; i < inner_len; ++i)
        result.push_back(0);

    std::span<uint8_t> ct_out(result.data.data(), inner_len);
    std::span<const uint8_t> inner_span(inner.data.data(), inner_len);

    auto tag = Traits::aead_encrypt(key, nonce, inner_span, aad, ct_out);

    for (size_t i = 0; i < 16; ++i)
        result.push_back(tag[i]);

    return result;
}

// Decrypt a TLS 1.3 record.
//
// Input: encrypted_record = ciphertext || tag (the record fragment,
// without the 5-byte header).
//
// Decrypts, extracts the inner content type (last non-zero byte),
// and returns the plaintext with its real content type.
//
// Returns nullopt on AEAD authentication failure or malformed inner
// plaintext (all zeros after decryption).
template <typename Traits>
constexpr std::optional<Tls13DecryptedRecord> tls13_decrypt_record(
    std::span<const uint8_t, Traits::key_length> key,
    std::span<const uint8_t, 12> write_iv,
    uint64_t sequence_number,
    std::span<const uint8_t> encrypted_record)
{
    // Minimum: tag only (zero-length inner plaintext is invalid —
    // need at least the content type byte)
    if (encrypted_record.size() < Traits::tag_length + 1)
        return std::nullopt;

    size_t ct_len = encrypted_record.size() - Traits::tag_length;
    auto ciphertext = encrypted_record.subspan(0, ct_len);
    std::array<uint8_t, 16> tag{};
    for (size_t i = 0; i < 16; ++i)
        tag[i] = encrypted_record[ct_len + i];

    auto record_length = static_cast<uint16_t>(encrypted_record.size());
    auto aad = build_tls13_additional_data(record_length);
    auto nonce = build_tls13_nonce(write_iv, sequence_number);

    // Decrypt into a temporary buffer
    asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH + 1> inner;
    for (size_t i = 0; i < ct_len; ++i)
        inner.push_back(0);

    std::span<uint8_t> pt_out(inner.data.data(), ct_len);
    bool ok = Traits::aead_decrypt(
        key, nonce, ciphertext, aad,
        std::span<const uint8_t, 16>(tag), pt_out);
    if (!ok) return std::nullopt;

    // Extract inner content type: scan backwards past zero padding
    // to find the last non-zero byte (the content type).
    size_t pos = ct_len;
    while (pos > 0 && inner.data[pos - 1] == 0)
        --pos;

    if (pos == 0)
        return std::nullopt; // All zeros — malformed

    auto content_type = static_cast<ContentType>(inner.data[pos - 1]);
    size_t plaintext_len = pos - 1;

    Tls13DecryptedRecord result;
    result.content_type = content_type;
    for (size_t i = 0; i < plaintext_len; ++i)
        result.plaintext.push_back(inner.data[i]);

    return result;
}

} // namespace tls
