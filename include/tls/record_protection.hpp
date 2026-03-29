/**
 * TLS 1.2 AES-GCM record protection — RFC 5288.
 *
 * Encrypts and decrypts TLS record payloads using AES-GCM with
 * per-record nonce construction and additional data per the spec.
 *
 * Fully constexpr.
 */

#pragma once

#include "record.hpp"
#include "types.hpp"
#include <crypto/gcm.hpp>
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace tls {

// RFC 5288 Section 3:
// nonce = fixed_iv(4) || explicit_nonce(8)
// The explicit nonce is the 64-bit sequence number.
constexpr std::array<uint8_t, 12> build_nonce(
    std::span<const uint8_t, 4> fixed_iv,
    uint64_t sequence_number)
{
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < 4; ++i)
        nonce[i] = fixed_iv[i];
    for (int i = 7; i >= 0; --i)
        nonce[4 + (7 - i)] = static_cast<uint8_t>(sequence_number >> (i * 8));
    return nonce;
}

// RFC 5246 Section 6.2.3.3:
// additional_data = seq_num(8) + type(1) + version(2) + length(2)
constexpr std::array<uint8_t, 13> build_additional_data(
    uint64_t sequence_number,
    ContentType type,
    ProtocolVersion version,
    uint16_t plaintext_length)
{
    std::array<uint8_t, 13> aad{};
    for (int i = 7; i >= 0; --i)
        aad[7 - i] = static_cast<uint8_t>(sequence_number >> (i * 8));
    aad[8]  = static_cast<uint8_t>(type);
    aad[9]  = version.major;
    aad[10] = version.minor;
    aad[11] = static_cast<uint8_t>(plaintext_length >> 8);
    aad[12] = static_cast<uint8_t>(plaintext_length);
    return aad;
}

// Encrypt a TLS record payload.
// Returns: explicit_nonce(8) || ciphertext(plaintext.size()) || tag(16)
template <block_cipher Cipher>
constexpr asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> encrypt_record(
    std::span<const uint8_t, Cipher::key_size> key,
    std::span<const uint8_t, 4> fixed_iv,
    uint64_t sequence_number,
    ContentType type,
    ProtocolVersion version,
    std::span<const uint8_t> plaintext)
{
    auto nonce = build_nonce(fixed_iv, sequence_number);
    auto aad = build_additional_data(sequence_number, type, version,
                                     static_cast<uint16_t>(plaintext.size()));

    // Output buffer: explicit_nonce(8) + ciphertext + tag(16)
    asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> result;

    // Write explicit nonce (last 8 bytes of the full nonce)
    for (size_t i = 4; i < 12; ++i)
        result.push_back(nonce[i]);

    // Expand result to hold ciphertext
    for (size_t i = 0; i < plaintext.size(); ++i)
        result.push_back(0);

    // Encrypt into the ciphertext portion (offset 8)
    std::span<uint8_t> ct_out(result.data.data() + 8, plaintext.size());
    auto tag = gcm_encrypt_rt<Cipher>(key, nonce, plaintext, aad, ct_out);

    // Append tag
    for (size_t i = 0; i < 16; ++i)
        result.push_back(tag[i]);

    return result;
}

// Decrypt a TLS record payload.
// Input: explicit_nonce(8) || ciphertext || tag(16)
// Returns plaintext, or nullopt on authentication failure.
template <block_cipher Cipher>
constexpr std::optional<asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH>> decrypt_record(
    std::span<const uint8_t, Cipher::key_size> key,
    std::span<const uint8_t, 4> fixed_iv,
    uint64_t sequence_number,
    ContentType type,
    ProtocolVersion version,
    std::span<const uint8_t> record_payload)
{
    // Minimum: explicit_nonce(8) + tag(16) = 24 bytes, zero-length plaintext
    if (record_payload.size() < 24)
        return std::nullopt;

    size_t ct_len = record_payload.size() - 8 - 16;

    // Reconstruct nonce from fixed_iv + explicit_nonce
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < 4; ++i)
        nonce[i] = fixed_iv[i];
    for (size_t i = 0; i < 8; ++i)
        nonce[4 + i] = record_payload[i];

    auto ciphertext = record_payload.subspan(8, ct_len);
    std::array<uint8_t, 16> tag{};
    for (size_t i = 0; i < 16; ++i)
        tag[i] = record_payload[8 + ct_len + i];

    auto aad = build_additional_data(sequence_number, type, version,
                                     static_cast<uint16_t>(ct_len));

    asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH> plaintext;
    for (size_t i = 0; i < ct_len; ++i)
        plaintext.push_back(0);

    std::span<uint8_t> pt_out(plaintext.data.data(), ct_len);
    bool ok = gcm_decrypt_rt<Cipher>(
        key, nonce, ciphertext, aad,
        std::span<const uint8_t, 16>(tag),
        pt_out);

    if (!ok) return std::nullopt;
    return plaintext;
}

} // namespace tls
