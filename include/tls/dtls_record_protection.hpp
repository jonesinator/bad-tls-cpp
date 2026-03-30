/**
 * DTLS 1.2 AES-GCM record protection — RFC 6347 Section 4.1.2.
 *
 * DTLS uses the same AES-GCM encryption as TLS 1.2 but with a different
 * nonce and AAD construction that incorporates the epoch and 48-bit
 * sequence number.
 *
 * Also provides an anti-replay window per RFC 6347 Section 4.1.2.6.
 */

#pragma once

#include "dtls_record.hpp"
#include "record.hpp"
#include "types.hpp"
#include <crypto/gcm.hpp>
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace tls {

// RFC 6347: nonce = fixed_iv(4) || epoch(2) || sequence_number(6)
// The explicit nonce on the wire is epoch(2) || sequence_number(6) = 8 bytes.
constexpr std::array<uint8_t, 12> build_dtls_nonce(
    std::span<const uint8_t, 4> fixed_iv,
    uint16_t epoch,
    uint64_t sequence_number)
{
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < 4; ++i)
        nonce[i] = fixed_iv[i];
    nonce[4] = static_cast<uint8_t>(epoch >> 8);
    nonce[5] = static_cast<uint8_t>(epoch);
    for (int i = 5; i >= 0; --i)
        nonce[6 + (5 - i)] = static_cast<uint8_t>(sequence_number >> (i * 8));
    return nonce;
}

// RFC 6347 Section 4.1.2.1: AAD = epoch(2) + seq_num(6) + type(1) + version(2) + length(2)
// This is 13 bytes, same size as TLS but the first 8 bytes are epoch||seq_num(6)
// instead of seq_num(8).
constexpr std::array<uint8_t, 13> build_dtls_additional_data(
    uint16_t epoch,
    uint64_t sequence_number,
    ContentType type,
    ProtocolVersion version,
    uint16_t plaintext_length)
{
    std::array<uint8_t, 13> aad{};
    aad[0] = static_cast<uint8_t>(epoch >> 8);
    aad[1] = static_cast<uint8_t>(epoch);
    for (int i = 5; i >= 0; --i)
        aad[2 + (5 - i)] = static_cast<uint8_t>(sequence_number >> (i * 8));
    aad[8]  = static_cast<uint8_t>(type);
    aad[9]  = version.major;
    aad[10] = version.minor;
    aad[11] = static_cast<uint8_t>(plaintext_length >> 8);
    aad[12] = static_cast<uint8_t>(plaintext_length);
    return aad;
}

// Encrypt a DTLS record payload.
// Returns: explicit_nonce(8) || ciphertext(plaintext.size()) || tag(16)
template <block_cipher Cipher>
asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> dtls_encrypt_record(
    std::span<const uint8_t, Cipher::key_size> key,
    std::span<const uint8_t, 4> fixed_iv,
    uint16_t epoch,
    uint64_t sequence_number,
    ContentType type,
    ProtocolVersion version,
    std::span<const uint8_t> plaintext)
{
    auto nonce = build_dtls_nonce(fixed_iv, epoch, sequence_number);
    auto aad = build_dtls_additional_data(epoch, sequence_number, type, version,
                                          static_cast<uint16_t>(plaintext.size()));

    asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH> result;

    // Write explicit nonce (last 8 bytes of the full nonce: epoch + seq_num)
    for (size_t i = 4; i < 12; ++i)
        result.push_back(nonce[i]);

    // Expand result to hold ciphertext
    for (size_t i = 0; i < plaintext.size(); ++i)
        result.push_back(0);

    // Encrypt
    std::span<uint8_t> ct_out(result.data.data() + 8, plaintext.size());
    auto tag = gcm_encrypt_rt<Cipher>(key, nonce, plaintext, aad, ct_out);

    // Append tag
    for (size_t i = 0; i < 16; ++i)
        result.push_back(tag[i]);

    return result;
}

// Decrypt a DTLS record payload.
// Input: explicit_nonce(8) || ciphertext || tag(16)
template <block_cipher Cipher>
std::optional<asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH>> dtls_decrypt_record(
    std::span<const uint8_t, Cipher::key_size> key,
    std::span<const uint8_t, 4> fixed_iv,
    uint16_t epoch,
    uint64_t sequence_number,
    ContentType type,
    ProtocolVersion version,
    std::span<const uint8_t> record_payload)
{
    if (record_payload.size() < 24) return std::nullopt;

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

    auto aad = build_dtls_additional_data(epoch, sequence_number, type, version,
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

// Anti-replay window — RFC 6347 Section 4.1.2.6
// Sliding window of 64 sequence numbers.
struct replay_window {
    uint64_t max_seq = 0;
    uint64_t bitmap = 0;  // bit i set means (max_seq - i) has been received
    bool initialized = false;

    // Check if a sequence number is acceptable and mark it as received.
    // Returns true if the record should be accepted.
    bool check_and_update(uint64_t seq) {
        if (!initialized) {
            max_seq = seq;
            bitmap = 1;
            initialized = true;
            return true;
        }

        if (seq > max_seq) {
            uint64_t shift = seq - max_seq;
            if (shift >= 64)
                bitmap = 0;
            else
                bitmap <<= shift;
            bitmap |= 1;
            max_seq = seq;
            return true;
        }

        uint64_t diff = max_seq - seq;
        if (diff >= 64) return false;  // too old

        uint64_t mask = uint64_t{1} << diff;
        if (bitmap & mask) return false;  // duplicate
        bitmap |= mask;
        return true;
    }
};

} // namespace tls
