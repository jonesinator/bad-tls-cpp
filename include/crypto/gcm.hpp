/**
 * GCM (Galois/Counter Mode) authenticated encryption — NIST SP 800-38D.
 *
 * Provides gcm_encrypt and gcm_decrypt, templated on any block cipher
 * satisfying the block_cipher concept (e.g., aes_state<128>).
 *
 * Fully constexpr — can be used at compile time.
 */

#ifndef GCM_HPP_
#define GCM_HPP_

#include "aes.hpp"
#include "block_cipher_concept.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <span>

static_assert(block_cipher<aes128>);
static_assert(block_cipher<aes192>);
static_assert(block_cipher<aes256>);

namespace gcm_detail {

// --- Helpers ---

constexpr void xor_block(std::array<uint8_t, 16>& a,
                         const std::array<uint8_t, 16>& b) noexcept {
    for (int i = 0; i < 16; ++i) a[i] ^= b[i];
}

// Increment the rightmost 32 bits of a 128-bit counter (big-endian).
constexpr void inc32(std::array<uint8_t, 16>& counter) noexcept {
    for (int i = 15; i >= 12; --i) {
        if (++counter[i] != 0) break;
    }
}

constexpr bool constant_time_equal(const std::array<uint8_t, 16>& a,
                                   const std::array<uint8_t, 16>& b) noexcept {
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

// --- GF(2^128) multiplication (SP 800-38D Algorithm 1) ---
// Bit-reflected convention: right-shift with R = 0xE1 || 0^120.

constexpr std::array<uint8_t, 16> gf128_mul(
    const std::array<uint8_t, 16>& X,
    const std::array<uint8_t, 16>& Y) noexcept
{
    std::array<uint8_t, 16> Z{};
    std::array<uint8_t, 16> V = Y;

    for (int i = 0; i < 128; ++i) {
        if ((X[i / 8] >> (7 - (i % 8))) & 1)
            xor_block(Z, V);
        bool lsb = V[15] & 1;
        for (int j = 15; j > 0; --j)
            V[j] = static_cast<uint8_t>((V[j] >> 1) | (V[j-1] << 7));
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xE1;
    }
    return Z;
}

// --- GHASH ---

// Process arbitrary-length data through GHASH state, zero-padding final partial block.
constexpr void ghash_update(std::array<uint8_t, 16>& state,
                            const std::array<uint8_t, 16>& H,
                            std::span<const uint8_t> data) noexcept
{
    size_t offset = 0;
    while (offset + 16 <= data.size()) {
        for (int i = 0; i < 16; ++i)
            state[i] ^= data[offset + i];
        state = gf128_mul(state, H);
        offset += 16;
    }
    // Handle partial final block (zero-padded)
    if (offset < data.size()) {
        size_t remaining = data.size() - offset;
        for (size_t i = 0; i < remaining; ++i)
            state[i] ^= data[offset + i];
        state = gf128_mul(state, H);
    }
}

// Full GHASH(H, A, C) per SP 800-38D Section 6.4:
// Process A (padded) || C (padded) || [len(A) in bits || len(C) in bits] as 64-bit BE.
constexpr std::array<uint8_t, 16> ghash(
    const std::array<uint8_t, 16>& H,
    std::span<const uint8_t> A,
    std::span<const uint8_t> C) noexcept
{
    std::array<uint8_t, 16> state{};
    ghash_update(state, H, A);
    ghash_update(state, H, C);

    // Length block: [len(A)*8 as 64-bit BE] || [len(C)*8 as 64-bit BE]
    uint64_t a_bits = A.size() * 8;
    uint64_t c_bits = C.size() * 8;
    std::array<uint8_t, 16> len_block{};
    for (int i = 7; i >= 0; --i) {
        len_block[7 - i] = static_cast<uint8_t>(a_bits >> (i * 8));
        len_block[15 - i] = static_cast<uint8_t>(c_bits >> (i * 8));
    }
    for (int i = 0; i < 16; ++i)
        state[i] ^= len_block[i];
    state = gf128_mul(state, H);

    return state;
}

// Compute J0 from IV (SP 800-38D Section 7.1).
constexpr std::array<uint8_t, 16> compute_j0(
    const std::array<uint8_t, 16>& H,
    std::span<const uint8_t> iv) noexcept
{
    std::array<uint8_t, 16> j0{};
    if (iv.size() == 12) {
        for (int i = 0; i < 12; ++i) j0[i] = iv[i];
        j0[15] = 0x01;
    } else {
        // GHASH over IV: process IV (padded) || 0^64 || [len(IV)*8 as 64-bit BE]
        ghash_update(j0, H, iv);
        uint64_t iv_bits = iv.size() * 8;
        std::array<uint8_t, 16> len_block{};
        for (int i = 7; i >= 0; --i)
            len_block[15 - i] = static_cast<uint8_t>(iv_bits >> (i * 8));
        for (int i = 0; i < 16; ++i)
            j0[i] ^= len_block[i];
        j0 = gf128_mul(j0, H);
    }
    return j0;
}

} // namespace gcm_detail

// --- GCM result type ---

template <size_t N>
struct gcm_result {
    std::array<uint8_t, N> ciphertext;
    std::array<uint8_t, 16> tag;
};

// --- GCM Encrypt (SP 800-38D Section 7.1) ---

template <block_cipher Cipher, size_t N>
constexpr gcm_result<N> gcm_encrypt(
    std::span<const uint8_t, Cipher::key_size> key,
    std::span<const uint8_t> iv,
    std::span<const uint8_t, N> plaintext,
    std::span<const uint8_t> aad) noexcept
{
    static_assert(Cipher::block_size == 16, "GCM requires a 128-bit block cipher");

    Cipher cipher;
    cipher.init(key);

    // H = E_K(0^128)
    std::array<uint8_t, 16> zero{};
    auto H = cipher.encrypt_block(zero);

    // J0 = initial counter
    auto j0 = gcm_detail::compute_j0(H, iv);

    // CTR encryption
    gcm_result<N> result{};
    auto counter = j0;
    size_t offset = 0;
    while (offset < N) {
        gcm_detail::inc32(counter);
        auto keystream = cipher.encrypt_block(counter);
        size_t block_len = (N - offset < 16) ? N - offset : 16;
        for (size_t i = 0; i < block_len; ++i)
            result.ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        offset += block_len;
    }

    // Tag = GHASH_H(AAD, CT) XOR E_K(J0)
    auto ghash_val = gcm_detail::ghash(H, aad,
        std::span<const uint8_t, N>(result.ciphertext));
    auto encrypted_j0 = cipher.encrypt_block(j0);
    gcm_detail::xor_block(ghash_val, encrypted_j0);
    result.tag = ghash_val;

    return result;
}

// --- GCM Decrypt (SP 800-38D Section 7.2) ---

template <block_cipher Cipher, size_t N>
constexpr std::optional<std::array<uint8_t, N>> gcm_decrypt(
    std::span<const uint8_t, Cipher::key_size> key,
    std::span<const uint8_t> iv,
    std::span<const uint8_t, N> ciphertext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, 16> tag) noexcept
{
    static_assert(Cipher::block_size == 16, "GCM requires a 128-bit block cipher");

    Cipher cipher;
    cipher.init(key);

    // H = E_K(0^128)
    std::array<uint8_t, 16> zero{};
    auto H = cipher.encrypt_block(zero);

    // J0 = initial counter
    auto j0 = gcm_detail::compute_j0(H, iv);

    // Verify tag first
    auto ghash_val = gcm_detail::ghash(H, aad, ciphertext);
    auto encrypted_j0 = cipher.encrypt_block(j0);
    gcm_detail::xor_block(ghash_val, encrypted_j0);

    std::array<uint8_t, 16> expected_tag{};
    for (int i = 0; i < 16; ++i) expected_tag[i] = tag[i];

    if (!gcm_detail::constant_time_equal(ghash_val, expected_tag))
        return std::nullopt;

    // CTR decryption (identical to encryption)
    std::array<uint8_t, N> plaintext{};
    auto counter = j0;
    size_t offset = 0;
    while (offset < N) {
        gcm_detail::inc32(counter);
        auto keystream = cipher.encrypt_block(counter);
        size_t block_len = (N - offset < 16) ? N - offset : 16;
        for (size_t i = 0; i < block_len; ++i)
            plaintext[offset + i] = ciphertext[offset + i] ^ keystream[i];
        offset += block_len;
    }

    return plaintext;
}

#endif /* GCM_HPP_ */
