/**
 * ChaCha20 stream cipher — RFC 7539 Section 2.4.
 *
 * Provides the ChaCha20 quarter-round, block function, and encryption.
 * Uses a 256-bit key, 96-bit nonce, and 32-bit block counter.
 *
 * Also defines `chacha20_poly1305_cipher`, a marker type used by TLS
 * cipher suite traits (not a block_cipher — ChaCha20 is a stream cipher).
 *
 * Fully constexpr.
 */

#ifndef CHACHA20_HPP_
#define CHACHA20_HPP_

#include <array>
#include <cstdint>
#include <span>

// Marker type for TLS cipher suite traits. Not a block_cipher.
struct chacha20_poly1305_cipher {
    static constexpr size_t key_size = 32;
};

namespace chacha20_detail {

constexpr uint32_t rotl32(uint32_t v, unsigned n) noexcept {
    return (v << n) | (v >> (32 - n));
}

// RFC 7539 Section 2.1: quarter-round on four uint32_t values
constexpr void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

constexpr uint32_t le_load32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

constexpr void le_store32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

} // namespace chacha20_detail

/**
 * Generate one 64-byte ChaCha20 keystream block.
 *
 * @param key     256-bit key (32 bytes).
 * @param nonce   96-bit nonce (12 bytes).
 * @param counter 32-bit block counter.
 *
 * @returns 64 bytes of keystream.
 */
constexpr std::array<uint8_t, 64> chacha20_block(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    uint32_t counter) noexcept
{
    using namespace chacha20_detail;

    // Initialize state: constants + key + counter + nonce
    uint32_t state[16];
    state[0]  = 0x61707865;  // "expa"
    state[1]  = 0x3320646e;  // "nd 3"
    state[2]  = 0x79622d32;  // "2-by"
    state[3]  = 0x6b206574;  // "te k"
    state[4]  = le_load32(key.data());
    state[5]  = le_load32(key.data() + 4);
    state[6]  = le_load32(key.data() + 8);
    state[7]  = le_load32(key.data() + 12);
    state[8]  = le_load32(key.data() + 16);
    state[9]  = le_load32(key.data() + 20);
    state[10] = le_load32(key.data() + 24);
    state[11] = le_load32(key.data() + 28);
    state[12] = counter;
    state[13] = le_load32(nonce.data());
    state[14] = le_load32(nonce.data() + 4);
    state[15] = le_load32(nonce.data() + 8);

    // Working copy
    uint32_t w[16];
    for (int i = 0; i < 16; ++i) w[i] = state[i];

    // 20 rounds = 10 double-rounds
    for (int i = 0; i < 10; ++i) {
        // Column rounds
        quarter_round(w[0], w[4], w[8],  w[12]);
        quarter_round(w[1], w[5], w[9],  w[13]);
        quarter_round(w[2], w[6], w[10], w[14]);
        quarter_round(w[3], w[7], w[11], w[15]);
        // Diagonal rounds
        quarter_round(w[0], w[5], w[10], w[15]);
        quarter_round(w[1], w[6], w[11], w[12]);
        quarter_round(w[2], w[7], w[8],  w[13]);
        quarter_round(w[3], w[4], w[9],  w[14]);
    }

    // Add initial state back
    for (int i = 0; i < 16; ++i) w[i] += state[i];

    // Serialize as little-endian
    std::array<uint8_t, 64> out{};
    for (int i = 0; i < 16; ++i)
        le_store32(out.data() + i * 4, w[i]);

    return out;
}

/**
 * Encrypt (or decrypt) data with ChaCha20.
 *
 * XORs plaintext with the ChaCha20 keystream starting at the given counter.
 * Encryption and decryption are the same operation (XOR is its own inverse).
 *
 * @param key     256-bit key (32 bytes).
 * @param nonce   96-bit nonce (12 bytes).
 * @param counter Initial block counter (1 for AEAD payload, 0 for Poly1305 key gen).
 * @param input   Data to encrypt/decrypt.
 * @param output  Output buffer (same size as input).
 */
constexpr void chacha20_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    uint32_t counter,
    std::span<const uint8_t> input,
    std::span<uint8_t> output) noexcept
{
    size_t pos = 0;
    while (pos < input.size()) {
        auto block = chacha20_block(key, nonce, counter++);
        size_t remaining = input.size() - pos;
        size_t chunk = remaining < 64 ? remaining : 64;
        for (size_t i = 0; i < chunk; ++i)
            output[pos + i] = input[pos + i] ^ block[i];
        pos += chunk;
    }
}

#endif /* CHACHA20_HPP_ */
