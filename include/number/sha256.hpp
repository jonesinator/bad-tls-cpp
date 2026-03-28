/**
 * FIPS 180-4 SHA-256 hash function.
 *
 * Provides both a streaming interface (sha256_state) and a one-shot convenience function (sha256).
 * Fully constexpr — can be used at compile time.
 */

#ifndef SHA256_HPP_
#define SHA256_HPP_

#include <array>
#include <bit>
#include <cstdint>
#include <span>

constexpr std::array<uint32_t, 64> sha256_K = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

struct sha256_state {
    std::array<uint32_t, 8> h;
    std::array<uint8_t, 64> buffer;
    uint8_t buffer_len = 0;
    uint64_t total_len = 0;

    constexpr void init() noexcept {
        h = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
        buffer_len = 0;
        total_len = 0;
    }

    constexpr void update(std::span<const uint8_t> data) noexcept {
        total_len += data.size();

        size_t offset = 0;
        // Fill buffer if partially full
        if (buffer_len > 0) {
            size_t space = 64 - buffer_len;
            size_t to_copy = data.size() < space ? data.size() : space;
            for (size_t i = 0; i < to_copy; ++i)
                buffer[buffer_len + i] = data[i];
            buffer_len += static_cast<uint8_t>(to_copy);
            offset = to_copy;

            if (buffer_len == 64) {
                compress(buffer.data());
                buffer_len = 0;
            }
        }

        // Process full blocks directly from input
        while (offset + 64 <= data.size()) {
            compress(data.data() + offset);
            offset += 64;
        }

        // Buffer remaining bytes
        for (size_t i = offset; i < data.size(); ++i)
            buffer[buffer_len++] = data[i];
    }

    constexpr std::array<uint8_t, 32> finalize() noexcept {
        uint64_t bit_len = total_len * 8;

        // Append 0x80
        buffer[buffer_len++] = 0x80;

        // If not enough room for the 8-byte length, pad and compress
        if (buffer_len > 56) {
            while (buffer_len < 64)
                buffer[buffer_len++] = 0;
            compress(buffer.data());
            buffer_len = 0;
        }

        // Pad with zeros up to length field
        while (buffer_len < 56)
            buffer[buffer_len++] = 0;

        // Append bit length as big-endian 64-bit
        for (int i = 7; i >= 0; --i)
            buffer[buffer_len++] = static_cast<uint8_t>(bit_len >> (i * 8));

        compress(buffer.data());

        // Produce output
        std::array<uint8_t, 32> result{};
        for (int i = 0; i < 8; ++i) {
            result[i * 4 + 0] = static_cast<uint8_t>(h[i] >> 24);
            result[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
            result[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
            result[i * 4 + 3] = static_cast<uint8_t>(h[i]);
        }
        return result;
    }

private:
    constexpr void compress(const uint8_t* block) noexcept {
        // Prepare message schedule
        std::array<uint32_t, 64> w{};
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
                   (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);

        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        auto [a, b, c, d, e, f, g, hh] = h;

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = hh + S1 + ch + sha256_K[i] + w[i];
            uint32_t S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
};

constexpr std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) noexcept {
    sha256_state s;
    s.init();
    s.update(data);
    return s.finalize();
}

#endif /* SHA256_HPP_ */
