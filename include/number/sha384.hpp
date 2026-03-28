/**
 * FIPS 180-4 SHA-384 hash function.
 *
 * SHA-384 uses the SHA-512 compression function with different initial hash values
 * and output truncated to 384 bits. Fully constexpr.
 */

#ifndef SHA384_HPP_
#define SHA384_HPP_

#include "number.hpp"
#include <array>
#include <bit>
#include <cstdint>
#include <span>

namespace sha512_detail {

consteval bool is_prime(int n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (int i = 5; i * i <= n; i += 6)
        if (n % i == 0 || n % (i + 2) == 0) return false;
    return true;
}

consteval int nth_prime(int n) {
    int count = 0;
    for (int c = 2;; ++c)
        if (is_prime(c) && ++count == n) return c;
}

consteval double sqrt(double x) {
    double g = x / 2;
    for (int i = 0; i < 100; ++i)
        g = (g + x / g) / 2;
    return g;
}

consteval double cbrt(double x) {
    double g = x / 3;
    for (int i = 0; i < 100; ++i)
        g = (2 * g + x / (g * g)) / 3;
    return g;
}

// 256-bit integer for exact compile-time arithmetic.
using u256 = number<uint32_t, 8>;

consteval u256 from_u64(uint64_t v) {
    return (u256(static_cast<uint32_t>(v >> 32)) << 32) + u256(static_cast<uint32_t>(v));
}

consteval uint64_t to_u64(u256 v) {
    return static_cast<uint64_t>(v);
}

/**
 * Compute floor(sqrt(n) * 2^64) = isqrt(n * 2^128) exactly.
 */
consteval uint64_t frac64_sqrt(unsigned n) {
    u256 N = u256(n) << 128;

    // Initial guess from double (accurate to ~32 fractional bits)
    double d = sqrt(double(n));
    auto ip = static_cast<unsigned>(d);
    double frac = d - double(ip);
    auto frac_hi = static_cast<uint32_t>(frac * double(1ULL << 32));
    u256 x = (u256(ip) << 64) + (u256(frac_hi) << 32);

    // Newton: x = (x + N/x) / 2
    for (int i = 0; i < 2; ++i)
        x = (x + N / x) / u256(2U);

    // Exact correction
    while (x * x > N) x -= u256(1U);
    while ((x + u256(1U)) * (x + u256(1U)) <= N) x += u256(1U);

    // Extract fractional bits
    return to_u64(x - (u256(ip) << 64));
}

/**
 * Compute floor(cbrt(n) * 2^64) = icbrt(n * 2^192) exactly.
 */
consteval uint64_t frac64_cbrt(unsigned n) {
    u256 N = u256(n) << 192;

    // Initial guess from double
    double d = cbrt(double(n));
    auto ip = static_cast<unsigned>(d);
    double frac = d - double(ip);
    auto frac_hi = static_cast<uint32_t>(frac * double(1ULL << 32));
    u256 x = (u256(ip) << 64) + (u256(frac_hi) << 32);

    // Newton: x = (2*x + N/x^2) / 3
    for (int i = 0; i < 2; ++i)
        x = (u256(2U) * x + N / (x * x)) / u256(3U);

    // Exact correction
    while (x * x * x > N) x -= u256(1U);
    while ((x + u256(1U)) * (x + u256(1U)) * (x + u256(1U)) <= N) x += u256(1U);

    return to_u64(x - (u256(ip) << 64));
}

// First 64 bits of fractional parts of cube roots of the first 80 primes.
consteval std::array<uint64_t, 80> make_K() {
    std::array<uint64_t, 80> k{};
    for (int i = 0; i < 80; ++i)
        k[i] = frac64_cbrt(nth_prime(i + 1));
    return k;
}

// SHA-384 initial hash values: square roots of the 9th through 16th primes.
consteval std::array<uint64_t, 8> make_H0_384() {
    std::array<uint64_t, 8> h{};
    for (int i = 0; i < 8; ++i)
        h[i] = frac64_sqrt(nth_prime(i + 9));
    return h;
}

} // namespace sha512_detail

constexpr std::array<uint64_t, 80> sha512_K = sha512_detail::make_K();
constexpr std::array<uint64_t, 8> sha384_H0 = sha512_detail::make_H0_384();

// Verify derived constants against FIPS 180-4.
static_assert(sha512_K[0] == 0x428A2F98D728AE22);
static_assert(sha512_K[24] == 0x983E5152EE66DFAB);
static_assert(sha512_K[35] == 0x53380D139D95B3DF);
static_assert(sha512_K[79] == 0x6C44198C4A475817);
static_assert(sha384_H0[0] == 0xCBBB9D5DC1059ED8);
static_assert(sha384_H0[7] == 0x47B5481DBEFA4FA4);

struct sha384_state {
    static constexpr size_t block_size = 128;
    static constexpr size_t digest_size = 48;

    std::array<uint64_t, 8> h;
    std::array<uint8_t, 128> buffer;
    uint8_t buffer_len = 0;
    uint64_t total_len = 0;

    constexpr void init() noexcept {
        h = sha384_H0;
        buffer_len = 0;
        total_len = 0;
    }

    constexpr void update(std::span<const uint8_t> data) noexcept {
        total_len += data.size();

        size_t offset = 0;
        if (buffer_len > 0) {
            size_t space = 128 - buffer_len;
            size_t to_copy = data.size() < space ? data.size() : space;
            for (size_t i = 0; i < to_copy; ++i)
                buffer[buffer_len + i] = data[i];
            buffer_len += static_cast<uint8_t>(to_copy);
            offset = to_copy;

            if (buffer_len == 128) {
                compress(buffer.data());
                buffer_len = 0;
            }
        }

        while (offset + 128 <= data.size()) {
            compress(data.data() + offset);
            offset += 128;
        }

        for (size_t i = offset; i < data.size(); ++i)
            buffer[buffer_len++] = data[i];
    }

    constexpr std::array<uint8_t, 48> finalize() noexcept {
        uint64_t bit_len = total_len * 8;

        buffer[buffer_len++] = 0x80;

        if (buffer_len > 112) {
            while (buffer_len < 128)
                buffer[buffer_len++] = 0;
            compress(buffer.data());
            buffer_len = 0;
        }

        while (buffer_len < 112)
            buffer[buffer_len++] = 0;

        // 128-bit big-endian bit length (upper 64 bits zero for practical sizes)
        for (int i = 0; i < 8; ++i)
            buffer[buffer_len++] = 0;
        for (int i = 7; i >= 0; --i)
            buffer[buffer_len++] = static_cast<uint8_t>(bit_len >> (i * 8));

        compress(buffer.data());

        // Output first 6 of 8 hash words (384 bits = 48 bytes)
        std::array<uint8_t, 48> result{};
        for (int i = 0; i < 6; ++i) {
            result[i * 8 + 0] = static_cast<uint8_t>(h[i] >> 56);
            result[i * 8 + 1] = static_cast<uint8_t>(h[i] >> 48);
            result[i * 8 + 2] = static_cast<uint8_t>(h[i] >> 40);
            result[i * 8 + 3] = static_cast<uint8_t>(h[i] >> 32);
            result[i * 8 + 4] = static_cast<uint8_t>(h[i] >> 24);
            result[i * 8 + 5] = static_cast<uint8_t>(h[i] >> 16);
            result[i * 8 + 6] = static_cast<uint8_t>(h[i] >> 8);
            result[i * 8 + 7] = static_cast<uint8_t>(h[i]);
        }
        return result;
    }

private:
    constexpr void compress(const uint8_t* block) noexcept {
        std::array<uint64_t, 80> w{};
        for (int i = 0; i < 16; ++i)
            w[i] = (uint64_t(block[i * 8]) << 56) | (uint64_t(block[i * 8 + 1]) << 48) |
                   (uint64_t(block[i * 8 + 2]) << 40) | (uint64_t(block[i * 8 + 3]) << 32) |
                   (uint64_t(block[i * 8 + 4]) << 24) | (uint64_t(block[i * 8 + 5]) << 16) |
                   (uint64_t(block[i * 8 + 6]) << 8) | uint64_t(block[i * 8 + 7]);

        for (int i = 16; i < 80; ++i) {
            uint64_t s0 = std::rotr(w[i - 15], 1) ^ std::rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = std::rotr(w[i - 2], 19) ^ std::rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        auto [a, b, c, d, e, f, g, hh] = h;

        for (int i = 0; i < 80; ++i) {
            uint64_t S1 = std::rotr(e, 14) ^ std::rotr(e, 18) ^ std::rotr(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t temp1 = hh + S1 + ch + sha512_K[i] + w[i];
            uint64_t S0 = std::rotr(a, 28) ^ std::rotr(a, 34) ^ std::rotr(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;

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

#endif /* SHA384_HPP_ */
