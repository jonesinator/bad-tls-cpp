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

namespace sha256_detail {

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

consteval uint32_t frac32(double x) {
    return static_cast<uint32_t>((x - static_cast<uint64_t>(x)) * double(1ULL << 32));
}

// First 32 bits of the fractional parts of the cube roots of the first 64 primes.
consteval std::array<uint32_t, 64> make_K() {
    std::array<uint32_t, 64> k{};
    for (int i = 0; i < 64; ++i)
        k[i] = frac32(cbrt(static_cast<double>(nth_prime(i + 1))));
    return k;
}

// First 32 bits of the fractional parts of the square roots of the first 8 primes.
consteval std::array<uint32_t, 8> make_H0() {
    std::array<uint32_t, 8> h{};
    for (int i = 0; i < 8; ++i)
        h[i] = frac32(sqrt(static_cast<double>(nth_prime(i + 1))));
    return h;
}

} // namespace sha256_detail

constexpr std::array<uint32_t, 64> sha256_K = sha256_detail::make_K();
constexpr std::array<uint32_t, 8> sha256_H0 = sha256_detail::make_H0();

struct sha256_state {
    static constexpr size_t block_size = 64;
    static constexpr size_t digest_size = 32;

    std::array<uint32_t, 8> h;
    std::array<uint8_t, 64> buffer;
    uint8_t buffer_len = 0;
    uint64_t total_len = 0;

    constexpr void init() noexcept {
        h = sha256_H0;
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
