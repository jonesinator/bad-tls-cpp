/**
 * FIPS 180-4 SHA-2 family: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
 *
 * Single template parameterized on <FullBits, TruncBits>:
 *   sha2_state<256>       = SHA-256
 *   sha2_state<256, 224>  = SHA-224
 *   sha2_state<512>       = SHA-512
 *   sha2_state<512, 384>  = SHA-384
 *   sha2_state<512, 224>  = SHA-512/224
 *   sha2_state<512, 256>  = SHA-512/256
 *
 * Fully constexpr — can be used at compile time.
 */

#ifndef SHA2_HPP_
#define SHA2_HPP_

#include "number.hpp"
#include <array>
#include <bit>
#include <cstdint>
#include <span>

namespace sha2_detail {

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

// 256-bit integer for exact compile-time fractional root computation.
using u256 = number<uint32_t, 8>;

consteval u256 from_u64(uint64_t v) {
    return (u256(static_cast<uint32_t>(v >> 32)) << 32) + u256(static_cast<uint32_t>(v));
}

consteval uint64_t to_u64(u256 v) {
    return static_cast<uint64_t>(v);
}

consteval double sqrt_approx(double x) {
    double g = x / 2;
    for (int i = 0; i < 100; ++i)
        g = (g + x / g) / 2;
    return g;
}

consteval double cbrt_approx(double x) {
    double g = x / 3;
    for (int i = 0; i < 100; ++i)
        g = (2 * g + x / (g * g)) / 3;
    return g;
}

// Compute floor(sqrt(n) * 2^64) = isqrt(n * 2^128) exactly.
consteval uint64_t frac64_sqrt(unsigned n) {
    u256 N = u256(n) << 128;
    double d = sqrt_approx(double(n));
    auto ip = static_cast<unsigned>(d);
    double frac = d - double(ip);
    auto frac_hi = static_cast<uint32_t>(frac * double(1ULL << 32));
    u256 x = (u256(ip) << 64) + (u256(frac_hi) << 32);
    for (int i = 0; i < 2; ++i)
        x = (x + N / x) / u256(2U);
    while (x * x > N) x -= u256(1U);
    while ((x + u256(1U)) * (x + u256(1U)) <= N) x += u256(1U);
    return to_u64(x - (u256(ip) << 64));
}

// Compute floor(cbrt(n) * 2^64) = icbrt(n * 2^192) exactly.
consteval uint64_t frac64_cbrt(unsigned n) {
    u256 N = u256(n) << 192;
    double d = cbrt_approx(double(n));
    auto ip = static_cast<unsigned>(d);
    double frac = d - double(ip);
    auto frac_hi = static_cast<uint32_t>(frac * double(1ULL << 32));
    u256 x = (u256(ip) << 64) + (u256(frac_hi) << 32);
    for (int i = 0; i < 2; ++i)
        x = (u256(2U) * x + N / (x * x)) / u256(3U);
    while (x * x * x > N) x -= u256(1U);
    while ((x + u256(1U)) * (x + u256(1U)) * (x + u256(1U)) <= N) x += u256(1U);
    return to_u64(x - (u256(ip) << 64));
}

// --- Core traits: rotation constants and word sizes ---

template <size_t FullBits> struct core;

template <> struct core<256> {
    using word_t = uint32_t;
    static constexpr int rounds = 64;
    static constexpr size_t block_bytes = 64;
    static constexpr int word_bytes = 4;
    // Message schedule: sigma0, sigma1
    static constexpr int s0r1 = 7,  s0r2 = 18, s0s = 3;
    static constexpr int s1r1 = 17, s1r2 = 19, s1s = 10;
    // Compression: Sigma0, Sigma1
    static constexpr int S0r1 = 2,  S0r2 = 13, S0r3 = 22;
    static constexpr int S1r1 = 6,  S1r2 = 11, S1r3 = 25;
};

template <> struct core<512> {
    using word_t = uint64_t;
    static constexpr int rounds = 80;
    static constexpr size_t block_bytes = 128;
    static constexpr int word_bytes = 8;
    static constexpr int s0r1 = 1,  s0r2 = 8,  s0s = 7;
    static constexpr int s1r1 = 19, s1r2 = 61, s1s = 6;
    static constexpr int S0r1 = 28, S0r2 = 34, S0r3 = 39;
    static constexpr int S1r1 = 14, S1r2 = 18, S1r3 = 41;
};

// --- K round constants ---

template <size_t FullBits>
consteval auto make_K() {
    using C = core<FullBits>;
    using word_t = typename C::word_t;
    std::array<word_t, C::rounds> k{};
    for (int i = 0; i < C::rounds; ++i) {
        uint64_t full = frac64_cbrt(nth_prime(i + 1));
        if constexpr (FullBits == 256)
            k[i] = static_cast<uint32_t>(full >> 32);
        else
            k[i] = full;
    }
    return k;
}

// --- Compression function (free, for use by both sha2_state and H0 generation) ---

template <size_t FullBits>
constexpr void compress(
    std::array<typename core<FullBits>::word_t, 8>& h,
    const uint8_t* block,
    const std::array<typename core<FullBits>::word_t, core<FullBits>::rounds>& K) noexcept
{
    using C = core<FullBits>;
    using word_t = typename C::word_t;

    std::array<word_t, C::rounds> w{};
    for (int i = 0; i < 16; ++i) {
        word_t val = 0;
        for (int j = 0; j < C::word_bytes; ++j)
            val = (val << 8) | word_t(block[i * C::word_bytes + j]);
        w[i] = val;
    }

    for (int i = 16; i < C::rounds; ++i) {
        word_t s0 = std::rotr(w[i-15], C::s0r1) ^ std::rotr(w[i-15], C::s0r2) ^ (w[i-15] >> C::s0s);
        word_t s1 = std::rotr(w[i-2], C::s1r1) ^ std::rotr(w[i-2], C::s1r2) ^ (w[i-2] >> C::s1s);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    auto [a, b, c, d, e, f, g, hh] = h;

    for (int i = 0; i < C::rounds; ++i) {
        word_t S1 = std::rotr(e, C::S1r1) ^ std::rotr(e, C::S1r2) ^ std::rotr(e, C::S1r3);
        word_t ch = (e & f) ^ (~e & g);
        word_t temp1 = hh + S1 + ch + K[i] + w[i];
        word_t S0 = std::rotr(a, C::S0r1) ^ std::rotr(a, C::S0r2) ^ std::rotr(a, C::S0r3);
        word_t maj = (a & b) ^ (a & c) ^ (b & c);
        word_t temp2 = S0 + maj;

        hh = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// --- Initial hash values ---

template <size_t FullBits, size_t TruncBits>
consteval auto make_H0() {
    static_assert(
        (FullBits == 256 && (TruncBits == 224 || TruncBits == 256)) ||
        (FullBits == 512 && (TruncBits == 224 || TruncBits == 256 ||
                             TruncBits == 384 || TruncBits == 512)),
        "unsupported SHA-2 variant");

    using word_t = typename core<FullBits>::word_t;
    std::array<word_t, 8> h{};

    if constexpr (FullBits == 256 && TruncBits == 256) {
        // First 32 bits of fractional parts of square roots of first 8 primes
        for (int i = 0; i < 8; ++i)
            h[i] = static_cast<uint32_t>(frac64_sqrt(nth_prime(i + 1)) >> 32);
    } else if constexpr (FullBits == 256 && TruncBits == 224) {
        // Second 32 bits of fractional parts of square roots of 9th-16th primes
        for (int i = 0; i < 8; ++i)
            h[i] = static_cast<uint32_t>(frac64_sqrt(nth_prime(i + 9)));
    } else if constexpr (FullBits == 512 && TruncBits == 512) {
        // First 64 bits of fractional parts of square roots of first 8 primes
        for (int i = 0; i < 8; ++i)
            h[i] = frac64_sqrt(nth_prime(i + 1));
    } else if constexpr (FullBits == 512 && TruncBits == 384) {
        // First 64 bits of fractional parts of square roots of 9th-16th primes
        for (int i = 0; i < 8; ++i)
            h[i] = frac64_sqrt(nth_prime(i + 9));
    } else if constexpr (FullBits == 512 && (TruncBits == 224 || TruncBits == 256)) {
        // FIPS 180-4 Section 5.3.6: SHA-512/t IV generation
        // Start with SHA-512 H0 XOR 0xa5a5a5a5a5a5a5a5
        for (int i = 0; i < 8; ++i)
            h[i] = frac64_sqrt(nth_prime(i + 1)) ^ 0xa5a5a5a5a5a5a5a5ULL;

        // Hash the ASCII string "SHA-512/224" or "SHA-512/256" (11 bytes, fits in one block)
        auto K = make_K<512>();
        std::array<uint8_t, 128> block{};
        block[0]='S'; block[1]='H'; block[2]='A'; block[3]='-';
        block[4]='5'; block[5]='1'; block[6]='2'; block[7]='/';
        if constexpr (TruncBits == 224) {
            block[8]='2'; block[9]='2'; block[10]='4';
        } else {
            block[8]='2'; block[9]='5'; block[10]='6';
        }
        constexpr size_t len = 11;
        block[len] = 0x80;
        // 128-bit big-endian bit length at end of block
        uint64_t bit_len = len * 8;
        for (int i = 7; i >= 0; --i)
            block[120 + (7 - i)] = static_cast<uint8_t>(bit_len >> (i * 8));

        compress<512>(h, block.data(), K);
    }

    return h;
}

} // namespace sha2_detail

// --- Global constants ---

template <size_t FullBits>
inline constexpr auto sha2_K = sha2_detail::make_K<FullBits>();

template <size_t FullBits, size_t TruncBits = FullBits>
inline constexpr auto sha2_H0 = sha2_detail::make_H0<FullBits, TruncBits>();

// Verify derived constants against FIPS 180-4.
static_assert(sha2_K<256>[0] == 0x428A2F98);
static_assert(sha2_K<256>[63] == 0xC67178F2);
static_assert(sha2_H0<256>[0] == 0x6A09E667);
static_assert(sha2_H0<256>[7] == 0x5BE0CD19);
static_assert(sha2_H0<256, 224>[0] == 0xC1059ED8);
static_assert(sha2_H0<256, 224>[7] == 0xBEFA4FA4);
static_assert(sha2_K<512>[0] == 0x428A2F98D728AE22);
static_assert(sha2_K<512>[24] == 0x983E5152EE66DFAB);
static_assert(sha2_K<512>[35] == 0x53380D139D95B3DF);
static_assert(sha2_K<512>[79] == 0x6C44198C4A475817);
static_assert(sha2_H0<512>[0] == 0x6A09E667F3BCC908);
static_assert(sha2_H0<512>[7] == 0x5BE0CD19137E2179);
static_assert(sha2_H0<512, 384>[0] == 0xCBBB9D5DC1059ED8);
static_assert(sha2_H0<512, 384>[7] == 0x47B5481DBEFA4FA4);
static_assert(sha2_H0<512, 256>[0] == 0x22312194FC2BF72C);
static_assert(sha2_H0<512, 256>[7] == 0x0EB72DDC81C52CA2);
static_assert(sha2_H0<512, 224>[0] == 0x8C3D37C819544DA2);
static_assert(sha2_H0<512, 224>[7] == 0x1112E6AD91D692A1);

// --- sha2_state template ---

template <size_t FullBits, size_t TruncBits = FullBits>
struct sha2_state {
    static_assert(
        (FullBits == 256 && (TruncBits == 224 || TruncBits == 256)) ||
        (FullBits == 512 && (TruncBits == 224 || TruncBits == 256 ||
                             TruncBits == 384 || TruncBits == 512)),
        "unsupported SHA-2 variant");

    using C = sha2_detail::core<FullBits>;
    using word_t = typename C::word_t;

    static constexpr size_t block_size = C::block_bytes;
    static constexpr size_t digest_size = TruncBits / 8;

    std::array<word_t, 8> h;
    std::array<uint8_t, C::block_bytes> buffer;
    uint8_t buffer_len = 0;
    uint64_t total_len = 0;

    constexpr void init() noexcept {
        h = sha2_H0<FullBits, TruncBits>;
        buffer_len = 0;
        total_len = 0;
    }

    constexpr void update(std::span<const uint8_t> data) noexcept {
        total_len += data.size();
        size_t offset = 0;

        if (buffer_len > 0) {
            size_t space = C::block_bytes - buffer_len;
            size_t to_copy = data.size() < space ? data.size() : space;
            for (size_t i = 0; i < to_copy; ++i)
                buffer[buffer_len + i] = data[i];
            buffer_len += static_cast<uint8_t>(to_copy);
            offset = to_copy;

            if (buffer_len == C::block_bytes) {
                compress(buffer.data());
                buffer_len = 0;
            }
        }

        while (offset + C::block_bytes <= data.size()) {
            compress(data.data() + offset);
            offset += C::block_bytes;
        }

        for (size_t i = offset; i < data.size(); ++i)
            buffer[buffer_len++] = data[i];
    }

    constexpr std::array<uint8_t, digest_size> finalize() noexcept {
        uint64_t bit_len = total_len * 8;
        constexpr size_t len_field = FullBits == 256 ? 8 : 16;
        constexpr size_t pad_threshold = C::block_bytes - len_field;

        buffer[buffer_len++] = 0x80;

        if (buffer_len > pad_threshold) {
            while (buffer_len < C::block_bytes)
                buffer[buffer_len++] = 0;
            compress(buffer.data());
            buffer_len = 0;
        }

        while (buffer_len < pad_threshold)
            buffer[buffer_len++] = 0;

        if constexpr (FullBits == 512) {
            // Upper 64 bits of 128-bit length (zero for practical sizes)
            for (int i = 0; i < 8; ++i)
                buffer[buffer_len++] = 0;
        }

        for (int i = 7; i >= 0; --i)
            buffer[buffer_len++] = static_cast<uint8_t>(bit_len >> (i * 8));

        compress(buffer.data());

        std::array<uint8_t, digest_size> result{};
        size_t pos = 0;
        for (int i = 0; i < 8 && pos < digest_size; ++i)
            for (int j = C::word_bytes - 1; j >= 0 && pos < digest_size; --j)
                result[pos++] = static_cast<uint8_t>(h[i] >> (j * 8));
        return result;
    }

private:
    constexpr void compress(const uint8_t* block) noexcept {
        sha2_detail::compress<FullBits>(h, block, sha2_K<FullBits>);
    }
};

// --- Type aliases ---

using sha224_state = sha2_state<256, 224>;
using sha256_state = sha2_state<256>;
using sha384_state = sha2_state<512, 384>;
using sha512_state = sha2_state<512>;
using sha512_224_state = sha2_state<512, 224>;
using sha512_256_state = sha2_state<512, 256>;

// --- Convenience one-shot functions ---

constexpr std::array<uint8_t, 28> sha224(std::span<const uint8_t> data) noexcept {
    sha224_state s; s.init(); s.update(data); return s.finalize();
}

constexpr std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) noexcept {
    sha256_state s; s.init(); s.update(data); return s.finalize();
}

constexpr std::array<uint8_t, 48> sha384(std::span<const uint8_t> data) noexcept {
    sha384_state s; s.init(); s.update(data); return s.finalize();
}

constexpr std::array<uint8_t, 64> sha512(std::span<const uint8_t> data) noexcept {
    sha512_state s; s.init(); s.update(data); return s.finalize();
}

constexpr std::array<uint8_t, 28> sha512_224(std::span<const uint8_t> data) noexcept {
    sha512_224_state s; s.init(); s.update(data); return s.finalize();
}

constexpr std::array<uint8_t, 32> sha512_256(std::span<const uint8_t> data) noexcept {
    sha512_256_state s; s.init(); s.update(data); return s.finalize();
}

#endif /* SHA2_HPP_ */
