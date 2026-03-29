/**
 * Cryptographic random number generation.
 *
 * Defines a random_generator concept and provides:
 *   - system_random: CSPRNG backed by std::random_device (runtime only)
 *   - xoshiro256ss: deterministic PRNG for constexpr testing (NOT cryptographic)
 *
 * Helper functions:
 *   - random_bytes<N>(rng): fill an array with random bytes
 *   - random_scalar<TCurve>(rng): generate a scalar in [1, n-1] for ECC
 */

#ifndef RANDOM_HPP_
#define RANDOM_HPP_

#include <array>
#include <concepts>
#include <cstdint>
#include <random>
#include <span>

// A random_generator can fill a span of bytes with random data.
template <typename R>
concept random_generator = requires(R r, std::span<uint8_t> buf) {
    { r.fill(buf) } -> std::same_as<void>;
};

// CSPRNG backed by std::random_device. Runtime only (not constexpr).
struct system_random {
    void fill(std::span<uint8_t> buf) {
        std::random_device rd;
        // random_device produces unsigned int values; extract bytes from each.
        for (size_t i = 0; i < buf.size(); ) {
            auto val = rd();
            for (size_t j = 0; j < sizeof(val) && i < buf.size(); ++j, ++i)
                buf[i] = static_cast<uint8_t>(val >> (j * 8));
        }
    }
};

// Deterministic PRNG based on xoshiro256** (Blackman & Vigna, 2018).
// Suitable for constexpr testing. NOT cryptographically secure.
struct xoshiro256ss {
    std::array<uint64_t, 4> state;

    explicit constexpr xoshiro256ss(uint64_t seed) noexcept {
        // SplitMix64 to initialize state from a single seed
        for (auto& s : state) {
            seed += 0x9E3779B97F4A7C15ULL;
            uint64_t z = seed;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            s = z ^ (z >> 31);
        }
    }

    constexpr uint64_t next() noexcept {
        auto rotl = [](uint64_t x, int k) -> uint64_t {
            return (x << k) | (x >> (64 - k));
        };
        uint64_t result = rotl(state[1] * 5, 7) * 9;
        uint64_t t = state[1] << 17;
        state[2] ^= state[0];
        state[3] ^= state[1];
        state[1] ^= state[2];
        state[0] ^= state[3];
        state[2] ^= t;
        state[3] = rotl(state[3], 45);
        return result;
    }

    constexpr void fill(std::span<uint8_t> buf) noexcept {
        size_t i = 0;
        while (i < buf.size()) {
            uint64_t val = next();
            for (size_t j = 0; j < 8 && i < buf.size(); ++j, ++i)
                buf[i] = static_cast<uint8_t>(val >> (j * 8));
        }
    }
};

// Fill an array with random bytes.
template <size_t N, random_generator R>
constexpr std::array<uint8_t, N> random_bytes(R& rng) {
    std::array<uint8_t, N> buf{};
    rng.fill(buf);
    return buf;
}

// Generate a random ECC scalar in [1, n-1] for the given curve.
// Uses rejection sampling: generate random bytes sized to the curve order,
// interpret as a number, reject if >= n or == 0.
template <typename TCurve, random_generator R>
constexpr typename TCurve::number_type random_scalar(R& rng) {
    using num = typename TCurve::number_type;
    auto n = TCurve::n();
    // Compute byte length of curve order (not the full number type width).
    size_t order_bytes = (n.bit_width() + 7) / 8;

    for (;;) {
        // Generate random bytes into a full-width array, but only fill order_bytes.
        std::array<uint8_t, num::num_bytes> buf{};
        // Place random bytes at the end (big-endian: leading zeros, then random).
        size_t offset = num::num_bytes - order_bytes;
        std::array<uint8_t, num::num_bytes> rand_buf{};
        rng.fill(std::span<uint8_t>(rand_buf.data(), order_bytes));
        for (size_t i = 0; i < order_bytes; ++i)
            buf[offset + i] = rand_buf[i];

        auto k = num::from_bytes(buf);
        if (k >= n || k == num(0U))
            continue;
        return k;
    }
}

static_assert(random_generator<system_random>);
static_assert(random_generator<xoshiro256ss>);

#endif /* RANDOM_HPP_ */
