/**
 * HMAC-SHA-256 (RFC 2104) keyed-hash message authentication code.
 *
 * Uses the streaming sha256_state to avoid allocating concatenated buffers.
 * Fully constexpr.
 */

#ifndef HMAC_SHA256_HPP_
#define HMAC_SHA256_HPP_

#include "sha256.hpp"
#include <array>
#include <cstdint>
#include <span>

constexpr std::array<uint8_t, 32> hmac_sha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> message) noexcept
{
    // If key > 64 bytes, hash it first
    std::array<uint8_t, 64> key_pad{};
    if (key.size() > 64) {
        auto hashed = sha256(key);
        for (size_t i = 0; i < 32; ++i)
            key_pad[i] = hashed[i];
    } else {
        for (size_t i = 0; i < key.size(); ++i)
            key_pad[i] = key[i];
    }
    // Remaining bytes of key_pad are already zero

    // Inner hash: SHA-256((key XOR ipad) || message)
    std::array<uint8_t, 64> ipad{};
    for (size_t i = 0; i < 64; ++i)
        ipad[i] = key_pad[i] ^ 0x36;

    sha256_state inner;
    inner.init();
    inner.update(ipad);
    inner.update(message);
    auto inner_hash = inner.finalize();

    // Outer hash: SHA-256((key XOR opad) || inner_hash)
    std::array<uint8_t, 64> opad{};
    for (size_t i = 0; i < 64; ++i)
        opad[i] = key_pad[i] ^ 0x5C;

    sha256_state outer;
    outer.init();
    outer.update(opad);
    outer.update(inner_hash);
    return outer.finalize();
}

#endif /* HMAC_SHA256_HPP_ */
