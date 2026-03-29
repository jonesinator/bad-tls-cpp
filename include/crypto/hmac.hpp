/**
 * HMAC (RFC 2104) keyed-hash message authentication code.
 *
 * Templated on any hash type satisfying the hash_function concept.
 * Fully constexpr.
 */

#ifndef HMAC_HPP_
#define HMAC_HPP_

#include "hash_concept.hpp"
#include <array>
#include <cstdint>
#include <span>

template <hash_function Hash>
constexpr std::array<uint8_t, Hash::digest_size> hmac(
    std::span<const uint8_t> key,
    std::span<const uint8_t> message) noexcept
{
    constexpr size_t B = Hash::block_size;

    // If key > block_size, hash it first
    std::array<uint8_t, B> key_pad{};
    if (key.size() > B) {
        Hash kh;
        kh.init();
        kh.update(key);
        auto hashed = kh.finalize();
        for (size_t i = 0; i < hashed.size(); ++i)
            key_pad[i] = hashed[i];
    } else {
        for (size_t i = 0; i < key.size(); ++i)
            key_pad[i] = key[i];
    }

    // Inner hash: Hash((key XOR ipad) || message)
    std::array<uint8_t, B> ipad{};
    for (size_t i = 0; i < B; ++i)
        ipad[i] = key_pad[i] ^ 0x36;

    Hash inner;
    inner.init();
    inner.update(ipad);
    inner.update(message);
    auto inner_hash = inner.finalize();

    // Outer hash: Hash((key XOR opad) || inner_hash)
    std::array<uint8_t, B> opad{};
    for (size_t i = 0; i < B; ++i)
        opad[i] = key_pad[i] ^ 0x5C;

    Hash outer;
    outer.init();
    outer.update(opad);
    outer.update(inner_hash);
    return outer.finalize();
}

#endif /* HMAC_HPP_ */
