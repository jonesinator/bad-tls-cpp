/**
 * TLS 1.2 PRF (RFC 5246 Section 5).
 *
 * PRF(secret, label, seed) = P_hash(secret, label || seed)
 * where P_hash iterates HMAC to produce arbitrary-length output.
 *
 * TLS 1.2 uses PRF with SHA-256 by default. Templated on any hash
 * satisfying the hash_function concept.
 *
 * Fully constexpr.
 */

#ifndef TLS_PRF_HPP_
#define TLS_PRF_HPP_

#include "hmac.hpp"
#include <array>
#include <cstdint>
#include <span>

/**
 * P_hash(secret, seed) — RFC 5246 Section 5.
 *
 * Produces L bytes of output by iterating HMAC:
 *   A(0) = seed
 *   A(i) = HMAC_hash(secret, A(i-1))
 *   P_hash = HMAC_hash(secret, A(1) || seed) ||
 *            HMAC_hash(secret, A(2) || seed) || ...
 */
template <hash_function THash, size_t L>
constexpr std::array<uint8_t, L> p_hash(
    std::span<const uint8_t> secret,
    std::span<const uint8_t> seed) noexcept
{
    constexpr size_t D = THash::digest_size;
    static_assert(L > 0, "Output length must be positive");

    std::array<uint8_t, L> output{};

    // A(1) = HMAC(secret, seed)
    auto a = hmac<THash>(secret, seed);

    size_t offset = 0;
    while (offset < L) {
        // HMAC(secret, A(i) || seed)
        // Build concatenation into a fixed buffer: A is D bytes, seed is variable.
        std::array<uint8_t, D + 256> buf{};
        size_t buf_len = 0;
        for (size_t j = 0; j < D; ++j)
            buf[buf_len++] = a[j];
        for (size_t j = 0; j < seed.size(); ++j)
            buf[buf_len++] = seed[j];

        auto p = hmac<THash>(secret, std::span<const uint8_t>(buf.data(), buf_len));

        for (size_t j = 0; j < D && offset < L; ++j)
            output[offset++] = p[j];

        // A(i+1) = HMAC(secret, A(i))
        a = hmac<THash>(secret, a);
    }

    return output;
}

/**
 * TLS 1.2 PRF — RFC 5246 Section 5.
 *
 * PRF(secret, label, seed) = P_hash(secret, label || seed)
 *
 * The label is an ASCII string (e.g., "master secret", "key expansion").
 * L is the number of output bytes (compile-time constant).
 */
template <hash_function THash, size_t L>
constexpr std::array<uint8_t, L> tls_prf(
    std::span<const uint8_t> secret,
    std::span<const uint8_t> label,
    std::span<const uint8_t> seed) noexcept
{
    // Concatenate label || seed
    // Labels are short ASCII strings (max ~24 bytes), seeds are 64 bytes max
    // (client_random + server_random = 32 + 32).
    std::array<uint8_t, 256> label_seed{};
    size_t ls_len = 0;
    for (size_t i = 0; i < label.size(); ++i)
        label_seed[ls_len++] = label[i];
    for (size_t i = 0; i < seed.size(); ++i)
        label_seed[ls_len++] = seed[i];

    return p_hash<THash, L>(secret, std::span<const uint8_t>(label_seed.data(), ls_len));
}

#endif /* TLS_PRF_HPP_ */
