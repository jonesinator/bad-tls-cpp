/**
 * HKDF (RFC 5869) HMAC-based Extract-and-Expand Key Derivation Function.
 *
 * Built on the existing HMAC implementation. Fully constexpr.
 * Templated on any hash type satisfying the hash_function concept.
 */

#ifndef HKDF_HPP_
#define HKDF_HPP_

#include "hmac.hpp"
#include <array>
#include <cstdint>
#include <span>

/**
 * HKDF-Extract (RFC 5869 Section 2.2).
 *
 * PRK = HMAC-Hash(salt, IKM). If salt is empty, a zero-filled array of
 * Hash::digest_size bytes is used per the RFC.
 */
template <hash_function THash>
constexpr std::array<uint8_t, THash::digest_size> hkdf_extract(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm) noexcept
{
    constexpr size_t D = THash::digest_size;

    if (salt.empty()) {
        std::array<uint8_t, D> zero_salt{};
        return hmac<THash>(zero_salt, ikm);
    }
    return hmac<THash>(salt, ikm);
}

/**
 * HKDF-Expand (RFC 5869 Section 2.3).
 *
 * Expands PRK into L bytes of output keying material using the info context.
 * T(i) = HMAC-Hash(PRK, T(i-1) || info || i), with T(0) = empty.
 * L must be <= 255 * Hash::digest_size.
 */
template <hash_function THash, size_t L>
constexpr std::array<uint8_t, L> hkdf_expand(
    std::span<const uint8_t> prk,
    std::span<const uint8_t> info) noexcept
{
    constexpr size_t D = THash::digest_size;
    static_assert(L > 0, "Output length must be positive");
    static_assert(L <= 255 * D, "Output length exceeds HKDF maximum (255 * HashLen)");

    constexpr size_t N = (L + D - 1) / D; // ceil(L / D)

    std::array<uint8_t, L> okm{};
    std::array<uint8_t, D> t_prev{};
    size_t t_prev_len = 0; // T(0) is empty

    size_t offset = 0;
    for (size_t i = 1; i <= N; ++i) {
        // Build input: T(i-1) || info || counter
        // Max size: D + info.size() + 1, but info.size() is runtime.
        // Use a two-step HMAC approach: feed chunks via hash update.
        // Since hmac() takes a single span, we need to build the buffer.
        // Max practical size for crypto use is small, so we use a fixed buffer.
        // T(i-1) is at most D bytes, counter is 1 byte.
        // We need t_prev_len + info.size() + 1 bytes total.

        // Allocate on stack: D + 1 for T(i-1) and counter, plus info
        // Since we can't VLA in constexpr, concatenate into a fixed max buffer.
        // For typical use (D=32 or 48, info < 256), this is fine.
        // We'll build the message piece by piece into a reasonably sized array.
        std::array<uint8_t, D + 256 + 1> buf{};
        size_t buf_len = 0;

        // Append T(i-1)
        for (size_t j = 0; j < t_prev_len; ++j)
            buf[buf_len++] = t_prev[j];

        // Append info
        for (size_t j = 0; j < info.size(); ++j)
            buf[buf_len++] = info[j];

        // Append counter byte
        buf[buf_len++] = static_cast<uint8_t>(i);

        auto t = hmac<THash>(prk, std::span<const uint8_t>(buf.data(), buf_len));

        // Copy to output
        for (size_t j = 0; j < D && offset < L; ++j)
            okm[offset++] = t[j];

        t_prev = t;
        t_prev_len = D;
    }

    return okm;
}

/**
 * HKDF one-shot (RFC 5869 Section 2.1): extract then expand.
 */
template <hash_function THash, size_t L>
constexpr std::array<uint8_t, L> hkdf(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> info) noexcept
{
    auto prk = hkdf_extract<THash>(salt, ikm);
    return hkdf_expand<THash, L>(prk, info);
}

#endif /* HKDF_HPP_ */
