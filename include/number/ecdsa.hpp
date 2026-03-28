/**
 * ECDSA (Elliptic Curve Digital Signature Algorithm) sign and verify.
 *
 * Uses RFC 6979 deterministic k generation — no CSPRNG needed. Signatures are reproducible given
 * the same private key and message. Low-S normalization is applied by default for OpenSSL
 * compatibility.
 *
 * Templated on TCurve (e.g. p256<uint512>, secp256k1<uint512>).
 */

#ifndef ECDSA_HPP_
#define ECDSA_HPP_

#include "ecc.hpp"
#include "hmac_sha256.hpp"
#include "sha256.hpp"
#include <array>
#include <cstdint>
#include <span>

template <typename TCurve>
struct ecdsa_signature {
    typename TCurve::number_type r;
    typename TCurve::number_type s;
};

namespace ecdsa_detail {

/**
 * RFC 6979 Section 3.2: deterministic generation of k for ECDSA signing.
 */
template <typename TCurve>
constexpr typename TCurve::number_type rfc6979_k(
    const typename TCurve::number_type& private_key,
    const std::array<uint8_t, 32>& message_hash) noexcept
{
    using num = typename TCurve::number_type;
    const num n = TCurve::n();

    auto x_bytes = private_key.to_bytes(std::endian::big);
    // Truncate to 32 bytes (the low 32 of the big-endian representation)
    std::array<uint8_t, 32> x{};
    for (size_t i = 0; i < 32; ++i)
        x[i] = x_bytes[x_bytes.size() - 32 + i];

    // Step (a): h1 = message_hash (already provided)

    // Step (b): V = 0x01 repeated 32 times
    std::array<uint8_t, 32> V{};
    for (auto& b : V) b = 0x01;

    // Step (c): K = 0x00 repeated 32 times
    std::array<uint8_t, 32> K{};

    // Step (d): K = HMAC(K, V || 0x00 || x || h1)
    {
        std::array<uint8_t, 97> data{};
        for (size_t i = 0; i < 32; ++i) data[i] = V[i];
        data[32] = 0x00;
        for (size_t i = 0; i < 32; ++i) data[33 + i] = x[i];
        for (size_t i = 0; i < 32; ++i) data[65 + i] = message_hash[i];
        K = hmac_sha256(K, data);
    }

    // Step (e): V = HMAC(K, V)
    V = hmac_sha256(K, V);

    // Step (f): K = HMAC(K, V || 0x01 || x || h1)
    {
        std::array<uint8_t, 97> data{};
        for (size_t i = 0; i < 32; ++i) data[i] = V[i];
        data[32] = 0x01;
        for (size_t i = 0; i < 32; ++i) data[33 + i] = x[i];
        for (size_t i = 0; i < 32; ++i) data[65 + i] = message_hash[i];
        K = hmac_sha256(K, data);
    }

    // Step (g): V = HMAC(K, V)
    V = hmac_sha256(K, V);

    // Step (h): generate k
    for (;;) {
        V = hmac_sha256(K, V);
        auto candidate = num::from_bytes(std::span<const uint8_t>(V.data(), 32), std::endian::big);
        if (candidate != num(0U) && candidate < n) {
            return candidate;
        }

        // Retry: K = HMAC(K, V || 0x00), V = HMAC(K, V)
        std::array<uint8_t, 33> retry_data{};
        for (size_t i = 0; i < 32; ++i) retry_data[i] = V[i];
        retry_data[32] = 0x00;
        K = hmac_sha256(K, retry_data);
        V = hmac_sha256(K, V);
    }
}

} // namespace ecdsa_detail

/**
 * Sign a pre-hashed message using ECDSA with RFC 6979 deterministic k.
 *
 * @param private_key The signer's private key scalar d.
 * @param message_hash The SHA-256 hash of the message to sign.
 * @returns The ECDSA signature (r, s) with low-S normalization.
 */
template <typename TCurve>
constexpr ecdsa_signature<TCurve> ecdsa_sign(
    const typename TCurve::number_type& private_key,
    const std::array<uint8_t, 32>& message_hash) noexcept
{
    using num = typename TCurve::number_type;
    using fe = field_element<TCurve>;

    const num n = TCurve::n();
    const num z = num::from_bytes(std::span<const uint8_t>(message_hash.data(), 32), std::endian::big);

    const num k = ecdsa_detail::rfc6979_k<TCurve>(private_key, message_hash);

    // (x1, y1) = k * G
    point<TCurve> G{fe{TCurve::gx()}, fe{TCurve::gy()}};
    point<TCurve> R = G.scalar_mul(k);

    num r = R.x().value() % n;

    // s = k^-1 * (z + r * d) mod n
    num k_inv = *k.inv_mod(n);
    // Reduce intermediates to avoid overflow: (z % n + (r * d) % n) % n
    num rd = (r * private_key) % n;
    num zn = z % n;
    num sum = (zn + rd) % n;
    num s = (k_inv * sum) % n;

    // Low-S normalization (BIP 62 / OpenSSL convention)
    num half_n = n / num(2U);
    if (s > half_n) {
        s = n - s;
    }

    return {r, s};
}

/**
 * Sign a raw message: hashes with SHA-256, then signs.
 */
template <typename TCurve>
ecdsa_signature<TCurve> ecdsa_sign_message(
    const typename TCurve::number_type& private_key,
    std::span<const uint8_t> message)
{
    auto hash = sha256(message);
    return ecdsa_sign<TCurve>(private_key, hash);
}

/**
 * Verify an ECDSA signature against a pre-hashed message.
 *
 * @param public_key The signer's public key point Q.
 * @param message_hash The SHA-256 hash of the signed message.
 * @param sig The ECDSA signature (r, s).
 * @returns True if the signature is valid.
 */
template <typename TCurve>
constexpr bool ecdsa_verify(
    const point<TCurve>& public_key,
    const std::array<uint8_t, 32>& message_hash,
    const ecdsa_signature<TCurve>& sig) noexcept
{
    using num = typename TCurve::number_type;
    using fe = field_element<TCurve>;

    const num n = TCurve::n();
    const num zero(0U);

    // Check r, s in [1, n-1]
    if (sig.r == zero || sig.r >= n) return false;
    if (sig.s == zero || sig.s >= n) return false;

    const num z = num::from_bytes(std::span<const uint8_t>(message_hash.data(), 32), std::endian::big);

    // w = s^-1 mod n
    auto w_opt = sig.s.inv_mod(n);
    if (!w_opt) return false;
    num w = *w_opt;

    // u1 = z * w mod n, u2 = r * w mod n
    num u1 = (z * w) % n;
    num u2 = (sig.r * w) % n;

    // (x1, y1) = u1*G + u2*Q
    point<TCurve> G{fe{TCurve::gx()}, fe{TCurve::gy()}};
    point<TCurve> P = G.scalar_mul(u1) + public_key.scalar_mul(u2);

    if (P.is_infinity()) return false;

    return (P.x().value() % n) == sig.r;
}

/**
 * Verify an ECDSA signature against a raw message: hashes with SHA-256, then verifies.
 */
template <typename TCurve>
bool ecdsa_verify_message(
    const point<TCurve>& public_key,
    std::span<const uint8_t> message,
    const ecdsa_signature<TCurve>& sig)
{
    auto hash = sha256(message);
    return ecdsa_verify<TCurve>(public_key, hash, sig);
}

#endif /* ECDSA_HPP_ */
