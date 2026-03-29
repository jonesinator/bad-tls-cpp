/**
 * ECDH (Elliptic Curve Diffie-Hellman) key agreement.
 *
 * Provides keypair derivation, public key validation, raw shared secret computation,
 * and an integrated HKDF path. No CSPRNG — the caller supplies private key scalars.
 *
 * Templated on TCurve (e.g. p256<uint512>, secp256k1<uint512>) following the same
 * conventions as ecdsa.hpp.
 */

#ifndef ECDH_HPP_
#define ECDH_HPP_

#include "ecc.hpp"
#include "hkdf.hpp"
#include <optional>
#include <span>

template <typename TCurve>
struct ecdh_keypair {
    typename TCurve::number_type private_key;
    point<TCurve> public_key;
};

/**
 * Derive an ECDH keypair from a private scalar.
 *
 * Computes Q = d * G. The caller is responsible for ensuring d is in [1, n-1]
 * (e.g. generated from a CSPRNG or loaded from a PEM file).
 */
template <typename TCurve>
constexpr ecdh_keypair<TCurve> ecdh_keypair_from_private(
    const typename TCurve::number_type& private_key) noexcept
{
    using fe = field_element<TCurve>;
    point<TCurve> G{fe{TCurve::gx()}, fe{TCurve::gy()}};
    return {private_key, G.scalar_mul(private_key)};
}

/**
 * Validate a peer's public key per SEC 1 v2 Section 3.2.2.1.
 *
 * Checks: (1) not point at infinity, (2) on curve, (3) n * Q == infinity (subgroup check).
 */
template <typename TCurve>
constexpr bool ecdh_validate_public_key(const point<TCurve>& pk) noexcept
{
    if (pk.is_infinity()) return false;
    if (!pk.on_curve()) return false;
    if (!pk.scalar_mul(TCurve::n()).is_infinity()) return false;
    return true;
}

/**
 * Compute the raw ECDH shared secret: x-coordinate of my_private * their_public.
 *
 * Returns std::nullopt if the result is the point at infinity (invalid input).
 */
template <typename TCurve>
constexpr std::optional<typename TCurve::number_type> ecdh_raw_shared_secret(
    const typename TCurve::number_type& my_private_key,
    const point<TCurve>& their_public_key) noexcept
{
    auto S = their_public_key.scalar_mul(my_private_key);
    if (S.is_infinity()) return std::nullopt;
    return S.x().value();
}

/**
 * ECDH with HKDF key derivation.
 *
 * Computes the raw shared secret, serializes the x-coordinate to big-endian bytes,
 * and feeds it through HKDF-Extract-and-Expand to produce L bytes of keying material.
 *
 * Returns std::nullopt if the raw shared secret computation fails (point at infinity).
 */
template <typename TCurve, hash_function THash, size_t L>
constexpr std::optional<std::array<uint8_t, L>> ecdh_derive(
    const typename TCurve::number_type& my_private_key,
    const point<TCurve>& their_public_key,
    std::span<const uint8_t> salt = {},
    std::span<const uint8_t> info = {}) noexcept
{
    auto secret = ecdh_raw_shared_secret<TCurve>(my_private_key, their_public_key);
    if (!secret) return std::nullopt;

    auto ikm = secret->to_bytes(std::endian::big);
    return hkdf<THash, L>(salt, ikm, info);
}

#endif /* ECDH_HPP_ */
