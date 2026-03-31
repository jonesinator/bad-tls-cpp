/**
 * X25519 key exchange — RFC 7748.
 *
 * Implements Diffie-Hellman on Curve25519 using the Montgomery ladder.
 * Operates on raw 32-byte keys (little-endian, per the RFC).
 *
 * Reuses field_element<> from ecc.hpp for modular arithmetic over
 * the prime field p = 2^255 - 19.
 */

#ifndef X25519_HPP_
#define X25519_HPP_

#include "ecc.hpp"
#include <array>
#include <cstdint>
#include <optional>

/**
 * Curve25519 field parameters for use with field_element<>.
 *
 * Only p() is used by field_element arithmetic. The other methods are stubs
 * for template compatibility — X25519 uses the Montgomery ladder, not
 * Weierstrass point operations.
 *
 * @tparam TNumber The underlying number type. Must be at least 512 bits
 *                 (double the 255-bit field size) for multiplication.
 */
template <typename TNumber>
struct curve25519 {
    using number_type = TNumber;

    static constexpr number_type p() {
        return *number_type::from_string(
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
            string_base::hexadecimal);
    }

    // Stubs for field_element compatibility (not used by X25519)
    static constexpr number_type a() { return number_type(486662U); }
    static constexpr number_type b() { return number_type(1U); }
    static constexpr number_type gx() { return number_type(9U); }
    static constexpr number_type gy() { return number_type(0U); }
    static constexpr number_type n() {
        return *number_type::from_string(
            "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
            string_base::hexadecimal);
    }
};

namespace x25519_detail {

template <typename TNumber>
using fe = field_element<curve25519<TNumber>>;

/**
 * Decode 32 little-endian bytes into a field element, masking bit 255.
 */
template <typename TNumber>
constexpr fe<TNumber> decode_u_coordinate(const std::array<uint8_t, 32>& bytes) noexcept {
    auto masked = bytes;
    masked[31] &= 0x7F;  // mask bit 255 per RFC 7748 Section 5
    auto n = TNumber::from_bytes(masked, std::endian::little);
    return fe<TNumber>{n};
}

/**
 * Encode a field element as 32 little-endian bytes.
 */
template <typename TNumber>
constexpr std::array<uint8_t, 32> encode_u_coordinate(const fe<TNumber>& u) noexcept {
    auto full = u.value().to_bytes(std::endian::little);
    std::array<uint8_t, 32> result{};
    for (size_t i = 0; i < 32; ++i)
        result[i] = full[i];
    return result;
}

/**
 * Decode a scalar from 32 little-endian bytes (no clamping).
 */
template <typename TNumber>
constexpr TNumber decode_scalar(const std::array<uint8_t, 32>& bytes) noexcept {
    return TNumber::from_bytes(bytes, std::endian::little);
}

} // namespace x25519_detail

/**
 * Clamp a 32-byte X25519 scalar in place.
 *
 * Per RFC 7748 Section 5:
 *   - Clear bits 0, 1, 2 (make divisible by 8, clearing cofactor)
 *   - Clear bit 255 (ensure scalar < 2^255)
 *   - Set bit 254 (ensure constant-time ladder has fixed number of steps)
 */
constexpr void x25519_clamp(std::array<uint8_t, 32>& scalar) noexcept {
    scalar[0] &= 248;   // clear bits 0, 1, 2
    scalar[31] &= 127;  // clear bit 255
    scalar[31] |= 64;   // set bit 254
}

/**
 * X25519 scalar multiplication using the Montgomery ladder.
 *
 * Computes scalar * u on Curve25519, returning the u-coordinate of the result
 * as 32 little-endian bytes.
 *
 * The scalar is clamped before use. The u-coordinate has bit 255 masked.
 * This follows RFC 7748 Section 5 exactly.
 *
 * @tparam TNumber The number type (e.g. number<uint32_t, 16> for 512-bit).
 * @param scalar_bytes 32-byte little-endian scalar (will be clamped).
 * @param u_bytes      32-byte little-endian u-coordinate of the input point.
 *
 * @returns 32-byte little-endian u-coordinate of the result.
 */
template <typename TNumber>
constexpr std::array<uint8_t, 32> x25519_scalar_mult(
    std::array<uint8_t, 32> scalar_bytes,
    const std::array<uint8_t, 32>& u_bytes) noexcept
{
    using fe = x25519_detail::fe<TNumber>;

    x25519_clamp(scalar_bytes);
    auto k = x25519_detail::decode_scalar<TNumber>(scalar_bytes);
    auto u = x25519_detail::decode_u_coordinate<TNumber>(u_bytes);

    // a24 = (A - 2) / 4 = (486662 - 2) / 4 = 121665 per RFC 7748 Section 5
    fe a24{TNumber(121665U)};

    // Montgomery ladder — RFC 7748 Section 5
    fe x_2{TNumber(1U)};
    fe z_2{TNumber(0U)};
    fe x_3 = u;
    fe z_3{TNumber(1U)};

    bool swap = false;

    // Iterate from bit 254 down to bit 0
    for (int t = 254; t >= 0; --t) {
        // Extract bit t of the scalar
        // bit_width of digit_max tells us bits per digit
        auto word_bits = std::bit_width(static_cast<uint64_t>(TNumber::digit_max));
        auto digit_idx = static_cast<unsigned>(t) / word_bits;
        auto bit_idx = static_cast<unsigned>(t) % word_bits;
        bool k_t = (k.digit(digit_idx) >> bit_idx) & 1;

        // Conditional swap
        if (swap != k_t) {
            auto tmp_x = x_2; x_2 = x_3; x_3 = tmp_x;
            auto tmp_z = z_2; z_2 = z_3; z_3 = tmp_z;
        }
        swap = k_t;

        // Ladder step
        fe A = x_2 + z_2;
        fe AA = A * A;
        fe B = x_2 - z_2;
        fe BB = B * B;
        fe E = AA - BB;
        fe C = x_3 + z_3;
        fe D = x_3 - z_3;
        fe DA = D * A;
        fe CB = C * B;
        x_3 = (DA + CB) * (DA + CB);
        z_3 = u * ((DA - CB) * (DA - CB));
        x_2 = AA * BB;
        z_2 = E * (AA + a24 * E);
    }

    // Final conditional swap
    if (swap) {
        auto tmp_x = x_2; x_2 = x_3; x_3 = tmp_x;
        auto tmp_z = z_2; z_2 = z_3; z_3 = tmp_z;
    }

    // Result: x_2 * z_2^(p-2) mod p (Fermat's little theorem inversion)
    // If z_2 == 0 (low-order point input), return all zeros.
    if (z_2.value() == TNumber(0U)) {
        return std::array<uint8_t, 32>{};
    }
    fe result = x_2 / z_2;
    return x25519_detail::encode_u_coordinate<TNumber>(result);
}

/**
 * Compute an X25519 public key from a 32-byte private key.
 *
 * This is scalar multiplication of the private key by the base point (u = 9).
 *
 * @tparam TNumber The number type.
 * @param private_key 32-byte little-endian private key (will be clamped internally).
 *
 * @returns 32-byte little-endian public key.
 */
template <typename TNumber>
constexpr std::array<uint8_t, 32> x25519_public_key(
    const std::array<uint8_t, 32>& private_key) noexcept
{
    std::array<uint8_t, 32> basepoint{};
    basepoint[0] = 9;  // u = 9 in little-endian
    return x25519_scalar_mult<TNumber>(private_key, basepoint);
}

/**
 * Compute an X25519 shared secret.
 *
 * Returns std::nullopt if the result is the all-zeros value (low-order point input),
 * as required by RFC 7748 Section 6.1.
 *
 * @tparam TNumber The number type.
 * @param my_private_key   32-byte little-endian private key.
 * @param their_public_key 32-byte little-endian public key.
 *
 * @returns 32-byte shared secret, or nullopt on low-order point.
 */
template <typename TNumber>
constexpr std::optional<std::array<uint8_t, 32>> x25519_shared_secret(
    const std::array<uint8_t, 32>& my_private_key,
    const std::array<uint8_t, 32>& their_public_key) noexcept
{
    auto result = x25519_scalar_mult<TNumber>(my_private_key, their_public_key);

    // Check for all-zeros output (low-order point)
    bool all_zero = true;
    for (size_t i = 0; i < 32; ++i) {
        if (result[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return std::nullopt;

    return result;
}

#endif /* X25519_HPP_ */
