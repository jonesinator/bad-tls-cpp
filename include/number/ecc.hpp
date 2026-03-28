/**
 * Elliptic curve cryptography over prime fields, built on the number class.
 *
 * Provides a field element type with automatic modular reduction, a curve point type with
 * addition/doubling, scalar multiplication, and parameter structs for secp256k1 and P-256.
 *
 * The field element and point types are templated on a curve type TCurve, which provides static
 * methods returning the curve parameters. The underlying number type must be wide enough to hold
 * the product of two field elements before reduction (e.g. number<uint32_t, 16> for 256-bit
 * curves).
 *
 * See "ecc_test.cpp" for unit tests.
 */

#ifndef ECC_HPP_
#define ECC_HPP_

#include "number.hpp"

/**
 * An element of the prime field F_p, where p is determined by the curve type TCurve.
 *
 * All arithmetic automatically reduces modulo p. The value is always in [0, p).
 *
 * @tparam TCurve A type providing a static method p() returning the field prime, plus a(), b(),
 *                gx(), gy(), n() for the other curve parameters. Must also provide a number_type
 *                type alias.
 */
template <typename TCurve>
class field_element {
public:
    using number_type = typename TCurve::number_type;

    constexpr field_element() noexcept : value_() {}

    explicit constexpr field_element(const number_type& value) noexcept
        : value_(value % TCurve::p()) {}

    constexpr field_element(const field_element&) noexcept = default;
    constexpr field_element(field_element&&) noexcept = default;
    constexpr ~field_element() noexcept = default;
    constexpr field_element& operator=(const field_element&) noexcept = default;
    constexpr field_element& operator=(field_element&&) noexcept = default;
    constexpr bool operator==(const field_element&) const noexcept = default;

    constexpr field_element operator+(const field_element& rhs) const noexcept {
        number_type sum = value_ + rhs.value_;
        return sum >= TCurve::p() ? field_element(sum - TCurve::p(), raw{})
                                  : field_element(sum, raw{});
    }

    constexpr field_element& operator+=(const field_element& rhs) noexcept {
        *this = *this + rhs;
        return *this;
    }

    constexpr field_element operator-() const noexcept {
        return value_ == number_type(0U) ? *this
                                         : field_element(TCurve::p() - value_, raw{});
    }

    constexpr field_element operator-(const field_element& rhs) const noexcept {
        return value_ >= rhs.value_ ? field_element(value_ - rhs.value_, raw{})
                                    : field_element(TCurve::p() - (rhs.value_ - value_), raw{});
    }

    constexpr field_element& operator-=(const field_element& rhs) noexcept {
        *this = *this - rhs;
        return *this;
    }

    constexpr field_element operator*(const field_element& rhs) const noexcept {
        return field_element((value_ * rhs.value_) % TCurve::p(), raw{});
    }

    constexpr field_element& operator*=(const field_element& rhs) noexcept {
        *this = *this * rhs;
        return *this;
    }

    constexpr field_element operator/(const field_element& rhs) const noexcept {
        return *this * field_element(
            rhs.value_.inv_mod(TCurve::p()).value_or(number_type(0U)), raw{});
    }

    constexpr field_element& operator/=(const field_element& rhs) noexcept {
        *this = *this / rhs;
        return *this;
    }

    constexpr number_type value() const noexcept { return value_; }

private:
    struct raw {};
    constexpr field_element(const number_type& value, raw) noexcept : value_(value) {}

    number_type value_;
};

/**
 * A point on an elliptic curve y^2 = x^3 + ax + b over F_p.
 *
 * Supports point addition, doubling, negation, and scalar multiplication. The point at infinity
 * (group identity) is represented by the infinity_ flag.
 *
 * @tparam TCurve A curve parameter type (e.g. secp256k1<TNumber> or p256<TNumber>).
 */
template <typename TCurve>
class point {
public:
    using fe = field_element<TCurve>;
    using number_type = typename TCurve::number_type;

    static constexpr point infinity() noexcept { return point(); }

    constexpr point() noexcept : x_(), y_(), infinity_(true) {}

    constexpr point(const fe& x, const fe& y) noexcept
        : x_(x), y_(y), infinity_(false) {}

    constexpr point(const point&) noexcept = default;
    constexpr point(point&&) noexcept = default;
    constexpr ~point() noexcept = default;
    constexpr point& operator=(const point&) noexcept = default;
    constexpr point& operator=(point&&) noexcept = default;

    constexpr bool operator==(const point& rhs) const noexcept {
        if (infinity_ && rhs.infinity_) return true;
        if (infinity_ || rhs.infinity_) return false;
        return x_ == rhs.x_ && y_ == rhs.y_;
    }

    constexpr bool is_infinity() const noexcept { return infinity_; }
    constexpr fe x() const noexcept { return x_; }
    constexpr fe y() const noexcept { return y_; }

    constexpr point operator-() const noexcept {
        if (infinity_) return *this;
        return point(x_, -y_);
    }

    constexpr point operator+(const point& rhs) const noexcept {
        if (infinity_) return rhs;
        if (rhs.infinity_) return *this;

        if (x_ == rhs.x_) {
            if (y_ == rhs.y_) {
                return double_point();
            } else {
                return infinity();
            }
        }

        fe s = (rhs.y_ - y_) / (rhs.x_ - x_);
        fe x3 = s * s - x_ - rhs.x_;
        fe y3 = s * (x_ - x3) - y_;
        return point(x3, y3);
    }

    constexpr point& operator+=(const point& rhs) noexcept {
        *this = *this + rhs;
        return *this;
    }

    /**
     * Compute k * P using the double-and-add algorithm.
     *
     * @param k The scalar to multiply by.
     *
     * @returns The point k * P.
     */
    constexpr point scalar_mul(number_type k) const noexcept {
        point result;
        point temp = *this;

        while (k) {
            if (k.is_odd()) {
                result += temp;
            }
            temp += temp;
            k >>= 1;
        }

        return result;
    }

    /**
     * Check whether this point lies on the curve y^2 = x^3 + ax + b.
     *
     * @returns True if the point is on the curve (or is the point at infinity).
     */
    constexpr bool on_curve() const noexcept {
        if (infinity_) return true;
        fe a(TCurve::a());
        fe b(TCurve::b());
        return y_ * y_ == x_ * x_ * x_ + a * x_ + b;
    }

private:
    constexpr point double_point() const noexcept {
        fe zero_fe;
        if (infinity_ || y_ == zero_fe) {
            return infinity();
        }

        fe two(number_type(2U));
        fe three(number_type(3U));
        fe a(TCurve::a());

        fe s = (three * x_ * x_ + a) / (two * y_);
        fe x3 = s * s - two * x_;
        fe y3 = s * (x_ - x3) - y_;
        return point(x3, y3);
    }

    fe x_, y_;
    bool infinity_ = true;
};

/**
 * Curve parameters for secp256k1 (y^2 = x^3 + 7 over F_p).
 *
 * Used by Bitcoin, Ethereum, and many other cryptocurrency systems.
 *
 * @tparam TNumber The underlying number type. Must be wide enough to hold the product of two
 *                 256-bit field elements (i.e. at least 512 bits).
 */
template <typename TNumber>
struct secp256k1 {
    using number_type = TNumber;

    static number_type p() {
        return *number_type::from_string(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            string_base::hexadecimal);
    }

    static number_type a() { return number_type(0U); }
    static number_type b() { return number_type(7U); }

    static number_type gx() {
        return *number_type::from_string(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            string_base::hexadecimal);
    }

    static number_type gy() {
        return *number_type::from_string(
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            string_base::hexadecimal);
    }

    static number_type n() {
        return *number_type::from_string(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            string_base::hexadecimal);
    }
};

/**
 * Curve parameters for P-256 / secp256r1 (y^2 = x^3 - 3x + b over F_p).
 *
 * The NIST standard curve, used by TLS, WebAuthn, and many other systems.
 *
 * @tparam TNumber The underlying number type. Must be wide enough to hold the product of two
 *                 256-bit field elements (i.e. at least 512 bits).
 */
template <typename TNumber>
struct p256 {
    using number_type = TNumber;

    static number_type p() {
        return *number_type::from_string(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            string_base::hexadecimal);
    }

    static number_type a() {
        return *number_type::from_string(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            string_base::hexadecimal);
    }

    static number_type b() {
        return *number_type::from_string(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            string_base::hexadecimal);
    }

    static number_type gx() {
        return *number_type::from_string(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            string_base::hexadecimal);
    }

    static number_type gy() {
        return *number_type::from_string(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            string_base::hexadecimal);
    }

    static number_type n() {
        return *number_type::from_string(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            string_base::hexadecimal);
    }
};

#endif /* ECC_HPP_ */
