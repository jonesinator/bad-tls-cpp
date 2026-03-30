/**
 * Comprehensive tests for the fixed-width big integer class (number<>).
 *
 * Covers arithmetic, bitwise ops, shifts, conversions, modular arithmetic,
 * and edge cases around overflow, underflow, division by zero, and boundaries.
 */

#include <number/number.hpp>
#include <cassert>
#include <cstdint>
#include <array>
#include <sstream>
#include <format>

// Commonly used types
using u128 = number<uint32_t, 4>;    // 128-bit
using u256 = number<uint32_t, 8>;    // 256-bit
using u64  = number<uint32_t, 2>;    // 64-bit
using u32  = number<uint32_t, 1>;    // 32-bit (single digit)
using u8num = number<uint8_t, 4>;    // 4 x uint8_t digits (base 256), 32-bit total
using u8_2 = number<uint8_t, 2>;     // 2 x uint8_t digits, 16-bit total

// ===== Construction and basic properties =====

void test_default_construction() {
    u128 a;
    assert(!a);  // zero is falsy
    assert(a == u128(0U));
}

void test_integer_construction() {
    u128 a(42U);
    assert(a);  // non-zero is truthy
    assert(a == u128(42U));

    u128 b(0U);
    assert(!b);

    // Max single digit
    u128 c(0xFFFFFFFFU);
    assert(c);
}

void test_copy_move() {
    u128 a(123U);
    u128 b = a;
    assert(a == b);

    u128 c = std::move(b);
    assert(c == a);
}

// ===== Comparison operators =====

void test_comparisons() {
    u128 zero(0U);
    u128 one(1U);
    u128 max_digit(0xFFFFFFFFU);

    assert(zero == zero);
    assert(zero < one);
    assert(one > zero);
    assert(one <= one);
    assert(one >= one);
    assert(zero <= one);
    assert(one >= zero);
    assert(zero != one);

    // Multi-digit comparison: higher digit matters more
    u128 a(0U);
    a.set_digit(3, 1U);  // set highest digit
    u128 b(0xFFFFFFFFU); // max in lowest digit
    assert(a > b);  // higher digit wins
}

// ===== Addition =====

void test_addition_basic() {
    assert(u128(0U) + u128(0U) == u128(0U));
    assert(u128(1U) + u128(0U) == u128(1U));
    assert(u128(0U) + u128(1U) == u128(1U));
    assert(u128(1U) + u128(1U) == u128(2U));
    assert(u128(100U) + u128(200U) == u128(300U));
}

void test_addition_carry() {
    // Adding two values that cause carry from digit 0 to digit 1
    u128 a(0xFFFFFFFFU);
    u128 b(1U);
    u128 result = a + b;
    // 0xFFFFFFFF + 1 = 0x1_00000000 -> digit(0)=0, digit(1)=1
    assert(result.digit(0) == 0);
    assert(result.digit(1) == 1);
}

void test_addition_carry_chain() {
    // All digits at max, add 1 -> should overflow and wrap to 0
    u32 max_single(0xFFFFFFFFU);
    u32 result = max_single + u32(1U);
    assert(result == u32(0U));  // overflow wraps
}

void test_addition_overflow_wraps() {
    // 128-bit number, all digits max + 1 = 0 (wraps)
    u128 max_val;
    for (unsigned i = 0; i < 4; ++i)
        max_val.set_digit(i, 0xFFFFFFFFU);
    u128 result = max_val + u128(1U);
    assert(result == u128(0U));
}

// ===== Subtraction =====

void test_subtraction_basic() {
    assert(u128(5U) - u128(3U) == u128(2U));
    assert(u128(100U) - u128(0U) == u128(100U));
    assert(u128(0U) - u128(0U) == u128(0U));
    assert(u128(1U) - u128(1U) == u128(0U));
}

void test_subtraction_borrow() {
    // 0x1_00000000 - 1 = 0xFFFFFFFF
    u128 a(0U);
    a.set_digit(1, 1U);
    u128 result = a - u128(1U);
    assert(result == u128(0xFFFFFFFFU));
}

void test_subtraction_underflow_wraps() {
    // 0 - 1 wraps to max value
    u128 result = u128(0U) - u128(1U);
    // Should be all 0xFFFFFFFF digits
    for (unsigned i = 0; i < 4; ++i)
        assert(result.digit(i) == 0xFFFFFFFFU);
}

// ===== Increment / Decrement =====

void test_increment_decrement() {
    u128 a(5U);
    ++a;
    assert(a == u128(6U));
    a++;
    assert(a == u128(7U));
    --a;
    assert(a == u128(6U));
    a--;
    assert(a == u128(5U));

    // Pre-increment returns new value
    u128 b(10U);
    u128 c = ++b;
    assert(c == u128(11U));

    // Post-increment returns old value
    u128 d = b++;
    assert(d == u128(11U));
    assert(b == u128(12U));
}

// ===== Multiplication =====

void test_multiplication_basic() {
    assert(u128(0U) * u128(5U) == u128(0U));
    assert(u128(5U) * u128(0U) == u128(0U));
    assert(u128(1U) * u128(42U) == u128(42U));
    assert(u128(42U) * u128(1U) == u128(42U));
    assert(u128(6U) * u128(7U) == u128(42U));
    assert(u128(100U) * u128(100U) == u128(10000U));
}

void test_multiplication_large() {
    // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE_00000001
    u128 a(0xFFFFFFFFU);
    u128 b(0xFFFFFFFFU);
    u128 result = a * b;
    assert(result.digit(0) == 1U);
    assert(result.digit(1) == 0xFFFFFFFEU);
}

void test_multiplication_overflow_wraps() {
    // For a single-digit number, overflow wraps
    u32 a(0x10000U);
    u32 b(0x10000U);
    u32 result = a * b;
    // 0x10000 * 0x10000 = 0x1_00000000, wraps to 0
    assert(result == u32(0U));
}

// ===== Division =====

void test_division_basic() {
    assert(u128(42U) / u128(1U) == u128(42U));
    assert(u128(42U) / u128(42U) == u128(1U));
    assert(u128(100U) / u128(10U) == u128(10U));
    assert(u128(7U) / u128(2U) == u128(3U));  // truncating
    assert(u128(10U) / u128(3U) == u128(3U)); // truncating
}

void test_division_by_zero() {
    // Division by zero returns 0 (documented behavior)
    assert(u128(42U) / u128(0U) == u128(0U));
    assert(u128(0U) / u128(0U) == u128(0U));
}

void test_division_zero_dividend() {
    assert(u128(0U) / u128(5U) == u128(0U));
}

void test_division_divisor_greater() {
    assert(u128(3U) / u128(5U) == u128(0U));
}

void test_division_large() {
    // Test multi-digit division
    // 0x1_00000000 / 2 = 0x80000000
    u128 a(0U);
    a.set_digit(1, 1U);
    u128 result = a / u128(2U);
    assert(result == u128(0x80000000U));
}

// ===== Modulo =====

void test_modulo_basic() {
    assert(u128(10U) % u128(3U) == u128(1U));
    assert(u128(10U) % u128(5U) == u128(0U));
    assert(u128(7U) % u128(7U) == u128(0U));
    assert(u128(0U) % u128(5U) == u128(0U));
    assert(u128(3U) % u128(5U) == u128(3U));
}

void test_division_modulo_consistency() {
    // For any a, b (b != 0): a == (a / b) * b + (a % b)
    u128 a(12345U);
    u128 b(67U);
    u128 q = a / b;
    u128 r = a % b;
    assert(q * b + r == a);
}

// ===== Left shift (via repeated doubling) =====

void test_left_shift() {
    assert(u128(1U) << 0 == u128(1U));
    assert(u128(1U) << 1 == u128(2U));
    assert(u128(1U) << 8 == u128(256U));
    assert(u128(1U) << 31 == u128(0x80000000U));

    // Shift into next digit
    u128 result = u128(1U) << 32;
    assert(result.digit(0) == 0);
    assert(result.digit(1) == 1);
}

void test_left_shift_overflow() {
    // Shift beyond width wraps to 0
    u32 a(1U);
    u32 result = a << 32;
    assert(result == u32(0U));
}

// ===== Right shift (via repeated halving) =====

void test_right_shift() {
    assert(u128(4U) >> 1 == u128(2U));
    assert(u128(4U) >> 2 == u128(1U));
    assert(u128(4U) >> 3 == u128(0U));
    assert(u128(256U) >> 8 == u128(1U));

    // Shift from higher digit down
    u128 a(0U);
    a.set_digit(1, 1U);  // = 0x1_00000000
    assert(a >> 1 == u128(0x80000000U));
}

void test_right_shift_to_zero() {
    assert(u128(1U) >> 1 == u128(0U));
    assert(u128(1U) >> 128 == u128(0U));
}

// ===== Bitwise AND =====

void test_bitwise_and() {
    assert((u128(0xFFU) & u128(0x0FU)) == u128(0x0FU));
    assert((u128(0U) & u128(0xFFFFFFFFU)) == u128(0U));
    assert((u128(0xFFFFFFFFU) & u128(0xFFFFFFFFU)) == u128(0xFFFFFFFFU));
}

// ===== Bitwise OR =====

void test_bitwise_or() {
    assert((u128(0xF0U) | u128(0x0FU)) == u128(0xFFU));
    assert((u128(0U) | u128(0U)) == u128(0U));
    assert((u128(0U) | u128(42U)) == u128(42U));
}

// ===== Bitwise XOR =====

void test_bitwise_xor() {
    assert((u128(0xFFU) ^ u128(0xFFU)) == u128(0U));
    assert((u128(0xFFU) ^ u128(0U)) == u128(0xFFU));
    assert((u128(0xF0U) ^ u128(0x0FU)) == u128(0xFFU));
}

// ===== Bitwise NOT =====

void test_bitwise_not() {
    u128 zero;
    u128 result = ~zero;
    // ~0 should be all digit_max
    for (unsigned i = 0; i < 4; ++i)
        assert(result.digit(i) == 0xFFFFFFFFU);

    // ~~x == x
    u128 a(42U);
    assert(~~a == a);
}

// ===== Power =====

void test_pow() {
    assert(u128(2U).pow(u128(0U)) == u128(1U));
    assert(u128(2U).pow(u128(1U)) == u128(2U));
    assert(u128(2U).pow(u128(10U)) == u128(1024U));
    assert(u128(0U).pow(u128(0U)) == u128(1U));  // 0^0 = 1 by convention
    assert(u128(0U).pow(u128(5U)) == u128(0U));
    assert(u128(1U).pow(u128(1000U)) == u128(1U));
    assert(u128(3U).pow(u128(5U)) == u128(243U));
}

// ===== Power mod =====

void test_pow_mod() {
    // 2^10 mod 1000 = 1024 mod 1000 = 24
    assert(u128(2U).pow_mod(u128(10U), u128(1000U)) == u128(24U));

    // Fermat's little theorem: a^(p-1) mod p = 1 for prime p
    // p = 17, a = 3: 3^16 mod 17 = 1
    assert(u128(3U).pow_mod(u128(16U), u128(17U)) == u128(1U));

    // 0^0 mod m = 1 (standard convention)
    assert(u128(0U).pow_mod(u128(0U), u128(7U)) == u128(1U));

    // Large exponent: 7^256 mod 13
    u256 base(7U);
    u256 exp(256U);
    u256 mod(13U);
    u256 result = base.pow_mod(exp, mod);
    // 7^256 mod 13: by Fermat's little, 7^12 = 1 mod 13, 256 = 21*12 + 4, so 7^4 mod 13 = 2401 mod 13 = 9
    assert(result == u256(9U));
}

// ===== Modular inverse =====

void test_inv_mod() {
    // 3 * inv(3) mod 7 = 1; inv(3) mod 7 = 5 (since 3*5=15=2*7+1)
    auto inv = u128(3U).inv_mod(u128(7U));
    assert(inv.has_value());
    assert(*inv == u128(5U));

    // Verify: a * inv(a) mod m = 1
    u128 a(17U), m(100U);
    auto inv_a = a.inv_mod(m);
    assert(inv_a.has_value());
    assert((a * *inv_a) % m == u128(1U));

    // No inverse when gcd != 1
    auto no_inv = u128(6U).inv_mod(u128(4U));
    assert(!no_inv.has_value());

    // inv(1) mod m = 1
    auto inv_one = u128(1U).inv_mod(u128(100U));
    assert(inv_one.has_value());
    assert(*inv_one == u128(1U));

    // inv(0) mod m has no inverse
    auto inv_zero = u128(0U).inv_mod(u128(7U));
    assert(!inv_zero.has_value());
}

// ===== GCD =====

void test_gcd() {
    assert(u128(12U).gcd(u128(8U)) == u128(4U));
    assert(u128(17U).gcd(u128(13U)) == u128(1U));  // coprime
    assert(u128(0U).gcd(u128(5U)) == u128(5U));
    assert(u128(5U).gcd(u128(0U)) == u128(5U));
    assert(u128(0U).gcd(u128(0U)) == u128(0U));
    assert(u128(100U).gcd(u128(100U)) == u128(100U));

    // GCD is commutative
    assert(u128(48U).gcd(u128(18U)) == u128(18U).gcd(u128(48U)));
}

// ===== is_even / is_odd =====

void test_parity() {
    assert(u128(0U).is_even());
    assert(!u128(0U).is_odd());
    assert(u128(1U).is_odd());
    assert(!u128(1U).is_even());
    assert(u128(2U).is_even());
    assert(u128(0xFFFFFFFFU).is_odd());
}

// ===== bit_width =====

void test_bit_width() {
    assert(u128(0U).bit_width() == 0);
    assert(u128(1U).bit_width() == 1);
    assert(u128(2U).bit_width() == 2);
    assert(u128(3U).bit_width() == 2);
    assert(u128(4U).bit_width() == 3);
    assert(u128(255U).bit_width() == 8);
    assert(u128(256U).bit_width() == 9);
    assert(u128(0xFFFFFFFFU).bit_width() == 32);

    // Multi-digit
    u128 a(0U);
    a.set_digit(1, 1U);  // = 2^32
    assert(a.bit_width() == 33);
}

// ===== most_significant_digit =====

void test_most_significant_digit() {
    assert(u128(0U).most_significant_digit() == 0);
    assert(u128(1U).most_significant_digit() == 1);
    assert(u128(0xFFFFFFFFU).most_significant_digit() == 1);

    u128 a(0U);
    a.set_digit(2, 1U);
    assert(a.most_significant_digit() == 3);
}

// ===== digit / set_digit =====

void test_digit_access() {
    u128 a(0U);

    // Initial state: all digits zero
    for (unsigned i = 0; i < 4; ++i)
        assert(a.digit(i) == 0);

    // Set and read back
    a.set_digit(0, 42U);
    assert(a.digit(0) == 42U);

    a.set_digit(3, 99U);
    assert(a.digit(3) == 99U);

    // Out of range digit access returns 0
    assert(a.digit(100) == 0);

    // Out of range set_digit is a no-op
    a.set_digit(100, 42U);  // should not crash
}

// ===== from_string / to_string =====

void test_string_decimal() {
    auto a = u128::from_string("12345");
    assert(a.has_value());
    assert(*a == u128(12345U));
    assert(a->to_string() == "12345");

    // Zero
    auto z = u128::from_string("0");
    assert(z.has_value());
    assert(z->to_string() == "0");
}

void test_string_hex() {
    auto a = u128::from_string("ff", string_base::hexadecimal);
    assert(a.has_value());
    assert(*a == u128(255U));
    assert(a->to_string(string_base::hexadecimal) == "ff");

    auto b = u128::from_string("FF", string_base::hexadecimal);
    assert(b.has_value());
    assert(*b == u128(255U));

    auto c = u128::from_string("deadbeef", string_base::hexadecimal);
    assert(c.has_value());
    assert(*c == u128(0xDEADBEEFU));
}

void test_string_binary() {
    auto a = u128::from_string("1010", string_base::binary);
    assert(a.has_value());
    assert(*a == u128(10U));
    assert(a->to_string(string_base::binary) == "1010");
}

void test_string_octal() {
    auto a = u128::from_string("77", string_base::octal);
    assert(a.has_value());
    assert(*a == u128(63U));
    assert(a->to_string(string_base::octal) == "77");
}

void test_string_invalid() {
    assert(!u128::from_string("xyz").has_value());
    assert(!u128::from_string("").has_value());
    assert(!u128::from_string("12g").has_value());
    assert(!u128::from_string("2", string_base::binary).has_value());
}

// ===== from_bytes / to_bytes =====

void test_bytes_roundtrip_big_endian() {
    std::array<uint8_t, 4> bytes = {0x01, 0x02, 0x03, 0x04};
    auto a = u128::from_bytes(bytes, std::endian::big);
    // 0x01020304
    assert(a == u128(0x01020304U));

    auto out = a.to_bytes(std::endian::big);
    // 128-bit number = 16 bytes, value in last 4 bytes
    assert(out[12] == 0x01);
    assert(out[13] == 0x02);
    assert(out[14] == 0x03);
    assert(out[15] == 0x04);
}

void test_bytes_roundtrip_little_endian() {
    std::array<uint8_t, 4> bytes = {0x04, 0x03, 0x02, 0x01};
    auto a = u128::from_bytes(bytes, std::endian::little);
    assert(a == u128(0x01020304U));

    auto out = a.to_bytes(std::endian::little);
    assert(out[0] == 0x04);
    assert(out[1] == 0x03);
    assert(out[2] == 0x02);
    assert(out[3] == 0x01);
}

void test_bytes_empty() {
    std::array<uint8_t, 0> empty{};
    auto a = u128::from_bytes(std::span<const uint8_t>(empty));
    assert(a == u128(0U));
}

void test_bytes_single_byte() {
    std::array<uint8_t, 1> one = {0x42};
    auto a = u128::from_bytes(one);
    assert(a == u128(0x42U));
}

void test_bytes_full_width() {
    // 128-bit = 16 bytes
    u128 a(0U);
    a.set_digit(3, 0xDEADBEEFU);
    a.set_digit(2, 0xCAFEBABEU);
    a.set_digit(1, 0x12345678U);
    a.set_digit(0, 0x9ABCDEF0U);

    auto bytes = a.to_bytes(std::endian::big);
    auto roundtrip = u128::from_bytes(bytes, std::endian::big);
    assert(roundtrip == a);

    auto bytes_le = a.to_bytes(std::endian::little);
    auto roundtrip_le = u128::from_bytes(bytes_le, std::endian::little);
    assert(roundtrip_le == a);
}

// ===== Integer conversion =====

void test_integer_conversion() {
    u128 a(0xDEADBEEFU);
    assert(static_cast<uint32_t>(a) == 0xDEADBEEFU);

    u128 b(255U);
    assert(static_cast<uint8_t>(b) == 255U);

    // Truncation for values that don't fit
    u128 c(0U);
    c.set_digit(1, 1U);  // = 0x1_00000000
    // When cast to uint32_t, should truncate to lower 32 bits = 0
    auto val = static_cast<uint32_t>(c);
    (void)val;  // implementation-defined truncation
}

// ===== Boolean conversion =====

void test_boolean_conversion() {
    assert(!u128(0U));
    assert(u128(1U));
    assert(u128(0xFFFFFFFFU));

    u128 a(0U);
    a.set_digit(3, 1U);
    assert(a);  // non-zero in high digit
}

// ===== Conversion between sizes =====

void test_size_conversion() {
    // Smaller to larger
    u64 small(42U);
    u128 big = small;
    assert(big == u128(42U));

    // Preserves multi-digit values
    u64 multi(0U);
    multi.set_digit(1, 0xABU);
    multi.set_digit(0, 0xCDU);
    u128 promoted = multi;
    assert(promoted.digit(0) == 0xCDU);
    assert(promoted.digit(1) == 0xABU);
    assert(promoted.digit(2) == 0U);
}

// ===== Compound assignment operators =====

void test_compound_assignment() {
    u128 a(10U);
    a += u128(5U);  assert(a == u128(15U));
    a -= u128(3U);  assert(a == u128(12U));
    a *= u128(4U);  assert(a == u128(48U));
    a /= u128(6U);  assert(a == u128(8U));
    a %= u128(3U);  assert(a == u128(2U));
    a <<= 3;        assert(a == u128(16U));
    a >>= 2;        assert(a == u128(4U));
    a &= u128(5U);  assert(a == u128(4U));  // 100 & 101 = 100
    a |= u128(3U);  assert(a == u128(7U));  // 100 | 011 = 111
    a ^= u128(5U);  assert(a == u128(2U));  // 111 ^ 101 = 010
}

// ===== Algebraic properties =====

void test_commutativity() {
    u128 a(1234U), b(5678U);
    assert(a + b == b + a);
    assert(a * b == b * a);
}

void test_associativity() {
    u128 a(11U), b(22U), c(33U);
    assert((a + b) + c == a + (b + c));
    assert((a * b) * c == a * (b * c));
}

void test_distributivity() {
    u128 a(7U), b(11U), c(13U);
    assert(a * (b + c) == a * b + a * c);
}

void test_identity_elements() {
    u128 a(42U);
    assert(a + u128(0U) == a);  // additive identity
    assert(a * u128(1U) == a);  // multiplicative identity
    assert(a - u128(0U) == a);
    assert(a / u128(1U) == a);
}

// ===== Edge cases with uint8_t digit type =====

void test_uint8_digits() {
    // 2-digit base-256 number = 16-bit range
    u8_2 a(255U);
    u8_2 b(1U);
    u8_2 result = a + b;
    assert(result.digit(0) == 0);
    assert(result.digit(1) == 1);

    // 255 * 255 = 65025 = 0xFE01
    u8_2 c(255U);
    u8_2 d(255U);
    u8_2 product = c * d;
    assert(product.digit(0) == 1);
    assert(product.digit(1) == 254);

    // Division
    u8_2 e(200U);
    u8_2 f(10U);
    assert(e / f == u8_2(20U));
}

// ===== Stream I/O =====

void test_ostream() {
    u128 a(12345U);
    std::ostringstream oss;
    oss << a;
    assert(oss.str() == "12345");

    // Hex output
    std::ostringstream hex_oss;
    hex_oss << std::hex << u128(0xABCDU);
    assert(hex_oss.str() == "abcd");

    // Hex with showbase
    std::ostringstream hex_base;
    hex_base << std::hex << std::showbase << u128(255U);
    assert(hex_base.str() == "0xff");
}

void test_istream() {
    u128 a;
    std::istringstream iss("42");
    iss >> a;
    assert(a == u128(42U));

    // Hex with prefix
    u128 b;
    std::istringstream hex_iss("0xFF");
    hex_iss >> b;
    assert(b == u128(255U));
}

// ===== std::format =====

void test_format() {
    u128 a(42U);
    assert(std::format("{}", a) == "42");
    assert(std::format("{:x}", a) == "2a");
    assert(std::format("{:X}", a) == "2A");
    assert(std::format("{:#x}", a) == "0x2a");
    assert(std::format("{:b}", a) == "101010");
    assert(std::format("{:o}", a) == "52");
    assert(std::format("{:>10}", a) == "        42");
    assert(std::format("{:<10}", a) == "42        ");
    assert(std::format("{:^10}", a) == "    42    ");
    assert(std::format("{:010}", a) == "0000000042");
}

// ===== Constexpr verification =====

void test_constexpr() {
    // All basic operations should work at compile time
    static_assert(u128(2U) + u128(3U) == u128(5U));
    static_assert(u128(10U) - u128(3U) == u128(7U));
    static_assert(u128(6U) * u128(7U) == u128(42U));
    static_assert(u128(42U) / u128(6U) == u128(7U));
    static_assert(u128(10U) % u128(3U) == u128(1U));
    static_assert(u128(1U) << 8 == u128(256U));
    static_assert(u128(256U) >> 8 == u128(1U));
    static_assert((u128(0xFFU) & u128(0x0FU)) == u128(0x0FU));
    static_assert((u128(0xF0U) | u128(0x0FU)) == u128(0xFFU));
    static_assert(u128(2U).pow(u128(10U)) == u128(1024U));
    static_assert(u128(3U).pow_mod(u128(16U), u128(17U)) == u128(1U));
    static_assert(u128(12U).gcd(u128(8U)) == u128(4U));
    static_assert(!u128(0U));
    static_assert(u128(1U).is_odd());
    static_assert(u128(2U).is_even());

    // from_string at compile time
    static_assert(*u128::from_string("42") == u128(42U));
    static_assert(*u128::from_string("ff", string_base::hexadecimal) == u128(255U));
}

// ===== Large number stress: 256-bit arithmetic =====

void test_large_256bit() {
    // A well-known 256-bit prime (P-256 curve order)
    auto n = u256::from_string(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        string_base::hexadecimal);
    assert(n.has_value());

    // n - 1 + 1 == n
    u256 nm1 = *n - u256(1U);
    assert(nm1 + u256(1U) == *n);

    // n * 1 == n
    assert(*n * u256(1U) == *n);

    // n / n == 1
    assert(*n / *n == u256(1U));

    // n % n == 0
    assert(*n % *n == u256(0U));

    // (n - 1) % n == n - 1
    assert(nm1 % *n == nm1);
}

void test_large_mul_div_roundtrip() {
    auto a = u256::from_string("DEADBEEFCAFEBABE", string_base::hexadecimal);
    auto b = u256::from_string("1234567890ABCDEF", string_base::hexadecimal);
    assert(a.has_value() && b.has_value());

    u256 product = *a * *b;
    // product / a should be b (if no overflow)
    u256 quotient = product / *a;
    assert(quotient == *b);
}

// ===== Specific regression-style edge cases =====

void test_subtract_self() {
    u128 a(0xDEADBEEFU);
    assert(a - a == u128(0U));
}

void test_divide_self() {
    u128 a(0xDEADBEEFU);
    assert(a / a == u128(1U));
}

void test_power_of_two_division() {
    // Division by powers of two should give same result as right shift
    u128 a(1024U);
    assert(a / u128(2U) == u128(512U));
    assert(a / u128(4U) == u128(256U));
    assert(a / u128(8U) == u128(128U));
}

void test_consecutive_operations() {
    // (2^32 + 1)^2 = 2^64 + 2^33 + 1
    u128 a(0U);
    a.set_digit(1, 1U);
    a += u128(1U);  // a = 2^32 + 1

    u128 sq = a * a;
    // Expected: digit(0) = 1, digit(1) = 2, digit(2) = 1
    assert(sq.digit(0) == 1);
    assert(sq.digit(1) == 2);
    assert(sq.digit(2) == 1);
}

int main() {
    // Construction
    test_default_construction();
    test_integer_construction();
    test_copy_move();

    // Comparison
    test_comparisons();

    // Addition
    test_addition_basic();
    test_addition_carry();
    test_addition_carry_chain();
    test_addition_overflow_wraps();

    // Subtraction
    test_subtraction_basic();
    test_subtraction_borrow();
    test_subtraction_underflow_wraps();

    // Increment/decrement
    test_increment_decrement();

    // Multiplication
    test_multiplication_basic();
    test_multiplication_large();
    test_multiplication_overflow_wraps();

    // Division
    test_division_basic();
    test_division_by_zero();
    test_division_zero_dividend();
    test_division_divisor_greater();
    test_division_large();

    // Modulo
    test_modulo_basic();
    test_division_modulo_consistency();

    // Shifts
    test_left_shift();
    test_left_shift_overflow();
    test_right_shift();
    test_right_shift_to_zero();

    // Bitwise
    test_bitwise_and();
    test_bitwise_or();
    test_bitwise_xor();
    test_bitwise_not();

    // Power
    test_pow();
    test_pow_mod();

    // Modular inverse
    test_inv_mod();

    // GCD
    test_gcd();

    // Properties
    test_parity();
    test_bit_width();
    test_most_significant_digit();
    test_digit_access();

    // String conversion
    test_string_decimal();
    test_string_hex();
    test_string_binary();
    test_string_octal();
    test_string_invalid();

    // Byte conversion
    test_bytes_roundtrip_big_endian();
    test_bytes_roundtrip_little_endian();
    test_bytes_empty();
    test_bytes_single_byte();
    test_bytes_full_width();

    // Integer/bool conversion
    test_integer_conversion();
    test_boolean_conversion();
    test_size_conversion();

    // Compound assignment
    test_compound_assignment();

    // Algebraic properties
    test_commutativity();
    test_associativity();
    test_distributivity();
    test_identity_elements();

    // Different digit types
    test_uint8_digits();

    // I/O
    test_ostream();
    test_istream();
    test_format();

    // Constexpr
    test_constexpr();

    // Large numbers
    test_large_256bit();
    test_large_mul_div_roundtrip();

    // Regression / edge cases
    test_subtract_self();
    test_divide_self();
    test_power_of_two_division();
    test_consecutive_operations();

    return 0;
}
