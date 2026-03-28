/**
 * Implements class number, a fixed-width unsigned integer with basic operations sufficient for many
 * cryptographic procedures. That said, use at your own risk. _That_ said, please do not use this
 * library for any production purpose, but please do use it for educational purposes.
 *
 * This header file is self-contained, depending only on the C++23 or later standard library. It
 * should be easy to add this library to any project simply by copying this file and including it.
 *
 * See class documentation for further details. See "integer_test.cpp" for unit tests.
 */

#ifndef NUMBER_HPP_
#define NUMBER_HPP_

#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <cstdint>
#include <format>
#include <istream>
#include <iterator>
#include <limits>
#include <optional>
#include <ostream>
#include <ranges>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

/**
 * The base of a string representing a number.
 */
enum class string_base : unsigned { binary = 2, octal = 8, decimal = 10, hexadecimal = 16 };

/**
 * A fixed-width unsigned integer that does not require exceptions or dynamic memory allocation.
 *
 * @tparam TDigit    The type used to store digits. Must be an unsigned integer type.
 * @tparam NDigits   The number of digits that compose the number. Must be greater than zero.
 * @tparam NDigitMax The maximum value a single digit may hold. Must be one less than a power of two
 *                   (i.e. the base NDigitMax+1 must be a power of two). This is one less than the
 *                   "base" of the number.
 *
 * Ideally, one would specify the base and the number of digits to define a number, but since we're
 * working with a computer, we must use one of the pre-defined unsigned integer widths to store our
 * digits, thus TDigit and NDigitMax are both required, rather than simply the base. We take
 * NDigitMax as a template parameter instead of a base, since it can always be expressed as a
 * TDigit, but the base may be outside of that range. For example, if TDigit is std::uint8_t then a
 * it can represent numbers 0 through 255 -- 256 possible values -- so the highest base compatible
 * with std::uint8_t is 256, but that cannot be represented using a TDigit itself, while an
 * NDigitMax of 255 can fit into a TDigit.
 *
 * The number is stored as an array of TDigits which is NDigits in length. The digit at index zero
 * is most significant, and the digit at index NDigits - 1 is least significant. This way, the
 * default three-way comparison operator works correctly to apply a strong ordering to the numbers.
 *
 *             Most Significant           Least Significant
 *             V                          V
 * digits := [ TDigit[0], TDigit[1], ..., TDigit[NDigits-1] ]
 *
 * Intermediate results must be stored in a type larger than the storage type, so a larger than
 * TDigit must be available. Practically that means that TDigit can be uint32_t at most. While
 * uint64_t _could_ be supported by some compilers by using the nonstandard unsigned __int128, it is
 * not implemented here.
 *
 * This class is optimized for simplicity and readability over performance. Numerous optimizations
 * could be made such as implementing special algorithms for when multiplying by a single digit, or
 * optimizing for cases where the base is a power of two, but none of these are done in order to
 * preserve the clarity of the code. While the code is very slow compared to sophisticated
 * implementations, it is still usable.
 *
 * No exceptions are thrown by this class. All operations succeed, even if there is loss of
 * information. No flags or other mechanisms exist to detect overflow or underflow of any
 * calculations. This class is no "safer" than standard unsigned integers, it's just larger.
 *
 * This is less flexible than an arbitrary-precision integer, but uses fixed memory and simpler
 * algorithms. No dynamic memory allocation is required except when converting the number to a
 * std::string.
 */
template <typename TDigit, unsigned NDigits, TDigit NDigitMax = std::numeric_limits<TDigit>::max()>
requires (std::unsigned_integral<TDigit> && NDigits > 0 && NDigitMax > 0
    && std::has_single_bit(static_cast<std::uint64_t>(NDigitMax) + 1U))
class number {
public:
    /**
     * The storage type for digits.
     */
    using digit_type = TDigit;

    /**
     * The number of digits stored in the number.
     */
    static constexpr unsigned num_digits = NDigits;

    /**
     * The maximum value a single digit may hold.
     */
    static constexpr digit_type digit_max = NDigitMax;

    /**
     * The number of bytes needed to store the number.
     */
    static constexpr unsigned num_bytes =
        (num_digits * std::bit_width(static_cast<std::uint64_t>(digit_max)) + 7) / 8;

    /**
     * Creates a fixed-width unsigned integer from a std::string_view. The entire std::string_view
     * must be consumed for success, otherwise std::nullopt is returned.
     *
     * @param input_string The string to convert to a number.
     * @param input_base The base of the input string.
     *
     * @returns A number wrapped in a std::optional if succesful, otherwise std::nullopt.
     */
    static constexpr std::optional<number> from_string(
        std::string_view input_string,
        string_base input_base = string_base::decimal
    ) noexcept {
        auto decode_char = [input_base](char c) -> std::optional<unsigned> {
            std::optional<unsigned> value;
            if (c >= '0' && c <= '9') {
                value = static_cast<unsigned>(c) - static_cast<unsigned>('0');
            } else if (c >= 'a' && c <= 'f') {
                value = 10 + (static_cast<unsigned>(c) - static_cast<unsigned>('a'));
            } else if (c >= 'A' && c <= 'F') {
                value = 10 + (static_cast<unsigned>(c) - static_cast<unsigned>('A'));
            }
            return (value && *value < std::to_underlying(input_base)) ? value : std::nullopt;
        };

        number result;
        number power(1U);
        number base_number(std::to_underlying(input_base));
        std::string_view::reverse_iterator character = input_string.rbegin();

        for (; character != input_string.rend(); character++, power *= base_number) {
            if(std::optional<unsigned> value = decode_char(*character)) {
                result += number(*value) * power;
            } else {
                return std::nullopt;
            }
        }

        return result;
    }

    /**
     * Creates a fixed-width unsigned integer from a range of bytes. Bytes are interpreted as an
     * unsigned value in the specified byte order.
     *
     * @param first The beginning of the byte range.
     * @param last  The end of the byte range (sentinel).
     * @param order The byte order of the input (default: big-endian).
     *
     * @returns The number represented by the byte range.
     */
    template <std::input_iterator Iter, std::sentinel_for<Iter> Sent>
    static constexpr number from_bytes(
        Iter first, Sent last, std::endian order = std::endian::big
    ) noexcept {
        // Resolve native to the platform's actual byte order.
        std::endian resolved = order == std::endian::native
            ? (std::endian::native == std::endian::big ? std::endian::big : std::endian::little)
            : order;

        number result;
        number byte_base(256U);

        if (resolved == std::endian::big) {
            for (; first != last; ++first) {
                result *= byte_base;
                result += number(static_cast<unsigned>(static_cast<std::uint8_t>(*first)));
            }
        } else {
            number power(1U);
            for (; first != last; ++first) {
                result += number(static_cast<unsigned>(static_cast<std::uint8_t>(*first))) * power;
                power *= byte_base;
            }
        }

        return result;
    }

    /**
     * Creates a fixed-width unsigned integer from a range of bytes. Bytes are interpreted as an
     * unsigned value in the specified byte order.
     *
     * @param range The range of bytes to convert.
     * @param order The byte order of the input (default: big-endian).
     *
     * @returns The number represented by the byte range.
     */
    template <std::ranges::input_range Range>
    static constexpr number from_bytes(
        const Range& range, std::endian order = std::endian::big
    ) noexcept {
        return from_bytes(std::ranges::begin(range), std::ranges::end(range), order);
    }

    constexpr number() noexcept {
        digits_.fill(0U);
    }

    template <typename T>
    requires std::unsigned_integral<T>
    explicit constexpr number(T value) noexcept {
        *this = value;
    }

    template <unsigned NDigits2>
    requires (NDigits2 < num_digits)
    constexpr number(const number<digit_type, NDigits2, digit_max>& value) noexcept {
        *this = value;
    }

    constexpr number(const number& other) noexcept = default;
    constexpr number(number&& other) noexcept = default;
    constexpr ~number() noexcept = default;
    constexpr number& operator=(const number& other) noexcept = default;
    constexpr number& operator=(number&& other) noexcept = default;
    constexpr std::strong_ordering operator<=>(const number&) const noexcept = default;

    /**
     * Returns true if the number is non-zero.
     */
    explicit constexpr operator bool() const noexcept {
        for (auto d : digits_) {
            if (d != 0) return true;
        }
        return false;
    }

    template <typename T>
    requires std::unsigned_integral<T>
    explicit constexpr operator T() const noexcept {
        T value = 0;
        T power = 1;
        typename digits::const_reverse_iterator i = digits_.rbegin();

        for (; i != digits_.rend(); ++i) {
            T power_previous = power;
            value += power * *i;
            power *= base;
            if (power < power_previous) {
                break;
            }
        }

        return value;
    }

    template <typename T>
    requires std::unsigned_integral<T>
    constexpr number& operator=(T value) noexcept {
        typename digits::reverse_iterator cursor = digits_.rbegin();
        for (; value != 0 && cursor != digits_.rend(); ++cursor, value /= base) {
            *cursor = value % base;
        }
        for (; cursor != digits_.rend(); ++cursor) {
            *cursor = 0;
        }
        return *this;
    }

    template <unsigned NDigits2>
    requires (NDigits2 < num_digits)
    constexpr number& operator=(const number<digit_type, NDigits2, digit_max>& value) noexcept {
        for (unsigned i = 0; i < num_digits; ++i) {
            set_digit(i, value.digit(i));
        }
        return *this;
    }

    constexpr number operator+(const number& rhs) const noexcept {
        number result;
        typename digits::const_reverse_iterator op1 = digits_.rbegin();
        typename digits::const_reverse_iterator op2 = rhs.digits_.rbegin();
        typename digits::reverse_iterator res = result.digits_.rbegin();
        unsigned carry = 0;

        for(; op1 != digits_.rend(); ++op1, ++op2, ++res) {
            big_digit_type digit_result = static_cast<big_digit_type>(*op1) + *op2 + carry;
            carry = digit_result >= base;
            *res = digit_result % base;
        }

        return result;
    }

    constexpr number& operator+=(const number& rhs) noexcept {
        *this = *this + rhs;
        return *this;
    }

    constexpr number& operator++() noexcept {
        *this = *this + number(1U);
        return *this;
    }

    constexpr number operator++(int) noexcept {
        number previous = *this;
        ++(*this);
        return previous;
    }

    constexpr number operator-(const number& rhs) const noexcept {
        number result;
        typename digits::const_reverse_iterator op1 = digits_.rbegin();
        typename digits::const_reverse_iterator op2 = rhs.digits_.rbegin();
        typename digits::reverse_iterator res = result.digits_.rbegin();
        unsigned borrow = 0;

        for(; op1 != digits_.rend(); ++op1, ++op2, ++res) {
            big_digit_type digit_result = (base + *op1) - (static_cast<big_digit_type>(borrow) + *op2);
            borrow = digit_result < base;
            *res = digit_result % base;
        }

        return result;
    }

    constexpr number& operator-=(const number& rhs) noexcept {
        *this = *this - rhs;
        return *this;
    }

    constexpr number& operator--() noexcept {
        *this = *this - number(1U);
        return *this;
    }

    constexpr number operator--(int) noexcept {
        number previous = *this;
        --(*this);
        return previous;
    }

    constexpr number operator*(const number& rhs) const noexcept {
        number w;
        unsigned n = rhs.most_significant_digit();
        unsigned m = most_significant_digit();

        for (unsigned j = 0; j < n; ++j) {
            digit_type k = 0;

            for (unsigned i = 0; i < m; ++i) {
                // Note: max value is digit_max^2 + 2*digit_max, which exactly fills big_digit_type.
                big_digit_type t =
                    static_cast<big_digit_type>(digit(i)) * rhs.digit(j) + w.digit(i + j) + k;
                k = t / base;
                w.set_digit(i + j, t % base);
            }

            w.set_digit(j + m, k);
        }

        return w;
    }

    constexpr number& operator*=(const number& rhs) noexcept {
        *this = *this * rhs;
        return *this;
    }

    constexpr number operator/(const number& rhs) const noexcept {
        // Some intermediate results may require an additional digit.
        using big_number = number<digit_type, num_digits + 1, digit_max>;

        // Handle special cases.
        if (!*this || !rhs || rhs > *this) {
            return number(0U);
        } else if (rhs == *this) {
            return number(1U);
        } else if (rhs == number(1U)) {
            return *this;
        }
        // Given the above, if we get here, then 1 < rhs < *this.

        // Multiply the numerator and denominator by a normalization factor to ensure the leading
        // digit of the denominator is at least half the maximum digit value.
        big_number norm(base / (static_cast<big_digit_type>(rhs.digit(rhs.most_significant_digit() - 1U)) + 1U));
        big_number num = big_number(*this) * norm;
        big_number den = big_number(rhs) * norm;
        unsigned n = den.most_significant_digit();
        unsigned m = num.most_significant_digit() - n;

        // Loop through each possible quotient digit.
        number quotient;
        for (int j = m; j >= 0; --j) {
            // Guess the value of the quotient and remainder.
            big_digit_type qh =
                (static_cast<big_digit_type>(num.digit(j + n)) * base + num.digit(j + n - 1)) /
                den.digit(n - 1);
            big_digit_type rh =
                (static_cast<big_digit_type>(num.digit(j + n)) * base + num.digit(j + n - 1)) %
                den.digit(n - 1);

            // Correct the quotient and remainder if needed. The inner comparison is only
            // meaningful when the denominator has at least two digits (n >= 2).
            while (qh >= base || (n >= 2 && (qh * den.digit(n - 2)) > (base * rh + num.digit(j + n - 2)))) {
                --qh;
                rh += den.digit(n - 1);
                if (rh >= base) {
                    break;
                }
            }

            // Get the top n most significant digits from the numerator.
            big_number sig;
            for (int i = j + n; i >= j; i--) {
                sig.set_digit(i - j, num.digit(i));
            }

            // Try the guessed quotient as in long division.
            big_number trial = big_number(qh) * den;

            // If the trial is too high, reduce the guessed quotient and try again.
            // Use a while loop instead of a for loop, but this should never run more than once.
            while (sig < trial) {
                --qh;
                trial = big_number(qh) * den;
            }

            // We now have the new quotient digit. Set it in the output number, and update the
            // numerator.
            quotient.set_digit(j, static_cast<digit_type>(qh));
            big_number diff = sig - trial;
            for (int i = j + n; i >= j; i--) {
                num.set_digit(i, diff.digit(i - j));
            }
        }

        return quotient;
    }

    constexpr number& operator/=(const number& rhs) noexcept {
        *this = *this / rhs;
        return *this;
    }

    constexpr number operator%(const number& rhs) const noexcept {
        return *this - ((*this / rhs) * rhs);
    }

    constexpr number& operator%=(const number& rhs) noexcept {
        *this = *this % rhs;
        return *this;
    }

    constexpr number operator<<(unsigned n) const noexcept {
        number result = *this;
        for (unsigned i = 0; i < n; ++i) {
            result = result + result;
        }
        return result;
    }

    constexpr number& operator<<=(unsigned n) noexcept {
        *this = *this << n;
        return *this;
    }

    constexpr number operator>>(unsigned n) const noexcept {
        number result = *this;
        for (unsigned i = 0; i < n; ++i) {
            digit_type remainder = 0;
            for (auto& d : result.digits_) {
                big_digit_type combined = static_cast<big_digit_type>(remainder) * base + d;
                d = static_cast<digit_type>(combined / 2);
                remainder = combined % 2;
            }
        }
        return result;
    }

    constexpr number& operator>>=(unsigned n) noexcept {
        *this = *this >> n;
        return *this;
    }

    constexpr number operator&(const number& rhs) const noexcept {
        number result;
        for (unsigned i = 0; i < num_digits; ++i) {
            result.digits_[i] = digits_[i] & rhs.digits_[i];
        }
        return result;
    }

    constexpr number& operator&=(const number& rhs) noexcept {
        *this = *this & rhs;
        return *this;
    }

    constexpr number operator|(const number& rhs) const noexcept {
        number result;
        for (unsigned i = 0; i < num_digits; ++i) {
            result.digits_[i] = (digits_[i] | rhs.digits_[i]) % base;
        }
        return result;
    }

    constexpr number& operator|=(const number& rhs) noexcept {
        *this = *this | rhs;
        return *this;
    }

    constexpr number operator^(const number& rhs) const noexcept {
        number result;
        for (unsigned i = 0; i < num_digits; ++i) {
            result.digits_[i] = (digits_[i] ^ rhs.digits_[i]) % base;
        }
        return result;
    }

    constexpr number& operator^=(const number& rhs) noexcept {
        *this = *this ^ rhs;
        return *this;
    }

    constexpr number operator~() const noexcept {
        number result;
        for (unsigned i = 0; i < num_digits; ++i) {
            result.digits_[i] = digit_max - digits_[i];
        }
        return result;
    }

    /**
     * Compute this number raised to a given exponent.
     *
     * @param exponent The exponent to raise this number to.
     *
     * @returns The result of this^exponent.
     */
    constexpr number pow(number exponent) const noexcept {
        number result(1U);
        number b = *this;

        while (exponent) {
            if (exponent.is_odd()) {
                result *= b;
            }
            exponent /= number(2U);
            b *= b;
        }

        return result;
    }

    /**
     * Compute this number raised to a given exponent, modulo a given modulus.
     *
     * @param exponent The exponent to raise this number to.
     * @param modulus  The modulus to reduce the result by.
     *
     * @returns The result of (this^exponent) % modulus.
     */
    constexpr number pow_mod(number exponent, const number& modulus) const noexcept {
        number result = number(1U) % modulus;
        number b = *this % modulus;

        while (exponent) {
            if (exponent.is_odd()) {
                result = (result * b) % modulus;
            }
            exponent >>= 1;
            b = (b * b) % modulus;
        }

        return result;
    }

    /**
     * Compute the modular multiplicative inverse of this number modulo a given modulus using the
     * extended Euclidean algorithm with sign tracking.
     *
     * @param modulus The modulus to compute the inverse with respect to.
     *
     * @returns The inverse wrapped in a std::optional if it exists (i.e. gcd(*this, modulus) == 1),
     *          otherwise std::nullopt.
     */
    constexpr std::optional<number> inv_mod(const number& modulus) const noexcept {
        number old_r = modulus, r = *this % modulus;
        number old_s(0U), s(1U);
        bool old_s_pos = true, s_pos = true;

        while (r) {
            number q = old_r / r;

            number new_r = old_r - q * r;
            old_r = r;
            r = new_r;

            number product = q * s;
            number new_s;
            bool new_s_pos;
            if (old_s_pos == s_pos) {
                if (old_s >= product) {
                    new_s = old_s - product;
                    new_s_pos = old_s_pos;
                } else {
                    new_s = product - old_s;
                    new_s_pos = !old_s_pos;
                }
            } else {
                new_s = old_s + product;
                new_s_pos = old_s_pos;
            }
            old_s = s;    old_s_pos = s_pos;
            s = new_s;    s_pos = new_s_pos;
        }

        if (old_r != number(1U)) {
            return std::nullopt;
        }

        if (old_s_pos) {
            return old_s % modulus;
        } else {
            return modulus - (old_s % modulus);
        }
    }

    /**
     * Converts the number to a string in a given base.
     *
     * @param sb The base of the string to produce.
     *
     * @returns A std::string representing the base-encoded number. 
     */
    constexpr std::string to_string(string_base sb = string_base::decimal) const noexcept {
        if (!*this) {
            return "0";
        }

        std::string s;
        number n = *this;
        number b(std::to_underlying(sb));

        while(n) {
            unsigned string_digit = static_cast<unsigned>(n % b);
            if (string_digit <= 9) {
                s += '0' + static_cast<char>(string_digit);
            } else {
                s += 'a' + static_cast<char>(string_digit - 10);
            }
            n /= b;
        }

        std::ranges::reverse(s);
        return s;
    }

    /**
     * Converts the number to a fixed-size array of bytes in the specified byte order.
     *
     * @param order The byte order of the output (default: big-endian).
     *
     * @returns A std::array of bytes representing the number.
     */
    constexpr std::array<std::uint8_t, num_bytes> to_bytes(
        std::endian order = std::endian::big
    ) const noexcept {
        std::array<std::uint8_t, num_bytes> result{};
        constexpr unsigned bits_per_digit = std::bit_width(static_cast<std::uint64_t>(digit_max));

        std::uint64_t accumulator = 0;
        unsigned acc_bits = 0;
        unsigned byte_idx = 0;

        for (unsigned d = 0; d < num_digits; ++d) {
            accumulator |= static_cast<std::uint64_t>(digit(d)) << acc_bits;
            acc_bits += bits_per_digit;

            while (acc_bits >= 8 && byte_idx < num_bytes) {
                result[byte_idx++] = static_cast<std::uint8_t>(accumulator & 0xFF);
                accumulator >>= 8;
                acc_bits -= 8;
            }
        }

        if (acc_bits > 0 && byte_idx < num_bytes) {
            result[byte_idx] = static_cast<std::uint8_t>(accumulator & 0xFF);
        }

        // result is in little-endian order. Reverse for big-endian.
        std::endian resolved = order == std::endian::native
            ? (std::endian::native == std::endian::big ? std::endian::big : std::endian::little)
            : order;

        if (resolved == std::endian::big) {
            std::ranges::reverse(result);
        }

        return result;
    }

    /**
     * Gets the power of the highest non-zero digit in the number.
     *
     * @returns The power of the highest non-zero digit in the number.
     */
    constexpr unsigned most_significant_digit() const noexcept {
        unsigned n = num_digits;
        for (auto i = digits_.begin(); i != digits_.end() && *i == 0; ++i, --n);
        return n;
    }

    /**
     * Gets the value of a particular digit.
     *
     * @param power The power, i.e. base^power, of the digit to get. Essentially the reverse index.
     *
     * @returns The value of the digit. Powers beyond NDigits/num_digits will always yield zero.
     */
    constexpr digit_type digit(unsigned power) const noexcept {
        return power >= num_digits ? 0 : digits_[num_digits - 1 - power];
    }

    /**
     * Sets the value of a particular digit.
     *
     * @param power The power, i.e. base^power, of the digit to set. Essentially the reverse index.
     * @param value The value to set the digit to. May be truncated mod base.
     *
     * @note Setting the value of digits for powers beyond NDigits/num_digits will succeed, but will
     *       be a no-op.
     */
    constexpr void set_digit(unsigned power, digit_type value) noexcept {
        if (power < num_digits) {
            digits_[num_digits - 1 - power] = value % base;
        }
    }

    /**
     * Returns true if the number is even.
     */
    constexpr bool is_even() const noexcept {
        return (digit(0) & 1) == 0;
    }

    /**
     * Returns true if the number is odd.
     */
    constexpr bool is_odd() const noexcept {
        return (digit(0) & 1) == 1;
    }

    /**
     * Returns the number of bits needed to represent the number, i.e. the position of the highest
     * set bit plus one. Returns zero for a zero value.
     */
    constexpr unsigned bit_width() const noexcept {
        static constexpr unsigned bits_per_digit =
            std::bit_width(static_cast<std::uint64_t>(digit_max));

        for (unsigned i = num_digits; i > 0; --i) {
            digit_type d = digits_[num_digits - i];
            if (d != 0) {
                return (i - 1) * bits_per_digit +
                    std::bit_width(static_cast<std::uint64_t>(d));
            }
        }
        return 0;
    }

    /**
     * Compute the greatest common divisor of this number and another using the Euclidean algorithm.
     *
     * @param other The other number.
     *
     * @returns The greatest common divisor.
     */
    constexpr number gcd(const number& other) const noexcept {
        number a = *this;
        number b = other;
        number zero(0U);

        while (b) {
            number t = b;
            b = a % b;
            a = t;
        }

        return a;
    }

private:
    /**
     * Type used to store the digits for this number.
     */
    using digits = std::array<digit_type, num_digits>;

    /**
     * Type used to store intermediate results of calculations between digits that might overflow.
     */
    using big_digit_type =
        std::conditional_t<sizeof(digit_type) <= sizeof(std::uint8_t),  std::uint16_t,
            std::conditional_t<sizeof(digit_type) <= sizeof(std::uint16_t), std::uint32_t,
                std::conditional_t<sizeof(digit_type) <= sizeof(std::uint32_t), std::uint64_t,
                    void>>>;

    /**
     * The number base used to store the digits this number.
     */
    static constexpr big_digit_type base = static_cast<big_digit_type>(digit_max) + 1;

    /**
     * Stores the digit information for the number. More significant digits have lower indices.
     */
    digits digits_;
};

/**
 * Output stream operator for numbers. Respects the base, showbase, uppercase, width, fill, and
 * alignment flags of the stream.
 *
 * @param stream Stream to output the number on.
 * @param num    Number to output on the stream.
 *
 * @returns A reference to the original output stream.
 */
template <typename TDigit, unsigned NDigits, TDigit NDigitMax>
std::ostream& operator<<(std::ostream& stream, const number<TDigit, NDigits, NDigitMax>& num) {
    string_base sb = string_base::decimal;
    switch (stream.flags() & std::ios_base::basefield) {
    case std::ios_base::oct: sb = string_base::octal; break;
    case std::ios_base::hex: sb = string_base::hexadecimal; break;
    default: break;
    }

    std::string digits = num.to_string(sb);

    bool upper = stream.flags() & std::ios_base::uppercase;
    if (upper) {
        for (auto& c : digits) {
            if (c >= 'a' && c <= 'f') c -= ('a' - 'A');
        }
    }

    std::string_view prefix;
    if (stream.flags() & std::ios_base::showbase) {
        if (sb == string_base::octal && digits != "0") {
            prefix = "0o";
        } else if (sb == string_base::hexadecimal) {
            prefix = upper ? "0X" : "0x";
        }
    }

    auto w = stream.width();
    auto content_len = static_cast<std::streamsize>(prefix.size() + digits.size());
    std::streamsize pad = (w > content_len) ? w - content_len : 0;
    char fill = stream.fill();
    auto adjust = stream.flags() & std::ios_base::adjustfield;

    stream.width(0);

    if (adjust == std::ios_base::left) {
        stream.write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
        stream.write(digits.data(), static_cast<std::streamsize>(digits.size()));
        for (std::streamsize i = 0; i < pad; ++i) stream.put(fill);
    } else if (adjust == std::ios_base::internal) {
        stream.write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
        for (std::streamsize i = 0; i < pad; ++i) stream.put(fill);
        stream.write(digits.data(), static_cast<std::streamsize>(digits.size()));
    } else {
        for (std::streamsize i = 0; i < pad; ++i) stream.put(fill);
        stream.write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
        stream.write(digits.data(), static_cast<std::streamsize>(digits.size()));
    }

    return stream;
}

/**
 * Input stream operator for numbers. Respects the base flags of the stream and handles base
 * prefixes (0x/0X for hex, 0o/0O for octal, 0b/0B for binary). When no base flag is set,
 * auto-detects the base from the prefix, defaulting to decimal.
 *
 * @param stream Stream to get the number from.
 * @param num    Reference to the number to get from the stream.
 *
 * @returns A reference to the original input stream.
 */
template <typename TDigit, unsigned NDigits, TDigit NDigitMax>
std::istream& operator>>(std::istream& stream, number<TDigit, NDigits, NDigitMax>& out) {
    using num = number<TDigit, NDigits, NDigitMax>;

    std::string number_string;
    stream >> number_string;

    if (number_string.empty()) {
        stream.setstate(std::ios_base::failbit);
        return stream;
    }

    auto strip_prefix = [](std::string_view s, std::string_view prefix) -> std::string_view {
        if (s.size() > prefix.size() &&
            std::string_view(s.data(), prefix.size()) == prefix) {
            return s.substr(prefix.size());
        }
        return s;
    };

    std::string_view digits = number_string;
    string_base sb;

    auto basefield = stream.flags() & std::ios_base::basefield;
    if (basefield == std::ios_base::hex) {
        sb = string_base::hexadecimal;
        digits = strip_prefix(digits, "0x");
        digits = strip_prefix(digits, "0X");
    } else if (basefield == std::ios_base::oct) {
        sb = string_base::octal;
        digits = strip_prefix(digits, "0o");
        digits = strip_prefix(digits, "0O");
        // Also accept a bare leading 0 as an octal indicator.
        if (digits.size() > 1 && digits[0] == '0') {
            digits = digits.substr(1);
        }
    } else if (basefield == std::ios_base::dec) {
        sb = string_base::decimal;
    } else {
        // No base flag set: auto-detect from prefix.
        if (digits.size() > 1 && digits[0] == '0') {
            char second = digits[1];
            if (second == 'x' || second == 'X') {
                sb = string_base::hexadecimal;
                digits = digits.substr(2);
            } else if (second == 'o' || second == 'O') {
                sb = string_base::octal;
                digits = digits.substr(2);
            } else if (second == 'b' || second == 'B') {
                sb = string_base::binary;
                digits = digits.substr(2);
            } else {
                // Leading zero with digits: treat as octal.
                sb = string_base::octal;
                digits = digits.substr(1);
            }
        } else {
            sb = string_base::decimal;
        }
    }

    if (digits.empty()) {
        // Prefix with no digits (e.g. just "0x") is invalid, except "0" alone is valid.
        if (number_string == "0") {
            out = num(0U);
        } else {
            stream.setstate(std::ios_base::failbit);
        }
        return stream;
    }

    if (auto result = num::from_string(digits, sb)) {
        out = *result;
    } else {
        stream.setstate(std::ios_base::failbit);
    }

    return stream;
}

/**
 * std::format support for numbers. Supports the standard integer format spec:
 *
 *   [[fill]align][#][0][width][type]
 *
 * Where:
 *   fill   Any character (default: space)
 *   align  '<' (left), '>' (right, default), '^' (center)
 *   #      Alternate form: adds base prefix (0b, 0o, 0x)
 *   0      Zero-pad between prefix and digits (ignored if align is set)
 *   width  Minimum field width
 *   type   'b'/'B' (binary), 'o' (octal), 'd' (decimal), 'x'/'X' (hex)
 */
template <typename TDigit, unsigned NDigits, TDigit NDigitMax>
struct std::formatter<number<TDigit, NDigits, NDigitMax>> {
    char fill_ = ' ';
    char align_ = '\0';
    bool alternate_ = false;
    bool zero_pad_ = false;
    int width_ = 0;
    char type_ = 'd';

    constexpr auto parse(std::format_parse_context& ctx) -> std::format_parse_context::iterator {
        auto it = ctx.begin();
        auto end = ctx.end();

        auto is_align = [](char c) { return c == '<' || c == '>' || c == '^'; };

        if (it != end && it + 1 != end && is_align(*(it + 1))) {
            fill_ = *it;
            align_ = *(it + 1);
            it += 2;
        } else if (it != end && is_align(*it)) {
            align_ = *it;
            ++it;
        }

        if (it != end && *it == '#') {
            alternate_ = true;
            ++it;
        }

        if (it != end && *it == '0') {
            zero_pad_ = true;
            ++it;
        }

        while (it != end && *it >= '0' && *it <= '9') {
            width_ = width_ * 10 + (*it - '0');
            ++it;
        }

        if (it != end) {
            switch (*it) {
            case 'b': case 'B': case 'o': case 'd': case 'x': case 'X':
                type_ = *it;
                ++it;
                break;
            default:
                break;
            }
        }

        if (it != end && *it != '}') {
            throw std::format_error("invalid format specifier for number");
        }

        return it;
    }

    auto format(
        const number<TDigit, NDigits, NDigitMax>& num, std::format_context& ctx
    ) const -> std::format_context::iterator {
        string_base sb;
        switch (type_) {
        case 'b': case 'B': sb = string_base::binary; break;
        case 'o': sb = string_base::octal; break;
        case 'x': case 'X': sb = string_base::hexadecimal; break;
        default: sb = string_base::decimal; break;
        }

        std::string digits = num.to_string(sb);

        if (type_ == 'X' || type_ == 'B') {
            for (auto& c : digits) {
                if (c >= 'a' && c <= 'f') c -= ('a' - 'A');
            }
        }

        std::string_view prefix;
        if (alternate_) {
            switch (type_) {
            case 'b': prefix = "0b"; break;
            case 'B': prefix = "0B"; break;
            case 'o': if (digits != "0") prefix = "0o"; break;
            case 'x': prefix = "0x"; break;
            case 'X': prefix = "0X"; break;
            default: break;
            }
        }

        std::size_t content_len = prefix.size() + digits.size();
        std::size_t pad = (width_ > 0 && static_cast<std::size_t>(width_) > content_len)
            ? static_cast<std::size_t>(width_) - content_len : 0;

        auto out = ctx.out();

        bool use_zero_pad = zero_pad_ && align_ == '\0';
        char eff_fill = use_zero_pad ? '0' : fill_;
        char eff_align = align_ != '\0' ? align_ : '>';

        auto write_chars = [&](std::string_view sv) { for (char c : sv) *out++ = c; };
        auto write_pad = [&](std::size_t n) { for (std::size_t i = 0; i < n; ++i) *out++ = eff_fill; };

        if (use_zero_pad) {
            write_chars(prefix);
            write_pad(pad);
            write_chars(digits);
        } else if (eff_align == '<') {
            write_chars(prefix);
            write_chars(digits);
            write_pad(pad);
        } else if (eff_align == '^') {
            write_pad(pad / 2);
            write_chars(prefix);
            write_chars(digits);
            write_pad(pad - pad / 2);
        } else {
            write_pad(pad);
            write_chars(prefix);
            write_chars(digits);
        }

        return out;
    }
};

#endif /* NUMBER_HPP_ */
