/**
 * X.509 certificate time validation — RFC 5280 Section 4.1.2.5.
 *
 * Provides a certificate_verifier that checks each certificate's
 * notBefore and notAfter fields against a reference time.
 *
 * Supports both system clock (default) and manually specified time
 * points for testing and reproducibility.
 *
 * Time formats:
 *   - UTCTime:         YYMMDDHHMMSSZ (13 bytes, YY>=50 → 19YY, YY<50 → 20YY)
 *   - GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes)
 */

#pragma once

#include <x509/verify.hpp>
#include <chrono>
#include <ctime>
#include <optional>
#include <stdexcept>

namespace asn1::x509 {

namespace detail {

// Parse a 2-digit decimal value from raw bytes at the given offset.
inline int parse_2digits(const std::vector<uint8_t>& bytes, size_t offset) {
    return (bytes[offset] - '0') * 10 + (bytes[offset + 1] - '0');
}

// Parse a 4-digit decimal value from raw bytes at the given offset.
inline int parse_4digits(const std::vector<uint8_t>& bytes, size_t offset) {
    return (bytes[offset] - '0') * 1000 +
           (bytes[offset + 1] - '0') * 100 +
           (bytes[offset + 2] - '0') * 10 +
           (bytes[offset + 3] - '0');
}

// Parse an X.509 Time CHOICE (UTCTime or GeneralizedTime) into a time_point.
inline auto parse_x509_time(const auto& time_choice)
    -> std::chrono::system_clock::time_point
{
    int year, month, day, hour, minute, second;

    if (time_choice.value.index() == 0) {
        // UTCTime: YYMMDDHHMMSSZ
        auto& bytes = time_choice.template as<"utcTime">().bytes;
        if (bytes.size() != 13 || bytes[12] != 'Z')
            throw std::runtime_error{"invalid UTCTime format"};

        int yy = parse_2digits(bytes, 0);
        year = (yy >= 50) ? 1900 + yy : 2000 + yy;
        month  = parse_2digits(bytes, 2);
        day    = parse_2digits(bytes, 4);
        hour   = parse_2digits(bytes, 6);
        minute = parse_2digits(bytes, 8);
        second = parse_2digits(bytes, 10);
    } else {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        auto& bytes = time_choice.template as<"generalTime">().bytes;
        if (bytes.size() < 15 || bytes[14] != 'Z')
            throw std::runtime_error{"invalid GeneralizedTime format"};

        year   = parse_4digits(bytes, 0);
        month  = parse_2digits(bytes, 4);
        day    = parse_2digits(bytes, 6);
        hour   = parse_2digits(bytes, 8);
        minute = parse_2digits(bytes, 10);
        second = parse_2digits(bytes, 12);
    }

    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon  = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min  = minute;
    tm.tm_sec  = second;
    tm.tm_isdst = 0;

    std::time_t t = timegm(&tm);
    if (t == static_cast<std::time_t>(-1))
        throw std::runtime_error{"failed to convert X.509 time"};

    return std::chrono::system_clock::from_time_t(t);
}

} // namespace detail

// Time verifier — satisfies the certificate_verifier concept.
// Checks notBefore <= check_time <= notAfter for every certificate in the chain.
struct time_verifier {
    // If set, verify against this time; otherwise use system_clock::now().
    std::optional<std::chrono::system_clock::time_point> check_time;

    bool verify(const cert_context& ctx) const {
        auto tp = check_time.value_or(std::chrono::system_clock::now());
        auto& validity = ctx.cert.get<"tbsCertificate">().get<"validity">();
        auto not_before = detail::parse_x509_time(validity.get<"notBefore">());
        auto not_after  = detail::parse_x509_time(validity.get<"notAfter">());
        return not_before <= tp && tp <= not_after;
    }
};

} // namespace asn1::x509
