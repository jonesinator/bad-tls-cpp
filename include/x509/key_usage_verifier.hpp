/**
 * X.509 KeyUsage extension verification — RFC 5280 Section 4.2.1.3.
 *
 * Provides a certificate_verifier that enforces KeyUsage constraints:
 *   - If the KeyUsage extension is absent, the certificate passes
 *     (the extension is optional per RFC 5280).
 *   - If present on a non-leaf (depth > 0) certificate, the keyCertSign
 *     bit must be set (required for CA certificates that sign other certs).
 */

#pragma once

#include <x509/verify.hpp>

namespace asn1::x509 {

enum class key_usage_bit : uint8_t {
    digital_signature = 0,
    non_repudiation   = 1,
    key_encipherment  = 2,
    data_encipherment = 3,
    key_agreement     = 4,
    key_cert_sign     = 5,
    crl_sign          = 6,
    encipher_only     = 7,
    decipher_only     = 8,
};

namespace detail {

// Test whether a specific bit is set in a DER-encoded BIT STRING.
// BIT STRING bit numbering: bit 0 is the MSB of byte 0.
inline bool has_key_usage_bit(const der::BitString& bs, key_usage_bit bit) {
    auto idx = static_cast<uint8_t>(bit);
    size_t byte_idx = idx / 8;
    uint8_t bit_offset = 7 - (idx % 8);  // MSB-first within each byte
    if (byte_idx >= bs.bytes.size()) return false;
    return (bs.bytes[byte_idx] >> bit_offset) & 1;
}

// Extract the KeyUsage BIT STRING from a certificate's extensions.
// Returns nullopt if the extension is absent.
inline auto parse_key_usage(const Certificate& cert) -> std::optional<der::BitString> {
    auto& tbs = cert.get<"tbsCertificate">();
    if (!tbs.get<"extensions">().has_value())
        return std::nullopt;

    auto& exts = *tbs.get<"extensions">();
    for (size_t i = 0; i < exts.size(); ++i) {
        if (exts[i].get<"extnID">().to_string() == "2.5.29.15") {
            auto& ext_val = exts[i].get<"extnValue">();
            der::Reader r{ext_val.bytes};
            return r.read_bit_string();
        }
    }
    return std::nullopt;
}

} // namespace detail

// KeyUsage verifier — satisfies the certificate_verifier concept.
struct key_usage_verifier {
    bool verify(const cert_context& ctx) const {
        auto ku = detail::parse_key_usage(ctx.cert);
        if (!ku) return true;  // Extension absent: no restriction

        if (ctx.depth > 0) {
            // Non-leaf: must have keyCertSign
            if (!detail::has_key_usage_bit(*ku, key_usage_bit::key_cert_sign))
                return false;
        }
        return true;
    }
};

} // namespace asn1::x509
