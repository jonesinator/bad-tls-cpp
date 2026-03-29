/**
 * X.509 hostname verification — RFC 6125, RFC 2818.
 *
 * Provides a certificate_verifier that checks the server's certificate
 * against an expected hostname using Subject Alternative Names (SAN)
 * and Common Name (CN) fallback.
 *
 * Matching rules:
 *   - If SAN extension (2.5.29.17) exists, match dNSName entries only
 *   - If no SAN, fall back to CN in the subject
 *   - Wildcard matching: *.example.com matches foo.example.com
 *     but not foo.bar.example.com or example.com
 */

#pragma once

#include <x509/verify.hpp>
#include <string_view>

namespace asn1::x509 {

namespace detail {

// Case-insensitive comparison for hostnames (ASCII only)
inline bool hostname_eq(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

// Match a hostname against a pattern that may contain a leading wildcard.
// RFC 6125 Section 6.4.3: wildcard must be leftmost label only,
// must not match across dots, and the pattern must have at least 2 dots
// (*.com is not valid).
inline bool match_hostname(std::string_view pattern, std::string_view hostname) {
    if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        // Wildcard pattern: *.example.com
        auto suffix = pattern.substr(1); // .example.com

        // Suffix must have at least one more dot (so *.com fails)
        if (suffix.find('.', 1) == std::string_view::npos)
            return false;

        // Hostname must have a dot separating the first label from the rest
        auto dot = hostname.find('.');
        if (dot == std::string_view::npos)
            return false;

        // The part after the first label must match the wildcard suffix
        return hostname_eq(hostname.substr(dot), suffix);
    }
    return hostname_eq(pattern, hostname);
}

// Extract dNSName entries from a DER-encoded GeneralNames sequence.
// GeneralNames ::= SEQUENCE OF GeneralName
// GeneralName ::= CHOICE { ... dNSName [2] IA5String ... }
inline std::vector<std::string> extract_dns_names(std::span<const uint8_t> general_names_der) {
    std::vector<std::string> names;
    der::Reader r{general_names_der};
    auto seq_hdr = r.read_header();  // outer SEQUENCE
    auto seq_reader = r.scoped(seq_hdr.length);

    while (!seq_reader.at_end()) {
        auto hdr = seq_reader.read_header();
        auto content = seq_reader.read_content(hdr.length);

        // dNSName is context-specific [2], primitive
        // Tag byte: 0x82 (context class 0x80 | tag number 2)
        if (hdr.class_bits == 0x80 && hdr.tag_number == 2) {
            names.emplace_back(
                reinterpret_cast<const char*>(content.data()), content.size());
        }
    }
    return names;
}

// Extract the Common Name from a certificate's subject.
// Walks the RDNSequence looking for OID 2.5.4.3 (CN).
inline std::string extract_common_name(const Certificate& cert) {
    auto& subject = cert.get<"tbsCertificate">().get<"subject">();
    // Subject is CHOICE { rdnSequence RDNSequence }
    // RDNSequence is SEQUENCE OF RelativeDistinguishedName
    // RDN is SET OF AttributeTypeAndValue
    // ATV is SEQUENCE { type OID, value ANY }
    auto& rdn_seq = subject.as<"rdnSequence">();
    for (size_t i = 0; i < rdn_seq.size(); ++i) {
        auto& rdn = rdn_seq[i];
        for (size_t j = 0; j < rdn.size(); ++j) {
            auto& atv = rdn[j];
            if (atv.get<"type">().to_string() == "2.5.4.3") {
                // CN value is ANY — read as raw bytes, interpret as string
                auto& val = atv.get<"value">();
                // AnyValue contains the full TLV; skip tag+length to get content
                der::Reader vr{val.raw_tlv};
                auto vh = vr.read_header();
                auto vc = vr.read_content(vh.length);
                return std::string(reinterpret_cast<const char*>(vc.data()), vc.size());
            }
        }
    }
    return {};
}

} // namespace detail

// Hostname verifier — satisfies the certificate_verifier concept.
// Only checks the leaf certificate (depth == 0).
struct hostname_verifier {
    std::string_view expected_hostname;

    bool verify(const cert_context& ctx) const {
        // Only verify the leaf certificate
        if (ctx.depth != 0) return true;

        auto& cert = ctx.cert;
        auto& tbs = cert.get<"tbsCertificate">();

        // Look for SAN extension (OID 2.5.29.17)
        if (tbs.get<"extensions">().has_value()) {
            auto& exts = *tbs.get<"extensions">();
            for (size_t i = 0; i < exts.size(); ++i) {
                if (exts[i].get<"extnID">().to_string() == "2.5.29.17") {
                    // Found SAN — extract dNSName entries from extnValue
                    auto& ext_val = exts[i].get<"extnValue">();
                    auto dns_names = detail::extract_dns_names(ext_val.bytes);

                    // If SAN exists, CN is not checked (RFC 6125 Section 6.4.4)
                    for (auto& name : dns_names) {
                        if (detail::match_hostname(name, expected_hostname))
                            return true;
                    }
                    return false;
                }
            }
        }

        // No SAN — fall back to CN
        auto cn = detail::extract_common_name(cert);
        if (cn.empty()) return false;
        return detail::match_hostname(cn, expected_hostname);
    }
};

} // namespace asn1::x509
