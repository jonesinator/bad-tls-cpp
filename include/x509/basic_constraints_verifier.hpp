/**
 * X.509 BasicConstraints extension verification — RFC 5280 Section 4.2.1.9.
 *
 * Provides a certificate_verifier that enforces BasicConstraints:
 *   - Non-leaf certificates (depth > 0) MUST have the BasicConstraints
 *     extension with cA=TRUE.
 *   - If pathLenConstraint is present, the number of intermediate CA
 *     certificates between this CA and the leaf must not exceed it.
 *   - Leaf certificates (depth == 0) are not required to have this extension.
 */

#pragma once

#include <x509/verify.hpp>
#include <optional>

namespace asn1::x509 {

namespace detail {

struct basic_constraints_value {
    bool ca = false;
    std::optional<int64_t> path_len_constraint;
};

// Parse the BasicConstraints extension from a certificate.
// Returns nullopt if the extension is absent.
//
// BasicConstraints ::= SEQUENCE {
//     cA                  BOOLEAN DEFAULT FALSE,
//     pathLenConstraint   INTEGER (0..MAX) OPTIONAL
// }
inline auto parse_basic_constraints(const Certificate& cert)
    -> std::optional<basic_constraints_value>
{
    auto& tbs = cert.get<"tbsCertificate">();
    if (!tbs.get<"extensions">().has_value())
        return std::nullopt;

    auto& exts = *tbs.get<"extensions">();
    for (size_t i = 0; i < exts.size(); ++i) {
        if (exts[i].get<"extnID">().to_string() == "2.5.29.19") {
            auto& ext_val = exts[i].get<"extnValue">();
            der::Reader r{ext_val.bytes};
            auto seq = r.enter_sequence();

            basic_constraints_value bc;

            // cA BOOLEAN DEFAULT FALSE — may be absent
            if (!seq.at_end() && seq.peek_matches(0x00, der::TagBoolean)) {
                bc.ca = seq.read_boolean().value;
            }

            // pathLenConstraint INTEGER OPTIONAL
            if (!seq.at_end() && seq.peek_matches(0x00, der::TagInteger)) {
                bc.path_len_constraint = seq.read_integer().to_int64();
            }

            return bc;
        }
    }
    return std::nullopt;
}

} // namespace detail

// BasicConstraints verifier — satisfies the certificate_verifier concept.
struct basic_constraints_verifier {
    bool verify(const cert_context& ctx) const {
        // Leaf certificates: no BasicConstraints required
        if (ctx.depth == 0) return true;

        // Non-leaf: MUST have BasicConstraints with cA=TRUE
        auto bc = detail::parse_basic_constraints(ctx.cert);
        if (!bc || !bc->ca) return false;

        // Enforce pathLenConstraint if present.
        // ctx.depth counts up from 0 (leaf). This cert is at ctx.depth.
        // The number of intermediate CA certs between this CA and the
        // leaf is (ctx.depth - 1).
        if (bc->path_len_constraint.has_value()) {
            auto intermediates_below = static_cast<int64_t>(ctx.depth) - 1;
            if (intermediates_below > *bc->path_len_constraint)
                return false;
        }

        return true;
    }
};

} // namespace asn1::x509
