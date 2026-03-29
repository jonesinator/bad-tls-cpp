/**
 * X.509 trust store — a collection of trusted root CA certificates.
 *
 * Root certificates are matched by comparing the DER-encoded subject Name
 * of the root against the issuer Name of the certificate being verified.
 */

#pragma once

#include <x509/verify.hpp>
#include <optional>
#include <vector>

namespace asn1::x509 {

struct trust_store {
    struct root_entry {
        std::vector<uint8_t> subject_der;  // Re-encoded subject Name DER
        Certificate cert;
        std::vector<uint8_t> cert_der;
    };

    std::vector<root_entry> roots;

    void add(std::vector<uint8_t> cert_der) {
        auto cert = parse_certificate(cert_der);

        // Re-encode subject Name to canonical DER for matching
        der::Writer w;
        der::encode<X509Mod, X509Mod.find_type("Name")>(
            w, cert.get<"tbsCertificate">().get<"subject">());
        auto subject_der = std::move(w).finish();

        roots.push_back({
            std::move(subject_der),
            std::move(cert),
            std::move(cert_der)
        });
    }

    void add_pem(std::string_view pem) {
        auto block = asn1::pem::decode(pem);
        add(std::move(block.der));
    }

    struct root_match {
        const Certificate& cert;
        std::span<const uint8_t> cert_der;
    };

    auto find_issuer(const Certificate& cert) const -> std::optional<root_match> {
        // Re-encode the certificate's issuer Name
        der::Writer w;
        der::encode<X509Mod, X509Mod.find_type("Name")>(
            w, cert.get<"tbsCertificate">().get<"issuer">());
        auto issuer_der = std::move(w).finish();

        for (auto& root : roots) {
            if (root.subject_der == issuer_der)
                return root_match{root.cert, root.cert_der};
        }
        return std::nullopt;
    }
};

} // namespace asn1::x509
