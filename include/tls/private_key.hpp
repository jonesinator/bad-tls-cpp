/**
 * EC private key loading from PEM — RFC 5915 (SEC 1) and RFC 5958 (PKCS#8).
 *
 * Supports two PEM formats:
 *   - "EC PRIVATE KEY" (SEC 1 / ECPrivateKey)
 *   - "PRIVATE KEY" (PKCS#8 / OneAsymmetricKey wrapping ECPrivateKey)
 *
 * Returns the private scalar and detected curve for use with tls_server.
 */

#pragma once

#include "types.hpp"
#include <asn1/parser.hpp>
#include <asn1/pem.hpp>
#include <asn1/der/codegen.hpp>
#include <crypto/ecc.hpp>
#include <stdexcept>
#include <string_view>
#include <variant>
#include <vector>

namespace tls {

namespace detail {
    constexpr char ecc_asn1[] = {
        #embed "definitions/ecprivatekey.asn1"
    };
    constexpr auto EccMod = asn1::parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});
} // namespace detail

using ec_private_key = std::variant<
    asn1::x509::p256_curve::number_type,   // P-256 scalar
    asn1::x509::p384_curve::number_type    // P-384 scalar
>;

struct loaded_key {
    ec_private_key key;
    NamedCurve curve;
};

inline loaded_key load_ec_private_key(std::string_view pem_text) {
    auto blocks = asn1::pem::decode_all(pem_text);
    if (blocks.empty())
        throw std::runtime_error{"no PEM blocks found"};

    std::vector<uint8_t> priv_bytes;

    for (auto& block : blocks) {
        if (block.label == "EC PRIVATE KEY") {
            // SEC 1 format: ECPrivateKey directly
            asn1::der::Reader r{block.der};
            auto key = asn1::der::decode<detail::EccMod,
                detail::EccMod.find_type("ECPrivateKey")>(r);
            priv_bytes = key.get<"privateKey">().bytes;
            break;
        }

        if (block.label == "PRIVATE KEY") {
            // PKCS#8 format: OneAsymmetricKey wrapping ECPrivateKey
            asn1::der::Reader r{block.der};
            auto oakey = asn1::der::decode<detail::EccMod,
                detail::EccMod.find_type("OneAsymmetricKey")>(r);

            // The privateKey OCTET STRING contains a DER-encoded ECPrivateKey
            auto& inner_bytes = oakey.get<"privateKey">().bytes;
            asn1::der::Reader inner_r{inner_bytes};
            auto ec_key = asn1::der::decode<detail::EccMod,
                detail::EccMod.find_type("ECPrivateKey")>(inner_r);
            priv_bytes = ec_key.get<"privateKey">().bytes;
            break;
        }
    }

    if (priv_bytes.empty())
        throw std::runtime_error{"no EC private key found in PEM"};

    if (priv_bytes.size() <= 32) {
        // Pad to 32 bytes if needed
        while (priv_bytes.size() < 32)
            priv_bytes.insert(priv_bytes.begin(), 0);
        auto d = asn1::x509::p256_curve::number_type::from_bytes(priv_bytes);
        return {ec_private_key{d}, NamedCurve::secp256r1};
    }

    if (priv_bytes.size() <= 48) {
        while (priv_bytes.size() < 48)
            priv_bytes.insert(priv_bytes.begin(), 0);
        auto d = asn1::x509::p384_curve::number_type::from_bytes(priv_bytes);
        return {ec_private_key{d}, NamedCurve::secp384r1};
    }

    throw std::runtime_error{"unsupported EC key size"};
}

} // namespace tls
