/**
 * Private key loading from PEM — EC (RFC 5915, RFC 5958) and RSA (PKCS#1, PKCS#8).
 *
 * Supports PEM formats:
 *   - "EC PRIVATE KEY"      (SEC 1 / ECPrivateKey)
 *   - "RSA PRIVATE KEY"     (PKCS#1 / RSAPrivateKey)
 *   - "PRIVATE KEY"         (PKCS#8 / OneAsymmetricKey — auto-detects EC vs RSA)
 *
 * Returns the private key and detected key type for use with tls_client/tls_server.
 */

#pragma once

#include "types.hpp"
#include <asn1/parser.hpp>
#include <asn1/pem.hpp>
#include <asn1/der/codegen.hpp>
#include <asn1/der/reader.hpp>
#include <crypto/ecc.hpp>
#include <crypto/rsa.hpp>
#include <number/number.hpp>
#include <stdexcept>
#include <string_view>
#include <variant>
#include <vector>

namespace tls {

// Key backing types — same instantiations as asn1::x509 aliases
using rsa_num = number<uint32_t, 256>;
using p256_curve = p256<number<uint32_t, 16>>;
using p384_curve = p384<number<uint32_t, 24>>;

namespace detail {
    constexpr char ecc_asn1[] = {
        #embed "definitions/ecprivatekey.asn1"
    };
    constexpr auto EccMod = asn1::parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});
} // namespace detail

// --- Key types ---

using ec_private_key = std::variant<
    p256_curve::number_type,   // P-256 scalar
    p384_curve::number_type    // P-384 scalar
>;

using tls_private_key = std::variant<
    p256_curve::number_type,   // P-256 scalar
    p384_curve::number_type,   // P-384 scalar
    rsa_private_key<rsa_num>   // RSA private key
>;

enum class key_type { ec, rsa };

struct loaded_key {
    tls_private_key key;
    NamedCurve curve = NamedCurve::secp256r1;  // only meaningful for EC keys
    key_type type = key_type::ec;

    // Extract EC key variant for use with configs that expect ec_private_key.
    // Throws if the key is not EC.
    ec_private_key ec_key() const {
        if (auto* p = std::get_if<p256_curve::number_type>(&key))
            return *p;
        if (auto* p = std::get_if<p384_curve::number_type>(&key))
            return *p;
        throw std::runtime_error{"key is not EC"};
    }
};

// --- RSA private key parsing (manual DER, mirrors rsa_tool.cpp) ---

namespace detail {

inline rsa_num read_rsa_integer(asn1::der::Reader& r) {
    auto hdr = r.read_header();
    auto content = r.read_content(hdr.length);
    // Strip leading zero byte used for sign padding
    size_t start = 0;
    while (start < content.size() - 1 && content[start] == 0) ++start;
    return rsa_num::from_bytes(
        std::span<const uint8_t>(content.data() + start, content.size() - start));
}

inline void skip_der_element(asn1::der::Reader& r) {
    auto hdr = r.read_header();
    r.read_content(hdr.length);
}

// Parse PKCS#1 RSAPrivateKey: SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
inline rsa_private_key<rsa_num> parse_rsa_private_key_pkcs1(
    std::span<const uint8_t> der)
{
    asn1::der::Reader r{der};
    r.read_header();  // outer SEQUENCE
    skip_der_element(r);  // version INTEGER
    auto n = read_rsa_integer(r);
    skip_der_element(r);  // e (public exponent — not needed for signing)
    auto d = read_rsa_integer(r);
    return {n, d};
}

// Check if PKCS#8 AlgorithmIdentifier OID is RSA (1.2.840.113549.1.1.1)
inline bool is_rsa_oid(std::span<const uint8_t> oid_content) {
    // DER encoding of 1.2.840.113549.1.1.1
    static constexpr uint8_t rsa_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    if (oid_content.size() != sizeof(rsa_oid)) return false;
    for (size_t i = 0; i < sizeof(rsa_oid); ++i)
        if (oid_content[i] != rsa_oid[i]) return false;
    return true;
}

// Check if PKCS#8 AlgorithmIdentifier OID is EC (1.2.840.10045.2.1)
inline bool is_ec_oid(std::span<const uint8_t> oid_content) {
    static constexpr uint8_t ec_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
    if (oid_content.size() != sizeof(ec_oid)) return false;
    for (size_t i = 0; i < sizeof(ec_oid); ++i)
        if (oid_content[i] != ec_oid[i]) return false;
    return true;
}

} // namespace detail

// --- Loaders ---

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
        auto d = p256_curve::number_type::from_bytes(priv_bytes);
        return {tls_private_key{d}, NamedCurve::secp256r1, key_type::ec};
    }

    if (priv_bytes.size() <= 48) {
        while (priv_bytes.size() < 48)
            priv_bytes.insert(priv_bytes.begin(), 0);
        auto d = p384_curve::number_type::from_bytes(priv_bytes);
        return {tls_private_key{d}, NamedCurve::secp384r1, key_type::ec};
    }

    throw std::runtime_error{"unsupported EC key size"};
}

inline loaded_key load_rsa_private_key(std::string_view pem_text) {
    auto blocks = asn1::pem::decode_all(pem_text);
    if (blocks.empty())
        throw std::runtime_error{"no PEM blocks found"};

    for (auto& block : blocks) {
        if (block.label == "RSA PRIVATE KEY") {
            auto key = detail::parse_rsa_private_key_pkcs1(block.der);
            return {tls_private_key{key}, NamedCurve::secp256r1, key_type::rsa};
        }

        if (block.label == "PRIVATE KEY") {
            // PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { RSAPrivateKey } }
            asn1::der::Reader r{block.der};
            r.read_header();  // outer SEQUENCE
            detail::skip_der_element(r);  // version
            detail::skip_der_element(r);  // AlgorithmIdentifier
            auto os_hdr = r.read_header();  // OCTET STRING
            auto os_content = r.read_content(os_hdr.length);
            std::vector<uint8_t> inner(os_content.begin(), os_content.end());
            auto key = detail::parse_rsa_private_key_pkcs1(inner);
            return {tls_private_key{key}, NamedCurve::secp256r1, key_type::rsa};
        }
    }

    throw std::runtime_error{"no RSA private key found in PEM"};
}

// Unified loader: auto-detects EC vs RSA from PEM label and PKCS#8 OID.
inline loaded_key load_private_key(std::string_view pem_text) {
    auto blocks = asn1::pem::decode_all(pem_text);
    if (blocks.empty())
        throw std::runtime_error{"no PEM blocks found"};

    for (auto& block : blocks) {
        if (block.label == "EC PRIVATE KEY")
            return load_ec_private_key(pem_text);

        if (block.label == "RSA PRIVATE KEY")
            return load_rsa_private_key(pem_text);

        if (block.label == "PRIVATE KEY") {
            // PKCS#8: inspect AlgorithmIdentifier OID to determine key type
            asn1::der::Reader r{block.der};
            r.read_header();  // outer SEQUENCE
            detail::skip_der_element(r);  // version INTEGER

            // AlgorithmIdentifier: SEQUENCE { OID, ... }
            r.read_header();  // AlgorithmIdentifier SEQUENCE header
            auto oid_hdr = r.read_header();  // OID header
            auto oid_content = r.read_content(oid_hdr.length);

            if (detail::is_rsa_oid(oid_content))
                return load_rsa_private_key(pem_text);
            if (detail::is_ec_oid(oid_content))
                return load_ec_private_key(pem_text);

            throw std::runtime_error{"unsupported PKCS#8 key algorithm"};
        }
    }

    throw std::runtime_error{"no private key found in PEM"};
}

} // namespace tls
