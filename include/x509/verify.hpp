/**
 * X.509 certificate chain verification framework.
 *
 * Provides:
 *   - TBS byte extraction from raw Certificate DER
 *   - Public key extraction from SubjectPublicKeyInfo (RSA and EC)
 *   - Single certificate signature verification (RSA PKCS#1 v1.5, ECDSA)
 *   - Chain verification with modular verifier policies
 *
 * The certificate_verifier concept allows callers to attach custom
 * verification policies (name chaining, basic constraints, etc.).
 */

#pragma once

#include <asn1/parser.hpp>
#include <asn1/pem.hpp>
#include <asn1/der/codegen.hpp>
#include <crypto/rsa.hpp>
#include <crypto/ecdsa.hpp>
#include <crypto/sha2.hpp>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace asn1::x509 {

// --- X.509 module (parsed at compile time) ---

namespace detail {
    constexpr char x509_schema[] = {
        #embed "definitions/x509.asn1"
    };
    constexpr auto x509_mod = parse_module(std::string_view{x509_schema, sizeof(x509_schema)});
} // namespace detail

inline constexpr auto& X509Mod = detail::x509_mod;

// The parsed Certificate type
using Certificate = der::Mapped<X509Mod, X509Mod.find_type("Certificate")>;

// --- Public key variant ---

using rsa_num = number<uint32_t, 256>;  // RSA-4096 backing (8192-bit)
using uint512 = number<uint32_t, 16>;
using uint768 = number<uint32_t, 24>;
using p256_curve = p256<uint512>;
using p384_curve = p384<uint768>;

using x509_public_key = std::variant<
    rsa_public_key<rsa_num>,
    point<p256_curve>,
    point<p384_curve>
>;

// --- Verifier framework ---

struct cert_context {
    const Certificate& cert;
    const Certificate* issuer;            // nullptr for root/last in chain
    std::span<const uint8_t> cert_der;    // raw DER of this certificate
    std::span<const uint8_t> tbs_der;     // raw DER of TBSCertificate only
    size_t depth;                         // 0 = leaf
    size_t chain_length;
};

template <typename V>
concept certificate_verifier = requires(const V& v, const cert_context& ctx) {
    { v.verify(ctx) } -> std::same_as<bool>;
};

// Type-erased adapter for runtime flexibility
struct dynamic_verifier {
    std::function<bool(const cert_context&)> fn;
    bool verify(const cert_context& ctx) const { return fn(ctx); }
};

// --- TBS byte extraction ---

inline auto extract_tbs_der(std::span<const uint8_t> cert_der) -> std::span<const uint8_t> {
    der::Reader r{cert_der};
    r.read_header();  // Skip outer Certificate SEQUENCE header
    auto tbs = r.peek_header();  // Peek at TBSCertificate header
    return cert_der.subspan(r.position(), tbs.header_size + tbs.length);
}

// --- Parse certificate from DER ---

inline auto parse_certificate(std::span<const uint8_t> der_bytes) -> Certificate {
    der::Reader r{der_bytes};
    return der::decode<X509Mod, X509Mod.find_type("Certificate")>(r);
}

inline auto parse_certificate_pem(std::string_view pem) -> Certificate {
    return pem::decode_to<X509Mod, X509Mod.find_type("Certificate")>(pem);
}

// --- Public key extraction ---

inline auto extract_public_key(const Certificate& cert) -> x509_public_key {
    auto& spki = cert.get<"tbsCertificate">().get<"subjectPublicKeyInfo">();
    auto alg_oid = spki.get<"algorithm">().get<"algorithm">().to_string();
    auto& pub_bits = spki.get<"subjectPublicKey">();

    if (alg_oid == "1.2.840.113549.1.1.1") {
        // RSA: BIT STRING contains PKCS#1 RSAPublicKey (SEQUENCE { n INTEGER, e INTEGER })
        der::Reader r{pub_bits.bytes};
        r.read_header();  // SEQUENCE header

        // Read n
        auto n_hdr = r.read_header();
        auto n_content = r.read_content(n_hdr.length);
        size_t n_start = 0;
        while (n_start < n_content.size() - 1 && n_content[n_start] == 0) ++n_start;
        auto n = rsa_num::from_bytes(
            std::span<const uint8_t>(n_content.data() + n_start, n_content.size() - n_start));

        // Read e
        auto e_hdr = r.read_header();
        auto e_content = r.read_content(e_hdr.length);
        size_t e_start = 0;
        while (e_start < e_content.size() - 1 && e_content[e_start] == 0) ++e_start;
        auto e = rsa_num::from_bytes(
            std::span<const uint8_t>(e_content.data() + e_start, e_content.size() - e_start));

        return rsa_public_key<rsa_num>{n, e};
    }

    if (alg_oid == "1.2.840.10045.2.1") {
        // EC: determine curve from AlgorithmIdentifier parameters
        auto& params = spki.get<"algorithm">().get<"parameters">();
        if (!params.has_value())
            throw std::runtime_error{"EC key missing curve parameters"};

        // Parse the OID from the raw TLV of the parameters
        der::Reader pr{params->raw_tlv};
        auto curve_oid = pr.read_oid().to_string();

        auto pub_span = std::span<const uint8_t>(pub_bits.bytes);

        if (curve_oid == "1.2.840.10045.3.1.7") {
            // P-256 (prime256v1): 0x04 || x(32) || y(32)
            if (pub_span.size() != 65 || pub_span[0] != 0x04)
                throw std::runtime_error{"invalid P-256 public key"};
            auto x = uint512::from_bytes(pub_span.subspan(1, 32));
            auto y = uint512::from_bytes(pub_span.subspan(33, 32));
            using fe = field_element<p256_curve>;
            return point<p256_curve>{fe{x}, fe{y}};
        }

        if (curve_oid == "1.3.132.0.34") {
            // P-384 (secp384r1): 0x04 || x(48) || y(48)
            if (pub_span.size() != 97 || pub_span[0] != 0x04)
                throw std::runtime_error{"invalid P-384 public key"};
            auto x = uint768::from_bytes(pub_span.subspan(1, 48));
            auto y = uint768::from_bytes(pub_span.subspan(49, 48));
            using fe = field_element<p384_curve>;
            return point<p384_curve>{fe{x}, fe{y}};
        }

        throw std::runtime_error{"unsupported EC curve: " + std::string(curve_oid)};
    }

    throw std::runtime_error{"unsupported public key algorithm: " + std::string(alg_oid)};
}

// --- ECDSA signature parsing ---

namespace detail {

template <typename TCurve>
auto parse_ecdsa_signature(std::span<const uint8_t> sig_bytes)
    -> ecdsa_signature<TCurve>
{
    der::Reader r{sig_bytes};
    r.read_header();  // SEQUENCE

    auto r_hdr = r.read_header();
    auto r_content = r.read_content(r_hdr.length);
    size_t r_start = 0;
    while (r_start < r_content.size() - 1 && r_content[r_start] == 0) ++r_start;

    auto s_hdr = r.read_header();
    auto s_content = r.read_content(s_hdr.length);
    size_t s_start = 0;
    while (s_start < s_content.size() - 1 && s_content[s_start] == 0) ++s_start;

    using num_t = typename TCurve::number_type;
    return {
        num_t::from_bytes(std::span<const uint8_t>(r_content.data() + r_start, r_content.size() - r_start)),
        num_t::from_bytes(std::span<const uint8_t>(s_content.data() + s_start, s_content.size() - s_start))
    };
}

} // namespace detail

// --- Single certificate signature verification ---

inline bool verify_certificate_signature(
    std::span<const uint8_t> cert_der,
    const Certificate& cert,
    const x509_public_key& issuer_key)
{
    auto tbs_bytes = extract_tbs_der(cert_der);
    auto sig_oid = cert.get<"signatureAlgorithm">().get<"algorithm">().to_string();
    auto& sig_bits = cert.get<"signatureValue">();

    // RSA PKCS#1 v1.5 + SHA-256
    if (sig_oid == "1.2.840.113549.1.1.11") {
        auto hash = sha256(tbs_bytes);
        auto* key = std::get_if<rsa_public_key<rsa_num>>(&issuer_key);
        if (!key) return false;
        rsa_signature<rsa_num> sig{rsa_num::from_bytes(sig_bits.bytes)};
        return rsa_pkcs1_v1_5_verify<rsa_num, sha256_state>(*key, hash, sig);
    }

    // RSA PKCS#1 v1.5 + SHA-384
    if (sig_oid == "1.2.840.113549.1.1.12") {
        auto hash = sha384(tbs_bytes);
        auto* key = std::get_if<rsa_public_key<rsa_num>>(&issuer_key);
        if (!key) return false;
        rsa_signature<rsa_num> sig{rsa_num::from_bytes(sig_bits.bytes)};
        return rsa_pkcs1_v1_5_verify<rsa_num, sha384_state>(*key, hash, sig);
    }

    // RSA PKCS#1 v1.5 + SHA-512
    if (sig_oid == "1.2.840.113549.1.1.13") {
        auto hash = sha512(tbs_bytes);
        auto* key = std::get_if<rsa_public_key<rsa_num>>(&issuer_key);
        if (!key) return false;
        rsa_signature<rsa_num> sig{rsa_num::from_bytes(sig_bits.bytes)};
        return rsa_pkcs1_v1_5_verify<rsa_num, sha512_state>(*key, hash, sig);
    }

    // ECDSA + SHA-256 (P-256 or P-384 key)
    if (sig_oid == "1.2.840.10045.4.3.2") {
        auto hash = sha256(tbs_bytes);
        if (auto* key = std::get_if<point<p256_curve>>(&issuer_key)) {
            auto sig = detail::parse_ecdsa_signature<p256_curve>(sig_bits.bytes);
            return ecdsa_verify<p256_curve, sha256_state>(*key, hash, sig);
        }
        if (auto* key = std::get_if<point<p384_curve>>(&issuer_key)) {
            auto sig = detail::parse_ecdsa_signature<p384_curve>(sig_bits.bytes);
            return ecdsa_verify<p384_curve, sha256_state>(*key, hash, sig);
        }
        return false;
    }

    // ECDSA + SHA-384 (P-256 or P-384 key)
    if (sig_oid == "1.2.840.10045.4.3.3") {
        auto hash = sha384(tbs_bytes);
        if (auto* key = std::get_if<point<p384_curve>>(&issuer_key)) {
            auto sig = detail::parse_ecdsa_signature<p384_curve>(sig_bits.bytes);
            return ecdsa_verify<p384_curve, sha384_state>(*key, hash, sig);
        }
        if (auto* key = std::get_if<point<p256_curve>>(&issuer_key)) {
            auto sig = detail::parse_ecdsa_signature<p256_curve>(sig_bits.bytes);
            return ecdsa_verify<p256_curve, sha384_state>(*key, hash, sig);
        }
        return false;
    }

    return false;  // unsupported algorithm
}

// --- Chain verification ---
// Builds a trust path from the leaf (chain_der[0]) to a root in the trust
// store, searching the chain as an unordered collection rather than assuming
// strict sequential ordering. Handles cross-signed intermediates and chains
// where a cert is itself a trust anchor.

template <certificate_verifier... Vs>
bool verify_chain(
    std::span<const std::vector<uint8_t>> chain_der,  // leaf-first
    const auto& roots,  // trust_store with find_issuer()
    Vs&&... verifiers)
{
    if (chain_der.empty()) return false;

    // Parse all certificates
    std::vector<Certificate> certs;
    certs.reserve(chain_der.size());
    for (auto& der : chain_der)
        certs.push_back(parse_certificate(der));

    // Helper: encode a Name field to canonical DER for comparison
    auto encode_name = [](const auto& name) {
        der::Writer w;
        der::encode<X509Mod, X509Mod.find_type("Name")>(w, name);
        return std::move(w).finish();
    };

    // Walk from leaf (index 0) up to a trust anchor
    size_t current = 0;
    constexpr size_t max_depth = 10;

    for (size_t depth = 0; depth < max_depth; ++depth) {
        // Run verifiers on this cert
        auto tbs_der = extract_tbs_der(chain_der[current]);
        cert_context ctx{
            .cert = certs[current],
            .issuer = nullptr,
            .cert_der = chain_der[current],
            .tbs_der = tbs_der,
            .depth = depth,
            .chain_length = chain_der.size()
        };
        if constexpr (sizeof...(Vs) > 0) {
            if (!(verifiers.verify(ctx) && ...))
                return false;
        }

        // Check if this cert's issuer is a root in the trust store
        auto root = roots.find_issuer(certs[current]);
        if (root) {
            auto root_key = extract_public_key(root->cert);
            return verify_certificate_signature(
                chain_der[current], certs[current], root_key);
        }

        // Search the chain for a cert whose subject matches this cert's issuer
        auto issuer_name = encode_name(
            certs[current].get<"tbsCertificate">().get<"issuer">());
        bool found = false;
        for (size_t j = 0; j < certs.size(); ++j) {
            if (j == current) continue;
            auto subject = encode_name(
                certs[j].get<"tbsCertificate">().get<"subject">());
            if (subject == issuer_name) {
                auto issuer_key = extract_public_key(certs[j]);
                if (!verify_certificate_signature(
                        chain_der[current], certs[current], issuer_key))
                    return false;
                current = j;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return false;  // exceeded max depth
}

} // namespace asn1::x509
