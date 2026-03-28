#include <number/ecc.hpp>
#include <asn1/pem.hpp>
#include <asn1/parser.hpp>
#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>

using namespace asn1;
using namespace asn1::der;
using namespace asn1::pem;

// Parse ASN.1 definitions at compile time
constexpr char ecc_asn1[] = {
    #embed "definitions/ecprivatekey.asn1"
};
constexpr auto Mod = parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});

// Number and curve types for P-256
using uint512 = number<std::uint32_t, 16>;
using p256_curve = p256<uint512>;
using p256_fe = field_element<p256_curve>;
using p256_point = point<p256_curve>;

// The same real OpenSSL-generated P-256 key used in test_pem.cpp
constexpr std::string_view test_pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEILqCeQe9YS7mdX3IseutWyDcygJWrKtkpQul8wWxsKNMoAoGCCqGSM49\n"
    "AwEHoUQDQgAE2wIVduUCSe5a9JoCg7cE5lmkK1GAlNnYpqTz5ZB9339rsLkmHZIi\n"
    "jMWwbEFkrrjsCG4+H2avHOsSky5iNHfRvA==\n"
    "-----END EC PRIVATE KEY-----\n";

// --- Tests ---

void test_import_private_key() {
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(test_pem);

    auto& priv_bytes = key.get<"privateKey">().bytes;
    assert(priv_bytes.size() == 32);

    auto d = uint512::from_bytes(priv_bytes);
    assert(d != uint512(0U));
}

void test_import_public_key_on_curve() {
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(test_pem);

    auto& pub_bytes = key.get<"publicKey">()->bytes;
    assert(pub_bytes.size() == 65);
    assert(pub_bytes[0] == 0x04);

    auto pub_span = std::span<const uint8_t>(pub_bytes);
    auto x = uint512::from_bytes(pub_span.subspan(1, 32));
    auto y = uint512::from_bytes(pub_span.subspan(33, 32));

    p256_point Q{p256_fe{x}, p256_fe{y}};
    assert(Q.on_curve());
}

void test_derive_public_from_private() {
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(test_pem);

    // Import private scalar
    auto d = uint512::from_bytes(key.get<"privateKey">().bytes);

    // Import public key point
    auto& pub_bytes = key.get<"publicKey">()->bytes;
    auto pub_span = std::span<const uint8_t>(pub_bytes);
    auto x = uint512::from_bytes(pub_span.subspan(1, 32));
    auto y = uint512::from_bytes(pub_span.subspan(33, 32));
    p256_point Q{p256_fe{x}, p256_fe{y}};

    // Derive public key: Q' = d * G
    p256_point G{p256_fe{p256_curve::gx()}, p256_fe{p256_curve::gy()}};
    p256_point derived = G.scalar_mul(d);

    assert(derived == Q);
}

void test_generator_on_curve() {
    p256_point G{p256_fe{p256_curve::gx()}, p256_fe{p256_curve::gy()}};
    assert(G.on_curve());
}

int main() {
    test_import_private_key();
    test_import_public_key_on_curve();
    test_derive_public_from_private();
    test_generator_on_curve();
    return 0;
}
