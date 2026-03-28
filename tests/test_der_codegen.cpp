#include <asn1/der/codegen.hpp>
#include <asn1/parser.hpp>
#include <cassert>
#include <cstdint>
#include <type_traits>
#include <vector>

using namespace asn1;
using namespace asn1::der;

// --- Parse the ASN.1 definitions at compile time ---

constexpr char ecc_asn1[] = {
    #embed "definitions/ecprivatekey.asn1"
};
constexpr auto Mod = parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});

// --- Map ASN.1 types to C++ types ---

using AlgorithmIdentifier = Type<Mod, "AlgorithmIdentifier">;
using SubjectPublicKeyInfo = Type<Mod, "SubjectPublicKeyInfo">;
using ECParameters        = Type<Mod, "ECParameters">;
using ECPrivateKey        = Type<Mod, "ECPrivateKey">;
using OneAsymmetricKey    = Type<Mod, "OneAsymmetricKey">;
using ECDSASigValue       = Type<Mod, "ECDSA-Sig-Value">;

// --- Static type checks ---

// ECPrivateKey is a SequenceType with 4 fields
static_assert(ECPrivateKey::field_count == 4);
// version is INTEGER (not optional)
static_assert(std::is_same_v<
    std::tuple_element_t<0, ECPrivateKey::FieldsTuple>, Integer>);
// privateKey is OCTET STRING (not optional)
static_assert(std::is_same_v<
    std::tuple_element_t<1, ECPrivateKey::FieldsTuple>, OctetString>);
// parameters is OPTIONAL -> std::optional<ECParameters>
static_assert(std::is_same_v<
    std::tuple_element_t<2, ECPrivateKey::FieldsTuple>, std::optional<ECParameters>>);
// publicKey is OPTIONAL -> std::optional<BitString>
static_assert(std::is_same_v<
    std::tuple_element_t<3, ECPrivateKey::FieldsTuple>, std::optional<BitString>>);

// ECDSA-Sig-Value has 2 INTEGER fields
static_assert(ECDSASigValue::field_count == 2);
static_assert(std::is_same_v<
    std::tuple_element_t<0, ECDSASigValue::FieldsTuple>, Integer>);
static_assert(std::is_same_v<
    std::tuple_element_t<1, ECDSASigValue::FieldsTuple>, Integer>);

// AlgorithmIdentifier: algorithm is OID, parameters is optional AnyValue
static_assert(AlgorithmIdentifier::field_count == 2);
static_assert(std::is_same_v<
    std::tuple_element_t<0, AlgorithmIdentifier::FieldsTuple>, ObjectIdentifier>);
static_assert(std::is_same_v<
    std::tuple_element_t<1, AlgorithmIdentifier::FieldsTuple>, std::optional<AnyValue>>);

// --- Runtime round-trip tests ---

void test_ecdsa_sig_value() {
    // Construct an ECDSA-Sig-Value
    ECDSASigValue sig;
    sig.get<"r">() = Integer::from_int64(12345);
    sig.get<"s">() = Integer::from_int64(67890);

    // Encode
    Writer w;
    encode<Mod, Mod.find_type("ECDSA-Sig-Value")>(w, sig);
    auto bytes = std::move(w).finish();

    // Decode
    Reader r{bytes};
    auto decoded = decode<Mod, Mod.find_type("ECDSA-Sig-Value")>(r);

    assert(decoded.get<"r">().to_int64() == 12345);
    assert(decoded.get<"s">().to_int64() == 67890);
}

void test_algorithm_identifier() {
    // AlgorithmIdentifier with ecPublicKey OID and NULL parameters
    AlgorithmIdentifier alg;
    alg.get<"algorithm">() = ObjectIdentifier::from_string("1.2.840.10045.2.1");

    // Encode the OID for prime256v1 as the parameters (wrapped in AnyValue)
    {
        Writer param_w;
        param_w.write(ObjectIdentifier::from_string("1.2.840.10045.3.1.7"));
        alg.get<"parameters">() = AnyValue{std::move(param_w).finish()};
    }

    Writer w;
    encode<Mod, Mod.find_type("AlgorithmIdentifier")>(w, alg);
    auto bytes = std::move(w).finish();

    Reader r{bytes};
    auto decoded = decode<Mod, Mod.find_type("AlgorithmIdentifier")>(r);

    assert(decoded.get<"algorithm">().to_string() == "1.2.840.10045.2.1");
    assert(decoded.get<"parameters">().has_value());
}

void test_ec_private_key_roundtrip() {
    // Construct a minimal ECPrivateKey
    ECPrivateKey key;
    key.get<"version">() = Integer::from_int64(1);
    key.get<"privateKey">() = OctetString{{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    }};
    // Leave parameters and publicKey empty (optional)

    Writer w;
    encode<Mod, Mod.find_type("ECPrivateKey")>(w, key);
    auto bytes = std::move(w).finish();

    Reader r{bytes};
    auto decoded = decode<Mod, Mod.find_type("ECPrivateKey")>(r);

    assert(decoded.get<"version">().to_int64() == 1);
    assert(decoded.get<"privateKey">().bytes.size() == 32);
    assert(!decoded.get<"parameters">().has_value());
    assert(!decoded.get<"publicKey">().has_value());
}

void test_ec_private_key_with_optionals() {
    // ECPrivateKey with parameters and publicKey
    ECPrivateKey key;
    key.get<"version">() = Integer::from_int64(1);
    key.get<"privateKey">() = OctetString{{0xAA, 0xBB, 0xCC}};

    // parameters: [0] EXPLICIT ECParameters (CHOICE { namedCurve OID })
    ECParameters params;
    params.value.emplace<0>(ObjectIdentifier::from_string("1.2.840.10045.3.1.7"));
    key.get<"parameters">() = params;

    // publicKey: [1] EXPLICIT BIT STRING
    key.get<"publicKey">() = BitString{{0x04, 0xDE, 0xAD}, 0};

    Writer w;
    encode<Mod, Mod.find_type("ECPrivateKey")>(w, key);
    auto bytes = std::move(w).finish();

    Reader r{bytes};
    auto decoded = decode<Mod, Mod.find_type("ECPrivateKey")>(r);

    assert(decoded.get<"version">().to_int64() == 1);
    assert(decoded.get<"privateKey">().bytes == (std::vector<uint8_t>{0xAA, 0xBB, 0xCC}));
    assert(decoded.get<"parameters">().has_value());
    auto& dec_params = decoded.get<"parameters">().value();
    assert(std::get<0>(dec_params.value).to_string() == "1.2.840.10045.3.1.7");
    assert(decoded.get<"publicKey">().has_value());
    assert(decoded.get<"publicKey">()->bytes == (std::vector<uint8_t>{0x04, 0xDE, 0xAD}));
}

void test_subject_public_key_info() {
    SubjectPublicKeyInfo spki;

    // algorithm: AlgorithmIdentifier with ecPublicKey OID + prime256v1 params
    auto& alg = spki.get<"algorithm">();
    alg.get<"algorithm">() = ObjectIdentifier::from_string("1.2.840.10045.2.1");
    {
        Writer param_w;
        param_w.write(ObjectIdentifier::from_string("1.2.840.10045.3.1.7"));
        alg.get<"parameters">() = AnyValue{std::move(param_w).finish()};
    }

    spki.get<"subjectPublicKey">() = BitString{{0x04, 0x01, 0x02}, 0};

    Writer w;
    encode<Mod, Mod.find_type("SubjectPublicKeyInfo")>(w, spki);
    auto bytes = std::move(w).finish();

    Reader r{bytes};
    auto decoded = decode<Mod, Mod.find_type("SubjectPublicKeyInfo")>(r);

    assert(decoded.get<"algorithm">().get<"algorithm">().to_string() == "1.2.840.10045.2.1");
    assert(decoded.get<"subjectPublicKey">().bytes == (std::vector<uint8_t>{0x04, 0x01, 0x02}));
}

void test_known_der_ecdsa_sig() {
    // Hand-crafted DER for ECDSA-Sig-Value { r: 1, s: 2 }
    // SEQUENCE { INTEGER 1, INTEGER 2 }
    std::vector<uint8_t> der = {
        0x30, 0x06,       // SEQUENCE, length 6
        0x02, 0x01, 0x01, // INTEGER 1
        0x02, 0x01, 0x02  // INTEGER 2
    };

    Reader r{der};
    auto sig = decode<Mod, Mod.find_type("ECDSA-Sig-Value")>(r);
    assert(sig.get<"r">().to_int64() == 1);
    assert(sig.get<"s">().to_int64() == 2);

    // Re-encode and compare
    Writer w;
    encode<Mod, Mod.find_type("ECDSA-Sig-Value")>(w, sig);
    assert(std::move(w).finish() == der);
}

void test_real_openssl_ec_key() {
    // Real EC private key generated by: openssl ecparam -name prime256v1 -genkey -noout -outform DER
    std::vector<uint8_t> der = {
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
        0xb1, 0x3c, 0x89, 0xa5, 0x7c, 0xc5, 0xca, 0x1c,
        0xd7, 0x1d, 0xf6, 0x80, 0x13, 0xcb, 0x12, 0x70,
        0x5b, 0xf4, 0xe9, 0xf4, 0xea, 0x8d, 0xe7, 0xcd,
        0x6a, 0xc6, 0x5f, 0x3f, 0x21, 0x71, 0x5e, 0xb5,
        0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
        0x00, 0x04, 0x07, 0xb2, 0x2a, 0x32, 0xa2, 0x96,
        0xa6, 0x05, 0x32, 0xc8, 0x3e, 0xc9, 0x6a, 0x08,
        0x90, 0x0f, 0x00, 0xcb, 0x3f, 0xb3, 0x62, 0x63,
        0xff, 0x36, 0xb8, 0x29, 0xf1, 0x67, 0xcc, 0x21,
        0x2b, 0xa5, 0xf9, 0x1d, 0xf1, 0xb4, 0x03, 0x7f,
        0x43, 0xed, 0xe7, 0xf1, 0xd8, 0xd3, 0x3d, 0xd2,
        0x42, 0x5b, 0xb4, 0x28, 0x9f, 0xed, 0xbf, 0x26,
        0xfe, 0x2c, 0x01, 0xa8, 0xd1, 0xb7, 0x22, 0x4f,
        0xf1, 0x90
    };

    // Decode
    Reader r{der};
    auto key = decode<Mod, Mod.find_type("ECPrivateKey")>(r);

    // Verify structure
    assert(key.get<"version">().to_int64() == 1);
    assert(key.get<"privateKey">().bytes.size() == 32);

    // parameters: [0] EXPLICIT ECParameters (CHOICE { namedCurve OID })
    assert(key.get<"parameters">().has_value());
    auto& params = key.get<"parameters">().value();
    assert(std::get<0>(params.value).to_string() == "1.2.840.10045.3.1.7");

    // publicKey: [1] EXPLICIT BIT STRING (uncompressed point = 04 || x || y)
    assert(key.get<"publicKey">().has_value());
    auto& pub = key.get<"publicKey">().value();
    assert(pub.unused_bits == 0);
    assert(pub.bytes.size() == 65); // 1 + 32 + 32
    assert(pub.bytes[0] == 0x04);   // uncompressed

    // Re-encode and compare byte-for-byte
    Writer w;
    encode<Mod, Mod.find_type("ECPrivateKey")>(w, key);
    auto reencoded = std::move(w).finish();
    assert(reencoded == der);
}

int main() {
    test_ecdsa_sig_value();
    test_algorithm_identifier();
    test_ec_private_key_roundtrip();
    test_ec_private_key_with_optionals();
    test_subject_public_key_info();
    test_known_der_ecdsa_sig();
    test_real_openssl_ec_key();
    return 0;
}
