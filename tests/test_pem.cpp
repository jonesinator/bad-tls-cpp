#include <asn1/pem.hpp>
#include <asn1/parser.hpp>
#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using namespace asn1;
using namespace asn1::der;
using namespace asn1::pem;

// Parse ASN.1 definitions at compile time
constexpr char ecc_asn1[] = {
    #embed "definitions/ecprivatekey.asn1"
};
constexpr auto Mod = parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});
using ECPrivateKey = Type<Mod, "ECPrivateKey">;

// --- Tests ---

void test_pem_roundtrip_raw() {
    // Encode some DER bytes to PEM and decode back
    std::vector<uint8_t> der = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};

    auto pem_str = encode("TEST DATA", der);

    // Check structure
    assert(pem_str.find("-----BEGIN TEST DATA-----") != std::string::npos);
    assert(pem_str.find("-----END TEST DATA-----") != std::string::npos);

    // Decode back
    auto block = decode(pem_str);
    assert(block.label == "TEST DATA");
    assert(block.der == der);
}

void test_pem_line_wrapping() {
    // Create DER data large enough to produce multiple base64 lines
    std::vector<uint8_t> der(100, 0x42);

    auto pem_str = encode("LONG DATA", der);

    // Each line between BEGIN/END should be at most 64 chars
    auto begin_end = pem_str.find('\n');
    auto end_start = pem_str.rfind("-----END");

    auto content = std::string_view{pem_str}.substr(begin_end + 1, end_start - begin_end - 1);
    std::size_t pos = 0;
    while (pos < content.size()) {
        auto nl = content.find('\n', pos);
        if (nl == std::string_view::npos) break;
        auto line_len = nl - pos;
        assert(line_len <= 64);
        pos = nl + 1;
    }

    // Round-trip
    auto block = decode(pem_str);
    assert(block.der == der);
}

void test_pem_label_extraction() {
    std::string pem =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "AQEB\n"
        "-----END EC PRIVATE KEY-----\n";

    auto block = decode(pem);
    assert(block.label == "EC PRIVATE KEY");
}

void test_real_openssl_pem() {
    // Real OpenSSL-generated EC private key PEM
    std::string_view pem =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEILqCeQe9YS7mdX3IseutWyDcygJWrKtkpQul8wWxsKNMoAoGCCqGSM49\n"
        "AwEHoUQDQgAE2wIVduUCSe5a9JoCg7cE5lmkK1GAlNnYpqTz5ZB9339rsLkmHZIi\n"
        "jMWwbEFkrrjsCG4+H2avHOsSky5iNHfRvA==\n"
        "-----END EC PRIVATE KEY-----\n";

    // Decode PEM to Block
    auto block = decode(pem);
    assert(block.label == "EC PRIVATE KEY");
    assert(!block.der.empty());

    // Decode DER to typed ECPrivateKey
    Reader r{block.der};
    auto key = der::decode<Mod, Mod.find_type("ECPrivateKey")>(r);

    assert(key.get<"version">().to_int64() == 1);
    assert(key.get<"privateKey">().bytes.size() == 32);
    assert(key.get<"parameters">().has_value());
    assert(key.get<"publicKey">().has_value());
    assert(key.get<"publicKey">()->bytes.size() == 65); // uncompressed point
    assert(key.get<"publicKey">()->bytes[0] == 0x04);

    // Check curve OID (prime256v1)
    auto& params = key.get<"parameters">().value();
    assert(std::get<0>(params.value).to_string() == "1.2.840.10045.3.1.7");

    // Re-encode to DER and compare
    Writer w;
    der::encode<Mod, Mod.find_type("ECPrivateKey")>(w, key);
    auto reencoded_der = std::move(w).finish();
    assert(reencoded_der == block.der);

    // Re-encode to PEM and decode again to verify
    auto reencoded_pem = asn1::pem::encode("EC PRIVATE KEY", reencoded_der);
    auto block2 = decode(reencoded_pem);
    assert(block2.der == block.der);
}

void test_convenience_decode_to() {
    std::string_view pem =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEILqCeQe9YS7mdX3IseutWyDcygJWrKtkpQul8wWxsKNMoAoGCCqGSM49\n"
        "AwEHoUQDQgAE2wIVduUCSe5a9JoCg7cE5lmkK1GAlNnYpqTz5ZB9339rsLkmHZIi\n"
        "jMWwbEFkrrjsCG4+H2avHOsSky5iNHfRvA==\n"
        "-----END EC PRIVATE KEY-----\n";

    // One-liner: PEM → typed value
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(pem);
    assert(key.get<"version">().to_int64() == 1);
    assert(key.get<"privateKey">().bytes.size() == 32);

    // With matching expected label
    auto key2 = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(
        pem, "EC PRIVATE KEY");
    assert(key2.get<"version">().to_int64() == 1);

    // With wrong expected label — should throw
    bool threw = false;
    try {
        asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(
            pem, "PUBLIC KEY");
    } catch (const asn1::pem::PemError& e) {
        threw = true;
        std::string_view msg = e.what();
        assert(msg.find("PUBLIC KEY") != std::string_view::npos);
        assert(msg.find("EC PRIVATE KEY") != std::string_view::npos);
    }
    assert(threw);
}

void test_convenience_encode_from() {
    // Build a minimal ECPrivateKey
    ECPrivateKey key;
    key.get<"version">() = Integer::from_int64(1);
    key.get<"privateKey">() = OctetString{{0xAA, 0xBB, 0xCC}};

    auto pem_str = asn1::pem::encode_from<Mod, Mod.find_type("ECPrivateKey")>(
        "EC PRIVATE KEY", key);

    assert(pem_str.find("-----BEGIN EC PRIVATE KEY-----") != std::string::npos);
    assert(pem_str.find("-----END EC PRIVATE KEY-----") != std::string::npos);

    // Round-trip back
    auto decoded = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(pem_str);
    assert(decoded.get<"version">().to_int64() == 1);
    assert(decoded.get<"privateKey">().bytes == (std::vector<uint8_t>{0xAA, 0xBB, 0xCC}));
}

int main() {
    test_pem_roundtrip_raw();
    test_pem_line_wrapping();
    test_pem_label_extraction();
    test_real_openssl_pem();
    test_convenience_decode_to();
    test_convenience_encode_from();
    return 0;
}
