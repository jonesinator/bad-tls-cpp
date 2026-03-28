/**
 * CLI tool for ECDSA sign/verify using P-256 or P-384, for interop testing with OpenSSL.
 *
 * The curve is auto-detected from the key's private key byte length.
 *
 * Usage:
 *   ecdsa_tool sign <pem_key_file> <message_file> <output_sig_der>
 *   ecdsa_tool verify <pem_key_file> <message_file> <input_sig_der>
 */

#include <number/ecdsa.hpp>
#include <number/sha384.hpp>
#include <asn1/pem.hpp>
#include <asn1/parser.hpp>
#include <asn1/der/codegen.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace asn1;
using namespace asn1::der;

constexpr char ecc_asn1[] = {
    #embed "definitions/ecprivatekey.asn1"
};
constexpr auto Mod = parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});

using uint512 = number<std::uint32_t, 16>;
using p256_curve = p256<uint512>;
using p256_fe = field_element<p256_curve>;
using p256_point = point<p256_curve>;

using uint768 = number<std::uint32_t, 24>;
using p384_curve = p384<uint768>;
using p384_fe = field_element<p384_curve>;
using p384_point = point<p384_curve>;

static std::vector<uint8_t> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", path); std::exit(1); }
    return {std::istreambuf_iterator<char>(f), {}};
}

static std::string read_text(const char* path) {
    std::ifstream f(path);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", path); std::exit(1); }
    return {std::istreambuf_iterator<char>(f), {}};
}

static void write_file(const char* path, std::span<const uint8_t> data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "cannot write %s\n", path); std::exit(1); }
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

template <typename Num>
static Integer num_to_integer(const Num& n) {
    auto bytes = n.to_bytes(std::endian::big);
    size_t start = 0;
    while (start < bytes.size() - 1 && bytes[start] == 0) ++start;
    Integer result;
    if (bytes[start] & 0x80) result.bytes.push_back(0x00);
    result.bytes.insert(result.bytes.end(), bytes.begin() + start, bytes.end());
    return result;
}

enum class curve_type { p256, p384 };

static curve_type detect_curve(const std::vector<uint8_t>& priv_bytes) {
    if (priv_bytes.size() <= 32) return curve_type::p256;
    if (priv_bytes.size() <= 48) return curve_type::p384;
    std::fprintf(stderr, "unsupported key size: %zu bytes\n", priv_bytes.size());
    std::exit(2);
}

static int do_sign(const char* key_path, const char* msg_path, const char* sig_path) {
    auto pem = read_text(key_path);
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(pem);
    auto msg = read_file(msg_path);

    Type<Mod, "ECDSA-Sig-Value"> der_sig;

    switch (detect_curve(key.get<"privateKey">().bytes)) {
    case curve_type::p256: {
        auto d = uint512::from_bytes(key.get<"privateKey">().bytes);
        auto sig = ecdsa_sign_message<p256_curve, sha256_state>(d, msg);
        der_sig.get<"r">() = num_to_integer(sig.r);
        der_sig.get<"s">() = num_to_integer(sig.s);
        break;
    }
    case curve_type::p384: {
        auto d = uint768::from_bytes(key.get<"privateKey">().bytes);
        auto sig = ecdsa_sign_message<p384_curve, sha384_state>(d, msg);
        der_sig.get<"r">() = num_to_integer(sig.r);
        der_sig.get<"s">() = num_to_integer(sig.s);
        break;
    }
    }

    Writer w;
    encode<Mod, Mod.find_type("ECDSA-Sig-Value")>(w, der_sig);
    auto der_bytes = std::move(w).finish();

    write_file(sig_path, der_bytes);
    std::printf("signed %zu bytes -> %s\n", msg.size(), sig_path);
    return 0;
}

static int do_verify(const char* key_path, const char* msg_path, const char* sig_path) {
    auto pem = read_text(key_path);
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(pem);

    auto msg = read_file(msg_path);
    auto der = read_file(sig_path);

    Reader r{der};
    auto der_sig = decode<Mod, Mod.find_type("ECDSA-Sig-Value")>(r);

    bool ok = false;

    switch (detect_curve(key.get<"privateKey">().bytes)) {
    case curve_type::p256: {
        auto& pub_bytes = key.get<"publicKey">()->bytes;
        auto pub_span = std::span<const uint8_t>(pub_bytes);
        auto x = uint512::from_bytes(pub_span.subspan(1, 32));
        auto y = uint512::from_bytes(pub_span.subspan(33, 32));
        p256_point Q{p256_fe{x}, p256_fe{y}};

        auto r_val = uint512::from_bytes(der_sig.get<"r">().bytes);
        auto s_val = uint512::from_bytes(der_sig.get<"s">().bytes);
        ecdsa_signature<p256_curve> sig{r_val, s_val};

        auto hash = sha256(std::span<const uint8_t>(msg));
        ok = ecdsa_verify<p256_curve, sha256_state>(Q, hash, sig);
        break;
    }
    case curve_type::p384: {
        auto& pub_bytes = key.get<"publicKey">()->bytes;
        auto pub_span = std::span<const uint8_t>(pub_bytes);
        auto x = uint768::from_bytes(pub_span.subspan(1, 48));
        auto y = uint768::from_bytes(pub_span.subspan(49, 48));
        p384_point Q{p384_fe{x}, p384_fe{y}};

        auto r_val = uint768::from_bytes(der_sig.get<"r">().bytes);
        auto s_val = uint768::from_bytes(der_sig.get<"s">().bytes);
        ecdsa_signature<p384_curve> sig{r_val, s_val};

        sha384_state hs;
        hs.init();
        hs.update(std::span<const uint8_t>(msg));
        auto hash = hs.finalize();
        ok = ecdsa_verify<p384_curve, sha384_state>(Q, hash, sig);
        break;
    }
    }

    if (ok) {
        std::puts("Verified OK");
        return 0;
    } else {
        std::puts("Verification Failure");
        return 1;
    }
}

int main(int argc, char** argv) {
    if (argc != 5) {
        std::fprintf(stderr, "usage: %s sign|verify <pem_key> <message> <signature.der>\n",
                     argv[0]);
        return 2;
    }

    if (std::strcmp(argv[1], "sign") == 0)
        return do_sign(argv[2], argv[3], argv[4]);
    if (std::strcmp(argv[1], "verify") == 0)
        return do_verify(argv[2], argv[3], argv[4]);

    std::fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
