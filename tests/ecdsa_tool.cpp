/**
 * CLI tool for ECDSA sign/verify using P-256, for interop testing with OpenSSL.
 *
 * Usage:
 *   ecdsa_tool sign <pem_key_file> <message_file> <output_sig_der>
 *   ecdsa_tool verify <pem_key_file> <message_file> <input_sig_der>
 */

#include <number/ecdsa.hpp>
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

static Integer num_to_integer(const uint512& n) {
    auto bytes = n.to_bytes(std::endian::big);
    size_t start = 0;
    while (start < bytes.size() - 1 && bytes[start] == 0) ++start;
    Integer result;
    if (bytes[start] & 0x80) result.bytes.push_back(0x00);
    result.bytes.insert(result.bytes.end(), bytes.begin() + start, bytes.end());
    return result;
}

static int do_sign(const char* key_path, const char* msg_path, const char* sig_path) {
    auto pem = read_text(key_path);
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(pem);
    auto d = uint512::from_bytes(key.get<"privateKey">().bytes);

    auto msg = read_file(msg_path);
    auto sig = ecdsa_sign_message<p256_curve, sha256_state>(d, msg);

    Type<Mod, "ECDSA-Sig-Value"> der_sig;
    der_sig.get<"r">() = num_to_integer(sig.r);
    der_sig.get<"s">() = num_to_integer(sig.s);

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

    auto& pub_bytes = key.get<"publicKey">()->bytes;
    auto pub_span = std::span<const uint8_t>(pub_bytes);
    auto x = uint512::from_bytes(pub_span.subspan(1, 32));
    auto y = uint512::from_bytes(pub_span.subspan(33, 32));
    p256_point Q{p256_fe{x}, p256_fe{y}};

    auto msg = read_file(msg_path);
    auto der = read_file(sig_path);

    Reader r{der};
    auto der_sig = decode<Mod, Mod.find_type("ECDSA-Sig-Value")>(r);
    auto r_val = uint512::from_bytes(der_sig.get<"r">().bytes);
    auto s_val = uint512::from_bytes(der_sig.get<"s">().bytes);

    ecdsa_signature<p256_curve> sig{r_val, s_val};
    auto hash = sha256(std::span<const uint8_t>(msg));

    if (ecdsa_verify<p256_curve, sha256_state>(Q, hash, sig)) {
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
