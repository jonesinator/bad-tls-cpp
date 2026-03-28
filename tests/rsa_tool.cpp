/**
 * CLI tool for RSA-PSS sign/verify using RSA-2048/SHA-256,
 * for interop testing with OpenSSL.
 *
 * Usage:
 *   rsa_tool sign   <pem_key_file> <message_file> <output_sig_bin>
 *   rsa_tool verify <pem_key_file> <message_file> <input_sig_bin>
 *
 * Accepts both traditional RSA private key PEM (BEGIN RSA PRIVATE KEY)
 * and public key PEM (BEGIN PUBLIC KEY) formats.
 *
 * For signing, uses random salt (read from /dev/urandom).
 * Salt length = SHA-256 digest size = 32 bytes.
 */

#include <number/rsa.hpp>
#include <number/sha2.hpp>
#include <asn1/pem.hpp>
#include <asn1/der/reader.hpp>
#include <asn1/der/types.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using namespace asn1::der;

// RSA-2048: 4096-bit backing type
using rsa_num = number<std::uint32_t, 128>;

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

// Parse a DER INTEGER into an rsa_num
static rsa_num read_integer(Reader& r) {
    auto hdr = r.read_header();
    auto content = r.read_content(hdr.length);
    // Strip leading zero byte used for sign padding
    size_t start = 0;
    while (start < content.size() - 1 && content[start] == 0) ++start;
    return rsa_num::from_bytes(
        std::span<const uint8_t>(content.data() + start, content.size() - start));
}

// Skip a DER element
static void skip_element(Reader& r) {
    auto hdr = r.read_header();
    r.read_content(hdr.length);
}

struct rsa_keys {
    rsa_num n, e, d;
    bool has_private;
};

// Parse PKCS#1 RSA private key: SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
static rsa_keys parse_rsa_private_key(const std::vector<uint8_t>& der) {
    Reader r{der};
    auto seq_hdr = r.read_header(); // outer SEQUENCE
    (void)seq_hdr;

    skip_element(r);  // version INTEGER
    auto n = read_integer(r);
    auto e = read_integer(r);
    auto d = read_integer(r);
    // Skip p, q, dp, dq, qinv

    return {n, e, d, true};
}

// Parse PKCS#1 RSA public key: SEQUENCE { n, e }
static rsa_keys parse_rsa_public_key_raw(const std::vector<uint8_t>& der) {
    Reader r{der};
    auto seq_hdr = r.read_header(); // outer SEQUENCE
    (void)seq_hdr;

    auto n = read_integer(r);
    auto e = read_integer(r);

    return {n, e, rsa_num(0U), false};
}

// Parse SPKI (SubjectPublicKeyInfo): SEQUENCE { AlgorithmIdentifier, BIT STRING }
// The BIT STRING contains the PKCS#1 RSA public key
static rsa_keys parse_spki(const std::vector<uint8_t>& der) {
    Reader r{der};
    auto seq_hdr = r.read_header(); // outer SEQUENCE
    (void)seq_hdr;

    // Skip AlgorithmIdentifier
    skip_element(r);

    // BIT STRING containing the public key
    auto bs_hdr = r.read_header();
    auto bs_content = r.read_content(bs_hdr.length);

    // First byte is unused-bits count (should be 0)
    std::vector<uint8_t> pk_der(bs_content.begin() + 1, bs_content.end());
    return parse_rsa_public_key_raw(pk_der);
}

static rsa_keys load_key(const char* path) {
    auto pem_text = read_text(path);

    // Detect PEM type
    if (pem_text.find("BEGIN RSA PRIVATE KEY") != std::string::npos) {
        auto der = asn1::pem::decode(pem_text).der;
        return parse_rsa_private_key(der);
    } else if (pem_text.find("BEGIN PUBLIC KEY") != std::string::npos) {
        auto der = asn1::pem::decode(pem_text).der;
        return parse_spki(der);
    } else if (pem_text.find("BEGIN PRIVATE KEY") != std::string::npos) {
        // PKCS#8 wrapper: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { RSAPrivateKey } }
        auto der = asn1::pem::decode(pem_text).der;
        Reader r{der};
        auto seq_hdr = r.read_header();
        (void)seq_hdr;
        skip_element(r);  // version
        skip_element(r);  // AlgorithmIdentifier
        auto os_hdr = r.read_header();  // OCTET STRING
        auto os_content = r.read_content(os_hdr.length);
        std::vector<uint8_t> inner(os_content.begin(), os_content.end());
        return parse_rsa_private_key(inner);
    }

    std::fprintf(stderr, "unsupported PEM format in %s\n", path);
    std::exit(1);
}

static int do_sign(const char* key_path, const char* msg_path, const char* sig_path) {
    auto keys = load_key(key_path);
    if (!keys.has_private) {
        std::fprintf(stderr, "need private key for signing\n");
        return 1;
    }

    auto msg = read_file(msg_path);
    auto mHash = sha256(std::span<const uint8_t>(msg));

    // Read random salt from /dev/urandom
    std::array<uint8_t, 32> salt{};
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) { std::fprintf(stderr, "cannot open /dev/urandom\n"); return 1; }
    urandom.read(reinterpret_cast<char*>(salt.data()), salt.size());

    rsa_private_key<rsa_num> priv{keys.n, keys.d};
    auto sig = rsa_pss_sign<rsa_num, sha256_state>(priv, mHash, salt);

    // Convert signature to big-endian bytes, strip to modulus byte length
    auto sig_bytes = sig.value.to_bytes(std::endian::big);
    size_t k = (keys.n.bit_width() + 7) / 8;
    std::vector<uint8_t> out(sig_bytes.end() - k, sig_bytes.end());

    write_file(sig_path, out);
    std::printf("signed %zu bytes -> %s (%zu-byte signature)\n", msg.size(), sig_path, out.size());
    return 0;
}

static int do_verify(const char* key_path, const char* msg_path, const char* sig_path) {
    auto keys = load_key(key_path);
    auto msg = read_file(msg_path);
    auto sig_bytes = read_file(sig_path);

    auto mHash = sha256(std::span<const uint8_t>(msg));

    rsa_public_key<rsa_num> pub{keys.n, keys.e};
    rsa_signature<rsa_num> sig{rsa_num::from_bytes(sig_bytes)};

    bool ok = rsa_pss_verify<rsa_num, sha256_state>(pub, mHash, sig);

    if (ok) {
        std::puts("Verified OK");
        return 0;
    } else {
        std::puts("Verification Failure");
        return 1;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s sign|verify ...\n", argv[0]);
        return 2;
    }

    if (std::strcmp(argv[1], "sign") == 0 && argc == 5)
        return do_sign(argv[2], argv[3], argv[4]);
    if (std::strcmp(argv[1], "verify") == 0 && argc == 5)
        return do_verify(argv[2], argv[3], argv[4]);

    std::fprintf(stderr, "usage: %s sign <pem_key> <message> <signature.bin>\n"
                         "       %s verify <pem_key_or_pub> <message> <signature.bin>\n",
                         argv[0], argv[0]);
    return 2;
}
