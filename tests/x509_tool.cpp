/**
 * CLI tool for X.509 certificate chain verification,
 * for interop testing with OpenSSL.
 *
 * Usage:
 *   x509_tool verify-chain <root_ca.pem> <cert1.pem> [cert2.pem ...]
 *
 * Certificates are listed leaf-first. The root CA PEM is the trust anchor.
 * Returns exit code 0 on success, 1 on verification failure.
 */

#include <asn1/x509/trust_store.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static std::string read_text(const char* path) {
    std::ifstream f(path);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", path); std::exit(2); }
    return {std::istreambuf_iterator<char>(f), {}};
}

static std::vector<uint8_t> pem_to_der(const char* path) {
    auto pem = read_text(path);
    return asn1::pem::decode(pem).der;
}

int main(int argc, char** argv) {
    if (argc < 4 || std::strcmp(argv[1], "verify-chain") != 0) {
        std::fprintf(stderr,
            "usage: %s verify-chain <root_ca.pem> <cert1.pem> [cert2.pem ...]\n"
            "  Certificates listed leaf-first. Root CA is the trust anchor.\n",
            argv[0]);
        return 2;
    }

    // argv[2] = root CA PEM
    // argv[3..] = chain certs, leaf-first
    const char* root_path = argv[2];

    asn1::x509::trust_store store;
    store.add_pem(read_text(root_path));

    std::vector<std::vector<uint8_t>> chain;
    for (int i = 3; i < argc; ++i)
        chain.push_back(pem_to_der(argv[i]));

    bool ok = asn1::x509::verify_chain(chain, store);

    if (ok) {
        std::puts("Chain Verified OK");
        return 0;
    } else {
        std::puts("Chain Verification Failure");
        return 1;
    }
}
