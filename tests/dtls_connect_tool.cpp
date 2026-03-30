/**
 * DTLS 1.2 client tool.
 *
 * Usage: ./dtls_connect_tool [options] <hostname> [port]
 *
 * Options:
 *   --cafile <ca.pem>    Use custom CA certificate file instead of Mozilla roots
 *   --cert <cert.pem>    Client certificate for mTLS
 *   --key <key.pem>      Client private key for mTLS
 *
 * Connects via UDP, performs a DTLS 1.2 handshake, sends a short message,
 * and prints the response.
 */

#include <tls/udp_transport.hpp>
#include <tls/dtls_client.hpp>
#include <tls/private_key.hpp>
#include <x509/mozilla_roots.hpp>
#include <crypto/random.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    std::setbuf(stdout, nullptr);

    const char* cafile = nullptr;
    const char* certfile = nullptr;
    const char* keyfile = nullptr;
    const char* hostname_arg = nullptr;
    const char* port_arg = nullptr;

    int i = 1;
    while (i < argc) {
        if (std::strcmp(argv[i], "--cafile") == 0 && i + 1 < argc) {
            cafile = argv[++i]; ++i;
        } else if (std::strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            certfile = argv[++i]; ++i;
        } else if (std::strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            keyfile = argv[++i]; ++i;
        } else if (!hostname_arg) {
            hostname_arg = argv[i++];
        } else if (!port_arg) {
            port_arg = argv[i++];
        } else {
            ++i;
        }
    }

    if (!hostname_arg) {
        std::fprintf(stderr,
            "Usage: %s [--cafile <ca.pem>] [--cert <cert.pem>] [--key <key.pem>] "
            "<hostname> [port]\n", argv[0]);
        return 1;
    }

    std::string hostname = hostname_arg;
    uint16_t port = port_arg ? static_cast<uint16_t>(std::atoi(port_arg)) : 4433;

    // Load trust store
    asn1::x509::trust_store roots;
    if (cafile) {
        std::printf("Loading CA certificates from %s...\n", cafile);
        std::ifstream f(cafile);
        if (!f) { std::fprintf(stderr, "Cannot open %s\n", cafile); return 1; }
        std::string pem{std::istreambuf_iterator<char>(f), {}};
        auto blocks = asn1::pem::decode_all(pem);
        for (auto& block : blocks)
            if (block.label == "CERTIFICATE") roots.add(std::move(block.der));
        std::printf("Loaded %zu CA cert(s)\n", roots.roots.size());
    } else {
        std::printf("Loading Mozilla root certificates...\n");
        roots = asn1::x509::load_mozilla_roots();
        std::printf("Loaded %zu roots\n", roots.roots.size());
    }

    // Load client certificate and key (mTLS)
    std::vector<std::vector<uint8_t>> client_cert_chain;
    tls::loaded_key client_loaded{tls::tls_private_key{tls::p256_curve::number_type{}}, tls::NamedCurve::secp256r1, tls::key_type::ec};
    bool have_client_cert = false;
    if (certfile && keyfile) {
        std::printf("Loading client certificate from %s...\n", certfile);
        std::ifstream cf(certfile);
        if (!cf) { std::fprintf(stderr, "Cannot open %s\n", certfile); return 1; }
        std::string cert_pem{std::istreambuf_iterator<char>(cf), {}};
        auto cert_blocks = asn1::pem::decode_all(cert_pem);
        for (auto& block : cert_blocks)
            if (block.label == "CERTIFICATE") client_cert_chain.push_back(std::move(block.der));
        std::printf("Loaded %zu client cert(s)\n", client_cert_chain.size());

        std::printf("Loading client key from %s...\n", keyfile);
        std::ifstream kf(keyfile);
        if (!kf) { std::fprintf(stderr, "Cannot open %s\n", keyfile); return 1; }
        std::string key_pem{std::istreambuf_iterator<char>(kf), {}};
        client_loaded = tls::load_private_key(key_pem);
        have_client_cert = true;
    }

    std::printf("Connecting to %s:%u (UDP)...\n", hostname.c_str(), port);
    tls::udp_transport conn(hostname, port);
    if (!conn.is_connected()) {
        std::fprintf(stderr, "Failed to connect\n");
        return 1;
    }
    conn.set_recv_timeout(5000);
    std::printf("UDP connected\n");

    system_random rng;
    tls::dtls_client_config cfg;
    cfg.trust = &roots;
    cfg.hostname = hostname;
    if (have_client_cert) {
        cfg.client_certificate_chain = client_cert_chain;
        cfg.client_private_key = client_loaded.key;
        cfg.client_key_curve = client_loaded.curve;
    }

    tls::dtls_client client(conn, rng, cfg);
    std::printf("Starting DTLS handshake...\n");
    auto result = client.handshake();
    if (!result.ok()) {
        std::fprintf(stderr, "Handshake failed (error %d)\n", static_cast<int>(result.error));
        return 1;
    }
    std::printf("DTLS handshake complete! Suite: 0x%04X\n",
                static_cast<unsigned>(client.negotiated_suite()));

    // Send a test message
    const char* msg = "Hello from DTLS client\n";
    auto send_result = client.send(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(msg), std::strlen(msg)));
    if (!send_result.ok()) {
        std::fprintf(stderr, "Send failed\n");
        return 1;
    }

    // Read response
    std::printf("\n--- Response ---\n");
    std::array<uint8_t, 4096> buf{};
    auto recv_result = client.recv(buf);
    if (recv_result.ok() && recv_result.value > 0)
        std::fwrite(buf.data(), 1, recv_result.value, stdout);
    std::printf("\n--- End ---\n");

    client.close();
    return 0;
}
