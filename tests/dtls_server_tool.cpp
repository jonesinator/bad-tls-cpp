/**
 * DTLS 1.2 server tool.
 *
 * Usage: ./dtls_server_tool [options] <cert.pem> <key.pem> [bind_addr] [port]
 *
 * Options:
 *   --client-ca <ca.pem>      Request and verify client certificates (mTLS)
 *   --require-client-cert     Reject clients without certificates
 *
 * Listens for DTLS connections via UDP, performs handshake, echoes data.
 */

#include <tls/udp_transport.hpp>
#include <tls/dtls_server.hpp>
#include <tls/private_key.hpp>
#include <asn1/pem.hpp>
#include <x509/trust_store.hpp>
#include <crypto/random.hpp>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static volatile sig_atomic_t running = 1;
static void handle_signal(int) { running = 0; }

static std::string read_file(const char* path) {
    std::ifstream f(path);
    if (!f) { std::fprintf(stderr, "Cannot open %s\n", path); std::exit(1); }
    return {std::istreambuf_iterator<char>(f), {}};
}

int main(int argc, char* argv[]) {
    std::setbuf(stdout, nullptr);

    const char* client_ca_path = nullptr;
    bool require_client_cert = false;
    const char* cert_path = nullptr;
    const char* key_path = nullptr;
    const char* bind_addr_arg = nullptr;
    const char* port_arg = nullptr;

    int i = 1;
    while (i < argc) {
        if (std::strcmp(argv[i], "--client-ca") == 0 && i + 1 < argc) {
            client_ca_path = argv[++i]; ++i;
        } else if (std::strcmp(argv[i], "--require-client-cert") == 0) {
            require_client_cert = true; ++i;
        } else if (!cert_path) {
            cert_path = argv[i++];
        } else if (!key_path) {
            key_path = argv[i++];
        } else if (!bind_addr_arg) {
            bind_addr_arg = argv[i++];
        } else if (!port_arg) {
            port_arg = argv[i++];
        } else {
            ++i;
        }
    }

    if (!cert_path || !key_path) {
        std::fprintf(stderr,
            "Usage: %s [--client-ca <ca.pem>] [--require-client-cert] "
            "<cert.pem> <key.pem> [bind_addr] [port]\n", argv[0]);
        return 1;
    }

    std::string bind_addr = bind_addr_arg ? bind_addr_arg : "";
    uint16_t port = port_arg ? static_cast<uint16_t>(std::atoi(port_arg)) : 4433;

    // Load certificate chain
    std::printf("Loading certificates from %s...\n", cert_path);
    auto cert_pem = read_file(cert_path);
    auto cert_blocks = asn1::pem::decode_all(cert_pem);
    std::vector<std::vector<uint8_t>> cert_chain;
    for (auto& block : cert_blocks)
        if (block.label == "CERTIFICATE") cert_chain.push_back(std::move(block.der));
    if (cert_chain.empty()) {
        std::fprintf(stderr, "No certificates found in %s\n", cert_path);
        return 1;
    }
    std::printf("Loaded %zu certificate(s)\n", cert_chain.size());

    // Load private key
    std::printf("Loading private key from %s...\n", key_path);
    auto key_pem = read_file(key_path);
    auto loaded = tls::load_private_key(key_pem);
    if (loaded.type == tls::key_type::rsa)
        std::printf("Key type: RSA\n");
    else
        std::printf("Key type: EC (%s)\n",
            loaded.curve == tls::NamedCurve::secp256r1 ? "P-256" :
            loaded.curve == tls::NamedCurve::secp384r1 ? "P-384" : "P-521");

    // Load client CA
    asn1::x509::trust_store client_ca_store;
    if (client_ca_path) {
        std::printf("Loading client CA from %s...\n", client_ca_path);
        auto ca_pem = read_file(client_ca_path);
        auto ca_blocks = asn1::pem::decode_all(ca_pem);
        for (auto& block : ca_blocks)
            if (block.label == "CERTIFICATE") client_ca_store.add(std::move(block.der));
        std::printf("Loaded %zu client CA cert(s)\n", client_ca_store.roots.size());
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGPIPE, SIG_IGN);

    std::printf("Server ready on %s:%u (UDP). Press Ctrl+C to stop.\n",
        bind_addr.empty() ? "0.0.0.0" : bind_addr.c_str(), port);

    while (running) {
        // Create a fresh listener for each connection (since accept transfers the socket)
        tls::udp_listener listener(bind_addr, port);
        if (!listener.is_listening()) {
            std::fprintf(stderr, "Failed to listen\n");
            return 1;
        }

        std::array<uint8_t, 65536> initial_buf{};
        size_t initial_len = 0;
        auto conn = listener.accept(initial_buf, initial_len);
        if (!conn.is_connected()) continue;

        std::printf("Client connected\n");
        conn.set_recv_timeout(5000);

        system_random rng;
        tls::dtls_server_config cfg;
        cfg.certificate_chain = cert_chain;
        cfg.private_key = loaded.key;
        cfg.private_key_curve = loaded.curve;
        if (client_ca_path) {
            cfg.client_ca = &client_ca_store;
            cfg.require_client_cert = require_client_cert;
        }
        // Generate cookie secret
        cfg.cookie_secret = random_bytes<32>(rng);

        tls::dtls_server server(conn, rng, cfg);
        auto result = server.handshake(
            std::span<const uint8_t>(initial_buf.data(), initial_len));
        if (!result.ok()) {
            std::fprintf(stderr, "Handshake failed (error %d)\n",
                static_cast<int>(result.error));
            continue;
        }
        std::printf("DTLS handshake complete! Suite: 0x%04X, client_authenticated: %s\n",
            static_cast<unsigned>(server.negotiated_suite()),
            server.client_authenticated() ? "yes" : "no");

        // Read and echo
        std::array<uint8_t, 4096> buf{};
        auto recv_result = server.recv(buf);
        if (recv_result.ok() && recv_result.value > 0) {
            std::printf("Received %zu bytes from client\n", recv_result.value);
        }

        const char* body = server.client_authenticated()
            ? "Hello, secure!\n" : (client_ca_path ? "Hello, insecure!\n" : "Hello, world!\n");
        size_t body_len = std::strlen(body);

        auto send_result = server.send(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(body), body_len));
        if (!send_result.ok())
            std::fprintf(stderr, "Send failed\n");

        server.close();
        std::printf("Connection closed\n\n");
    }

    std::printf("\nShutting down.\n");
    return 0;
}
