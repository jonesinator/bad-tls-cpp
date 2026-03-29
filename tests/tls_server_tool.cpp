/**
 * TLS 1.2 server tool.
 *
 * Usage: ./tls_server_tool <cert.pem> <key.pem> [bind_addr] [port]
 *
 * Loads an EC private key and certificate chain from PEM files,
 * listens for TLS connections, and serves "Hello, world!\n" to each client.
 */

#include <tls/tcp_transport.hpp>
#include <tls/server.hpp>
#include <tls/private_key.hpp>
#include <asn1/pem.hpp>
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
    if (!f) {
        std::fprintf(stderr, "Cannot open %s\n", path);
        std::exit(1);
    }
    return {std::istreambuf_iterator<char>(f), {}};
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::fprintf(stderr, "Usage: %s <cert.pem> <key.pem> [bind_addr] [port]\n", argv[0]);
        return 1;
    }

    const char* cert_path = argv[1];
    const char* key_path = argv[2];
    std::string bind_addr = (argc >= 4) ? argv[3] : "";
    uint16_t port = (argc >= 5) ? static_cast<uint16_t>(std::atoi(argv[4])) : 4433;

    // Load certificate chain
    std::printf("Loading certificates from %s...\n", cert_path);
    auto cert_pem = read_file(cert_path);
    auto cert_blocks = asn1::pem::decode_all(cert_pem);
    std::vector<std::vector<uint8_t>> cert_chain;
    for (auto& block : cert_blocks) {
        if (block.label == "CERTIFICATE")
            cert_chain.push_back(std::move(block.der));
    }
    if (cert_chain.empty()) {
        std::fprintf(stderr, "No certificates found in %s\n", cert_path);
        return 1;
    }
    std::printf("Loaded %zu certificate(s)\n", cert_chain.size());

    // Load private key
    std::printf("Loading private key from %s...\n", key_path);
    auto key_pem = read_file(key_path);
    auto loaded = tls::load_ec_private_key(key_pem);
    std::printf("Key curve: %s\n",
        loaded.curve == tls::NamedCurve::secp256r1 ? "P-256" : "P-384");

    // Start listening
    std::printf("Listening on %s:%u...\n",
        bind_addr.empty() ? "0.0.0.0" : bind_addr.c_str(), port);
    tls::tcp_listener listener(bind_addr, port);
    if (!listener.is_listening()) {
        std::fprintf(stderr, "Failed to listen\n");
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGPIPE, SIG_IGN);

    std::printf("Server ready. Press Ctrl+C to stop.\n");

    while (running) {
        auto conn = listener.accept();
        if (!conn.is_connected()) continue;

        std::printf("Client connected\n");

        system_random rng;
        tls::server_config cfg;
        cfg.certificate_chain = cert_chain;
        cfg.private_key = loaded.key;
        cfg.private_key_curve = loaded.curve;

        tls::tls_server server(conn, rng, cfg);
        auto result = server.handshake();
        if (!result.ok()) {
            std::fprintf(stderr, "Handshake failed (error %d)\n",
                static_cast<int>(result.error));
            continue;
        }
        std::printf("TLS handshake complete! Suite: 0x%04X\n",
            static_cast<unsigned>(server.negotiated_suite()));

        // Read client request (discard it)
        std::array<uint8_t, 4096> buf{};
        auto recv_result = server.recv(buf);
        if (recv_result.ok() && recv_result.value > 0) {
            std::printf("Received %zu bytes from client\n", recv_result.value);
        }

        // Send response
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 14\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Hello, world!\n";
        auto send_result = server.send(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(response), std::strlen(response)));
        if (!send_result.ok()) {
            std::fprintf(stderr, "Send failed\n");
        }

        server.close();
        std::printf("Connection closed\n\n");
    }

    std::printf("\nShutting down.\n");
    return 0;
}
