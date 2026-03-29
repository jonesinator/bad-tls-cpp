/**
 * TLS 1.2 end-to-end connection tool.
 *
 * Usage: ./tls_connect_tool <hostname> [port]
 *
 * Connects to a server, performs a TLS 1.2 handshake with certificate
 * and hostname verification using the Mozilla CA bundle, sends an
 * HTTP/1.1 GET request, and prints the response.
 */

#include <tls/tcp_transport.hpp>
#include <tls/client.hpp>
#include <x509/mozilla_roots.hpp>
#include <crypto/random.hpp>
#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <hostname> [port]\n", argv[0]);
        return 1;
    }

    std::string hostname = argv[1];
    uint16_t port = (argc >= 3) ? static_cast<uint16_t>(std::atoi(argv[2])) : 443;

    std::printf("Loading Mozilla root certificates...\n");
    auto roots = asn1::x509::load_mozilla_roots();
    std::printf("Loaded %zu roots\n", roots.roots.size());

    std::printf("Connecting to %s:%u...\n", hostname.c_str(), port);
    tls::tcp_transport conn(hostname, port);
    if (!conn.is_connected()) {
        std::fprintf(stderr, "Failed to connect\n");
        return 1;
    }
    std::printf("TCP connected\n");

    system_random rng;
    tls::client_config cfg;
    cfg.trust = &roots;
    cfg.hostname = hostname;

    tls::tls_client client(conn, rng, cfg);
    std::printf("Starting TLS handshake...\n");
    auto result = client.handshake();
    if (!result.ok()) {
        std::fprintf(stderr, "Handshake failed (error %d)\n", static_cast<int>(result.error));
        return 1;
    }
    std::printf("TLS handshake complete! Suite: 0x%04X\n",
                static_cast<unsigned>(client.negotiated_suite()));

    // Send HTTP/1.1 GET request
    std::string request = "GET / HTTP/1.1\r\nHost: " + hostname +
                          "\r\nConnection: close\r\n\r\n";
    auto send_result = client.send(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(request.data()), request.size()));
    if (!send_result.ok()) {
        std::fprintf(stderr, "Send failed\n");
        return 1;
    }

    // Read and print response
    std::printf("\n--- Response ---\n");
    std::array<uint8_t, 4096> buf{};
    while (true) {
        auto recv_result = client.recv(buf);
        if (!recv_result.ok() || recv_result.value == 0) break;
        std::fwrite(buf.data(), 1, recv_result.value, stdout);
    }
    std::printf("\n--- End ---\n");

    client.close();
    return 0;
}
