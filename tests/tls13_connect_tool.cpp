/**
 * TLS 1.3 end-to-end connection tool.
 *
 * Usage: ./tls13_connect_tool [options] <hostname> [port]
 *
 * Options:
 *   --cafile <ca.pem>    Use custom CA certificate file instead of Mozilla roots
 *
 * Connects to a server, performs a TLS 1.3 handshake with certificate
 * and hostname verification, sends an HTTP/1.1 GET request, and prints
 * the response.
 */

#include <tls/tcp_transport.hpp>
#include <tls/tls13_client.hpp>
#include <x509/mozilla_roots.hpp>
#include <crypto/random.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    std::setbuf(stdout, nullptr);

    const char* cafile = nullptr;
    const char* hostname_arg = nullptr;
    const char* port_arg = nullptr;

    int i = 1;
    while (i < argc) {
        if (std::strcmp(argv[i], "--cafile") == 0 && i + 1 < argc) {
            cafile = argv[++i];
            ++i;
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
            "Usage: %s [--cafile <ca.pem>] <hostname> [port]\n", argv[0]);
        return 1;
    }

    std::string hostname = hostname_arg;
    uint16_t port = port_arg ? static_cast<uint16_t>(std::atoi(port_arg)) : 443;

    // Load trust store
    asn1::x509::trust_store roots;
    if (cafile) {
        std::printf("Loading CA certificates from %s...\n", cafile);
        std::ifstream f(cafile);
        if (!f) {
            std::fprintf(stderr, "Cannot open %s\n", cafile);
            return 1;
        }
        std::string pem{std::istreambuf_iterator<char>(f), {}};
        auto blocks = asn1::pem::decode_all(pem);
        for (auto& block : blocks) {
            if (block.label == "CERTIFICATE")
                roots.add(std::move(block.der));
        }
        std::printf("Loaded %zu CA cert(s)\n", roots.roots.size());
    } else {
        std::printf("Loading Mozilla root certificates...\n");
        roots = asn1::x509::load_mozilla_roots();
        std::printf("Loaded %zu roots\n", roots.roots.size());
    }

    std::printf("Connecting to %s:%u...\n", hostname.c_str(), port);
    tls::tcp_transport conn(hostname, port);
    if (!conn.is_connected()) {
        std::fprintf(stderr, "Failed to connect\n");
        return 1;
    }
    std::printf("TCP connected\n");

    system_random rng;
    tls::tls13_client_config cfg;
    cfg.trust = &roots;
    cfg.hostname = hostname;

    tls::tls13_client client(conn, rng, cfg);
    std::printf("Starting TLS 1.3 handshake...\n");
    auto result = client.handshake();
    if (!result.ok()) {
        std::fprintf(stderr, "Handshake failed (error %d)\n", static_cast<int>(result.error));
        return 1;
    }
    std::printf("TLS 1.3 handshake complete! Suite: 0x%04X\n",
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
