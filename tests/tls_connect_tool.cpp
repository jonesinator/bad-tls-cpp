/**
 * TLS 1.2 end-to-end connection tool.
 *
 * Usage: ./tls_connect_tool [options] <hostname> [port]
 *
 * Options:
 *   --cafile <ca.pem>    Use custom CA certificate file instead of Mozilla roots
 *   --cert <cert.pem>    Client certificate for mTLS
 *   --key <key.pem>      Client private key for mTLS
 *
 * Connects to a server, performs a TLS 1.2 handshake with certificate
 * and hostname verification, sends an HTTP/1.1 GET request, and prints
 * the response.
 */

#include <tls/tcp_transport.hpp>
#include <tls/client.hpp>
#include <tls/private_key.hpp>
#include <x509/mozilla_roots.hpp>
#include <crypto/random.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    std::setbuf(stdout, nullptr);

    // Parse arguments
    const char* cafile = nullptr;
    const char* certfile = nullptr;
    const char* keyfile = nullptr;
    const char* ticket_file = nullptr;
    const char* hostname_arg = nullptr;
    const char* port_arg = nullptr;

    int i = 1;
    while (i < argc) {
        if (std::strcmp(argv[i], "--cafile") == 0 && i + 1 < argc) {
            cafile = argv[++i];
            ++i;
        } else if (std::strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            certfile = argv[++i];
            ++i;
        } else if (std::strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            keyfile = argv[++i];
            ++i;
        } else if (std::strcmp(argv[i], "--ticket-file") == 0 && i + 1 < argc) {
            ticket_file = argv[++i];
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
            "Usage: %s [--cafile <ca.pem>] [--cert <cert.pem>] [--key <key.pem>] "
            "[--ticket-file <file>] <hostname> [port]\n", argv[0]);
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

    // Load client certificate and key (mTLS)
    std::vector<std::vector<uint8_t>> client_cert_chain;
    tls::loaded_key client_loaded{tls::tls_private_key{tls::p256_curve::number_type{}}, tls::NamedCurve::secp256r1, tls::key_type::ec};
    bool have_client_cert = false;
    if (certfile && keyfile) {
        std::printf("Loading client certificate from %s...\n", certfile);
        std::ifstream cf(certfile);
        if (!cf) {
            std::fprintf(stderr, "Cannot open %s\n", certfile);
            return 1;
        }
        std::string cert_pem{std::istreambuf_iterator<char>(cf), {}};
        auto cert_blocks = asn1::pem::decode_all(cert_pem);
        for (auto& block : cert_blocks) {
            if (block.label == "CERTIFICATE")
                client_cert_chain.push_back(std::move(block.der));
        }
        std::printf("Loaded %zu client cert(s)\n", client_cert_chain.size());

        std::printf("Loading client key from %s...\n", keyfile);
        std::ifstream kf(keyfile);
        if (!kf) {
            std::fprintf(stderr, "Cannot open %s\n", keyfile);
            return 1;
        }
        std::string key_pem{std::istreambuf_iterator<char>(kf), {}};
        client_loaded = tls::load_private_key(key_pem);
        have_client_cert = true;
        if (client_loaded.type == tls::key_type::rsa)
            std::printf("Client key type: RSA\n");
        else
            std::printf("Client key type: EC (%s)\n",
                client_loaded.curve == tls::NamedCurve::secp256r1 ? "P-256" : "P-384");
    }

    std::printf("Connecting to %s:%u...\n", hostname.c_str(), port);
    tls::tcp_transport conn(hostname, port);
    if (!conn.is_connected()) {
        std::fprintf(stderr, "Failed to connect\n");
        return 1;
    }
    std::printf("TCP connected\n");

    // Load session ticket for resumption (if file exists)
    std::vector<uint8_t> ticket_data;
    tls::session_data resume_sd;
    bool have_ticket = false;
    if (ticket_file) {
        std::ifstream tf(ticket_file, std::ios::binary);
        if (tf) {
            // Ticket file format: master_secret(48) + cipher_suite(2) + ticket_len(2) + ticket(var)
            std::array<uint8_t, 48> ms;
            tf.read(reinterpret_cast<char*>(ms.data()), 48);
            uint8_t cs_hi = 0, cs_lo = 0;
            tf.read(reinterpret_cast<char*>(&cs_hi), 1);
            tf.read(reinterpret_cast<char*>(&cs_lo), 1);
            uint8_t tl_hi = 0, tl_lo = 0;
            tf.read(reinterpret_cast<char*>(&tl_hi), 1);
            tf.read(reinterpret_cast<char*>(&tl_lo), 1);
            uint16_t tl = static_cast<uint16_t>((tl_hi << 8) | tl_lo);
            ticket_data.resize(tl);
            tf.read(reinterpret_cast<char*>(ticket_data.data()), tl);
            if (tf) {
                resume_sd.master_secret = ms;
                resume_sd.cipher_suite = static_cast<tls::CipherSuite>((cs_hi << 8) | cs_lo);
                have_ticket = true;
                std::printf("Loaded session ticket (%zu bytes) for resumption\n", ticket_data.size());
            }
        }
    }

    system_random rng;
    tls::client_config cfg;
    cfg.trust = &roots;
    cfg.hostname = hostname;
    if (have_client_cert) {
        cfg.client_certificate_chain = client_cert_chain;
        cfg.client_private_key = client_loaded.key;
        cfg.client_key_curve = client_loaded.curve;
    }
    if (have_ticket) {
        cfg.session_ticket = ticket_data;
        cfg.resume_session = &resume_sd;
    }

    tls::tls_client client(conn, rng, cfg);
    std::printf("Starting TLS handshake...\n");
    auto result = client.handshake();
    if (!result.ok()) {
        std::fprintf(stderr, "Handshake failed (error %d)\n", static_cast<int>(result.error));
        return 1;
    }
    std::printf("TLS handshake complete! Suite: 0x%04X\n",
                static_cast<unsigned>(client.negotiated_suite()));

    // Save received ticket for future resumption
    if (ticket_file && !client.received_ticket().empty()) {
        std::ofstream tf(ticket_file, std::ios::binary | std::ios::trunc);
        if (tf) {
            // File format: master_secret(48) + cipher_suite(2) + ticket_len(2) + ticket(var)
            auto& ms = client.master_secret();
            tf.write(reinterpret_cast<const char*>(ms.data()), 48);
            uint16_t cs = static_cast<uint16_t>(client.negotiated_suite());
            uint8_t cs_hi = static_cast<uint8_t>(cs >> 8);
            uint8_t cs_lo = static_cast<uint8_t>(cs);
            tf.write(reinterpret_cast<const char*>(&cs_hi), 1);
            tf.write(reinterpret_cast<const char*>(&cs_lo), 1);
            auto& ticket = client.received_ticket();
            uint8_t tl_hi = static_cast<uint8_t>(ticket.size() >> 8);
            uint8_t tl_lo = static_cast<uint8_t>(ticket.size());
            tf.write(reinterpret_cast<const char*>(&tl_hi), 1);
            tf.write(reinterpret_cast<const char*>(&tl_lo), 1);
            tf.write(reinterpret_cast<const char*>(ticket.data()), static_cast<std::streamsize>(ticket.size()));
            std::printf("Saved session ticket (%zu bytes) to %s\n", ticket.size(), ticket_file);
        }
    }

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
