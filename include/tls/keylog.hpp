/**
 * SSLKEYLOGFILE support — NSS Key Log Format.
 *
 * When the SSLKEYLOGFILE environment variable is set, logs TLS master
 * secrets so that tools like Wireshark can decrypt captured traffic.
 *
 * Format (one line per session):
 *   CLIENT_RANDOM <32-byte client_random hex> <48-byte master_secret hex>
 *
 * See https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
 */

#pragma once

#include "types.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>

namespace tls {

inline void log_master_secret(const Random& client_random,
                              const std::array<uint8_t, 48>& master_secret)
{
    const char* path = std::getenv("SSLKEYLOGFILE");
    if (!path) return;

    std::FILE* f = std::fopen(path, "a");
    if (!f) return;

    std::fprintf(f, "CLIENT_RANDOM ");
    for (auto b : client_random)
        std::fprintf(f, "%02x", b);
    std::fprintf(f, " ");
    for (auto b : master_secret)
        std::fprintf(f, "%02x", b);
    std::fprintf(f, "\n");

    std::fclose(f);
}

// TLS 1.3 key log — RFC draft-ietf-tls-keylogfile.
// Labels: CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET,
//         CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET
inline void log_tls13_secret(const char* label,
                             const Random& client_random,
                             std::span<const uint8_t> secret)
{
    const char* path = std::getenv("SSLKEYLOGFILE");
    if (!path) return;

    std::FILE* f = std::fopen(path, "a");
    if (!f) return;

    std::fprintf(f, "%s ", label);
    for (auto b : client_random)
        std::fprintf(f, "%02x", b);
    std::fprintf(f, " ");
    for (size_t i = 0; i < secret.size(); ++i)
        std::fprintf(f, "%02x", secret[i]);
    std::fprintf(f, "\n");

    std::fclose(f);
}

} // namespace tls
