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

} // namespace tls
