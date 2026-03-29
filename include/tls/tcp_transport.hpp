/**
 * TCP transport — POSIX socket implementation of the transport concept.
 *
 * Provides blocking TCP I/O with DNS resolution via getaddrinfo.
 * Supports IPv4 and IPv6. RAII: constructor connects, destructor closes.
 * Move-only.
 */

#pragma once

#include "transport.hpp"
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdint>
#include <span>
#include <string>

namespace tls {

class tcp_transport {
    int fd_ = -1;

public:
    tcp_transport(const std::string& host, const std::string& port) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* result = nullptr;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0)
            return;

        for (auto* rp = result; rp; rp = rp->ai_next) {
            fd_ = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd_ == -1) continue;
            if (::connect(fd_, rp->ai_addr, rp->ai_addrlen) == 0) break;
            ::close(fd_);
            fd_ = -1;
        }
        freeaddrinfo(result);
    }

    tcp_transport(const std::string& host, uint16_t port)
        : tcp_transport(host, std::to_string(port)) {}

    ~tcp_transport() { if (fd_ != -1) ::close(fd_); }

    tcp_transport(const tcp_transport&) = delete;
    tcp_transport& operator=(const tcp_transport&) = delete;

    tcp_transport(tcp_transport&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    tcp_transport& operator=(tcp_transport&& o) noexcept {
        if (this != &o) {
            if (fd_ != -1) ::close(fd_);
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }

    bool is_connected() const { return fd_ != -1; }

    size_t read(std::span<uint8_t> buf) {
        if (fd_ == -1) return 0;
        auto n = ::read(fd_, buf.data(), buf.size());
        return (n <= 0) ? 0 : static_cast<size_t>(n);
    }

    size_t write(std::span<const uint8_t> data) {
        if (fd_ == -1) return 0;
        size_t total = 0;
        while (total < data.size()) {
            auto n = ::write(fd_, data.data() + total, data.size() - total);
            if (n <= 0) return total;
            total += static_cast<size_t>(n);
        }
        return total;
    }
};

static_assert(transport<tcp_transport>);

} // namespace tls
