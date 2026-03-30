/**
 * UDP transport — POSIX socket implementation for DTLS.
 *
 * Provides blocking UDP I/O with DNS resolution via getaddrinfo.
 * Supports IPv4 and IPv6. RAII: constructor connects, destructor closes.
 * Move-only. Satisfies the transport concept.
 */

#pragma once

#include "transport.hpp"
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

namespace tls {

class udp_transport {
    int fd_ = -1;

    explicit udp_transport(int fd) : fd_(fd) {}
    friend class udp_listener;

public:
    udp_transport(const std::string& host, const std::string& port) {
        addrinfo hints{};
        // For UDP, prefer IPv4 to avoid IPv6 reachability issues
        // (connect() always succeeds for UDP even if the peer is unreachable)
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

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

    udp_transport(const std::string& host, uint16_t port)
        : udp_transport(host, std::to_string(port)) {}

    ~udp_transport() { if (fd_ != -1) ::close(fd_); }

    udp_transport(const udp_transport&) = delete;
    udp_transport& operator=(const udp_transport&) = delete;

    udp_transport(udp_transport&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    udp_transport& operator=(udp_transport&& o) noexcept {
        if (this != &o) {
            if (fd_ != -1) ::close(fd_);
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }

    bool is_connected() const { return fd_ != -1; }

    // Set receive timeout for retransmission timer support.
    // Returns true on success.
    bool set_recv_timeout(int milliseconds) {
        if (fd_ == -1) return false;
        struct timeval tv{};
        tv.tv_sec = milliseconds / 1000;
        tv.tv_usec = (milliseconds % 1000) * 1000;
        return ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
    }

    size_t read(std::span<uint8_t> buf) {
        if (fd_ == -1) return 0;
        auto n = ::recv(fd_, buf.data(), buf.size(), 0);
        return (n <= 0) ? 0 : static_cast<size_t>(n);
    }

    size_t write(std::span<const uint8_t> data) {
        if (fd_ == -1) return 0;
        auto n = ::send(fd_, data.data(), data.size(), 0);
        return (n <= 0) ? 0 : static_cast<size_t>(n);
    }
};

static_assert(transport<udp_transport>);

class udp_listener {
    int fd_ = -1;
    struct sockaddr_storage peer_addr_{};
    socklen_t peer_addr_len_ = 0;

public:
    udp_listener(const std::string& bind_addr, uint16_t port) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        addrinfo* result = nullptr;
        auto port_str = std::to_string(port);
        const char* node = bind_addr.empty() ? nullptr : bind_addr.c_str();
        if (getaddrinfo(node, port_str.c_str(), &hints, &result) != 0)
            return;

        for (auto* rp = result; rp; rp = rp->ai_next) {
            fd_ = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd_ == -1) continue;

            int opt = 1;
            ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            if (::bind(fd_, rp->ai_addr, rp->ai_addrlen) == 0) break;
            ::close(fd_);
            fd_ = -1;
        }
        freeaddrinfo(result);
    }

    ~udp_listener() { if (fd_ != -1) ::close(fd_); }

    udp_listener(const udp_listener&) = delete;
    udp_listener& operator=(const udp_listener&) = delete;

    udp_listener(udp_listener&& o) noexcept
        : fd_(o.fd_), peer_addr_(o.peer_addr_), peer_addr_len_(o.peer_addr_len_) {
        o.fd_ = -1;
    }
    udp_listener& operator=(udp_listener&& o) noexcept {
        if (this != &o) {
            if (fd_ != -1) ::close(fd_);
            fd_ = o.fd_;
            peer_addr_ = o.peer_addr_;
            peer_addr_len_ = o.peer_addr_len_;
            o.fd_ = -1;
        }
        return *this;
    }

    bool is_listening() const { return fd_ != -1; }

    // Accept a DTLS "connection": receives the first datagram from a peer
    // and returns a connected UDP transport locked to that peer.
    // The initial datagram is discarded (caller should handle it via the
    // returned transport's initial_data).
    // For simplicity, we connect() the listener socket to the peer,
    // then transfer ownership. This means only one peer per listener.
    udp_transport accept(std::span<uint8_t> initial_buf, size_t& initial_len) {
        if (fd_ == -1) { initial_len = 0; return udp_transport(-1); }

        peer_addr_len_ = sizeof(peer_addr_);
        auto n = ::recvfrom(fd_, initial_buf.data(), initial_buf.size(), 0,
                            reinterpret_cast<struct sockaddr*>(&peer_addr_),
                            &peer_addr_len_);
        if (n <= 0) { initial_len = 0; return udp_transport(-1); }
        initial_len = static_cast<size_t>(n);

        // Connect the socket to the peer so subsequent send/recv are directed
        if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&peer_addr_),
                      peer_addr_len_) != 0) {
            initial_len = 0;
            return udp_transport(-1);
        }

        // Transfer socket ownership
        int accepted_fd = fd_;
        fd_ = -1;
        return udp_transport(accepted_fd);
    }
};

} // namespace tls
