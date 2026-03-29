/**
 * TLS transport abstraction.
 *
 * Defines the transport concept for byte-level I/O and provides
 * memory_transport for constexpr testing.
 */

#pragma once

#include <asn1/fixed_vector.hpp>
#include <concepts>
#include <cstdint>
#include <span>

namespace tls {

template <typename T>
concept transport = requires(T t, std::span<uint8_t> buf, std::span<const uint8_t> data) {
    { t.read(buf) } -> std::same_as<size_t>;
    { t.write(data) } -> std::same_as<size_t>;
};

// Constexpr-capable mock transport for testing.
// Pre-load rx_buf with server responses; tx_buf captures client output.
struct memory_transport {
    asn1::FixedVector<uint8_t, 32768> rx_buf;
    asn1::FixedVector<uint8_t, 32768> tx_buf;
    size_t rx_pos = 0;

    constexpr size_t read(std::span<uint8_t> buf) {
        size_t avail = rx_buf.size() - rx_pos;
        size_t n = (buf.size() < avail) ? buf.size() : avail;
        for (size_t i = 0; i < n; ++i)
            buf[i] = rx_buf[rx_pos + i];
        rx_pos += n;
        return n;
    }

    constexpr size_t write(std::span<const uint8_t> data) {
        for (size_t i = 0; i < data.size(); ++i)
            tx_buf.push_back(data[i]);
        return data.size();
    }
};

static_assert(transport<memory_transport>);

} // namespace tls
