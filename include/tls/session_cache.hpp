/**
 * TLS 1.2 session cache — RFC 5246 Section 7.4.1.2.
 *
 * Stores session data (master secret, cipher suite, etc.) keyed by
 * session ID for session resumption via abbreviated handshakes.
 */

#pragma once

#include "types.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace tls {

struct session_data {
    SessionId session_id;
    CipherSuite cipher_suite{};
    std::array<uint8_t, 48> master_secret{};
    bool use_extended_master_secret = false;
    std::string negotiated_protocol;
};

class session_cache {
    std::vector<session_data> entries_;
    size_t max_entries_;

public:
    explicit session_cache(size_t max_entries = 64)
        : max_entries_(max_entries > 0 ? max_entries : 1) {}

    void store(const session_data& data) {
        // Replace existing entry with same session_id
        for (auto& e : entries_) {
            if (e.session_id.length == data.session_id.length &&
                e.session_id.length > 0 &&
                e.session_id == data.session_id) {
                e = data;
                return;
            }
        }
        // Evict oldest entry if at capacity
        if (entries_.size() >= max_entries_)
            entries_.erase(entries_.begin());
        entries_.push_back(data);
    }

    const session_data* find(const SessionId& id) const {
        for (auto& e : entries_) {
            if (e.session_id.length == id.length &&
                id.length > 0 &&
                e.session_id == id)
                return &e;
        }
        return nullptr;
    }

    void remove(const SessionId& id) {
        entries_.erase(
            std::remove_if(entries_.begin(), entries_.end(),
                [&](const session_data& e) {
                    return e.session_id.length == id.length &&
                           id.length > 0 &&
                           e.session_id == id;
                }),
            entries_.end());
    }

    size_t size() const { return entries_.size(); }
};

} // namespace tls
