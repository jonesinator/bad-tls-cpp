/**
 * TLS 1.2 handshake transcript hash — RFC 5246 Section 7.4.9.
 *
 * Wraps a hash_function state for incrementally accumulating
 * handshake messages. Supports non-destructive current_hash()
 * (finalizes a copy) needed for computing Finished.verify_data
 * mid-transcript.
 *
 * Fully constexpr.
 */

#pragma once

#include <crypto/hash_concept.hpp>
#include <array>
#include <span>

namespace tls {

template <hash_function THash>
struct TranscriptHash {
    THash state;

    constexpr TranscriptHash() { state.init(); }

    // Feed a complete handshake message (header + body) into the transcript
    constexpr void update(std::span<const uint8_t> handshake_message) {
        state.update(handshake_message);
    }

    // Get the current hash without consuming the state (finalizes a copy)
    constexpr std::array<uint8_t, THash::digest_size> current_hash() const {
        THash copy = state;
        return copy.finalize();
    }

    // Finalize and return the hash (consumes the state)
    constexpr std::array<uint8_t, THash::digest_size> finalize() {
        return state.finalize();
    }
};

} // namespace tls
