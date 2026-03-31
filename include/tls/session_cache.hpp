/**
 * TLS 1.2 session cache and session ticket support —
 * RFC 5246 Section 7.4.1.2, RFC 5077.
 *
 * Stores session data (master secret, cipher suite, etc.) keyed by
 * session ID for session resumption via abbreviated handshakes.
 *
 * Also provides ticket_key and encrypt_ticket/decrypt_ticket for
 * stateless session resumption via session tickets (RFC 5077).
 */

#pragma once

#include "types.hpp"
#include <crypto/aes.hpp>
#include <crypto/gcm.hpp>
#include <crypto/random.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tls {

struct session_data {
    SessionId session_id;
    CipherSuite cipher_suite{};
    std::array<uint8_t, 48> master_secret{};
    bool use_extended_master_secret = false;
    std::string negotiated_protocol;
    std::vector<uint8_t> ticket;  // RFC 5077 — client-side ticket storage
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

// --- Session tickets (RFC 5077) ---

// Server-side ticket encryption key.
// The server uses this to encrypt session state into opaque tickets.
struct ticket_key {
    std::array<uint8_t, 16> key_name{};  // identifies which key encrypted the ticket
    std::array<uint8_t, 16> aes_key{};   // AES-128-GCM encryption key
};

// Ticket wire format: key_name(16) || iv(12) || ciphertext(var) || tag(16)
// Plaintext format:   cipher_suite(2) || ems_flag(1) || master_secret(48) || alpn_len(2) || alpn(var)
inline constexpr size_t TICKET_OVERHEAD = 16 + 12 + 16; // key_name + iv + tag

// Encrypt session state into an opaque ticket.
template <random_generator RNG>
std::vector<uint8_t> encrypt_ticket(const ticket_key& key,
                                    const session_data& session,
                                    RNG& rng) {
    // Serialize plaintext: cipher_suite(2) + ems(1) + master_secret(48) + alpn_len(2) + alpn
    size_t alpn_len = session.negotiated_protocol.size();
    size_t pt_len = 2 + 1 + 48 + 2 + alpn_len;
    std::vector<uint8_t> plaintext(pt_len);
    size_t pos = 0;
    plaintext[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(session.cipher_suite) >> 8);
    plaintext[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(session.cipher_suite));
    plaintext[pos++] = session.use_extended_master_secret ? 1 : 0;
    for (size_t i = 0; i < 48; ++i)
        plaintext[pos++] = session.master_secret[i];
    plaintext[pos++] = static_cast<uint8_t>(alpn_len >> 8);
    plaintext[pos++] = static_cast<uint8_t>(alpn_len);
    for (size_t i = 0; i < alpn_len; ++i)
        plaintext[pos++] = static_cast<uint8_t>(session.negotiated_protocol[i]);

    // Generate random IV
    auto iv = random_bytes<12>(rng);

    // Encrypt with AES-128-GCM, using key_name as AAD
    std::vector<uint8_t> ciphertext(pt_len);
    auto tag = gcm_encrypt_rt<aes_state<128>>(
        std::span<const uint8_t, 16>(key.aes_key),
        std::span<const uint8_t>(iv),
        std::span<const uint8_t>(plaintext),
        std::span<const uint8_t>(key.key_name),
        std::span<uint8_t>(ciphertext));

    // Assemble ticket: key_name(16) || iv(12) || ciphertext || tag(16)
    std::vector<uint8_t> ticket;
    ticket.reserve(TICKET_OVERHEAD + pt_len);
    ticket.insert(ticket.end(), key.key_name.begin(), key.key_name.end());
    ticket.insert(ticket.end(), iv.begin(), iv.end());
    ticket.insert(ticket.end(), ciphertext.begin(), ciphertext.end());
    ticket.insert(ticket.end(), tag.begin(), tag.end());
    return ticket;
}

// Decrypt a ticket and recover session state.
// Returns nullopt if key_name doesn't match, decryption fails, or format is invalid.
inline std::optional<session_data> decrypt_ticket(const ticket_key& key,
                                                  std::span<const uint8_t> ticket) {
    // Minimum ticket size: key_name(16) + iv(12) + min_plaintext(53) + tag(16)
    constexpr size_t MIN_PT = 2 + 1 + 48 + 2; // cipher_suite + ems + master_secret + alpn_len
    if (ticket.size() < TICKET_OVERHEAD + MIN_PT)
        return std::nullopt;

    // Verify key_name
    for (size_t i = 0; i < 16; ++i) {
        if (ticket[i] != key.key_name[i])
            return std::nullopt;
    }

    auto iv = ticket.subspan(16, 12);
    size_t ct_len = ticket.size() - TICKET_OVERHEAD;
    auto ciphertext = ticket.subspan(28, ct_len);
    std::array<uint8_t, 16> tag;
    for (size_t i = 0; i < 16; ++i)
        tag[i] = ticket[28 + ct_len + i];

    // Decrypt
    std::vector<uint8_t> plaintext(ct_len);
    bool ok = gcm_decrypt_rt<aes_state<128>>(
        std::span<const uint8_t, 16>(key.aes_key),
        iv,
        ciphertext,
        std::span<const uint8_t>(key.key_name),
        std::span<const uint8_t, 16>(tag),
        std::span<uint8_t>(plaintext));
    if (!ok)
        return std::nullopt;

    // Deserialize plaintext
    if (plaintext.size() < MIN_PT)
        return std::nullopt;

    size_t pos = 0;
    session_data sd;
    sd.cipher_suite = static_cast<CipherSuite>(
        (static_cast<uint16_t>(plaintext[pos]) << 8) | plaintext[pos + 1]);
    pos += 2;
    sd.use_extended_master_secret = (plaintext[pos++] != 0);
    for (size_t i = 0; i < 48; ++i)
        sd.master_secret[i] = plaintext[pos++];
    uint16_t alpn_len = static_cast<uint16_t>(
        (static_cast<uint16_t>(plaintext[pos]) << 8) | plaintext[pos + 1]);
    pos += 2;
    if (pos + alpn_len != plaintext.size())
        return std::nullopt;
    sd.negotiated_protocol.assign(
        reinterpret_cast<const char*>(plaintext.data() + pos), alpn_len);

    return sd;
}

} // namespace tls
