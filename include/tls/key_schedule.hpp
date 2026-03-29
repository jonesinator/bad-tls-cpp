/**
 * TLS 1.2 key schedule — RFC 5246 Sections 6.3 and 8.1.
 *
 * Master secret derivation, key block expansion, and Finished.verify_data
 * computation using the TLS PRF.
 *
 * Fully constexpr.
 */

#pragma once

#include "types.hpp"
#include "cipher_suite.hpp"
#include <crypto/tls_prf.hpp>
#include <array>
#include <cstdint>
#include <span>

namespace tls {

// RFC 5246 Section 8.1:
// master_secret = PRF(pre_master_secret, "master secret",
//                     ClientHello.random + ServerHello.random)[0..47]
template <hash_function THash>
constexpr std::array<uint8_t, 48> derive_master_secret(
    std::span<const uint8_t> pre_master_secret,
    const Random& client_random,
    const Random& server_random)
{
    // seed = client_random || server_random
    std::array<uint8_t, 64> seed{};
    for (size_t i = 0; i < 32; ++i) seed[i] = client_random[i];
    for (size_t i = 0; i < 32; ++i) seed[32 + i] = server_random[i];

    constexpr uint8_t label[] = "master secret";
    // Note: string literal includes null terminator, label is 13 bytes
    return tls_prf<THash, 48>(
        pre_master_secret,
        std::span<const uint8_t>(label, 13),
        std::span<const uint8_t>(seed));
}

// Expanded key material from the key block
struct KeyBlock {
    std::array<uint8_t, 32> client_write_key{}; // up to AES-256 (32 bytes)
    std::array<uint8_t, 32> server_write_key{};
    std::array<uint8_t, 4> client_write_iv{};   // GCM fixed IV
    std::array<uint8_t, 4> server_write_iv{};
    size_t key_length = 0; // actual key bytes used (16 or 32)
};

// RFC 5246 Section 6.3:
// key_block = PRF(master_secret, "key expansion",
//                 server_random + client_random)
// For AEAD cipher suites (RFC 5288), key_block partitions into:
//   client_write_key [key_length]
//   server_write_key [key_length]
//   client_write_iv  [fixed_iv_length]
//   server_write_iv  [fixed_iv_length]
// No MAC keys for AEAD.
template <hash_function THash>
constexpr KeyBlock derive_key_block(
    const std::array<uint8_t, 48>& master_secret,
    const Random& client_random,
    const Random& server_random,
    const CipherSuiteParams& params)
{
    // seed = server_random || client_random (note: reversed from master secret!)
    std::array<uint8_t, 64> seed{};
    for (size_t i = 0; i < 32; ++i) seed[i] = server_random[i];
    for (size_t i = 0; i < 32; ++i) seed[32 + i] = client_random[i];

    constexpr uint8_t label[] = "key expansion";

    // Total key material needed: 2*key_length + 2*fixed_iv_length
    // Max: 2*32 + 2*4 = 72 bytes
    auto material = tls_prf<THash, 72>(
        master_secret,
        std::span<const uint8_t>(label, 13),
        std::span<const uint8_t>(seed));

    KeyBlock kb;
    kb.key_length = params.key_length;

    size_t offset = 0;
    for (size_t i = 0; i < params.key_length; ++i)
        kb.client_write_key[i] = material[offset++];
    for (size_t i = 0; i < params.key_length; ++i)
        kb.server_write_key[i] = material[offset++];
    for (size_t i = 0; i < params.fixed_iv_length; ++i)
        kb.client_write_iv[i] = material[offset++];
    for (size_t i = 0; i < params.fixed_iv_length; ++i)
        kb.server_write_iv[i] = material[offset++];

    return kb;
}

// RFC 5246 Section 7.4.9:
// verify_data = PRF(master_secret, finished_label,
//                   Hash(handshake_messages))[0..11]
// finished_label = "client finished" (15 bytes) or "server finished" (15 bytes)
template <hash_function THash>
constexpr std::array<uint8_t, 12> compute_verify_data(
    const std::array<uint8_t, 48>& master_secret,
    bool is_client,
    std::span<const uint8_t> transcript_hash)
{
    constexpr uint8_t client_label[] = "client finished";
    constexpr uint8_t server_label[] = "server finished";

    auto label_span = is_client
        ? std::span<const uint8_t>(client_label, 15)
        : std::span<const uint8_t>(server_label, 15);

    return tls_prf<THash, 12>(
        master_secret,
        label_span,
        transcript_hash);
}

} // namespace tls
