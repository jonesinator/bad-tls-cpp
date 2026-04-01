/**
 * TLS 1.3 cipher suite definitions — RFC 8446 Section B.4.
 *
 * Maps TLS 1.3 cipher suite enum values to AEAD algorithm parameters,
 * hash types, and provides unified AEAD encrypt/decrypt static methods.
 *
 * TLS 1.3 cipher suites specify only AEAD + hash (no key exchange or
 * signature algorithm — those are negotiated separately).
 *
 * Fully constexpr.
 */

#pragma once

#include "types.hpp"
#include <crypto/aes.hpp>
#include <crypto/chacha20.hpp>
#include <crypto/chacha20_poly1305.hpp>
#include <crypto/gcm.hpp>
#include <crypto/sha2.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace tls {

struct Tls13CipherSuiteParams {
    size_t key_length;   // AEAD key size in bytes (16 or 32)
    size_t iv_length;    // Always 12 for TLS 1.3
    size_t tag_length;   // Always 16
    size_t hash_size;    // Hash output size (32 or 48)
};

constexpr Tls13CipherSuiteParams get_tls13_cipher_suite_params(Tls13CipherSuite suite) {
    switch (suite) {
    case Tls13CipherSuite::TLS_AES_128_GCM_SHA256:
        return {16, 12, 16, 32};
    case Tls13CipherSuite::TLS_AES_256_GCM_SHA384:
        return {32, 12, 16, 48};
    case Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        return {32, 12, 16, 32};
    }
    throw "unsupported TLS 1.3 cipher suite";
}

// Compile-time type mapping and AEAD operations per cipher suite.
template <Tls13CipherSuite Suite> struct tls13_cipher_suite_traits;

template <> struct tls13_cipher_suite_traits<Tls13CipherSuite::TLS_AES_128_GCM_SHA256> {
    using cipher_type = aes128;
    using hash_type = sha256_state;
    static constexpr size_t key_length = 16;
    static constexpr size_t iv_length = 12;
    static constexpr size_t tag_length = 16;

    static constexpr std::array<uint8_t, 16> aead_encrypt(
        std::span<const uint8_t, 16> key,
        std::span<const uint8_t, 12> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> aad,
        std::span<uint8_t> ct_out) noexcept
    {
        return gcm_encrypt_rt<aes128>(key, nonce, plaintext, aad, ct_out);
    }

    static constexpr bool aead_decrypt(
        std::span<const uint8_t, 16> key,
        std::span<const uint8_t, 12> nonce,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> aad,
        std::span<const uint8_t, 16> tag,
        std::span<uint8_t> pt_out) noexcept
    {
        return gcm_decrypt_rt<aes128>(key, nonce, ciphertext, aad, tag, pt_out);
    }
};

template <> struct tls13_cipher_suite_traits<Tls13CipherSuite::TLS_AES_256_GCM_SHA384> {
    using cipher_type = aes256;
    using hash_type = sha384_state;
    static constexpr size_t key_length = 32;
    static constexpr size_t iv_length = 12;
    static constexpr size_t tag_length = 16;

    static constexpr std::array<uint8_t, 16> aead_encrypt(
        std::span<const uint8_t, 32> key,
        std::span<const uint8_t, 12> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> aad,
        std::span<uint8_t> ct_out) noexcept
    {
        return gcm_encrypt_rt<aes256>(key, nonce, plaintext, aad, ct_out);
    }

    static constexpr bool aead_decrypt(
        std::span<const uint8_t, 32> key,
        std::span<const uint8_t, 12> nonce,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> aad,
        std::span<const uint8_t, 16> tag,
        std::span<uint8_t> pt_out) noexcept
    {
        return gcm_decrypt_rt<aes256>(key, nonce, ciphertext, aad, tag, pt_out);
    }
};

template <> struct tls13_cipher_suite_traits<Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256> {
    using cipher_type = chacha20_poly1305_cipher;
    using hash_type = sha256_state;
    static constexpr size_t key_length = 32;
    static constexpr size_t iv_length = 12;
    static constexpr size_t tag_length = 16;

    static constexpr std::array<uint8_t, 16> aead_encrypt(
        std::span<const uint8_t, 32> key,
        std::span<const uint8_t, 12> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> aad,
        std::span<uint8_t> ct_out) noexcept
    {
        return chacha20_poly1305_encrypt(key, nonce, plaintext, aad, ct_out);
    }

    static constexpr bool aead_decrypt(
        std::span<const uint8_t, 32> key,
        std::span<const uint8_t, 12> nonce,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> aad,
        std::span<const uint8_t, 16> tag,
        std::span<uint8_t> pt_out) noexcept
    {
        return chacha20_poly1305_decrypt(key, nonce, ciphertext, aad, tag, pt_out);
    }
};

// Runtime→compile-time dispatch: calls f.template operator()<traits>()
// for the matching TLS 1.3 cipher suite.
template <typename F>
constexpr auto dispatch_tls13_cipher_suite(Tls13CipherSuite suite, F&& f) {
    switch (suite) {
    case Tls13CipherSuite::TLS_AES_128_GCM_SHA256:
        return f.template operator()<tls13_cipher_suite_traits<Tls13CipherSuite::TLS_AES_128_GCM_SHA256>>();
    case Tls13CipherSuite::TLS_AES_256_GCM_SHA384:
        return f.template operator()<tls13_cipher_suite_traits<Tls13CipherSuite::TLS_AES_256_GCM_SHA384>>();
    case Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        return f.template operator()<tls13_cipher_suite_traits<Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256>>();
    }
    throw "unsupported TLS 1.3 cipher suite";
}

} // namespace tls
