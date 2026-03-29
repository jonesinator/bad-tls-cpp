/**
 * TLS 1.2 cipher suite definitions — RFC 5288, RFC 5289.
 *
 * Maps cipher suite enum values to algorithm parameters and C++ types
 * from the crypto module.
 *
 * Fully constexpr.
 */

#pragma once

#include "types.hpp"
#include <crypto/aes.hpp>
#include <crypto/sha2.hpp>
#include <cstddef>

namespace tls {

struct CipherSuiteParams {
    size_t key_length;          // AES key size in bytes (16 or 32)
    size_t fixed_iv_length;     // Implicit IV size (4 bytes for GCM)
    size_t record_iv_length;    // Explicit nonce size (8 bytes for GCM)
    size_t tag_length;          // AEAD tag size (16 bytes for GCM)
    size_t prf_hash_size;       // PRF hash output size (32 or 48)
    size_t verify_data_length;  // Finished.verify_data length (always 12)
};

constexpr CipherSuiteParams get_cipher_suite_params(CipherSuite suite) {
    switch (suite) {
    case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
    case CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        return {16, 4, 8, 16, 32, 12};
    case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
    case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        return {32, 4, 8, 16, 48, 12};
    }
    throw "unsupported cipher suite";
}

// Compile-time type mapping per cipher suite
template <CipherSuite Suite> struct cipher_suite_traits;

template <> struct cipher_suite_traits<CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256> {
    using cipher_type = aes128;
    using hash_type = sha256_state;
    static constexpr size_t key_length = 16;
    static constexpr size_t fixed_iv_length = 4;
    static constexpr size_t record_iv_length = 8;
    static constexpr size_t tag_length = 16;
};

template <> struct cipher_suite_traits<CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256> {
    using cipher_type = aes128;
    using hash_type = sha256_state;
    static constexpr size_t key_length = 16;
    static constexpr size_t fixed_iv_length = 4;
    static constexpr size_t record_iv_length = 8;
    static constexpr size_t tag_length = 16;
};

template <> struct cipher_suite_traits<CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384> {
    using cipher_type = aes256;
    using hash_type = sha384_state;
    static constexpr size_t key_length = 32;
    static constexpr size_t fixed_iv_length = 4;
    static constexpr size_t record_iv_length = 8;
    static constexpr size_t tag_length = 16;
};

template <> struct cipher_suite_traits<CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384> {
    using cipher_type = aes256;
    using hash_type = sha384_state;
    static constexpr size_t key_length = 32;
    static constexpr size_t fixed_iv_length = 4;
    static constexpr size_t record_iv_length = 8;
    static constexpr size_t tag_length = 16;
};

// Runtime→compile-time dispatch: calls f.template operator()<traits>()
// for the matching cipher suite.
template <typename F>
constexpr auto dispatch_cipher_suite(CipherSuite suite, F&& f) {
    switch (suite) {
    case CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        return f.template operator()<cipher_suite_traits<CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256>>();
    case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        return f.template operator()<cipher_suite_traits<CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256>>();
    case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        return f.template operator()<cipher_suite_traits<CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384>>();
    case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        return f.template operator()<cipher_suite_traits<CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384>>();
    }
    throw "unsupported cipher suite";
}

} // namespace tls
