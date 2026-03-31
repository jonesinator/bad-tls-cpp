/**
 * TLS 1.2 wire-format types — RFC 5246, RFC 4492.
 *
 * Enumerations and value types matching the TLS binary protocol.
 * All types are constexpr and trivially copyable.
 */

#pragma once

#include <array>
#include <cstdint>

namespace tls {

// RFC 5246 Section 6.2.1
enum class ContentType : uint8_t {
    change_cipher_spec = 20,
    alert              = 21,
    handshake          = 22,
    application_data   = 23,
};

// RFC 5246 Section 6.2.1
struct ProtocolVersion {
    uint8_t major;
    uint8_t minor;
    constexpr bool operator==(const ProtocolVersion&) const = default;
};

inline constexpr ProtocolVersion TLS_1_0{3, 1};
inline constexpr ProtocolVersion TLS_1_1{3, 2};
inline constexpr ProtocolVersion TLS_1_2{3, 3};

// DTLS versions use inverted numbering — RFC 6347 Section 4.1
inline constexpr ProtocolVersion DTLS_1_0{254, 255};  // 0xFEFF
inline constexpr ProtocolVersion DTLS_1_2{254, 253};  // 0xFEFD

// RFC 5246 Section 7.4
enum class HandshakeType : uint8_t {
    client_hello         = 1,
    server_hello         = 2,
    hello_verify_request = 3,   // DTLS — RFC 6347 Section 4.2.1
    new_session_ticket   = 4,   // RFC 5077
    certificate          = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done   = 14,
    certificate_verify  = 15,
    client_key_exchange = 16,
    finished            = 20,
};

// RFC 5246 Section 7.4.1.1, RFC 4492, RFC 7905
enum class CipherSuite : uint16_t {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            = 0xC02B,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            = 0xC02C,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256              = 0xC02F,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384              = 0xC030,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256         = 0xCCA8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256       = 0xCCA9,
};

// RFC 5246 Section 7.2
enum class AlertLevel : uint8_t {
    warning = 1,
    fatal   = 2,
};

enum class AlertDescription : uint8_t {
    close_notify            = 0,
    unexpected_message      = 10,
    bad_record_mac          = 20,
    decryption_failed       = 21,
    record_overflow         = 22,
    handshake_failure       = 40,
    bad_certificate         = 42,
    certificate_expired     = 45,
    certificate_unknown     = 46,
    illegal_parameter       = 47,
    unknown_ca              = 48,
    decode_error            = 50,
    decrypt_error           = 51,
    protocol_version        = 70,
    insufficient_security   = 71,
    internal_error          = 80,
    no_application_protocol = 120,  // RFC 7301
};

// RFC 4492 Section 5.1.1, RFC 8422
enum class NamedCurve : uint16_t {
    secp256r1 = 23,
    secp384r1 = 24,
    x25519    = 29,
};

// RFC 5246 Section 7.4.1.4.1, RFC 8446 Section 4.2.3
enum class HashAlgorithm : uint8_t {
    sha256  = 4,
    sha384  = 5,
    sha512  = 6,
    rsa_pss = 8,  // RSA-PSS scheme — "signature" byte encodes the hash
};

enum class SignatureAlgorithm : uint8_t {
    rsa   = 1,
    ecdsa = 3,
};

struct SignatureAndHashAlgorithm {
    HashAlgorithm hash;
    SignatureAlgorithm signature;
    constexpr bool operator==(const SignatureAndHashAlgorithm&) const = default;
};

// RSA-PSS SignatureScheme helpers (RFC 8446 Section 4.2.3)
// Wire encoding: rsa_pss_rsae_sha256 = 0x0804, sha384 = 0x0805, sha512 = 0x0806
// In SignatureAndHashAlgorithm: hash = rsa_pss (0x08), signature byte = hash id (4/5/6)
constexpr bool is_rsa_pss_scheme(SignatureAndHashAlgorithm alg) noexcept {
    return alg.hash == HashAlgorithm::rsa_pss;
}
constexpr HashAlgorithm rsa_pss_actual_hash(SignatureAndHashAlgorithm alg) noexcept {
    return static_cast<HashAlgorithm>(static_cast<uint8_t>(alg.signature));
}

// RFC 5246 Section 7.4.1.2 — 32 bytes of randomness (caller-provided)
using Random = std::array<uint8_t, 32>;

// RFC 5246 Section 7.4.1.2 — variable-length session ID (0–32 bytes)
struct SessionId {
    std::array<uint8_t, 32> data{};
    uint8_t length = 0;
    constexpr bool operator==(const SessionId&) const = default;
};

// RFC 5246 Section 7.4.1.2
enum class CompressionMethod : uint8_t {
    null = 0,
};

// RFC 4492 Section 5.4 — EC curve type byte
enum class ECCurveType : uint8_t {
    named_curve = 3,
};

// RFC 4492 Section 5.1.2 — EC point format
enum class ECPointFormat : uint8_t {
    uncompressed = 0,
};

// TLS extension types
enum class ExtensionType : uint16_t {
    ec_point_formats     = 11,
    supported_groups     = 10,  // formerly "elliptic_curves"
    signature_algorithms = 13,
    application_layer_protocol_negotiation = 16,  // RFC 7301
    extended_master_secret = 0x0017,  // RFC 7627
    session_ticket       = 35,  // RFC 5077
    renegotiation_info   = 0xFF01,  // RFC 5746
};

} // namespace tls
