#include <tls/types.hpp>
#include <cassert>

void test_enum_wire_values() {
    // ContentType
    static_assert(static_cast<uint8_t>(tls::ContentType::change_cipher_spec) == 20);
    static_assert(static_cast<uint8_t>(tls::ContentType::alert) == 21);
    static_assert(static_cast<uint8_t>(tls::ContentType::handshake) == 22);
    static_assert(static_cast<uint8_t>(tls::ContentType::application_data) == 23);

    // HandshakeType
    static_assert(static_cast<uint8_t>(tls::HandshakeType::client_hello) == 1);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::server_hello) == 2);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::certificate) == 11);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::server_key_exchange) == 12);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::server_hello_done) == 14);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::client_key_exchange) == 16);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::finished) == 20);

    // TLS 1.3 HandshakeType values
    static_assert(static_cast<uint8_t>(tls::HandshakeType::end_of_early_data) == 5);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::encrypted_extensions) == 8);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::key_update) == 24);
    static_assert(static_cast<uint8_t>(tls::HandshakeType::message_hash) == 254);

    // CipherSuites
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) == 0xC02B);
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) == 0xC02C);
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) == 0xC02F);
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) == 0xC030);

    // TLS 1.3 CipherSuites
    static_assert(static_cast<uint16_t>(tls::Tls13CipherSuite::TLS_AES_128_GCM_SHA256) == 0x1301);
    static_assert(static_cast<uint16_t>(tls::Tls13CipherSuite::TLS_AES_256_GCM_SHA384) == 0x1302);
    static_assert(static_cast<uint16_t>(tls::Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256) == 0x1303);

    // NamedCurves
    static_assert(static_cast<uint16_t>(tls::NamedCurve::secp256r1) == 23);
    static_assert(static_cast<uint16_t>(tls::NamedCurve::secp384r1) == 24);

    // AlertLevel
    static_assert(static_cast<uint8_t>(tls::AlertLevel::warning) == 1);
    static_assert(static_cast<uint8_t>(tls::AlertLevel::fatal) == 2);

    // TLS 1.3 AlertDescription
    static_assert(static_cast<uint8_t>(tls::AlertDescription::missing_extension) == 109);
    static_assert(static_cast<uint8_t>(tls::AlertDescription::certificate_required) == 116);

    // ExtensionType — TLS 1.3 additions
    static_assert(static_cast<uint16_t>(tls::ExtensionType::supported_versions) == 43);
    static_assert(static_cast<uint16_t>(tls::ExtensionType::psk_key_exchange_modes) == 45);
    static_assert(static_cast<uint16_t>(tls::ExtensionType::key_share) == 51);

    // SignatureScheme
    static_assert(static_cast<uint16_t>(tls::SignatureScheme::ecdsa_secp256r1_sha256) == 0x0403);
    static_assert(static_cast<uint16_t>(tls::SignatureScheme::ecdsa_secp384r1_sha384) == 0x0503);
    static_assert(static_cast<uint16_t>(tls::SignatureScheme::ecdsa_secp521r1_sha512) == 0x0603);
    static_assert(static_cast<uint16_t>(tls::SignatureScheme::rsa_pss_rsae_sha256) == 0x0804);
    static_assert(static_cast<uint16_t>(tls::SignatureScheme::rsa_pss_rsae_sha384) == 0x0805);
    static_assert(static_cast<uint16_t>(tls::SignatureScheme::rsa_pss_rsae_sha512) == 0x0806);
}

void test_protocol_version() {
    static_assert(tls::TLS_1_0 == tls::ProtocolVersion{3, 1});
    static_assert(tls::TLS_1_1 == tls::ProtocolVersion{3, 2});
    static_assert(tls::TLS_1_2 == tls::ProtocolVersion{3, 3});
    static_assert(tls::TLS_1_3 == tls::ProtocolVersion{3, 4});
    static_assert(!(tls::TLS_1_0 == tls::TLS_1_2));
}

void test_session_id() {
    constexpr tls::SessionId empty{};
    static_assert(empty.length == 0);

    constexpr auto make_sid = [] {
        tls::SessionId sid{};
        sid.length = 4;
        sid.data[0] = 0xAA;
        sid.data[1] = 0xBB;
        sid.data[2] = 0xCC;
        sid.data[3] = 0xDD;
        return sid;
    };
    constexpr auto sid = make_sid();
    static_assert(sid.length == 4);
    static_assert(sid.data[0] == 0xAA);
}

void test_signature_and_hash() {
    constexpr tls::SignatureAndHashAlgorithm sha256_rsa{
        tls::HashAlgorithm::sha256, tls::SignatureAlgorithm::rsa};
    constexpr tls::SignatureAndHashAlgorithm sha256_ecdsa{
        tls::HashAlgorithm::sha256, tls::SignatureAlgorithm::ecdsa};
    static_assert(sha256_rsa == sha256_rsa);
    static_assert(!(sha256_rsa == sha256_ecdsa));
}

void test_signature_scheme_conversion() {
    // Round-trip: SignatureAndHashAlgorithm -> SignatureScheme -> SignatureAndHashAlgorithm
    constexpr tls::SignatureAndHashAlgorithm sha256_ecdsa{
        tls::HashAlgorithm::sha256, tls::SignatureAlgorithm::ecdsa};
    static_assert(tls::to_signature_scheme(sha256_ecdsa) == tls::SignatureScheme::ecdsa_secp256r1_sha256);
    static_assert(tls::to_signature_and_hash(tls::SignatureScheme::ecdsa_secp256r1_sha256) == sha256_ecdsa);

    // RSA-PSS round-trip
    constexpr tls::SignatureAndHashAlgorithm rsa_pss_sha256{
        tls::HashAlgorithm::rsa_pss, static_cast<tls::SignatureAlgorithm>(4)};
    static_assert(tls::to_signature_scheme(rsa_pss_sha256) == tls::SignatureScheme::rsa_pss_rsae_sha256);
    static_assert(tls::to_signature_and_hash(tls::SignatureScheme::rsa_pss_rsae_sha256) == rsa_pss_sha256);
}

int main() {
    test_enum_wire_values();
    test_protocol_version();
    test_session_id();
    test_signature_and_hash();
    test_signature_scheme_conversion();
    return 0;
}
