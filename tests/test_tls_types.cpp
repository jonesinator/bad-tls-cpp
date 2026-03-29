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

    // CipherSuites
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) == 0xC02B);
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) == 0xC02C);
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) == 0xC02F);
    static_assert(static_cast<uint16_t>(tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) == 0xC030);

    // NamedCurves
    static_assert(static_cast<uint16_t>(tls::NamedCurve::secp256r1) == 23);
    static_assert(static_cast<uint16_t>(tls::NamedCurve::secp384r1) == 24);

    // AlertLevel
    static_assert(static_cast<uint8_t>(tls::AlertLevel::warning) == 1);
    static_assert(static_cast<uint8_t>(tls::AlertLevel::fatal) == 2);
}

void test_protocol_version() {
    static_assert(tls::TLS_1_0 == tls::ProtocolVersion{3, 1});
    static_assert(tls::TLS_1_1 == tls::ProtocolVersion{3, 2});
    static_assert(tls::TLS_1_2 == tls::ProtocolVersion{3, 3});
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

int main() {
    test_enum_wire_values();
    test_protocol_version();
    test_session_id();
    test_signature_and_hash();
    return 0;
}
