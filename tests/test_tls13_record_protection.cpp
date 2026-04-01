/**
 * TLS 1.3 record protection tests — RFC 8446 Section 5.
 *
 * Verifies nonce construction, AAD format, encrypt/decrypt roundtrips
 * for all three TLS 1.3 cipher suites, inner content type handling,
 * and tamper detection.
 */

#include <tls/tls13_record_protection.hpp>
#include <cassert>
#include <cstdint>

using aes128_traits = tls::tls13_cipher_suite_traits<
    tls::Tls13CipherSuite::TLS_AES_128_GCM_SHA256>;
using aes256_traits = tls::tls13_cipher_suite_traits<
    tls::Tls13CipherSuite::TLS_AES_256_GCM_SHA384>;
using chacha_traits = tls::tls13_cipher_suite_traits<
    tls::Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256>;

void test_build_tls13_nonce() {
    constexpr auto test = [] {
        // Known IV and sequence number
        std::array<uint8_t, 12> iv{};
        for (size_t i = 0; i < 12; ++i)
            iv[i] = static_cast<uint8_t>(0xA0 + i);

        auto nonce = tls::build_tls13_nonce(iv, 42);

        // Verify it matches XOR of IV with padded seq (42 = 0x2A)
        // padded_seq = {0,0,0,0, 0,0,0,0, 0,0,0, 0x2A}
        // nonce[11] = iv[11] ^ 0x2A, all others = iv[i] ^ 0
        for (size_t i = 0; i < 11; ++i)
            if (nonce[i] != iv[i]) throw "nonce prefix mismatch";
        if (nonce[11] != (iv[11] ^ 0x2A)) throw "nonce XOR mismatch";

        // Verify it matches build_chacha_nonce for the same inputs
        auto chacha_nonce = tls::build_chacha_nonce(iv, 42);
        for (size_t i = 0; i < 12; ++i)
            if (nonce[i] != chacha_nonce[i]) throw "should match chacha nonce";

        return true;
    };
    static_assert(test());
}

void test_build_tls13_additional_data() {
    constexpr auto test = [] {
        auto aad = tls::build_tls13_additional_data(0x0105);

        // Should be: 0x17 0x03 0x03 0x01 0x05
        if (aad[0] != 0x17) throw "wrong content type";
        if (aad[1] != 0x03) throw "wrong version major";
        if (aad[2] != 0x03) throw "wrong version minor";
        if (aad[3] != 0x01) throw "wrong length high byte";
        if (aad[4] != 0x05) throw "wrong length low byte";

        return true;
    };
    static_assert(test());
}

void test_encrypt_decrypt_roundtrip_aes128() {
    constexpr auto test = [] {
        std::array<uint8_t, 16> key{};
        for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);

        std::array<uint8_t, 12> iv{};
        for (size_t i = 0; i < 12; ++i) iv[i] = static_cast<uint8_t>(0x10 + i);

        std::array<uint8_t, 11> plaintext{};
        for (size_t i = 0; i < 11; ++i)
            plaintext[i] = static_cast<uint8_t>('A' + i);

        auto encrypted = tls::tls13_encrypt_record<aes128_traits>(
            key, iv, 0, tls::ContentType::application_data, plaintext);

        // Encrypted should be: ciphertext(12) + tag(16) = 28 bytes
        // 12 = plaintext(11) + content_type(1)
        if (encrypted.size() != 11 + 1 + 16) throw "wrong encrypted size";

        auto decrypted = tls::tls13_decrypt_record<aes128_traits>(
            key, iv, 0,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.size()));

        if (!decrypted) throw "decryption failed";
        if (decrypted->content_type != tls::ContentType::application_data)
            throw "wrong content type";
        if (decrypted->plaintext.size() != 11)
            throw "wrong plaintext size";
        for (size_t i = 0; i < 11; ++i)
            if (decrypted->plaintext[i] != plaintext[i])
                throw "plaintext mismatch";

        return true;
    };
    static_assert(test());
}

void test_encrypt_decrypt_roundtrip_aes256() {
    constexpr auto test = [] {
        std::array<uint8_t, 32> key{};
        for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i * 3);

        std::array<uint8_t, 12> iv{};
        for (size_t i = 0; i < 12; ++i) iv[i] = static_cast<uint8_t>(0x20 + i);

        std::array<uint8_t, 8> plaintext{};
        for (size_t i = 0; i < 8; ++i) plaintext[i] = static_cast<uint8_t>(i);

        auto encrypted = tls::tls13_encrypt_record<aes256_traits>(
            key, iv, 7, tls::ContentType::handshake, plaintext);

        auto decrypted = tls::tls13_decrypt_record<aes256_traits>(
            key, iv, 7,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.size()));

        if (!decrypted) throw "decryption failed";
        if (decrypted->content_type != tls::ContentType::handshake)
            throw "wrong content type";
        if (decrypted->plaintext.size() != 8)
            throw "wrong plaintext size";
        for (size_t i = 0; i < 8; ++i)
            if (decrypted->plaintext[i] != plaintext[i])
                throw "plaintext mismatch";

        return true;
    };
    static_assert(test());
}

void test_encrypt_decrypt_roundtrip_chacha20() {
    constexpr auto test = [] {
        std::array<uint8_t, 32> key{};
        for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(0xFF - i);

        std::array<uint8_t, 12> iv{};
        for (size_t i = 0; i < 12; ++i) iv[i] = static_cast<uint8_t>(0x40 + i);

        std::array<uint8_t, 16> plaintext{};
        for (size_t i = 0; i < 16; ++i)
            plaintext[i] = static_cast<uint8_t>('a' + i);

        auto encrypted = tls::tls13_encrypt_record<chacha_traits>(
            key, iv, 99, tls::ContentType::application_data, plaintext);

        auto decrypted = tls::tls13_decrypt_record<chacha_traits>(
            key, iv, 99,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.size()));

        if (!decrypted) throw "decryption failed";
        if (decrypted->content_type != tls::ContentType::application_data)
            throw "wrong content type";
        if (decrypted->plaintext.size() != 16)
            throw "wrong plaintext size";
        for (size_t i = 0; i < 16; ++i)
            if (decrypted->plaintext[i] != plaintext[i])
                throw "plaintext mismatch";

        return true;
    };
    static_assert(test());
}

void test_inner_content_type_variants() {
    constexpr auto test = [] {
        std::array<uint8_t, 16> key{};
        for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i + 0x30);

        std::array<uint8_t, 12> iv{};
        for (size_t i = 0; i < 12; ++i) iv[i] = static_cast<uint8_t>(i);

        std::array<uint8_t, 4> data = {1, 2, 3, 4};

        // Test handshake content type
        auto enc_hs = tls::tls13_encrypt_record<aes128_traits>(
            key, iv, 0, tls::ContentType::handshake, data);
        auto dec_hs = tls::tls13_decrypt_record<aes128_traits>(
            key, iv, 0,
            std::span<const uint8_t>(enc_hs.data.data(), enc_hs.size()));
        if (!dec_hs || dec_hs->content_type != tls::ContentType::handshake)
            throw "handshake type failed";

        // Test alert content type
        auto enc_alert = tls::tls13_encrypt_record<aes128_traits>(
            key, iv, 1, tls::ContentType::alert, data);
        auto dec_alert = tls::tls13_decrypt_record<aes128_traits>(
            key, iv, 1,
            std::span<const uint8_t>(enc_alert.data.data(), enc_alert.size()));
        if (!dec_alert || dec_alert->content_type != tls::ContentType::alert)
            throw "alert type failed";

        // Test application_data content type
        auto enc_app = tls::tls13_encrypt_record<aes128_traits>(
            key, iv, 2, tls::ContentType::application_data, data);
        auto dec_app = tls::tls13_decrypt_record<aes128_traits>(
            key, iv, 2,
            std::span<const uint8_t>(enc_app.data.data(), enc_app.size()));
        if (!dec_app || dec_app->content_type != tls::ContentType::application_data)
            throw "application_data type failed";

        return true;
    };
    static_assert(test());
}

void test_tampered_ciphertext() {
    constexpr auto test = [] {
        std::array<uint8_t, 16> key{};
        for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);

        std::array<uint8_t, 12> iv{};
        std::array<uint8_t, 8> plaintext = {1, 2, 3, 4, 5, 6, 7, 8};

        auto encrypted = tls::tls13_encrypt_record<aes128_traits>(
            key, iv, 0, tls::ContentType::application_data, plaintext);

        // Flip a byte in the ciphertext
        encrypted.data[0] ^= 0xFF;

        auto decrypted = tls::tls13_decrypt_record<aes128_traits>(
            key, iv, 0,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.size()));

        if (decrypted) throw "tampered ciphertext should fail";

        return true;
    };
    static_assert(test());
}

void test_wrong_sequence_number() {
    constexpr auto test = [] {
        std::array<uint8_t, 16> key{};
        for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);

        std::array<uint8_t, 12> iv{};
        std::array<uint8_t, 8> plaintext = {1, 2, 3, 4, 5, 6, 7, 8};

        auto encrypted = tls::tls13_encrypt_record<aes128_traits>(
            key, iv, 5, tls::ContentType::application_data, plaintext);

        // Decrypt with wrong sequence number
        auto decrypted = tls::tls13_decrypt_record<aes128_traits>(
            key, iv, 6,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.size()));

        if (decrypted) throw "wrong sequence number should fail";

        return true;
    };
    static_assert(test());
}

void test_no_explicit_nonce_on_wire() {
    constexpr auto test = [] {
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 12> iv{};
        std::array<uint8_t, 5> plaintext = {1, 2, 3, 4, 5};

        auto encrypted = tls::tls13_encrypt_record<aes128_traits>(
            key, iv, 0, tls::ContentType::application_data, plaintext);

        // TLS 1.3: no explicit nonce prefix (unlike TLS 1.2 AES-GCM).
        // Output should be exactly: ciphertext(6) + tag(16) = 22 bytes
        // where 6 = plaintext(5) + content_type(1)
        if (encrypted.size() != 5 + 1 + 16) throw "unexpected size";

        return true;
    };
    static_assert(test());
}

int main() {
    test_build_tls13_nonce();
    test_build_tls13_additional_data();
    test_encrypt_decrypt_roundtrip_aes128();
    test_encrypt_decrypt_roundtrip_aes256();
    test_encrypt_decrypt_roundtrip_chacha20();
    test_inner_content_type_variants();
    test_tampered_ciphertext();
    test_wrong_sequence_number();
    test_no_explicit_nonce_on_wire();
    return 0;
}
