#include <tls/record_protection.hpp>
#include <crypto/aes.hpp>
#include <cassert>

void test_build_nonce() {
    constexpr auto test = [] {
        std::array<uint8_t, 4> fixed_iv = {0x01, 0x02, 0x03, 0x04};
        auto nonce = tls::build_nonce(fixed_iv, 0x0000000000000001ULL);
        // nonce = fixed_iv(4) || seq_num_be(8)
        if (nonce[0] != 0x01 || nonce[1] != 0x02 || nonce[2] != 0x03 || nonce[3] != 0x04)
            throw "fixed_iv wrong";
        // seq_num 1 as big-endian 8 bytes: 00 00 00 00 00 00 00 01
        if (nonce[4] != 0 || nonce[5] != 0 || nonce[6] != 0 || nonce[7] != 0)
            throw "seq high bytes wrong";
        if (nonce[8] != 0 || nonce[9] != 0 || nonce[10] != 0 || nonce[11] != 1)
            throw "seq low bytes wrong";
        return true;
    };
    static_assert(test());
}

void test_build_additional_data() {
    constexpr auto test = [] {
        auto aad = tls::build_additional_data(
            42, tls::ContentType::application_data, tls::TLS_1_2, 100);
        // seq_num 42 = 0x2A as big-endian 8 bytes
        if (aad[6] != 0 || aad[7] != 0x2A) throw "seq wrong";
        // type = 23 (application_data)
        if (aad[8] != 23) throw "type wrong";
        // version = 3.3
        if (aad[9] != 3 || aad[10] != 3) throw "version wrong";
        // length = 100 = 0x0064
        if (aad[11] != 0 || aad[12] != 100) throw "length wrong";
        return true;
    };
    static_assert(test());
}

void test_encrypt_decrypt_roundtrip() {
    // AES-128-GCM roundtrip
    constexpr auto test = [] {
        std::array<uint8_t, 16> key = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
        };
        std::array<uint8_t, 4> fixed_iv = {0xCA,0xFE,0xBA,0xBE};
        uint64_t seq = 0;

        std::array<uint8_t, 16> plaintext = {
            'H','e','l','l','o',',',' ','T','L','S',' ','1','.','2','!','\0'
        };

        auto encrypted = tls::encrypt_record<aes128>(
            key, fixed_iv, seq,
            tls::ContentType::application_data, tls::TLS_1_2,
            plaintext);

        // encrypted = explicit_nonce(8) + ciphertext(16) + tag(16) = 40 bytes
        if (encrypted.size() != 40) throw "wrong encrypted size";

        auto decrypted = tls::decrypt_record<aes128>(
            key, fixed_iv, seq,
            tls::ContentType::application_data, tls::TLS_1_2,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.len));

        if (!decrypted) throw "decryption failed";
        if (decrypted->size() != 16) throw "wrong decrypted size";
        for (size_t i = 0; i < 16; ++i)
            if ((*decrypted)[i] != plaintext[i]) throw "plaintext mismatch";

        return true;
    };
    static_assert(test());
}

void test_tampered_ciphertext() {
    constexpr auto test = [] {
        std::array<uint8_t, 16> key = {
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
        };
        std::array<uint8_t, 4> fixed_iv = {0xDE,0xAD,0xBE,0xEF};

        std::array<uint8_t, 8> plaintext = {1,2,3,4,5,6,7,8};

        auto encrypted = tls::encrypt_record<aes128>(
            key, fixed_iv, 0,
            tls::ContentType::application_data, tls::TLS_1_2,
            plaintext);

        // Tamper with a ciphertext byte
        encrypted.data[10] ^= 0xFF;

        auto result = tls::decrypt_record<aes128>(
            key, fixed_iv, 0,
            tls::ContentType::application_data, tls::TLS_1_2,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.len));

        if (result.has_value()) throw "should fail on tampered data";
        return true;
    };
    static_assert(test());
}

void test_wrong_sequence_number() {
    constexpr auto test = [] {
        std::array<uint8_t, 16> key = {
            0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
            0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
        };
        std::array<uint8_t, 4> fixed_iv = {0x01,0x02,0x03,0x04};

        std::array<uint8_t, 4> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};

        auto encrypted = tls::encrypt_record<aes128>(
            key, fixed_iv, 5,
            tls::ContentType::application_data, tls::TLS_1_2,
            plaintext);

        // Try to decrypt with wrong sequence number
        auto result = tls::decrypt_record<aes128>(
            key, fixed_iv, 6, // wrong seq
            tls::ContentType::application_data, tls::TLS_1_2,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.len));

        if (result.has_value()) throw "should fail with wrong seq";
        return true;
    };
    static_assert(test());
}

void test_aes256_gcm() {
    constexpr auto test = [] {
        std::array<uint8_t, 32> key = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
        };
        std::array<uint8_t, 4> fixed_iv = {0xAA,0xBB,0xCC,0xDD};

        std::array<uint8_t, 32> plaintext{};
        for (size_t i = 0; i < 32; ++i) plaintext[i] = static_cast<uint8_t>(i);

        auto encrypted = tls::encrypt_record<aes256>(
            key, fixed_iv, 0,
            tls::ContentType::application_data, tls::TLS_1_2,
            plaintext);

        // 8 (nonce) + 32 (ct) + 16 (tag) = 56
        if (encrypted.size() != 56) throw "wrong size";

        auto decrypted = tls::decrypt_record<aes256>(
            key, fixed_iv, 0,
            tls::ContentType::application_data, tls::TLS_1_2,
            std::span<const uint8_t>(encrypted.data.data(), encrypted.len));

        if (!decrypted) throw "decrypt failed";
        for (size_t i = 0; i < 32; ++i)
            if ((*decrypted)[i] != plaintext[i]) throw "mismatch";

        return true;
    };
    static_assert(test());
}

void test_runtime_gcm_roundtrip() {
    // Test the new gcm_encrypt_rt/gcm_decrypt_rt directly
    std::array<uint8_t, 16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    std::array<uint8_t, 12> iv = {
        0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,0xDE,0xCA,0xF8,0x88
    };
    std::array<uint8_t, 20> plaintext{};
    for (size_t i = 0; i < 20; ++i) plaintext[i] = static_cast<uint8_t>(i * 7);
    std::array<uint8_t, 8> aad = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

    std::array<uint8_t, 20> ciphertext{};
    auto tag = gcm_encrypt_rt<aes128>(key, iv, plaintext, aad, ciphertext);

    std::array<uint8_t, 20> recovered{};
    bool ok = gcm_decrypt_rt<aes128>(key, iv, ciphertext, aad,
        std::span<const uint8_t, 16>(tag), recovered);
    assert(ok);
    for (size_t i = 0; i < 20; ++i)
        assert(recovered[i] == plaintext[i]);

    // Verify it matches the compile-time-size version
    auto ct_result = gcm_encrypt<aes128>(key, iv,
        std::span<const uint8_t, 20>(plaintext), aad);
    for (size_t i = 0; i < 20; ++i)
        assert(ciphertext[i] == ct_result.ciphertext[i]);
    for (size_t i = 0; i < 16; ++i)
        assert(tag[i] == ct_result.tag[i]);
}

int main() {
    test_build_nonce();
    test_build_additional_data();
    test_encrypt_decrypt_roundtrip();
    test_tampered_ciphertext();
    test_wrong_sequence_number();
    test_aes256_gcm();
    test_runtime_gcm_roundtrip();
    return 0;
}
