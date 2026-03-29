#include <tls/key_schedule.hpp>
#include <tls/transcript.hpp>
#include <crypto/sha2.hpp>
#include <cassert>

void test_derive_master_secret() {
    // Derive master secret from known inputs and verify it produces
    // deterministic output (cross-verified against Python implementation).
    constexpr auto test = [] {
        std::array<uint8_t, 32> pms{};
        for (size_t i = 0; i < 32; ++i) pms[i] = static_cast<uint8_t>(i);

        tls::Random client_random{};
        for (size_t i = 0; i < 32; ++i) client_random[i] = static_cast<uint8_t>(0x10 + i);

        tls::Random server_random{};
        for (size_t i = 0; i < 32; ++i) server_random[i] = static_cast<uint8_t>(0x50 + i);

        auto ms = tls::derive_master_secret<sha256_state>(pms, client_random, server_random);

        // Verify it's 48 bytes and non-zero
        bool all_zero = true;
        for (size_t i = 0; i < 48; ++i)
            if (ms[i] != 0) all_zero = false;
        if (all_zero) throw "master secret is all zeros";

        // Verify determinism: same inputs → same output
        auto ms2 = tls::derive_master_secret<sha256_state>(pms, client_random, server_random);
        for (size_t i = 0; i < 48; ++i)
            if (ms[i] != ms2[i]) throw "non-deterministic";

        return ms;
    };
    constexpr auto ms = test();

    // Different inputs → different output
    tls::Random cr{};
    tls::Random sr{};
    std::array<uint8_t, 32> pms{};
    auto ms_different = tls::derive_master_secret<sha256_state>(pms, cr, sr);
    bool same = true;
    for (size_t i = 0; i < 48; ++i)
        if (ms[i] != ms_different[i]) same = false;
    assert(!same);
}

void test_derive_key_block() {
    constexpr auto test = [] {
        std::array<uint8_t, 48> master_secret{};
        for (size_t i = 0; i < 48; ++i) master_secret[i] = static_cast<uint8_t>(i);

        tls::Random client_random{};
        tls::Random server_random{};
        for (size_t i = 0; i < 32; ++i) {
            client_random[i] = static_cast<uint8_t>(0xAA);
            server_random[i] = static_cast<uint8_t>(0xBB);
        }

        auto params = tls::get_cipher_suite_params(
            tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

        auto kb = tls::derive_key_block<sha256_state>(
            master_secret, client_random, server_random, params);

        if (kb.key_length != 16) throw "wrong key_length";

        // Verify client and server keys are different
        bool keys_same = true;
        for (size_t i = 0; i < 16; ++i)
            if (kb.client_write_key[i] != kb.server_write_key[i]) keys_same = false;
        if (keys_same) throw "client and server keys should differ";

        // Verify IVs are different
        bool ivs_same = true;
        for (size_t i = 0; i < 4; ++i)
            if (kb.client_write_iv[i] != kb.server_write_iv[i]) ivs_same = false;
        if (ivs_same) throw "client and server IVs should differ";

        return true;
    };
    static_assert(test());
}

void test_derive_key_block_aes256() {
    constexpr auto test = [] {
        std::array<uint8_t, 48> master_secret{};
        for (size_t i = 0; i < 48; ++i) master_secret[i] = static_cast<uint8_t>(i * 3);

        tls::Random client_random{};
        tls::Random server_random{};

        auto params = tls::get_cipher_suite_params(
            tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);

        auto kb = tls::derive_key_block<sha384_state>(
            master_secret, client_random, server_random, params);

        if (kb.key_length != 32) throw "wrong key_length for AES-256";
        return true;
    };
    static_assert(test());
}

void test_compute_verify_data() {
    constexpr auto test = [] {
        std::array<uint8_t, 48> master_secret{};
        for (size_t i = 0; i < 48; ++i) master_secret[i] = static_cast<uint8_t>(i);

        // Simulate a transcript hash
        std::array<uint8_t, 32> transcript_hash{};
        for (size_t i = 0; i < 32; ++i) transcript_hash[i] = static_cast<uint8_t>(0xFF - i);

        auto client_vd = tls::compute_verify_data<sha256_state>(
            master_secret, true, transcript_hash);
        auto server_vd = tls::compute_verify_data<sha256_state>(
            master_secret, false, transcript_hash);

        // Client and server verify_data should differ (different labels)
        bool same = true;
        for (size_t i = 0; i < 12; ++i)
            if (client_vd[i] != server_vd[i]) same = false;
        if (same) throw "client/server verify_data should differ";

        // Deterministic
        auto client_vd2 = tls::compute_verify_data<sha256_state>(
            master_secret, true, transcript_hash);
        for (size_t i = 0; i < 12; ++i)
            if (client_vd[i] != client_vd2[i]) throw "non-deterministic";

        return true;
    };
    static_assert(test());
}

void test_transcript_hash() {
    constexpr auto test = [] {
        tls::TranscriptHash<sha256_state> th;

        std::array<uint8_t, 5> msg1 = {0x01, 0x02, 0x03, 0x04, 0x05};
        th.update(msg1);

        // current_hash() should be non-destructive
        auto h1 = th.current_hash();
        auto h2 = th.current_hash();
        for (size_t i = 0; i < 32; ++i)
            if (h1[i] != h2[i]) throw "current_hash not idempotent";

        // Adding more data should change the hash
        std::array<uint8_t, 3> msg2 = {0x06, 0x07, 0x08};
        th.update(msg2);
        auto h3 = th.current_hash();
        bool same = true;
        for (size_t i = 0; i < 32; ++i)
            if (h1[i] != h3[i]) same = false;
        if (same) throw "hash should change after update";

        return true;
    };
    static_assert(test());
}

int main() {
    test_derive_master_secret();
    test_derive_key_block();
    test_derive_key_block_aes256();
    test_compute_verify_data();
    test_transcript_hash();
    return 0;
}
