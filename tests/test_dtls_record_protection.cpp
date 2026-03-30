/**
 * DTLS record protection tests.
 *
 * Tests DTLS nonce/AAD construction, encrypt/decrypt roundtrip,
 * and anti-replay window.
 */

#include <tls/dtls_record_protection.hpp>
#include <crypto/aes.hpp>
#include <cassert>
#include <cstdio>

using namespace tls;

static void test_dtls_nonce_construction() {
    std::array<uint8_t, 4> iv = {0x01, 0x02, 0x03, 0x04};
    auto nonce = build_dtls_nonce(std::span<const uint8_t, 4>(iv), 1, 42);

    assert(nonce[0] == 0x01);
    assert(nonce[1] == 0x02);
    assert(nonce[2] == 0x03);
    assert(nonce[3] == 0x04);
    assert(nonce[4] == 0x00);  // epoch high
    assert(nonce[5] == 0x01);  // epoch low
    assert(nonce[6] == 0x00);
    assert(nonce[7] == 0x00);
    assert(nonce[8] == 0x00);
    assert(nonce[9] == 0x00);
    assert(nonce[10] == 0x00);
    assert(nonce[11] == 42);   // sequence number

    std::printf("  dtls_nonce_construction: PASS\n");
}

static void test_dtls_aad_construction() {
    auto aad = build_dtls_additional_data(
        1,                        // epoch
        42,                       // sequence
        ContentType::application_data,
        DTLS_1_2,
        100);                     // plaintext length

    assert(aad.size() == 13);
    assert(aad[0] == 0x00);      // epoch high
    assert(aad[1] == 0x01);      // epoch low
    // sequence 42 in 6 bytes
    assert(aad[2] == 0x00);
    assert(aad[3] == 0x00);
    assert(aad[4] == 0x00);
    assert(aad[5] == 0x00);
    assert(aad[6] == 0x00);
    assert(aad[7] == 42);
    assert(aad[8] == 23);       // application_data
    assert(aad[9] == 254);      // DTLS_1_2 major
    assert(aad[10] == 253);     // DTLS_1_2 minor
    assert(aad[11] == 0);       // length high
    assert(aad[12] == 100);     // length low

    std::printf("  dtls_aad_construction: PASS\n");
}

static void test_dtls_encrypt_decrypt_roundtrip() {
    std::array<uint8_t, 16> key{};
    for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);

    std::array<uint8_t, 4> iv = {0xAA, 0xBB, 0xCC, 0xDD};

    uint8_t plaintext[] = "Hello, DTLS world!";
    size_t pt_len = sizeof(plaintext) - 1;

    auto encrypted = dtls_encrypt_record<aes128>(
        std::span<const uint8_t, 16>(key),
        std::span<const uint8_t, 4>(iv),
        1, 0,
        ContentType::application_data,
        DTLS_1_2,
        std::span<const uint8_t>(plaintext, pt_len));

    // encrypted = explicit_nonce(8) + ciphertext(pt_len) + tag(16)
    assert(encrypted.size() == 8 + pt_len + 16);

    auto decrypted = dtls_decrypt_record<aes128>(
        std::span<const uint8_t, 16>(key),
        std::span<const uint8_t, 4>(iv),
        1, 0,
        ContentType::application_data,
        DTLS_1_2,
        std::span<const uint8_t>(encrypted.data.data(), encrypted.len));

    assert(decrypted.has_value());
    assert(decrypted->size() == pt_len);
    for (size_t i = 0; i < pt_len; ++i)
        assert((*decrypted)[i] == plaintext[i]);

    std::printf("  dtls_encrypt_decrypt_roundtrip: PASS\n");
}

static void test_dtls_decrypt_wrong_epoch() {
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 4> iv = {0x01, 0x02, 0x03, 0x04};

    uint8_t pt[] = {1, 2, 3};
    auto encrypted = dtls_encrypt_record<aes128>(
        std::span<const uint8_t, 16>(key),
        std::span<const uint8_t, 4>(iv),
        1, 0,
        ContentType::application_data,
        DTLS_1_2,
        std::span<const uint8_t>(pt, 3));

    // Try decrypting with wrong epoch (different AAD)
    auto decrypted = dtls_decrypt_record<aes128>(
        std::span<const uint8_t, 16>(key),
        std::span<const uint8_t, 4>(iv),
        2, 0,  // wrong epoch
        ContentType::application_data,
        DTLS_1_2,
        std::span<const uint8_t>(encrypted.data.data(), encrypted.len));

    assert(!decrypted.has_value());

    std::printf("  dtls_decrypt_wrong_epoch: PASS\n");
}

static void test_replay_window_basic() {
    replay_window w;

    // First record accepted
    assert(w.check_and_update(0));
    // Duplicate rejected
    assert(!w.check_and_update(0));
    // Next in sequence accepted
    assert(w.check_and_update(1));
    // Out of order within window accepted
    assert(w.check_and_update(10));
    assert(w.check_and_update(5));
    // Duplicate rejected
    assert(!w.check_and_update(5));

    std::printf("  replay_window_basic: PASS\n");
}

static void test_replay_window_old_rejected() {
    replay_window w;

    // Advance to sequence 100
    assert(w.check_and_update(100));
    // Sequence 36 is 64 behind 100, should be rejected (too old)
    assert(!w.check_and_update(36));
    // Sequence 37 is within the 64-entry window
    assert(w.check_and_update(37));

    std::printf("  replay_window_old_rejected: PASS\n");
}

static void test_replay_window_large_jump() {
    replay_window w;

    assert(w.check_and_update(0));
    // Jump far ahead
    assert(w.check_and_update(1000));
    // Old one is now too far behind
    assert(!w.check_and_update(0));
    // But 999 is within window
    assert(w.check_and_update(999));

    std::printf("  replay_window_large_jump: PASS\n");
}

int main() {
    std::printf("DTLS record protection tests:\n");
    test_dtls_nonce_construction();
    test_dtls_aad_construction();
    test_dtls_encrypt_decrypt_roundtrip();
    test_dtls_decrypt_wrong_epoch();
    test_replay_window_basic();
    test_replay_window_old_rejected();
    test_replay_window_large_jump();
    std::printf("All DTLS record protection tests passed.\n");
    return 0;
}
