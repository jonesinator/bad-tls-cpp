#include <number/tls_prf.hpp>
#include <number/sha2.hpp>
#include <cassert>
#include <cstdint>
#include <array>
#include <span>

// --- Test Case 1: All-zero inputs, PRF-SHA256 ---

void test_prf_sha256_zeros() {
    // secret: 48 zero bytes, label: "test label", seed: 32 zero bytes
    // Output verified against Python hmac + hashlib implementation
    std::array<uint8_t, 48> secret{};
    const char* label_str = "test label";
    auto label = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(label_str), 10);
    std::array<uint8_t, 32> seed{};

    auto output = tls_prf<sha256_state, 100>(secret, label, seed);

    // Expected: 7422612f7e7c28a654da5ad71ac030cf...
    assert(output[0] == 0x74 && output[1] == 0x22 && output[2] == 0x61 && output[3] == 0x2F);
    assert(output[4] == 0x7E && output[5] == 0x7C && output[6] == 0x28 && output[7] == 0xA6);
    // ...e3fa99ec8fd6f9c70ea9aa4cea21c3b5
    assert(output[16] == 0xE3 && output[17] == 0xFA && output[18] == 0x99 && output[19] == 0xEC);
    // Last bytes: ...93a78875
    assert(output[96] == 0x93 && output[97] == 0xA7 && output[98] == 0x88 && output[99] == 0x75);
}

// --- Test Case 2: Non-trivial inputs ---

void test_prf_sha256_nontrivial() {
    // secret: 9bbe436ba940f017b17652849a71db35
    // label: "test label"
    // seed: a0ba9f936cda311827a6f796ffd5198c
    std::array<uint8_t, 16> secret = {
        0x9B,0xBE,0x43,0x6B, 0xA9,0x40,0xF0,0x17,
        0xB1,0x76,0x52,0x84, 0x9A,0x71,0xDB,0x35
    };
    const char* label_str = "test label";
    auto label = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(label_str), 10);
    std::array<uint8_t, 16> seed = {
        0xA0,0xBA,0x9F,0x93, 0x6C,0xDA,0x31,0x18,
        0x27,0xA6,0xF7,0x96, 0xFF,0xD5,0x19,0x8C
    };

    auto output = tls_prf<sha256_state, 100>(secret, label, seed);

    // Expected: e3f229ba727be17b8d122620557cd453...
    assert(output[0] == 0xE3 && output[1] == 0xF2 && output[2] == 0x29 && output[3] == 0xBA);
    assert(output[4] == 0x72 && output[5] == 0x7B && output[6] == 0xE1 && output[7] == 0x7B);
    // ...c2aab21d07c3d495
    assert(output[16] == 0xC2 && output[17] == 0xAA && output[18] == 0xB2 && output[19] == 0x1D);
    // Last bytes: ...347b66
    assert(output[97] == 0x34 && output[98] == 0x7B && output[99] == 0x66);
}

// --- Test P_hash directly with SHA-384 ---

void test_prf_sha384() {
    // Verify the PRF also works with SHA-384 (used in some TLS 1.2 cipher suites)
    std::array<uint8_t, 16> secret = {
        0x9B,0xBE,0x43,0x6B, 0xA9,0x40,0xF0,0x17,
        0xB1,0x76,0x52,0x84, 0x9A,0x71,0xDB,0x35
    };
    const char* label_str = "test label";
    auto label = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(label_str), 10);
    std::array<uint8_t, 16> seed = {
        0xA0,0xBA,0x9F,0x93, 0x6C,0xDA,0x31,0x18,
        0x27,0xA6,0xF7,0x96, 0xFF,0xD5,0x19,0x8C
    };

    auto output = tls_prf<sha384_state, 48>(secret, label, seed);

    // Expected: dd88775cd827187b67a3f7652b5c13f7...
    assert(output[0] == 0xDD && output[1] == 0x88 && output[2] == 0x77 && output[3] == 0x5C);
    assert(output[4] == 0xD8 && output[5] == 0x27 && output[6] == 0x18 && output[7] == 0x7B);
    // Last bytes: ...21ddb1
    assert(output[45] == 0x21 && output[46] == 0xDD && output[47] == 0xB1);
}

// --- Compile-time test ---

void test_constexpr() {
    constexpr std::array<uint8_t, 48> secret{};
    constexpr auto label_bytes = std::array<uint8_t, 10>{
        't','e','s','t',' ','l','a','b','e','l'
    };
    constexpr std::array<uint8_t, 32> seed{};

    constexpr auto output = tls_prf<sha256_state, 32>(
        secret,
        std::span<const uint8_t, 10>(label_bytes),
        seed);
    static_assert(output[0] == 0x74 && output[1] == 0x22);
    static_assert(output[2] == 0x61 && output[3] == 0x2F);
}

int main() {
    test_prf_sha256_zeros();
    test_prf_sha256_nontrivial();
    test_prf_sha384();
    test_constexpr();
    return 0;
}
