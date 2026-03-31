#include <crypto/x25519.hpp>
#include <cassert>
#include <cstdint>

using uint512 = number<std::uint32_t, 16>;

// Helper: convert a hex string to a 32-byte little-endian array
constexpr std::array<uint8_t, 32> hex_to_bytes(const char* hex) {
    std::array<uint8_t, 32> result{};
    for (size_t i = 0; i < 32; ++i) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        result[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
    }
    return result;
}

// --- RFC 7748 Section 5.2: Test vectors ---

void test_rfc7748_vector_1() {
    // Input scalar:
    //   a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
    // Input u-coordinate:
    //   e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
    // Output u-coordinate:
    //   c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552

    auto scalar = hex_to_bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto u_in   = hex_to_bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    auto expected = hex_to_bytes("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    auto result = x25519_scalar_mult<uint512>(scalar, u_in);
    assert(result == expected);
}

void test_rfc7748_vector_2() {
    // Input scalar:
    //   4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
    // Input u-coordinate:
    //   e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
    // Output u-coordinate:
    //   95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957

    auto scalar = hex_to_bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    auto u_in   = hex_to_bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    auto expected = hex_to_bytes("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    auto result = x25519_scalar_mult<uint512>(scalar, u_in);
    assert(result == expected);
}

// --- RFC 7748 Section 6.1: Diffie-Hellman test vectors ---

void test_rfc7748_dh() {
    // Alice's private key (clamped form is used internally)
    auto alice_priv = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    // Alice's public key = X25519(alice_priv, 9)
    auto alice_pub_expected = hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

    // Bob's private key
    auto bob_priv = hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    // Bob's public key = X25519(bob_priv, 9)
    auto bob_pub_expected = hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    // Shared secret
    auto shared_expected = hex_to_bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // Verify public keys
    auto alice_pub = x25519_public_key<uint512>(alice_priv);
    auto bob_pub = x25519_public_key<uint512>(bob_priv);
    assert(alice_pub == alice_pub_expected);
    assert(bob_pub == bob_pub_expected);

    // Verify shared secret from both sides
    auto secret_a = x25519_shared_secret<uint512>(alice_priv, bob_pub);
    auto secret_b = x25519_shared_secret<uint512>(bob_priv, alice_pub);
    assert(secret_a.has_value());
    assert(secret_b.has_value());
    assert(*secret_a == shared_expected);
    assert(*secret_b == shared_expected);
}

// --- Clamping test ---

void test_clamp() {
    // All-ones input
    std::array<uint8_t, 32> scalar{};
    for (auto& b : scalar) b = 0xFF;

    x25519_clamp(scalar);

    // Byte 0: 0xFF & 248 = 0xF8
    assert(scalar[0] == 0xF8);
    // Byte 31: (0xFF & 127) | 64 = 0x7F
    assert(scalar[31] == 0x7F);

    // All-zeros input
    std::array<uint8_t, 32> zero{};
    x25519_clamp(zero);
    assert(zero[0] == 0x00);
    assert(zero[31] == 0x40);  // bit 254 set
}

// --- Roundtrip test ---

void test_roundtrip() {
    // Two arbitrary private keys
    auto priv_a = hex_to_bytes("a8abababababababababababababababababababababababababababababababab06");
    auto priv_b = hex_to_bytes("c8cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd09");

    auto pub_a = x25519_public_key<uint512>(priv_a);
    auto pub_b = x25519_public_key<uint512>(priv_b);

    auto secret_a = x25519_shared_secret<uint512>(priv_a, pub_b);
    auto secret_b = x25519_shared_secret<uint512>(priv_b, pub_a);

    assert(secret_a.has_value());
    assert(secret_b.has_value());
    assert(*secret_a == *secret_b);
}

// --- Low-order point rejection ---

void test_low_order_point_rejected() {
    // u = 0 is a low-order point — scalar multiplication yields the zero point
    std::array<uint8_t, 32> zero_point{};
    auto priv = hex_to_bytes("a8abababababababababababababababababababababababababababababababab06");

    auto result = x25519_shared_secret<uint512>(priv, zero_point);
    assert(!result.has_value());
}

// --- Constexpr test ---

consteval bool test_rfc7748_constexpr() {
    auto scalar = hex_to_bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto u_in   = hex_to_bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    auto expected = hex_to_bytes("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    auto result = x25519_scalar_mult<uint512>(scalar, u_in);
    return result == expected;
}

static_assert(test_rfc7748_constexpr(), "RFC 7748 Section 5.2 test vector 1 failed at compile time");

int main() {
    test_rfc7748_vector_1();
    test_rfc7748_vector_2();
    test_rfc7748_dh();
    test_clamp();
    test_roundtrip();
    test_low_order_point_rejected();

    return 0;
}
