/**
 * Comprehensive tests for the SHA-2 family implementation.
 *
 * Tests all six variants (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
 * against NIST test vectors from FIPS 180-4. Also tests streaming (multi-update),
 * block boundary behavior, empty messages, and constexpr evaluation.
 */

#include <crypto/sha2.hpp>
#include <cassert>
#include <cstdint>
#include <array>
#include <span>
#include <string_view>
#include <vector>

// Helper: convert hex string to byte array
template <size_t N>
constexpr std::array<uint8_t, N> hex_to_bytes(std::string_view hex) {
    std::array<uint8_t, N> result{};
    for (size_t i = 0; i < N; ++i) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return 0;
        };
        result[i] = (nibble(hex[2*i]) << 4) | nibble(hex[2*i+1]);
    }
    return result;
}

// Helper: make span from string (without null terminator)
std::span<const uint8_t> str_span(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

// ============================================================
// NIST Test Vectors from FIPS 180-4
// ============================================================

// --- SHA-256 ---

void test_sha256_empty() {
    auto h = sha256(std::span<const uint8_t>{});
    auto expected = hex_to_bytes<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(h == expected);
}

void test_sha256_abc() {
    // NIST one-block message: "abc"
    auto h = sha256(str_span("abc"));
    auto expected = hex_to_bytes<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert(h == expected);
}

void test_sha256_two_block() {
    // NIST two-block message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    auto h = sha256(str_span("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    auto expected = hex_to_bytes<32>("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert(h == expected);
}

// --- SHA-224 ---

void test_sha224_empty() {
    auto h = sha224(std::span<const uint8_t>{});
    auto expected = hex_to_bytes<28>("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    assert(h == expected);
}

void test_sha224_abc() {
    auto h = sha224(str_span("abc"));
    auto expected = hex_to_bytes<28>("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    assert(h == expected);
}

void test_sha224_two_block() {
    auto h = sha224(str_span("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    auto expected = hex_to_bytes<28>("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    assert(h == expected);
}

// --- SHA-512 ---

void test_sha512_empty() {
    auto h = sha512(std::span<const uint8_t>{});
    auto expected = hex_to_bytes<64>(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    assert(h == expected);
}

void test_sha512_abc() {
    auto h = sha512(str_span("abc"));
    auto expected = hex_to_bytes<64>(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    assert(h == expected);
}

void test_sha512_two_block() {
    // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    auto h = sha512(str_span(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    auto expected = hex_to_bytes<64>(
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    assert(h == expected);
}

// --- SHA-384 ---

void test_sha384_empty() {
    auto h = sha384(std::span<const uint8_t>{});
    auto expected = hex_to_bytes<48>(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
        "274edebfe76f65fbd51ad2f14898b95b");
    assert(h == expected);
}

void test_sha384_abc() {
    auto h = sha384(str_span("abc"));
    auto expected = hex_to_bytes<48>(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7");
    assert(h == expected);
}

void test_sha384_two_block() {
    auto h = sha384(str_span(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    auto expected = hex_to_bytes<48>(
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
        "fcc7c71a557e2db966c3e9fa91746039");
    assert(h == expected);
}

// --- SHA-512/224 ---

void test_sha512_224_empty() {
    auto h = sha512_224(std::span<const uint8_t>{});
    auto expected = hex_to_bytes<28>("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    assert(h == expected);
}

void test_sha512_224_abc() {
    auto h = sha512_224(str_span("abc"));
    auto expected = hex_to_bytes<28>("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    assert(h == expected);
}

// --- SHA-512/256 ---

void test_sha512_256_empty() {
    auto h = sha512_256(std::span<const uint8_t>{});
    auto expected = hex_to_bytes<32>("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    assert(h == expected);
}

void test_sha512_256_abc() {
    auto h = sha512_256(str_span("abc"));
    auto expected = hex_to_bytes<32>("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    assert(h == expected);
}

// ============================================================
// Streaming (multi-update) tests
// ============================================================

void test_sha256_streaming_equivalence() {
    // Single-shot vs multi-update must produce identical results
    std::string_view msg = "The quick brown fox jumps over the lazy dog";
    auto single = sha256(str_span(msg));

    sha256_state s;
    s.init();
    // Feed one byte at a time
    for (char c : msg) {
        uint8_t b = static_cast<uint8_t>(c);
        s.update(std::span<const uint8_t>(&b, 1));
    }
    auto streamed = s.finalize();
    assert(single == streamed);
}

void test_sha512_streaming_equivalence() {
    std::string_view msg = "The quick brown fox jumps over the lazy dog";
    auto single = sha512(str_span(msg));

    sha512_state s;
    s.init();
    for (char c : msg) {
        uint8_t b = static_cast<uint8_t>(c);
        s.update(std::span<const uint8_t>(&b, 1));
    }
    assert(single == s.finalize());
}

void test_sha256_chunked_updates() {
    // Feed in various chunk sizes
    std::string_view msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto expected = sha256(str_span(msg));

    for (size_t chunk_size : {1, 2, 3, 7, 13, 31, 55, 56, 63, 64, 100}) {
        sha256_state s;
        s.init();
        size_t offset = 0;
        while (offset < msg.size()) {
            size_t len = std::min(chunk_size, msg.size() - offset);
            s.update(str_span(msg.substr(offset, len)));
            offset += len;
        }
        assert(s.finalize() == expected);
    }
}

void test_sha384_chunked_updates() {
    std::string_view msg =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    auto expected = sha384(str_span(msg));

    for (size_t chunk_size : {1, 5, 17, 64, 127, 128, 200}) {
        sha384_state s;
        s.init();
        size_t offset = 0;
        while (offset < msg.size()) {
            size_t len = std::min(chunk_size, msg.size() - offset);
            s.update(str_span(msg.substr(offset, len)));
            offset += len;
        }
        assert(s.finalize() == expected);
    }
}

// ============================================================
// Block boundary tests
// ============================================================

void test_sha256_exactly_one_block() {
    // SHA-256 block = 64 bytes. Message of exactly 64 bytes.
    // Padding will require a second block (64 + 1 + padding + 8 > 64)
    std::array<uint8_t, 64> data;
    data.fill(0x41);  // 'A'
    auto h = sha256(data);

    // Verify via streaming
    sha256_state s;
    s.init();
    s.update(data);
    assert(s.finalize() == h);
}

void test_sha256_block_minus_one() {
    // 63 bytes: fits in one block with padding (63 + 1 = 64, but need 8 bytes for length)
    // Actually 63 + 1 + 0 padding + 8 length = 72 > 64, so needs 2 blocks
    // This tests the boundary where buffer_len > pad_threshold after 0x80
    std::array<uint8_t, 63> data;
    data.fill(0x42);
    auto h = sha256(data);

    sha256_state s;
    s.init();
    s.update(data);
    assert(s.finalize() == h);
}

void test_sha256_55_bytes() {
    // 55 bytes: 55 + 1 + 8 = 64, fits exactly in one block padding
    std::array<uint8_t, 55> data;
    data.fill(0x43);
    auto h = sha256(data);

    sha256_state s;
    s.init();
    s.update(data);
    assert(s.finalize() == h);
}

void test_sha256_56_bytes() {
    // 56 bytes: 56 + 1 + 8 = 65 > 64, needs 2 blocks for padding
    // This is the exact threshold where an extra block is needed
    std::array<uint8_t, 56> data;
    data.fill(0x44);
    auto h = sha256(data);

    sha256_state s;
    s.init();
    s.update(data);
    assert(s.finalize() == h);
}

void test_sha512_block_boundaries() {
    // SHA-512 block = 128 bytes, length field = 16 bytes
    // pad_threshold = 128 - 16 = 112

    // 111 bytes: 111 + 1 + 16 = 128, fits in one block
    std::array<uint8_t, 111> data_111;
    data_111.fill(0x45);
    auto h_111 = sha512(data_111);
    sha512_state s1;
    s1.init();
    s1.update(data_111);
    assert(s1.finalize() == h_111);

    // 112 bytes: 112 + 1 + 16 = 129 > 128, needs 2 blocks
    std::array<uint8_t, 112> data_112;
    data_112.fill(0x46);
    auto h_112 = sha512(data_112);
    sha512_state s2;
    s2.init();
    s2.update(data_112);
    assert(s2.finalize() == h_112);

    // 128 bytes: exactly one full block, padding in second block
    std::array<uint8_t, 128> data_128;
    data_128.fill(0x47);
    auto h_128 = sha512(data_128);
    sha512_state s3;
    s3.init();
    s3.update(data_128);
    assert(s3.finalize() == h_128);
}

// ============================================================
// Single byte messages
// ============================================================

void test_sha256_single_byte() {
    uint8_t byte = 0x00;
    auto h = sha256(std::span<const uint8_t>(&byte, 1));
    auto expected = hex_to_bytes<32>("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
    assert(h == expected);
}

void test_sha256_single_byte_ff() {
    uint8_t byte = 0xFF;
    auto h = sha256(std::span<const uint8_t>(&byte, 1));
    // Known result for SHA-256 of 0xFF
    auto expected = hex_to_bytes<32>("a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89");
    assert(h == expected);
}

// ============================================================
// Known test vectors: "The quick brown fox..."
// ============================================================

void test_sha256_quick_brown_fox() {
    auto h = sha256(str_span("The quick brown fox jumps over the lazy dog"));
    auto expected = hex_to_bytes<32>("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    assert(h == expected);
}

void test_sha512_quick_brown_fox() {
    auto h = sha512(str_span("The quick brown fox jumps over the lazy dog"));
    auto expected = hex_to_bytes<64>(
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64"
        "2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
    assert(h == expected);
}

// ============================================================
// Reinit / reuse state
// ============================================================

void test_state_reuse() {
    sha256_state s;

    s.init();
    s.update(str_span("abc"));
    auto h1 = s.finalize();

    // Re-init and hash something different
    s.init();
    s.update(str_span("def"));
    auto h2 = s.finalize();

    assert(h1 != h2);
    assert(h1 == sha256(str_span("abc")));
    assert(h2 == sha256(str_span("def")));
}

// ============================================================
// Large message (multi-block)
// ============================================================

void test_sha256_large_message() {
    // Hash 1000 bytes of 0x61 ('a')
    std::vector<uint8_t> data(1000, 0x61);
    auto single = sha256(data);

    // Verify streaming gives same result
    sha256_state s;
    s.init();
    s.update(data);
    assert(s.finalize() == single);

    // Verify with different chunking
    sha256_state s2;
    s2.init();
    for (size_t i = 0; i < 1000; i += 64) {
        size_t len = std::min<size_t>(64, 1000 - i);
        s2.update(std::span<const uint8_t>(data.data() + i, len));
    }
    assert(s2.finalize() == single);
}

// ============================================================
// Digest size and block size constants
// ============================================================

void test_constants() {
    static_assert(sha224_state::digest_size == 28);
    static_assert(sha224_state::block_size == 64);
    static_assert(sha256_state::digest_size == 32);
    static_assert(sha256_state::block_size == 64);
    static_assert(sha384_state::digest_size == 48);
    static_assert(sha384_state::block_size == 128);
    static_assert(sha512_state::digest_size == 64);
    static_assert(sha512_state::block_size == 128);
    static_assert(sha512_224_state::digest_size == 28);
    static_assert(sha512_224_state::block_size == 128);
    static_assert(sha512_256_state::digest_size == 32);
    static_assert(sha512_256_state::block_size == 128);
}

// ============================================================
// Constexpr evaluation
// ============================================================

void test_constexpr_sha256() {
    // Verify SHA-256 of "abc" at compile time
    constexpr auto h = [] {
        std::array<uint8_t, 3> msg = {'a', 'b', 'c'};
        return sha256(msg);
    }();
    constexpr auto expected = hex_to_bytes<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    static_assert(h == expected);
}

void test_constexpr_sha512() {
    constexpr auto h = [] {
        std::array<uint8_t, 3> msg = {'a', 'b', 'c'};
        return sha512(msg);
    }();
    constexpr auto expected = hex_to_bytes<64>(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    static_assert(h == expected);
}

void test_constexpr_sha384() {
    constexpr auto h = [] {
        std::array<uint8_t, 3> msg = {'a', 'b', 'c'};
        return sha384(msg);
    }();
    constexpr auto expected = hex_to_bytes<48>(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7");
    static_assert(h == expected);
}

void test_constexpr_empty() {
    constexpr auto h = sha256(std::span<const uint8_t>{});
    constexpr auto expected = hex_to_bytes<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    static_assert(h == expected);
}

// ============================================================
// Cross-variant: same message, different algorithms must differ
// ============================================================

void test_all_variants_differ() {
    auto msg = str_span("test");
    auto h224 = sha224(msg);
    auto h256 = sha256(msg);
    auto h384 = sha384(msg);
    auto h512 = sha512(msg);
    auto h512_224 = sha512_224(msg);
    auto h512_256 = sha512_256(msg);

    // SHA-224 and SHA-512/224 have same digest size but must differ
    assert(h224 != h512_224);

    // SHA-256 and SHA-512/256 have same digest size but must differ
    assert(h256 != h512_256);

    // All 48-byte+ digests differ (compare first 28 bytes of different-sized digests would be meaningless,
    // so just verify the same-size pairs differ)
    // SHA-224 vs SHA-512/224 already checked
    // SHA-256 vs SHA-512/256 already checked

    // Verify none are all-zero
    auto is_zero = [](auto& arr) {
        for (auto b : arr) if (b != 0) return false;
        return true;
    };
    assert(!is_zero(h224));
    assert(!is_zero(h256));
    assert(!is_zero(h384));
    assert(!is_zero(h512));
    assert(!is_zero(h512_224));
    assert(!is_zero(h512_256));
}

// ============================================================
// Zero-length update should be a no-op
// ============================================================

void test_empty_update() {
    sha256_state s;
    s.init();
    s.update(std::span<const uint8_t>{});
    s.update(str_span("abc"));
    s.update(std::span<const uint8_t>{});
    auto h = s.finalize();
    assert(h == sha256(str_span("abc")));
}

// ============================================================
// H0 and K constants (FIPS 180-4 spot checks, beyond static_asserts in sha2.hpp)
// ============================================================

void test_fips_constants() {
    // SHA-256 first round constant = cube root of 2 fractional
    assert(sha2_K<256>[0] == 0x428A2F98U);
    // SHA-256 last round constant
    assert(sha2_K<256>[63] == 0xC67178F2U);

    // SHA-512 first round constant
    assert(sha2_K<512>[0] == 0x428A2F98D728AE22ULL);
    // SHA-512 last round constant
    assert(sha2_K<512>[79] == 0x6C44198C4A475817ULL);

    // SHA-256 initial hash value H0[0] = fractional part of sqrt(2)
    assert(sha2_H0<256>[0] == 0x6A09E667U);
}

int main() {
    // SHA-256 NIST vectors
    test_sha256_empty();
    test_sha256_abc();
    test_sha256_two_block();

    // SHA-224 NIST vectors
    test_sha224_empty();
    test_sha224_abc();
    test_sha224_two_block();

    // SHA-512 NIST vectors
    test_sha512_empty();
    test_sha512_abc();
    test_sha512_two_block();

    // SHA-384 NIST vectors
    test_sha384_empty();
    test_sha384_abc();
    test_sha384_two_block();

    // SHA-512/224 NIST vectors
    test_sha512_224_empty();
    test_sha512_224_abc();

    // SHA-512/256 NIST vectors
    test_sha512_256_empty();
    test_sha512_256_abc();

    // Streaming / multi-update
    test_sha256_streaming_equivalence();
    test_sha512_streaming_equivalence();
    test_sha256_chunked_updates();
    test_sha384_chunked_updates();

    // Block boundaries
    test_sha256_exactly_one_block();
    test_sha256_block_minus_one();
    test_sha256_55_bytes();
    test_sha256_56_bytes();
    test_sha512_block_boundaries();

    // Single byte
    test_sha256_single_byte();
    test_sha256_single_byte_ff();

    // Known vectors
    test_sha256_quick_brown_fox();
    test_sha512_quick_brown_fox();

    // State reuse
    test_state_reuse();

    // Large message
    test_sha256_large_message();

    // Constants
    test_constants();

    // Constexpr
    test_constexpr_sha256();
    test_constexpr_sha512();
    test_constexpr_sha384();
    test_constexpr_empty();

    // Cross-variant
    test_all_variants_differ();

    // Empty update
    test_empty_update();

    // FIPS constants
    test_fips_constants();

    return 0;
}
