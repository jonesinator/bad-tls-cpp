/**
 * FIPS 197 AES block cipher: AES-128, AES-192, AES-256.
 *
 * Single template parameterized on <KeyBits>:
 *   aes_state<128> = AES-128 (10 rounds)
 *   aes_state<192> = AES-192 (12 rounds)
 *   aes_state<256> = AES-256 (14 rounds)
 *
 * Fully constexpr — can be used at compile time.
 */

#ifndef AES_HPP_
#define AES_HPP_

#include <array>
#include <cstdint>
#include <span>

namespace aes_detail {

// --- GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x + 1 ---

consteval uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        bool hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B; // reduce mod x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return result;
}

consteval uint8_t gf_pow(uint8_t base, uint8_t exp) {
    uint8_t result = 1;
    for (uint8_t e = exp; e > 0; e >>= 1) {
        if (e & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
    }
    return result;
}

consteval uint8_t gf_inv(uint8_t x) {
    if (x == 0) return 0;
    return gf_pow(x, 254); // x^254 = x^{-1} since x^255 = 1
}

// Affine transform: rotate bits of b and XOR with 0x63
consteval uint8_t affine(uint8_t b) {
    uint8_t result = 0x63;
    for (int i = 0; i < 8; ++i) {
        uint8_t bit = ((b >> i) ^ (b >> ((i + 4) % 8)) ^ (b >> ((i + 5) % 8))
                     ^ (b >> ((i + 6) % 8)) ^ (b >> ((i + 7) % 8))) & 1;
        result ^= bit << i;
    }
    return result;
}

// Inverse affine transform
consteval uint8_t inv_affine(uint8_t b) {
    uint8_t result = 0x05;
    for (int i = 0; i < 8; ++i) {
        uint8_t bit = ((b >> ((i + 2) % 8)) ^ (b >> ((i + 5) % 8))
                     ^ (b >> ((i + 7) % 8))) & 1;
        result ^= bit << i;
    }
    return result;
}

// --- Table generation ---

consteval std::array<uint8_t, 256> make_sbox() {
    std::array<uint8_t, 256> s{};
    for (int i = 0; i < 256; ++i)
        s[i] = affine(gf_inv(static_cast<uint8_t>(i)));
    return s;
}

consteval std::array<uint8_t, 256> make_inv_sbox() {
    std::array<uint8_t, 256> s{};
    for (int i = 0; i < 256; ++i)
        s[i] = gf_inv(inv_affine(static_cast<uint8_t>(i)));
    return s;
}

consteval std::array<uint8_t, 11> make_rcon() {
    std::array<uint8_t, 11> rc{};
    rc[0] = 0;
    rc[1] = 1;
    for (int i = 2; i <= 10; ++i)
        rc[i] = gf_mul(rc[i - 1], 2);
    return rc;
}

// --- Core traits ---

template <size_t KeyBits> struct core;

template <> struct core<128> {
    static constexpr size_t Nk = 4;
    static constexpr size_t Nr = 10;
};

template <> struct core<192> {
    static constexpr size_t Nk = 6;
    static constexpr size_t Nr = 12;
};

template <> struct core<256> {
    static constexpr size_t Nk = 8;
    static constexpr size_t Nr = 14;
};

// --- Key expansion (FIPS 197 Section 5.2) ---

template <size_t KeyBits>
constexpr std::array<uint8_t, 16 * (core<KeyBits>::Nr + 1)> expand_key(
    const uint8_t* key,
    const std::array<uint8_t, 256>& sbox,
    const std::array<uint8_t, 11>& rcon) noexcept
{
    constexpr size_t Nk = core<KeyBits>::Nk;
    constexpr size_t Nr = core<KeyBits>::Nr;
    constexpr size_t total_bytes = 16 * (Nr + 1);

    std::array<uint8_t, total_bytes> w{};

    // Copy key into first Nk words
    for (size_t i = 0; i < Nk * 4; ++i)
        w[i] = key[i];

    for (size_t i = Nk; i < 4 * (Nr + 1); ++i) {
        uint8_t temp[4];
        temp[0] = w[(i - 1) * 4 + 0];
        temp[1] = w[(i - 1) * 4 + 1];
        temp[2] = w[(i - 1) * 4 + 2];
        temp[3] = w[(i - 1) * 4 + 3];

        if (i % Nk == 0) {
            // RotWord + SubWord + Rcon
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[i / Nk];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        } else if (Nk > 6 && i % Nk == 4) {
            // SubWord only (AES-256 extra)
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        w[i * 4 + 0] = w[(i - Nk) * 4 + 0] ^ temp[0];
        w[i * 4 + 1] = w[(i - Nk) * 4 + 1] ^ temp[1];
        w[i * 4 + 2] = w[(i - Nk) * 4 + 2] ^ temp[2];
        w[i * 4 + 3] = w[(i - Nk) * 4 + 3] ^ temp[3];
    }

    return w;
}

// --- Round operations ---
// State layout: column-major, state[row + 4*col]

constexpr void sub_bytes(std::array<uint8_t, 16>& s,
                         const std::array<uint8_t, 256>& sbox) noexcept {
    for (auto& b : s) b = sbox[b];
}

constexpr void inv_sub_bytes(std::array<uint8_t, 16>& s,
                             const std::array<uint8_t, 256>& inv_sbox) noexcept {
    for (auto& b : s) b = inv_sbox[b];
}

constexpr void shift_rows(std::array<uint8_t, 16>& s) noexcept {
    // Row 1: shift left 1
    uint8_t t = s[1];
    s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    // Row 2: shift left 2
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    // Row 3: shift left 3 (= shift right 1)
    t = s[15];
    s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

constexpr void inv_shift_rows(std::array<uint8_t, 16>& s) noexcept {
    // Row 1: shift right 1
    uint8_t t = s[13];
    s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    // Row 2: shift right 2
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    // Row 3: shift right 3 (= shift left 1)
    t = s[3];
    s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

constexpr uint8_t xtime(uint8_t a) noexcept {
    return static_cast<uint8_t>((a << 1) ^ ((a >> 7) * 0x1B));
}

constexpr void mix_columns(std::array<uint8_t, 16>& s) noexcept {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        s[i]   = a0 ^ xtime(a0 ^ a1) ^ t;
        s[i+1] = a1 ^ xtime(a1 ^ a2) ^ t;
        s[i+2] = a2 ^ xtime(a2 ^ a3) ^ t;
        s[i+3] = a3 ^ xtime(a3 ^ a0) ^ t;
    }
}

constexpr void inv_mix_columns(std::array<uint8_t, 16>& s) noexcept {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
        // Compute multiplications by 9, 11, 13, 14 via xtime chains
        uint8_t x2_0 = xtime(a0), x2_1 = xtime(a1), x2_2 = xtime(a2), x2_3 = xtime(a3);
        uint8_t x4_0 = xtime(x2_0), x4_1 = xtime(x2_1), x4_2 = xtime(x2_2), x4_3 = xtime(x2_3);
        uint8_t x8_0 = xtime(x4_0), x8_1 = xtime(x4_1), x8_2 = xtime(x4_2), x8_3 = xtime(x4_3);
        // 14 = 8+4+2, 11 = 8+2+1, 13 = 8+4+1, 9 = 8+1
        s[i]   = (x8_0^x4_0^x2_0) ^ (x8_1^x2_1^a1)   ^ (x8_2^x4_2^a2)   ^ (x8_3^a3);
        s[i+1] = (x8_0^a0)         ^ (x8_1^x4_1^x2_1) ^ (x8_2^x2_2^a2)   ^ (x8_3^x4_3^a3);
        s[i+2] = (x8_0^x4_0^a0)   ^ (x8_1^a1)         ^ (x8_2^x4_2^x2_2) ^ (x8_3^x2_3^a3);
        s[i+3] = (x8_0^x2_0^a0)   ^ (x8_1^x4_1^a1)   ^ (x8_2^a2)         ^ (x8_3^x4_3^x2_3);
    }
}

constexpr void add_round_key(std::array<uint8_t, 16>& s,
                             const uint8_t* rk) noexcept {
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
}

} // namespace aes_detail

// --- Global constants ---

inline constexpr auto aes_sbox = aes_detail::make_sbox();
inline constexpr auto aes_inv_sbox = aes_detail::make_inv_sbox();
inline constexpr auto aes_rcon = aes_detail::make_rcon();

// Verify against FIPS 197
static_assert(aes_sbox[0x00] == 0x63);
static_assert(aes_sbox[0x01] == 0x7C);
static_assert(aes_sbox[0x53] == 0xED);
static_assert(aes_sbox[0xFF] == 0x16);
static_assert(aes_inv_sbox[0x63] == 0x00);
static_assert(aes_inv_sbox[0x7C] == 0x01);
static_assert(aes_inv_sbox[0x16] == 0xFF);
static_assert(aes_rcon[1] == 0x01);
static_assert(aes_rcon[10] == 0x36);

// --- aes_state template ---

template <size_t KeyBits>
struct aes_state {
    static_assert(KeyBits == 128 || KeyBits == 192 || KeyBits == 256,
                  "AES key size must be 128, 192, or 256 bits");

    using C = aes_detail::core<KeyBits>;

    static constexpr size_t key_size = KeyBits / 8;
    static constexpr size_t block_size = 16;
    static constexpr size_t rounds = C::Nr;

    std::array<uint8_t, 16 * (C::Nr + 1)> round_keys{};

    constexpr void init(std::span<const uint8_t, key_size> key) noexcept {
        round_keys = aes_detail::expand_key<KeyBits>(key.data(), aes_sbox, aes_rcon);
    }

    constexpr std::array<uint8_t, 16> encrypt_block(
        std::span<const uint8_t, 16> plaintext) const noexcept
    {
        std::array<uint8_t, 16> s{};
        for (int i = 0; i < 16; ++i) s[i] = plaintext[i];

        aes_detail::add_round_key(s, round_keys.data());

        for (size_t r = 1; r < C::Nr; ++r) {
            aes_detail::sub_bytes(s, aes_sbox);
            aes_detail::shift_rows(s);
            aes_detail::mix_columns(s);
            aes_detail::add_round_key(s, round_keys.data() + r * 16);
        }

        aes_detail::sub_bytes(s, aes_sbox);
        aes_detail::shift_rows(s);
        aes_detail::add_round_key(s, round_keys.data() + C::Nr * 16);

        return s;
    }

    constexpr std::array<uint8_t, 16> decrypt_block(
        std::span<const uint8_t, 16> ciphertext) const noexcept
    {
        std::array<uint8_t, 16> s{};
        for (int i = 0; i < 16; ++i) s[i] = ciphertext[i];

        aes_detail::add_round_key(s, round_keys.data() + C::Nr * 16);

        for (size_t r = C::Nr - 1; r >= 1; --r) {
            aes_detail::inv_shift_rows(s);
            aes_detail::inv_sub_bytes(s, aes_inv_sbox);
            aes_detail::add_round_key(s, round_keys.data() + r * 16);
            aes_detail::inv_mix_columns(s);
        }

        aes_detail::inv_shift_rows(s);
        aes_detail::inv_sub_bytes(s, aes_inv_sbox);
        aes_detail::add_round_key(s, round_keys.data());

        return s;
    }
};

// --- Type aliases ---

using aes128 = aes_state<128>;
using aes192 = aes_state<192>;
using aes256 = aes_state<256>;

// --- Convenience one-shot functions ---

template <size_t KeyBits>
constexpr std::array<uint8_t, 16> aes_encrypt(
    std::span<const uint8_t, KeyBits / 8> key,
    std::span<const uint8_t, 16> plaintext) noexcept
{
    aes_state<KeyBits> s;
    s.init(key);
    return s.encrypt_block(plaintext);
}

template <size_t KeyBits>
constexpr std::array<uint8_t, 16> aes_decrypt(
    std::span<const uint8_t, KeyBits / 8> key,
    std::span<const uint8_t, 16> ciphertext) noexcept
{
    aes_state<KeyBits> s;
    s.init(key);
    return s.decrypt_block(ciphertext);
}

#endif /* AES_HPP_ */
