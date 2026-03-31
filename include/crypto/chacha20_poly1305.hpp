/**
 * ChaCha20-Poly1305 AEAD — RFC 7539 Section 2.8.
 *
 * Authenticated encryption with associated data combining ChaCha20
 * for encryption and Poly1305 for authentication.
 *
 * Fully constexpr.
 */

#ifndef CHACHA20_POLY1305_HPP_
#define CHACHA20_POLY1305_HPP_

#include "chacha20.hpp"
#include "poly1305.hpp"
#include <array>
#include <cstdint>
#include <span>

namespace chacha20_poly1305_detail {

constexpr bool constant_time_equal(
    const std::array<uint8_t, 16>& a,
    const std::array<uint8_t, 16>& b) noexcept
{
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

// Build the Poly1305 input per RFC 7539 Section 2.8:
//   pad16(aad) || pad16(ciphertext) || le64(aad_len) || le64(ct_len)
// Feed it to a poly1305_state.
constexpr void poly1305_construct_input(
    poly1305_state& mac,
    std::span<const uint8_t> aad,
    std::span<const uint8_t> ciphertext) noexcept
{
    // AAD
    mac.update(aad);
    // Pad AAD to 16-byte boundary
    size_t aad_pad = (16 - (aad.size() % 16)) % 16;
    if (aad_pad > 0) {
        uint8_t zeros[16]{};
        mac.update(std::span<const uint8_t>(zeros, aad_pad));
    }

    // Ciphertext
    mac.update(ciphertext);
    // Pad ciphertext to 16-byte boundary
    size_t ct_pad = (16 - (ciphertext.size() % 16)) % 16;
    if (ct_pad > 0) {
        uint8_t zeros[16]{};
        mac.update(std::span<const uint8_t>(zeros, ct_pad));
    }

    // Lengths as little-endian 64-bit
    uint8_t lengths[16]{};
    uint64_t aad_len = aad.size();
    uint64_t ct_len = ciphertext.size();
    for (int i = 0; i < 8; ++i) {
        lengths[i]     = static_cast<uint8_t>(aad_len >> (i * 8));
        lengths[8 + i] = static_cast<uint8_t>(ct_len >> (i * 8));
    }
    mac.update(std::span<const uint8_t>(lengths, 16));
}

} // namespace chacha20_poly1305_detail

/**
 * Encrypt with ChaCha20-Poly1305 AEAD.
 *
 * @param key            256-bit key (32 bytes).
 * @param nonce          96-bit nonce (12 bytes).
 * @param plaintext      Data to encrypt.
 * @param aad            Additional authenticated data.
 * @param ciphertext_out Output buffer for ciphertext (same size as plaintext).
 *
 * @returns 16-byte authentication tag.
 */
constexpr std::array<uint8_t, 16> chacha20_poly1305_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    std::span<uint8_t> ciphertext_out) noexcept
{
    // 1. Generate Poly1305 one-time key: ChaCha20 block 0, first 32 bytes
    auto otk_block = chacha20_block(key, nonce, 0);
    std::array<uint8_t, 32> otk{};
    for (int i = 0; i < 32; ++i) otk[i] = otk_block[i];

    // 2. Encrypt plaintext with ChaCha20 starting at counter=1
    chacha20_encrypt(key, nonce, 1, plaintext, ciphertext_out);

    // 3. Compute Poly1305 tag over aad + ciphertext + lengths
    poly1305_state mac;
    mac.init(otk);
    chacha20_poly1305_detail::poly1305_construct_input(
        mac, aad, std::span<const uint8_t>(ciphertext_out.data(), plaintext.size()));

    return mac.finalize();
}

/**
 * Decrypt with ChaCha20-Poly1305 AEAD.
 *
 * @param key           256-bit key (32 bytes).
 * @param nonce         96-bit nonce (12 bytes).
 * @param ciphertext    Encrypted data.
 * @param aad           Additional authenticated data.
 * @param tag           16-byte authentication tag to verify.
 * @param plaintext_out Output buffer for plaintext (same size as ciphertext).
 *
 * @returns true if tag is valid and decryption succeeded, false otherwise.
 */
constexpr bool chacha20_poly1305_decrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, 16> tag,
    std::span<uint8_t> plaintext_out) noexcept
{
    // 1. Generate Poly1305 one-time key
    auto otk_block = chacha20_block(key, nonce, 0);
    std::array<uint8_t, 32> otk{};
    for (int i = 0; i < 32; ++i) otk[i] = otk_block[i];

    // 2. Verify tag before decrypting
    poly1305_state mac;
    mac.init(otk);
    chacha20_poly1305_detail::poly1305_construct_input(mac, aad, ciphertext);
    auto computed_tag = mac.finalize();

    std::array<uint8_t, 16> expected_tag{};
    for (int i = 0; i < 16; ++i) expected_tag[i] = tag[i];

    if (!chacha20_poly1305_detail::constant_time_equal(computed_tag, expected_tag))
        return false;

    // 3. Decrypt with ChaCha20 starting at counter=1
    chacha20_encrypt(key, nonce, 1, ciphertext, plaintext_out);
    return true;
}

#endif /* CHACHA20_POLY1305_HPP_ */
