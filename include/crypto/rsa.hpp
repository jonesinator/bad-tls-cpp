/**
 * RSA-PSS (RSASSA-PSS) signature signing and verification per RFC 8017.
 *
 * Uses MGF1 mask generation (RFC 8017 Section B.2.1). Salt is caller-supplied.
 * For deterministic signing in constexpr contexts, derive salt from HMAC(key, message).
 *
 * TNum must be a number<> type with at least double the modulus bit width
 * to avoid overflow in pow_mod intermediate products:
 *   RSA-2048: TNum = number<uint32_t, 128>  (4096-bit backing)
 *   RSA-4096: TNum = number<uint32_t, 256>  (8192-bit backing)
 *
 * Fully constexpr — can be used at compile time.
 */

#ifndef RSA_HPP_
#define RSA_HPP_

#include <number/number.hpp>
#include "hash_concept.hpp"
#include <array>
#include <cstdint>
#include <span>

// --- Key and signature types ---

template <typename TNum>
struct rsa_public_key {
    TNum n;  // modulus
    TNum e;  // public exponent (typically 65537)
};

template <typename TNum>
struct rsa_private_key {
    TNum n;  // modulus
    TNum d;  // private exponent
};

template <typename TNum>
struct rsa_signature {
    TNum value;
};

namespace rsa_detail {

// --- MGF1 (RFC 8017 Section B.2.1) ---

template <hash_function THash, size_t MaxLen>
constexpr std::array<uint8_t, MaxLen> mgf1(
    std::span<const uint8_t> seed, size_t mask_len) noexcept
{
    constexpr size_t hLen = THash::digest_size;
    std::array<uint8_t, MaxLen> output{};
    size_t offset = 0;

    for (uint32_t counter = 0; offset < mask_len; ++counter) {
        THash h;
        h.init();
        h.update(seed);
        // I2OSP(counter, 4) — 4-byte big-endian counter
        std::array<uint8_t, 4> c_bytes = {
            static_cast<uint8_t>(counter >> 24),
            static_cast<uint8_t>(counter >> 16),
            static_cast<uint8_t>(counter >> 8),
            static_cast<uint8_t>(counter)
        };
        h.update(c_bytes);
        auto digest = h.finalize();

        for (size_t j = 0; j < hLen && offset < mask_len; ++j)
            output[offset++] = digest[j];
    }
    return output;
}

// --- EMSA-PSS-ENCODE (RFC 8017 Section 9.1.1) ---

template <hash_function THash, size_t BufLen>
constexpr std::array<uint8_t, BufLen> emsa_pss_encode(
    const std::array<uint8_t, THash::digest_size>& mHash,
    std::span<const uint8_t> salt,
    size_t emBits) noexcept
{
    constexpr size_t hLen = THash::digest_size;
    size_t emLen = (emBits + 7) / 8;
    size_t sLen = salt.size();
    size_t dbLen = emLen - hLen - 1;

    // M' = 0x00(x8) || mHash || salt
    THash h;
    h.init();
    std::array<uint8_t, 8> padding{};
    h.update(padding);
    h.update(mHash);
    h.update(salt);
    auto H = h.finalize();

    // DB = PS(zeros) || 0x01 || salt
    // PS length = emLen - sLen - hLen - 2
    std::array<uint8_t, BufLen> db{};
    size_t ps_len = emLen - sLen - hLen - 2;
    // db[0..ps_len-1] are already zero
    db[ps_len] = 0x01;
    for (size_t i = 0; i < sLen; ++i)
        db[ps_len + 1 + i] = salt[i];

    // dbMask = MGF1(H, dbLen)
    auto dbMask = mgf1<THash, BufLen>(H, dbLen);

    // maskedDB = DB XOR dbMask
    for (size_t i = 0; i < dbLen; ++i)
        db[i] ^= dbMask[i];

    // Zero top 8*emLen - emBits bits
    size_t top_bits = 8 * emLen - emBits;
    if (top_bits > 0)
        db[0] &= static_cast<uint8_t>(0xFF >> top_bits);

    // EM = maskedDB || H || 0xBC
    // Place into output buffer right-aligned at position BufLen - emLen
    std::array<uint8_t, BufLen> em{};
    size_t base = BufLen - emLen;
    for (size_t i = 0; i < dbLen; ++i)
        em[base + i] = db[i];
    for (size_t i = 0; i < hLen; ++i)
        em[base + dbLen + i] = H[i];
    em[base + emLen - 1] = 0xBC;

    return em;
}

// --- EMSA-PSS-VERIFY (RFC 8017 Section 9.1.2) ---

template <hash_function THash>
constexpr bool emsa_pss_verify(
    const std::array<uint8_t, THash::digest_size>& mHash,
    std::span<const uint8_t> em,
    size_t emBits,
    size_t sLen) noexcept
{
    constexpr size_t hLen = THash::digest_size;
    size_t emLen = (emBits + 7) / 8;

    if (em.size() < emLen)
        return false;

    // Work with the last emLen bytes of em
    auto emBase = em.size() - emLen;

    if (emLen < hLen + sLen + 2)
        return false;

    if (em[emBase + emLen - 1] != 0xBC)
        return false;

    size_t dbLen = emLen - hLen - 1;

    // Check top bits of maskedDB are zero
    size_t top_bits = 8 * emLen - emBits;
    if (top_bits > 0) {
        uint8_t top_mask = static_cast<uint8_t>(0xFF << (8 - top_bits));
        if (em[emBase] & top_mask)
            return false;
    }

    // Extract H
    std::array<uint8_t, hLen> H{};
    for (size_t i = 0; i < hLen; ++i)
        H[i] = em[emBase + dbLen + i];

    // dbMask = MGF1(H, dbLen)
    // Use a fixed max buffer — dbLen <= emLen <= some reasonable bound
    // We'll use a large enough static array
    constexpr size_t MaxDB = 512;  // supports up to RSA-4096
    auto dbMask = mgf1<THash, MaxDB>(H, dbLen);

    // DB = maskedDB XOR dbMask
    std::array<uint8_t, MaxDB> DB{};
    for (size_t i = 0; i < dbLen; ++i)
        DB[i] = em[emBase + i] ^ dbMask[i];

    // Zero top bits
    if (top_bits > 0)
        DB[0] &= static_cast<uint8_t>(0xFF >> top_bits);

    // Check PS || 0x01 structure
    size_t ps_len = emLen - hLen - sLen - 2;
    for (size_t i = 0; i < ps_len; ++i)
        if (DB[i] != 0x00) return false;
    if (DB[ps_len] != 0x01)
        return false;

    // Extract salt from DB
    // salt = DB[ps_len+1 .. ps_len+sLen]

    // M' = 0x00(x8) || mHash || salt
    THash h;
    h.init();
    std::array<uint8_t, 8> padding{};
    h.update(padding);
    h.update(mHash);
    h.update(std::span<const uint8_t>(DB.data() + ps_len + 1, sLen));
    auto H_prime = h.finalize();

    // Compare H and H'
    for (size_t i = 0; i < hLen; ++i)
        if (H[i] != H_prime[i]) return false;

    return true;
}

// --- PKCS#1 v1.5 DigestInfo DER prefixes (RFC 8017 Section 9.2 Note 1) ---

// SHA-256: SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING(32) }
inline constexpr std::array<uint8_t, 19> pkcs1_digestinfo_sha256 = {
    0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,
    0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};

// SHA-384: SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.2, NULL }, OCTET STRING(48) }
inline constexpr std::array<uint8_t, 19> pkcs1_digestinfo_sha384 = {
    0x30,0x41,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,
    0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30
};

// SHA-512: SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.3, NULL }, OCTET STRING(64) }
inline constexpr std::array<uint8_t, 19> pkcs1_digestinfo_sha512 = {
    0x30,0x51,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,
    0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40
};

// Select DigestInfo prefix based on hash digest size
template <hash_function THash>
constexpr std::span<const uint8_t> digestinfo_prefix() noexcept {
    if constexpr (THash::digest_size == 32) return pkcs1_digestinfo_sha256;
    else if constexpr (THash::digest_size == 48) return pkcs1_digestinfo_sha384;
    else if constexpr (THash::digest_size == 64) return pkcs1_digestinfo_sha512;
}

// --- EMSA-PKCS1-v1_5 verification (RFC 8017 Section 9.2) ---

template <hash_function THash>
constexpr bool emsa_pkcs1_v1_5_verify(
    const std::array<uint8_t, THash::digest_size>& mHash,
    std::span<const uint8_t> em,
    size_t emLen) noexcept
{
    constexpr size_t hLen = THash::digest_size;
    auto prefix = digestinfo_prefix<THash>();
    size_t tLen = prefix.size() + hLen;  // DigestInfo prefix + hash

    if (emLen < tLen + 11)
        return false;

    // Work with the last emLen bytes (for double-width number types)
    size_t base = em.size() - emLen;

    // Check 0x00 0x01
    if (em[base] != 0x00 || em[base + 1] != 0x01)
        return false;

    // Check PS (0xFF padding), must be at least 8 bytes
    size_t ps_len = emLen - tLen - 3;
    if (ps_len < 8)
        return false;
    for (size_t i = 0; i < ps_len; ++i)
        if (em[base + 2 + i] != 0xFF) return false;

    // Check 0x00 separator
    if (em[base + 2 + ps_len] != 0x00)
        return false;

    // Check DigestInfo prefix
    size_t di_start = base + 3 + ps_len;
    for (size_t i = 0; i < prefix.size(); ++i)
        if (em[di_start + i] != prefix[i]) return false;

    // Check hash
    size_t hash_start = di_start + prefix.size();
    for (size_t i = 0; i < hLen; ++i)
        if (em[hash_start + i] != mHash[i]) return false;

    return true;
}

} // namespace rsa_detail

// --- RSASSA-PSS-SIGN (RFC 8017 Section 8.1.1) ---

template <typename TNum, hash_function THash>
constexpr rsa_signature<TNum> rsa_pss_sign(
    const rsa_private_key<TNum>& key,
    const std::array<uint8_t, THash::digest_size>& message_hash,
    std::span<const uint8_t> salt) noexcept
{
    size_t modBits = key.n.bit_width();
    size_t emBits = modBits - 1;

    auto em = rsa_detail::emsa_pss_encode<THash, TNum::num_bytes>(
        message_hash, salt, emBits);

    TNum m = TNum::from_bytes(em, std::endian::big);
    TNum s = m.pow_mod(key.d, key.n);

    return {s};
}

// --- RSASSA-PSS-VERIFY (RFC 8017 Section 8.1.2) ---

template <typename TNum, hash_function THash>
constexpr bool rsa_pss_verify(
    const rsa_public_key<TNum>& key,
    const std::array<uint8_t, THash::digest_size>& message_hash,
    const rsa_signature<TNum>& sig) noexcept
{
    // Check signature range
    if (sig.value >= key.n)
        return false;

    // RSAVP1: m = s^e mod n
    TNum m = sig.value.pow_mod(key.e, key.n);

    // I2OSP: convert to byte string
    auto em_bytes = m.to_bytes(std::endian::big);

    size_t modBits = key.n.bit_width();
    size_t emBits = modBits - 1;
    size_t sLen = THash::digest_size;  // TLS 1.2 convention: sLen == hLen

    return rsa_detail::emsa_pss_verify<THash>(
        message_hash,
        std::span<const uint8_t>(em_bytes),
        emBits, sLen);
}

// --- RSASSA-PKCS1-v1_5 SIGN (RFC 8017 Section 8.2.1) ---

// GCC -O2 emits a false-positive stringop-overflow when TNum::num_bytes is much larger
// than the actual modulus size (e.g. 1024-byte backing for RSA-2048's 256-byte modulus).
// The runtime indexing is safe because 'base' is always >= 0 and (base + k) == num_bytes.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"

template <typename TNum, hash_function THash>
constexpr rsa_signature<TNum> rsa_pkcs1_v1_5_sign(
    const rsa_private_key<TNum>& key,
    const std::array<uint8_t, THash::digest_size>& message_hash) noexcept
{
    constexpr size_t hLen = THash::digest_size;
    auto prefix = rsa_detail::digestinfo_prefix<THash>();
    size_t k = (key.n.bit_width() + 7) / 8;
    size_t tLen = prefix.size() + hLen;

    // Build EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
    std::array<uint8_t, TNum::num_bytes> em{};
    size_t base = TNum::num_bytes - k;
    em[base] = 0x00;
    em[base + 1] = 0x01;
    size_t ps_len = k - tLen - 3;
    for (size_t i = 0; i < ps_len; ++i)
        em[base + 2 + i] = 0xFF;
    em[base + 2 + ps_len] = 0x00;
    for (size_t i = 0; i < prefix.size(); ++i)
        em[base + 3 + ps_len + i] = prefix[i];
    for (size_t i = 0; i < hLen; ++i)
        em[base + 3 + ps_len + prefix.size() + i] = message_hash[i];

    TNum m = TNum::from_bytes(em, std::endian::big);
    TNum s = m.pow_mod(key.d, key.n);

    return {s};
}

#pragma GCC diagnostic pop

// --- RSASSA-PKCS1-v1_5 VERIFY (RFC 8017 Section 8.2.2) ---

template <typename TNum, hash_function THash>
constexpr bool rsa_pkcs1_v1_5_verify(
    const rsa_public_key<TNum>& key,
    const std::array<uint8_t, THash::digest_size>& message_hash,
    const rsa_signature<TNum>& sig) noexcept
{
    if (sig.value >= key.n)
        return false;

    TNum m = sig.value.pow_mod(key.e, key.n);
    auto em_bytes = m.to_bytes(std::endian::big);

    size_t k = (key.n.bit_width() + 7) / 8;

    return rsa_detail::emsa_pkcs1_v1_5_verify<THash>(
        message_hash,
        std::span<const uint8_t>(em_bytes),
        k);
}

// --- PKCS1 v1.5 message convenience wrappers ---

template <typename TNum, hash_function THash>
constexpr rsa_signature<TNum> rsa_pkcs1_v1_5_sign_message(
    const rsa_private_key<TNum>& key,
    std::span<const uint8_t> message) noexcept
{
    THash h;
    h.init();
    h.update(message);
    auto hash = h.finalize();
    return rsa_pkcs1_v1_5_sign<TNum, THash>(key, hash);
}

template <typename TNum, hash_function THash>
constexpr bool rsa_pkcs1_v1_5_verify_message(
    const rsa_public_key<TNum>& key,
    std::span<const uint8_t> message,
    const rsa_signature<TNum>& sig) noexcept
{
    THash h;
    h.init();
    h.update(message);
    auto hash = h.finalize();
    return rsa_pkcs1_v1_5_verify<TNum, THash>(key, hash, sig);
}

// --- PSS message convenience wrappers ---

template <typename TNum, hash_function THash>
constexpr rsa_signature<TNum> rsa_pss_sign_message(
    const rsa_private_key<TNum>& key,
    std::span<const uint8_t> message,
    std::span<const uint8_t> salt) noexcept
{
    THash h;
    h.init();
    h.update(message);
    auto hash = h.finalize();
    return rsa_pss_sign<TNum, THash>(key, hash, salt);
}

template <typename TNum, hash_function THash>
constexpr bool rsa_pss_verify_message(
    const rsa_public_key<TNum>& key,
    std::span<const uint8_t> message,
    const rsa_signature<TNum>& sig) noexcept
{
    THash h;
    h.init();
    h.update(message);
    auto hash = h.finalize();
    return rsa_pss_verify<TNum, THash>(key, hash, sig);
}

#endif /* RSA_HPP_ */
