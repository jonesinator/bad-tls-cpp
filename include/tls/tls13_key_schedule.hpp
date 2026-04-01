/**
 * TLS 1.3 key schedule — RFC 8446 Section 7.1.
 *
 * HKDF-based key derivation replacing the TLS 1.2 PRF.
 * Provides HKDF-Expand-Label, Derive-Secret, traffic key extraction,
 * and a staged key schedule struct mirroring the RFC derivation chain.
 *
 * Fully constexpr.
 */

#pragma once

#include <crypto/hkdf.hpp>
#include <crypto/hmac.hpp>
#include <crypto/hash_concept.hpp>
#include <array>
#include <cstdint>
#include <span>

namespace tls {

// ---- Traffic key material for a single direction ----
// TLS 1.3 always uses 12-byte IVs (the full nonce).
template <size_t KeyLen, size_t IVLen = 12>
struct TrafficKeys {
    std::array<uint8_t, KeyLen> key{};
    std::array<uint8_t, IVLen> iv{};
};

// ---- HKDF-Expand-Label (RFC 8446 Section 7.1) ----
//
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//     HKDF-Expand(Secret, HkdfLabel, Length)
//
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
// } HkdfLabel;
template <hash_function THash, size_t L>
constexpr std::array<uint8_t, L> hkdf_expand_label(
    std::span<const uint8_t> secret,
    std::span<const uint8_t> label,
    std::span<const uint8_t> context)
{
    // Build HkdfLabel into a fixed buffer.
    // Max practical size: 2 + 1 + 6 + label.size() + 1 + context.size() ~= 70 bytes.
    std::array<uint8_t, 512> hkdf_label{};
    size_t pos = 0;

    // uint16 length = L
    hkdf_label[pos++] = static_cast<uint8_t>((L >> 8) & 0xFF);
    hkdf_label[pos++] = static_cast<uint8_t>(L & 0xFF);

    // opaque label<7..255> = "tls13 " + Label
    constexpr uint8_t prefix[] = {'t', 'l', 's', '1', '3', ' '};
    auto label_len = static_cast<uint8_t>(6 + label.size());
    hkdf_label[pos++] = label_len;
    for (size_t i = 0; i < 6; ++i) hkdf_label[pos++] = prefix[i];
    for (size_t i = 0; i < label.size(); ++i) hkdf_label[pos++] = label[i];

    // opaque context<0..255>
    hkdf_label[pos++] = static_cast<uint8_t>(context.size());
    for (size_t i = 0; i < context.size(); ++i) hkdf_label[pos++] = context[i];

    return hkdf_expand<THash, L>(secret, std::span<const uint8_t>(hkdf_label.data(), pos));
}

// ---- Derive-Secret (RFC 8446 Section 7.1) ----
//
// Derive-Secret(Secret, Label, Messages) =
//     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
template <hash_function THash>
constexpr std::array<uint8_t, THash::digest_size> derive_secret(
    std::span<const uint8_t> secret,
    std::span<const uint8_t> label,
    std::span<const uint8_t> transcript_hash)
{
    return hkdf_expand_label<THash, THash::digest_size>(secret, label, transcript_hash);
}

// ---- Traffic key derivation (RFC 8446 Section 7.3) ----
//
// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
// [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv",  "", iv_length)
template <hash_function THash, size_t KeyLen, size_t IVLen = 12>
constexpr TrafficKeys<KeyLen, IVLen> derive_traffic_keys(
    std::span<const uint8_t> traffic_secret)
{
    TrafficKeys<KeyLen, IVLen> keys;

    constexpr uint8_t key_label[] = {'k', 'e', 'y'};
    constexpr uint8_t iv_label[] = {'i', 'v'};

    keys.key = hkdf_expand_label<THash, KeyLen>(
        traffic_secret, std::span<const uint8_t>(key_label, 3), {});
    keys.iv = hkdf_expand_label<THash, IVLen>(
        traffic_secret, std::span<const uint8_t>(iv_label, 2), {});

    return keys;
}

// ---- Full TLS 1.3 Key Schedule (RFC 8446 Section 7.1) ----
//
// Staged derivation mirroring the RFC:
//   Stage 1: Early Secret       (from PSK or zeros)
//   Stage 2: Handshake Secret   (mixed with ECDHE shared secret)
//   Stage 3: Master Secret      (application traffic keys)
template <hash_function THash>
struct Tls13KeySchedule {
    static constexpr size_t D = THash::digest_size;
    using secret_t = std::array<uint8_t, D>;

    // Intermediate secrets
    secret_t early_secret{};
    secret_t handshake_secret{};
    secret_t master_secret{};

    // Handshake traffic secrets
    secret_t client_handshake_traffic_secret{};
    secret_t server_handshake_traffic_secret{};

    // Application traffic secrets
    secret_t client_application_traffic_secret{};
    secret_t server_application_traffic_secret{};

    // Exporter and resumption
    secret_t exporter_master_secret{};
    secret_t resumption_master_secret{};

    // ---- Stage 1: Early Secret ----
    // PSK is the pre-shared key; for non-PSK mode, pass zeros (D bytes).
    // early_secret = HKDF-Extract(salt=0, IKM=PSK)
    constexpr void derive_early_secret(std::span<const uint8_t> psk)
    {
        early_secret = hkdf_extract<THash>({}, psk);
    }

    // Convenience: non-PSK mode (IKM = zeros)
    constexpr void derive_early_secret()
    {
        secret_t zero_psk{};
        derive_early_secret(zero_psk);
    }

    // ---- Stage 2: Handshake Secret ----
    // transcript_hash = Hash(ClientHello...ServerHello)
    constexpr void derive_handshake_secrets(
        std::span<const uint8_t> dhe_shared_secret,
        std::span<const uint8_t> transcript_hash)
    {
        // salt = Derive-Secret(early_secret, "derived", "")
        auto salt = derive_secret_with_empty_hash(early_secret, "derived", 7);

        handshake_secret = hkdf_extract<THash>(salt, dhe_shared_secret);

        constexpr uint8_t c_hs[] = {'c', ' ', 'h', 's', ' ',
                                     't', 'r', 'a', 'f', 'f', 'i', 'c'};
        constexpr uint8_t s_hs[] = {'s', ' ', 'h', 's', ' ',
                                     't', 'r', 'a', 'f', 'f', 'i', 'c'};

        client_handshake_traffic_secret = derive_secret<THash>(
            handshake_secret, std::span<const uint8_t>(c_hs, 12), transcript_hash);
        server_handshake_traffic_secret = derive_secret<THash>(
            handshake_secret, std::span<const uint8_t>(s_hs, 12), transcript_hash);
    }

    // ---- Stage 3: Master Secret ----
    // transcript_hash = Hash(ClientHello...server Finished)
    constexpr void derive_master_secrets(
        std::span<const uint8_t> server_finished_transcript_hash)
    {
        // salt = Derive-Secret(handshake_secret, "derived", "")
        auto salt = derive_secret_with_empty_hash(handshake_secret, "derived", 7);

        // IKM = 0 (no new key material at master stage)
        secret_t zero_ikm{};
        master_secret = hkdf_extract<THash>(salt, zero_ikm);

        constexpr uint8_t c_ap[] = {'c', ' ', 'a', 'p', ' ',
                                     't', 'r', 'a', 'f', 'f', 'i', 'c'};
        constexpr uint8_t s_ap[] = {'s', ' ', 'a', 'p', ' ',
                                     't', 'r', 'a', 'f', 'f', 'i', 'c'};
        constexpr uint8_t exp[] = {'e', 'x', 'p', ' ',
                                    'm', 'a', 's', 't', 'e', 'r'};

        client_application_traffic_secret = derive_secret<THash>(
            master_secret, std::span<const uint8_t>(c_ap, 12),
            server_finished_transcript_hash);
        server_application_traffic_secret = derive_secret<THash>(
            master_secret, std::span<const uint8_t>(s_ap, 12),
            server_finished_transcript_hash);
        exporter_master_secret = derive_secret<THash>(
            master_secret, std::span<const uint8_t>(exp, 10),
            server_finished_transcript_hash);
    }

    // ---- Resumption Master Secret ----
    // transcript_hash = Hash(ClientHello...client Finished)
    constexpr void derive_resumption_master_secret(
        std::span<const uint8_t> client_finished_transcript_hash)
    {
        constexpr uint8_t res[] = {'r', 'e', 's', ' ',
                                    'm', 'a', 's', 't', 'e', 'r'};

        resumption_master_secret = derive_secret<THash>(
            master_secret, std::span<const uint8_t>(res, 10),
            client_finished_transcript_hash);
    }

    // ---- Finished key (RFC 8446 Section 4.4.4) ----
    // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    constexpr secret_t compute_finished_key(
        std::span<const uint8_t> base_key) const
    {
        constexpr uint8_t label[] = {'f', 'i', 'n', 'i', 's', 'h', 'e', 'd'};
        return hkdf_expand_label<THash, D>(
            base_key, std::span<const uint8_t>(label, 8), {});
    }

    // ---- Finished verify_data (RFC 8446 Section 4.4.4) ----
    // verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context,
    //                                                   Certificate*, CertificateVerify*))
    constexpr secret_t compute_finished_verify_data(
        std::span<const uint8_t> base_key,
        std::span<const uint8_t> transcript_hash) const
    {
        auto finished_key = compute_finished_key(base_key);
        return hmac<THash>(finished_key, transcript_hash);
    }

private:
    // Derive-Secret(secret, label, "") where "" means hash of empty input.
    // Used for the "derived" intermediate salt derivations.
    static constexpr secret_t derive_secret_with_empty_hash(
        std::span<const uint8_t> secret,
        const char* label_str,
        size_t label_len)
    {
        // Hash("")
        THash h;
        h.init();
        auto empty_hash = h.finalize();

        // Build label span from string literal (excluding null terminator)
        // We use a fixed buffer since constexpr can't do reinterpret_cast
        std::array<uint8_t, 32> label_buf{};
        for (size_t i = 0; i < label_len; ++i)
            label_buf[i] = static_cast<uint8_t>(label_str[i]);

        return derive_secret<THash>(
            secret,
            std::span<const uint8_t>(label_buf.data(), label_len),
            empty_hash);
    }
};

} // namespace tls
