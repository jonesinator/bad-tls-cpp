/**
 * TLS 1.2 connection infrastructure.
 *
 * Provides:
 *   - tls_error / tls_result error handling
 *   - record_io: buffered record-layer I/O with encryption state
 *   - handshake_reader: message framing within handshake records
 *   - verify_server_key_exchange: SKE signature verification
 *   - compute_ecdh_exchange: ECDH key exchange helpers
 */

#pragma once

#include "cipher_suite.hpp"
#include "handshake.hpp"
#include "key_schedule.hpp"
#include "record.hpp"
#include "record_protection.hpp"
#include "transcript.hpp"
#include "transport.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <crypto/ecdh.hpp>
#include <crypto/x25519.hpp>
#include <crypto/ecdsa.hpp>
#include <crypto/random.hpp>
#include <crypto/rsa.hpp>
#include <crypto/sha2.hpp>
#include <x509/verify.hpp>
#include <array>
#include <cstdint>
#include <span>

namespace tls {

// --- Role ---

enum class tls_role : uint8_t { client, server };

// --- Error handling ---

enum class tls_error : uint8_t {
    ok = 0,
    unexpected_message,
    bad_record_mac,
    handshake_failure,
    bad_certificate,
    decode_error,
    signature_verification_failed,
    unsupported_curve,
    invalid_server_key,
    transport_closed,
    internal_error,
};

template <typename T>
struct tls_result {
    T value{};
    tls_error error = tls_error::ok;
    constexpr bool ok() const { return error == tls_error::ok; }
    constexpr explicit operator bool() const { return ok(); }
};

template <>
struct tls_result<void> {
    tls_error error = tls_error::ok;
    constexpr bool ok() const { return error == tls_error::ok; }
    constexpr explicit operator bool() const { return ok(); }
};

// --- Buffered record I/O ---

template <transport Transport>
struct record_io {
    Transport& trans;

    // Read buffer for accumulating bytes from transport
    asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH + RECORD_HEADER_LENGTH + 256> read_buf;
    size_t read_pos = 0;

    // Encryption state
    struct cipher_state {
        std::array<uint8_t, 32> write_key{};
        std::array<uint8_t, 32> read_key{};
        std::array<uint8_t, 12> write_iv{};
        std::array<uint8_t, 12> read_iv{};
        size_t key_length = 0;
        uint64_t write_seq = 0;
        uint64_t read_seq = 0;
        CipherSuite suite{};
    };

    bool write_encrypted = false;
    bool read_encrypted = false;
    cipher_state cs{};

    tls_role role_ = tls_role::client;

    constexpr explicit record_io(Transport& t) : trans(t) {}
    constexpr record_io(Transport& t, tls_role role) : trans(t), role_(role) {}

    constexpr void activate_write_cipher(const KeyBlock& kb, CipherSuite suite) {
        cs.suite = suite;
        cs.key_length = kb.key_length;
        if (role_ == tls_role::client) {
            cs.write_key = kb.client_write_key;
            cs.write_iv = kb.client_write_iv;
        } else {
            cs.write_key = kb.server_write_key;
            cs.write_iv = kb.server_write_iv;
        }
        cs.write_seq = 0;
        write_encrypted = true;
    }

    constexpr void activate_read_cipher(const KeyBlock& kb, CipherSuite suite) {
        cs.suite = suite;
        cs.key_length = kb.key_length;
        if (role_ == tls_role::client) {
            cs.read_key = kb.server_write_key;
            cs.read_iv = kb.server_write_iv;
        } else {
            cs.read_key = kb.client_write_key;
            cs.read_iv = kb.client_write_iv;
        }
        cs.read_seq = 0;
        read_encrypted = true;
    }

    constexpr tls_result<void> send_record(ContentType type, std::span<const uint8_t> payload) {
        if (write_encrypted) {
            auto encrypted = dispatch_cipher_suite(cs.suite, [&]<typename Traits>() {
                if constexpr (Traits::record_iv_length == 0) {
                    return encrypt_record_chacha20(
                        std::span<const uint8_t, 32>(cs.write_key.data(), 32),
                        std::span<const uint8_t, 12>(cs.write_iv),
                        cs.write_seq, type, TLS_1_2, payload);
                } else {
                    using Cipher = typename Traits::cipher_type;
                    return encrypt_record<Cipher>(
                        std::span<const uint8_t, Traits::key_length>(cs.write_key.data(), Traits::key_length),
                        std::span<const uint8_t, 4>(cs.write_iv.data(), 4),
                        cs.write_seq, type, TLS_1_2, payload);
                }
            });
            cs.write_seq++;

            TlsWriter<MAX_CIPHERTEXT_LENGTH + RECORD_HEADER_LENGTH> w;
            TlsRecord rec;
            rec.type = type;
            rec.version = TLS_1_2;
            rec.fragment = encrypted;
            write_record(w, rec);
            auto written = trans.write(w.data());
            if (written < w.size()) return {tls_error::internal_error};
        } else {
            TlsWriter<MAX_PLAINTEXT_LENGTH + RECORD_HEADER_LENGTH> w;
            TlsRecord rec;
            rec.type = type;
            rec.version = TLS_1_2;
            for (size_t i = 0; i < payload.size(); ++i)
                rec.fragment.push_back(payload[i]);
            write_record(w, rec);
            auto written = trans.write(w.data());
            if (written < w.size()) return {tls_error::internal_error};
        }
        return {tls_error::ok};
    }

    // Read exactly n bytes from transport into read_buf, returns false on EOF
    constexpr bool fill_read_buf(size_t target_size) {
        while (read_buf.size() - read_pos < target_size) {
            std::array<uint8_t, 4096> tmp{};
            size_t need = target_size - (read_buf.size() - read_pos);
            size_t ask = need < tmp.size() ? need : tmp.size();
            size_t got = trans.read(std::span<uint8_t>(tmp.data(), ask));
            if (got == 0) return false;
            for (size_t i = 0; i < got; ++i)
                read_buf.push_back(tmp[i]);
        }
        return true;
    }

    constexpr void compact_read_buf() {
        size_t remaining = read_buf.size() - read_pos;
        for (size_t i = 0; i < remaining; ++i)
            read_buf.data[i] = read_buf.data[read_pos + i];
        read_buf.len = remaining;
        read_pos = 0;
    }

    constexpr tls_result<TlsRecord> recv_record() {
        compact_read_buf();

        // Read header (5 bytes)
        if (!fill_read_buf(RECORD_HEADER_LENGTH))
            return {{}, tls_error::transport_closed};

        // Parse length from header bytes
        uint16_t frag_len = static_cast<uint16_t>(
            (read_buf[read_pos + 3] << 8) | read_buf[read_pos + 4]);

        // Read full record
        if (!fill_read_buf(RECORD_HEADER_LENGTH + frag_len))
            return {{}, tls_error::transport_closed};

        auto record_span = std::span<const uint8_t>(
            read_buf.data.data() + read_pos, RECORD_HEADER_LENGTH + frag_len);
        TlsReader r(record_span);
        auto rec_opt = read_record(r);
        if (!rec_opt) return {{}, tls_error::decode_error};
        read_pos += RECORD_HEADER_LENGTH + frag_len;

        auto rec = *rec_opt;

        // Decrypt if needed
        if (read_encrypted) {
            auto plaintext = dispatch_cipher_suite(cs.suite, [&]<typename Traits>()
                -> std::optional<asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH>> {
                if constexpr (Traits::record_iv_length == 0) {
                    return decrypt_record_chacha20(
                        std::span<const uint8_t, 32>(cs.read_key.data(), 32),
                        std::span<const uint8_t, 12>(cs.read_iv),
                        cs.read_seq, rec.type, rec.version,
                        std::span<const uint8_t>(rec.fragment.data.data(), rec.fragment.len));
                } else {
                    using Cipher = typename Traits::cipher_type;
                    return decrypt_record<Cipher>(
                        std::span<const uint8_t, Traits::key_length>(cs.read_key.data(), Traits::key_length),
                        std::span<const uint8_t, 4>(cs.read_iv.data(), 4),
                        cs.read_seq, rec.type, rec.version,
                        std::span<const uint8_t>(rec.fragment.data.data(), rec.fragment.len));
                }
            });
            cs.read_seq++;
            if (!plaintext) return {{}, tls_error::bad_record_mac};
            rec.fragment.len = 0;
            for (size_t i = 0; i < plaintext->size(); ++i)
                rec.fragment.push_back((*plaintext)[i]);
        }

        return {rec, tls_error::ok};
    }
};

// --- Handshake message reader ---
// Handles multiple messages in one record or messages spanning records.

template <transport Transport>
struct handshake_reader {
    record_io<Transport>& rio;
    asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH + 4096> buf;
    size_t pos = 0;

    constexpr explicit handshake_reader(record_io<Transport>& r) : rio(r) {}

    constexpr size_t available() const { return buf.size() - pos; }

    // Ensure at least n bytes are available in the buffer.
    // Fetches more handshake records if needed.
    constexpr tls_result<void> ensure(size_t n) {
        while (available() < n) {
            auto rec = rio.recv_record();
            if (!rec) return {rec.error};
            if (rec.value.type != ContentType::handshake)
                return {tls_error::unexpected_message};
            for (size_t i = 0; i < rec.value.fragment.size(); ++i)
                buf.push_back(rec.value.fragment[i]);
        }
        return {tls_error::ok};
    }

    // Read the next complete handshake message.
    // Returns a span covering the full message (header + body).
    // Adds the raw bytes to the transcript hash.
    template <hash_function THash>
    constexpr tls_result<std::span<const uint8_t>> next_message(TranscriptHash<THash>& transcript) {
        // Need at least 4 bytes for handshake header
        auto hdr_err = ensure(4);
        if (!hdr_err) return {{}, hdr_err.error};

        // Parse length from header
        uint32_t body_len = (static_cast<uint32_t>(buf[pos + 1]) << 16) |
                            (static_cast<uint32_t>(buf[pos + 2]) << 8) |
                            buf[pos + 3];
        size_t total = 4 + body_len;

        auto body_err = ensure(total);
        if (!body_err) return {{}, body_err.error};

        auto msg_span = std::span<const uint8_t>(buf.data.data() + pos, total);
        transcript.update(msg_span);
        pos += total;
        return {msg_span, tls_error::ok};
    }
};

// --- ServerKeyExchange signature verification ---

inline bool verify_server_key_exchange(
    const ServerKeyExchangeEcdhe& ske,
    const Random& client_random,
    const Random& server_random,
    const asn1::x509::x509_public_key& server_pub_key)
{
    // Reconstruct signed data: client_random || server_random || server_params
    // server_params = curve_type(1) || named_curve(2) || point_len(1) || point
    std::array<uint8_t, 201> signed_data{};
    size_t pos = 0;
    for (size_t i = 0; i < 32; ++i) signed_data[pos++] = client_random[i];
    for (size_t i = 0; i < 32; ++i) signed_data[pos++] = server_random[i];
    signed_data[pos++] = static_cast<uint8_t>(ECCurveType::named_curve);
    signed_data[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(ske.named_curve) >> 8);
    signed_data[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(ske.named_curve));
    signed_data[pos++] = static_cast<uint8_t>(ske.public_key.size());
    for (size_t i = 0; i < ske.public_key.size(); ++i)
        signed_data[pos++] = ske.public_key[i];
    auto data_span = std::span<const uint8_t>(signed_data.data(), pos);

    if (ske.sig_algorithm.signature == SignatureAlgorithm::rsa) {
        auto* key = std::get_if<rsa_public_key<asn1::x509::rsa_num>>(&server_pub_key);
        if (!key) return false;
        rsa_signature<asn1::x509::rsa_num> sig{
            asn1::x509::rsa_num::from_bytes(
                std::span<const uint8_t>(ske.signature.data.data(), ske.signature.len))};

        if (ske.sig_algorithm.hash == HashAlgorithm::sha256)
            return rsa_pkcs1_v1_5_verify<asn1::x509::rsa_num, sha256_state>(*key, sha256(data_span), sig);
        if (ske.sig_algorithm.hash == HashAlgorithm::sha384)
            return rsa_pkcs1_v1_5_verify<asn1::x509::rsa_num, sha384_state>(*key, sha384(data_span), sig);
        return false;
    }

    if (ske.sig_algorithm.signature == SignatureAlgorithm::ecdsa) {
        if (ske.sig_algorithm.hash == HashAlgorithm::sha256) {
            auto* key = std::get_if<point<asn1::x509::p256_curve>>(&server_pub_key);
            if (!key) return false;
            auto sig = asn1::x509::detail::parse_ecdsa_signature<asn1::x509::p256_curve>(
                std::span<const uint8_t>(ske.signature.data.data(), ske.signature.len));
            return ecdsa_verify<asn1::x509::p256_curve, sha256_state>(*key, sha256(data_span), sig);
        }
        if (ske.sig_algorithm.hash == HashAlgorithm::sha384) {
            auto* key = std::get_if<point<asn1::x509::p384_curve>>(&server_pub_key);
            if (!key) return false;
            auto sig = asn1::x509::detail::parse_ecdsa_signature<asn1::x509::p384_curve>(
                std::span<const uint8_t>(ske.signature.data.data(), ske.signature.len));
            return ecdsa_verify<asn1::x509::p384_curve, sha384_state>(*key, sha384(data_span), sig);
        }
        return false;
    }

    return false;
}

// --- ECDH exchange ---

struct pre_master_secret {
    std::array<uint8_t, 48> data{};
    size_t length = 0;
};

struct ecdh_exchange_result {
    pre_master_secret pms;
    ClientKeyExchangeEcdhe cke;
};

namespace detail {

template <typename TCurve, random_generator RNG>
tls_result<ecdh_exchange_result> compute_ecdh_exchange_impl(
    std::span<const uint8_t> server_point_bytes, RNG& rng)
{
    using fe = field_element<TCurve>;
    using num = typename TCurve::number_type;

    if (server_point_bytes.size() < 3 || server_point_bytes[0] != 0x04)
        return {{}, tls_error::invalid_server_key};

    size_t coord_len = (server_point_bytes.size() - 1) / 2;
    auto x = num::from_bytes(server_point_bytes.subspan(1, coord_len));
    auto y = num::from_bytes(server_point_bytes.subspan(1 + coord_len, coord_len));
    point<TCurve> server_point{fe{x}, fe{y}};

    if (!ecdh_validate_public_key(server_point))
        return {{}, tls_error::invalid_server_key};

    auto priv = random_scalar<TCurve>(rng);
    auto kp = ecdh_keypair_from_private<TCurve>(priv);

    auto secret_opt = ecdh_raw_shared_secret<TCurve>(priv, server_point);
    if (!secret_opt) return {{}, tls_error::internal_error};

    // Serialize shared secret
    pre_master_secret pms{};
    auto secret_bytes = secret_opt->to_bytes(std::endian::big);
    pms.length = coord_len;
    size_t offset = secret_bytes.size() - coord_len;
    for (size_t i = 0; i < coord_len; ++i)
        pms.data[i] = secret_bytes[offset + i];

    // Serialize our public key: 0x04 || x || y
    ClientKeyExchangeEcdhe cke{};
    cke.public_key.push_back(0x04);
    auto our_x = kp.public_key.x().value().to_bytes(std::endian::big);
    auto our_y = kp.public_key.y().value().to_bytes(std::endian::big);
    size_t x_off = our_x.size() - coord_len;
    size_t y_off = our_y.size() - coord_len;
    for (size_t i = 0; i < coord_len; ++i) cke.public_key.push_back(our_x[x_off + i]);
    for (size_t i = 0; i < coord_len; ++i) cke.public_key.push_back(our_y[y_off + i]);

    return {{pms, cke}, tls_error::ok};
}

template <random_generator RNG>
tls_result<ecdh_exchange_result> compute_x25519_exchange_impl(
    std::span<const uint8_t> server_key_bytes, RNG& rng)
{
    if (server_key_bytes.size() != 32)
        return {{}, tls_error::invalid_server_key};

    // Generate ephemeral private key (32 random bytes, clamping happens inside)
    auto priv = random_bytes<32>(rng);
    auto pub = x25519_public_key<asn1::x509::uint512>(priv);

    // Compute shared secret
    std::array<uint8_t, 32> peer_key{};
    for (size_t i = 0; i < 32; ++i) peer_key[i] = server_key_bytes[i];
    auto secret = x25519_shared_secret<asn1::x509::uint512>(priv, peer_key);
    if (!secret) return {{}, tls_error::internal_error};

    // Pack pre-master secret (32 bytes)
    pre_master_secret pms{};
    pms.length = 32;
    for (size_t i = 0; i < 32; ++i) pms.data[i] = (*secret)[i];

    // Client public key: 32 raw bytes (no 0x04 prefix for X25519)
    ClientKeyExchangeEcdhe cke{};
    for (size_t i = 0; i < 32; ++i) cke.public_key.push_back(pub[i]);

    return {{pms, cke}, tls_error::ok};
}

} // namespace detail

template <random_generator RNG>
tls_result<ecdh_exchange_result> compute_ecdh_exchange(
    NamedCurve curve,
    std::span<const uint8_t> server_point_bytes,
    RNG& rng)
{
    if (curve == NamedCurve::secp256r1)
        return detail::compute_ecdh_exchange_impl<asn1::x509::p256_curve>(server_point_bytes, rng);
    if (curve == NamedCurve::secp384r1)
        return detail::compute_ecdh_exchange_impl<asn1::x509::p384_curve>(server_point_bytes, rng);
    if (curve == NamedCurve::x25519)
        return detail::compute_x25519_exchange_impl(server_point_bytes, rng);
    return {{}, tls_error::unsupported_curve};
}

} // namespace tls
