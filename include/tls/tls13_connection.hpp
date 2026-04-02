/**
 * TLS 1.3 record I/O — RFC 8446 Section 5.
 *
 * Provides tls13_record_io: a buffered record layer for TLS 1.3 with:
 *   - Multi-stage key activation (handshake → application)
 *   - Inner content type extraction from encrypted records
 *   - Middlebox-compatibility CCS dropping
 *   - Independent read/write key activation
 *
 * Separate from record_io (TLS 1.2) because the encryption model is
 * fundamentally different: TLS 1.3 keys change mid-handshake, encrypted
 * records always have outer type application_data, and the real content
 * type is hidden inside the ciphertext.
 */

#pragma once

#include "connection.hpp"
#include "tls13_cipher_suite.hpp"
#include "tls13_key_schedule.hpp"
#include "tls13_record_protection.hpp"
#include "record.hpp"
#include "transcript.hpp"
#include "transport.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace tls {

// Result of receiving a TLS 1.3 record after decryption.
struct Tls13ReceivedRecord {
    ContentType content_type;
    std::vector<uint8_t> fragment;
};

// --- TLS 1.3 record I/O ---

template <transport Transport>
struct tls13_record_io {
    Transport& trans;

    // Read buffer
    asn1::FixedVector<uint8_t, MAX_CIPHERTEXT_LENGTH + RECORD_HEADER_LENGTH + 256> read_buf;
    size_t read_pos = 0;

    // Write/read cipher state — independent activation for each direction.
    struct direction_state {
        std::array<uint8_t, 32> key{};
        std::array<uint8_t, 12> iv{};
        size_t key_length = 0;
        uint64_t seq = 0;
        bool encrypted = false;
        Tls13CipherSuite suite{};
    };

    direction_state write_state{};
    direction_state read_state{};

    explicit tls13_record_io(Transport& t) : trans(t) {}

    // --- Key activation ---

    // Activate write-direction encryption with the given traffic secret.
    // Resets the write sequence number.
    void activate_write_keys(Tls13CipherSuite suite,
                             std::span<const uint8_t> traffic_secret)
    {
        auto params = get_tls13_cipher_suite_params(suite);
        write_state.suite = suite;
        write_state.key_length = params.key_length;
        write_state.seq = 0;
        write_state.encrypted = true;

        dispatch_tls13_cipher_suite(suite, [&]<typename Traits>() {
            using Hash = typename Traits::hash_type;
            auto keys = derive_traffic_keys<Hash, Traits::key_length>(traffic_secret);
            for (size_t i = 0; i < Traits::key_length; ++i)
                write_state.key[i] = keys.key[i];
            write_state.iv = keys.iv;
        });
    }

    // Activate read-direction encryption with the given traffic secret.
    void activate_read_keys(Tls13CipherSuite suite,
                            std::span<const uint8_t> traffic_secret)
    {
        auto params = get_tls13_cipher_suite_params(suite);
        read_state.suite = suite;
        read_state.key_length = params.key_length;
        read_state.seq = 0;
        read_state.encrypted = true;

        dispatch_tls13_cipher_suite(suite, [&]<typename Traits>() {
            using Hash = typename Traits::hash_type;
            auto keys = derive_traffic_keys<Hash, Traits::key_length>(traffic_secret);
            for (size_t i = 0; i < Traits::key_length; ++i)
                read_state.key[i] = keys.key[i];
            read_state.iv = keys.iv;
        });
    }

    // --- Send record ---

    tls_result<void> send_record(ContentType inner_type,
                                 std::span<const uint8_t> payload)
    {
        if (write_state.encrypted) {
            // Encrypt: inner content type is appended to plaintext inside AEAD.
            auto ciphertext = dispatch_tls13_cipher_suite(write_state.suite,
                [&]<typename Traits>() {
                    return tls13_encrypt_record<Traits>(
                        std::span<const uint8_t, Traits::key_length>(
                            write_state.key.data(), Traits::key_length),
                        std::span<const uint8_t, 12>(write_state.iv),
                        write_state.seq,
                        inner_type,
                        payload);
                });
            write_state.seq++;

            // Frame as record with outer type application_data, version TLS 1.2
            TlsWriter<MAX_CIPHERTEXT_LENGTH + RECORD_HEADER_LENGTH> w;
            TlsRecord rec;
            rec.type = ContentType::application_data;
            rec.version = TLS_1_2;
            for (size_t i = 0; i < ciphertext.size(); ++i)
                rec.fragment.push_back(ciphertext[i]);
            write_record(w, rec);
            auto written = trans.write(w.data());
            if (written < w.size()) return {tls_error::internal_error};
        } else {
            // Plaintext record (only for initial ClientHello/ServerHello and CCS)
            TlsWriter<MAX_PLAINTEXT_LENGTH + RECORD_HEADER_LENGTH> w;
            TlsRecord rec;
            rec.type = inner_type;
            rec.version = TLS_1_2;
            for (size_t i = 0; i < payload.size(); ++i)
                rec.fragment.push_back(payload[i]);
            write_record(w, rec);
            auto written = trans.write(w.data());
            if (written < w.size()) return {tls_error::internal_error};
        }
        return {tls_error::ok};
    }

    // Send a middlebox-compatibility ChangeCipherSpec record (unencrypted).
    tls_result<void> send_ccs() {
        uint8_t ccs_byte = 1;
        // CCS is always sent unencrypted, even if write keys are active.
        TlsWriter<16> w;
        TlsRecord rec;
        rec.type = ContentType::change_cipher_spec;
        rec.version = TLS_1_2;
        rec.fragment.push_back(ccs_byte);
        write_record(w, rec);
        auto written = trans.write(w.data());
        if (written < w.size()) return {tls_error::internal_error};
        return {tls_error::ok};
    }

    // --- Receive record ---

    bool fill_read_buf(size_t target_size) {
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

    void compact_read_buf() {
        size_t remaining = read_buf.size() - read_pos;
        for (size_t i = 0; i < remaining; ++i)
            read_buf.data[i] = read_buf.data[read_pos + i];
        read_buf.len = remaining;
        read_pos = 0;
    }

    // Receive and (if encrypted) decrypt a record.
    // Silently drops ChangeCipherSpec records (middlebox compatibility).
    tls_result<Tls13ReceivedRecord> recv_record() {
        for (;;) {
            compact_read_buf();

            if (!fill_read_buf(RECORD_HEADER_LENGTH))
                return {{}, tls_error::transport_closed};

            uint16_t frag_len = static_cast<uint16_t>(
                (read_buf[read_pos + 3] << 8) | read_buf[read_pos + 4]);

            if (!fill_read_buf(RECORD_HEADER_LENGTH + frag_len))
                return {{}, tls_error::transport_closed};

            auto record_span = std::span<const uint8_t>(
                read_buf.data.data() + read_pos, RECORD_HEADER_LENGTH + frag_len);
            TlsReader r(record_span);
            auto rec_opt = read_record(r);
            if (!rec_opt) return {{}, tls_error::decode_error};
            read_pos += RECORD_HEADER_LENGTH + frag_len;
            auto rec = *rec_opt;

            // Drop middlebox CCS silently
            if (rec.type == ContentType::change_cipher_spec)
                continue;

            // Alert records pass through without decryption
            if (rec.type == ContentType::alert) {
                Tls13ReceivedRecord result;
                result.content_type = ContentType::alert;
                result.fragment.assign(
                    rec.fragment.data.data(),
                    rec.fragment.data.data() + rec.fragment.size());
                return {std::move(result), tls_error::ok};
            }

            // Encrypted record (outer type = application_data)
            if (read_state.encrypted && rec.type == ContentType::application_data) {
                auto decrypted = dispatch_tls13_cipher_suite(read_state.suite,
                    [&]<typename Traits>()
                        -> std::optional<Tls13DecryptedRecord> {
                        return tls13_decrypt_record<Traits>(
                            std::span<const uint8_t, Traits::key_length>(
                                read_state.key.data(), Traits::key_length),
                            std::span<const uint8_t, 12>(read_state.iv),
                            read_state.seq,
                            std::span<const uint8_t>(
                                rec.fragment.data.data(), rec.fragment.size()));
                    });
                read_state.seq++;

                if (!decrypted) return {{}, tls_error::bad_record_mac};

                Tls13ReceivedRecord result;
                result.content_type = decrypted->content_type;
                result.fragment.assign(
                    decrypted->plaintext.data.data(),
                    decrypted->plaintext.data.data() + decrypted->plaintext.size());
                return {std::move(result), tls_error::ok};
            }

            // Plaintext record (handshake or other, before encryption activated)
            Tls13ReceivedRecord result;
            result.content_type = rec.type;
            result.fragment.assign(
                rec.fragment.data.data(),
                rec.fragment.data.data() + rec.fragment.size());
            return {std::move(result), tls_error::ok};
        }
    }
};

// --- TLS 1.3 handshake message reader ---
// Like handshake_reader for TLS 1.2, but works with tls13_record_io.
// Handles message framing within handshake records (including encrypted ones).

template <transport Transport>
struct tls13_handshake_reader {
    tls13_record_io<Transport>& rio;
    std::vector<uint8_t> buf;
    size_t pos = 0;

    explicit tls13_handshake_reader(tls13_record_io<Transport>& r) : rio(r) {}

    size_t available() const { return buf.size() - pos; }

    // Ensure at least n bytes are available.
    // Fetches more handshake records if needed.
    tls_result<void> ensure(size_t n) {
        while (available() < n) {
            auto rec = rio.recv_record();
            if (!rec) return {rec.error};
            if (rec.value.content_type != ContentType::handshake)
                return {tls_error::unexpected_message};
            buf.insert(buf.end(),
                       rec.value.fragment.begin(),
                       rec.value.fragment.end());
        }
        return {tls_error::ok};
    }

    // Read the next complete handshake message.
    // Returns a span covering the full message (header + body).
    // Adds the raw bytes to the transcript hash.
    template <hash_function THash>
    tls_result<std::vector<uint8_t>> next_message(TranscriptHash<THash>& transcript) {
        auto hdr_err = ensure(4);
        if (!hdr_err) return {{}, hdr_err.error};

        uint32_t body_len = (static_cast<uint32_t>(buf[pos + 1]) << 16) |
                            (static_cast<uint32_t>(buf[pos + 2]) << 8) |
                            buf[pos + 3];
        size_t total = 4 + body_len;

        auto body_err = ensure(total);
        if (!body_err) return {{}, body_err.error};

        std::vector<uint8_t> msg(buf.begin() + pos, buf.begin() + pos + total);
        transcript.update(std::span<const uint8_t>(msg));
        pos += total;
        return {std::move(msg), tls_error::ok};
    }
};

} // namespace tls
