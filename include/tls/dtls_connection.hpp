/**
 * DTLS 1.2 connection infrastructure.
 *
 * Provides:
 *   - dtls_record_io: datagram-oriented record I/O with epoch tracking
 *   - dtls_handshake_reader: message framing with DTLS headers
 *
 * Unlike TLS, DTLS record_io:
 *   - Tracks epoch (incremented on ChangeCipherSpec)
 *   - Uses 48-bit sequence numbers per epoch
 *   - Includes anti-replay window for incoming records
 *   - Reads/writes complete datagrams (no stream buffering)
 */

#pragma once

#include "cipher_suite.hpp"
#include "connection.hpp"
#include "dtls_handshake.hpp"
#include "dtls_record.hpp"
#include "dtls_record_protection.hpp"
#include "key_schedule.hpp"
#include "transcript.hpp"
#include "transport.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace tls {

// --- Datagram-oriented record I/O ---

template <transport Transport>
struct dtls_record_io {
    Transport& trans;

    // Encryption state
    struct cipher_state {
        std::array<uint8_t, 32> write_key{};
        std::array<uint8_t, 32> read_key{};
        std::array<uint8_t, 4>  write_iv{};
        std::array<uint8_t, 4>  read_iv{};
        size_t key_length = 0;
        CipherSuite suite{};
    };

    bool write_encrypted = false;
    bool read_encrypted = false;
    cipher_state cs{};

    uint16_t write_epoch = 0;
    uint64_t write_seq = 0;
    uint16_t read_epoch = 0;

    replay_window replay{};
    tls_role role_ = tls_role::client;

    // Datagram buffer: a single UDP datagram may contain multiple DTLS records.
    // We read the whole datagram, then return records one at a time.
    std::vector<uint8_t> dgram_buf;
    size_t dgram_pos = 0;

    explicit dtls_record_io(Transport& t) : trans(t) {}
    dtls_record_io(Transport& t, tls_role role) : trans(t), role_(role) {}

    void activate_write_cipher(const KeyBlock& kb, CipherSuite suite) {
        cs.suite = suite;
        cs.key_length = kb.key_length;
        if (role_ == tls_role::client) {
            cs.write_key = kb.client_write_key;
            cs.write_iv = kb.client_write_iv;
        } else {
            cs.write_key = kb.server_write_key;
            cs.write_iv = kb.server_write_iv;
        }
        write_epoch++;
        write_seq = 0;
        write_encrypted = true;
    }

    void activate_read_cipher(const KeyBlock& kb, CipherSuite suite) {
        cs.suite = suite;
        cs.key_length = kb.key_length;
        if (role_ == tls_role::client) {
            cs.read_key = kb.server_write_key;
            cs.read_iv = kb.server_write_iv;
        } else {
            cs.read_key = kb.client_write_key;
            cs.read_iv = kb.client_write_iv;
        }
        read_epoch++;
        replay = replay_window{};  // reset on epoch change
        read_encrypted = true;
    }

    tls_result<void> send_record(ContentType type, std::span<const uint8_t> payload) {
        DtlsRecord rec;
        rec.type = type;
        rec.version = DTLS_1_2;
        rec.epoch = write_epoch;
        rec.sequence_number = write_seq;

        if (write_encrypted) {
            auto encrypted = dispatch_cipher_suite(cs.suite, [&]<typename Traits>() {
                using Cipher = typename Traits::cipher_type;
                return dtls_encrypt_record<Cipher>(
                    std::span<const uint8_t, Traits::key_length>(cs.write_key.data(), Traits::key_length),
                    std::span<const uint8_t, 4>(cs.write_iv),
                    write_epoch, write_seq, type, DTLS_1_2, payload);
            });
            rec.fragment = encrypted;
        } else {
            for (size_t i = 0; i < payload.size(); ++i)
                rec.fragment.push_back(payload[i]);
        }
        write_seq++;

        TlsWriter<MAX_CIPHERTEXT_LENGTH + DTLS_RECORD_HEADER_LENGTH> w;
        write_dtls_record(w, rec);
        auto written = trans.write(w.data());
        if (written < w.size()) return {tls_error::internal_error};
        return {tls_error::ok};
    }

    // Send multiple records in a single datagram (flight).
    tls_result<void> send_flight(std::span<const std::pair<ContentType, std::vector<uint8_t>>> records) {
        // Serialize all records into one buffer
        TlsWriter<65536> w;
        for (auto& [type, payload] : records) {
            DtlsRecord rec;
            rec.type = type;
            rec.version = DTLS_1_2;
            rec.epoch = write_epoch;
            rec.sequence_number = write_seq;

            if (write_encrypted) {
                auto encrypted = dispatch_cipher_suite(cs.suite, [&]<typename Traits>() {
                    using Cipher = typename Traits::cipher_type;
                    return dtls_encrypt_record<Cipher>(
                        std::span<const uint8_t, Traits::key_length>(cs.write_key.data(), Traits::key_length),
                        std::span<const uint8_t, 4>(cs.write_iv),
                        write_epoch, write_seq, type, DTLS_1_2,
                        std::span<const uint8_t>(payload));
                });
                rec.fragment = encrypted;
            } else {
                for (auto b : payload) rec.fragment.push_back(b);
            }
            write_seq++;
            write_dtls_record(w, rec);
        }
        auto written = trans.write(w.data());
        if (written < w.size()) return {tls_error::internal_error};
        return {tls_error::ok};
    }

    // Receive a single DTLS record.
    // A UDP datagram may contain multiple DTLS records packed together.
    // We buffer the datagram and return records one at a time.
    tls_result<DtlsRecord> recv_record() {
        // If we have buffered data from a previous datagram, try to parse from it
        while (dgram_pos >= dgram_buf.size()) {
            // Need a new datagram
            std::array<uint8_t, 65536> buf{};
            size_t n = trans.read(std::span<uint8_t>(buf));
            if (n == 0) return {{}, tls_error::transport_closed};
            dgram_buf.assign(buf.data(), buf.data() + n);
            dgram_pos = 0;
        }

        size_t remaining = dgram_buf.size() - dgram_pos;
        if (remaining < DTLS_RECORD_HEADER_LENGTH)
            return {{}, tls_error::decode_error};

        TlsReader r(std::span<const uint8_t>(dgram_buf.data() + dgram_pos, remaining));
        auto rec_opt = read_dtls_record(r);
        if (!rec_opt) return {{}, tls_error::decode_error};

        // Advance past this record
        dgram_pos += (remaining - r.remaining());

        auto rec = *rec_opt;

        // Decrypt if the record's epoch matches the read epoch and encryption is active
        if (read_encrypted && rec.epoch == read_epoch) {
            // Anti-replay check
            if (!replay.check_and_update(rec.sequence_number))
                return {{}, tls_error::bad_record_mac};

            auto plaintext = dispatch_cipher_suite(cs.suite, [&]<typename Traits>()
                -> std::optional<asn1::FixedVector<uint8_t, MAX_PLAINTEXT_LENGTH>> {
                using Cipher = typename Traits::cipher_type;
                return dtls_decrypt_record<Cipher>(
                    std::span<const uint8_t, Traits::key_length>(cs.read_key.data(), Traits::key_length),
                    std::span<const uint8_t, 4>(cs.read_iv),
                    rec.epoch, rec.sequence_number,
                    rec.type, rec.version,
                    std::span<const uint8_t>(rec.fragment.data.data(), rec.fragment.len));
            });
            if (!plaintext) return {{}, tls_error::bad_record_mac};
            rec.fragment.len = 0;
            for (size_t i = 0; i < plaintext->size(); ++i)
                rec.fragment.push_back((*plaintext)[i]);
        }

        return {rec, tls_error::ok};
    }

    // Buffer pre-read data (from listener's initial datagram) so that
    // subsequent recv_record() calls can parse records from it.
    void buffer_initial_data(std::span<const uint8_t> data) {
        dgram_buf.assign(data.begin(), data.end());
        dgram_pos = 0;
    }
};

// --- DTLS handshake message reader ---
// Parses DTLS handshake headers (12-byte) and provides message bodies.

template <transport Transport>
struct dtls_handshake_reader {
    dtls_record_io<Transport>& rio;
    std::vector<uint8_t> buf;  // accumulated handshake bytes from current record
    size_t pos = 0;

    explicit dtls_handshake_reader(dtls_record_io<Transport>& r) : rio(r) {}

    void reset() { buf.clear(); pos = 0; }

    size_t available() const { return buf.size() - pos; }

    // Read the next handshake record and buffer its contents
    tls_result<void> fetch_record() {
        auto rec = rio.recv_record();
        if (!rec) return {rec.error};
        if (rec.value.type != ContentType::handshake)
            return {tls_error::unexpected_message};
        // Append fragment to buffer
        for (size_t i = 0; i < rec.value.fragment.size(); ++i)
            buf.push_back(rec.value.fragment[i]);
        return {tls_error::ok};
    }

    // Buffer data from pre-read record fragment
    void buffer_fragment(std::span<const uint8_t> data) {
        for (size_t i = 0; i < data.size(); ++i)
            buf.push_back(data[i]);
    }

    // Read the next complete DTLS handshake message.
    // Returns body span (after the 12-byte DTLS handshake header).
    // Adds the message to transcript as a TLS-style handshake message
    // (4-byte header + body) for hash compatibility.
    template <hash_function THash>
    tls_result<std::pair<DtlsHandshakeHeader, std::span<const uint8_t>>>
    next_message(TranscriptHash<THash>& transcript)
    {
        // Ensure at least 12 bytes for DTLS handshake header
        while (available() < DTLS_HANDSHAKE_HEADER_LENGTH) {
            auto err = fetch_record();
            if (!err) return {{}, err.error};
        }

        // Parse header
        TlsReader hdr_r(std::span<const uint8_t>(buf.data() + pos, available()));
        auto hdr = read_dtls_handshake_header(hdr_r);

        // Ensure full fragment is available
        size_t total = DTLS_HANDSHAKE_HEADER_LENGTH + hdr.fragment_length;
        while (available() < total) {
            auto err = fetch_record();
            if (!err) return {{}, err.error};
        }

        // Body starts after the 12-byte header
        auto body = std::span<const uint8_t>(buf.data() + pos + DTLS_HANDSHAKE_HEADER_LENGTH,
                                              hdr.fragment_length);

        // Add to transcript as TLS-format: type(1) + length(3) + body
        // (DTLS transcript uses only the de-fragmented message without
        // message_seq/fragment_offset/fragment_length per RFC 6347 Section 4.2.6)
        std::array<uint8_t, 4> tls_hdr{};
        tls_hdr[0] = static_cast<uint8_t>(hdr.type);
        tls_hdr[1] = static_cast<uint8_t>((hdr.length >> 16) & 0xFF);
        tls_hdr[2] = static_cast<uint8_t>((hdr.length >> 8) & 0xFF);
        tls_hdr[3] = static_cast<uint8_t>(hdr.length & 0xFF);
        transcript.update(std::span<const uint8_t>(tls_hdr));
        transcript.update(body);

        pos += total;
        return {{hdr, body}, tls_error::ok};
    }

    // Read next message WITHOUT adding to transcript (for HelloVerifyRequest)
    tls_result<std::pair<DtlsHandshakeHeader, std::span<const uint8_t>>>
    next_message_no_transcript()
    {
        while (available() < DTLS_HANDSHAKE_HEADER_LENGTH) {
            auto err = fetch_record();
            if (!err) return {{}, err.error};
        }

        TlsReader hdr_r(std::span<const uint8_t>(buf.data() + pos, available()));
        auto hdr = read_dtls_handshake_header(hdr_r);

        size_t total = DTLS_HANDSHAKE_HEADER_LENGTH + hdr.fragment_length;
        while (available() < total) {
            auto err = fetch_record();
            if (!err) return {{}, err.error};
        }

        auto body = std::span<const uint8_t>(buf.data() + pos + DTLS_HANDSHAKE_HEADER_LENGTH,
                                              hdr.fragment_length);
        pos += total;
        return {{hdr, body}, tls_error::ok};
    }
};

} // namespace tls
