/**
 * TLS 1.3 extension serialization — RFC 8446 Section 4.2.
 *
 * Read/write functions for TLS 1.3-specific extensions used in
 * ClientHello and ServerHello: supported_versions, key_share,
 * signature_algorithms, and psk_key_exchange_modes.
 *
 * Uses TlsReader/TlsWriter from record.hpp.
 */

#pragma once

#include "record.hpp"
#include "types.hpp"
#include <asn1/fixed_vector.hpp>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace tls {

// --- Key share entry (RFC 8446 Section 4.2.8) ---

struct KeyShareEntry {
    NamedCurve group;
    asn1::FixedVector<uint8_t, 133> key_exchange; // x25519=32, P-256=65, P-384=97, P-521=133
    constexpr bool operator==(const KeyShareEntry&) const = default;
};

// --- Extension writers for ClientHello ---

// supported_versions (type 43) — RFC 8446 Section 4.2.1
// Client: list of supported versions.
template <size_t Cap>
constexpr void write_supported_versions_client(
    TlsWriter<Cap>& w,
    std::span<const ProtocolVersion> versions)
{
    w.write_u16(static_cast<uint16_t>(ExtensionType::supported_versions));
    // extension data: 1-byte list length + 2 bytes per version
    auto list_len = static_cast<uint8_t>(versions.size() * 2);
    w.write_u16(static_cast<uint16_t>(1 + list_len)); // extension data length
    w.write_u8(list_len);
    for (size_t i = 0; i < versions.size(); ++i) {
        w.write_u8(versions[i].major);
        w.write_u8(versions[i].minor);
    }
}

// key_share (type 51) — RFC 8446 Section 4.2.8
// Client: list of key share offers.
template <size_t Cap>
constexpr void write_key_share_client(
    TlsWriter<Cap>& w,
    std::span<const KeyShareEntry> entries)
{
    w.write_u16(static_cast<uint16_t>(ExtensionType::key_share));

    // Compute client_shares length: sum of (2 + 2 + key_exchange.size()) per entry
    uint16_t shares_len = 0;
    for (size_t i = 0; i < entries.size(); ++i)
        shares_len = static_cast<uint16_t>(shares_len + 4 + entries[i].key_exchange.size());

    w.write_u16(static_cast<uint16_t>(2 + shares_len)); // extension data length
    w.write_u16(shares_len);                              // client_shares length

    for (size_t i = 0; i < entries.size(); ++i) {
        w.write_u16(static_cast<uint16_t>(entries[i].group));
        w.write_u16(static_cast<uint16_t>(entries[i].key_exchange.size()));
        w.write_bytes(std::span<const uint8_t>(
            entries[i].key_exchange.data.data(), entries[i].key_exchange.len));
    }
}

// signature_algorithms (type 13) — RFC 8446 Section 4.2.3
// TLS 1.3 uses the same wire format as TLS 1.2 but with SignatureScheme values.
template <size_t Cap>
constexpr void write_signature_algorithms_13(
    TlsWriter<Cap>& w,
    std::span<const SignatureScheme> schemes)
{
    w.write_u16(static_cast<uint16_t>(ExtensionType::signature_algorithms));
    auto list_len = static_cast<uint16_t>(schemes.size() * 2);
    w.write_u16(static_cast<uint16_t>(2 + list_len)); // extension data length
    w.write_u16(list_len);
    for (size_t i = 0; i < schemes.size(); ++i)
        w.write_u16(static_cast<uint16_t>(schemes[i]));
}

// psk_key_exchange_modes (type 45) — RFC 8446 Section 4.2.9
template <size_t Cap>
constexpr void write_psk_key_exchange_modes(TlsWriter<Cap>& w)
{
    w.write_u16(static_cast<uint16_t>(ExtensionType::psk_key_exchange_modes));
    w.write_u16(2); // extension data length
    w.write_u8(1);  // modes list length
    w.write_u8(1);  // psk_dhe_ke(1)
}

// --- Extension readers for ServerHello ---

// Parse supported_versions from ServerHello extension data.
// Input: the extension data bytes (after type and length).
constexpr ProtocolVersion read_supported_versions_server(TlsReader& r) {
    ProtocolVersion v;
    v.major = r.read_u8();
    v.minor = r.read_u8();
    return v;
}

// Parse key_share from ServerHello extension data.
// Server sends a single KeyShareEntry (no list length prefix).
constexpr KeyShareEntry read_key_share_server(TlsReader& r) {
    KeyShareEntry entry;
    entry.group = static_cast<NamedCurve>(r.read_u16());
    uint16_t key_len = r.read_u16();
    auto key_data = r.read_bytes(key_len);
    for (size_t i = 0; i < key_len; ++i)
        entry.key_exchange.push_back(key_data[i]);
    return entry;
}

// --- ServerHello extension parsing ---

// Result of parsing TLS 1.3 ServerHello extensions.
struct Tls13ServerHelloExtensions {
    ProtocolVersion selected_version{};
    bool has_supported_versions = false;
    KeyShareEntry server_share{};
    bool has_key_share = false;
};

// Parse all extensions from a ServerHello to extract TLS 1.3 fields.
// Input: the raw extension bytes (after the 2-byte extension list length).
constexpr Tls13ServerHelloExtensions parse_server_hello_extensions_13(
    std::span<const uint8_t> ext_data)
{
    Tls13ServerHelloExtensions result;
    TlsReader r(ext_data);

    while (!r.at_end()) {
        auto ext_type = static_cast<ExtensionType>(r.read_u16());
        uint16_t ext_len = r.read_u16();
        auto ext_body = r.sub_reader(ext_len);

        if (ext_type == ExtensionType::supported_versions) {
            result.selected_version = read_supported_versions_server(ext_body);
            result.has_supported_versions = true;
        } else if (ext_type == ExtensionType::key_share) {
            result.server_share = read_key_share_server(ext_body);
            result.has_key_share = true;
        }
        // Other extensions are silently ignored
    }

    return result;
}

// --- Full ClientHello extension block for TLS 1.3 ---

// Writes the complete extension block for a TLS 1.3-capable ClientHello.
// Includes both TLS 1.2 compatibility extensions and TLS 1.3 extensions.
template <size_t Cap>
constexpr void write_tls13_client_hello_extensions(
    TlsWriter<Cap>& w,
    std::span<const NamedCurve> curves,
    std::span<const SignatureScheme> sig_schemes,
    std::span<const KeyShareEntry> key_shares,
    std::string_view hostname = {},
    std::span<const std::string_view> alpn_protocols = {})
{
    // Outer extensions length placeholder
    size_t ext_list_pos = w.position();
    w.write_u16(0);

    // server_name / SNI (type 0) — RFC 6066 Section 3
    if (!hostname.empty()) {
        w.write_u16(static_cast<uint16_t>(ExtensionType::server_name));
        auto name_len = static_cast<uint16_t>(hostname.size());
        auto entry_len = static_cast<uint16_t>(1 + 2 + name_len);
        auto list_len = static_cast<uint16_t>(2 + entry_len);
        w.write_u16(list_len);
        w.write_u16(entry_len);
        w.write_u8(0); // host_name type
        w.write_u16(name_len);
        w.write_bytes(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(hostname.data()), hostname.size()));
    }

    // supported_groups (type 10)
    {
        w.write_u16(static_cast<uint16_t>(ExtensionType::supported_groups));
        auto data_len = static_cast<uint16_t>(2 + curves.size() * 2);
        w.write_u16(data_len);
        w.write_u16(static_cast<uint16_t>(curves.size() * 2));
        for (size_t i = 0; i < curves.size(); ++i)
            w.write_u16(static_cast<uint16_t>(curves[i]));
    }

    // signature_algorithms (type 13) — using TLS 1.3 SignatureScheme values
    write_signature_algorithms_13(w, sig_schemes);

    // supported_versions (type 43) — offer TLS 1.3 and TLS 1.2
    {
        ProtocolVersion versions[] = {TLS_1_3, TLS_1_2};
        write_supported_versions_client(w, versions);
    }

    // key_share (type 51) — pre-generated ephemeral keys
    write_key_share_client(w, key_shares);

    // psk_key_exchange_modes (type 45) — required for future PSK support
    write_psk_key_exchange_modes(w);

    // application_layer_protocol_negotiation (type 16) — RFC 7301
    if (!alpn_protocols.empty()) {
        w.write_u16(static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation));
        uint16_t list_len = 0;
        for (size_t i = 0; i < alpn_protocols.size(); ++i)
            list_len = static_cast<uint16_t>(list_len + 1 + alpn_protocols[i].size());
        w.write_u16(static_cast<uint16_t>(2 + list_len));
        w.write_u16(list_len);
        for (size_t i = 0; i < alpn_protocols.size(); ++i) {
            w.write_u8(static_cast<uint8_t>(alpn_protocols[i].size()));
            for (size_t j = 0; j < alpn_protocols[i].size(); ++j)
                w.write_u8(static_cast<uint8_t>(alpn_protocols[i][j]));
        }
    }

    // Patch total extensions length
    auto total = static_cast<uint16_t>(w.position() - ext_list_pos - 2);
    w.patch_u16(ext_list_pos, total);
}

// --- Server-side extension writers ---

// supported_versions for ServerHello — single selected version.
template <size_t Cap>
constexpr void write_supported_versions_server(TlsWriter<Cap>& w, ProtocolVersion version) {
    w.write_u16(static_cast<uint16_t>(ExtensionType::supported_versions));
    w.write_u16(2); // extension data length
    w.write_u8(version.major);
    w.write_u8(version.minor);
}

// key_share for ServerHello — single selected share.
template <size_t Cap>
constexpr void write_key_share_server(TlsWriter<Cap>& w, const KeyShareEntry& entry) {
    w.write_u16(static_cast<uint16_t>(ExtensionType::key_share));
    auto key_len = static_cast<uint16_t>(entry.key_exchange.size());
    w.write_u16(static_cast<uint16_t>(4 + key_len)); // extension data length
    w.write_u16(static_cast<uint16_t>(entry.group));
    w.write_u16(key_len);
    w.write_bytes(std::span<const uint8_t>(
        entry.key_exchange.data.data(), entry.key_exchange.len));
}

} // namespace tls
