#include <tls/tls13_extensions.hpp>
#include <cassert>

using namespace tls;

void test_supported_versions_round_trip() {
    // Write supported_versions client extension
    TlsWriter<64> w;
    ProtocolVersion versions[] = {TLS_1_3, TLS_1_2};
    write_supported_versions_client(w, versions);

    auto data = w.data();
    TlsReader r(data);

    // Extension type
    assert(r.read_u16() == static_cast<uint16_t>(ExtensionType::supported_versions));
    uint16_t ext_len = r.read_u16();
    assert(ext_len == 5); // 1 (list len) + 2*2 (two versions)

    uint8_t list_len = r.read_u8();
    assert(list_len == 4);

    // First version: TLS 1.3 = {3, 4}
    assert(r.read_u8() == 3);
    assert(r.read_u8() == 4);
    // Second version: TLS 1.2 = {3, 3}
    assert(r.read_u8() == 3);
    assert(r.read_u8() == 3);
    assert(r.at_end());
}

void test_supported_versions_server() {
    // Write server extension
    TlsWriter<64> w;
    write_supported_versions_server(w, TLS_1_3);

    auto data = w.data();
    TlsReader r(data);

    assert(r.read_u16() == static_cast<uint16_t>(ExtensionType::supported_versions));
    uint16_t ext_len = r.read_u16();
    assert(ext_len == 2);

    auto version = read_supported_versions_server(r);
    assert(version == TLS_1_3);
}

void test_key_share_round_trip() {
    // Create a fake x25519 key share (32 bytes)
    KeyShareEntry entry;
    entry.group = NamedCurve::x25519;
    for (uint8_t i = 0; i < 32; ++i)
        entry.key_exchange.push_back(i + 1);

    // Write client key_share
    TlsWriter<128> w;
    KeyShareEntry entries[] = {entry};
    write_key_share_client(w, entries);

    auto data = w.data();
    TlsReader r(data);

    assert(r.read_u16() == static_cast<uint16_t>(ExtensionType::key_share));
    uint16_t ext_len = r.read_u16();
    assert(ext_len == 2 + 4 + 32); // shares_len(2) + group(2) + key_len(2) + key(32)

    uint16_t shares_len = r.read_u16();
    assert(shares_len == 4 + 32);

    // Parse the entry
    auto parsed = read_key_share_server(r); // same wire format for single entry
    assert(parsed.group == NamedCurve::x25519);
    assert(parsed.key_exchange.size() == 32);
    for (uint8_t i = 0; i < 32; ++i)
        assert(parsed.key_exchange[i] == i + 1);
}

void test_key_share_server_round_trip() {
    KeyShareEntry entry;
    entry.group = NamedCurve::secp256r1;
    // Fake P-256 uncompressed point (65 bytes)
    entry.key_exchange.push_back(0x04);
    for (uint8_t i = 0; i < 64; ++i)
        entry.key_exchange.push_back(i);

    TlsWriter<128> w;
    write_key_share_server(w, entry);

    auto data = w.data();
    TlsReader r(data);

    assert(r.read_u16() == static_cast<uint16_t>(ExtensionType::key_share));
    uint16_t ext_len = r.read_u16();
    auto ext_body = r.sub_reader(ext_len);

    auto parsed = read_key_share_server(ext_body);
    assert(parsed.group == NamedCurve::secp256r1);
    assert(parsed.key_exchange.size() == 65);
    assert(parsed.key_exchange[0] == 0x04);
}

void test_signature_algorithms_13() {
    SignatureScheme schemes[] = {
        SignatureScheme::ecdsa_secp256r1_sha256,
        SignatureScheme::rsa_pss_rsae_sha256,
    };

    TlsWriter<64> w;
    write_signature_algorithms_13(w, schemes);

    auto data = w.data();
    TlsReader r(data);

    assert(r.read_u16() == static_cast<uint16_t>(ExtensionType::signature_algorithms));
    uint16_t ext_len = r.read_u16();
    assert(ext_len == 2 + 4); // list_len(2) + 2 schemes * 2 bytes

    uint16_t list_len = r.read_u16();
    assert(list_len == 4);

    assert(r.read_u16() == 0x0403); // ecdsa_secp256r1_sha256
    assert(r.read_u16() == 0x0804); // rsa_pss_rsae_sha256
}

void test_psk_key_exchange_modes() {
    TlsWriter<16> w;
    write_psk_key_exchange_modes(w);

    auto data = w.data();
    TlsReader r(data);

    assert(r.read_u16() == static_cast<uint16_t>(ExtensionType::psk_key_exchange_modes));
    uint16_t ext_len = r.read_u16();
    assert(ext_len == 2);
    assert(r.read_u8() == 1); // modes list length
    assert(r.read_u8() == 1); // psk_dhe_ke
}

void test_parse_server_hello_extensions_13() {
    // Build fake ServerHello extensions with supported_versions + key_share
    TlsWriter<128> w;
    write_supported_versions_server(w, TLS_1_3);

    KeyShareEntry share;
    share.group = NamedCurve::x25519;
    for (uint8_t i = 0; i < 32; ++i)
        share.key_exchange.push_back(0xAA);
    write_key_share_server(w, share);

    auto result = parse_server_hello_extensions_13(w.data());
    assert(result.has_supported_versions);
    assert(result.selected_version == TLS_1_3);
    assert(result.has_key_share);
    assert(result.server_share.group == NamedCurve::x25519);
    assert(result.server_share.key_exchange.size() == 32);
    assert(result.server_share.key_exchange[0] == 0xAA);
}

void test_full_client_hello_extensions() {
    NamedCurve curves[] = {NamedCurve::x25519, NamedCurve::secp256r1};
    SignatureScheme schemes[] = {
        SignatureScheme::ecdsa_secp256r1_sha256,
        SignatureScheme::rsa_pss_rsae_sha256,
    };

    KeyShareEntry share;
    share.group = NamedCurve::x25519;
    for (uint8_t i = 0; i < 32; ++i)
        share.key_exchange.push_back(i);
    KeyShareEntry shares[] = {share};

    TlsWriter<1024> w;
    write_tls13_client_hello_extensions(w, curves, schemes, shares, "example.com");

    // Verify the outer structure: 2-byte length prefix, then extension list
    auto data = w.data();
    TlsReader r(data);
    uint16_t total_len = r.read_u16();
    assert(total_len == data.size() - 2);

    // Walk through extensions and check types are present
    bool has_sni = false, has_groups = false, has_sigalgs = false;
    bool has_versions = false, has_keyshare = false, has_psk_modes = false;

    while (!r.at_end()) {
        auto ext_type = static_cast<ExtensionType>(r.read_u16());
        uint16_t ext_len = r.read_u16();
        r.read_bytes(ext_len); // skip body

        if (ext_type == ExtensionType::server_name) has_sni = true;
        if (ext_type == ExtensionType::supported_groups) has_groups = true;
        if (ext_type == ExtensionType::signature_algorithms) has_sigalgs = true;
        if (ext_type == ExtensionType::supported_versions) has_versions = true;
        if (ext_type == ExtensionType::key_share) has_keyshare = true;
        if (ext_type == ExtensionType::psk_key_exchange_modes) has_psk_modes = true;
    }

    assert(has_sni);
    assert(has_groups);
    assert(has_sigalgs);
    assert(has_versions);
    assert(has_keyshare);
    assert(has_psk_modes);
}

int main() {
    test_supported_versions_round_trip();
    test_supported_versions_server();
    test_key_share_round_trip();
    test_key_share_server_round_trip();
    test_signature_algorithms_13();
    test_psk_key_exchange_modes();
    test_parse_server_hello_extensions_13();
    test_full_client_hello_extensions();
    return 0;
}
