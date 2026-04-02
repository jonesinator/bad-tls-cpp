#include <tls/tls13_handshake.hpp>
#include <cassert>
#include <cstring>

using namespace tls;

void test_encrypted_extensions_round_trip() {
    // Write EncryptedExtensions with empty extensions
    TlsWriter<64> w;
    write_tls13_encrypted_extensions(w, {});

    auto data = w.data();
    TlsReader r(data);

    auto hdr = read_handshake_header(r);
    assert(hdr.type == HandshakeType::encrypted_extensions);
    assert(hdr.length == 2); // just the 2-byte extensions length

    auto msg = read_tls13_encrypted_extensions(r);
    assert(msg.extensions.empty());
}

void test_encrypted_extensions_with_alpn() {
    // Build ALPN extension data: type(2) + len(2) + list_len(2) + proto_len(1) + proto
    TlsWriter<64> ext_w;
    ext_w.write_u16(static_cast<uint16_t>(ExtensionType::application_layer_protocol_negotiation));
    ext_w.write_u16(5);  // extension data length
    ext_w.write_u16(3);  // protocol_name_list length
    ext_w.write_u8(2);   // protocol name length
    ext_w.write_u8('h');
    ext_w.write_u8('2');

    // Write EncryptedExtensions
    TlsWriter<128> w;
    write_tls13_encrypted_extensions(w, ext_w.data());

    auto data = w.data();
    TlsReader r(data);

    auto hdr = read_handshake_header(r);
    assert(hdr.type == HandshakeType::encrypted_extensions);

    auto msg = read_tls13_encrypted_extensions(r);
    auto alpn = parse_alpn_from_extensions(msg.extensions);
    assert(alpn == "h2");
}

void test_tls13_certificate_round_trip() {
    // Create fake cert chain
    std::vector<uint8_t> cert1 = {0x30, 0x82, 0x01, 0x00}; // fake DER
    std::vector<uint8_t> cert2 = {0x30, 0x82, 0x02, 0x00};
    std::vector<std::vector<uint8_t>> chain = {cert1, cert2};

    TlsWriter<256> w;
    write_tls13_certificate(w, {}, chain);

    auto data = w.data();
    TlsReader r(data);

    auto hdr = read_handshake_header(r);
    assert(hdr.type == HandshakeType::certificate);

    auto msg = read_tls13_certificate(r);
    assert(msg.certificate_request_context.empty());
    assert(msg.entries.size() == 2);
    assert(msg.entries[0].cert_data == cert1);
    assert(msg.entries[1].cert_data == cert2);
    assert(msg.entries[0].extensions.empty());
    assert(msg.entries[1].extensions.empty());
}

void test_certificate_verify_content() {
    // RFC 8446 Section 4.4.3: the content to be signed is:
    //   0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
    std::array<uint8_t, 32> transcript_hash{};
    for (size_t i = 0; i < 32; ++i) transcript_hash[i] = static_cast<uint8_t>(i);

    auto content = build_tls13_certificate_verify_content(true, transcript_hash);

    // Check total length: 64 + 33 + 1 + 32 = 130
    assert(content.size() == 130);

    // First 64 bytes are 0x20
    for (size_t i = 0; i < 64; ++i)
        assert(content[i] == 0x20);

    // Context string
    const char* expected_ctx = "TLS 1.3, server CertificateVerify";
    for (size_t i = 0; i < 33; ++i)
        assert(content[64 + i] == static_cast<uint8_t>(expected_ctx[i]));

    // Separator
    assert(content[97] == 0x00);

    // Transcript hash
    for (size_t i = 0; i < 32; ++i)
        assert(content[98 + i] == static_cast<uint8_t>(i));

    // Client version
    auto client_content = build_tls13_certificate_verify_content(false, transcript_hash);
    assert(client_content.size() == 130);
    const char* client_ctx = "TLS 1.3, client CertificateVerify";
    for (size_t i = 0; i < 33; ++i)
        assert(client_content[64 + i] == static_cast<uint8_t>(client_ctx[i]));
}

void test_certificate_verify_round_trip() {
    CertificateVerify msg;
    msg.algorithm.hash = HashAlgorithm::rsa_pss;
    msg.algorithm.signature = static_cast<SignatureAlgorithm>(4); // sha256
    for (uint8_t i = 0; i < 64; ++i)
        msg.signature.push_back(i);

    TlsWriter<256> w;
    write_tls13_certificate_verify(w, msg);

    auto data = w.data();
    TlsReader r(data);

    auto hdr = read_handshake_header(r);
    assert(hdr.type == HandshakeType::certificate_verify);

    auto parsed = read_tls13_certificate_verify(r);
    assert(parsed.algorithm.hash == HashAlgorithm::rsa_pss);
    assert(parsed.signature.size() == 64);
    for (uint8_t i = 0; i < 64; ++i)
        assert(parsed.signature[i] == i);
}

void test_tls13_finished_round_trip() {
    // SHA-256: 32-byte verify_data
    std::array<uint8_t, 32> verify_data{};
    for (size_t i = 0; i < 32; ++i) verify_data[i] = static_cast<uint8_t>(i + 0x10);

    TlsWriter<64> w;
    write_tls13_finished(w, verify_data);

    auto data = w.data();
    TlsReader r(data);

    auto hdr = read_handshake_header(r);
    assert(hdr.type == HandshakeType::finished);
    assert(hdr.length == 32);

    auto msg = read_tls13_finished(r, 32);
    assert(msg.verify_data.size() == 32);
    for (size_t i = 0; i < 32; ++i)
        assert(msg.verify_data[i] == static_cast<uint8_t>(i + 0x10));

    // SHA-384: 48-byte verify_data
    std::array<uint8_t, 48> verify_data_384{};
    for (size_t i = 0; i < 48; ++i) verify_data_384[i] = static_cast<uint8_t>(i);

    TlsWriter<80> w2;
    write_tls13_finished(w2, verify_data_384);

    auto data2 = w2.data();
    TlsReader r2(data2);

    auto hdr2 = read_handshake_header(r2);
    assert(hdr2.type == HandshakeType::finished);
    assert(hdr2.length == 48);

    auto msg2 = read_tls13_finished(r2, 48);
    assert(msg2.verify_data.size() == 48);
}

int main() {
    test_encrypted_extensions_round_trip();
    test_encrypted_extensions_with_alpn();
    test_tls13_certificate_round_trip();
    test_certificate_verify_content();
    test_certificate_verify_round_trip();
    test_tls13_finished_round_trip();
    return 0;
}
