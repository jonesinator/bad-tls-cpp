/**
 * DTLS handshake message tests.
 *
 * Tests HelloVerifyRequest, DTLS ClientHello, and handshake message
 * serialization with DTLS headers.
 */

#include <tls/dtls_handshake.hpp>
#include <cassert>
#include <cstdio>

using namespace tls;

static void test_hello_verify_request_roundtrip() {
    HelloVerifyRequest hvr;
    hvr.server_version = DTLS_1_2;
    for (uint8_t i = 0; i < 32; ++i)
        hvr.cookie.push_back(i);

    TlsWriter<256> w;
    write_hello_verify_request(w, 0, hvr);

    // Parse: DTLS handshake header (12 bytes) + body
    TlsReader r(w.data());
    auto hdr = read_dtls_handshake_header(r);
    assert(hdr.type == HandshakeType::hello_verify_request);
    assert(hdr.message_seq == 0);
    assert(hdr.fragment_offset == 0);
    assert(hdr.fragment_length == hdr.length);

    auto body = r.read_bytes(hdr.fragment_length);
    TlsReader body_r(body);
    auto parsed = read_hello_verify_request(body_r);
    assert(parsed.server_version == DTLS_1_2);
    assert(parsed.cookie.size() == 32);
    for (uint8_t i = 0; i < 32; ++i)
        assert(parsed.cookie[i] == i);

    std::printf("  hello_verify_request_roundtrip: PASS\n");
}

static void test_dtls_client_hello_roundtrip() {
    DtlsClientHello ch;
    ch.client_version = DTLS_1_2;
    for (size_t i = 0; i < 32; ++i) ch.random[i] = static_cast<uint8_t>(i);
    ch.session_id.length = 0;
    for (uint8_t i = 0; i < 16; ++i)
        ch.cookie.push_back(i + 0xA0);
    ch.cipher_suites.push_back(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    ch.compression_methods.push_back(CompressionMethod::null);

    TlsWriter<2048> w;
    write_dtls_client_hello(w, 1, ch);

    TlsReader r(w.data());
    auto hdr = read_dtls_handshake_header(r);
    assert(hdr.type == HandshakeType::client_hello);
    assert(hdr.message_seq == 1);
    assert(hdr.fragment_offset == 0);
    assert(hdr.fragment_length == hdr.length);

    auto body = r.read_bytes(hdr.fragment_length);
    TlsReader body_r(body);
    auto parsed = read_dtls_client_hello(body_r);
    assert(parsed.client_version == DTLS_1_2);
    for (size_t i = 0; i < 32; ++i)
        assert(parsed.random[i] == static_cast<uint8_t>(i));
    assert(parsed.cookie.size() == 16);
    for (uint8_t i = 0; i < 16; ++i)
        assert(parsed.cookie[i] == i + 0xA0);
    assert(parsed.cipher_suites.size() == 1);
    assert(parsed.cipher_suites[0] == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);

    std::printf("  dtls_client_hello_roundtrip: PASS\n");
}

static void test_dtls_client_hello_no_cookie() {
    DtlsClientHello ch;
    ch.client_version = DTLS_1_2;
    for (size_t i = 0; i < 32; ++i) ch.random[i] = 0;
    ch.session_id.length = 0;
    // No cookie
    ch.cipher_suites.push_back(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    ch.compression_methods.push_back(CompressionMethod::null);

    TlsWriter<2048> w;
    write_dtls_client_hello(w, 0, ch);

    TlsReader r(w.data());
    auto hdr = read_dtls_handshake_header(r);
    auto body = r.read_bytes(hdr.fragment_length);
    TlsReader body_r(body);
    auto parsed = read_dtls_client_hello(body_r);
    assert(parsed.cookie.size() == 0);

    std::printf("  dtls_client_hello_no_cookie: PASS\n");
}

static void test_dtls_finished_roundtrip() {
    Finished fin;
    for (size_t i = 0; i < 12; ++i)
        fin.verify_data[i] = static_cast<uint8_t>(0xA0 + i);

    TlsWriter<64> w;
    write_dtls_finished(w, 7, fin);

    TlsReader r(w.data());
    auto hdr = read_dtls_handshake_header(r);
    assert(hdr.type == HandshakeType::finished);
    assert(hdr.message_seq == 7);
    assert(hdr.length == 12);
    assert(hdr.fragment_length == 12);

    auto parsed = read_finished(r);
    for (size_t i = 0; i < 12; ++i)
        assert(parsed.verify_data[i] == static_cast<uint8_t>(0xA0 + i));

    std::printf("  dtls_finished_roundtrip: PASS\n");
}

static void test_dtls_server_hello_done() {
    TlsWriter<64> w;
    write_dtls_server_hello_done(w, 4);

    TlsReader r(w.data());
    auto hdr = read_dtls_handshake_header(r);
    assert(hdr.type == HandshakeType::server_hello_done);
    assert(hdr.message_seq == 4);
    assert(hdr.length == 0);
    assert(hdr.fragment_length == 0);

    std::printf("  dtls_server_hello_done: PASS\n");
}

int main() {
    std::printf("DTLS handshake tests:\n");
    test_hello_verify_request_roundtrip();
    test_dtls_client_hello_roundtrip();
    test_dtls_client_hello_no_cookie();
    test_dtls_finished_roundtrip();
    test_dtls_server_hello_done();
    std::printf("All DTLS handshake tests passed.\n");
    return 0;
}
