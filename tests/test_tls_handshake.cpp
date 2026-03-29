#include <tls/handshake.hpp>
#include <cassert>

void test_client_hello_serialize() {
    constexpr auto test = [] {
        tls::ClientHello ch;
        ch.client_version = tls::TLS_1_2;
        for (size_t i = 0; i < 32; ++i) ch.random[i] = static_cast<uint8_t>(i);
        ch.session_id.length = 0;
        ch.cipher_suites.push_back(tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        ch.cipher_suites.push_back(tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        ch.compression_methods.push_back(tls::CompressionMethod::null);

        // Build extensions
        tls::TlsWriter<512> ext_w;
        std::array<tls::NamedCurve, 2> curves = {
            tls::NamedCurve::secp256r1, tls::NamedCurve::secp384r1};
        std::array<tls::SignatureAndHashAlgorithm, 2> sig_algs = {{
            {tls::HashAlgorithm::sha256, tls::SignatureAlgorithm::rsa},
            {tls::HashAlgorithm::sha256, tls::SignatureAlgorithm::ecdsa},
        }};
        tls::write_client_hello_extensions(ext_w, curves, sig_algs);
        for (size_t i = 0; i < ext_w.size(); ++i)
            ch.extensions.push_back(ext_w.data()[i]);

        // Serialize
        tls::TlsWriter<1024> w;
        tls::write_client_hello(w, ch);

        auto data = w.data();
        // First byte should be HandshakeType::client_hello = 1
        if (data[0] != 1) throw "wrong handshake type";
        // Bytes 1-3: 24-bit length
        uint32_t body_len = (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
        // Total message = 4 (header) + body_len
        if (4 + body_len != data.size()) throw "length mismatch";

        // After header: version(2) + random(32) + session_id_len(1) + cipher_suites_len(2) + suites(4) + comp_len(1) + comp(1) + extensions
        if (data[4] != 3 || data[5] != 3) throw "wrong version in body";

        // Random starts at offset 6
        if (data[6] != 0x00 || data[7] != 0x01) throw "wrong random";

        return true;
    };
    static_assert(test());
}

void test_server_hello_parse() {
    constexpr auto test = [] {
        // Build a ServerHello wire format manually
        tls::TlsWriter<256> w;
        // version
        w.write_u8(3); w.write_u8(3);
        // random (32 bytes)
        for (int i = 0; i < 32; ++i) w.write_u8(static_cast<uint8_t>(0x80 + i));
        // session_id: length 4 + 4 bytes
        w.write_u8(4);
        w.write_u8(0xAA); w.write_u8(0xBB); w.write_u8(0xCC); w.write_u8(0xDD);
        // cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
        w.write_u16(0xC02F);
        // compression: null
        w.write_u8(0);

        tls::TlsReader r(w.data());
        auto sh = tls::read_server_hello(r);

        if (!(sh.server_version == tls::TLS_1_2)) throw "version mismatch";
        if (sh.random[0] != 0x80 || sh.random[31] != 0x9F) throw "random mismatch";
        if (sh.session_id.length != 4) throw "session_id length mismatch";
        if (sh.session_id.data[0] != 0xAA) throw "session_id data mismatch";
        if (sh.cipher_suite != tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            throw "cipher_suite mismatch";
        if (sh.compression_method != tls::CompressionMethod::null) throw "compression mismatch";
        return true;
    };
    static_assert(test());
}

void test_certificate_parse() {
    constexpr auto test = [] {
        // Build a Certificate message: total_len(3) + [cert_len(3) + cert_data]*
        tls::TlsWriter<256> w;
        // Two certs: one of 3 bytes, one of 2 bytes
        uint32_t total = 3 + 3 + 3 + 2; // cert1_len(3) + cert1(3) + cert2_len(3) + cert2(2)
        w.write_u24(total);
        w.write_u24(3); w.write_u8(0x30); w.write_u8(0x82); w.write_u8(0x01); // cert1
        w.write_u24(2); w.write_u8(0x30); w.write_u8(0x00);                    // cert2

        tls::TlsReader r(w.data());
        auto cm = tls::read_certificate(r);

        if (cm.certificate_list.size() != 2) throw "wrong cert count";
        if (cm.certificate_list[0].size() != 3) throw "cert1 wrong size";
        if (cm.certificate_list[0][0] != 0x30) throw "cert1 wrong data";
        if (cm.certificate_list[1].size() != 2) throw "cert2 wrong size";
        return true;
    };
    static_assert(test());
}

void test_server_key_exchange_ecdhe_parse() {
    constexpr auto test = [] {
        tls::TlsWriter<256> w;
        // curve_type: named_curve = 3
        w.write_u8(3);
        // named_curve: secp256r1 = 23
        w.write_u16(23);
        // public_key: length + 5 dummy bytes (0x04 + x + y placeholder)
        w.write_u8(5);
        w.write_u8(0x04); w.write_u8(0x01); w.write_u8(0x02);
        w.write_u8(0x03); w.write_u8(0x04);
        // sig_algorithm: sha256(4) + rsa(1)
        w.write_u8(4); w.write_u8(1);
        // signature: length(2) + 3 bytes
        w.write_u16(3);
        w.write_u8(0xAA); w.write_u8(0xBB); w.write_u8(0xCC);

        tls::TlsReader r(w.data());
        auto ske = tls::read_server_key_exchange_ecdhe(r);

        if (ske.named_curve != tls::NamedCurve::secp256r1) throw "curve mismatch";
        if (ske.public_key.size() != 5) throw "pubkey size mismatch";
        if (ske.public_key[0] != 0x04) throw "pubkey format mismatch";
        if (ske.sig_algorithm.hash != tls::HashAlgorithm::sha256) throw "hash mismatch";
        if (ske.sig_algorithm.signature != tls::SignatureAlgorithm::rsa) throw "sig mismatch";
        if (ske.signature.size() != 3) throw "sig size mismatch";
        if (ske.signature[0] != 0xAA) throw "sig data mismatch";
        return true;
    };
    static_assert(test());
}

void test_finished_roundtrip() {
    constexpr auto test = [] {
        tls::Finished fin;
        for (int i = 0; i < 12; ++i) fin.verify_data[i] = static_cast<uint8_t>(0xF0 + i);

        tls::TlsWriter<32> w;
        tls::write_finished(w, fin);

        auto data = w.data();
        // Header: type(1) + length(3) + verify_data(12) = 16 bytes
        if (data.size() != 16) throw "wrong size";
        if (data[0] != 20) throw "wrong type"; // HandshakeType::finished = 20
        if (data[1] != 0 || data[2] != 0 || data[3] != 12) throw "wrong length";
        if (data[4] != 0xF0) throw "wrong verify_data";

        // Parse body (after header)
        auto body = std::span<const uint8_t>(data.data() + 4, 12);
        tls::TlsReader r(body);
        auto parsed = tls::read_finished(r);
        for (int i = 0; i < 12; ++i)
            if (parsed.verify_data[i] != fin.verify_data[i]) throw "roundtrip mismatch";
        return true;
    };
    static_assert(test());
}

void test_client_key_exchange_ecdhe() {
    constexpr auto test = [] {
        tls::ClientKeyExchangeEcdhe cke;
        cke.public_key.push_back(0x04);
        for (int i = 0; i < 64; ++i)
            cke.public_key.push_back(static_cast<uint8_t>(i));

        tls::TlsWriter<128> w;
        tls::write_client_key_exchange_ecdhe(w, cke);

        auto data = w.data();
        // Header: type(1) + length(3) + point_len(1) + point(65) = 70 bytes
        if (data[0] != 16) throw "wrong type"; // HandshakeType::client_key_exchange = 16
        uint32_t body_len = (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
        if (body_len != 66) throw "wrong body length"; // 1 (point_len) + 65 (point)
        if (data[4] != 65) throw "wrong point length";
        if (data[5] != 0x04) throw "wrong point format";
        if (data[6] != 0x00) throw "wrong point data";
        return true;
    };
    static_assert(test());
}

int main() {
    test_client_hello_serialize();
    test_server_hello_parse();
    test_certificate_parse();
    test_server_key_exchange_ecdhe_parse();
    test_finished_roundtrip();
    test_client_key_exchange_ecdhe();
    return 0;
}
