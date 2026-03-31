/**
 * TLS 1.2 client handshake test.
 *
 * Constructs a scripted memory_transport with pre-computed server responses,
 * runs the client handshake, and verifies completion.
 *
 * Uses xoshiro256ss for deterministic client randomness and a known
 * ECDSA P-256 server key for the test certificate.
 */

#include <tls/client.hpp>
#include <crypto/ecdsa.hpp>
#include <crypto/ecc.hpp>
#include <cassert>

using namespace tls;
using namespace asn1::x509;

// --- Helpers ---

// Build a minimal self-signed X.509 certificate DER from an EC P-256 key.
std::vector<uint8_t> build_test_certificate(
    const point<p256_curve>& pub_key,
    const uint512& priv_key)
{
    asn1::der::Writer tbs;
    tbs.write_constructed(0x30, [&](asn1::der::Writer& s) {
        // version [0] EXPLICIT INTEGER = v3
        s.write_constructed(0xA0, [&](asn1::der::Writer& v) {
            v.write(asn1::der::Integer::from_int64(2));
        });
        s.write(asn1::der::Integer::from_int64(1)); // serial
        // signature algorithm: ecdsa-with-SHA256
        s.write_constructed(0x30, [&](asn1::der::Writer& alg) {
            alg.write(asn1::der::ObjectIdentifier::from_string("1.2.840.10045.4.3.2"));
        });
        // issuer: CN=test
        s.write_constructed(0x30, [&](asn1::der::Writer& nm) {
            nm.write_constructed(0x31, [&](asn1::der::Writer& rdn) {
                rdn.write_constructed(0x30, [&](asn1::der::Writer& atv) {
                    atv.write(asn1::der::ObjectIdentifier::from_string("2.5.4.3"));
                    atv.write_tag(0x00, false, 12);
                    std::array<uint8_t, 4> cn = {'t','e','s','t'};
                    atv.write_length(4); atv.write_bytes(cn);
                });
            });
        });
        // validity
        s.write_constructed(0x30, [&](asn1::der::Writer& v) {
            std::array<uint8_t, 13> nb = {'2','5','0','1','0','1','0','0','0','0','0','0','Z'};
            v.write_tag(0x00, false, 23); v.write_length(13); v.write_bytes(nb);
            std::array<uint8_t, 13> na = {'3','5','0','1','0','1','0','0','0','0','0','0','Z'};
            v.write_tag(0x00, false, 23); v.write_length(13); v.write_bytes(na);
        });
        // subject: CN=test
        s.write_constructed(0x30, [&](asn1::der::Writer& nm) {
            nm.write_constructed(0x31, [&](asn1::der::Writer& rdn) {
                rdn.write_constructed(0x30, [&](asn1::der::Writer& atv) {
                    atv.write(asn1::der::ObjectIdentifier::from_string("2.5.4.3"));
                    atv.write_tag(0x00, false, 12);
                    std::array<uint8_t, 4> cn = {'t','e','s','t'};
                    atv.write_length(4); atv.write_bytes(cn);
                });
            });
        });
        // SubjectPublicKeyInfo
        s.write_constructed(0x30, [&](asn1::der::Writer& spki) {
            spki.write_constructed(0x30, [&](asn1::der::Writer& alg) {
                alg.write(asn1::der::ObjectIdentifier::from_string("1.2.840.10045.2.1"));
                alg.write(asn1::der::ObjectIdentifier::from_string("1.2.840.10045.3.1.7"));
            });
            auto x_bytes = pub_key.x().value().to_bytes(std::endian::big);
            auto y_bytes = pub_key.y().value().to_bytes(std::endian::big);
            asn1::der::BitString bs;
            bs.unused_bits = 0;
            bs.bytes.push_back(0x04);
            for (size_t i = 0; i < 32; ++i) bs.bytes.push_back(x_bytes[x_bytes.size() - 32 + i]);
            for (size_t i = 0; i < 32; ++i) bs.bytes.push_back(y_bytes[y_bytes.size() - 32 + i]);
            spki.write(bs);
        });
    });
    auto tbs_bytes = std::move(tbs).finish();

    auto tbs_hash = sha256(tbs_bytes);
    auto sig = ecdsa_sign<p256_curve, sha256_state>(priv_key, tbs_hash);

    // DER-encode ECDSA signature
    auto encode_sig = [](const ecdsa_signature<p256_curve>& sig) {
        asn1::der::Writer sw;
        sw.write_constructed(0x30, [&](asn1::der::Writer& seq) {
            auto encode_int = [&](const uint512& val) {
                auto bytes = val.to_bytes(std::endian::big);
                size_t start = 0;
                while (start < bytes.size() - 1 && bytes[start] == 0) ++start;
                std::vector<uint8_t> v(bytes.begin() + start, bytes.end());
                if (v[0] & 0x80) v.insert(v.begin(), 0x00);
                asn1::der::Integer i; i.bytes = v;
                seq.write(i);
            };
            encode_int(sig.r);
            encode_int(sig.s);
        });
        return std::move(sw).finish();
    };
    auto sig_der = encode_sig(sig);

    asn1::der::Writer cert_w;
    cert_w.write_constructed(0x30, [&](asn1::der::Writer& c) {
        c.write_bytes(tbs_bytes);
        c.write_constructed(0x30, [&](asn1::der::Writer& alg) {
            alg.write(asn1::der::ObjectIdentifier::from_string("1.2.840.10045.4.3.2"));
        });
        asn1::der::BitString sig_bs;
        sig_bs.unused_bits = 0;
        for (auto b : sig_der) sig_bs.bytes.push_back(b);
        c.write(sig_bs);
    });
    return std::move(cert_w).finish();
}

std::vector<uint8_t> make_record(ContentType type, std::span<const uint8_t> fragment) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(type));
    out.push_back(3); out.push_back(3);
    out.push_back(static_cast<uint8_t>(fragment.size() >> 8));
    out.push_back(static_cast<uint8_t>(fragment.size()));
    out.insert(out.end(), fragment.begin(), fragment.end());
    return out;
}

void test_concept_satisfaction() {
    static_assert(transport<memory_transport>);
}

void test_full_handshake() {
    // Server's ECDSA P-256 identity key
    auto server_priv = uint512::from_bytes(std::array<uint8_t, 32>{
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20});

    using fe = field_element<p256_curve>;
    point<p256_curve> G{fe{p256_curve::gx()}, fe{p256_curve::gy()}};
    auto server_pub = G.scalar_mul(server_priv);
    auto cert_der = build_test_certificate(server_pub, server_priv);

    // Server's ephemeral ECDH key
    auto server_ecdh_priv = uint512::from_bytes(std::array<uint8_t, 32>{
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99});
    auto server_ecdh_kp = ecdh_keypair_from_private<p256_curve>(server_ecdh_priv);

    // Pre-compute client random (xoshiro256ss(42) first 32 bytes)
    xoshiro256ss sim_rng(42);
    auto expected_client_random = random_bytes<32>(sim_rng);

    // Pre-compute client's ephemeral key (next random_scalar from same RNG)
    auto client_ecdh_priv = random_scalar<p256_curve>(sim_rng);
    auto client_ecdh_kp = ecdh_keypair_from_private<p256_curve>(client_ecdh_priv);

    Random server_random{};
    for (size_t i = 0; i < 32; ++i) server_random[i] = static_cast<uint8_t>(0xB0 + i);

    // --- Build ServerHello ---
    TlsWriter<256> sh_w;
    sh_w.write_u8(static_cast<uint8_t>(HandshakeType::server_hello));
    sh_w.write_u24(0); size_t sh_body_start = sh_w.position();
    sh_w.write_u8(3); sh_w.write_u8(3);
    sh_w.write_bytes(server_random);
    sh_w.write_u8(0); // empty session_id
    sh_w.write_u16(0xC02B); // ECDHE_ECDSA_AES128_GCM_SHA256
    sh_w.write_u8(0); // null compression
    sh_w.patch_u24(1, static_cast<uint32_t>(sh_w.position() - sh_body_start));

    // --- Build Certificate ---
    // Structure: type(1) | body_len(3) | certs_total_len(3) | cert_len(3) | cert_data
    TlsWriter<16384> cert_w;
    cert_w.write_u8(static_cast<uint8_t>(HandshakeType::certificate));
    uint32_t certs_total = 3 + static_cast<uint32_t>(cert_der.size()); // cert_len(3) + cert_data
    uint32_t body_len = 3 + certs_total; // certs_total_len(3) + certs_total
    cert_w.write_u24(body_len);
    cert_w.write_u24(certs_total);
    cert_w.write_u24(static_cast<uint32_t>(cert_der.size()));
    cert_w.write_bytes(cert_der);

    // --- Build ServerKeyExchange ---
    auto sx = server_ecdh_kp.public_key.x().value().to_bytes(std::endian::big);
    auto sy = server_ecdh_kp.public_key.y().value().to_bytes(std::endian::big);
    std::array<uint8_t, 65> server_point{};
    server_point[0] = 0x04;
    for (size_t i = 0; i < 32; ++i) server_point[1 + i] = sx[sx.size() - 32 + i];
    for (size_t i = 0; i < 32; ++i) server_point[33 + i] = sy[sy.size() - 32 + i];

    // Signed data
    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), expected_client_random.begin(), expected_client_random.end());
    signed_data.insert(signed_data.end(), server_random.begin(), server_random.end());
    signed_data.push_back(0x03); // named_curve
    signed_data.push_back(0x00); signed_data.push_back(23); // secp256r1
    signed_data.push_back(65);
    signed_data.insert(signed_data.end(), server_point.begin(), server_point.end());

    auto ske_hash = sha256(signed_data);
    auto ske_sig = ecdsa_sign<p256_curve, sha256_state>(server_priv, ske_hash);

    // DER-encode SKE signature
    auto encode_sig = [](const ecdsa_signature<p256_curve>& sig) {
        asn1::der::Writer sw;
        sw.write_constructed(0x30, [&](asn1::der::Writer& seq) {
            auto encode_int = [&](const uint512& val) {
                auto bytes = val.to_bytes(std::endian::big);
                size_t start = 0;
                while (start < bytes.size() - 1 && bytes[start] == 0) ++start;
                std::vector<uint8_t> v(bytes.begin() + start, bytes.end());
                if (v[0] & 0x80) v.insert(v.begin(), 0x00);
                asn1::der::Integer i; i.bytes = v;
                seq.write(i);
            };
            encode_int(sig.r);
            encode_int(sig.s);
        });
        return std::move(sw).finish();
    };
    auto ske_sig_der = encode_sig(ske_sig);

    TlsWriter<1024> ske_w;
    ske_w.write_u8(static_cast<uint8_t>(HandshakeType::server_key_exchange));
    ske_w.write_u24(0); size_t ske_body_start = ske_w.position();
    ske_w.write_u8(0x03); // named_curve
    ske_w.write_u16(23);  // secp256r1
    ske_w.write_u8(65);
    ske_w.write_bytes(server_point);
    ske_w.write_u8(4); ske_w.write_u8(3); // SHA256 + ECDSA
    ske_w.write_u16(static_cast<uint16_t>(ske_sig_der.size()));
    ske_w.write_bytes(ske_sig_der);
    ske_w.patch_u24(1, static_cast<uint32_t>(ske_w.position() - ske_body_start));

    // --- ServerHelloDone ---
    std::array<uint8_t, 4> shd_bytes = {
        static_cast<uint8_t>(HandshakeType::server_hello_done), 0, 0, 0};

    // --- Compute transcript for server Finished ---

    // Replay client's ClientHello construction
    xoshiro256ss ch_rng(42);
    auto ch_random = random_bytes<32>(ch_rng);
    ClientHello client_hello{};
    client_hello.client_version = TLS_1_2;
    client_hello.random = ch_random;
    client_hello.session_id.length = 0;
    client_config cfg;
    for (size_t i = 0; i < cfg.num_cipher_suites; ++i)
        client_hello.cipher_suites.push_back(cfg.cipher_suites[i]);
    client_hello.compression_methods.push_back(CompressionMethod::null);
    TlsWriter<512> ext_wr;
    write_client_hello_extensions(ext_wr,
        std::span<const NamedCurve>(cfg.curves.data(), cfg.num_curves),
        std::span<const SignatureAndHashAlgorithm>(cfg.sig_algs.data(), cfg.num_sig_algs));
    for (size_t i = 0; i < ext_wr.size(); ++i)
        client_hello.extensions.push_back(ext_wr.data()[i]);
    TlsWriter<1024> ch_writer;
    write_client_hello(ch_writer, client_hello);

    // Build transcript hash
    sha256_state th; th.init();
    th.update(ch_writer.data());
    th.update(sh_w.data());
    th.update(cert_w.data());
    th.update(ske_w.data());
    th.update(std::span<const uint8_t>(shd_bytes));

    // Client's CKE
    ClientKeyExchangeEcdhe cke{};
    cke.public_key.push_back(0x04);
    auto cx = client_ecdh_kp.public_key.x().value().to_bytes(std::endian::big);
    auto cy = client_ecdh_kp.public_key.y().value().to_bytes(std::endian::big);
    for (size_t i = 0; i < 32; ++i) cke.public_key.push_back(cx[cx.size() - 32 + i]);
    for (size_t i = 0; i < 32; ++i) cke.public_key.push_back(cy[cy.size() - 32 + i]);
    TlsWriter<256> cke_writer;
    write_client_key_exchange_ecdhe(cke_writer, cke);
    th.update(cke_writer.data());

    // Shared secret
    auto shared_opt = ecdh_raw_shared_secret<p256_curve>(server_ecdh_priv, client_ecdh_kp.public_key);
    assert(shared_opt.has_value());
    auto pms_full = shared_opt->to_bytes(std::endian::big);
    std::array<uint8_t, 32> pms{};
    for (size_t i = 0; i < 32; ++i) pms[i] = pms_full[pms_full.size() - 32 + i];

    auto master = derive_master_secret<sha256_state>(pms, ch_random, server_random);
    auto params = get_cipher_suite_params(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    auto kb = derive_key_block<sha256_state>(master, ch_random, server_random, params);

    // Client Finished
    sha256_state th_for_cfin = th;
    auto client_vd = compute_verify_data<sha256_state>(master, true, th_for_cfin.finalize());
    Finished cfin{}; cfin.verify_data = client_vd;
    TlsWriter<64> cfin_w;
    write_finished(cfin_w, cfin);
    th.update(cfin_w.data());

    // Server Finished
    sha256_state th_for_sfin = th;
    auto server_vd = compute_verify_data<sha256_state>(master, false, th_for_sfin.finalize());
    Finished sfin{}; sfin.verify_data = server_vd;
    TlsWriter<64> sfin_w;
    write_finished(sfin_w, sfin);

    // Encrypt server Finished
    auto encrypted_fin = encrypt_record<aes128>(
        std::span<const uint8_t, 16>(kb.server_write_key.data(), 16),
        std::span<const uint8_t, 4>(kb.server_write_iv.data(), 4),
        0, ContentType::handshake, TLS_1_2, sfin_w.data());

    // --- Assemble memory transport ---
    auto sh_rec = make_record(ContentType::handshake, sh_w.data());
    auto cert_rec = make_record(ContentType::handshake, cert_w.data());
    auto ske_rec = make_record(ContentType::handshake, ske_w.data());
    auto shd_rec = make_record(ContentType::handshake, std::span<const uint8_t>(shd_bytes));
    auto ccs_rec = make_record(ContentType::change_cipher_spec, std::array<uint8_t, 1>{1});
    auto sfin_rec = make_record(ContentType::handshake,
        std::span<const uint8_t>(encrypted_fin.data.data(), encrypted_fin.len));

    memory_transport mt;
    auto append = [&](const std::vector<uint8_t>& v) {
        for (auto b : v) mt.rx_buf.push_back(b);
    };
    append(sh_rec);
    append(cert_rec);
    append(ske_rec);
    append(shd_rec);
    append(ccs_rec);
    append(sfin_rec);

    // --- Run handshake ---
    xoshiro256ss client_rng(42);
    tls_client client(mt, client_rng);
    auto result = client.handshake();

    assert(result.ok());
    assert(client.is_connected());
    assert(client.negotiated_suite() == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
}

int main() {
    test_concept_satisfaction();
    test_full_handshake();
    return 0;
}
