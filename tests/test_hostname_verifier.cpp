#include <x509/hostname_verifier.hpp>
#include <cassert>

using namespace asn1::x509;

// --- Unit tests for matching logic ---

void test_exact_match() {
    assert(detail::match_hostname("example.com", "example.com"));
    assert(detail::match_hostname("Example.COM", "example.com"));
    assert(!detail::match_hostname("example.com", "other.com"));
    assert(!detail::match_hostname("example.com", "sub.example.com"));
}

void test_wildcard_match() {
    // Basic wildcard
    assert(detail::match_hostname("*.example.com", "foo.example.com"));
    assert(detail::match_hostname("*.example.com", "bar.example.com"));
    assert(detail::match_hostname("*.Example.COM", "foo.example.com"));

    // Wildcard must not match across dots
    assert(!detail::match_hostname("*.example.com", "foo.bar.example.com"));

    // Wildcard must not match the parent domain itself
    assert(!detail::match_hostname("*.example.com", "example.com"));

    // *.com is not valid (must have at least 2 dots in the pattern)
    assert(!detail::match_hostname("*.com", "example.com"));

    // Non-wildcard that starts with * in middle shouldn't match as wildcard
    assert(!detail::match_hostname("f*.example.com", "foo.example.com"));
}

void test_hostname_eq() {
    assert(detail::hostname_eq("abc", "abc"));
    assert(detail::hostname_eq("ABC", "abc"));
    assert(detail::hostname_eq("abc", "ABC"));
    assert(!detail::hostname_eq("abc", "abd"));
    assert(!detail::hostname_eq("abc", "ab"));
}

// --- Integration test with a real certificate ---

void test_verifier_with_san() {
    // Build a test cert with SAN extension containing dNSName entries.
    // We construct the cert DER manually using the DER writer.

    // First, build the SAN extension value: GeneralNames with two dNSNames
    auto build_san = []() {
        asn1::der::Writer w;
        w.write_constructed(0x30, [&](asn1::der::Writer& seq) {
            // dNSName [2] "example.com"
            std::string_view name1 = "example.com";
            seq.write_tag(0x80, false, 2);
            seq.write_length(name1.size());
            seq.write_bytes(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(name1.data()), name1.size()));

            // dNSName [2] "*.example.com"
            std::string_view name2 = "*.example.com";
            seq.write_tag(0x80, false, 2);
            seq.write_length(name2.size());
            seq.write_bytes(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(name2.data()), name2.size()));
        });
        return std::move(w).finish();
    };
    auto san_der = build_san();

    // Test extract_dns_names directly
    auto names = detail::extract_dns_names(san_der);
    assert(names.size() == 2);
    assert(names[0] == "example.com");
    assert(names[1] == "*.example.com");

    // Build a minimal certificate with SAN extension
    // We need: TBSCertificate → extensions → Extension with OID 2.5.29.17
    using uint512 = number<uint32_t, 16>;
    using curve = p256<uint512>;
    using fe = field_element<curve>;

    // Dummy key
    auto priv = uint512::from_bytes(std::array<uint8_t, 32>{
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20});
    point<curve> G{fe{curve::gx()}, fe{curve::gy()}};
    auto pub = G.scalar_mul(priv);

    asn1::der::Writer tbs;
    tbs.write_constructed(0x30, [&](asn1::der::Writer& s) {
        // version [0] EXPLICIT INTEGER = v3
        s.write_constructed(0xA0, [&](asn1::der::Writer& v) {
            v.write(asn1::der::Integer::from_int64(2));
        });
        s.write(asn1::der::Integer::from_int64(1));
        // signature algorithm
        s.write_constructed(0x30, [&](asn1::der::Writer& alg) {
            alg.write(asn1::der::ObjectIdentifier::from_string("1.2.840.10045.4.3.2"));
        });
        // issuer CN=test
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
            std::array<uint8_t, 13> t = {'2','5','0','1','0','1','0','0','0','0','0','0','Z'};
            v.write_tag(0x00, false, 23); v.write_length(13); v.write_bytes(t);
            v.write_tag(0x00, false, 23); v.write_length(13); v.write_bytes(t);
        });
        // subject CN=wrongname (SAN should take precedence)
        s.write_constructed(0x30, [&](asn1::der::Writer& nm) {
            nm.write_constructed(0x31, [&](asn1::der::Writer& rdn) {
                rdn.write_constructed(0x30, [&](asn1::der::Writer& atv) {
                    atv.write(asn1::der::ObjectIdentifier::from_string("2.5.4.3"));
                    atv.write_tag(0x00, false, 12);
                    std::array<uint8_t, 9> cn = {'w','r','o','n','g','n','a','m','e'};
                    atv.write_length(9); atv.write_bytes(cn);
                });
            });
        });
        // SubjectPublicKeyInfo
        s.write_constructed(0x30, [&](asn1::der::Writer& spki) {
            spki.write_constructed(0x30, [&](asn1::der::Writer& alg) {
                alg.write(asn1::der::ObjectIdentifier::from_string("1.2.840.10045.2.1"));
                alg.write(asn1::der::ObjectIdentifier::from_string("1.2.840.10045.3.1.7"));
            });
            auto x_bytes = pub.x().value().to_bytes(std::endian::big);
            auto y_bytes = pub.y().value().to_bytes(std::endian::big);
            asn1::der::BitString bs;
            bs.unused_bits = 0;
            bs.bytes.push_back(0x04);
            for (size_t i = 0; i < 32; ++i) bs.bytes.push_back(x_bytes[x_bytes.size() - 32 + i]);
            for (size_t i = 0; i < 32; ++i) bs.bytes.push_back(y_bytes[y_bytes.size() - 32 + i]);
            spki.write(bs);
        });
        // extensions [3] EXPLICIT Extensions
        s.write_constructed(0xA3, [&](asn1::der::Writer& ext_wrap) {
            ext_wrap.write_constructed(0x30, [&](asn1::der::Writer& exts) {
                // SAN extension
                exts.write_constructed(0x30, [&](asn1::der::Writer& ext) {
                    ext.write(asn1::der::ObjectIdentifier::from_string("2.5.29.17"));
                    asn1::der::OctetString san_os;
                    for (auto b : san_der) san_os.bytes.push_back(b);
                    ext.write(san_os);
                });
            });
        });
    });
    auto tbs_bytes = std::move(tbs).finish();

    // Sign
    auto tbs_hash = sha256(tbs_bytes);
    auto sig = ecdsa_sign<curve, sha256_state>(priv, tbs_hash);

    // Encode signature
    auto encode_sig = [](const ecdsa_signature<curve>& sig) {
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

    // Build Certificate
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
    auto cert_der = std::move(cert_w).finish();

    // Parse and create cert_context
    auto cert = parse_certificate(cert_der);
    auto tbs_extracted = extract_tbs_der(cert_der);
    cert_context ctx{
        .cert = cert,
        .issuer = nullptr,
        .cert_der = cert_der,
        .tbs_der = tbs_extracted,
        .depth = 0,
        .chain_length = 1
    };

    // SAN has example.com and *.example.com
    hostname_verifier hv_exact{"example.com"};
    assert(hv_exact.verify(ctx));

    hostname_verifier hv_wild{"foo.example.com"};
    assert(hv_wild.verify(ctx));

    hostname_verifier hv_wrong{"other.com"};
    assert(!hv_wrong.verify(ctx));

    // CN is "wrongname" but SAN takes precedence — should NOT match
    hostname_verifier hv_cn{"wrongname"};
    assert(!hv_cn.verify(ctx));

    // Non-leaf should always pass
    cert_context ctx_nonleaf{
        .cert = cert,
        .issuer = nullptr,
        .cert_der = cert_der,
        .tbs_der = tbs_extracted,
        .depth = 1,
        .chain_length = 2
    };
    hostname_verifier hv_any{"anything"};
    assert(hv_any.verify(ctx_nonleaf));
}

int main() {
    test_exact_match();
    test_wildcard_match();
    test_hostname_eq();
    test_verifier_with_san();
    return 0;
}
