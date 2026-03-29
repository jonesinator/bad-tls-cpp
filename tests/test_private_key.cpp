#include <tls/private_key.hpp>
#include <crypto/sha2.hpp>
#include <cassert>

// RSA-2048 test key in PKCS#1 format, generated with `openssl genrsa -traditional 2048`.
static constexpr auto rsa_pkcs1_pem = R"(
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs7iWC4gOyMZCM/i5cIoaN4fx+07ujLSjwbL/eKgTF6nDWJmH
ymb/N0S5K4cdVvp+Lq+hnjcc6YIQ0G1SU30k6984WysgJmxFEnKAY163WeVlml2b
Y9AUfLoWeVg/VykV76wJYYUOc1cWLxX/1isiZLFNjo654+T+bV3tLb4KwqlfigfN
9c85ESw2c7Lywb1JtS4wOesvgiagLDU+uwqslu/ER6rSltXnswKrIu1VzBJx0kPD
3I1h/5+hBBqK7mLJZdcWfJr238wNC/ejQpHlJZISXrEXVEp07lySZHqfsYpYZ59t
i/2Ao72NkBI5GSZaNftUamyLpA65qAeWHiqXIwIDAQABAoIBABiz1mvfV6jhF1ht
Z4/Aa7oWRXx1bPSKH7gQEm1TLMyj2OXktHVtksbV+12wRKgf5hgkq+JDUQYHiqgb
XqV7HggNtoFRfCnL1/KhKmR+MFV64mxFUYZ2o1pBebVUG+CvFQTMcL2mvEW+Qp5W
N8QIScHtXOurUoGwiAggUOlopbH7uttgUcqu5rxj82l+1dWff3v0H7+9gXZ4yI/B
t0rSOF9Ne1BE+A45JJVFbOIw2ziFqakXaqH+SoLHruHT6uR+JDd1c3X2K005klQx
7Tsv41QjZ2hedyAndvcKn7KHIz1ImaK/HlcR6Hzlt11eDzqJYAphcR2m45NgcD6h
p+8GT4ECgYEA2yy7d9Zc9m+lNam5s5pV19LB0/0GfRFUGSfndmAb9vlQ4YygMyU3
4Mt6cvU3Vcm2j9uaA0PcDUHv51xFQ8xgTnT5/tkdtrNiFra4bgReo/3Jfbd+2DRQ
0cWS+0gXTViq7fpnubui404FIj1v63bkqZcem8QRjk1YRLFMUxMIX+8CgYEA0erZ
YES2bQ1xozEg00L9Wl50qsrXBYn+qVTzGHtmqUubZqjYXlR7Y7WvQ1Rs3aPBOGSr
64a0nQJI6gn4Yi0e4Rc9Lgy1JMtsP5qyNVMy14yJgMQhb9FZ1TgzzNjlqJ2m1d6l
QYGuv3jIquTlPe3yuZujGfuc4yDxd0OF3+XlyA0CgYEAsmr5uRYx2xMLpGGkIEbU
9rpEuzNQ4uMGWOwZCk42tZhDdTiq+Lelg0NhTM+92gI4sWcNOvc03T3985Mzd3ua
MoQbNpC8FYx1nxPjkvvPpyPjsIl9orcDy6BQhGotPfOeQdgENDhA41UR7MuinkXM
4xl3+0ljGTpxTooeHcpymNUCgYBjroMVHOwH8xdgaEbvK2OF007Rf8sFnVbp8CYU
HR1ODVI5OLquaK3DVpZogaHEyitJ7Txadrgzys73HE7vx/9e4hsyT+SBGXxI49v2
SJDfHKR7GifKon5nKu4mO2UrYdnEu5p79eoWkHOx+0oE04asrwSPpRUGIjGn8c+T
1+b6zQKBgQCYCzxKyVRc4EsZFXuf0tZJDesUyDH6zlCrTnzdREOM9SSEBc4S/gKE
SxwAru8Pb0f9oWVJPZ4MiOphaDDSf9SrC1leTYFIx15EPr3eBiSqMLmD0DVoda5K
AlltAO4tTEHVQtXFIe1pPqVq/UElZnncJV7HkmbQiS9J2Lzvb5mzIw==
-----END RSA PRIVATE KEY-----
)";

// Same key converted to PKCS#8 with `openssl pkey -in rsa.pem`.
static constexpr auto rsa_pkcs8_pem = R"(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzuJYLiA7IxkIz
+Llwiho3h/H7Tu6MtKPBsv94qBMXqcNYmYfKZv83RLkrhx1W+n4ur6GeNxzpghDQ
bVJTfSTr3zhbKyAmbEUScoBjXrdZ5WWaXZtj0BR8uhZ5WD9XKRXvrAlhhQ5zVxYv
Ff/WKyJksU2Ojrnj5P5tXe0tvgrCqV+KB831zzkRLDZzsvLBvUm1LjA56y+CJqAs
NT67CqyW78RHqtKW1eezAqsi7VXMEnHSQ8PcjWH/n6EEGoruYsll1xZ8mvbfzA0L
96NCkeUlkhJesRdUSnTuXJJkep+xilhnn22L/YCjvY2QEjkZJlo1+1RqbIukDrmo
B5YeKpcjAgMBAAECggEAGLPWa99XqOEXWG1nj8BruhZFfHVs9IofuBASbVMszKPY
5eS0dW2SxtX7XbBEqB/mGCSr4kNRBgeKqBtepXseCA22gVF8KcvX8qEqZH4wVXri
bEVRhnajWkF5tVQb4K8VBMxwvaa8Rb5CnlY3xAhJwe1c66tSgbCICCBQ6Wilsfu6
22BRyq7mvGPzaX7V1Z9/e/Qfv72BdnjIj8G3StI4X017UET4DjkklUVs4jDbOIWp
qRdqof5Kgseu4dPq5H4kN3VzdfYrTTmSVDHtOy/jVCNnaF53ICd29wqfsocjPUiZ
or8eVxHofOW3XV4POolgCmFxHabjk2BwPqGn7wZPgQKBgQDbLLt31lz2b6U1qbmz
mlXX0sHT/QZ9EVQZJ+d2YBv2+VDhjKAzJTfgy3py9TdVybaP25oDQ9wNQe/nXEVD
zGBOdPn+2R22s2IWtrhuBF6j/cl9t37YNFDRxZL7SBdNWKrt+me5u6LjTgUiPW/r
duSplx6bxBGOTVhEsUxTEwhf7wKBgQDR6tlgRLZtDXGjMSDTQv1aXnSqytcFif6p
VPMYe2apS5tmqNheVHtjta9DVGzdo8E4ZKvrhrSdAkjqCfhiLR7hFz0uDLUky2w/
mrI1UzLXjImAxCFv0VnVODPM2OWonabV3qVBga6/eMiq5OU97fK5m6MZ+5zjIPF3
Q4Xf5eXIDQKBgQCyavm5FjHbEwukYaQgRtT2ukS7M1Di4wZY7BkKTja1mEN1OKr4
t6WDQ2FMz73aAjixZw069zTdPf3zkzN3e5oyhBs2kLwVjHWfE+OS+8+nI+OwiX2i
twPLoFCEai09855B2AQ0OEDjVRHsy6KeRczjGXf7SWMZOnFOih4dynKY1QKBgGOu
gxUc7AfzF2BoRu8rY4XTTtF/ywWdVunwJhQdHU4NUjk4uq5orcNWlmiBocTKK0nt
PFp2uDPKzvccTu/H/17iGzJP5IEZfEjj2/ZIkN8cpHsaJ8qifmcq7iY7ZSth2cS7
mnv16haQc7H7SgTThqyvBI+lFQYiMafxz5PX5vrNAoGBAJgLPErJVFzgSxkVe5/S
1kkN6xTIMfrOUKtOfN1EQ4z1JIQFzhL+AoRLHACu7w9vR/2hZUk9ngyI6mFoMNJ/
1KsLWV5NgUjHXkQ+vd4GJKowuYPQNWh1rkoCWW0A7i1MQdVC1cUh7Wk+pWr9QSVm
edwlXseSZtCJL0nYvO9vmbMj
-----END PRIVATE KEY-----
)";

// EC P-384 key for auto-detect testing (generated with openssl ecparam -name secp384r1 -genkey).
static constexpr auto ec_pem = R"(
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDB+wV2N1A3ZB8Uob2OR7cLbx7F+T8yjYFeAK8POnoclt+XmrKE0ZoLI
yFXE+Lns5Q6gBwYFK4EEACKhZANiAATVnFBx2DeYOm0fwgegV6xaPGsbbNE1arQd
1iZKW9ZwuoSWm5ZRDTS3xyVsPXt+XcwY9XMgxFWmHh2biKLgviHR8OFzOOurO59u
DjXegZG9fj09qONLkQR1t6kYLPEutYM=
-----END EC PRIVATE KEY-----
)";

void test_load_rsa_pkcs1() {
    auto loaded = tls::load_rsa_private_key(rsa_pkcs1_pem);
    assert(loaded.type == tls::key_type::rsa);
    auto* key = std::get_if<rsa_private_key<tls::rsa_num>>(&loaded.key);
    assert(key != nullptr);
    assert(key->n != tls::rsa_num(0U));
    assert(key->d != tls::rsa_num(0U));
}

void test_load_rsa_pkcs8() {
    auto loaded = tls::load_rsa_private_key(rsa_pkcs8_pem);
    assert(loaded.type == tls::key_type::rsa);
    auto* key = std::get_if<rsa_private_key<tls::rsa_num>>(&loaded.key);
    assert(key != nullptr);
    assert(key->n != tls::rsa_num(0U));
    assert(key->d != tls::rsa_num(0U));
}

void test_rsa_keys_match() {
    // Both formats should produce the same key
    auto pkcs1 = tls::load_rsa_private_key(rsa_pkcs1_pem);
    auto pkcs8 = tls::load_rsa_private_key(rsa_pkcs8_pem);
    auto* k1 = std::get_if<rsa_private_key<tls::rsa_num>>(&pkcs1.key);
    auto* k8 = std::get_if<rsa_private_key<tls::rsa_num>>(&pkcs8.key);
    assert(k1->n == k8->n);
    assert(k1->d == k8->d);
}

void test_unified_loader_rsa() {
    auto loaded = tls::load_private_key(rsa_pkcs1_pem);
    assert(loaded.type == tls::key_type::rsa);
    assert(std::get_if<rsa_private_key<tls::rsa_num>>(&loaded.key) != nullptr);

    auto loaded2 = tls::load_private_key(rsa_pkcs8_pem);
    assert(loaded2.type == tls::key_type::rsa);
    assert(std::get_if<rsa_private_key<tls::rsa_num>>(&loaded2.key) != nullptr);
}

void test_unified_loader_ec() {
    auto loaded = tls::load_private_key(ec_pem);
    assert(loaded.type == tls::key_type::ec);
    assert(loaded.curve == tls::NamedCurve::secp384r1);
    assert(std::get_if<tls::p384_curve::number_type>(&loaded.key) != nullptr);
}

void test_ec_key_accessor() {
    auto loaded = tls::load_private_key(ec_pem);
    auto eck = loaded.ec_key();
    assert(std::get_if<tls::p384_curve::number_type>(&eck) != nullptr);

    // RSA key should throw on ec_key()
    auto rsa_loaded = tls::load_private_key(rsa_pkcs1_pem);
    bool threw = false;
    try {
        rsa_loaded.ec_key();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);
}

void test_rsa_sign_verify_roundtrip() {
    // Load the RSA key and verify it can sign/verify
    auto loaded = tls::load_private_key(rsa_pkcs1_pem);
    auto* priv = std::get_if<rsa_private_key<tls::rsa_num>>(&loaded.key);
    assert(priv != nullptr);

    // Sign a message hash
    std::array<uint8_t, 32> hash{};
    for (size_t i = 0; i < 32; ++i) hash[i] = static_cast<uint8_t>(i);
    auto sig = rsa_pkcs1_v1_5_sign<tls::rsa_num, sha256_state>(*priv, hash);

    // To verify, we need the public key. Extract e from the PKCS#1 PEM manually.
    // We know e = 65537 for standard keys.
    rsa_public_key<tls::rsa_num> pub{priv->n, tls::rsa_num(65537U)};
    bool ok = rsa_pkcs1_v1_5_verify<tls::rsa_num, sha256_state>(pub, hash, sig);
    assert(ok);

    // Wrong hash should fail
    hash[0] ^= 1;
    bool bad = rsa_pkcs1_v1_5_verify<tls::rsa_num, sha256_state>(pub, hash, sig);
    assert(!bad);
}

int main() {
    std::printf("test_load_rsa_pkcs1...\n");
    test_load_rsa_pkcs1();
    std::printf("test_load_rsa_pkcs8...\n");
    test_load_rsa_pkcs8();
    std::printf("test_rsa_keys_match...\n");
    test_rsa_keys_match();
    std::printf("test_unified_loader_rsa...\n");
    test_unified_loader_rsa();
    std::printf("test_unified_loader_ec...\n");
    test_unified_loader_ec();
    std::printf("test_ec_key_accessor...\n");
    test_ec_key_accessor();
    std::printf("test_rsa_sign_verify_roundtrip...\n");
    test_rsa_sign_verify_roundtrip();
    std::printf("All private key tests passed.\n");
}
