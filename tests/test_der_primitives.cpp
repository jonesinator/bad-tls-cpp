#include <asn1/der/writer.hpp>
#include <asn1/der/reader.hpp>
#include <cassert>
#include <cstdint>
#include <vector>

using namespace asn1::der;

// Helper to compare byte vectors
void expect_bytes(const std::vector<uint8_t>& actual, std::initializer_list<uint8_t> expected) {
    std::vector<uint8_t> exp{expected};
    assert(actual == exp);
}

// --- Integer ---

void test_integer_positive() {
    Writer w;
    w.write(Integer::from_int64(5));
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x02, 0x01, 0x05});

    Reader r{bytes};
    auto v = r.read_integer();
    assert(v.to_int64() == 5);
}

void test_integer_zero() {
    Writer w;
    w.write(Integer::from_int64(0));
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x02, 0x01, 0x00});

    Reader r{bytes};
    assert(r.read_integer().to_int64() == 0);
}

void test_integer_negative() {
    Writer w;
    w.write(Integer::from_int64(-1));
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x02, 0x01, 0xFF});

    Reader r{bytes};
    assert(r.read_integer().to_int64() == -1);
}

void test_integer_128() {
    // 128 needs a leading 0x00 to stay positive
    Writer w;
    w.write(Integer::from_int64(128));
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x02, 0x02, 0x00, 0x80});

    Reader r{bytes};
    assert(r.read_integer().to_int64() == 128);
}

void test_integer_negative_128() {
    Writer w;
    w.write(Integer::from_int64(-128));
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x02, 0x01, 0x80});

    Reader r{bytes};
    assert(r.read_integer().to_int64() == -128);
}

void test_integer_large() {
    Writer w;
    w.write(Integer::from_int64(256));
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x02, 0x02, 0x01, 0x00});

    Reader r{bytes};
    assert(r.read_integer().to_int64() == 256);
}

// --- Boolean ---

void test_boolean() {
    {
        Writer w;
        w.write(Boolean{true});
        auto bytes = std::move(w).finish();
        expect_bytes(bytes, {0x01, 0x01, 0xFF});
        Reader r{bytes};
        assert(r.read_boolean().value == true);
    }
    {
        Writer w;
        w.write(Boolean{false});
        auto bytes = std::move(w).finish();
        expect_bytes(bytes, {0x01, 0x01, 0x00});
        Reader r{bytes};
        assert(r.read_boolean().value == false);
    }
}

// --- Null ---

void test_null() {
    Writer w;
    w.write(Null{});
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x05, 0x00});

    Reader r{bytes};
    r.read_null(); // just shouldn't throw
}

// --- OctetString ---

void test_octet_string() {
    Writer w;
    w.write(OctetString{{0x01, 0x02, 0x03}});
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {0x04, 0x03, 0x01, 0x02, 0x03});

    Reader r{bytes};
    auto os = r.read_octet_string();
    assert(os.bytes == (std::vector<uint8_t>{0x01, 0x02, 0x03}));
}

// --- BitString ---

void test_bit_string() {
    Writer w;
    w.write(BitString{{0x6E, 0x5D, 0xC0}, 2});
    auto bytes = std::move(w).finish();
    // Tag 0x03, length 4 (1 unused_bits byte + 3 data bytes), unused=2, data
    expect_bytes(bytes, {0x03, 0x04, 0x02, 0x6E, 0x5D, 0xC0});

    Reader r{bytes};
    auto bs = r.read_bit_string();
    assert(bs.unused_bits == 2);
    assert(bs.bytes == (std::vector<uint8_t>{0x6E, 0x5D, 0xC0}));
}

// --- ObjectIdentifier ---

void test_oid() {
    // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
    auto oid = ObjectIdentifier::from_string("1.2.840.10045.3.1.7");
    Writer w;
    w.write(oid);
    auto bytes = std::move(w).finish();

    // Known DER encoding for this OID
    expect_bytes(bytes, {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    });

    Reader r{bytes};
    auto decoded = r.read_oid();
    assert(decoded.to_string() == "1.2.840.10045.3.1.7");
}

void test_oid_ecPublicKey() {
    // 1.2.840.10045.2.1 (id-ecPublicKey)
    auto oid = ObjectIdentifier::from_string("1.2.840.10045.2.1");
    Writer w;
    w.write(oid);
    auto bytes = std::move(w).finish();
    expect_bytes(bytes, {
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
    });

    Reader r{bytes};
    assert(r.read_oid().to_string() == "1.2.840.10045.2.1");
}

// --- AnyValue ---

void test_any_value() {
    // Encode an integer, then read it back as AnyValue
    Writer w;
    w.write(Integer::from_int64(42));
    auto bytes = std::move(w).finish();

    Reader r{bytes};
    auto any = r.read_any();
    assert(any.raw_tlv == bytes);
}

// --- Constructed SEQUENCE (manual) ---

void test_manual_sequence() {
    Writer w;
    w.write_constructed(TagSequence, [](Writer& inner) {
        inner.write(Integer::from_int64(1));
        inner.write(OctetString{{0xAB, 0xCD}});
    });
    auto bytes = std::move(w).finish();

    // SEQUENCE { INTEGER 1, OCTET STRING ab cd }
    expect_bytes(bytes, {
        0x30, 0x07,             // SEQUENCE, length 7
        0x02, 0x01, 0x01,       // INTEGER 1
        0x04, 0x02, 0xAB, 0xCD  // OCTET STRING
    });

    Reader r{bytes};
    auto seq = r.enter_sequence();
    assert(seq.read_integer().to_int64() == 1);
    auto os = seq.read_octet_string();
    assert(os.bytes == (std::vector<uint8_t>{0xAB, 0xCD}));
    assert(seq.at_end());
}

// --- Long-form length ---

void test_long_length() {
    // Create an OCTET STRING with 200 bytes
    OctetString big;
    big.bytes.resize(200, 0x42);
    Writer w;
    w.write(big);
    auto bytes = std::move(w).finish();

    // Tag 0x04, length in long form: 0x81 0xC8 (200), then 200 bytes
    assert(bytes.size() == 203);
    assert(bytes[0] == 0x04);
    assert(bytes[1] == 0x81); // long form, 1 length byte
    assert(bytes[2] == 200);

    Reader r{bytes};
    auto os = r.read_octet_string();
    assert(os.bytes.size() == 200);
    assert(os.bytes[0] == 0x42);
}

// --- Explicit tag ---

void test_explicit_tag() {
    // [0] EXPLICIT INTEGER 42
    Writer w;
    uint8_t ctx0_constructed = ClassContextSpecific | Constructed | 0;
    w.write_constructed(ctx0_constructed, [](Writer& inner) {
        inner.write(Integer::from_int64(42));
    });
    auto bytes = std::move(w).finish();

    expect_bytes(bytes, {
        0xA0, 0x03,             // [0] CONSTRUCTED, length 3
        0x02, 0x01, 0x2A        // INTEGER 42
    });

    Reader r{bytes};
    auto inner = r.enter_explicit_tag(ClassContextSpecific, 0);
    assert(inner.read_integer().to_int64() == 42);
}

// --- Implicit tag ---

void test_implicit_tag() {
    // [1] IMPLICIT OCTET STRING 0xAB 0xCD
    // Implicit replaces the tag: instead of 0x04, use context [1] primitive
    Writer w;
    uint8_t ctx1 = ClassContextSpecific | 1;
    w.write(OctetString{{0xAB, 0xCD}}, ctx1);
    auto bytes = std::move(w).finish();

    expect_bytes(bytes, {
        0x81, 0x02, 0xAB, 0xCD  // [1] PRIMITIVE, length 2
    });

    Reader r{bytes};
    auto os = r.read_octet_string_implicit(ClassContextSpecific, 1);
    assert(os.bytes == (std::vector<uint8_t>{0xAB, 0xCD}));
}

// --- Tag peeking ---

void test_peek_matches() {
    Writer w;
    w.write(Integer::from_int64(7));
    auto bytes = std::move(w).finish();

    Reader r{bytes};
    assert(r.peek_matches(ClassUniversal, false, TagInteger));
    assert(!r.peek_matches(ClassUniversal, false, TagBoolean));
    assert(!r.peek_matches(ClassContextSpecific, false, 0));
}

int main() {
    test_integer_positive();
    test_integer_zero();
    test_integer_negative();
    test_integer_128();
    test_integer_negative_128();
    test_integer_large();
    test_boolean();
    test_null();
    test_octet_string();
    test_bit_string();
    test_oid();
    test_oid_ecPublicKey();
    test_any_value();
    test_manual_sequence();
    test_long_length();
    test_explicit_tag();
    test_implicit_tag();
    test_peek_matches();
    return 0;
}
