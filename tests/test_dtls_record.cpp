/**
 * DTLS record layer tests.
 *
 * Tests DtlsRecord serialization/deserialization and DTLS handshake headers.
 */

#include <tls/dtls_record.hpp>
#include <cassert>
#include <cstdio>

using namespace tls;

static void test_dtls_record_roundtrip() {
    DtlsRecord rec;
    rec.type = ContentType::handshake;
    rec.version = DTLS_1_2;
    rec.epoch = 1;
    rec.sequence_number = 0x123456789ABCull;
    const uint8_t payload[] = {1, 2, 3, 4, 5};
    for (auto b : payload) rec.fragment.push_back(b);

    TlsWriter<256> w;
    write_dtls_record(w, rec);

    auto data = w.data();
    assert(data.size() == DTLS_RECORD_HEADER_LENGTH + 5);

    // Verify header bytes
    assert(data[0] == 22);  // handshake
    assert(data[1] == 254); // DTLS 1.2 major
    assert(data[2] == 253); // DTLS 1.2 minor
    assert(data[3] == 0);   // epoch high
    assert(data[4] == 1);   // epoch low
    // sequence_number: 0x123456789ABC in 6 bytes
    assert(data[5] == 0x12);
    assert(data[6] == 0x34);
    assert(data[7] == 0x56);
    assert(data[8] == 0x78);
    assert(data[9] == 0x9A);
    assert(data[10] == 0xBC);
    // length: 5
    assert(data[11] == 0);
    assert(data[12] == 5);

    TlsReader r(data);
    auto parsed = read_dtls_record(r);
    assert(parsed.has_value());
    assert(parsed->type == ContentType::handshake);
    assert(parsed->version == DTLS_1_2);
    assert(parsed->epoch == 1);
    assert(parsed->sequence_number == 0x123456789ABCull);
    assert(parsed->fragment.size() == 5);
    for (size_t i = 0; i < 5; ++i)
        assert(parsed->fragment[i] == payload[i]);

    std::printf("  dtls_record_roundtrip: PASS\n");
}

static void test_dtls_handshake_header_roundtrip() {
    TlsWriter<64> w;
    write_dtls_handshake_header(w,
        HandshakeType::client_hello,
        0x1234,   // length
        5,        // message_seq
        0x100,    // fragment_offset
        0x1234);  // fragment_length

    auto data = w.data();
    assert(data.size() == DTLS_HANDSHAKE_HEADER_LENGTH);

    TlsReader r(data);
    auto hdr = read_dtls_handshake_header(r);
    assert(hdr.type == HandshakeType::client_hello);
    assert(hdr.length == 0x1234);
    assert(hdr.message_seq == 5);
    assert(hdr.fragment_offset == 0x100);
    assert(hdr.fragment_length == 0x1234);

    std::printf("  dtls_handshake_header_roundtrip: PASS\n");
}

static void test_dtls_record_epoch_zero() {
    DtlsRecord rec;
    rec.type = ContentType::application_data;
    rec.version = DTLS_1_2;
    rec.epoch = 0;
    rec.sequence_number = 0;
    rec.fragment.push_back(0xFF);

    TlsWriter<64> w;
    write_dtls_record(w, rec);

    TlsReader r(w.data());
    auto parsed = read_dtls_record(r);
    assert(parsed.has_value());
    assert(parsed->epoch == 0);
    assert(parsed->sequence_number == 0);

    std::printf("  dtls_record_epoch_zero: PASS\n");
}

static void test_u48_max_value() {
    TlsWriter<16> w;
    write_u48(w, 0xFFFFFFFFFFFFull);  // max 48-bit value

    TlsReader r(w.data());
    uint64_t val = read_u48(r);
    assert(val == 0xFFFFFFFFFFFFull);

    std::printf("  u48_max_value: PASS\n");
}

static void test_dtls_record_incomplete() {
    // Too few bytes for header
    uint8_t partial[] = {22, 254, 253, 0, 0};
    TlsReader r(std::span<const uint8_t>(partial, 5));
    auto result = read_dtls_record(r);
    assert(!result.has_value());

    std::printf("  dtls_record_incomplete: PASS\n");
}

int main() {
    std::printf("DTLS record tests:\n");
    test_dtls_record_roundtrip();
    test_dtls_handshake_header_roundtrip();
    test_dtls_record_epoch_zero();
    test_u48_max_value();
    test_dtls_record_incomplete();
    std::printf("All DTLS record tests passed.\n");
    return 0;
}
