#include <tls/record.hpp>
#include <cassert>

void test_reader_writer_roundtrip() {
    // Write some values, then read them back
    constexpr auto test = [] {
        tls::TlsWriter<64> w;
        w.write_u8(0x42);
        w.write_u16(0xABCD);
        w.write_u24(0x123456);
        std::array<uint8_t, 3> bytes = {0xDE, 0xAD, 0xBE};
        w.write_bytes(bytes);

        tls::TlsReader r(w.data());
        if (r.read_u8() != 0x42) throw "u8 mismatch";
        if (r.read_u16() != 0xABCD) throw "u16 mismatch";
        if (r.read_u24() != 0x123456) throw "u24 mismatch";
        auto read_back = r.read_bytes(3);
        if (read_back[0] != 0xDE || read_back[1] != 0xAD || read_back[2] != 0xBE)
            throw "bytes mismatch";
        if (!r.at_end()) throw "not at end";
        return true;
    };
    static_assert(test());
}

void test_record_roundtrip() {
    constexpr auto test = [] {
        tls::TlsRecord rec;
        rec.type = tls::ContentType::handshake;
        rec.version = tls::TLS_1_2;
        rec.fragment.push_back(0x01);
        rec.fragment.push_back(0x02);
        rec.fragment.push_back(0x03);

        // Serialize
        tls::TlsWriter<32> w;
        tls::write_record(w, rec);

        // Verify wire format: type(1) + version(2) + length(2) + fragment(3) = 8 bytes
        auto data = w.data();
        if (data.size() != 8) throw "wrong size";
        if (data[0] != 22) throw "wrong type"; // handshake = 22
        if (data[1] != 3 || data[2] != 3) throw "wrong version"; // TLS 1.2 = 3.3
        if (data[3] != 0 || data[4] != 3) throw "wrong length";
        if (data[5] != 0x01 || data[6] != 0x02 || data[7] != 0x03) throw "wrong fragment";

        // Deserialize
        tls::TlsReader r(data);
        auto parsed = tls::read_record(r);
        if (!parsed) throw "parse failed";
        if (parsed->type != tls::ContentType::handshake) throw "type mismatch";
        if (!(parsed->version == tls::TLS_1_2)) throw "version mismatch";
        if (parsed->fragment.size() != 3) throw "fragment size mismatch";
        if (parsed->fragment[0] != 0x01) throw "fragment content mismatch";
        return true;
    };
    static_assert(test());
}

void test_record_incomplete() {
    constexpr auto test = [] {
        // Too few bytes for header
        std::array<uint8_t, 3> short_data = {22, 3, 3};
        tls::TlsReader r1(short_data);
        if (tls::read_record(r1).has_value()) throw "should fail on short header";

        // Header says 10 bytes but only 2 available
        std::array<uint8_t, 7> trunc_data = {22, 3, 3, 0, 10, 0xAA, 0xBB};
        tls::TlsReader r2(trunc_data);
        if (tls::read_record(r2).has_value()) throw "should fail on truncated fragment";

        return true;
    };
    static_assert(test());
}

void test_writer_patch() {
    constexpr auto test = [] {
        tls::TlsWriter<32> w;
        w.write_u16(0);      // placeholder at pos 0
        w.write_u24(0);      // placeholder at pos 2
        w.write_u8(0xFF);    // data at pos 5

        w.patch_u16(0, 0x1234);
        w.patch_u24(2, 0xABCDEF);

        auto data = w.data();
        if (data[0] != 0x12 || data[1] != 0x34) throw "patch_u16 failed";
        if (data[2] != 0xAB || data[3] != 0xCD || data[4] != 0xEF) throw "patch_u24 failed";
        if (data[5] != 0xFF) throw "original data corrupted";
        return true;
    };
    static_assert(test());
}

void test_sub_reader() {
    constexpr auto test = [] {
        std::array<uint8_t, 6> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        tls::TlsReader r(data);
        r.read_u8(); // skip first byte

        auto sub = r.sub_reader(3); // read 3 bytes into sub-reader
        if (sub.remaining() != 3) throw "sub_reader wrong size";
        if (sub.read_u8() != 0x02) throw "sub_reader wrong data";
        if (sub.read_u8() != 0x03) throw "sub_reader wrong data 2";
        if (sub.read_u8() != 0x04) throw "sub_reader wrong data 3";
        if (!sub.at_end()) throw "sub_reader not at end";

        // Main reader should have advanced past the 3 bytes
        if (r.remaining() != 2) throw "main reader wrong remaining";
        if (r.read_u8() != 0x05) throw "main reader wrong data";
        return true;
    };
    static_assert(test());
}

int main() {
    test_reader_writer_roundtrip();
    test_record_roundtrip();
    test_record_incomplete();
    test_writer_patch();
    test_sub_reader();
    return 0;
}
