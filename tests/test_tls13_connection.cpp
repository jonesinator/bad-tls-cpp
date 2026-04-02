#include <tls/tls13_connection.hpp>
#include <cassert>
#include <cstring>

using namespace tls;

void test_plaintext_send_recv() {
    // Two transports wired together: client writes, server reads
    memory_transport client_to_server;
    memory_transport server_to_client;

    // Wrap in a transport adapter that links them
    // For simplicity, we'll test with a single transport doing write then read
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    // Send a plaintext handshake record
    uint8_t payload[] = {1, 2, 3, 4, 5};
    auto err = rio.send_record(ContentType::handshake, payload);
    assert(err.ok());

    // Now set up read by copying tx_buf to rx_buf
    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    auto rec = rio.recv_record();
    assert(rec.ok());
    assert(rec.value.content_type == ContentType::handshake);
    assert(rec.value.fragment.size() == 5);
    for (size_t i = 0; i < 5; ++i)
        assert(rec.value.fragment[i] == payload[i]);
}

void test_ccs_dropped() {
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    // Send a CCS record followed by a handshake record
    rio.send_ccs();

    uint8_t payload[] = {0xAA, 0xBB};
    rio.send_record(ContentType::handshake, payload);

    // Copy tx to rx
    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    // First recv should skip CCS and return the handshake record
    auto rec = rio.recv_record();
    assert(rec.ok());
    assert(rec.value.content_type == ContentType::handshake);
    assert(rec.value.fragment.size() == 2);
    assert(rec.value.fragment[0] == 0xAA);
}

void test_encrypted_round_trip() {
    // Test encrypted send/recv using AES-128-GCM-SHA256.
    // Both directions use the same "traffic secret" for simplicity.
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    // Use a test traffic secret (32 bytes for SHA-256)
    std::array<uint8_t, 32> traffic_secret{};
    for (size_t i = 0; i < 32; ++i)
        traffic_secret[i] = static_cast<uint8_t>(i + 1);

    rio.activate_write_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, traffic_secret);
    rio.activate_read_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, traffic_secret);

    // Send an encrypted handshake message
    uint8_t payload[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    auto err = rio.send_record(ContentType::handshake, payload);
    assert(err.ok());

    // Copy tx to rx
    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    // Receive and decrypt
    auto rec = rio.recv_record();
    assert(rec.ok());
    assert(rec.value.content_type == ContentType::handshake);
    assert(rec.value.fragment.size() == 8);
    for (size_t i = 0; i < 8; ++i)
        assert(rec.value.fragment[i] == payload[i]);
}

void test_encrypted_multiple_records() {
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    std::array<uint8_t, 32> traffic_secret{};
    for (size_t i = 0; i < 32; ++i)
        traffic_secret[i] = static_cast<uint8_t>(i + 0x10);

    rio.activate_write_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, traffic_secret);

    // Send multiple records
    uint8_t p1[] = {0xAA};
    uint8_t p2[] = {0xBB, 0xCC};
    rio.send_record(ContentType::handshake, p1);
    rio.send_record(ContentType::application_data, p2);

    // Copy tx to rx and activate read keys
    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    rio.activate_read_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, traffic_secret);

    // Receive first record
    auto rec1 = rio.recv_record();
    assert(rec1.ok());
    assert(rec1.value.content_type == ContentType::handshake);
    assert(rec1.value.fragment.size() == 1);
    assert(rec1.value.fragment[0] == 0xAA);

    // Receive second record
    auto rec2 = rio.recv_record();
    assert(rec2.ok());
    assert(rec2.value.content_type == ContentType::application_data);
    assert(rec2.value.fragment.size() == 2);
    assert(rec2.value.fragment[0] == 0xBB);
    assert(rec2.value.fragment[1] == 0xCC);
}

void test_encrypted_chacha20() {
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    std::array<uint8_t, 32> traffic_secret{};
    for (size_t i = 0; i < 32; ++i)
        traffic_secret[i] = static_cast<uint8_t>(i + 0x20);

    rio.activate_write_keys(Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256, traffic_secret);
    rio.activate_read_keys(Tls13CipherSuite::TLS_CHACHA20_POLY1305_SHA256, traffic_secret);

    uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    rio.send_record(ContentType::application_data, payload);

    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    auto rec = rio.recv_record();
    assert(rec.ok());
    assert(rec.value.content_type == ContentType::application_data);
    assert(rec.value.fragment.size() == 4);
    assert(rec.value.fragment[0] == 0xDE);
    assert(rec.value.fragment[3] == 0xEF);
}

void test_encrypted_aes256() {
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    // AES-256-GCM-SHA384 uses 48-byte traffic secrets
    std::array<uint8_t, 48> traffic_secret{};
    for (size_t i = 0; i < 48; ++i)
        traffic_secret[i] = static_cast<uint8_t>(i);

    rio.activate_write_keys(Tls13CipherSuite::TLS_AES_256_GCM_SHA384, traffic_secret);
    rio.activate_read_keys(Tls13CipherSuite::TLS_AES_256_GCM_SHA384, traffic_secret);

    uint8_t payload[] = {0x01, 0x02, 0x03};
    rio.send_record(ContentType::handshake, payload);

    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    auto rec = rio.recv_record();
    assert(rec.ok());
    assert(rec.value.content_type == ContentType::handshake);
    assert(rec.value.fragment.size() == 3);
}

void test_key_reactivation() {
    // Test that activating new keys resets the sequence number.
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    std::array<uint8_t, 32> hs_secret{};
    for (size_t i = 0; i < 32; ++i)
        hs_secret[i] = static_cast<uint8_t>(i + 1);

    std::array<uint8_t, 32> app_secret{};
    for (size_t i = 0; i < 32; ++i)
        app_secret[i] = static_cast<uint8_t>(i + 0x80);

    // Phase 1: handshake keys
    rio.activate_write_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, hs_secret);
    uint8_t p1[] = {0x01};
    rio.send_record(ContentType::handshake, p1);

    // Phase 2: switch to application keys
    rio.activate_write_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, app_secret);
    uint8_t p2[] = {0x02};
    rio.send_record(ContentType::application_data, p2);

    // Read phase 1 with handshake keys
    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    rio.activate_read_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, hs_secret);
    auto rec1 = rio.recv_record();
    assert(rec1.ok());
    assert(rec1.value.content_type == ContentType::handshake);
    assert(rec1.value.fragment[0] == 0x01);

    // Switch read keys to application
    rio.activate_read_keys(Tls13CipherSuite::TLS_AES_128_GCM_SHA256, app_secret);
    auto rec2 = rio.recv_record();
    assert(rec2.ok());
    assert(rec2.value.content_type == ContentType::application_data);
    assert(rec2.value.fragment[0] == 0x02);
}

void test_handshake_reader_basic() {
    memory_transport mt;
    tls13_record_io<memory_transport> rio(mt);

    // Build a handshake record containing a Finished message (type=20, len=12, data=12 bytes)
    TlsWriter<64> hw;
    hw.write_u8(20);  // HandshakeType::finished
    hw.write_u24(12); // body length
    for (int i = 0; i < 12; ++i)
        hw.write_u8(static_cast<uint8_t>(i + 0xA0));

    rio.send_record(ContentType::handshake, hw.data());

    // Copy tx -> rx
    mt.rx_buf.len = 0;
    mt.rx_pos = 0;
    for (size_t i = 0; i < mt.tx_buf.size(); ++i)
        mt.rx_buf.push_back(mt.tx_buf[i]);
    mt.tx_buf.len = 0;

    tls13_handshake_reader<memory_transport> reader(rio);
    TranscriptHash<sha256_state> transcript;

    auto msg = reader.next_message(transcript);
    assert(msg.ok());
    assert(msg.value.size() == 16); // 4 header + 12 body
    assert(msg.value[0] == 20); // HandshakeType::finished

    // Verify transcript was updated
    auto hash = transcript.current_hash();
    // Hash should be non-zero (we fed 16 bytes)
    bool all_zero = true;
    for (auto b : hash) if (b != 0) all_zero = false;
    assert(!all_zero);
}

int main() {
    test_plaintext_send_recv();
    test_ccs_dropped();
    test_encrypted_round_trip();
    test_encrypted_multiple_records();
    test_encrypted_chacha20();
    test_encrypted_aes256();
    test_key_reactivation();
    test_handshake_reader_basic();
    return 0;
}
