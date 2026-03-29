#include <tls/tcp_transport.hpp>
#include <cassert>

void test_concept() {
    static_assert(tls::transport<tls::tcp_transport>);
}

void test_connection_failure() {
    tls::tcp_transport t("127.0.0.1", "19999");
    assert(!t.is_connected());
    std::array<uint8_t, 1> buf{};
    assert(t.read(buf) == 0);
    assert(t.write(buf) == 0);
}

void test_move_semantics() {
    tls::tcp_transport t1("127.0.0.1", "19999");
    assert(!t1.is_connected());
    tls::tcp_transport t2(std::move(t1));
    assert(!t1.is_connected());
    assert(!t2.is_connected());
}

int main() {
    test_concept();
    test_connection_failure();
    test_move_semantics();
    return 0;
}
