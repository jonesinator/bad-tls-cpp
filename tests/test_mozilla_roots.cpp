#include <x509/mozilla_roots.hpp>
#include <cassert>
#include <cstdio>

void test_load_roots() {
    auto store = asn1::x509::load_mozilla_roots();
    // Mozilla bundle has ~130-150 root CAs
    std::printf("Loaded %zu root certificates\n", store.roots.size());
    assert(store.roots.size() > 100);
    assert(store.roots.size() < 200);
}

void test_roots_have_subjects() {
    auto store = asn1::x509::load_mozilla_roots();
    // Every root should have a non-empty subject DER
    for (auto& root : store.roots) {
        assert(!root.subject_der.empty());
        assert(!root.cert_der.empty());
    }
}

int main() {
    test_load_roots();
    test_roots_have_subjects();
    return 0;
}
