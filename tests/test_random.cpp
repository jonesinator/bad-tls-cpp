#include <crypto/random.hpp>
#include <crypto/ecc.hpp>
#include <cassert>

void test_concept_satisfaction() {
    static_assert(random_generator<system_random>);
    static_assert(random_generator<xoshiro256ss>);
}

void test_xoshiro_deterministic() {
    constexpr auto test = [] {
        xoshiro256ss rng1(42);
        xoshiro256ss rng2(42);
        auto a = random_bytes<32>(rng1);
        auto b = random_bytes<32>(rng2);
        for (size_t i = 0; i < 32; ++i)
            if (a[i] != b[i]) throw "same seed should produce same output";

        // Different seed → different output
        xoshiro256ss rng3(99);
        auto c = random_bytes<32>(rng3);
        bool all_same = true;
        for (size_t i = 0; i < 32; ++i)
            if (a[i] != c[i]) all_same = false;
        if (all_same) throw "different seeds should produce different output";

        return true;
    };
    static_assert(test());
}

void test_xoshiro_fills_all_bytes() {
    constexpr auto test = [] {
        xoshiro256ss rng(123);
        auto bytes = random_bytes<64>(rng);
        // Not all zeros
        bool all_zero = true;
        for (size_t i = 0; i < 64; ++i)
            if (bytes[i] != 0) all_zero = false;
        if (all_zero) throw "output should not be all zeros";
        return true;
    };
    static_assert(test());
}

void test_random_scalar_in_range() {
    // Verify random_scalar produces values in [1, n-1] for P-256
    // Runtime test because curve static methods aren't constexpr-qualified.
    using uint512 = number<uint32_t, 16>;
    using curve = p256<uint512>;

    xoshiro256ss rng(7);
    auto n = curve::n();
    auto zero = uint512(0U);

    for (int i = 0; i < 10; ++i) {
        auto k = random_scalar<curve>(rng);
        assert(k != zero);
        assert(k < n);
    }
}

void test_random_scalar_different_values() {
    using uint512 = number<uint32_t, 16>;
    using curve = p256<uint512>;

    xoshiro256ss rng(42);
    auto a = random_scalar<curve>(rng);
    auto b = random_scalar<curve>(rng);
    assert(!(a == b));
}

void test_system_random() {
    // Runtime test: system_random should produce non-zero output
    system_random rng;
    auto bytes = random_bytes<32>(rng);
    bool all_zero = true;
    for (size_t i = 0; i < 32; ++i)
        if (bytes[i] != 0) all_zero = false;
    assert(!all_zero);

    // Two calls should produce different output (with overwhelming probability)
    auto bytes2 = random_bytes<32>(rng);
    bool same = true;
    for (size_t i = 0; i < 32; ++i)
        if (bytes[i] != bytes2[i]) same = false;
    assert(!same);
}

void test_system_random_scalar() {
    using uint512 = number<uint32_t, 16>;
    using curve = p256<uint512>;

    system_random rng;
    auto k = random_scalar<curve>(rng);
    assert(k != uint512(0U));
    assert(k < curve::n());
}

int main() {
    test_concept_satisfaction();
    test_xoshiro_deterministic();
    test_xoshiro_fills_all_bytes();
    test_random_scalar_in_range();
    test_random_scalar_different_values();
    test_system_random();
    test_system_random_scalar();
    return 0;
}
