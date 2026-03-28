#include <asn1/fixed_string.hpp>
#include <asn1/fixed_vector.hpp>

using namespace asn1;

// FixedString tests
static_assert(FixedString<16>{"hello"}.size() == 5);
static_assert(FixedString<16>{"hello"}.view() == "hello");
static_assert(FixedString<16>{"hello"} == std::string_view{"hello"});
static_assert(FixedString<16>{} .empty());
static_assert(!FixedString<16>{"x"}.empty());
static_assert(FixedString<16>{"abc"}[1] == 'b');

consteval auto test_append() -> FixedString<32> {
    FixedString<32> s{"hello"};
    s.append(" world");
    return s;
}
static_assert(test_append().view() == "hello world");

consteval auto test_push_back() -> FixedString<16> {
    FixedString<16> s;
    s.push_back('a');
    s.push_back('b');
    return s;
}
static_assert(test_push_back().view() == "ab");

// FixedVector tests
consteval auto test_vec_push() -> FixedVector<int, 8> {
    FixedVector<int, 8> v;
    v.push_back(10);
    v.push_back(20);
    v.push_back(30);
    return v;
}
static_assert(test_vec_push().size() == 3);
static_assert(test_vec_push()[0] == 10);
static_assert(test_vec_push()[2] == 30);
static_assert(test_vec_push().back() == 30);

static_assert(FixedVector<int, 4>{}.empty());

consteval auto test_vec_eq() -> bool {
    FixedVector<int, 4> a, b;
    a.push_back(1); a.push_back(2);
    b.push_back(1); b.push_back(2);
    return a == b;
}
static_assert(test_vec_eq());

int main() {
    return 0;
}
