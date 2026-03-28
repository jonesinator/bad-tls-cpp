#pragma once

#include <array>
#include <cstddef>

namespace asn1 {

template <typename T, std::size_t Cap>
struct FixedVector {
    std::array<T, Cap> data{};
    std::size_t len = 0;

    constexpr FixedVector() = default;

    constexpr auto size() const -> std::size_t { return len; }
    constexpr bool empty() const { return len == 0; }

    constexpr void push_back(const T& v) { data[len++] = v; }

    constexpr auto operator[](std::size_t i) const -> const T& { return data[i]; }
    constexpr auto operator[](std::size_t i) -> T& { return data[i]; }

    constexpr auto back() const -> const T& { return data[len - 1]; }
    constexpr auto back() -> T& { return data[len - 1]; }

    constexpr auto begin() const { return data.begin(); }
    constexpr auto end() const { return data.begin() + len; }
    constexpr auto begin() { return data.begin(); }
    constexpr auto end() { return data.begin() + len; }

    constexpr bool operator==(const FixedVector&) const = default;
};

} // namespace asn1
