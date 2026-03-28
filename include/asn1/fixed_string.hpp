#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace asn1 {

template <std::size_t Cap = 256>
struct FixedString {
    std::array<char, Cap> data{};
    std::size_t len = 0;

    constexpr FixedString() = default;

    constexpr FixedString(std::string_view sv) : len{sv.size()} {
        for (std::size_t i = 0; i < sv.size(); ++i)
            data[i] = sv[i];
    }

    template <std::size_t N>
    constexpr FixedString(const char (&s)[N]) : FixedString{std::string_view{s, N - 1}} {}

    constexpr auto view() const -> std::string_view {
        return {data.data(), len};
    }

    constexpr auto size() const -> std::size_t { return len; }
    constexpr bool empty() const { return len == 0; }

    constexpr auto operator[](std::size_t i) const -> char { return data[i]; }
    constexpr auto operator[](std::size_t i) -> char& { return data[i]; }

    template <std::size_t OtherCap>
    constexpr FixedString& operator=(const FixedString<OtherCap>& other) {
        len = other.len;
        for (std::size_t i = 0; i < other.len; ++i)
            data[i] = other.data[i];
        return *this;
    }

    template <std::size_t OtherCap>
    constexpr FixedString(const FixedString<OtherCap>& other) : len{other.len} {
        for (std::size_t i = 0; i < other.len; ++i)
            data[i] = other.data[i];
    }

    constexpr void append(std::string_view sv) {
        for (std::size_t i = 0; i < sv.size(); ++i)
            data[len++] = sv[i];
    }

    constexpr void push_back(char c) { data[len++] = c; }

    constexpr bool operator==(const FixedString&) const = default;

    constexpr bool operator==(std::string_view sv) const {
        return view() == sv;
    }
};

} // namespace asn1
