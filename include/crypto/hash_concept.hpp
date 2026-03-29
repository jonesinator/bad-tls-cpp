#ifndef HASH_CONCEPT_HPP_
#define HASH_CONCEPT_HPP_

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

template <typename H>
concept hash_function = requires(H h, std::span<const uint8_t> data) {
    { H::block_size } -> std::convertible_to<size_t>;
    { H::digest_size } -> std::convertible_to<size_t>;
    { h.init() } -> std::same_as<void>;
    { h.update(data) } -> std::same_as<void>;
    { h.finalize() } -> std::same_as<std::array<uint8_t, H::digest_size>>;
};

#endif /* HASH_CONCEPT_HPP_ */
