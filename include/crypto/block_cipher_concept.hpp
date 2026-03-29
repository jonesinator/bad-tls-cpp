#ifndef BLOCK_CIPHER_CONCEPT_HPP_
#define BLOCK_CIPHER_CONCEPT_HPP_

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

template <typename B>
concept block_cipher = requires(B b, std::span<const uint8_t, B::key_size> key,
                                std::span<const uint8_t, B::block_size> block) {
    { B::key_size } -> std::convertible_to<size_t>;
    { B::block_size } -> std::convertible_to<size_t>;
    { b.init(key) } -> std::same_as<void>;
    { b.encrypt_block(block) } -> std::same_as<std::array<uint8_t, B::block_size>>;
};

#endif /* BLOCK_CIPHER_CONCEPT_HPP_ */
