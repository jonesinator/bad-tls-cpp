/**
 * Poly1305 message authentication code — RFC 7539 Section 2.5.
 *
 * One-time authenticator using polynomial evaluation over GF(2^130 - 5).
 * Uses a 5-limb 26-bit representation for the 130-bit accumulator.
 *
 * Provides both incremental (init/update/finalize) and one-shot interfaces.
 *
 * Fully constexpr.
 */

#ifndef POLY1305_HPP_
#define POLY1305_HPP_

#include <array>
#include <cstdint>
#include <span>

namespace poly1305_detail {

constexpr uint32_t le_load32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

constexpr void le_store32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

} // namespace poly1305_detail

struct poly1305_state {
    // Accumulator h in 5 limbs of 26 bits each
    uint32_t h[5]{};
    // Clamped key r in 5 limbs
    uint32_t r[5]{};
    // Key s (second 16 bytes), stored as-is for final addition
    uint32_t s[4]{};
    // Partial block buffer
    uint8_t buf[16]{};
    size_t buf_len = 0;

    constexpr void init(std::span<const uint8_t, 32> key) noexcept {
        // Decode r (first 16 bytes) and clamp per RFC 7539 Section 2.5
        uint32_t t0 = poly1305_detail::le_load32(key.data());
        uint32_t t1 = poly1305_detail::le_load32(key.data() + 4);
        uint32_t t2 = poly1305_detail::le_load32(key.data() + 8);
        uint32_t t3 = poly1305_detail::le_load32(key.data() + 12);

        // Clamp: clear top bits of certain bytes
        t0 &= 0x0fffffff;
        t1 &= 0x0ffffffc;
        t2 &= 0x0ffffffc;
        t3 &= 0x0ffffffc;

        // Pack into 5 limbs of 26 bits
        r[0] = t0 & 0x3ffffff;
        r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        r[4] = (t3 >> 8) & 0x3ffffff;

        // Decode s (second 16 bytes)
        s[0] = poly1305_detail::le_load32(key.data() + 16);
        s[1] = poly1305_detail::le_load32(key.data() + 20);
        s[2] = poly1305_detail::le_load32(key.data() + 24);
        s[3] = poly1305_detail::le_load32(key.data() + 28);

        // Zero accumulator and buffer
        for (int i = 0; i < 5; ++i) h[i] = 0;
        for (int i = 0; i < 16; ++i) buf[i] = 0;
        buf_len = 0;
    }

    constexpr void update(std::span<const uint8_t> data) noexcept {
        size_t pos = 0;

        // Fill partial buffer first
        if (buf_len > 0) {
            size_t need = 16 - buf_len;
            size_t take = data.size() < need ? data.size() : need;
            for (size_t i = 0; i < take; ++i)
                buf[buf_len + i] = data[i];
            buf_len += take;
            pos += take;
            if (buf_len < 16) return;
            process_block(buf, true);
            buf_len = 0;
        }

        // Process full 16-byte blocks
        while (pos + 16 <= data.size()) {
            uint8_t block[16];
            for (int i = 0; i < 16; ++i)
                block[i] = data[pos + i];
            process_block(block, true);
            pos += 16;
        }

        // Buffer remaining partial block
        size_t remaining = data.size() - pos;
        for (size_t i = 0; i < remaining; ++i)
            buf[i] = data[pos + i];
        buf_len = remaining;
    }

    constexpr std::array<uint8_t, 16> finalize() noexcept {
        // Process final partial block (if any) with padding
        if (buf_len > 0) {
            // Pad: add 0x01 byte, then zeros
            uint8_t block[16]{};
            for (size_t i = 0; i < buf_len; ++i)
                block[i] = buf[i];
            block[buf_len] = 0x01;
            // Process without the hibit (partial block)
            process_block(block, false);
        }

        // Final reduction
        // Compute h mod 2^130 - 5 fully
        uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

        // Full carry propagation
        uint32_t c;
        c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
        c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
        c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
        c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        // Compute h + -(2^130 - 5) = h - 2^130 + 5
        uint32_t g0 = h0 + 5;
        c = g0 >> 26; g0 &= 0x3ffffff;
        uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        uint32_t g4 = h4 + c - (1 << 26);

        // Select h if h < p, else g (if g didn't underflow)
        // mask is all-ones if g4 has bit 31 set (underflow), all-zeros otherwise
        uint32_t mask = (g4 >> 31) - 1;  // 0 if underflow, 0xffffffff if no underflow
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Pack h into 4 x uint32_t (little-endian 128-bit)
        uint64_t f;
        f = static_cast<uint64_t>(h0) | (static_cast<uint64_t>(h1) << 26);
        uint32_t out0 = static_cast<uint32_t>(f); f >>= 32;
        f += static_cast<uint64_t>(h2) << 20;
        uint32_t out1 = static_cast<uint32_t>(f); f >>= 32;
        f += static_cast<uint64_t>(h3) << 14;
        uint32_t out2 = static_cast<uint32_t>(f); f >>= 32;
        f += static_cast<uint64_t>(h4) << 8;
        uint32_t out3 = static_cast<uint32_t>(f);

        // Add s
        uint64_t acc = static_cast<uint64_t>(out0) + s[0]; out0 = static_cast<uint32_t>(acc); acc >>= 32;
        acc += static_cast<uint64_t>(out1) + s[1]; out1 = static_cast<uint32_t>(acc); acc >>= 32;
        acc += static_cast<uint64_t>(out2) + s[2]; out2 = static_cast<uint32_t>(acc); acc >>= 32;
        acc += static_cast<uint64_t>(out3) + s[3]; out3 = static_cast<uint32_t>(acc);

        // Serialize as little-endian
        std::array<uint8_t, 16> tag{};
        poly1305_detail::le_store32(tag.data(), out0);
        poly1305_detail::le_store32(tag.data() + 4, out1);
        poly1305_detail::le_store32(tag.data() + 8, out2);
        poly1305_detail::le_store32(tag.data() + 12, out3);
        return tag;
    }

private:
    // Process one 16-byte block. hibit = true for full blocks, false for final partial.
    constexpr void process_block(const uint8_t block[16], bool hibit) noexcept {
        uint32_t t0 = poly1305_detail::le_load32(block);
        uint32_t t1 = poly1305_detail::le_load32(block + 4);
        uint32_t t2 = poly1305_detail::le_load32(block + 8);
        uint32_t t3 = poly1305_detail::le_load32(block + 12);

        // Add chunk to accumulator (in 26-bit limbs)
        h[0] += t0 & 0x3ffffff;
        h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h[4] += (t3 >> 8);
        if (hibit) h[4] += (1 << 24);  // set bit 128

        // Multiply h by r
        uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
        uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

        uint64_t d0 = static_cast<uint64_t>(h[0]) * r0
                    + static_cast<uint64_t>(h[1]) * s4
                    + static_cast<uint64_t>(h[2]) * s3
                    + static_cast<uint64_t>(h[3]) * s2
                    + static_cast<uint64_t>(h[4]) * s1;
        uint64_t d1 = static_cast<uint64_t>(h[0]) * r1
                    + static_cast<uint64_t>(h[1]) * r0
                    + static_cast<uint64_t>(h[2]) * s4
                    + static_cast<uint64_t>(h[3]) * s3
                    + static_cast<uint64_t>(h[4]) * s2;
        uint64_t d2 = static_cast<uint64_t>(h[0]) * r2
                    + static_cast<uint64_t>(h[1]) * r1
                    + static_cast<uint64_t>(h[2]) * r0
                    + static_cast<uint64_t>(h[3]) * s4
                    + static_cast<uint64_t>(h[4]) * s3;
        uint64_t d3 = static_cast<uint64_t>(h[0]) * r3
                    + static_cast<uint64_t>(h[1]) * r2
                    + static_cast<uint64_t>(h[2]) * r1
                    + static_cast<uint64_t>(h[3]) * r0
                    + static_cast<uint64_t>(h[4]) * s4;
        uint64_t d4 = static_cast<uint64_t>(h[0]) * r4
                    + static_cast<uint64_t>(h[1]) * r3
                    + static_cast<uint64_t>(h[2]) * r2
                    + static_cast<uint64_t>(h[3]) * r1
                    + static_cast<uint64_t>(h[4]) * r0;

        // Partial reduction: carry propagation with mod 2^130-5
        uint32_t c;
        c = static_cast<uint32_t>(d0 >> 26); h[0] = static_cast<uint32_t>(d0) & 0x3ffffff; d1 += c;
        c = static_cast<uint32_t>(d1 >> 26); h[1] = static_cast<uint32_t>(d1) & 0x3ffffff; d2 += c;
        c = static_cast<uint32_t>(d2 >> 26); h[2] = static_cast<uint32_t>(d2) & 0x3ffffff; d3 += c;
        c = static_cast<uint32_t>(d3 >> 26); h[3] = static_cast<uint32_t>(d3) & 0x3ffffff; d4 += c;
        c = static_cast<uint32_t>(d4 >> 26); h[4] = static_cast<uint32_t>(d4) & 0x3ffffff; h[0] += c * 5;
        c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
    }
};

/**
 * Compute a Poly1305 MAC tag.
 *
 * @param key     32-byte one-time key (r || s).
 * @param message Data to authenticate.
 *
 * @returns 16-byte authentication tag.
 */
constexpr std::array<uint8_t, 16> poly1305_mac(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t> message) noexcept
{
    poly1305_state state;
    state.init(key);
    state.update(message);
    return state.finalize();
}

#endif /* POLY1305_HPP_ */
