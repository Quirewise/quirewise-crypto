/*
 * RIPEMD-128, the four-word variant of the RIPEMD family (Dobbertin,
 * Bosselaers and Preneel, 1996; ISO/IEC 10118-3). MDict key blocks derive
 * their block keys from it.
 *
 * The compression function runs the two parallel lines of RIPEMD-160's
 * four-round ancestor: both lines share the message orders and rotation
 * tables, the right line applies the boolean functions in reverse order,
 * and the four words are combined into four output words.
 */

#include <quirewise/crypto.h>

#include <string.h>

/* Message word order per round for the left and right lines. */
static const uint8_t rmd_left_index[4][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 },
    { 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12 },
    { 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2 }
};

static const uint8_t rmd_right_index[4][16] = {
    { 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12 },
    { 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2 },
    { 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13 },
    { 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14 }
};

/* Left-rotation amounts per round for the left and right lines. */
static const uint8_t rmd_left_rotate[4][16] = {
    { 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 },
    { 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12 },
    { 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5 },
    { 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 }
};

static const uint8_t rmd_right_rotate[4][16] = {
    { 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6 },
    { 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11 },
    { 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5 },
    { 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 }
};

static const uint32_t rmd_left_constant[4] = {
    0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu
};

static const uint32_t rmd_right_constant[4] = {
    0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x00000000u
};

static uint32_t rmd_rotate_left(uint32_t value, unsigned shift)
{
    return (value << shift) | (value >> (32u - shift));
}

static uint32_t rmd_boolean(unsigned round, uint32_t x, uint32_t y, uint32_t z)
{
    switch (round) {
    case 0u: return x ^ y ^ z;
    case 1u: return (x & y) | (~x & z);
    case 2u: return (x | ~y) ^ z;
    default: return (x & z) | (y & ~z);
    }
}

static uint32_t rmd_load32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void rmd_store32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

/* One 64-byte block; the step formula is the four-word ancestor of
 * RIPEMD-160 and the two lines combine by rotating the words by one. */
static void rmd_block(uint32_t state[4], const uint8_t block[64])
{
    uint32_t words[16];
    uint32_t left[4];
    uint32_t right[4];
    unsigned round;
    unsigned step;
    unsigned index;

    for (index = 0u; index < 16u; ++index)
        words[index] = rmd_load32(block + index * 4u);
    memcpy(left, state, sizeof(left));
    memcpy(right, state, sizeof(right));

    for (round = 0u; round < 4u; ++round) {
        for (step = 0u; step < 16u; ++step) {
            uint32_t value =
                rmd_rotate_left(left[0] +
                                    rmd_boolean(round, left[1], left[2],
                                                left[3]) +
                                    words[rmd_left_index[round][step]] +
                                    rmd_left_constant[round],
                                rmd_left_rotate[round][step]);
            uint32_t previous = left[3];
            left[3] = left[2];
            left[2] = left[1];
            left[1] = value;
            left[0] = previous;
            value = rmd_rotate_left(right[0] +
                                        rmd_boolean(3u - round, right[1],
                                                    right[2], right[3]) +
                                        words[rmd_right_index[round][step]] +
                                        rmd_right_constant[round],
                                    rmd_right_rotate[round][step]);
            previous = right[3];
            right[3] = right[2];
            right[2] = right[1];
            right[1] = value;
            right[0] = previous;
        }
    }

    {
        uint32_t combined = state[1] + left[2] + right[3];
        state[1] = state[2] + left[3] + right[0];
        state[2] = state[3] + left[0] + right[1];
        state[3] = state[0] + left[1] + right[2];
        state[0] = combined;
    }
}

QwCryptoStatus qw_crypto_ripemd128(const uint8_t *data, size_t size,
                                   uint8_t digest[16])
{
    uint32_t state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu,
                          0x10325476u };
    uint8_t tail[128];
    size_t offset = 0u;
    size_t remainder;
    size_t padded;
    uint64_t bits;
    unsigned index;

    if (!digest) return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    if (!data && size) return QW_CRYPTO_ERR_INVALID_ARGUMENT;

    while (size - offset >= 64u) {
        rmd_block(state, data + offset);
        offset += 64u;
    }
    remainder = size - offset;
    memset(tail, 0, sizeof(tail));
    if (remainder) memcpy(tail, data + offset, remainder);
    tail[remainder] = 0x80u;
    padded = (remainder + 1u <= 56u) ? 64u : 128u;
    bits = (uint64_t)size * 8u;
    for (index = 0u; index < 8u; ++index)
        tail[padded - 8u + index] = (uint8_t)(bits >> (8u * index));
    rmd_block(state, tail);
    if (padded == 128u) rmd_block(state, tail + 64);
    for (index = 0u; index < 4u; ++index)
        rmd_store32(digest + index * 4u, state[index]);
    return QW_CRYPTO_OK;
}
