#include "quirewise/crypto.h"

#include <string.h>

typedef struct QwMd5Context {
    uint32_t state[4];
    uint64_t bit_count;
    uint8_t buffer[64];
} QwMd5Context;

static uint32_t md5_rotate_left(uint32_t value, uint32_t bits)
{
    return (value << bits) | (value >> (32u - bits));
}

static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
    static const uint32_t constants[64] = {
        0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
        0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
        0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
        0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
        0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
        0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
        0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
        0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
        0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
        0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
        0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
        0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
        0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
        0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
        0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
        0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
    };
    static const uint8_t shifts[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    };
    uint32_t words[16];
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    for (unsigned i = 0; i < 16u; ++i) {
        const size_t offset = (size_t)i * 4u;
        words[i] = (uint32_t)block[offset] |
                   ((uint32_t)block[offset + 1u] << 8) |
                   ((uint32_t)block[offset + 2u] << 16) |
                   ((uint32_t)block[offset + 3u] << 24);
    }

    for (uint32_t i = 0; i < 64u; ++i) {
        uint32_t function;
        uint32_t word_index;
        if (i < 16u) {
            function = (b & c) | (~b & d);
            word_index = i;
        } else if (i < 32u) {
            function = (d & b) | (~d & c);
            word_index = (5u * i + 1u) & 15u;
        } else if (i < 48u) {
            function = b ^ c ^ d;
            word_index = (3u * i + 5u) & 15u;
        } else {
            function = c ^ (b | ~d);
            word_index = (7u * i) & 15u;
        }
        {
            const uint32_t previous_d = d;
            d = c;
            c = b;
            b += md5_rotate_left(a + function + constants[i] +
                                     words[word_index],
                                 shifts[i]);
            a = previous_d;
        }
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    qw_crypto_secure_zero(words, sizeof(words));
    qw_crypto_secure_zero(&a, sizeof(a));
    qw_crypto_secure_zero(&b, sizeof(b));
    qw_crypto_secure_zero(&c, sizeof(c));
    qw_crypto_secure_zero(&d, sizeof(d));
}

static void md5_update(QwMd5Context *context, const uint8_t *data, size_t size)
{
    size_t used = (size_t)((context->bit_count >> 3) & 63u);
    context->bit_count += (uint64_t)size * 8u;

    if (used != 0u) {
        const size_t available = 64u - used;
        if (size < available) {
            memcpy(context->buffer + used, data, size);
            return;
        }
        memcpy(context->buffer + used, data, available);
        md5_transform(context->state, context->buffer);
        data += available;
        size -= available;
    }

    while (size >= 64u) {
        md5_transform(context->state, data);
        data += 64u;
        size -= 64u;
    }
    if (size != 0u) memcpy(context->buffer, data, size);
}

QwCryptoStatus qw_crypto_md5_digest(const void *data, size_t size,
                                    uint8_t digest[16])
{
    static const uint8_t padding[64] = {0x80u};
    QwMd5Context context = {{0}, 0u, {0}};
    uint8_t length[8];
    size_t used;
    size_t pad_size;

    if (!digest || (size != 0u && !data) ||
        (uint64_t)size > UINT64_MAX / 8u) {
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    }

    context.state[0] = 0x67452301u;
    context.state[1] = 0xefcdab89u;
    context.state[2] = 0x98badcfeu;
    context.state[3] = 0x10325476u;
    if (size != 0u) md5_update(&context, (const uint8_t *)data, size);

    used = (size_t)((context.bit_count >> 3) & 63u);
    pad_size = used < 56u ? 56u - used : 120u - used;
    for (unsigned i = 0; i < sizeof(length); ++i)
        length[i] = (uint8_t)(context.bit_count >> (8u * i));
    md5_update(&context, padding, pad_size);
    md5_update(&context, length, sizeof(length));
    for (unsigned i = 0; i < 4u; ++i) {
        const uint32_t word = context.state[i];
        digest[i * 4u] = (uint8_t)word;
        digest[i * 4u + 1u] = (uint8_t)(word >> 8);
        digest[i * 4u + 2u] = (uint8_t)(word >> 16);
        digest[i * 4u + 3u] = (uint8_t)(word >> 24);
    }
    qw_crypto_secure_zero(length, sizeof(length));
    qw_crypto_secure_zero(&context, sizeof(context));
    return QW_CRYPTO_OK;
}
