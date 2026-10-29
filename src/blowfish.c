#include "quirewise/crypto.h"

#include <string.h>

extern const uint32_t qw_crypto_blowfish_p_init[18];
extern const uint32_t qw_crypto_blowfish_s_init[4][256];

static uint32_t blowfish_f(const uint32_t s[4][256], uint32_t x)
{
    return ((s[0][(x >> 24) & 0xFFu] + s[1][(x >> 16) & 0xFFu]) ^ s[2][(x >> 8) & 0xFFu])
           + s[3][x & 0xFFu];
}

static void blowfish_encrypt_block(const uint32_t p[18],
                                   const uint32_t s[4][256],
                                   uint32_t *left,
                                   uint32_t *right)
{
    uint32_t l = *left;
    uint32_t r = *right;

    for (int i = 0; i < 16; ++i) {
        l ^= p[i];
        r ^= blowfish_f(s, l);
        uint32_t swap = l;
        l = r;
        r = swap;
    }
    uint32_t swap = l;
    l = r;
    r = swap;
    r ^= p[16];
    l ^= p[17];

    *left = l;
    *right = r;
}

static void blowfish_decrypt_block(const uint32_t p[18],
                                   const uint32_t s[4][256],
                                   uint32_t *left,
                                   uint32_t *right)
{
    uint32_t l = *left;
    uint32_t r = *right;

    for (int i = 17; i >= 2; --i) {
        l ^= p[i];
        r ^= blowfish_f(s, l);
        uint32_t swap = l;
        l = r;
        r = swap;
    }
    uint32_t swap = l;
    l = r;
    r = swap;
    r ^= p[1];
    l ^= p[0];

    *left = l;
    *right = r;
}

static void blowfish_expand_key(const uint8_t *key, size_t key_length, uint32_t p[18],
                                uint32_t s[4][256])
{
    memcpy(p, qw_crypto_blowfish_p_init, sizeof(qw_crypto_blowfish_p_init));
    memcpy(s, qw_crypto_blowfish_s_init, sizeof(qw_crypto_blowfish_s_init));

    size_t cursor = 0;
    for (int i = 0; i < 18; ++i) {
        uint32_t word = 0;
        for (int byte = 0; byte < 4; ++byte) {
            word = (word << 8) | key[cursor % key_length];
            ++cursor;
        }
        p[i] ^= word;
        qw_crypto_secure_zero(&word, sizeof(word));
    }

    uint32_t l = 0;
    uint32_t r = 0;
    for (int i = 0; i < 18; i += 2) {
        blowfish_encrypt_block(p, s, &l, &r);
        p[i] = l;
        p[i + 1] = r;
    }
    for (int box = 0; box < 4; ++box) {
        for (int i = 0; i < 256; i += 2) {
            blowfish_encrypt_block(p, s, &l, &r);
            s[box][i] = l;
            s[box][i + 1] = r;
        }
    }
    qw_crypto_secure_zero(&l, sizeof(l));
    qw_crypto_secure_zero(&r, sizeof(r));
}


static uint32_t read_u32_be(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static void write_u32_be(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

QwCryptoStatus qw_crypto_blowfish_ecb_decrypt(const uint8_t *key,
                                               size_t key_size,
                                               uint8_t *data, size_t size)
{
    uint32_t p[18];
    uint32_t s[4][256];
    if (!key || key_size < 4u || key_size > 56u ||
        (size != 0u && !data) || (size % 8u) != 0u) {
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    }
    if (size == 0u) return QW_CRYPTO_OK;

    blowfish_expand_key(key, key_size, p, s);
    for (size_t offset = 0; offset < size; offset += 8u) {
        uint32_t left = read_u32_be(data + offset);
        uint32_t right = read_u32_be(data + offset + 4u);
        blowfish_decrypt_block(p, s, &left, &right);
        write_u32_be(data + offset, left);
        write_u32_be(data + offset + 4u, right);
        qw_crypto_secure_zero(&left, sizeof(left));
        qw_crypto_secure_zero(&right, sizeof(right));
    }
    qw_crypto_secure_zero(p, sizeof(p));
    qw_crypto_secure_zero(s, sizeof(s));
    return QW_CRYPTO_OK;
}
