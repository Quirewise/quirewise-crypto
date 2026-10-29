#include "quirewise/crypto.h"

static uint32_t read_u32_be(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static uint32_t read_u32_le(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void write_u32_be(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static void write_u32_le(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}

QwCryptoStatus qw_crypto_tea64_ecb_decrypt(const uint8_t key[16],
                                            uint8_t *data, size_t size)
{
    if (!key || (size != 0u && !data) || (size % 8u) != 0u)
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;

    for (size_t offset = 0; offset < size; offset += 8u) {
        uint32_t v0 = read_u32_be(data + offset);
        uint32_t v1 = read_u32_be(data + offset + 4u);
        uint32_t k[4] = {
            read_u32_be(key), read_u32_be(key + 4u),
            read_u32_be(key + 8u), read_u32_be(key + 12u),
        };
        uint32_t sum = UINT32_C(0x9e3779b9) * 16u;
        for (unsigned round = 0; round < 16u; ++round) {
            v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
            v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
            sum -= UINT32_C(0x9e3779b9);
        }
        write_u32_be(data + offset, v0);
        write_u32_be(data + offset + 4u, v1);
        qw_crypto_secure_zero(k, sizeof(k));
        qw_crypto_secure_zero(&v0, sizeof(v0));
        qw_crypto_secure_zero(&v1, sizeof(v1));
        qw_crypto_secure_zero(&sum, sizeof(sum));
    }
    return QW_CRYPTO_OK;
}

QwCryptoStatus qw_crypto_pdg_tea128_ecb_decrypt(const uint8_t key[16],
                                                 uint8_t *data, size_t size)
{
    if (!key || (size != 0u && !data))
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    uint32_t k0 = read_u32_le(key);
    uint32_t k1 = read_u32_le(key + 4u);
    uint32_t k2 = read_u32_le(key + 8u);
    uint32_t k3 = read_u32_le(key + 12u);

    for (size_t offset = 0; size - offset >= 16u; offset += 16u) {
        uint32_t v0 = read_u32_le(data + offset);
        uint32_t v1 = read_u32_le(data + offset + 4u);
        uint32_t v2 = read_u32_le(data + offset + 8u);
        uint32_t v3 = read_u32_le(data + offset + 12u);
        uint32_t sum = UINT32_C(0xe3779b90);

        for (unsigned round = 0; round < 16u; ++round) {
            v3 -= (((v0 >> 5) + k1) ^ ((v0 << 4) + k2) ^ (v0 + sum));
            v2 -= (((v3 << 4) + k0) ^ ((v3 >> 5) + k3) ^ (v3 + sum));
            v1 -= (((v2 >> 5) + k3) ^ ((v2 << 4) + k2) ^ (v2 + sum));
            v0 -= (((v1 << 4) + k0) ^ ((v1 >> 5) + k1) ^ (v1 + sum));
            sum += UINT32_C(0x61c88647);
        }
        write_u32_le(data + offset, v0);
        write_u32_le(data + offset + 4u, v1);
        write_u32_le(data + offset + 8u, v2);
        write_u32_le(data + offset + 12u, v3);
        qw_crypto_secure_zero(&v0, sizeof(v0));
        qw_crypto_secure_zero(&v1, sizeof(v1));
        qw_crypto_secure_zero(&v2, sizeof(v2));
        qw_crypto_secure_zero(&v3, sizeof(v3));
        qw_crypto_secure_zero(&sum, sizeof(sum));
    }
    qw_crypto_secure_zero(&k0, sizeof(k0));
    qw_crypto_secure_zero(&k1, sizeof(k1));
    qw_crypto_secure_zero(&k2, sizeof(k2));
    qw_crypto_secure_zero(&k3, sizeof(k3));
    return QW_CRYPTO_OK;
}
