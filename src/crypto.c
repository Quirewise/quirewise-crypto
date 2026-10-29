#include "quirewise/crypto.h"

#include <string.h>

enum {
    RSA_512_BYTES = 64,
    RSA_512_LIMBS = 16,
    RSA_512_BITS = 512
};

typedef struct DesSchedule {
    uint64_t round_keys[16];
} DesSchedule;

static const uint8_t des_ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};
static const uint8_t des_fp[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};
static const uint8_t des_e[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};
static const uint8_t des_p[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};
static const uint8_t des_pc1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};
static const uint8_t des_pc2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
static const uint8_t des_shifts[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};
static const uint8_t des_sbox[8][64] = {
    {
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    }, {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    }, {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    }, {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    }, {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    }, {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    }, {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    }, {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    }
};

static uint64_t des_permute(uint64_t input, unsigned input_bits,
                            const uint8_t *table, unsigned output_bits)
{
    uint64_t output = 0;
    unsigned i;
    for (i = 0; i < output_bits; ++i)
        output = (output << 1) |
                 ((input >> (input_bits - table[i])) & UINT64_C(1));
    return output;
}

static uint64_t read_be64(const uint8_t bytes[8])
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) value = (value << 8) | bytes[i];
    return value;
}

static void write_be64(uint64_t value, uint8_t bytes[8])
{
    unsigned i;
    for (i = 0; i < 8; ++i) {
        bytes[7u - i] = (uint8_t)value;
        value >>= 8;
    }
}

static void des_schedule_init(DesSchedule *schedule, const uint8_t key[8])
{
    uint64_t selected = des_permute(read_be64(key), 64, des_pc1, 56);
    uint32_t c = (uint32_t)((selected >> 28) & UINT64_C(0x0fffffff));
    uint32_t d = (uint32_t)(selected & UINT64_C(0x0fffffff));
    unsigned round;
    for (round = 0; round < 16; ++round) {
        unsigned shift = des_shifts[round];
        c = ((c << shift) | (c >> (28u - shift))) & UINT32_C(0x0fffffff);
        d = ((d << shift) | (d >> (28u - shift))) & UINT32_C(0x0fffffff);
        schedule->round_keys[round] =
            des_permute(((uint64_t)c << 28) | d, 56, des_pc2, 48);
    }
    qw_crypto_secure_zero(&selected, sizeof(selected));
    qw_crypto_secure_zero(&c, sizeof(c));
    qw_crypto_secure_zero(&d, sizeof(d));
}

static uint32_t des_round(uint32_t right, uint64_t round_key)
{
    uint64_t expanded = des_permute(right, 32, des_e, 48) ^ round_key;
    uint32_t substituted = 0;
    uint32_t result;
    unsigned box;
    for (box = 0; box < 8; ++box) {
        unsigned six = (unsigned)((expanded >> (42u - box * 6u)) & 0x3fu);
        unsigned row = ((six & 0x20u) >> 4) | (six & 1u);
        unsigned column = (six >> 1) & 0x0fu;
        substituted = (substituted << 4) |
                      des_sbox[box][row * 16u + column];
    }
    result = (uint32_t)des_permute(substituted, 32, des_p, 32);
    qw_crypto_secure_zero(&expanded, sizeof(expanded));
    qw_crypto_secure_zero(&substituted, sizeof(substituted));
    return result;
}

static uint64_t des_block(uint64_t input, const DesSchedule *schedule,
                          int decrypt)
{
    uint64_t permuted = des_permute(input, 64, des_ip, 64);
    uint32_t left = (uint32_t)(permuted >> 32);
    uint32_t right = (uint32_t)permuted;
    uint64_t result;
    unsigned round;
    for (round = 0; round < 16; ++round) {
        unsigned key_index = decrypt ? 15u - round : round;
        uint32_t next = left ^ des_round(right, schedule->round_keys[key_index]);
        left = right;
        right = next;
        qw_crypto_secure_zero(&next, sizeof(next));
    }
    result = des_permute(((uint64_t)right << 32) | left, 64, des_fp, 64);
    qw_crypto_secure_zero(&permuted, sizeof(permuted));
    qw_crypto_secure_zero(&left, sizeof(left));
    qw_crypto_secure_zero(&right, sizeof(right));
    return result;
}

static uint64_t triple_des_encrypt(uint64_t block,
                                  const DesSchedule schedules[3])
{
    uint64_t first = des_block(block, &schedules[0], 0);
    uint64_t second = des_block(first, &schedules[1], 1);
    uint64_t result = des_block(second, &schedules[2], 0);
    qw_crypto_secure_zero(&block, sizeof(block));
    qw_crypto_secure_zero(&first, sizeof(first));
    qw_crypto_secure_zero(&second, sizeof(second));
    return result;
}

static uint32_t load_le32(const uint8_t bytes[4])
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void store_le32(uint32_t value, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int bigint_is_zero(const uint32_t value[16])
{
    uint32_t combined = 0;
    unsigned i;
    for (i = 0; i < 16; ++i) combined |= value[i];
    return combined == 0;
}

static int bigint_compare(const uint32_t left[16], const uint32_t right[16])
{
    unsigned i = 16;
    while (i > 0) {
        --i;
        if (left[i] > right[i]) return 1;
        if (left[i] < right[i]) return -1;
    }
    return 0;
}

static void bigint_subtract(uint32_t output[16],
                            const uint32_t left[16],
                            const uint32_t right[16])
{
    uint64_t borrow = 0;
    unsigned i;
    for (i = 0; i < 16; ++i) {
        uint64_t subtrahend = (uint64_t)right[i] + borrow;
        uint64_t minuend = left[i];
        output[i] = (uint32_t)(minuend - subtrahend);
        borrow = minuend < subtrahend;
    }
}

static void bigint_add_mod(uint32_t output[16], const uint32_t left[16],
                           const uint32_t right[16],
                           const uint32_t modulus[16])
{
    uint32_t sum[17] = {0};
    uint64_t carry = 0;
    unsigned i;
    for (i = 0; i < 16; ++i) {
        uint64_t value = (uint64_t)left[i] + right[i] + carry;
        sum[i] = (uint32_t)value;
        carry = value >> 32;
    }
    sum[16] = (uint32_t)carry;
    if (sum[16] != 0 || bigint_compare(sum, modulus) >= 0) {
        uint64_t borrow = 0;
        for (i = 0; i < 16; ++i) {
            uint64_t subtrahend = (uint64_t)modulus[i] + borrow;
            uint64_t minuend = sum[i];
            sum[i] = (uint32_t)(minuend - subtrahend);
            borrow = minuend < subtrahend;
        }
        sum[16] = (uint32_t)((uint64_t)sum[16] - borrow);
    }
    memcpy(output, sum, 16u * sizeof(output[0]));
    qw_crypto_secure_zero(sum, sizeof(sum));
}

static void bigint_multiply_mod(uint32_t output[16], const uint32_t left[16],
                                const uint32_t right[16],
                                const uint32_t modulus[16])
{
    uint32_t accumulator[16] = {0};
    uint32_t addend[16];
    uint32_t temporary[16];
    unsigned bit;
    memcpy(addend, left, sizeof(addend));
    for (bit = 0; bit < RSA_512_BITS; ++bit) {
        if ((right[bit / 32u] & (UINT32_C(1) << (bit % 32u))) != 0u) {
            bigint_add_mod(temporary, accumulator, addend, modulus);
            memcpy(accumulator, temporary, sizeof(accumulator));
        }
        bigint_add_mod(temporary, addend, addend, modulus);
        memcpy(addend, temporary, sizeof(addend));
    }
    memcpy(output, accumulator, sizeof(accumulator));
    qw_crypto_secure_zero(accumulator, sizeof(accumulator));
    qw_crypto_secure_zero(addend, sizeof(addend));
    qw_crypto_secure_zero(temporary, sizeof(temporary));
}

uint32_t qw_crypto_abi_version(void)
{
    return UINT32_C(0x00010000);
}

void qw_crypto_secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    while (size > 0u) {
        *bytes++ = 0;
        --size;
    }
}

QwCryptoStatus qw_crypto_rsa_mod_exp_512_le(
    const uint8_t ciphertext[64], const uint8_t exponent[64],
    const uint8_t modulus[64], uint8_t output[64])
{
    uint32_t base[16] = {0};
    uint32_t power[16] = {0};
    uint32_t mod[16] = {0};
    uint32_t result[16] = {0};
    uint32_t temporary[16] = {0};
    uint8_t encoded[RSA_512_BYTES] = {0};
    QwCryptoStatus status = QW_CRYPTO_OK;
    unsigned i;

    if (!ciphertext || !exponent || !modulus || !output)
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    for (i = 0; i < 16; ++i) {
        base[i] = load_le32(ciphertext + i * 4u);
        power[i] = load_le32(exponent + i * 4u);
        mod[i] = load_le32(modulus + i * 4u);
    }
    if (bigint_is_zero(mod)) {
        status = QW_CRYPTO_ERR_INVALID_MODULUS;
        goto done;
    }
    if (bigint_is_zero(power)) {
        status = QW_CRYPTO_ERR_INVALID_ARGUMENT;
        goto done;
    }
    if (bigint_compare(base, mod) >= 0) {
        status = QW_CRYPTO_ERR_OUT_OF_RANGE;
        goto done;
    }

    result[0] = 1u;
    if (bigint_compare(result, mod) >= 0) {
        bigint_subtract(temporary, result, mod);
        memcpy(result, temporary, sizeof(result));
    }
    for (i = 0; i < RSA_512_BITS; ++i) {
        if ((power[i / 32u] & (UINT32_C(1) << (i % 32u))) != 0u) {
            bigint_multiply_mod(temporary, result, base, mod);
            memcpy(result, temporary, sizeof(result));
        }
        bigint_multiply_mod(temporary, base, base, mod);
        memcpy(base, temporary, sizeof(base));
    }
    for (i = 0; i < 16; ++i) store_le32(result[i], encoded + i * 4u);
    memcpy(output, encoded, sizeof(encoded));

done:
    qw_crypto_secure_zero(base, sizeof(base));
    qw_crypto_secure_zero(power, sizeof(power));
    qw_crypto_secure_zero(mod, sizeof(mod));
    qw_crypto_secure_zero(result, sizeof(result));
    qw_crypto_secure_zero(temporary, sizeof(temporary));
    qw_crypto_secure_zero(encoded, sizeof(encoded));
    return status;
}

static QwCryptoStatus triple_des_mode(const uint8_t key[24],
                                      const uint8_t iv[8],
                                      uint8_t *data,
                                      size_t size,
                                      int ofb)
{
    DesSchedule schedules[3] = {{{0}}};
    uint8_t state[8] = {0};
    uint8_t stream[8] = {0};
    size_t offset;
    unsigned position = 0;

    if (!key || !iv || (size != 0u && !data))
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    if (size == 0u) return QW_CRYPTO_OK;
    des_schedule_init(&schedules[0], key);
    des_schedule_init(&schedules[1], key + 8u);
    des_schedule_init(&schedules[2], key + 16u);
    memcpy(state, iv, sizeof(state));
    for (offset = 0; offset < size; ++offset) {
        uint8_t input;
        if (position == 0u) {
            uint64_t encrypted = triple_des_encrypt(read_be64(state), schedules);
            write_be64(encrypted, stream);
            qw_crypto_secure_zero(&encrypted, sizeof(encrypted));
        }
        input = data[offset];
        data[offset] = (uint8_t)(input ^ stream[position]);
        state[position] = ofb ? stream[position] : input;
        position = (position + 1u) & 7u;
        qw_crypto_secure_zero(&input, sizeof(input));
    }
    qw_crypto_secure_zero(schedules, sizeof(schedules));
    qw_crypto_secure_zero(state, sizeof(state));
    qw_crypto_secure_zero(stream, sizeof(stream));
    return QW_CRYPTO_OK;
}

QwCryptoStatus qw_crypto_3des_cfb64_decrypt(const uint8_t key[24],
                                            const uint8_t iv[8],
                                            uint8_t *data,
                                            size_t size)
{
    return triple_des_mode(key, iv, data, size, 0);
}

QwCryptoStatus qw_crypto_3des_ofb64_crypt(const uint8_t key[24],
                                          const uint8_t iv[8],
                                          uint8_t *data,
                                          size_t size)
{
    return triple_des_mode(key, iv, data, size, 1);
}
