/* SHA-256, SHA-384 and SHA-512 one-shot digests (FIPS 180-4).
 *
 * These are needed by the PDF Standard security handler revision 6
 * (Algorithm 2.B), which hashes the password material with all three
 * functions and feeds the result back through AES-128-CBC.
 */

#include "quirewise/crypto.h"

#include <string.h>

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr32(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32u - count));
}

static void sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t schedule[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0u; index < 16u; ++index) {
        schedule[index] = ((uint32_t)block[index * 4u] << 24) |
                          ((uint32_t)block[index * 4u + 1u] << 16) |
                          ((uint32_t)block[index * 4u + 2u] << 8) |
                          (uint32_t)block[index * 4u + 3u];
    }
    for (index = 16u; index < 64u; ++index) {
        uint32_t s0 = rotr32(schedule[index - 15u], 7u) ^
                      rotr32(schedule[index - 15u], 18u) ^
                      (schedule[index - 15u] >> 3);
        uint32_t s1 = rotr32(schedule[index - 2u], 17u) ^
                      rotr32(schedule[index - 2u], 19u) ^
                      (schedule[index - 2u] >> 10);
        schedule[index] = schedule[index - 16u] + s0 +
                          schedule[index - 7u] + s1;
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (index = 0u; index < 64u; ++index) {
        uint32_t s1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + choice + sha256_k[index] + schedule[index];
        uint32_t s0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

QwCryptoStatus qw_crypto_sha256(const uint8_t *data, size_t size,
                                uint8_t out[32])
{
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint8_t block[64];
    uint64_t bit_length;
    size_t index;
    size_t offset = 0u;
    if (!out || (size && !data)) return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    while (size - offset >= 64u) {
        sha256_compress(state, data + offset);
        offset += 64u;
    }
    memset(block, 0, sizeof(block));
    /* A zero-length digest is valid with data == NULL; memcpy(dst, NULL, 0)
     * is still undefined behaviour and UBSan rejects it. */
    if (size > offset) {
        memcpy(block, data + offset, size - offset);
    }
    block[size - offset] = 0x80u;
    if (size - offset >= 56u) {
        sha256_compress(state, block);
        memset(block, 0, sizeof(block));
    }
    bit_length = (uint64_t)size * 8u;
    for (index = 0u; index < 8u; ++index) {
        block[63u - index] = (uint8_t)(bit_length >> (index * 8u));
    }
    sha256_compress(state, block);
    for (index = 0u; index < 8u; ++index) {
        out[index * 4u] = (uint8_t)(state[index] >> 24);
        out[index * 4u + 1u] = (uint8_t)(state[index] >> 16);
        out[index * 4u + 2u] = (uint8_t)(state[index] >> 8);
        out[index * 4u + 3u] = (uint8_t)state[index];
    }
    return QW_CRYPTO_OK;
}

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full,
    0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull,
    0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 0x2de92c6f592b0275ull,
    0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full,
    0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull,
    0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull,
    0x92722c851482353bull, 0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull,
    0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull,
    0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull,
    0xc67178f2e372532bull, 0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull,
    0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

static uint64_t rotr64(uint64_t value, unsigned int count)
{
    return (value >> count) | (value << (64u - count));
}

static void sha512_compress(uint64_t state[8], const uint8_t block[128])
{
    uint64_t schedule[80];
    uint64_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0u; index < 16u; ++index) {
        schedule[index] = 0u;
        for (size_t byte = 0u; byte < 8u; ++byte) {
            schedule[index] = (schedule[index] << 8) |
                              block[index * 8u + byte];
        }
    }
    for (index = 16u; index < 80u; ++index) {
        uint64_t s0 = rotr64(schedule[index - 15u], 1u) ^
                      rotr64(schedule[index - 15u], 8u) ^
                      (schedule[index - 15u] >> 7);
        uint64_t s1 = rotr64(schedule[index - 2u], 19u) ^
                      rotr64(schedule[index - 2u], 61u) ^
                      (schedule[index - 2u] >> 6);
        schedule[index] = schedule[index - 16u] + s0 +
                          schedule[index - 7u] + s1;
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (index = 0u; index < 80u; ++index) {
        uint64_t s1 = rotr64(e, 14u) ^ rotr64(e, 18u) ^ rotr64(e, 41u);
        uint64_t choice = (e & f) ^ (~e & g);
        uint64_t temp1 = h + s1 + choice + sha512_k[index] + schedule[index];
        uint64_t s0 = rotr64(a, 28u) ^ rotr64(a, 34u) ^ rotr64(a, 39u);
        uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = s0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static QwCryptoStatus sha512_family(const uint8_t *data, size_t size,
                                    uint64_t state[8], uint8_t *out,
                                    size_t out_size)
{
    uint8_t block[128];
    uint64_t bit_length;
    size_t index;
    size_t offset = 0u;
    if (!out || (size && !data)) return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    while (size - offset >= 128u) {
        sha512_compress(state, data + offset);
        offset += 128u;
    }
    memset(block, 0, sizeof(block));
    /* A zero-length digest is valid with data == NULL; memcpy(dst, NULL, 0)
     * is still undefined behaviour and UBSan rejects it. */
    if (size > offset) {
        memcpy(block, data + offset, size - offset);
    }
    block[size - offset] = 0x80u;
    if (size - offset >= 112u) {
        sha512_compress(state, block);
        memset(block, 0, sizeof(block));
    }
    bit_length = (uint64_t)size * 8u;
    /* Length field is 128 bits; the high half stays zero for sizes we accept. */
    for (index = 0u; index < 8u; ++index) {
        block[127u - index] = (uint8_t)(bit_length >> (index * 8u));
    }
    sha512_compress(state, block);
    for (index = 0u; index < out_size; ++index) {
        out[index] = (uint8_t)(state[index / 8u] >> (56u - (index % 8u) * 8u));
    }
    return QW_CRYPTO_OK;
}

QwCryptoStatus qw_crypto_sha384(const uint8_t *data, size_t size,
                                uint8_t out[48])
{
    uint64_t state[8] = {
        0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
        0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
        0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
        0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull
    };
    return sha512_family(data, size, state, out, 48u);
}

QwCryptoStatus qw_crypto_sha512(const uint8_t *data, size_t size,
                                uint8_t out[64])
{
    uint64_t state[8] = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
        0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
        0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
    };
    return sha512_family(data, size, state, out, 64u);
}
