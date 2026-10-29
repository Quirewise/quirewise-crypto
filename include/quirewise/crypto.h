#ifndef QUIREWISE_CRYPTO_H
#define QUIREWISE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum QwCryptoStatus {
    QW_CRYPTO_OK = 0,
    QW_CRYPTO_ERR_INVALID_ARGUMENT = 1,
    QW_CRYPTO_ERR_INVALID_MODULUS = 2,
    QW_CRYPTO_ERR_OUT_OF_RANGE = 3
} QwCryptoStatus;

/* ABI version 1.0.0, encoded as 0x00010000. */
uint32_t qw_crypto_abi_version(void);

/* Clear sensitive bytes through a volatile store. NULL is accepted only for size 0. */
void qw_crypto_secure_zero(void *memory, size_t size);

/*
 * Compute ciphertext^exponent mod modulus on fixed-width, 512-bit,
 * little-endian byte strings. Output is unchanged on failure.
 */
QwCryptoStatus qw_crypto_rsa_mod_exp_512_le(
    const uint8_t ciphertext[64],
    const uint8_t exponent[64],
    const uint8_t modulus[64],
    uint8_t output[64]);

/*
 * Decrypt an in-place 3DES CFB64 buffer, or apply 3DES OFB64. The key is
 * three consecutive DES keys and the IV is an 8-byte DES block. Empty input
 * is a successful no-op when key and IV are valid.
 */
QwCryptoStatus qw_crypto_3des_cfb64_decrypt(
    const uint8_t key[24],
    const uint8_t iv[8],
    uint8_t *data,
    size_t size);
QwCryptoStatus qw_crypto_3des_ofb64_crypt(
    const uint8_t key[24],
    const uint8_t iv[8],
    uint8_t *data,
    size_t size);

#ifdef __cplusplus
}
#endif

#endif
