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

/* Caller-owned PDG key schedule for its six-pass 16-byte block transform. */
typedef struct QwCryptoPdgDeslikeSchedule {
    uint32_t round_keys[6][32];
} QwCryptoPdgDeslikeSchedule;

/* ABI version 1.0.0, encoded as 0x00010000. */
uint32_t qw_crypto_abi_version(void);

/* Clear sensitive bytes through a volatile store. NULL is accepted only for size 0. */
void qw_crypto_secure_zero(void *memory, size_t size);

/* Digest bytes with MD5. A NULL data pointer is accepted only for size 0. */
QwCryptoStatus qw_crypto_md5_digest(const void *data, size_t size,
                                    uint8_t digest[16]);

/* Decrypt AES-128 or AES-256 ECB data in place. Size must be block aligned. */
QwCryptoStatus qw_crypto_aes128_ecb_decrypt(const uint8_t key[16],
                                            uint8_t *data, size_t size);
QwCryptoStatus qw_crypto_aes256_ecb_decrypt(const uint8_t key[32],
                                            uint8_t *data, size_t size);

/* Decrypt 8-byte blocks with the 128-bit-key TEA variant used by QMC. */
QwCryptoStatus qw_crypto_tea64_ecb_decrypt(const uint8_t key[16],
                                            uint8_t *data, size_t size);

/*
 * Decrypt complete 16-byte blocks with the 16-round, four-word PDG/PDZ TEA
 * variant. Any trailing partial block is left unchanged to match the engine.
 */
QwCryptoStatus qw_crypto_pdg_tea128_ecb_decrypt(const uint8_t key[16],
                                                 uint8_t *data, size_t size);

/* Standard Blowfish ECB, in place. Key size is 4..56 bytes; data is block aligned. */
QwCryptoStatus qw_crypto_blowfish_ecb_decrypt(const uint8_t *key,
                                               size_t key_size,
                                               uint8_t *data, size_t size);

/*
 * Generate the legacy Founder CEB RC4-like keystream. The key bytes are ORed
 * with 0xAA during setup, matching the container's variant.
 */
QwCryptoStatus qw_crypto_founder_ceb_keystream(const uint8_t *key,
                                                size_t key_size,
                                                uint8_t *stream,
                                                size_t stream_size);

/* PDG's DES-like key schedule and 16-byte block transform. */
QwCryptoStatus qw_crypto_pdg_deslike_schedule_init(
    const uint8_t key[16], QwCryptoPdgDeslikeSchedule *schedule);
QwCryptoStatus qw_crypto_pdg_deslike_transform16(
    uint8_t block[16], const QwCryptoPdgDeslikeSchedule *schedule);
void qw_crypto_pdg_deslike_schedule_clear(QwCryptoPdgDeslikeSchedule *schedule);

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
