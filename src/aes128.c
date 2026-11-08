#include "quirewise/crypto.h"

#include "aes.h"

QwCryptoStatus qw_crypto_aes128_ecb_decrypt(const uint8_t key[16],
                                            uint8_t *data, size_t size)
{
    struct AES_ctx context = {0};

    if (!key || (size != 0u && !data) || (size % AES_BLOCKLEN) != 0u) {
        qw_crypto_secure_zero(&context, sizeof(context));
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    }
    if (size == 0u) return QW_CRYPTO_OK;

    AES_init_ctx(&context, key);
    for (size_t offset = 0; offset < size; offset += AES_BLOCKLEN)
        AES_ECB_decrypt(&context, data + offset);
    qw_crypto_secure_zero(&context, sizeof(context));
    return QW_CRYPTO_OK;
}

QwCryptoStatus qw_crypto_aes128_ecb_encrypt(const uint8_t key[16],
                                            uint8_t *data, size_t size)
{
    struct AES_ctx context = {0};

    if (!key || (size != 0u && !data) || (size % AES_BLOCKLEN) != 0u) {
        qw_crypto_secure_zero(&context, sizeof(context));
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    }
    if (size == 0u) return QW_CRYPTO_OK;

    AES_init_ctx(&context, key);
    for (size_t offset = 0; offset < size; offset += AES_BLOCKLEN)
        AES_ECB_encrypt(&context, data + offset);
    qw_crypto_secure_zero(&context, sizeof(context));
    return QW_CRYPTO_OK;
}
