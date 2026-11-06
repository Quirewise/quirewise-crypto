#include "quirewise/crypto.h"

QwCryptoStatus qw_crypto_founder_ceb_keystream(const uint8_t *key,
                                                size_t key_size,
                                                uint8_t *stream,
                                                size_t stream_size)
{
    uint8_t state[256];
    uint8_t i = 0;
    uint8_t j = 0;

    if ((stream_size != 0u && (!key || key_size == 0u || !stream)) ||
        (key_size != 0u && !key)) {
        return QW_CRYPTO_ERR_INVALID_ARGUMENT;
    }
    if (stream_size == 0u) return QW_CRYPTO_OK;

    for (size_t n = 0; n < sizeof(state); ++n) state[n] = (uint8_t)n;
    for (size_t n = 0; n < sizeof(state); ++n) {
        j = (uint8_t)(j + state[n] + (uint8_t)(key[n % key_size] | 0xaau));
        {
            uint8_t temporary = state[n];
            state[n] = state[j];
            state[j] = temporary;
            qw_crypto_secure_zero(&temporary, sizeof(temporary));
        }
    }
    j = 0;
    for (size_t n = 0; n < stream_size; ++n) {
        uint8_t old_si;
        i = (uint8_t)(i + 1u);
        old_si = state[i];
        j = (uint8_t)(j + old_si);
        state[i] = state[j];
        state[j] = state[old_si];
        stream[n] = state[(uint8_t)(state[i] + state[j])];
    }
    qw_crypto_secure_zero(state, sizeof(state));
    qw_crypto_secure_zero(&i, sizeof(i));
    qw_crypto_secure_zero(&j, sizeof(j));
    return QW_CRYPTO_OK;
}
