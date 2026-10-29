#include <quirewise/crypto.h>

#include <stdio.h>
#include <string.h>

static int parse_hex(const char *hex, uint8_t *output, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        unsigned high;
        unsigned low;
        char a = hex[i * 2u];
        char b = hex[i * 2u + 1u];
        if (a >= '0' && a <= '9') high = (unsigned)(a - '0');
        else if (a >= 'a' && a <= 'f') high = (unsigned)(a - 'a' + 10);
        else return 0;
        if (b >= '0' && b <= '9') low = (unsigned)(b - '0');
        else if (b >= 'a' && b <= 'f') low = (unsigned)(b - 'a' + 10);
        else return 0;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return hex[size * 2u] == '\0';
}

static int equal_bytes(const uint8_t *left, const uint8_t *right, size_t size)
{
    return memcmp(left, right, size) == 0;
}

static void reverse_bytes(const uint8_t *input, uint8_t *output, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) output[i] = input[size - 1u - i];
}

static int test_md5(void)
{
    static const char empty_hex[] = "d41d8cd98f00b204e9800998ecf8427e";
    static const char abc_hex[] = "900150983cd24fb0d6963f7d28e17f72";
    uint8_t digest[16];
    uint8_t expected[16];

    if (!parse_hex(empty_hex, expected, sizeof(expected)) ||
        qw_crypto_md5_digest(NULL, 0u, digest) != QW_CRYPTO_OK ||
        !equal_bytes(digest, expected, sizeof(digest))) return 0;
    if (!parse_hex(abc_hex, expected, sizeof(expected)) ||
        qw_crypto_md5_digest("abc", 3u, digest) != QW_CRYPTO_OK ||
        !equal_bytes(digest, expected, sizeof(digest))) return 0;
    return qw_crypto_md5_digest(NULL, 1u, digest) ==
           QW_CRYPTO_ERR_INVALID_ARGUMENT;
}

static int test_block_crypto(void)
{
    static const char aes128_key_hex[] =
        "2b7e151628aed2a6abf7158809cf4f3c";
    static const char aes128_cipher_hex[] =
        "3ad77bb40d7a3660a89ecaf32466ef97";
    static const char aes128_plain_hex[] =
        "6bc1bee22e409f96e93d7e117393172a";
    static const char aes256_key_hex[] =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    static const char aes256_cipher_hex[] =
        "8ea2b7ca516745bfeafc49904b496089";
    static const char aes256_plain_hex[] =
        "00112233445566778899aabbccddeeff";
    static const char blowfish_key_hex[] = "0000000000000000";
    static const char blowfish_cipher_hex[] = "4ef997456198dd78";
    static const char zeros8_hex[] = "0000000000000000";
    static const char tea_key_hex[] = "000102030405060708090a0b0c0d0e0f";
    static const char tea_cipher_hex[] = "205f515574f0821c";
    static const char tea_plain_hex[] = "0011223344556677";
    static const char pdg_tea_cipher_hex[] =
        "bfd3a60001a9f090e4f93af660be2be7a1b2c3";
    static const char pdg_tea_plain_hex[] =
        "00112233445566778899aabbccddeeffa1b2c3";
    uint8_t key[32];
    uint8_t data[32];
    uint8_t expected[32];

    if (!parse_hex(aes128_key_hex, key, 16u) ||
        !parse_hex(aes128_cipher_hex, data, 16u) ||
        !parse_hex(aes128_plain_hex, expected, 16u) ||
        qw_crypto_aes128_ecb_decrypt(key, data, 16u) != QW_CRYPTO_OK ||
        !equal_bytes(data, expected, 16u)) {
        fputs("AES-128 ECB vector failed\n", stderr);
        return 0;
    }

    if (!parse_hex(aes256_key_hex, key, 32u) ||
        !parse_hex(aes256_cipher_hex, data, 16u) ||
        !parse_hex(aes256_plain_hex, expected, 16u) ||
        qw_crypto_aes256_ecb_decrypt(key, data, 16u) != QW_CRYPTO_OK ||
        !equal_bytes(data, expected, 16u)) {
        fputs("AES-256 ECB vector failed\n", stderr);
        return 0;
    }

    if (!parse_hex(blowfish_key_hex, key, 8u) ||
        !parse_hex(blowfish_cipher_hex, data, 8u) ||
        !parse_hex(zeros8_hex, expected, 8u) ||
        qw_crypto_blowfish_ecb_decrypt(key, 8u, data, 8u) != QW_CRYPTO_OK ||
        !equal_bytes(data, expected, 8u)) {
        fputs("Blowfish ECB vector failed\n", stderr);
        return 0;
    }

    if (!parse_hex(tea_key_hex, key, 16u) ||
        !parse_hex(tea_cipher_hex, data, 8u) ||
        !parse_hex(tea_plain_hex, expected, 8u) ||
        qw_crypto_tea64_ecb_decrypt(key, data, 8u) != QW_CRYPTO_OK ||
        !equal_bytes(data, expected, 8u)) {
        fputs("QMC TEA vector failed\n", stderr);
        return 0;
    }

    if (!parse_hex(tea_key_hex, key, 16u) ||
        !parse_hex(pdg_tea_cipher_hex, data, 19u) ||
        !parse_hex(pdg_tea_plain_hex, expected, 19u) ||
        qw_crypto_pdg_tea128_ecb_decrypt(key, data, 19u) != QW_CRYPTO_OK ||
        !equal_bytes(data, expected, 19u)) {
        fputs("PDG/PDZ TEA vector failed\n", stderr);
        return 0;
    }

    if (!parse_hex(aes128_key_hex, key, 16u) ||
        qw_crypto_aes128_ecb_decrypt(key, NULL, 0u) != QW_CRYPTO_OK ||
        qw_crypto_aes128_ecb_decrypt(key, data, 17u) !=
            QW_CRYPTO_ERR_INVALID_ARGUMENT ||
        qw_crypto_tea64_ecb_decrypt(key, data, 7u) !=
            QW_CRYPTO_ERR_INVALID_ARGUMENT ||
        qw_crypto_blowfish_ecb_decrypt(key, 3u, data, 8u) !=
            QW_CRYPTO_ERR_INVALID_ARGUMENT) {
        fputs("Cipher argument validation failed\n", stderr);
        return 0;
    }
    return 1;
}

static int test_founder_keystream(void)
{
    static const uint8_t key[] = {'k', 'e', 'y'};
    static const char expected_hex[] = "89143944afcde56dbd6cbac09d1f34a7";
    uint8_t stream[16];
    uint8_t expected[16];

    if (!parse_hex(expected_hex, expected, sizeof(expected)) ||
        qw_crypto_founder_ceb_keystream(key, sizeof(key), stream,
                                        sizeof(stream)) != QW_CRYPTO_OK) return 0;
    if (!equal_bytes(stream, expected, sizeof(stream))) {
        fputs("Founder actual: ", stderr);
        for (size_t i = 0; i < sizeof(stream); ++i) fprintf(stderr, "%02x", stream[i]);
        fputc('\n', stderr);
        return 0;
    }
    return qw_crypto_founder_ceb_keystream(NULL, 0u, NULL, 0u) ==
               QW_CRYPTO_OK &&
           qw_crypto_founder_ceb_keystream(NULL, 0u, stream, sizeof(stream)) ==
               QW_CRYPTO_ERR_INVALID_ARGUMENT;
}

static int test_pdg_deslike(void)
{
    static const char key_hex[] = "000102030405060708090a0b0c0d0e0f";
    static const char input_hex[] = "00112233445566778899aabbccddeeff";
    static const char expected_hex[] = "6d125381034a93bf593084cbfced37ac";
    uint8_t key[16];
    uint8_t block[16];
    uint8_t expected[16];
    QwCryptoPdgDeslikeSchedule schedule = {{{0}}};

    if (!parse_hex(key_hex, key, sizeof(key)) ||
        !parse_hex(input_hex, block, sizeof(block)) ||
        !parse_hex(expected_hex, expected, sizeof(expected)) ||
        qw_crypto_pdg_deslike_schedule_init(key, &schedule) != QW_CRYPTO_OK ||
        qw_crypto_pdg_deslike_transform16(block, &schedule) != QW_CRYPTO_OK) {
        qw_crypto_pdg_deslike_schedule_clear(&schedule);
        return 0;
    }
    if (!equal_bytes(block, expected, sizeof(block))) {
        fputs("PDG DES-like actual: ", stderr);
        for (size_t i = 0; i < sizeof(block); ++i) fprintf(stderr, "%02x", block[i]);
        fputc('\n', stderr);
        qw_crypto_pdg_deslike_schedule_clear(&schedule);
        return 0;
    }
    qw_crypto_pdg_deslike_schedule_clear(&schedule);
    return qw_crypto_pdg_deslike_schedule_init(NULL, &schedule) ==
           QW_CRYPTO_ERR_INVALID_ARGUMENT &&
           qw_crypto_pdg_deslike_transform16(NULL, &schedule) ==
               QW_CRYPTO_ERR_INVALID_ARGUMENT;
}

static int test_rsa(void)
{
    static const char ciphertext_hex[] =
        "efcdab8967452301000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000";
    static const char exponent_hex[] =
        "f384ff17a8165a0eceb0a526f54412a99a88ec6968b5e14faf7a08bee92ffde3"
        "5b18c54697d86ecc639700e642bc91757e522dc5ef4c95ccd746d2d259db00c5";
    static const char modulus_hex[] =
        "91437cd83d0722ce410bd96ca80cff34895a315e25128bc32529d5f614e45097"
        "e12e450c68daf1ad8d8e740ab708564f4f317b8012c44856de567d58522497db";
    static const char expected_hex[] =
        "d98ec83e4bbf785688cc6200b050e2e740c3dcd2bf602575c13040767f7260d2"
        "f42761ad2fc4563ec6aa2aac6ec05211d7c7a820662fbd0319381c74f9f50b2c";
    uint8_t ciphertext[64];
    uint8_t exponent[64];
    uint8_t modulus[64];
    uint8_t output[64];
    uint8_t expected[64];
    uint8_t be_ciphertext[64];
    uint8_t be_exponent[64];
    uint8_t be_modulus[64];
    uint8_t be_output[64];
    uint8_t be_expected[64];
    uint8_t api_ciphertext[64];
    uint8_t api_exponent[64];
    uint8_t api_modulus[64];
    uint8_t zero[64] = {0};
    size_t i;

    if (!parse_hex(ciphertext_hex, ciphertext, sizeof(ciphertext)) ||
        !parse_hex(exponent_hex, exponent, sizeof(exponent)) ||
        !parse_hex(modulus_hex, modulus, sizeof(modulus)) ||
        !parse_hex(expected_hex, expected, sizeof(expected))) return 0;
    if (qw_crypto_rsa_mod_exp_512_le(ciphertext, exponent, modulus, output) !=
            QW_CRYPTO_OK ||
        !equal_bytes(output, expected, sizeof(output))) return 0;

    reverse_bytes(ciphertext, be_ciphertext, sizeof(be_ciphertext));
    reverse_bytes(exponent, be_exponent, sizeof(be_exponent));
    reverse_bytes(modulus, be_modulus, sizeof(be_modulus));
    reverse_bytes(expected, be_expected, sizeof(be_expected));
    reverse_bytes(be_ciphertext, api_ciphertext, sizeof(api_ciphertext));
    reverse_bytes(be_exponent, api_exponent, sizeof(api_exponent));
    reverse_bytes(be_modulus, api_modulus, sizeof(api_modulus));
    if (qw_crypto_rsa_mod_exp_512_le(api_ciphertext, api_exponent,
                                     api_modulus, output) != QW_CRYPTO_OK) {
        return 0;
    }
    reverse_bytes(output, be_output, sizeof(be_output));
    if (!equal_bytes(be_output, be_expected, sizeof(be_output))) return 0;

    memset(output, 0xa5, sizeof(output));
    if (qw_crypto_rsa_mod_exp_512_le(ciphertext, exponent, zero, output) !=
            QW_CRYPTO_ERR_INVALID_MODULUS) return 0;
    for (i = 0; i < sizeof(output); ++i) if (output[i] != 0xa5u) return 0;
    if (qw_crypto_rsa_mod_exp_512_le(modulus, exponent, modulus, output) !=
        QW_CRYPTO_ERR_OUT_OF_RANGE) return 0;
    if (qw_crypto_rsa_mod_exp_512_le(ciphertext, zero, modulus, output) !=
        QW_CRYPTO_ERR_INVALID_ARGUMENT) return 0;
    return 1;
}

static int test_des_modes(void)
{
    static const uint8_t plaintext[] = "Quirewise CEB known answer";
    static const char key_hex[] =
        "0123456789abcdeffedcba987654321089abcdef01234567";
    static const char iv_hex[] = "0123456789abcdef";
    static const char cfb_hex[] =
        "38622e8fedc1bb5bd9c754855eea9d14476021fa134b6a50103b";
    static const char ofb_hex[] =
        "38622e8fedc1bb5b434adabc967e3f085a7f79fbeb64257e7e33";
    uint8_t key[24];
    uint8_t iv[8];
    uint8_t cfb[sizeof(plaintext) - 1u];
    uint8_t wrong_key_cfb[sizeof(plaintext) - 1u];
    uint8_t ofb[sizeof(plaintext) - 1u];
    uint8_t wrong_key[sizeof(key)];
    uint8_t expected[sizeof(plaintext) - 1u];

    if (!parse_hex(key_hex, key, sizeof(key)) ||
        !parse_hex(iv_hex, iv, sizeof(iv)) ||
        !parse_hex(cfb_hex, cfb, sizeof(cfb)) ||
        !parse_hex(ofb_hex, ofb, sizeof(ofb))) return 0;
    memcpy(expected, plaintext, sizeof(expected));
    if (qw_crypto_3des_cfb64_decrypt(key, iv, cfb, sizeof(cfb)) !=
            QW_CRYPTO_OK ||
        !equal_bytes(cfb, expected, sizeof(cfb))) return 0;
    memcpy(wrong_key, key, sizeof(wrong_key));
    wrong_key[0] ^= 0x80u;
    if (!parse_hex(cfb_hex, wrong_key_cfb, sizeof(wrong_key_cfb)) ||
        qw_crypto_3des_cfb64_decrypt(wrong_key, iv, wrong_key_cfb,
                                     sizeof(wrong_key_cfb)) != QW_CRYPTO_OK ||
        equal_bytes(wrong_key_cfb, expected, sizeof(wrong_key_cfb))) return 0;
    if (qw_crypto_3des_ofb64_crypt(key, iv, ofb, sizeof(ofb)) !=
            QW_CRYPTO_OK ||
        !equal_bytes(ofb, expected, sizeof(ofb))) return 0;
    if (qw_crypto_3des_cfb64_decrypt(key, iv, NULL, 0u) != QW_CRYPTO_OK ||
        qw_crypto_3des_ofb64_crypt(key, iv, NULL, 0u) != QW_CRYPTO_OK ||
        qw_crypto_3des_cfb64_decrypt(key, iv, NULL, 1u) !=
            QW_CRYPTO_ERR_INVALID_ARGUMENT) return 0;
    return 1;
}

static int test_secure_zero(void)
{
    uint8_t data[33];
    size_t i;
    memset(data, 0xa5, sizeof(data));
    qw_crypto_secure_zero(data, sizeof(data));
    for (i = 0; i < sizeof(data); ++i) if (data[i] != 0u) return 0;
    qw_crypto_secure_zero(NULL, 0u);
    return 1;
}

int main(void)
{
    if (qw_crypto_abi_version() != UINT32_C(0x00010000)) {
        fputs("Crypto ABI version check failed\n", stderr);
        return 1;
    }
    if (!test_md5()) { fputs("MD5 vectors failed\n", stderr); return 1; }
    if (!test_block_crypto()) { fputs("Block cipher vectors failed\n", stderr); return 1; }
    if (!test_founder_keystream()) { fputs("Founder CEB vector failed\n", stderr); return 1; }
    if (!test_pdg_deslike()) { fputs("PDG DES-like vector failed\n", stderr); return 1; }
    if (!test_rsa()) { fputs("RSA vectors failed\n", stderr); return 1; }
    if (!test_des_modes()) { fputs("3DES mode vectors failed\n", stderr); return 1; }
    if (!test_secure_zero()) { fputs("Secure zero check failed\n", stderr); return 1; }
    puts("Quirewise Crypto known-answer tests passed");
    return 0;
}
