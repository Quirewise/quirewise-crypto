# quirewise-crypto

The fixed cryptographic operations Quirewise format readers need, in one
dependency-free C11 library: digests, AES, Blowfish, 3DES, TEA, the PDG
transforms and 512-bit RSA.

`Quirewise::Crypto` is an independent, MIT-licensed C11 library, installed as a
CMake package that needs no Quirewise application code.

## What it does

- Computes one-shot MD5, SHA-256, SHA-384 and SHA-512 digests.
- Encrypts and decrypts AES-128 ECB, and decrypts AES-256 ECB, in place.
- Decrypts Blowfish ECB with 4 to 56-byte keys.
- Decrypts 3DES CFB64 and transforms 3DES OFB64, including partial final
  blocks.
- Decrypts the QMC 64-bit TEA variant and the PDG/PDZ 128-bit TEA variant.
- Provides the PDG DES-like key schedule and its 16-byte block transform.
- Generates the Founder CEB RC4-like keystream.
- Computes `ciphertext^exponent mod modulus` on 512-bit little-endian values.
- Wipes sensitive buffers through a volatile store.

It deliberately does **not** try to be a general crypto library: there is no
RNG, KDF, padding, AEAD, HMAC, certificate handling, AES-256 encryption, CBC,
CTR or GCM, and no constant-time or side-channel-hardening claim. Callers must
validate decrypted data against the enclosing format.

## Requirements

- C11 compiler and CMake 3.21 or newer.
- No third-party libraries and no other Quirewise package.
- CTest is used for the test suite.

## Build, test and install

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /path/to/prefix
```

Shared builds are available with `-DQUIREWISE_BUILD_SHARED=ON`.

## Use it from CMake

```cmake
find_package(QuirewiseCrypto CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE Quirewise::Crypto)
```

No include path or prefix plumbing is needed beyond `CMAKE_PREFIX_PATH` when
the package is installed outside a default prefix.

## Quick start

Hash a string, then decrypt an AES-128 block and encrypt it back to its
original ciphertext:

```c
#include <quirewise/crypto.h>

#include <stdio.h>
#include <string.h>

int main(void)
{
    static const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    static const uint8_t cipher[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };
    uint8_t digest[32];
    uint8_t block[sizeof(cipher)];
    size_t index;

    if (qw_crypto_sha256((const uint8_t *)"abc", 3u, digest) != QW_CRYPTO_OK)
        return 1;
    for (index = 0u; index < sizeof(digest); ++index)
        printf("%02x", digest[index]);
    putchar('\n');

    memcpy(block, cipher, sizeof(block));
    if (qw_crypto_aes128_ecb_decrypt(key, block, sizeof(block)) != QW_CRYPTO_OK)
        return 1;
    if (qw_crypto_aes128_ecb_encrypt(key, block, sizeof(block)) != QW_CRYPTO_OK)
        return 1;
    if (memcmp(block, cipher, sizeof(block)) != 0)
        return 1;

    qw_crypto_secure_zero(block, sizeof(block));
    qw_crypto_secure_zero(digest, sizeof(digest));
    puts("AES-128 ECB round-trip OK");
    return 0;
}
```

## API overview

| Header | Purpose |
|---|---|
| `quirewise/crypto.h` | `QwCryptoStatus`, digests, ciphers, RSA, wiping |

| Task | Functions |
|---|---|
| Version and wiping | `qw_crypto_abi_version`, `qw_crypto_secure_zero` |
| Digests | `qw_crypto_md5_digest`, `qw_crypto_sha256`, `qw_crypto_sha384`, `qw_crypto_sha512` |
| AES | `qw_crypto_aes128_ecb_encrypt`, `qw_crypto_aes128_ecb_decrypt`, `qw_crypto_aes256_ecb_decrypt` |
| TEA | `qw_crypto_tea64_ecb_decrypt`, `qw_crypto_pdg_tea128_ecb_decrypt` |
| PDG DES-like | `qw_crypto_pdg_deslike_schedule_init`, `qw_crypto_pdg_deslike_transform16`, `qw_crypto_pdg_deslike_schedule_clear` |
| Blowfish | `qw_crypto_blowfish_ecb_decrypt` |
| 3DES modes | `qw_crypto_3des_cfb64_decrypt`, `qw_crypto_3des_ofb64_crypt` |
| Founder CEB | `qw_crypto_founder_ceb_keystream` |
| RSA | `qw_crypto_rsa_mod_exp_512_le` |

## Behavior and limits

- Every function works on caller-owned buffers and writes in place; nothing is
  allocated, and there are no global variables or locks.
- `QwCryptoStatus` is 0 on success and **positive** on failure:
  `QW_CRYPTO_ERR_INVALID_ARGUMENT` (1), `QW_CRYPTO_ERR_INVALID_MODULUS` (2),
  `QW_CRYPTO_ERR_OUT_OF_RANGE` (3).
- A NULL data pointer is accepted only with a size of 0; the cipher calls
  always require their key pointer (and an IV for 3DES).
- Block alignment: AES needs a multiple of 16 bytes, TEA64 and Blowfish a
  multiple of 8. The PDG TEA128 variant accepts any size and leaves a trailing
  partial block unchanged. 3DES CFB/OFB accept any size, including 0.
- RSA takes three 64-byte little-endian values. A zero modulus fails with
  `INVALID_MODULUS`, a zero exponent with `INVALID_ARGUMENT`, and a ciphertext
  not below the modulus with `OUT_OF_RANGE`; `output` is untouched on failure.
- There is no padding, authentication, key derivation or format validation:
  decrypt, then check the container's own magic, length or checksum.

## Testing

`ctest` runs `quirewise_crypto_known_answers`, covering MD5 and SHA-2 vectors,
AES-128/256, Blowfish, both TEA variants, the PDG DES-like transform, the
Founder keystream, 3DES CFB64/OFB64, 512-bit RSA, `secure_zero` and the ABI
version.

## Documentation

See [docs/usage.md](docs/usage.md) for recipes: digesting a file, CEB-style
3DES-CFB64 payloads, block-cipher alignment, PDG schedules and RSA checks.

## License

MIT. See [LICENSE](LICENSE).
