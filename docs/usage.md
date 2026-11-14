# quirewise-crypto usage guide

Task-level workflows for `Quirewise::Crypto`. The whole API is declared in
`quirewise/crypto.h`.

## 1. Build and integrate

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /path/to/prefix
```

Consumer CMake:

```cmake
find_package(QuirewiseCrypto CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE Quirewise::Crypto)
```

There is no context object to create, no initialization call and no cleanup
call. Every function is a plain C entry point that works on your buffers.

## 2. Core model

- Inputs and outputs are caller-owned byte buffers. Every cipher writes **in
  place**; nothing is allocated and nothing is returned by pointer.
- Keys and IVs are declared as fixed-size array parameters. C adjusts them to
  pointers, so their size is documented but not enforced.
- Byte order is part of each algorithm: AES is byte-oriented; Blowfish and
  3DES read big-endian words; the QMC TEA64 variant reads big-endian; the PDG
  TEA128 and RSA variants read little-endian.
- Failure is a positive `QwCryptoStatus`: `QW_CRYPTO_OK` = 0,
  `QW_CRYPTO_ERR_INVALID_ARGUMENT` = 1, `QW_CRYPTO_ERR_INVALID_MODULUS` = 2,
  `QW_CRYPTO_ERR_OUT_OF_RANGE` = 3. Only RSA uses the last two.
- No function pads, authenticates or validates plaintext. That is the
  enclosing format's job, and you must do it before trusting the result.

## 3. Digest a file

```c
#include <quirewise/crypto.h>

#include <stdio.h>
#include <stdlib.h>

static int sha256_file(const char *path, uint8_t out[32])
{
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *data;
    QwCryptoStatus status;

    if (!file) return 0;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    data = (uint8_t *)malloc((size_t)length ? (size_t)length : 1u);
    if (!data || fread(data, 1u, (size_t)length, file) != (size_t)length) {
        fclose(file);
        free(data);
        return 0;
    }
    fclose(file);
    status = qw_crypto_sha256(data, (size_t)length, out);
    free(data);
    return status == QW_CRYPTO_OK;
}

int main(void)
{
    uint8_t digest[32];
    size_t index;

    if (!sha256_file("input.bin", digest)) return 1;
    for (index = 0u; index < sizeof(digest); ++index)
        printf("%02x", digest[index]);
    putchar('\n');
    return 0;
}
```

The digests are one-shot: the whole message must be in memory. `qw_crypto_md5_digest`
takes `const void *`; the SHA-2 functions take `const uint8_t *`. All accept
`NULL` data only when the size is 0, which is how you hash an empty input.

## 4. Decrypt a CEB-style 3DES-CFB64 payload

`qw_crypto_3des_cfb64_decrypt` takes a 24-byte key (`K1 || K2 || K3`), an
8-byte IV, and any byte length, including a partial final block.

```c
#include <quirewise/crypto.h>

#include <stdio.h>
#include <string.h>

int decrypt_ceb_page(uint8_t *page, size_t page_size, const uint8_t key[24],
                     const uint8_t iv[8])
{
    QwCryptoStatus status = qw_crypto_3des_cfb64_decrypt(key, iv, page,
                                                         page_size);

    if (status != QW_CRYPTO_OK) {
        fprintf(stderr, "3des: %d\n", (int)status);
        return 1;
    }
    /* No authentication: validate with the container's own markers. */
    if (page_size < 5u || memcmp(page, "%PDF-", 5u) != 0) {
        fputs("wrong key or not a CEB payload\n", stderr);
        return 1;
    }
    return 0;
}
```

`qw_crypto_3des_ofb64_crypt` uses the same key and IV layout, is symmetric
(call it for both directions), and keeps the keystream independent of the data.
Both modes return `QW_CRYPTO_OK` for a size of 0 without touching the buffer.

## 5. Decrypt fixed-size blocks

```c
uint8_t aes256_key[32] = { /* ... */ };
uint8_t block32[32];      /* exactly two AES blocks */

if (qw_crypto_aes256_ecb_decrypt(aes256_key, block32, sizeof(block32)) !=
    QW_CRYPTO_OK)
    return 1;                        /* size must be a multiple of 16 */

if (qw_crypto_blowfish_ecb_decrypt(blowfish_key, 8u, data, 8u) !=
    QW_CRYPTO_OK)
    return 1;                        /* key 4..56 bytes, size % 8 == 0 */

if (qw_crypto_tea64_ecb_decrypt(tea_key16, data, 8u) != QW_CRYPTO_OK)
    return 1;                        /* size % 8 == 0 */

/* PDG TEA128 accepts any size: full 16-byte blocks are transformed,
 * a trailing 1..15-byte partial block is left as-is. */
if (qw_crypto_pdg_tea128_ecb_decrypt(tea_key16, data, 19u) != QW_CRYPTO_OK)
    return 1;
```

- AES-128 has both directions (`qw_crypto_aes128_ecb_encrypt`,
  `qw_crypto_aes128_ecb_decrypt`); AES-256 is decrypt-only.
- Blowfish is decrypt-only; the key may be 4 to 56 bytes.
- TEA64 is decrypt-only and reads its key and blocks big-endian.
- Misaligned sizes fail with `QW_CRYPTO_ERR_INVALID_ARGUMENT` before anything
  is written.

## 6. Apply the PDG DES-like transform

The PDG reader needs a key schedule for its six-pass 16-byte transform. The
schedule is a caller-owned `QwCryptoPdgDeslikeSchedule`; clear it when done.

```c
#include <quirewise/crypto.h>

int transform_payload(uint8_t *payload, size_t payload_size,
                      const uint8_t key16[16])
{
    QwCryptoPdgDeslikeSchedule schedule;
    size_t offset;

    if (qw_crypto_pdg_deslike_schedule_init(key16, &schedule) != QW_CRYPTO_OK)
        return 1;
    for (offset = 0u; offset + 16u <= payload_size; offset += 16u) {
        if (qw_crypto_pdg_deslike_transform16(payload + offset, &schedule) !=
            QW_CRYPTO_OK) {
            qw_crypto_pdg_deslike_schedule_clear(&schedule);
            return 1;
        }
    }
    qw_crypto_pdg_deslike_schedule_clear(&schedule); /* wipe the round keys */
    return 0;
}
```

Reuse one schedule for many blocks; rebuilding it per block is correct but
much slower. The transform is direction-neutral, matching the PDG reader,
which uses the same routine on its special blocks.

## 7. Verify a 512-bit RSA little-endian block

```c
#include <quirewise/crypto.h>

#include <stdio.h>
#include <string.h>

int rsa_check(const uint8_t ciphertext[64], const uint8_t exponent[64],
              const uint8_t modulus[64], const uint8_t expected[64])
{
    uint8_t output[64];
    QwCryptoStatus status = qw_crypto_rsa_mod_exp_512_le(ciphertext, exponent,
                                                         modulus, output);

    if (status == QW_CRYPTO_ERR_OUT_OF_RANGE) {
        fputs("ciphertext is not below the modulus\n", stderr);
        return 1;
    }
    if (status != QW_CRYPTO_OK) {
        fprintf(stderr, "rsa: %d\n", (int)status);
        return 1;
    }
    /* Compare with the format's own padded digest, then wipe. */
    if (memcmp(output, expected, 64u) != 0) return 1;
    qw_crypto_secure_zero(output, sizeof(output));
    return 0;
}
```

- All three inputs and the output are 64-byte **little-endian** integers; the
  common public exponent 65537 is `01 00 01` followed by zeros.
- A zero modulus returns `QW_CRYPTO_ERR_INVALID_MODULUS`; a zero exponent
  returns `QW_CRYPTO_ERR_INVALID_ARGUMENT`; `ciphertext >= modulus` returns
  `QW_CRYPTO_ERR_OUT_OF_RANGE`.
- `output` is left untouched on every failure, so a caller-supplied sentinel
  survives for debugging.

## 8. Generate the Founder CEB keystream

```c
uint8_t keystream[4096];
size_t index;

if (qw_crypto_founder_ceb_keystream(key, key_size, keystream,
                                    sizeof(keystream)) != QW_CRYPTO_OK)
    return 1;
for (index = 0u; index < cipher_size; ++index)
    plain[index] = cipher[index] ^ keystream[index];
qw_crypto_secure_zero(keystream, sizeof(keystream));
```

The setup step ORs every key byte with `0xAA` before the RC4-like key
scheduling, matching the container variant; do not pre-mask the key yourself.
A `key_size` of 0 is accepted only when `stream_size` is also 0.

## 9. Error handling rules

- Compare against `QW_CRYPTO_OK`, not `!status`: failures are positive.
- `QW_CRYPTO_ERR_INVALID_ARGUMENT` covers NULL keys, NULL data with a non-zero
  size, a zero-length key, an out-of-range Blowfish key, and misaligned block
  sizes. Fix the call; retrying cannot help.
- `QW_CRYPTO_ERR_INVALID_MODULUS` and `QW_CRYPTO_ERR_OUT_OF_RANGE` mean the
  RSA input is corrupt or hostile; reject the block.
- Cipher functions do not set an error message. Log the numeric status.
- Argument failures are detected before any block is processed, so a rejected
  call leaves the buffer untouched; the output is still untrusted until your
  format check passes.

## 10. Memory, lifetime and threading

- No function allocates, retains a pointer, or uses global mutable state, so
  concurrent calls on separate buffers are safe.
- Keys, IVs and plaintext live in the caller's buffers. Wipe them with
  `qw_crypto_secure_zero`, which uses a volatile store so the compiler cannot
  drop the write; `qw_crypto_secure_zero(NULL, 0)` is a safe no-op.
- The only multi-call object is `QwCryptoPdgDeslikeSchedule` (6 x 32 `uint32_t`
  round keys). Initialize once, reuse, then `qw_crypto_pdg_deslike_schedule_clear`.
- `qw_crypto_abi_version` returns the encoded ABI version (1.0.0 is
  `0x00010000`); check it when you load the library dynamically.

## 11. Limits and format notes

| Item | Detail |
|---|---|
| AES block | 16 bytes; key 16 (AES-128) or 32 (AES-256, decrypt only) |
| Blowfish block | 8 bytes; key 4..56 bytes |
| TEA64 (QMC) | 8-byte blocks, big-endian, 16-byte key |
| PDG TEA128 | 16-byte blocks, little-endian, 16-byte key, partial tail ignored |
| 3DES | 24-byte key, 8-byte IV, CFB64 or OFB64, any length |
| RSA | 64-byte little-endian values, 512-bit modulus |
| Digests | MD5 16 bytes, SHA-256 32, SHA-384 48, SHA-512 64 |

- There is no stream API for digests, no AES-256 encryption, no Blowfish
  encryption, no AES-CBC/CTR/GCM, no HMAC and no KDF.
- The ciphers use table lookups, so no constant-time guarantee is made. Do not
  treat this package as hardened against local side-channel attackers.
- Key material stays in your buffers; wipe keys, IVs and plaintext with
  `qw_crypto_secure_zero` when you are done.

## 12. Related packages

- `Quirewise::PDG` uses the PDG TEA, AES-256, Blowfish and DES-like primitives.
- `Quirewise::Page` uses the Founder keystream, 3DES and RSA for CEB documents.
- `Quirewise::Audio` uses AES-128 and QMC TEA64 for encrypted audio.
- `Quirewise::Document` uses the digests and AES for PDF encryption paths.

## 13. License

MIT. See `LICENSE`.
