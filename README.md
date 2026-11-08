# Quirewise Crypto

Quirewise Crypto is a small, dependency-free package for the fixed cryptographic
operations used by the format readers:

- 512-bit RSA modular exponentiation over little-endian byte strings;
- three-key 3DES CFB64 decryption, OFB64 transformation and the PDG DES-like
  block transform;
- AES-128/AES-256 ECB (encrypt and decrypt), Blowfish ECB and the QMC/PDG TEA
  variants;
- MD5 and SHA-256/SHA-384/SHA-512 digests;
- the Founder CEB keystream and a TEA-based 8-byte block cipher;
- an optimizer-resistant byte clearing function.

It exports the CMake target Quirewise::Crypto and the public header
quirewise/crypto.h. The API does not expose OpenSSL types or provide unrelated
algorithms.

## Build and install

Configure with CMake, build the package, run CTest, and install with a prefix:

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ctest --test-dir build --output-on-failure
    cmake --install build --prefix install

Consumers can discover the installed package with
find_package(QuirewiseCrypto CONFIG REQUIRED).

The CFB and OFB operations have no authentication or padding layer. They
preserve the byte-stream behavior expected by CEB, including partial final
blocks; callers must validate decrypted data using the enclosing format.
