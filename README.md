# Quirewise Crypto

Quirewise Crypto is a small, dependency-free package for the fixed cryptographic
operations used by the Founder CEB reader:

- 512-bit RSA modular exponentiation over little-endian byte strings;
- three-key 3DES CFB64 decryption and OFB64 transformation;
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
