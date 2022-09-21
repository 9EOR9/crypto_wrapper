# crypto_wrapper
simple Crypto wrapper library

Crypto libraries supported:
* OpenSSL (min. required version 1.0.1, not tested with OpenSSL 3.0)
* Nettle (used by GnuTLS)
* BCrypt (Windows native Crypto next generation)

Supported block ciphers and sizes
* AES-128
* AES-192
* AES-256

Supported block cipher modes of operation
* ECB (electronic codebook)
* CBC (cipher block chaining)
* GCM (galois/counter mode)
* CTR (counter)

Supported hash algorithms
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512

MD5 and SHA1 hash algorithms are disabled by default. For enabling use the CMake option
-DWITH_SECURE_HASHES=OFF.

API functions:

