/*
 * Thin seam between the Milenage/5G-AKA logic and SoftHSM's
 * backend-independent crypto abstractions (CryptoFactory /
 * SymmetricAlgorithm / HashAlgorithm / MacAlgorithm / RNG).
 *
 * Everything in src/lib/milenage other than this file must be free of
 * direct OpenSSL/Botan calls; this file is the only place that talks
 * to CryptoFactory. It compiles and links the same way regardless of
 * which crypto backend SoftHSM was built with (WITH_CRYPTO_BACKEND=
 * openssl|botan) -- see doc/MILENAGE-5G-AKA-DESIGN.md section 17 for
 * the verification status of each backend in this environment (only
 * OpenSSL could actually be built and run here; Botan is not
 * installed, so that path is compile-checked only, not executed).
 */

#ifndef SOFTHSM_MILENAGE_CRYPTO_BACKEND_H
#define SOFTHSM_MILENAGE_CRYPTO_BACKEND_H

#include <cstdint>
#include <cstddef>
#include <vector>

namespace milenage_crypto {

/* Single AES-128 ECB block encryption (no padding), out = E_K(in), both
 * exactly 16 bytes. Used by the Milenage TEMP/OUTn construction. */
bool aes128EncryptBlock(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/* SHA-256 of an arbitrary-length buffer. */
bool sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* HMAC-SHA-256, arbitrary key and data length, full 32-byte output. */
bool hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]);

/* Cryptographically secure random bytes from SoftHSM's RNG abstraction. */
bool randomBytes(uint8_t *out, size_t len);

/* AES Key Wrap with Padding (RFC 5649 / NIST SP 800-38F), arbitrary
 * AES key size (16/24/32 bytes) and arbitrary plaintext length >= 1.
 * `out` receives the wrapped ciphertext on success. */
bool aesKwpWrap(const uint8_t *key, size_t keyLen, const uint8_t *plaintext, size_t ptLen,
                 std::vector<uint8_t> &out);

/* AES Key Unwrap with Padding. `out` receives the recovered plaintext
 * on success; returns false on any integrity/format failure. */
bool aesKwpUnwrap(const uint8_t *key, size_t keyLen, const uint8_t *wrapped, size_t wrappedLen,
                   std::vector<uint8_t> &out);

} // namespace milenage_crypto

#endif // SOFTHSM_MILENAGE_CRYPTO_BACKEND_H
