/*
 * Wrapped credential envelope (design doc section 9): builds/parses
 * the versioned plaintext envelope and wraps it with AES-KWP
 * (RFC 5649 / NIST SP 800-38F) via OpenSSL's AES-256-WRAP-PAD cipher.
 * See CredentialEnvelope.h for the INTERIM note on the raw-buffer
 * masterKey parameter.
 */

#include "CredentialEnvelope.h"
#include "../milenage/softhsm_milenage.h"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace milenage_envelope {

namespace {

constexpr size_t PLAINTEXT_LEN = SOFTHSM_MILENAGE_ENVELOPE_PLAINTEXT_LEN;

bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

void computeSubscriberBinding(const std::string &canonicalSupi, uint8_t out[32])
{
    std::string input = std::string(SOFTHSM_MILENAGE_SUBSCRIBER_BINDING_CONTEXT) + canonicalSupi;
    SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), out);
}

/* AES-KWP wrap: plaintext may be any length >= 1; output is
 * ((len + 7) / 8 + 1) * 8 bytes, i.e. 8 bytes longer than the next
 * 8-byte-aligned plaintext length. Returns false on any OpenSSL error. */
bool aesKwpWrap(const uint8_t key[MASTER_KEY_LEN], const uint8_t *plaintext, size_t ptLen,
                 std::vector<uint8_t> &out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    bool ok = false;
    out.assign(ptLen + 16, 0); /* generous upper bound */
    int outLen1 = 0, outLen2 = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap_pad(), nullptr, key, nullptr) == 1) {
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        if (EVP_EncryptUpdate(ctx, out.data(), &outLen1, plaintext, static_cast<int>(ptLen)) == 1 &&
            EVP_EncryptFinal_ex(ctx, out.data() + outLen1, &outLen2) == 1) {
            out.resize(outLen1 + outLen2);
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        out.clear();
    }
    return ok;
}

bool aesKwpUnwrap(const uint8_t key[MASTER_KEY_LEN], const uint8_t *wrapped, size_t wrappedLen,
                   std::vector<uint8_t> &out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    bool ok = false;
    out.assign(wrappedLen, 0);
    int outLen1 = 0, outLen2 = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap_pad(), nullptr, key, nullptr) == 1) {
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        if (EVP_DecryptUpdate(ctx, out.data(), &outLen1, wrapped, static_cast<int>(wrappedLen)) == 1 &&
            EVP_DecryptFinal_ex(ctx, out.data() + outLen1, &outLen2) == 1) {
            out.resize(outLen1 + outLen2);
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        out.clear();
    }
    return ok;
}

} // namespace

bool isCanonicalSupi(const std::string &supi)
{
    static const std::string prefix = "imsi-";
    if (supi.size() <= prefix.size() || supi.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    std::string digits = supi.substr(prefix.size());
    if (digits.size() < 5 || digits.size() > 15) {
        return false;
    }
    for (char c : digits) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

Error wrapSecret(const std::string &canonicalSupi, SecretType type, const uint8_t secret[16],
                  const uint8_t masterKey[MASTER_KEY_LEN], std::vector<uint8_t> &wrappedOut)
{
    if (!isCanonicalSupi(canonicalSupi)) {
        return Error::GENERIC_FAILURE;
    }

    uint8_t plaintext[PLAINTEXT_LEN];
    std::memset(plaintext, 0, sizeof(plaintext));
    std::memcpy(plaintext + 0, SOFTHSM_MILENAGE_ENVELOPE_MAGIC, 4);
    plaintext[4] = SOFTHSM_MILENAGE_ENVELOPE_VERSION;
    plaintext[5] = SOFTHSM_MILENAGE_ALG_MILENAGE_AES128;
    plaintext[6] = static_cast<uint8_t>(type);
    plaintext[7] = 0x00; /* reserved */
    computeSubscriberBinding(canonicalSupi, plaintext + 8);
    plaintext[40] = 0x00;
    plaintext[41] = 0x10; /* secret_length = 16, big-endian */
    std::memcpy(plaintext + 42, secret, 16);

    bool ok = aesKwpWrap(masterKey, plaintext, sizeof(plaintext), wrappedOut);
    std::memset(plaintext, 0, sizeof(plaintext));
    return ok ? Error::OK : Error::GENERIC_FAILURE;
}

Error unwrapSecret(const std::string &canonicalSupi, SecretType expectedType,
                    const std::vector<uint8_t> &wrapped, const uint8_t masterKey[MASTER_KEY_LEN],
                    uint8_t secretOut[16])
{
    if (!isCanonicalSupi(canonicalSupi)) {
        return Error::GENERIC_FAILURE;
    }
    if (wrapped.size() > SOFTHSM_MILENAGE_MAX_WRAPPED_BLOB_LEN) {
        return Error::GENERIC_FAILURE;
    }

    std::vector<uint8_t> plaintext;
    bool unwrapOk = aesKwpUnwrap(masterKey, wrapped.data(), wrapped.size(), plaintext);

    Error result = Error::GENERIC_FAILURE;

    if (unwrapOk && plaintext.size() == PLAINTEXT_LEN) {
        bool magicOk = std::memcmp(plaintext.data(), SOFTHSM_MILENAGE_ENVELOPE_MAGIC, 4) == 0;
        bool versionOk = plaintext[4] == SOFTHSM_MILENAGE_ENVELOPE_VERSION;
        bool algOk = plaintext[5] == SOFTHSM_MILENAGE_ALG_MILENAGE_AES128;
        bool typeOk = plaintext[6] == static_cast<uint8_t>(expectedType);
        bool reservedOk = plaintext[7] == 0x00;
        bool lenOk = plaintext[40] == 0x00 && plaintext[41] == 0x10;

        uint8_t expectedBinding[32];
        computeSubscriberBinding(canonicalSupi, expectedBinding);
        bool bindingOk = constantTimeEqual(plaintext.data() + 8, expectedBinding, 32);

        if (magicOk && versionOk && algOk && typeOk && reservedOk && lenOk && bindingOk) {
            std::memcpy(secretOut, plaintext.data() + 42, 16);
            result = Error::OK;
        }
    }

    if (!plaintext.empty()) {
        std::memset(plaintext.data(), 0, plaintext.size());
    }
    return result;
}

} // namespace milenage_envelope
