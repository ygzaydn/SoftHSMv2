#include "CryptoBackend.h"

#include <cstring>
#include "CryptoFactory.h"
#include "SymmetricAlgorithm.h"
#include "AESKey.h"
#include "SymmetricKey.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "RNG.h"
#include "ByteString.h"

namespace milenage_crypto {

bool aes128EncryptBlock(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    SymmetricAlgorithm *cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
    if (cipher == nullptr) {
        return false;
    }

    AESKey aesKey(128);
    aesKey.setKeyBits(ByteString(key, 16));

    bool ok = false;
    ByteString ciphertext;
    ByteString iv; /* empty: ECB does not use an IV */
    if (cipher->encryptInit(&aesKey, SymMode::ECB, iv, false)) {
        ByteString plaintext(in, 16);
        ByteString part;
        if (cipher->encryptUpdate(plaintext, part)) {
            ciphertext += part;
            ByteString final_;
            if (cipher->encryptFinal(final_)) {
                ciphertext += final_;
                ok = (ciphertext.size() == 16);
            }
        }
    }

    CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);

    if (ok) {
        memcpy(out, ciphertext.const_byte_str(), 16);
    }
    return ok;
}

bool sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    HashAlgorithm *hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA256);
    if (hash == nullptr) {
        return false;
    }

    bool ok = false;
    ByteString digest;
    if (hash->hashInit()) {
        ByteString input(data, len);
        if (hash->hashUpdate(input) && hash->hashFinal(digest)) {
            ok = (digest.size() == 32);
        }
    }

    CryptoFactory::i()->recycleHashAlgorithm(hash);

    if (ok) {
        memcpy(out, digest.const_byte_str(), 32);
    }
    return ok;
}

bool hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32])
{
    MacAlgorithm *mac = CryptoFactory::i()->getMacAlgorithm(MacAlgo::HMAC_SHA256);
    if (mac == nullptr) {
        return false;
    }

    SymmetricKey hmacKey;
    hmacKey.setKeyBits(ByteString(key, keyLen));

    bool ok = false;
    ByteString signature;
    if (mac->signInit(&hmacKey)) {
        ByteString input(data, len);
        if (mac->signUpdate(input) && mac->signFinal(signature)) {
            ok = (signature.size() == 32);
        }
    }

    CryptoFactory::i()->recycleMacAlgorithm(mac);

    if (ok) {
        memcpy(out, signature.const_byte_str(), 32);
    }
    return ok;
}

bool randomBytes(uint8_t *out, size_t len)
{
    RNG *rng = CryptoFactory::i()->getRNG();
    if (rng == nullptr) {
        return false;
    }

    ByteString data;
    bool ok = rng->generateRandom(data, len) && data.size() == len;
    if (ok) {
        memcpy(out, data.const_byte_str(), len);
    }
    return ok;
}

bool aesKwpWrap(const uint8_t *key, size_t keyLen, const uint8_t *plaintext, size_t ptLen,
                 std::vector<uint8_t> &out)
{
    SymmetricAlgorithm *cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
    if (cipher == nullptr) {
        return false;
    }

    AESKey wrapKey((unsigned long)(keyLen * 8));
    wrapKey.setKeyBits(ByteString(key, keyLen));

    ByteString in(plaintext, ptLen);
    ByteString wrapped;
    bool ok = cipher->wrapKey(&wrapKey, SymWrap::AES_KEYWRAP_PAD, in, wrapped);

    CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);

    out.clear();
    if (ok) {
        out.assign(wrapped.const_byte_str(), wrapped.const_byte_str() + wrapped.size());
    }
    return ok;
}

bool aesKwpUnwrap(const uint8_t *key, size_t keyLen, const uint8_t *wrapped, size_t wrappedLen,
                   std::vector<uint8_t> &out)
{
    SymmetricAlgorithm *cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
    if (cipher == nullptr) {
        return false;
    }

    AESKey wrapKey((unsigned long)(keyLen * 8));
    wrapKey.setKeyBits(ByteString(key, keyLen));

    ByteString in(wrapped, wrappedLen);
    ByteString plaintext;
    bool ok = cipher->unwrapKey(&wrapKey, SymWrap::AES_KEYWRAP_PAD, in, plaintext);

    CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);

    out.clear();
    if (ok) {
        out.assign(plaintext.const_byte_str(), plaintext.const_byte_str() + plaintext.size());
    }
    return ok;
}

} // namespace milenage_crypto
