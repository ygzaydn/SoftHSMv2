#include "TransportEnvelope.h"
#include "CryptoBackend.h"
#include "CredentialEnvelope.h" /* for isCanonicalSupi */
#include "softhsm_milenage.h"

#include <cstring>

namespace milenage_transport {

namespace {

constexpr size_t PLAINTEXT_LEN = SOFTHSM_MILENAGE_TRANSPORT_PLAINTEXT_LEN;

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
    std::string input = std::string(SOFTHSM_MILENAGE_TRANSPORT_BINDING_CONTEXT) + canonicalSupi;
    milenage_crypto::sha256(reinterpret_cast<const uint8_t *>(input.data()), input.size(), out);
}

} // namespace

Error wrapPackage(const std::string &canonicalSupi, SecretType type, const uint8_t secret[16],
                   const uint8_t *transactionId, size_t transactionIdLen,
                   const uint8_t transportKek[TRANSPORT_KEY_LEN],
                   std::vector<uint8_t> &packageOut)
{
    if (!milenage_envelope::isCanonicalSupi(canonicalSupi)) {
        return Error::GENERIC_FAILURE;
    }
    if (transactionIdLen > MAX_TRANSACTION_ID_LEN) {
        return Error::GENERIC_FAILURE;
    }

    uint8_t plaintext[PLAINTEXT_LEN];
    std::memset(plaintext, 0, sizeof(plaintext));
    std::memcpy(plaintext + 0, SOFTHSM_MILENAGE_TRANSPORT_MAGIC, 4);
    plaintext[4] = SOFTHSM_MILENAGE_TRANSPORT_VERSION;
    plaintext[5] = static_cast<uint8_t>(type);
    plaintext[6] = SOFTHSM_MILENAGE_TRANSPORT_KEY_VERSION;
    plaintext[7] = 0x00; /* reserved */
    computeSubscriberBinding(canonicalSupi, plaintext + 8);
    plaintext[40] = static_cast<uint8_t>(transactionIdLen);
    if (transactionIdLen > 0) {
        std::memcpy(plaintext + 41, transactionId, transactionIdLen);
    }
    plaintext[73] = 0x00;
    plaintext[74] = 0x10; /* secret_length = 16, big-endian */
    std::memcpy(plaintext + 75, secret, 16);

    bool ok = milenage_crypto::aesKwpWrap(transportKek, TRANSPORT_KEY_LEN, plaintext, sizeof(plaintext), packageOut);
    std::memset(plaintext, 0, sizeof(plaintext));
    return ok ? Error::OK : Error::GENERIC_FAILURE;
}

Error unwrapPackage(const std::string &canonicalSupi, SecretType expectedType,
                     const std::vector<uint8_t> &package,
                     const uint8_t transportKek[TRANSPORT_KEY_LEN],
                     uint8_t secretOut[16])
{
    if (!milenage_envelope::isCanonicalSupi(canonicalSupi)) {
        return Error::GENERIC_FAILURE;
    }

    std::vector<uint8_t> plaintext;
    bool unwrapOk = milenage_crypto::aesKwpUnwrap(transportKek, TRANSPORT_KEY_LEN, package.data(),
                                                   package.size(), plaintext);

    Error result = Error::GENERIC_FAILURE;

    if (unwrapOk && plaintext.size() == PLAINTEXT_LEN) {
        bool magicOk = std::memcmp(plaintext.data(), SOFTHSM_MILENAGE_TRANSPORT_MAGIC, 4) == 0;
        bool versionOk = plaintext[4] == SOFTHSM_MILENAGE_TRANSPORT_VERSION;
        bool typeOk = plaintext[5] == static_cast<uint8_t>(expectedType);
        bool keyVersionOk = plaintext[6] == SOFTHSM_MILENAGE_TRANSPORT_KEY_VERSION;
        bool reservedOk = plaintext[7] == 0x00;
        bool txnLenOk = plaintext[40] <= MAX_TRANSACTION_ID_LEN;
        bool lenOk = plaintext[73] == 0x00 && plaintext[74] == 0x10;

        uint8_t expectedBinding[32];
        computeSubscriberBinding(canonicalSupi, expectedBinding);
        bool bindingOk = constantTimeEqual(plaintext.data() + 8, expectedBinding, 32);

        if (magicOk && versionOk && typeOk && keyVersionOk && reservedOk && txnLenOk && lenOk && bindingOk) {
            std::memcpy(secretOut, plaintext.data() + 75, 16);
            result = Error::OK;
        }
    }

    if (!plaintext.empty()) {
        std::memset(plaintext.data(), 0, plaintext.size());
    }
    return result;
}

} // namespace milenage_transport
