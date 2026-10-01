#include "MilenageService.h"

#include "config.h"
#include <cstring>

#include "WireCodec.h"
#include "Milenage.h"
#include "FiveGAka.h"
#include "CredentialEnvelope.h"
#include "TransportEnvelope.h"
#include "CryptoBackend.h"
#include "softhsm_milenage.h"

namespace milenage_service {

namespace {

bool getField(const milenage_wire::Request &req, uint16_t tag, std::vector<uint8_t> &out)
{
    auto it = req.fields.find(tag);
    if (it == req.fields.end()) {
        return false;
    }
    out = it->second;
    return true;
}

bool getFixedField(const milenage_wire::Request &req, uint16_t tag, size_t expectedLen,
                    std::vector<uint8_t> &out)
{
    if (!getField(req, tag, out)) {
        return false;
    }
    return out.size() == expectedLen;
}

std::string bytesToString(const std::vector<uint8_t> &b)
{
    return std::string(reinterpret_cast<const char *>(b.data()), b.size());
}

} // namespace

Error generate5gHeAv(const uint8_t *request, size_t requestLen, const uint8_t masterKey[32],
                      std::vector<uint8_t> &response, const uint8_t *testRand)
{
    milenage_wire::Request req;
    if (milenage_wire::parseRequest(request, requestLen, req) != milenage_wire::Error::OK) {
        return Error::BAD_REQUEST;
    }
    if (req.operation != SOFTHSM_MILENAGE_OP_5G_HE_AV) {
        return Error::BAD_REQUEST;
    }

    std::vector<uint8_t> supiBytes, wrappedK, wrappedOpc, sqn, amf, snn;
    if (!getField(req, SOFTHSM_MILENAGE_TAG_SUPI, supiBytes) ||
        supiBytes.size() > SOFTHSM_MILENAGE_MAX_SUPI_LEN ||
        !getField(req, SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK) ||
        !getField(req, SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc) ||
        !getFixedField(req, SOFTHSM_MILENAGE_TAG_SQN, milenage::SQN_LEN, sqn) ||
        !getFixedField(req, SOFTHSM_MILENAGE_TAG_AMF, milenage::AMF_LEN, amf) ||
        !getField(req, SOFTHSM_MILENAGE_TAG_SNN, snn) ||
        snn.empty() || snn.size() > SOFTHSM_MILENAGE_MAX_SNN_LEN) {
        return Error::BAD_REQUEST;
    }
    if (wrappedK.size() > SOFTHSM_MILENAGE_MAX_WRAPPED_BLOB_LEN ||
        wrappedOpc.size() > SOFTHSM_MILENAGE_MAX_WRAPPED_BLOB_LEN) {
        return Error::BAD_REQUEST;
    }

    /* Test-only caller-supplied RAND over the wire (design doc section
     * 8 / spec section 14, WITH_MILENAGE_TEST_RAND). In a normal build
     * this tag is not registered for the AV operation at all: its
     * mere presence in the request is a hard parse failure, not a
     * silently-ignored field, so a test-only wire message can never
     * be replayed unnoticed against a production build. */
    uint8_t wireTestRand[16];
    bool haveWireTestRand = false;
    {
        std::vector<uint8_t> testRandField;
        bool hasTag = getField(req, SOFTHSM_MILENAGE_TAG_RAND, testRandField);
#ifdef WITH_MILENAGE_TEST_RAND
        if (hasTag) {
            if (testRandField.size() != milenage::RAND_LEN) {
                return Error::BAD_REQUEST;
            }
            std::memcpy(wireTestRand, testRandField.data(), milenage::RAND_LEN);
            haveWireTestRand = true;
        }
#else
        if (hasTag) {
            return Error::BAD_REQUEST;
        }
#endif
    }
    if (testRand == nullptr && haveWireTestRand) {
        testRand = wireTestRand;
    }

    std::string supi = bytesToString(supiBytes);

    uint8_t k[16], opc[16];
    milenage_envelope::Error envErr;
    envErr = milenage_envelope::unwrapSecret(supi, milenage_envelope::SecretType::K, wrappedK,
                                              masterKey, k);
    if (envErr != milenage_envelope::Error::OK) {
        return Error::CREDENTIAL_INVALID;
    }
    envErr = milenage_envelope::unwrapSecret(supi, milenage_envelope::SecretType::OPC, wrappedOpc,
                                              masterKey, opc);
    if (envErr != milenage_envelope::Error::OK) {
        std::memset(k, 0, sizeof(k));
        return Error::CREDENTIAL_INVALID;
    }

    uint8_t rand16[16];
    if (testRand != nullptr) {
        std::memcpy(rand16, testRand, 16);
    } else if (!milenage_crypto::randomBytes(rand16, 16)) {
        std::memset(k, 0, sizeof(k));
        std::memset(opc, 0, sizeof(opc));
        return Error::BAD_REQUEST;
    }

    uint8_t macA[8], res[8], ck[16], ik[16], ak[6];
    bool ok = milenage::f1(k, opc, rand16, sqn.data(), amf.data(), macA) &&
              milenage::f2345(k, opc, rand16, res, ck, ik, ak);

    uint8_t autn[16];
    if (ok) {
        ok = milenage::buildAutn(sqn.data(), ak, amf.data(), macA, autn);
    }

    uint8_t xresStar[16], kausf[32];
    if (ok) {
        ok = fiveg_aka::deriveXresStar(ck, ik, rand16, res, snn.data(), snn.size(), xresStar);
    }
    if (ok) {
        uint8_t sqnXorAk[6];
        for (size_t i = 0; i < 6; i++) sqnXorAk[i] = sqn[i] ^ ak[i];
        ok = fiveg_aka::deriveKausf(ck, ik, sqnXorAk, snn.data(), snn.size(), kausf);
        std::memset(sqnXorAk, 0, sizeof(sqnXorAk));
    }

    Error result = Error::OK;
    if (ok) {
        std::vector<std::pair<uint16_t, std::vector<uint8_t>>> fields = {
            {SOFTHSM_MILENAGE_TAG_OUT_RAND, std::vector<uint8_t>(rand16, rand16 + 16)},
            {SOFTHSM_MILENAGE_TAG_OUT_AUTN, std::vector<uint8_t>(autn, autn + 16)},
            {SOFTHSM_MILENAGE_TAG_OUT_XRES_STAR, std::vector<uint8_t>(xresStar, xresStar + 16)},
            {SOFTHSM_MILENAGE_TAG_OUT_KAUSF, std::vector<uint8_t>(kausf, kausf + 32)},
        };
        if (milenage_wire::buildResponse(SOFTHSM_MILENAGE_OP_5G_HE_AV, fields, response) !=
            milenage_wire::Error::OK) {
            result = Error::BAD_REQUEST;
        }
    } else {
        result = Error::BAD_REQUEST;
    }

    /* Wipe every plaintext/intermediate value regardless of outcome
     * (design doc section 12). */
    std::memset(k, 0, sizeof(k));
    std::memset(opc, 0, sizeof(opc));
    std::memset(macA, 0, sizeof(macA));
    std::memset(res, 0, sizeof(res));
    std::memset(ck, 0, sizeof(ck));
    std::memset(ik, 0, sizeof(ik));
    std::memset(ak, 0, sizeof(ak));
    if (testRand == nullptr) {
        std::memset(rand16, 0, sizeof(rand16));
    }

    return result;
}

Error resync(const uint8_t *request, size_t requestLen, const uint8_t masterKey[32],
             std::vector<uint8_t> &response)
{
    milenage_wire::Request req;
    if (milenage_wire::parseRequest(request, requestLen, req) != milenage_wire::Error::OK) {
        return Error::BAD_REQUEST;
    }
    if (req.operation != SOFTHSM_MILENAGE_OP_RESYNC) {
        return Error::BAD_REQUEST;
    }

    std::vector<uint8_t> supiBytes, wrappedK, wrappedOpc, randV, autsV;
    if (!getField(req, SOFTHSM_MILENAGE_TAG_SUPI, supiBytes) ||
        supiBytes.size() > SOFTHSM_MILENAGE_MAX_SUPI_LEN ||
        !getField(req, SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK) ||
        !getField(req, SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc) ||
        !getFixedField(req, SOFTHSM_MILENAGE_TAG_RAND, milenage::RAND_LEN, randV) ||
        !getFixedField(req, SOFTHSM_MILENAGE_TAG_AUTS, milenage::AUTS_LEN, autsV)) {
        return Error::BAD_REQUEST;
    }
    if (wrappedK.size() > SOFTHSM_MILENAGE_MAX_WRAPPED_BLOB_LEN ||
        wrappedOpc.size() > SOFTHSM_MILENAGE_MAX_WRAPPED_BLOB_LEN) {
        return Error::BAD_REQUEST;
    }

    std::string supi = bytesToString(supiBytes);

    uint8_t k[16], opc[16];
    if (milenage_envelope::unwrapSecret(supi, milenage_envelope::SecretType::K, wrappedK,
                                         masterKey, k) != milenage_envelope::Error::OK) {
        return Error::CREDENTIAL_INVALID;
    }
    if (milenage_envelope::unwrapSecret(supi, milenage_envelope::SecretType::OPC, wrappedOpc,
                                         masterKey, opc) != milenage_envelope::Error::OK) {
        std::memset(k, 0, sizeof(k));
        return Error::CREDENTIAL_INVALID;
    }

    uint8_t sqnMs[6];
    bool ok = milenage::verifyAuts(k, opc, randV.data(), autsV.data(), sqnMs);

    Error result;
    if (!ok) {
        result = Error::SIGNATURE_INVALID;
    } else {
        std::vector<std::pair<uint16_t, std::vector<uint8_t>>> fields = {
            {SOFTHSM_MILENAGE_TAG_OUT_SQN_MS, std::vector<uint8_t>(sqnMs, sqnMs + 6)},
        };
        result = (milenage_wire::buildResponse(SOFTHSM_MILENAGE_OP_RESYNC, fields, response) ==
                  milenage_wire::Error::OK)
                     ? Error::OK
                     : Error::BAD_REQUEST;
    }

    std::memset(k, 0, sizeof(k));
    std::memset(opc, 0, sizeof(opc));
    std::memset(sqnMs, 0, sizeof(sqnMs));
    return result;
}

Error provision(const uint8_t *request, size_t requestLen, const uint8_t masterKey[32],
                 std::vector<uint8_t> &response)
{
    milenage_wire::Request req;
    if (milenage_wire::parseRequest(request, requestLen, req) != milenage_wire::Error::OK) {
        return Error::BAD_REQUEST;
    }
    if (req.operation != SOFTHSM_MILENAGE_OP_PROVISION) {
        return Error::BAD_REQUEST;
    }

    std::vector<uint8_t> supiBytes, plainK, plainOpc;
    if (!getField(req, SOFTHSM_MILENAGE_TAG_SUPI, supiBytes) ||
        supiBytes.size() > SOFTHSM_MILENAGE_MAX_SUPI_LEN ||
        !getFixedField(req, SOFTHSM_MILENAGE_TAG_PLAINTEXT_K, 16, plainK) ||
        !getFixedField(req, SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC, 16, plainOpc)) {
        return Error::BAD_REQUEST;
    }

    std::string supi = bytesToString(supiBytes);

    std::vector<uint8_t> wrappedK, wrappedOpc;
    Error result = Error::OK;
    if (milenage_envelope::wrapSecret(supi, milenage_envelope::SecretType::K, plainK.data(),
                                       masterKey, wrappedK) != milenage_envelope::Error::OK) {
        result = Error::BAD_REQUEST;
    } else if (milenage_envelope::wrapSecret(supi, milenage_envelope::SecretType::OPC,
                                              plainOpc.data(), masterKey,
                                              wrappedOpc) != milenage_envelope::Error::OK) {
        result = Error::BAD_REQUEST;
    } else {
        std::vector<std::pair<uint16_t, std::vector<uint8_t>>> fields = {
            {SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K, wrappedK},
            {SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC, wrappedOpc},
        };
        result = (milenage_wire::buildResponse(SOFTHSM_MILENAGE_OP_PROVISION, fields, response) ==
                  milenage_wire::Error::OK)
                     ? Error::OK
                     : Error::BAD_REQUEST;
    }

    if (!plainK.empty()) std::memset(plainK.data(), 0, plainK.size());
    if (!plainOpc.empty()) std::memset(plainOpc.data(), 0, plainOpc.size());
    return result;
}

Error importTransportWrapped(const uint8_t *request, size_t requestLen, const uint8_t transportKek[32],
                              const uint8_t masterKey[32], std::vector<uint8_t> &response)
{
    milenage_wire::Request req;
    if (milenage_wire::parseRequest(request, requestLen, req) != milenage_wire::Error::OK) {
        return Error::BAD_REQUEST;
    }
    if (req.operation != SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT) {
        return Error::BAD_REQUEST;
    }

    std::vector<uint8_t> supiBytes, transportK, transportOpc;
    if (!getField(req, SOFTHSM_MILENAGE_TAG_SUPI, supiBytes) ||
        supiBytes.size() > SOFTHSM_MILENAGE_MAX_SUPI_LEN ||
        !getField(req, SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K, transportK) ||
        !getField(req, SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC, transportOpc)) {
        return Error::BAD_REQUEST;
    }

    std::string supi = bytesToString(supiBytes);

    uint8_t plainK[16], plainOpc[16];
    milenage_transport::Error txErr;
    txErr = milenage_transport::unwrapPackage(supi, milenage_transport::SecretType::K, transportK,
                                               transportKek, plainK);
    if (txErr != milenage_transport::Error::OK) {
        return Error::CREDENTIAL_INVALID;
    }
    txErr = milenage_transport::unwrapPackage(supi, milenage_transport::SecretType::OPC, transportOpc,
                                               transportKek, plainOpc);
    if (txErr != milenage_transport::Error::OK) {
        std::memset(plainK, 0, sizeof(plainK));
        return Error::CREDENTIAL_INVALID;
    }

    std::vector<uint8_t> wrappedK, wrappedOpc;
    Error result = Error::OK;
    if (milenage_envelope::wrapSecret(supi, milenage_envelope::SecretType::K, plainK,
                                       masterKey, wrappedK) != milenage_envelope::Error::OK) {
        result = Error::BAD_REQUEST;
    } else if (milenage_envelope::wrapSecret(supi, milenage_envelope::SecretType::OPC, plainOpc,
                                              masterKey, wrappedOpc) != milenage_envelope::Error::OK) {
        result = Error::BAD_REQUEST;
    } else {
        std::vector<std::pair<uint16_t, std::vector<uint8_t>>> fields = {
            {SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K, wrappedK},
            {SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC, wrappedOpc},
        };
        result = (milenage_wire::buildResponse(SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT, fields, response) ==
                  milenage_wire::Error::OK)
                     ? Error::OK
                     : Error::BAD_REQUEST;
    }

    std::memset(plainK, 0, sizeof(plainK));
    std::memset(plainOpc, 0, sizeof(plainOpc));
    return result;
}

} // namespace milenage_service
