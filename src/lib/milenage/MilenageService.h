/*
 * Orchestrates a single vendor-mechanism request end to end: parse the
 * wire-format request, validate fields, unwrap credentials, run
 * Milenage / 5G-AKA, build the wire-format response.
 *
 * This is the logic src/lib/SoftHSM.cpp's C_SignInit/C_Sign dispatch
 * calls for CKM_SOFTHSM_5G_HE_AV_WRAPPED / CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED
 * / CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED / CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED.
 * This module still takes the Master Storage Key (and, for transport
 * import, the Transport KEK) as raw 32-byte buffers rather than
 * PKCS#11 key handles -- see the INTERIM note in CredentialEnvelope.h;
 * SoftHSM.cpp obtains those raw bytes via the same
 * SoftHSM::getSymmetricKey() path used for every other key type in
 * this codebase, so the values never leave the crypto layer through
 * any *new* extraction path even though this module's own signature
 * looks like a raw-buffer API.
 *
 * All cryptography goes through src/lib/milenage/CryptoBackend.cpp
 * (CryptoFactory-backed, backend-independent) -- see design doc
 * section 17.
 */

#ifndef SOFTHSM_MILENAGE_SERVICE_H
#define SOFTHSM_MILENAGE_SERVICE_H

#include <cstdint>
#include <string>
#include <vector>

namespace milenage_service {

enum class Error {
    OK,
    BAD_REQUEST,       /* wire format / mandatory field errors */
    CREDENTIAL_INVALID,/* generic unwrap/envelope/binding failure, design doc section 9 */
    SIGNATURE_INVALID  /* MAC-S mismatch during resync, maps to CKR_SIGNATURE_INVALID */
};

/* Handles CKM_SOFTHSM_5G_HE_AV_WRAPPED.
 * request: full wire-format request buffer (design doc section 10).
 * masterKey: 32-byte raw buffer, see class-level INTERIM note.
 * response: full wire-format response buffer on Error::OK.
 *
 * testRand (16 bytes, non-null) lets a direct C++ caller (e.g. the
 * KAT tests) force a specific RAND without going through the wire
 * protocol; it is always available at this API layer regardless of
 * build flags. Production PKCS#11 dispatch (SoftHSM.cpp) never passes
 * it -- RAND there always comes from SoftHSM's RNG.
 *
 * Independently, when built with WITH_MILENAGE_TEST_RAND, a caller
 * may instead put a 16-byte SOFTHSM_MILENAGE_TAG_RAND field directly
 * in the wire request; this function reads and uses it exactly like
 * an explicit testRand argument (only if testRand itself is null). In
 * a build without WITH_MILENAGE_TEST_RAND, the mere presence of that
 * tag in an AV request is a hard failure (Error::BAD_REQUEST) -- it is
 * never silently ignored, so a test-mode wire message cannot be
 * replayed unnoticed against a production build. */
Error generate5gHeAv(const uint8_t *request, size_t requestLen,
                      const uint8_t masterKey[32],
                      std::vector<uint8_t> &response,
                      const uint8_t *testRand = nullptr);

/* Handles CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED. */
Error resync(const uint8_t *request, size_t requestLen,
             const uint8_t masterKey[32],
             std::vector<uint8_t> &response);

/* Handles CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED. Only reachable in a
 * plaintext-provisioning build (WITH_MILENAGE_PLAINTEXT_PROVISIONING);
 * again, this module does not itself enforce that gate. */
Error provision(const uint8_t *request, size_t requestLen,
                 const uint8_t masterKey[32],
                 std::vector<uint8_t> &response);

/* Handles CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED (design doc
 * section 6 / task item 6). Only reachable when built with
 * WITH_MILENAGE_TRANSPORT_IMPORT; this module does not itself enforce
 * that gate. Unwraps K and OPc from the transport-wrapped package
 * under transportKek, validates package metadata and subscriber
 * binding, re-wraps both secrets under masterKey exactly like
 * provision() does, and returns only wrapped_k/wrapped_opc -- never
 * plaintext K/OPc. */
Error importTransportWrapped(const uint8_t *request, size_t requestLen,
                              const uint8_t transportKek[32],
                              const uint8_t masterKey[32],
                              std::vector<uint8_t> &response);

} // namespace milenage_service

#endif // SOFTHSM_MILENAGE_SERVICE_H
