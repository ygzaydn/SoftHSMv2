/*
 * Orchestrates a single vendor-mechanism request end to end: parse the
 * wire-format request, validate fields, unwrap credentials, run
 * Milenage / 5G-AKA, build the wire-format response.
 *
 * This is the logic that C_SignInit/C_Sign would invoke for
 * CKM_SOFTHSM_5G_HE_AV_WRAPPED / CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED /
 * CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED once wired into
 * src/lib/SoftHSM.cpp's mechanism dispatch and session/key-object
 * model. That wiring does not exist yet -- see
 * doc/MILENAGE-5G-AKA-DESIGN.md section 17. This class takes the
 * Master Storage Key as a raw 32-byte buffer (see the INTERIM note in
 * CredentialEnvelope.h); it must be adapted to go through SoftHSM's
 * key-object/crypto layer instead before it is ever given a real
 * token key's value.
 *
 * RAND generation uses OpenSSL RAND_bytes() directly here for the same
 * "no Botan available in this dev environment" reason documented for
 * Milenage.cpp / FiveGAka.cpp.
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
 * Caller-supplied RAND (testRand != nullptr, 16 bytes) is only
 * intended to be reachable when WITH_MILENAGE_TEST_RAND is enabled;
 * this module does not itself gate that build flag (no build
 * integration exists yet), so callers driving this from production
 * PKCS#11 dispatch must not pass testRand. */
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

} // namespace milenage_service

#endif // SOFTHSM_MILENAGE_SERVICE_H
