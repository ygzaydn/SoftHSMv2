/*
 * Wrapped credential envelope: build/parse the plaintext envelope
 * (design doc section 9) and wrap/unwrap it with AES-KWP (RFC 5649)
 * under the Master Storage Key.
 *
 * STUB: signatures only, no implementation. See
 * doc/MILENAGE-5G-AKA-DESIGN.md sections 9 and 17. Not compiled into
 * any target yet.
 */

#ifndef SOFTHSM_MILENAGE_CREDENTIAL_ENVELOPE_H
#define SOFTHSM_MILENAGE_CREDENTIAL_ENVELOPE_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace milenage_envelope {

enum class SecretType : uint8_t { K = 0x01, OPC = 0x02 };

/* Generic failure for every unwrap/integrity/envelope/binding error
 * (design doc section 9 requires a single external error, no oracle). */
enum class Error { OK, GENERIC_FAILURE };

/* TODO(milenage): canonical SUPI validation - "imsi-" + 5..15 decimal
 * digits, exact match, no whitespace/case variation accepted. */
bool isCanonicalSupi(const std::string &supi);

/* TODO(milenage): build the 58-byte plaintext envelope
 * (SOFTHSM_MILENAGE_ENVELOPE_PLAINTEXT_LEN) for the given secret and
 * canonical SUPI, then AES-KWP-wrap it under masterKey. masterKey is an
 * opaque reference to a PKCS#11-backed key operation supplied by the
 * caller (not a raw key buffer) once wired into SoftHSM's crypto layer;
 * left abstract here pending that wiring. */
Error wrapSecret(const std::string &canonicalSupi, SecretType type,
                  const uint8_t secret[16],
                  std::vector<uint8_t> &wrappedOut);

/* TODO(milenage): AES-KWP-unwrap, parse envelope, validate magic/
 * version/algorithm/secret_type/reserved/secret_length, recompute and
 * constant-time-compare subscriber_binding against canonicalSupi.
 * Any failure returns Error::GENERIC_FAILURE and leaves secretOut
 * untouched/wiped. */
Error unwrapSecret(const std::string &canonicalSupi, SecretType expectedType,
                    const std::vector<uint8_t> &wrapped,
                    uint8_t secretOut[16]);

} // namespace milenage_envelope

#endif // SOFTHSM_MILENAGE_CREDENTIAL_ENVELOPE_H
