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

/* Master key length (AES-256). */
constexpr size_t MASTER_KEY_LEN = 32;

/* Builds the 58-byte plaintext envelope (see
 * SOFTHSM_MILENAGE_ENVELOPE_PLAINTEXT_LEN) for the given secret and
 * canonical SUPI, then AES-KWP-wraps it (RFC 5649) under masterKey.
 *
 * INTERIM: masterKey is a raw 32-byte key buffer here so this module
 * can be implemented and unit-tested standalone. The design in
 * doc/MILENAGE-5G-AKA-DESIGN.md section 5.1 requires the Master
 * Storage Key to be non-extractable and used only via a PKCS#11 key
 * handle; a follow-up commit must replace this raw-buffer interface
 * with one driven by SoftHSM's internal key-object/crypto layer so
 * the key value itself never exists outside that layer. Do not call
 * this function with a token's real Master Storage Key value obtained
 * by any extraction path. */
Error wrapSecret(const std::string &canonicalSupi, SecretType type,
                  const uint8_t secret[16],
                  const uint8_t masterKey[MASTER_KEY_LEN],
                  std::vector<uint8_t> &wrappedOut);

/* AES-KWP-unwraps, parses the envelope, validates magic/version/
 * algorithm/secret_type/reserved/secret_length, recomputes and
 * constant-time-compares subscriber_binding against canonicalSupi.
 * Any failure returns Error::GENERIC_FAILURE and leaves secretOut
 * untouched. See INTERIM note on wrapSecret regarding masterKey. */
Error unwrapSecret(const std::string &canonicalSupi, SecretType expectedType,
                    const std::vector<uint8_t> &wrapped,
                    const uint8_t masterKey[MASTER_KEY_LEN],
                    uint8_t secretOut[16]);

} // namespace milenage_envelope

#endif // SOFTHSM_MILENAGE_CREDENTIAL_ENVELOPE_H
