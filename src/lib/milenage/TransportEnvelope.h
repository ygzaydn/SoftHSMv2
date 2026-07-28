/*
 * Transport-wrapped provisioning package (design doc section 6 / task
 * item 6): the format an external secure provisioning authority uses
 * to hand K/OPc to SoftHSM under a separate Transport KEK, distinct
 * from the wrapped_k/wrapped_opc envelope in CredentialEnvelope.h
 * (which is always wrapped under the token's Master Storage Key and
 * is what actually gets stored in the UDM database).
 *
 * Flow (design doc section 6):
 *   authority: K, OPc --wrap under Transport KEK--> transport package
 *   SoftHSM (CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED):
 *     unwrap with Transport KEK, validate package metadata,
 *     re-wrap under the Master Storage Key (CredentialEnvelope),
 *     return only wrapped_k / wrapped_opc.
 *
 * wrapPackage() below exists so this module -- and tests -- can act as
 * the "secure provisioning authority" side for testing/PoC purposes;
 * in a real deployment that side lives entirely outside SoftHSM.
 */

#ifndef SOFTHSM_MILENAGE_TRANSPORT_ENVELOPE_H
#define SOFTHSM_MILENAGE_TRANSPORT_ENVELOPE_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace milenage_transport {

enum class SecretType : uint8_t { K = 0x01, OPC = 0x02 };
enum class Error { OK, GENERIC_FAILURE };

constexpr size_t TRANSPORT_KEY_LEN = 32; /* AES-256 */
constexpr size_t MAX_TRANSACTION_ID_LEN = 32;

/* Builds and AES-KWP-wraps a transport package binding: canonical
 * SUPI, secret type, a fixed package version, a fixed transport-key
 * version marker, the secret itself (16 bytes), and an optional
 * provisioning transaction identifier (0..32 bytes, may be empty).
 * "Secure provisioning authority" side -- see file header. */
Error wrapPackage(const std::string &canonicalSupi, SecretType type, const uint8_t secret[16],
                   const uint8_t *transactionId, size_t transactionIdLen,
                   const uint8_t transportKek[TRANSPORT_KEY_LEN],
                   std::vector<uint8_t> &packageOut);

/* AES-KWP-unwraps and fully validates a transport package: magic,
 * version, secret type, transport-key version, transaction-id length,
 * secret length, and (constant-time) subscriber binding. Any failure
 * returns Error::GENERIC_FAILURE without revealing which check failed
 * (design doc section 9's "one generic external error" rule applies
 * here too). "SoftHSM" side -- see file header. */
Error unwrapPackage(const std::string &canonicalSupi, SecretType expectedType,
                     const std::vector<uint8_t> &package,
                     const uint8_t transportKek[TRANSPORT_KEY_LEN],
                     uint8_t secretOut[16]);

} // namespace milenage_transport

#endif // SOFTHSM_MILENAGE_TRANSPORT_ENVELOPE_H
