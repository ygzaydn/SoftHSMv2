/*
 * Vendor-defined PKCS#11 interface for Milenage / 5G-AKA wrapped
 * subscriber credentials.
 *
 * See doc/MILENAGE-5G-AKA-DESIGN.md for the full design and current
 * implementation status. This header defines the mechanism IDs,
 * wire-format tags, envelope layouts, and key templates used by
 * src/lib/milenage/ and its PKCS#11 wiring in src/lib/SoftHSM.cpp
 * (build-gated by WITH_MILENAGE and its sub-flags).
 *
 * WARNING: SoftHSMv2 is a software PKCS#11 implementation. It does not
 * provide hardware isolation. A privileged attacker who can read the
 * process memory of the application linking libsofthsm2.so can recover
 * key material regardless of CKA_EXTRACTABLE / CKA_SENSITIVE. These
 * mechanisms restrict what is reachable through the PKCS#11 API; they
 * are not a substitute for host-level trust.
 */

#ifndef SOFTHSM_MILENAGE_H
#define SOFTHSM_MILENAGE_H

#include "cryptoki.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * Vendor mechanism IDs.
 *
 * 0x53470000 = ASCII "SG" (5G) in the top 16 bits, chosen to avoid
 * collision with known third-party vendor allocations while staying
 * inside the private CKM_VENDOR_DEFINED space.
 * ------------------------------------------------------------------- */
#define CKM_SOFTHSM_MILENAGE_BASE                  (CKM_VENDOR_DEFINED | 0x53470000UL)

#define CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED          (CKM_SOFTHSM_MILENAGE_BASE + 0x0001)
#define CKM_SOFTHSM_5G_HE_AV_WRAPPED                    (CKM_SOFTHSM_MILENAGE_BASE + 0x0002)
#define CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED             (CKM_SOFTHSM_MILENAGE_BASE + 0x0003)
/* Optional hardening mechanism (WITH_MILENAGE_TRANSPORT_IMPORT). */
#define CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED   (CKM_SOFTHSM_MILENAGE_BASE + 0x0004)
/* Test-only mechanism (WITH_MILENAGE_RAW_TESTS). Never built by default. */
#define CKM_SOFTHSM_MILENAGE_RAW_TEST                   (CKM_SOFTHSM_MILENAGE_BASE + 0x00FF)

/* ---------------------------------------------------------------------
 * Master Storage Key template (spec section 3.1). Reference values only;
 * the code that generates the key must set every one of these
 * attributes explicitly and every mechanism implementation must
 * re-verify them at operation time rather than trusting object metadata.
 * ------------------------------------------------------------------- */
#define SOFTHSM_MILENAGE_MASTER_KEY_LABEL   "open5gs-milenage-master"
#define SOFTHSM_MILENAGE_MASTER_KEY_ID_BYTE 0x01
#define SOFTHSM_MILENAGE_MASTER_KEY_VALUE_LEN 32 /* AES-256 */

/* ---------------------------------------------------------------------
 * Transport KEK template (design doc section 5.2 / task item 6).
 * Cryptographically separate key from the Master Storage Key: never
 * used for AV generation, and the Master Storage Key is never used
 * for transport import. Same non-extractable/non-generic-API-usable
 * shape as the Master Storage Key, restricted to
 * CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED only.
 * ------------------------------------------------------------------- */
#define SOFTHSM_MILENAGE_TRANSPORT_KEK_LABEL   "open5gs-milenage-transport-kek"
#define SOFTHSM_MILENAGE_TRANSPORT_KEK_ID_BYTE 0x02
#define SOFTHSM_MILENAGE_TRANSPORT_KEK_VALUE_LEN 32 /* AES-256 */

/* ---------------------------------------------------------------------
 * Transport-wrapped provisioning package (design doc section 6).
 * Distinct format and magic from the credential envelope below --
 * this is what an external provisioning authority sends in; it is
 * never what gets stored in the UDM database (that is always the
 * credential envelope, wrapped under the Master Storage Key).
 * ------------------------------------------------------------------- */
#define SOFTHSM_MILENAGE_TRANSPORT_MAGIC          "S5GT" /* 4 bytes, no NUL */
#define SOFTHSM_MILENAGE_TRANSPORT_VERSION        0x01
#define SOFTHSM_MILENAGE_TRANSPORT_KEY_VERSION    0x01
#define SOFTHSM_MILENAGE_TRANSPORT_BINDING_CONTEXT "open5gs-milenage-transport-v1:"
/* offset 0  magic[4]  "S5GT"
 * offset 4  version               1 byte
 * offset 5  secret_type           1 byte (K=1, OPc=2)
 * offset 6  transport_key_version 1 byte
 * offset 7  reserved              1 byte, must be 0
 * offset 8  subscriber_binding[32]
 * offset 40 transaction_id_len    1 byte, 0..32
 * offset 41 transaction_id[32]    fixed-size field, only the first
 *                                 transaction_id_len bytes are
 *                                 meaningful, the rest must be zero
 * offset 73 secret_length         2 bytes BE, must be 16
 * offset 75 secret_value[16]
 * total: 91 bytes plaintext, before AES-KWP wrapping.
 */
#define SOFTHSM_MILENAGE_TRANSPORT_PLAINTEXT_LEN 91

/* ---------------------------------------------------------------------
 * Credential envelope (spec section 6 / design doc section 9).
 * Wrapped independently per secret (K, OPc) with RFC 5649 AES-KWP under
 * the Master Storage Key.
 * ------------------------------------------------------------------- */
#define SOFTHSM_MILENAGE_ENVELOPE_MAGIC       "S5GC"   /* 4 bytes, no NUL */
#define SOFTHSM_MILENAGE_ENVELOPE_VERSION     0x01
#define SOFTHSM_MILENAGE_ALG_MILENAGE_AES128  0x01
#define SOFTHSM_MILENAGE_SECRET_TYPE_K        0x01
#define SOFTHSM_MILENAGE_SECRET_TYPE_OPC      0x02
#define SOFTHSM_MILENAGE_SUBSCRIBER_BINDING_LEN 32 /* SHA-256 */
#define SOFTHSM_MILENAGE_SECRET_LEN           16   /* Milenage K / OPc */
#define SOFTHSM_MILENAGE_SUBSCRIBER_BINDING_CONTEXT "open5gs-milenage-v1:"

/* Envelope byte layout (all multi-byte integers big-endian):
 *   offset  0  magic[4]              "S5GC"
 *   offset  4  version               1 byte
 *   offset  5  algorithm             1 byte
 *   offset  6  secret_type           1 byte
 *   offset  7  reserved              1 byte, must be 0
 *   offset  8  subscriber_binding[32]
 *   offset 40  secret_length         2 bytes BE, must be 16
 *   offset 42  secret_value[16]
 *   total: 58 bytes plaintext, before AES-KWP wrapping.
 */
#define SOFTHSM_MILENAGE_ENVELOPE_PLAINTEXT_LEN 58

/* ---------------------------------------------------------------------
 * Wire format (design doc section 10). Header + TLV records.
 * ------------------------------------------------------------------- */
#define SOFTHSM_MILENAGE_WIRE_MAGIC "S5GM" /* 4 bytes, no NUL */
#define SOFTHSM_MILENAGE_WIRE_VERSION 0x01

#define SOFTHSM_MILENAGE_MAX_REQUEST_LEN      4096
#define SOFTHSM_MILENAGE_MAX_RESPONSE_LEN     1024
#define SOFTHSM_MILENAGE_MAX_WRAPPED_BLOB_LEN 256
#define SOFTHSM_MILENAGE_MAX_SNN_LEN          255
#define SOFTHSM_MILENAGE_MAX_SUPI_LEN         32

/* Operation codes, carried in the wire header, matched to the mechanism
 * used to invoke C_SignInit so a request can't be replayed under a
 * different mechanism than it was built for. */
typedef enum {
    SOFTHSM_MILENAGE_OP_PROVISION           = 0x01,
    SOFTHSM_MILENAGE_OP_5G_HE_AV            = 0x02,
    SOFTHSM_MILENAGE_OP_RESYNC              = 0x03,
    SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT    = 0x04,
    SOFTHSM_MILENAGE_OP_RAW_TEST            = 0xFF
} softhsm_milenage_operation_t;

/* TLV tags. Odd/even split marks "critical" (must-understand) vs.
 * optional tags is deferred to the parser implementation; not encoded
 * in the tag value itself here. */
typedef enum {
    SOFTHSM_MILENAGE_TAG_SUPI        = 0x0001, /* canonical "imsi-..." string */
    SOFTHSM_MILENAGE_TAG_WRAPPED_K   = 0x0002,
    SOFTHSM_MILENAGE_TAG_WRAPPED_OPC = 0x0003,
    SOFTHSM_MILENAGE_TAG_SQN         = 0x0004, /* 6 bytes */
    SOFTHSM_MILENAGE_TAG_AMF         = 0x0005, /* 2 bytes */
    SOFTHSM_MILENAGE_TAG_SNN         = 0x0006, /* 1..255 bytes */
    SOFTHSM_MILENAGE_TAG_RAND        = 0x0007, /* 16 bytes; resync input, or
                                                   test-mode-only AV input */
    SOFTHSM_MILENAGE_TAG_AUTS        = 0x0008, /* 14 bytes, resync input */
    SOFTHSM_MILENAGE_TAG_PLAINTEXT_K   = 0x0009, /* provisioning only,
                                                     WITH_MILENAGE_PLAINTEXT_PROVISIONING */
    SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC = 0x000A, /* provisioning only */
    SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K   = 0x000B, /* WITH_MILENAGE_TRANSPORT_IMPORT */
    SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC = 0x000C,

    /* Response tags */
    SOFTHSM_MILENAGE_TAG_OUT_RAND     = 0x0101,
    SOFTHSM_MILENAGE_TAG_OUT_AUTN     = 0x0102,
    SOFTHSM_MILENAGE_TAG_OUT_XRES_STAR = 0x0103,
    SOFTHSM_MILENAGE_TAG_OUT_KAUSF    = 0x0104,
    SOFTHSM_MILENAGE_TAG_OUT_SQN_MS   = 0x0105,
    SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K   = 0x0106,
    SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC = 0x0107
} softhsm_milenage_tag_t;

/* Mechanism parameter for CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED
 * (WITH_MILENAGE_TRANSPORT_IMPORT), passed as pMechanism->pParameter
 * to C_SignInit. The mechanism's hKey is the Transport KEK (validated
 * against the template in section 5.2 of the design doc); this
 * mechanism additionally needs the token's Master Storage Key to
 * re-wrap the imported secrets, which standard PKCS#11 has no way to
 * pass except through a mechanism parameter -- masterKeyHandle is
 * that second key handle, explicitly supplied by the caller (not
 * looked up implicitly by label/ID inside SoftHSM), and is
 * independently re-validated server-side against the Master Storage
 * Key template exactly like every other mechanism in this file does. */
typedef struct CK_SOFTHSM_MILENAGE_TRANSPORT_IMPORT_PARAMS {
    CK_OBJECT_HANDLE masterKeyHandle;
} CK_SOFTHSM_MILENAGE_TRANSPORT_IMPORT_PARAMS;

#ifdef __cplusplus
}
#endif

#endif /* SOFTHSM_MILENAGE_H */
