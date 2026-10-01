/*
 * Milenage algorithm primitives (3GPP TS 35.206 / 35.207 / 35.208).
 *
 * STUB: signatures only, no implementation. See
 * doc/MILENAGE-5G-AKA-DESIGN.md section 12 and 17 (implementation
 * status). Not compiled into any target yet.
 *
 * All buffer-sized parameters use fixed-size arrays matching the
 * Milenage/AES-128 profile fixed by this phase's scope: 16-byte K,
 * 16-byte OPc, 6-byte SQN, 2-byte AMF, 16-byte RAND, 8-byte RES,
 * 14-byte AUTS.
 */

#ifndef SOFTHSM_MILENAGE_MILENAGE_H
#define SOFTHSM_MILENAGE_MILENAGE_H

#include <cstdint>
#include <cstddef>

namespace milenage {

constexpr size_t K_LEN = 16;
constexpr size_t OP_LEN = 16;
constexpr size_t OPC_LEN = 16;
constexpr size_t SQN_LEN = 6;
constexpr size_t AMF_LEN = 2;
constexpr size_t RAND_LEN = 16;
constexpr size_t RES_LEN = 8;
constexpr size_t MAC_LEN = 8;
constexpr size_t AUTN_LEN = 16;
constexpr size_t AUTS_LEN = 14;
constexpr size_t CK_LEN = 16;
constexpr size_t IK_LEN = 16;
constexpr size_t AK_LEN = 6;

/* TODO(milenage): derive OPc = E_K(OP) xor OP. Used by provisioning /
 * tests; the runtime AV/resync paths only ever see OPc, never OP. */
bool deriveOpc(const uint8_t k[K_LEN], const uint8_t op[OP_LEN],
                uint8_t opcOut[OPC_LEN]);

/* TODO(milenage): f1 - network authentication code MAC-A. */
bool f1(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
        const uint8_t rand[RAND_LEN], const uint8_t sqn[SQN_LEN],
        const uint8_t amf[AMF_LEN], uint8_t macAOut[MAC_LEN]);

/* TODO(milenage): f1* - resynchronization MAC-S. */
bool f1Star(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
            const uint8_t rand[RAND_LEN], const uint8_t sqn[SQN_LEN],
            const uint8_t amf[AMF_LEN], uint8_t macSOut[MAC_LEN]);

/* TODO(milenage): f2/f3/f4/f5 computed together (shared TEMP/OUT1/OUT2
 * blocks per TS 35.206 sample code structure), producing RES, CK, IK,
 * AK in one call to avoid recomputing intermediate rounds. */
bool f2345(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
           const uint8_t rand[RAND_LEN], uint8_t resOut[RES_LEN],
           uint8_t ckOut[CK_LEN], uint8_t ikOut[IK_LEN],
           uint8_t akOut[AK_LEN]);

/* TODO(milenage): f5* - resynchronization anonymity key AK*. */
bool f5Star(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
            const uint8_t rand[RAND_LEN], uint8_t akStarOut[AK_LEN]);

/* TODO(milenage): AUTN = (SQN xor AK) || AMF || MAC-A. */
bool buildAutn(const uint8_t sqn[SQN_LEN], const uint8_t ak[AK_LEN],
               const uint8_t amf[AMF_LEN], const uint8_t macA[MAC_LEN],
               uint8_t autnOut[AUTN_LEN]);

/* TODO(milenage): recover SQN_MS = (SQN xor AK*) from AUTS and AK*,
 * verify MAC-S, per TS 33.102 6.3.3 / TS 35.206 resync annex. Returns
 * false (and leaves sqnMsOut untouched) on any parse or MAC failure;
 * caller maps that to CKR_SIGNATURE_INVALID. Comparison of MAC-S must
 * be constant-time. */
bool verifyAuts(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
                 const uint8_t rand[RAND_LEN], const uint8_t auts[AUTS_LEN],
                 uint8_t sqnMsOut[SQN_LEN]);

} // namespace milenage

#endif // SOFTHSM_MILENAGE_MILENAGE_H
