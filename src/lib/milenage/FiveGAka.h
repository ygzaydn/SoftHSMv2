/*
 * 5G-AKA KDFs (3GPP TS 33.501 / applicable generic KDF spec): XRES*
 * and KAUSF derivation from the Milenage outputs.
 *
 * STUB: signatures only, no implementation. See
 * doc/MILENAGE-5G-AKA-DESIGN.md sections 12 and 17. Not compiled into
 * any target yet.
 */

#ifndef SOFTHSM_MILENAGE_FIVEGAKA_H
#define SOFTHSM_MILENAGE_FIVEGAKA_H

#include <cstdint>
#include <cstddef>
#include "Milenage.h"

namespace fiveg_aka {

constexpr size_t XRES_STAR_LEN = 16;
constexpr size_t KAUSF_LEN = 32;
constexpr size_t KAUSF_INPUT_KEY_LEN = 32; /* KEY = CK || IK, per TS 33.501 A.2/A.4 */

/* TODO(milenage): XRES* = KDF(CK||IK, "XRES*" domain-separated with
 * SNN, RAND, RES). */
bool deriveXresStar(const uint8_t ck[milenage::CK_LEN],
                     const uint8_t ik[milenage::IK_LEN],
                     const uint8_t rand[milenage::RAND_LEN],
                     const uint8_t res[milenage::RES_LEN],
                     const uint8_t *snn, size_t snnLen,
                     uint8_t xresStarOut[XRES_STAR_LEN]);

/* TODO(milenage): KAUSF = KDF(CK||IK, "KAUSF" domain-separated with SNN,
 * SQN xor AK). */
bool deriveKausf(const uint8_t ck[milenage::CK_LEN],
                  const uint8_t ik[milenage::IK_LEN],
                  const uint8_t sqnXorAk[milenage::SQN_LEN],
                  const uint8_t *snn, size_t snnLen,
                  uint8_t kausfOut[KAUSF_LEN]);

} // namespace fiveg_aka

#endif // SOFTHSM_MILENAGE_FIVEGAKA_H
