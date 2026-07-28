/*
 * 5G-AKA KDFs (3GPP TS 33.501 Annex A, built on the generic KDF of
 * TS 33.220 Annex B: HMAC-SHA-256 over S = FC || P0 || L0 || P1 || L1
 * || ...). HMAC-SHA-256 is provided by CryptoBackend.cpp, the only
 * file in this directory that talks to SoftHSM's CryptoFactory --
 * this file has no dependency on which crypto backend SoftHSM was
 * built with. See doc/MILENAGE-5G-AKA-DESIGN.md section 17.
 */

#include "FiveGAka.h"
#include "CryptoBackend.h"

#include <cstring>
#include <vector>

namespace fiveg_aka {

namespace {

constexpr uint8_t FC_XRES_STAR = 0x6B;
constexpr uint8_t FC_KAUSF     = 0x6A;

void appendParam(std::vector<uint8_t> &s, const uint8_t *p, size_t len)
{
    s.insert(s.end(), p, p + len);
    s.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    s.push_back(static_cast<uint8_t>(len & 0xFF));
}

/* Generic 3GPP KDF: HMAC-SHA-256(key, S), full 32-byte output. */
bool genericKdf(const uint8_t *key, size_t keyLen, const std::vector<uint8_t> &s,
                 uint8_t out32[32])
{
    return milenage_crypto::hmacSha256(key, keyLen, s.data(), s.size(), out32);
}

} // namespace

bool deriveXresStar(const uint8_t ck[milenage::CK_LEN], const uint8_t ik[milenage::IK_LEN],
                     const uint8_t rand[milenage::RAND_LEN], const uint8_t res[milenage::RES_LEN],
                     const uint8_t *snn, size_t snnLen, uint8_t xresStarOut[XRES_STAR_LEN])
{
    uint8_t key[KAUSF_INPUT_KEY_LEN];
    std::memcpy(key, ck, milenage::CK_LEN);
    std::memcpy(key + milenage::CK_LEN, ik, milenage::IK_LEN);

    std::vector<uint8_t> s;
    s.reserve(1 + snnLen + 2 + milenage::RAND_LEN + 2 + milenage::RES_LEN + 2);
    s.push_back(FC_XRES_STAR);
    appendParam(s, snn, snnLen);
    appendParam(s, rand, milenage::RAND_LEN);
    appendParam(s, res, milenage::RES_LEN);

    uint8_t full[32];
    if (!genericKdf(key, sizeof(key), s, full)) {
        return false;
    }
    /* XRES* is the 128 least-significant bits of the KDF output. */
    std::memcpy(xresStarOut, full + 16, XRES_STAR_LEN);
    return true;
}

bool deriveKausf(const uint8_t ck[milenage::CK_LEN], const uint8_t ik[milenage::IK_LEN],
                  const uint8_t sqnXorAk[milenage::SQN_LEN], const uint8_t *snn, size_t snnLen,
                  uint8_t kausfOut[KAUSF_LEN])
{
    uint8_t key[KAUSF_INPUT_KEY_LEN];
    std::memcpy(key, ck, milenage::CK_LEN);
    std::memcpy(key + milenage::CK_LEN, ik, milenage::IK_LEN);

    std::vector<uint8_t> s;
    s.reserve(1 + snnLen + 2 + milenage::SQN_LEN + 2);
    s.push_back(FC_KAUSF);
    appendParam(s, snn, snnLen);
    appendParam(s, sqnXorAk, milenage::SQN_LEN);

    return genericKdf(key, sizeof(key), s, kausfOut);
}

} // namespace fiveg_aka
