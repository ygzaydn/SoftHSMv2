/*
 * Milenage algorithm primitives (3GPP TS 35.206 Annex 3 reference
 * algorithm structure). Implemented independently from the 3GPP
 * pseudocode/sample C, using OpenSSL EVP for the single AES-128 block
 * primitive E_K(). Not yet wired into SoftHSM's CryptoFactory
 * abstraction (see doc/MILENAGE-5G-AKA-DESIGN.md section 17) — this
 * uses OpenSSL directly so it can be built/tested standalone in an
 * environment without the Botan backend available.
 */

#include "Milenage.h"

#include <cstring>
#include <openssl/evp.h>

namespace milenage {

namespace {

/* Single AES-128 ECB block encryption: out = E_K(in), 16 bytes. */
bool aes128EncryptBlock(const uint8_t key[K_LEN], const uint8_t in[16], uint8_t out[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    bool ok = false;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outLen1 = 0, outLen2 = 0;
        uint8_t buf[32];
        if (EVP_EncryptUpdate(ctx, buf, &outLen1, in, 16) == 1 &&
            EVP_EncryptFinal_ex(ctx, buf + outLen1, &outLen2) == 1 &&
            (outLen1 + outLen2) == 16) {
            std::memcpy(out, buf, 16);
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void xorBlock16(const uint8_t a[16], const uint8_t b[16], uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/* Left-rotate a 16-byte block by r bits (r must be a multiple of 8 for
 * this implementation, which matches all Milenage rotate constants:
 * 0, 32, 64, 96). */
void rotateLeftBytes(const uint8_t in[16], size_t rBits, uint8_t out[16])
{
    size_t rBytes = (rBits / 8) % 16;
    for (int i = 0; i < 16; i++) {
        out[i] = in[(i + rBytes) % 16];
    }
}

/* Computes TEMP = E_K(RAND xor OPc) and returns it, per 35.206 Annex 3. */
bool computeTemp(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
                  const uint8_t rand[RAND_LEN], uint8_t tempOut[16])
{
    uint8_t xored[16];
    xorBlock16(rand, opc, xored);
    return aes128EncryptBlock(k, xored, tempOut);
}

/* Computes one of the OUTn = E_K( rotate(TEMP xor OPc, r) xor c ) xor OPc
 * outputs shared by f2..f5/f5*. */
bool computeOutN(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
                  const uint8_t temp[16], const uint8_t c[16], size_t rBits,
                  uint8_t outN[16])
{
    uint8_t tempXorOpc[16];
    xorBlock16(temp, opc, tempXorOpc);
    uint8_t rotated[16];
    rotateLeftBytes(tempXorOpc, rBits, rotated);
    uint8_t rijndaelInput[16];
    xorBlock16(rotated, c, rijndaelInput);
    uint8_t encrypted[16];
    if (!aes128EncryptBlock(k, rijndaelInput, encrypted)) {
        return false;
    }
    xorBlock16(encrypted, opc, outN);
    return true;
}

/* Computes OUT1 (shared by f1 and f1*): E_K( rotate(IN1 xor OPc, r1) xor
 * TEMP ) xor OPc, where IN1 = SQN || AMF || SQN || AMF and r1 = 64 bits. */
bool computeOut1(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
                  const uint8_t temp[16], const uint8_t sqn[SQN_LEN],
                  const uint8_t amf[AMF_LEN], uint8_t out1[16])
{
    uint8_t in1[16];
    std::memcpy(in1, sqn, SQN_LEN);
    std::memcpy(in1 + SQN_LEN, amf, AMF_LEN);
    std::memcpy(in1 + SQN_LEN + AMF_LEN, sqn, SQN_LEN);
    std::memcpy(in1 + SQN_LEN + AMF_LEN + SQN_LEN, amf, AMF_LEN);

    uint8_t in1XorOpc[16];
    xorBlock16(in1, opc, in1XorOpc);
    uint8_t rotated[16];
    rotateLeftBytes(in1XorOpc, 64, rotated);
    uint8_t rijndaelInput[16];
    xorBlock16(rotated, temp, rijndaelInput);
    uint8_t encrypted[16];
    if (!aes128EncryptBlock(k, rijndaelInput, encrypted)) {
        return false;
    }
    xorBlock16(encrypted, opc, out1);
    return true;
}

const uint8_t C1[16] = {0};
const uint8_t C2[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
const uint8_t C3[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2};
const uint8_t C4[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,4};
const uint8_t C5[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,8};

constexpr size_t R2 = 0;
constexpr size_t R3 = 32;
constexpr size_t R4 = 64;
constexpr size_t R5 = 96;

bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace

bool deriveOpc(const uint8_t k[K_LEN], const uint8_t op[OP_LEN], uint8_t opcOut[OPC_LEN])
{
    uint8_t encrypted[16];
    if (!aes128EncryptBlock(k, op, encrypted)) {
        return false;
    }
    xorBlock16(encrypted, op, opcOut);
    return true;
}

bool f1(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
        const uint8_t rand[RAND_LEN], const uint8_t sqn[SQN_LEN],
        const uint8_t amf[AMF_LEN], uint8_t macAOut[MAC_LEN])
{
    uint8_t temp[16];
    if (!computeTemp(k, opc, rand, temp)) {
        return false;
    }
    uint8_t out1[16];
    if (!computeOut1(k, opc, temp, sqn, amf, out1)) {
        return false;
    }
    std::memcpy(macAOut, out1, MAC_LEN); /* MAC-A = OUT1[0..7] */
    return true;
}

bool f1Star(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
            const uint8_t rand[RAND_LEN], const uint8_t sqn[SQN_LEN],
            const uint8_t amf[AMF_LEN], uint8_t macSOut[MAC_LEN])
{
    /* f1* uses the same OUT1 computation as f1 but takes the other
     * half of the output. Per TS 33.102 6.3.3, AMF is set to all
     * zeroes for the resynchronization MAC-S computation; callers
     * (verifyAuts) are responsible for passing amf = {0,0}. */
    uint8_t temp[16];
    if (!computeTemp(k, opc, rand, temp)) {
        return false;
    }
    uint8_t out1[16];
    if (!computeOut1(k, opc, temp, sqn, amf, out1)) {
        return false;
    }
    std::memcpy(macSOut, out1 + MAC_LEN, MAC_LEN); /* MAC-S = OUT1[8..15] */
    return true;
}

bool f2345(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
           const uint8_t rand[RAND_LEN], uint8_t resOut[RES_LEN],
           uint8_t ckOut[CK_LEN], uint8_t ikOut[IK_LEN], uint8_t akOut[AK_LEN])
{
    uint8_t temp[16];
    if (!computeTemp(k, opc, rand, temp)) {
        return false;
    }

    uint8_t out2[16];
    if (!computeOutN(k, opc, temp, C2, R2, out2)) {
        return false;
    }
    /* Per 35.206 Annex 3: AK = OUT2[0..5] (6 bytes), RES = OUT2[8..15]
     * (last 8 bytes); bytes [6..7] of OUT2 are unused. */
    std::memcpy(akOut, out2, AK_LEN);
    std::memcpy(resOut, out2 + 8, RES_LEN);

    uint8_t out3[16];
    if (!computeOutN(k, opc, temp, C3, R3, out3)) {
        return false;
    }
    std::memcpy(ckOut, out3, CK_LEN); /* CK = OUT3 (all 16 bytes) */

    uint8_t out4[16];
    if (!computeOutN(k, opc, temp, C4, R4, out4)) {
        return false;
    }
    std::memcpy(ikOut, out4, IK_LEN); /* IK = OUT4 (all 16 bytes) */

    return true;
}

bool f5Star(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
            const uint8_t rand[RAND_LEN], uint8_t akStarOut[AK_LEN])
{
    uint8_t temp[16];
    if (!computeTemp(k, opc, rand, temp)) {
        return false;
    }
    uint8_t out5[16];
    if (!computeOutN(k, opc, temp, C5, R5, out5)) {
        return false;
    }
    std::memcpy(akStarOut, out5, AK_LEN); /* AK* = OUT5[0..5] */
    return true;
}

bool buildAutn(const uint8_t sqn[SQN_LEN], const uint8_t ak[AK_LEN],
               const uint8_t amf[AMF_LEN], const uint8_t macA[MAC_LEN],
               uint8_t autnOut[AUTN_LEN])
{
    for (size_t i = 0; i < SQN_LEN; i++) {
        autnOut[i] = sqn[i] ^ ak[i];
    }
    std::memcpy(autnOut + SQN_LEN, amf, AMF_LEN);
    std::memcpy(autnOut + SQN_LEN + AMF_LEN, macA, MAC_LEN);
    return true;
}

bool verifyAuts(const uint8_t k[K_LEN], const uint8_t opc[OPC_LEN],
                 const uint8_t rand[RAND_LEN], const uint8_t auts[AUTS_LEN],
                 uint8_t sqnMsOut[SQN_LEN])
{
    uint8_t akStar[AK_LEN];
    if (!f5Star(k, opc, rand, akStar)) {
        return false;
    }

    uint8_t sqnMs[SQN_LEN];
    for (size_t i = 0; i < SQN_LEN; i++) {
        sqnMs[i] = auts[i] ^ akStar[i];
    }

    const uint8_t amfZero[AMF_LEN] = {0, 0};
    uint8_t macS[MAC_LEN];
    if (!f1Star(k, opc, rand, sqnMs, amfZero, macS)) {
        return false;
    }

    if (!constantTimeEqual(macS, auts + SQN_LEN, MAC_LEN)) {
        return false;
    }

    std::memcpy(sqnMsOut, sqnMs, SQN_LEN);
    return true;
}

} // namespace milenage
