/*
 * Interim standalone self-test for src/lib/milenage.
 *
 * This is NOT wired into SoftHSM's CppUnit test suite
 * (src/lib/crypto/test) or into CMakeLists.txt/Makefile.am yet — see
 * doc/MILENAGE-5G-AKA-DESIGN.md section 17. It exists so the Milenage/
 * 5G-AKA primitives and the credential envelope can be built and run
 * independently while PKCS#11 dispatch wiring is still pending.
 *
 * Build (from this directory):
 *   g++ -std=c++17 -Wall -Wextra -I.. -I../../pkcs11 \
 *       standalone_selftest.cpp ../Milenage.cpp ../FiveGAka.cpp \
 *       ../CredentialEnvelope.cpp -lcrypto -o /tmp/milenage_selftest
 *   /tmp/milenage_selftest
 *
 * See also service_selftest.cpp (wire codec + service orchestration),
 * and pkcs11_e2e_test.cpp / pkcs11_restart_test.cpp (real PKCS#11-level
 * tests against a built libsofthsm2.so, requiring WITH_MILENAGE=ON).
 *
 * OPc, MAC-A (f1), RES (f2), and AK (f5) below are checked against the
 * published 3GPP TS 35.207 Test Set 1 vectors and were confirmed to
 * match when this file was last run. CK and IK are computed but not
 * asserted against an external vector: no independently-verified
 * TS 35.207 CK/IK value for Test Set 1 was available in this session,
 * so asserting a guessed value would be dishonest. The 5G-AKA KDF
 * (XRES-star / KAUSF) checks are determinism/self-consistency checks
 * only -- no TS 33.501 Annex A KAT was available to verify against here.
 * Both gaps should be closed with vectors obtained directly from the
 * 3GPP specifications before this is treated as fully validated.
 */

#include <cstdio>
#include <cstring>
#include <vector>
#include "../Milenage.h"
#include "../FiveGAka.h"
#include "../CredentialEnvelope.h"

static int failures = 0;

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = h[b[i]>>4]; out[2*i+1] = h[b[i]&0xf]; }
    out[2*n] = 0;
}

#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } else { printf("PASS: %s\n", msg); } } while (0)

static void fromhex(const char *s, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v; sscanf(s + 2*i, "%2x", &v); out[i] = (uint8_t)v;
    }
}

int main() {
    using namespace milenage;

    // 3GPP TS 35.207 published Test Set 1 vectors.
    uint8_t k[16], rand_[16], sqn[6], amf[2], op[16], opc_expected[16];
    fromhex("465b5ce8b199b49faa5f0a2ee238a6bc", k, 16);
    fromhex("23553cbe9637a89d218ae64dae47bf35", rand_, 16);
    fromhex("ff9bb4d0b607", sqn, 6);
    fromhex("b9b9", amf, 2);
    fromhex("cdc202d5123e20f62b6d676ac72cb318", op, 16);
    fromhex("cd63cb71954a9f4e48a5994e37a02baf", opc_expected, 16);

    uint8_t opc[16];
    CHECK(deriveOpc(k, op, opc), "deriveOpc executes");
    char opcHex[33]; hex(opc, 16, opcHex);
    printf("  computed OPc = %s\n", opcHex);
    CHECK(std::memcmp(opc, opc_expected, 16) == 0, "OPc matches TS 35.207 Test Set 1");

    uint8_t macA[8];
    CHECK(f1(k, opc, rand_, sqn, amf, macA), "f1 executes");
    char macAHex[17]; hex(macA, 8, macAHex);
    printf("  computed MAC-A = %s (expected 4a9ffac354dfafb3)\n", macAHex);
    uint8_t macAExpected[8]; fromhex("4a9ffac354dfafb3", macAExpected, 8);
    CHECK(std::memcmp(macA, macAExpected, 8) == 0, "f1 MAC-A matches TS 35.207 Test Set 1");

    uint8_t res[8], ck[16], ikk[16], ak[6];
    CHECK(f2345(k, opc, rand_, res, ck, ikk, ak), "f2345 executes");
    char resHex[17]; hex(res, 8, resHex);
    char ckHex[33]; hex(ck, 16, ckHex);
    char ikHex[33]; hex(ikk, 16, ikHex);
    char akHex[13]; hex(ak, 6, akHex);
    printf("  computed RES=%s (expected a54211d5e3ba50bf)\n", resHex);
    printf("  computed CK=%s (not asserted: no verified external vector available this session)\n", ckHex);
    printf("  computed IK=%s (not asserted: no verified external vector available this session)\n", ikHex);
    printf("  computed AK=%s (expected aa689c648370)\n", akHex);
    uint8_t resExpected[8]; fromhex("a54211d5e3ba50bf", resExpected, 8);
    CHECK(std::memcmp(res, resExpected, 8) == 0, "f2 RES matches TS 35.207 Test Set 1");
    uint8_t akExpected[6]; fromhex("aa689c648370", akExpected, 6);
    CHECK(std::memcmp(ak, akExpected, 6) == 0, "f5 AK matches TS 35.207 Test Set 1");

    // AUTN build + round trip self-consistency (not an external vector).
    uint8_t autn[16];
    CHECK(buildAutn(sqn, ak, amf, macA, autn), "buildAutn executes");

    // Resync round trip: build AUTS the same way a USIM would (using
    // AK*/MAC-S with AMF=0), then verify it recovers SQN_MS and matches.
    uint8_t akStar[6];
    CHECK(f5Star(k, opc, rand_, akStar), "f5Star executes");
    uint8_t amfZero[2] = {0,0};
    uint8_t macS[8];
    CHECK(f1Star(k, opc, rand_, sqn, amfZero, macS), "f1Star executes");
    uint8_t auts[14];
    for (int i = 0; i < 6; i++) auts[i] = sqn[i] ^ akStar[i];
    std::memcpy(auts + 6, macS, 8);

    uint8_t sqnMsOut[6];
    bool verifyOk = verifyAuts(k, opc, rand_, auts, sqnMsOut);
    CHECK(verifyOk, "verifyAuts accepts a validly constructed AUTS");
    CHECK(std::memcmp(sqnMsOut, sqn, 6) == 0, "verifyAuts recovers correct SQN_MS");

    // Tamper AUTS -> must fail.
    uint8_t autsBad[14];
    std::memcpy(autsBad, auts, 14);
    autsBad[13] ^= 0x01;
    uint8_t dummy[6];
    CHECK(!verifyAuts(k, opc, rand_, autsBad, dummy), "verifyAuts rejects tampered MAC-S");

    // 5G-AKA KDFs: determinism + sensitivity self-consistency checks
    // (no published external KAT used here — TS 33.501 Annex A test
    // vectors were not available to verify against in this session).
    uint8_t snn[] = "5G:mnc001.mcc001.3gppnetwork.org";
    size_t snnLen = sizeof(snn) - 1;
    uint8_t xres1[16], xres2[16];
    CHECK(fiveg_aka::deriveXresStar(ck, ikk, rand_, res, snn, snnLen, xres1), "deriveXresStar executes");
    CHECK(fiveg_aka::deriveXresStar(ck, ikk, rand_, res, snn, snnLen, xres2), "deriveXresStar deterministic");
    CHECK(std::memcmp(xres1, xres2, 16) == 0, "deriveXresStar repeatable for same input");

    uint8_t sqnXorAk[6];
    for (int i = 0; i < 6; i++) sqnXorAk[i] = sqn[i] ^ ak[i];
    uint8_t kausf1[32], kausf2[32];
    CHECK(fiveg_aka::deriveKausf(ck, ikk, sqnXorAk, snn, snnLen, kausf1), "deriveKausf executes");
    CHECK(fiveg_aka::deriveKausf(ck, ikk, sqnXorAk, snn, snnLen, kausf2), "deriveKausf deterministic");
    CHECK(std::memcmp(kausf1, kausf2, 32) == 0, "deriveKausf repeatable for same input");
    CHECK(std::memcmp(kausf1, xres1, 16) != 0, "KAUSF differs from XRES* (distinct FC domain separation)");

    // Envelope wrap/unwrap round trip + tamper/binding rejection tests.
    using namespace milenage_envelope;
    uint8_t masterKey[32];
    for (int i = 0; i < 32; i++) masterKey[i] = (uint8_t)(i * 7 + 1);

    std::string supiA = "imsi-001010123456789";
    std::string supiB = "imsi-001010999999999";
    uint8_t secretK[16]; std::memcpy(secretK, k, 16);
    uint8_t secretOpc[16]; std::memcpy(secretOpc, opc, 16);

    std::vector<uint8_t> wrappedK, wrappedOpc;
    CHECK(wrapSecret(supiA, SecretType::K, secretK, masterKey, wrappedK) == Error::OK, "wrapSecret(K) succeeds");
    CHECK(wrapSecret(supiA, SecretType::OPC, secretOpc, masterKey, wrappedOpc) == Error::OK, "wrapSecret(OPc) succeeds");

    uint8_t unwrappedK[16], unwrappedOpc[16];
    CHECK(unwrapSecret(supiA, SecretType::K, wrappedK, masterKey, unwrappedK) == Error::OK, "unwrapSecret(K) succeeds for correct SUPI");
    CHECK(std::memcmp(unwrappedK, secretK, 16) == 0, "unwrapped K matches original");
    CHECK(unwrapSecret(supiA, SecretType::OPC, wrappedOpc, masterKey, unwrappedOpc) == Error::OK, "unwrapSecret(OPc) succeeds for correct SUPI");
    CHECK(std::memcmp(unwrappedOpc, secretOpc, 16) == 0, "unwrapped OPc matches original");

    uint8_t dummySecret[16];
    CHECK(unwrapSecret(supiB, SecretType::K, wrappedK, masterKey, dummySecret) != Error::OK, "unwrapSecret rejects wrong SUPI binding");
    CHECK(unwrapSecret(supiA, SecretType::OPC, wrappedK, masterKey, dummySecret) != Error::OK, "unwrapSecret rejects swapped K blob claimed as OPc");
    CHECK(unwrapSecret(supiA, SecretType::K, wrappedOpc, masterKey, dummySecret) != Error::OK, "unwrapSecret rejects swapped OPc blob claimed as K");

    std::vector<uint8_t> tampered = wrappedK;
    tampered[tampered.size() - 1] ^= 0x01;
    CHECK(unwrapSecret(supiA, SecretType::K, tampered, masterKey, dummySecret) != Error::OK, "unwrapSecret rejects tampered ciphertext");

    std::vector<uint8_t> truncated(wrappedK.begin(), wrappedK.begin() + wrappedK.size() / 2);
    CHECK(unwrapSecret(supiA, SecretType::K, truncated, masterKey, dummySecret) != Error::OK, "unwrapSecret rejects truncated ciphertext");

    uint8_t wrongMasterKey[32];
    std::memcpy(wrongMasterKey, masterKey, 32);
    wrongMasterKey[0] ^= 0xFF;
    CHECK(unwrapSecret(supiA, SecretType::K, wrappedK, wrongMasterKey, dummySecret) != Error::OK, "unwrapSecret rejects wrong master key");

    CHECK(isCanonicalSupi("imsi-001010123456789"), "isCanonicalSupi accepts valid SUPI");
    CHECK(!isCanonicalSupi("imsi-abc"), "isCanonicalSupi rejects non-digit SUPI");
    CHECK(!isCanonicalSupi("001010123456789"), "isCanonicalSupi rejects missing prefix");
    CHECK(!isCanonicalSupi("imsi-123"), "isCanonicalSupi rejects too-short SUPI");

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
