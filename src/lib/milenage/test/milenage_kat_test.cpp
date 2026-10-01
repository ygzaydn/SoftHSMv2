/*
 * Known-answer tests for the Milenage / 5G-AKA primitives, integrated
 * into the project's CTest run (see src/lib/milenage/test/CMakeLists.txt).
 * Built only when WITH_MILENAGE is on; not gated on BUILD_TESTS/CppUnit
 * because this environment has no CppUnit available (no root to
 * install libcppunit-dev) -- see doc/MILENAGE-5G-AKA-DESIGN.md
 * section 17 for that limitation. This file uses a plain
 * assert-and-count-failures harness and a non-zero exit code on
 * failure, which `ctest` treats as a normal test failure.
 *
 * Vector sources (exact citations; nothing here was generated from
 * the implementation under test):
 *
 * 1. Milenage Test Set 1 and Test Set 2 (K, RAND, SQN, AMF, OP, OPc,
 *    f1/MAC-A, f1*\/MAC-S, f2/RES, f3/CK, f4/IK, f5/AK, f5*\/AK*):
 *    3GPP TS 35.207 "3G Security; Specification of the MILENAGE
 *    algorithm set: ... Document 3: Implementors' test data".
 *    Primary source (ETSI TS 135 207 V17.0.0 PDF,
 *    https://www.etsi.org/deliver/etsi_ts/135200_135299/135207/17.00.00_60/ts_135207v170000p.pdf)
 *    returned HTTP 403 to automated fetch in this session. The values
 *    below were instead taken from the open-source reference
 *    implementation CryptoMobile (https://github.com/mitshell/CryptoMobile,
 *    file test/test_Milenage.py, functions milenage_testset_1() and
 *    milenage_testset_2()), which states in its own documentation
 *    that these are the 3GPP TS 35.207 test vectors. Four of the
 *    eight Test Set 1 fields (OPc, MAC-A, RES, AK) were independently
 *    cross-checked against values recalled directly from 3GPP TS
 *    35.207 in an earlier session before this file existed and match
 *    exactly, which is strong corroborating evidence for the other
 *    four fields (MAC-S, CK, IK, AK*) sourced the same way. This
 *    should still be replaced with values transcribed directly from
 *    an official ETSI/3GPP PDF or a purchased/mirrored copy when one
 *    is reachable from a build environment with outbound access to
 *    etsi.org.
 *
 * 2. RFC 5649 AES-KWP: both worked examples from RFC 5649 section 6
 *    ("Key Wrap with Padding Examples"), https://www.rfc-editor.org/rfc/rfc5649,
 *    fetched directly from rfc-editor.org in this session.
 *
 * 3. 5G-AKA XRES-star / KAUSF: 3GPP TS 33.501 Annex A does not publish a
 *    worked numeric example (it gives only the FC/P/L construction
 *    rules), and none was found from an independent authoritative
 *    source in this session. The XRES-star / KAUSF checks below are
 *    therefore an INDEPENDENT CROSS-CHECK, not an official KAT: a
 *    second, separate implementation of the same TS 33.220 Annex B
 *    generic KDF construction is written directly in this test file
 *    using OpenSSL EVP HMAC (deliberately not calling into
 *    src/lib/milenage/CryptoBackend.cpp, so it does not share any code
 *    path with the implementation under test), and its output is
 *    compared against fiveg_aka::deriveXresStar/deriveKausf for the
 *    same CK/IK/RAND/RES/SNN/SQN-xor-AK inputs from Milenage Test Set 1.
 *    Agreement between two independent implementations of the same
 *    published construction is evidence of internal consistency, not
 *    proof of conformance to an official 3GPP-published number.
 */

#include <cstdio>
#include <cstring>
#include <vector>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "../Milenage.h"
#include "../FiveGAka.h"
#include "../CredentialEnvelope.h"
#include "../CryptoBackend.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } else { printf("PASS: %s\n", msg); } } while (0)

static void fromhex(const char *s, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(s + 2*i, "%2x", &v); out[i] = (uint8_t)v; }
}
static void hex(const uint8_t *b, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = h[b[i]>>4]; out[2*i+1] = h[b[i]&0xf]; }
    out[2*n] = 0;
}

struct MilenageTestSet {
    const char *name;
    const char *k, *rand_, *sqn, *amf, *op;
    const char *opc, *maca, *macs, *res, *ck, *ik, *ak, *akstar;
};

/* 3GPP TS 35.207 Test Set 1 and 2 -- see file header for exact sourcing. */
static const MilenageTestSet kMilenageSets[] = {
    {
        "TS 35.207 Test Set 1",
        "465b5ce8b199b49faa5f0a2ee238a6bc", "23553cbe9637a89d218ae64dae47bf35",
        "ff9bb4d0b607", "b9b9", "cdc202d5123e20f62b6d676ac72cb318",
        "cd63cb71954a9f4e48a5994e37a02baf", "4a9ffac354dfafb3", "01cfaf9ec4e871e9",
        "a54211d5e3ba50bf", "b40ba9a3c58b2a05bbf0d987b21bf8cb",
        "f769bcd751044604127672711c6d3441", "aa689c648370", "451e8beca43b",
    },
    {
        "TS 35.207 Test Set 2",
        "0396eb317b6d1c36f19c1c84cd6ffd16", "c00d603103dcee52c4478119494202e8",
        "fd8eef40df7d", "af17", "ff53bade17df5d4e793073ce9d7579fa",
        "53c15671c60a4b731c55b4a441c0bde2", "5df5b31807e258b0", "a8c016e51ef4a343",
        "d3a628ed988620f0", "58c433ff7a7082acd424220f2b67c556",
        "21a8c1f929702adb3e738488b9f5c5da", "c47783995f72", "30f1197061c1",
    },
};

static void runMilenageTestSet(const MilenageTestSet &t)
{
    using namespace milenage;
    uint8_t k[16], rand_[16], sqn[6], amf[2], op[16];
    fromhex(t.k, k, 16); fromhex(t.rand_, rand_, 16); fromhex(t.sqn, sqn, 6);
    fromhex(t.amf, amf, 2); fromhex(t.op, op, 16);

    uint8_t expOpc[16], expMacA[8], expMacS[8], expRes[8], expCk[16], expIk[16], expAk[6], expAkStar[6];
    fromhex(t.opc, expOpc, 16); fromhex(t.maca, expMacA, 8); fromhex(t.macs, expMacS, 8);
    fromhex(t.res, expRes, 8); fromhex(t.ck, expCk, 16); fromhex(t.ik, expIk, 16);
    fromhex(t.ak, expAk, 6); fromhex(t.akstar, expAkStar, 6);

    char label[128];

    uint8_t opc[16];
    deriveOpc(k, op, opc);
    snprintf(label, sizeof(label), "%s: OPc matches official vector", t.name);
    CHECK(std::memcmp(opc, expOpc, 16) == 0, label);

    uint8_t macA[8];
    f1(k, opc, rand_, sqn, amf, macA);
    snprintf(label, sizeof(label), "%s: f1 (MAC-A) matches official vector", t.name);
    CHECK(std::memcmp(macA, expMacA, 8) == 0, label);

    uint8_t macS[8];
    f1Star(k, opc, rand_, sqn, amf, macS);
    snprintf(label, sizeof(label), "%s: f1* (MAC-S, AMF as given) matches official vector", t.name);
    CHECK(std::memcmp(macS, expMacS, 8) == 0, label);

    uint8_t res[8], ck[16], ik[16], ak[6];
    f2345(k, opc, rand_, res, ck, ik, ak);
    snprintf(label, sizeof(label), "%s: f2 (RES) matches official vector", t.name);
    CHECK(std::memcmp(res, expRes, 8) == 0, label);
    snprintf(label, sizeof(label), "%s: f3 (CK) matches official vector", t.name);
    CHECK(std::memcmp(ck, expCk, 16) == 0, label);
    snprintf(label, sizeof(label), "%s: f4 (IK) matches official vector", t.name);
    CHECK(std::memcmp(ik, expIk, 16) == 0, label);
    snprintf(label, sizeof(label), "%s: f5 (AK) matches official vector", t.name);
    CHECK(std::memcmp(ak, expAk, 6) == 0, label);

    uint8_t akStar[6];
    f5Star(k, opc, rand_, akStar);
    snprintf(label, sizeof(label), "%s: f5* (AK*) matches official vector", t.name);
    CHECK(std::memcmp(akStar, expAkStar, 6) == 0, label);
}

/* RFC 5649 section 6 examples. Both use a 192-bit (24-byte) KEK, so
 * they exercise milenage_crypto::aesKwpWrap/aesKwpUnwrap directly at
 * a key size the production envelope code never uses (which is always
 * 256-bit) -- this validates the underlying AES-KWP primitive
 * SoftHSM's CryptoFactory backend provides, independent of the
 * envelope-specific 58-byte plaintext framing in CredentialEnvelope. */
static void runRfc5649Tests()
{
    uint8_t kek[24];
    fromhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", kek, 24);

    {
        uint8_t pt[20];
        fromhex("c37b7e6492584340bed12207808941155068f738", pt, 20);
        uint8_t expCt[32];
        fromhex("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a", expCt, 32);

        std::vector<uint8_t> ct;
        bool wrapOk = milenage_crypto::aesKwpWrap(kek, 24, pt, 20, ct);
        CHECK(wrapOk, "RFC 5649 example 1: AES-KWP wrap executes");
        CHECK(ct.size() == 32 && std::memcmp(ct.data(), expCt, 32) == 0,
              "RFC 5649 example 1 (20-byte key, 192-bit KEK): ciphertext matches RFC");

        std::vector<uint8_t> recovered;
        bool unwrapOk = milenage_crypto::aesKwpUnwrap(kek, 24, expCt, 32, recovered);
        CHECK(unwrapOk && recovered.size() == 20 && std::memcmp(recovered.data(), pt, 20) == 0,
              "RFC 5649 example 1: unwrap of the official ciphertext recovers the official plaintext");
    }
    {
        uint8_t pt[7];
        fromhex("466f7250617369", pt, 7);
        uint8_t expCt[16];
        fromhex("afbeb0f07dfbf5419200f2ccb50bb24f", expCt, 16);

        std::vector<uint8_t> ct;
        bool wrapOk = milenage_crypto::aesKwpWrap(kek, 24, pt, 7, ct);
        CHECK(wrapOk, "RFC 5649 example 2: AES-KWP wrap executes");
        CHECK(ct.size() == 16 && std::memcmp(ct.data(), expCt, 16) == 0,
              "RFC 5649 example 2 (7-byte key, 192-bit KEK): ciphertext matches RFC");

        std::vector<uint8_t> recovered;
        bool unwrapOk = milenage_crypto::aesKwpUnwrap(kek, 24, expCt, 16, recovered);
        CHECK(unwrapOk && recovered.size() == 7 && std::memcmp(recovered.data(), pt, 7) == 0,
              "RFC 5649 example 2: unwrap of the official ciphertext recovers the official plaintext");
    }
}

namespace independent_kdf {
/* A second, independent implementation of the TS 33.220 Annex B
 * generic KDF (HMAC-SHA-256 over FC || P0 || L0 || P1 || L1 || ...),
 * written directly against OpenSSL EVP HMAC in this test file only.
 * Deliberately does NOT call milenage_crypto:: or fiveg_aka:: so this
 * has no shared code path with the implementation under test -- see
 * the file header for why this is a cross-check, not an official KAT. */
static void appendParam(std::vector<uint8_t> &s, const uint8_t *p, size_t len) {
    s.insert(s.end(), p, p + len);
    s.push_back((uint8_t)((len >> 8) & 0xFF));
    s.push_back((uint8_t)(len & 0xFF));
}
static void kdf(const uint8_t *key, size_t keyLen, const std::vector<uint8_t> &s, uint8_t out32[32]) {
    unsigned int outLen = 0;
    HMAC(EVP_sha256(), key, (int)keyLen, s.data(), s.size(), out32, &outLen);
}
static void xresStar(const uint8_t ck[16], const uint8_t ik[16], const uint8_t rand_[16],
                      const uint8_t res[8], const uint8_t *snn, size_t snnLen, uint8_t out[16]) {
    uint8_t key[32]; std::memcpy(key, ck, 16); std::memcpy(key + 16, ik, 16);
    std::vector<uint8_t> s; s.push_back(0x6B);
    appendParam(s, snn, snnLen); appendParam(s, rand_, 16); appendParam(s, res, 8);
    uint8_t full[32]; kdf(key, 32, s, full);
    std::memcpy(out, full + 16, 16);
}
static void kausf(const uint8_t ck[16], const uint8_t ik[16], const uint8_t sqnXorAk[6],
                   const uint8_t *snn, size_t snnLen, uint8_t out[32]) {
    uint8_t key[32]; std::memcpy(key, ck, 16); std::memcpy(key + 16, ik, 16);
    std::vector<uint8_t> s; s.push_back(0x6A);
    appendParam(s, snn, snnLen); appendParam(s, sqnXorAk, 6);
    kdf(key, 32, s, out);
}
} // namespace independent_kdf

static void run5gAkaCrossCheck()
{
    using namespace milenage;
    /* Reuse TS 35.207 Test Set 1's official CK/IK/RES/RAND/SQN/AK as
     * the KDF's inputs -- the inputs are official Milenage values,
     * only the XRES-star / KAUSF construction on top of them is
     * cross-checked rather than KAT-verified. */
    uint8_t k[16], rand_[16], sqn[6], amf[2], op[16], opc[16];
    fromhex("465b5ce8b199b49faa5f0a2ee238a6bc", k, 16);
    fromhex("23553cbe9637a89d218ae64dae47bf35", rand_, 16);
    fromhex("ff9bb4d0b607", sqn, 6);
    fromhex("b9b9", amf, 2);
    fromhex("cdc202d5123e20f62b6d676ac72cb318", op, 16);
    deriveOpc(k, op, opc);

    uint8_t res[8], ck[16], ik[16], ak[6];
    f2345(k, opc, rand_, res, ck, ik, ak);

    uint8_t snn[] = "5G:mnc001.mcc001.3gppnetwork.org";
    size_t snnLen = sizeof(snn) - 1;

    uint8_t xresA[16], xresB[16];
    fiveg_aka::deriveXresStar(ck, ik, rand_, res, snn, snnLen, xresA);
    independent_kdf::xresStar(ck, ik, rand_, res, snn, snnLen, xresB);
    CHECK(std::memcmp(xresA, xresB, 16) == 0,
          "XRES* independent cross-check: production and standalone OpenSSL-EVP KDF implementations agree (NOT an official 3GPP-published KAT)");

    uint8_t sqnXorAk[6];
    for (int i = 0; i < 6; i++) sqnXorAk[i] = sqn[i] ^ ak[i];
    uint8_t kausfA[32], kausfB[32];
    fiveg_aka::deriveKausf(ck, ik, sqnXorAk, snn, snnLen, kausfA);
    independent_kdf::kausf(ck, ik, sqnXorAk, snn, snnLen, kausfB);
    CHECK(std::memcmp(kausfA, kausfB, 32) == 0,
          "KAUSF independent cross-check: production and standalone OpenSSL-EVP KDF implementations agree (NOT an official 3GPP-published KAT)");
}

/* Full 5G HE AV assembly using Test Set 1: exercises AUTN build and
 * the AUTS resync round trip end to end using only official Milenage
 * values as the base inputs. RAND is the official Test Set 1 RAND
 * here (used as a fixed AV RAND for reproducibility in this test, not
 * a claim that the production RNG path is exercised -- that is
 * covered separately by the PKCS#11 E2E test, which does draw RAND
 * from SoftHSM's RNG). */
static void runFullAvAndResync()
{
    using namespace milenage;
    uint8_t k[16], rand_[16], sqn[6], amf[2], op[16], opc[16];
    fromhex("465b5ce8b199b49faa5f0a2ee238a6bc", k, 16);
    fromhex("23553cbe9637a89d218ae64dae47bf35", rand_, 16);
    fromhex("ff9bb4d0b607", sqn, 6);
    fromhex("b9b9", amf, 2);
    fromhex("cdc202d5123e20f62b6d676ac72cb318", op, 16);
    deriveOpc(k, op, opc);

    uint8_t macA[8], res[8], ck[16], ik[16], ak[6];
    f1(k, opc, rand_, sqn, amf, macA);
    f2345(k, opc, rand_, res, ck, ik, ak);

    uint8_t autn[16];
    buildAutn(sqn, ak, amf, macA, autn);
    uint8_t expectedAutnPrefix[6]; /* SQN xor AK */
    for (int i = 0; i < 6; i++) expectedAutnPrefix[i] = sqn[i] ^ ak[i];
    CHECK(std::memcmp(autn, expectedAutnPrefix, 6) == 0, "AUTN: SQN xor AK field matches direct computation");
    CHECK(std::memcmp(autn + 6, amf, 2) == 0, "AUTN: AMF field placed correctly");
    CHECK(std::memcmp(autn + 8, macA, 8) == 0, "AUTN: MAC-A field placed correctly");

    uint8_t akStar[6], macS[8];
    const uint8_t amfZero[2] = {0, 0};
    f5Star(k, opc, rand_, akStar);
    f1Star(k, opc, rand_, sqn, amfZero, macS);
    uint8_t auts[14];
    for (int i = 0; i < 6; i++) auts[i] = sqn[i] ^ akStar[i];
    std::memcpy(auts + 6, macS, 8);

    uint8_t sqnMs[6];
    bool ok = verifyAuts(k, opc, rand_, auts, sqnMs);
    CHECK(ok, "Full AV / resync round trip: verifyAuts accepts an AUTS built from official Test Set 1 K/OPc");
    CHECK(std::memcmp(sqnMs, sqn, 6) == 0, "Full AV / resync round trip: recovered SQN_MS matches official Test Set 1 SQN");
}

int main()
{
    for (const auto &t : kMilenageSets) {
        runMilenageTestSet(t);
    }
    runRfc5649Tests();
    run5gAkaCrossCheck();
    runFullAvAndResync();

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
