/*
 * Standalone test for WireCodec + MilenageService, exercising the
 * three vendor operations (provision, 5G HE AV, resync) end to end
 * over the wire format, plus wire-parser rejection tests. Not wired
 * into any build system yet -- see doc/MILENAGE-5G-AKA-DESIGN.md
 * section 17. Build command mirrors standalone_selftest.cpp:
 *
 *   g++ -std=c++17 -Wall -Wextra -I.. -I../../pkcs11 \
 *       service_selftest.cpp ../WireCodec.cpp ../MilenageService.cpp \
 *       ../Milenage.cpp ../FiveGAka.cpp ../CredentialEnvelope.cpp \
 *       -lcrypto -o /tmp/milenage_service_selftest
 */

#include <cstdio>
#include <cstring>
#include <vector>
#include "../WireCodec.h"
#include "../MilenageService.h"
#include "../softhsm_milenage.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } else { printf("PASS: %s\n", msg); } } while (0)

static void appendTlv(std::vector<uint8_t> &v, uint16_t tag, const std::vector<uint8_t> &val)
{
    v.push_back((tag >> 8) & 0xFF); v.push_back(tag & 0xFF);
    uint32_t len = (uint32_t)val.size();
    v.push_back((len >> 24) & 0xFF); v.push_back((len >> 16) & 0xFF);
    v.push_back((len >> 8) & 0xFF); v.push_back(len & 0xFF);
    v.insert(v.end(), val.begin(), val.end());
}

static std::vector<uint8_t> buildRequest(uint8_t op, const std::vector<std::pair<uint16_t, std::vector<uint8_t>>> &fields)
{
    std::vector<uint8_t> body;
    for (auto &f : fields) appendTlv(body, f.first, f.second);

    std::vector<uint8_t> out;
    out.insert(out.end(), SOFTHSM_MILENAGE_WIRE_MAGIC, SOFTHSM_MILENAGE_WIRE_MAGIC + 4);
    out.push_back(SOFTHSM_MILENAGE_WIRE_VERSION);
    out.push_back(op);
    out.push_back(0); out.push_back(0);
    uint32_t total = (uint32_t)(out.size() + 4 + body.size());
    out.push_back((total >> 24) & 0xFF); out.push_back((total >> 16) & 0xFF);
    out.push_back((total >> 8) & 0xFF); out.push_back(total & 0xFF);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

static std::vector<uint8_t> str2v(const std::string &s) { return std::vector<uint8_t>(s.begin(), s.end()); }

int main()
{
    uint8_t masterKey[32];
    for (int i = 0; i < 32; i++) masterKey[i] = (uint8_t)(i * 3 + 5);

    std::string supi = "imsi-001010123456789";
    uint8_t plainK[16] = {0x46,0x5b,0x5c,0xe8,0xb1,0x99,0xb4,0x9f,0xaa,0x5f,0x0a,0x2e,0xe2,0x38,0xa6,0xbc};
    uint8_t plainOpc[16] = {0xcd,0x63,0xcb,0x71,0x95,0x4a,0x9f,0x4e,0x48,0xa5,0x99,0x4e,0x37,0xa0,0x2b,0xaf};

    // --- Provision ---
    auto provReq = buildRequest(SOFTHSM_MILENAGE_OP_PROVISION, {
        {SOFTHSM_MILENAGE_TAG_SUPI, str2v(supi)},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_K, std::vector<uint8_t>(plainK, plainK + 16)},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC, std::vector<uint8_t>(plainOpc, plainOpc + 16)},
    });
    std::vector<uint8_t> provResp;
    auto provErr = milenage_service::provision(provReq.data(), provReq.size(), masterKey, provResp);
    CHECK(provErr == milenage_service::Error::OK, "provision succeeds");

    milenage_wire::Request parsedProvResp;
    CHECK(milenage_wire::parseRequest(provResp.data(), provResp.size(), parsedProvResp) == milenage_wire::Error::OK,
          "provision response parses as valid wire message");
    std::vector<uint8_t> wrappedK = parsedProvResp.fields[SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K];
    std::vector<uint8_t> wrappedOpc = parsedProvResp.fields[SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC];
    CHECK(!wrappedK.empty() && !wrappedOpc.empty(), "provision response contains wrapped K and OPc");

    // --- 5G HE AV ---
    uint8_t sqn[6] = {0xff,0x9b,0xb4,0xd0,0xb6,0x07};
    uint8_t amf[2] = {0xb9,0xb9};
    std::string snn = "5G:mnc001.mcc001.3gppnetwork.org";
    auto avReq = buildRequest(SOFTHSM_MILENAGE_OP_5G_HE_AV, {
        {SOFTHSM_MILENAGE_TAG_SUPI, str2v(supi)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_SQN, std::vector<uint8_t>(sqn, sqn + 6)},
        {SOFTHSM_MILENAGE_TAG_AMF, std::vector<uint8_t>(amf, amf + 2)},
        {SOFTHSM_MILENAGE_TAG_SNN, str2v(snn)},
    });
    std::vector<uint8_t> avResp;
    auto avErr = milenage_service::generate5gHeAv(avReq.data(), avReq.size(), masterKey, avResp);
    CHECK(avErr == milenage_service::Error::OK, "generate5gHeAv succeeds with correctly wrapped credentials");

    milenage_wire::Request parsedAv;
    CHECK(milenage_wire::parseRequest(avResp.data(), avResp.size(), parsedAv) == milenage_wire::Error::OK,
          "AV response parses as valid wire message");
    CHECK(parsedAv.fields[SOFTHSM_MILENAGE_TAG_OUT_RAND].size() == 16, "AV response RAND is 16 bytes");
    CHECK(parsedAv.fields[SOFTHSM_MILENAGE_TAG_OUT_AUTN].size() == 16, "AV response AUTN is 16 bytes");
    CHECK(parsedAv.fields[SOFTHSM_MILENAGE_TAG_OUT_XRES_STAR].size() == 16, "AV response XRES* is 16 bytes");
    CHECK(parsedAv.fields[SOFTHSM_MILENAGE_TAG_OUT_KAUSF].size() == 32, "AV response KAUSF is 32 bytes");
    CHECK(parsedAv.fields.count(SOFTHSM_MILENAGE_TAG_OUT_RAND) &&
          parsedAv.fields.find(0x0002) == parsedAv.fields.end() /* no OUT_RES-like leak: only defined tags present */,
          "AV response contains no unexpected tags");
    CHECK(parsedAv.fields.size() == 4, "AV response contains exactly RAND, AUTN, XRES*, KAUSF (never RES/CK/IK/AK)");

    // Wrong SUPI must be rejected (cross-subscriber binding).
    auto avReqWrongSupi = buildRequest(SOFTHSM_MILENAGE_OP_5G_HE_AV, {
        {SOFTHSM_MILENAGE_TAG_SUPI, str2v("imsi-999999999999999")},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_SQN, std::vector<uint8_t>(sqn, sqn + 6)},
        {SOFTHSM_MILENAGE_TAG_AMF, std::vector<uint8_t>(amf, amf + 2)},
        {SOFTHSM_MILENAGE_TAG_SNN, str2v(snn)},
    });
    std::vector<uint8_t> respTmp;
    CHECK(milenage_service::generate5gHeAv(avReqWrongSupi.data(), avReqWrongSupi.size(), masterKey, respTmp) ==
          milenage_service::Error::CREDENTIAL_INVALID, "generate5gHeAv rejects wrong SUPI binding");

    // Repeated call must yield a fresh RAND (RNG actually used, not fixed).
    std::vector<uint8_t> avResp2;
    milenage_service::generate5gHeAv(avReq.data(), avReq.size(), masterKey, avResp2);
    milenage_wire::Request parsedAv2;
    milenage_wire::parseRequest(avResp2.data(), avResp2.size(), parsedAv2);
    CHECK(parsedAv.fields[SOFTHSM_MILENAGE_TAG_OUT_RAND] != parsedAv2.fields[SOFTHSM_MILENAGE_TAG_OUT_RAND],
          "generate5gHeAv produces a fresh RAND on each call");

    // Deterministic AV with a caller-supplied RAND (design-doc test-mode path).
    uint8_t fixedRand[16]; for (int i=0;i<16;i++) fixedRand[i] = (uint8_t)i;
    std::vector<uint8_t> avRespFixedA, avRespFixedB;
    milenage_service::generate5gHeAv(avReq.data(), avReq.size(), masterKey, avRespFixedA, fixedRand);
    milenage_service::generate5gHeAv(avReq.data(), avReq.size(), masterKey, avRespFixedB, fixedRand);
    CHECK(avRespFixedA == avRespFixedB, "generate5gHeAv with fixed testRand is fully deterministic");

    // --- Resync ---
    // Build a valid AUTS the same way MilenageService derived AK*/MAC-S,
    // by round-tripping through the low-level primitives directly is
    // out of scope here (covered in standalone_selftest.cpp); here we
    // just check malformed/garbage AUTS is rejected end to end.
    uint8_t randFixed[16]; for (int i=0;i<16;i++) randFixed[i] = (uint8_t)(0x10+i);
    uint8_t garbageAuts[14]; for (int i=0;i<14;i++) garbageAuts[i] = (uint8_t)(0xAA ^ i);
    auto resyncReq = buildRequest(SOFTHSM_MILENAGE_OP_RESYNC, {
        {SOFTHSM_MILENAGE_TAG_SUPI, str2v(supi)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_RAND, std::vector<uint8_t>(randFixed, randFixed + 16)},
        {SOFTHSM_MILENAGE_TAG_AUTS, std::vector<uint8_t>(garbageAuts, garbageAuts + 14)},
    });
    std::vector<uint8_t> resyncResp;
    CHECK(milenage_service::resync(resyncReq.data(), resyncReq.size(), masterKey, resyncResp) ==
          milenage_service::Error::SIGNATURE_INVALID, "resync rejects an invalid MAC-S with SIGNATURE_INVALID");
    CHECK(resyncResp.empty(), "resync does not populate a response buffer on MAC-S failure");

    // --- Wire codec structural rejection tests ---
    std::vector<uint8_t> req1 = avReq;
    req1[0] = 'X'; // corrupt magic
    milenage_wire::Request parsed1;
    CHECK(milenage_wire::parseRequest(req1.data(), req1.size(), parsed1) == milenage_wire::Error::BAD_MAGIC,
          "wire parser rejects bad magic");

    std::vector<uint8_t> req2 = avReq;
    req2.resize(req2.size() - 3); // truncate mid-TLV
    milenage_wire::Request parsed2;
    auto e2 = milenage_wire::parseRequest(req2.data(), req2.size(), parsed2);
    CHECK(e2 == milenage_wire::Error::TRUNCATED || e2 == milenage_wire::Error::LENGTH_MISMATCH,
          "wire parser rejects truncated request");

    // Duplicate mandatory tag.
    std::vector<uint8_t> dupBody;
    appendTlv(dupBody, SOFTHSM_MILENAGE_TAG_SUPI, str2v(supi));
    appendTlv(dupBody, SOFTHSM_MILENAGE_TAG_SUPI, str2v(supi));
    std::vector<uint8_t> dupReq;
    dupReq.insert(dupReq.end(), SOFTHSM_MILENAGE_WIRE_MAGIC, SOFTHSM_MILENAGE_WIRE_MAGIC + 4);
    dupReq.push_back(SOFTHSM_MILENAGE_WIRE_VERSION);
    dupReq.push_back(SOFTHSM_MILENAGE_OP_5G_HE_AV);
    dupReq.push_back(0); dupReq.push_back(0);
    uint32_t dupTotal = (uint32_t)(dupReq.size() + 4 + dupBody.size());
    dupReq.push_back((dupTotal>>24)&0xFF); dupReq.push_back((dupTotal>>16)&0xFF);
    dupReq.push_back((dupTotal>>8)&0xFF); dupReq.push_back(dupTotal&0xFF);
    dupReq.insert(dupReq.end(), dupBody.begin(), dupBody.end());
    milenage_wire::Request parsedDup;
    CHECK(milenage_wire::parseRequest(dupReq.data(), dupReq.size(), parsedDup) == milenage_wire::Error::DUPLICATE_TAG,
          "wire parser rejects duplicate mandatory tag");

    // Unknown critical tag.
    std::vector<uint8_t> unkBody;
    appendTlv(unkBody, 0x7777, str2v("x"));
    std::vector<uint8_t> unkReq;
    unkReq.insert(unkReq.end(), SOFTHSM_MILENAGE_WIRE_MAGIC, SOFTHSM_MILENAGE_WIRE_MAGIC + 4);
    unkReq.push_back(SOFTHSM_MILENAGE_WIRE_VERSION);
    unkReq.push_back(SOFTHSM_MILENAGE_OP_5G_HE_AV);
    unkReq.push_back(0); unkReq.push_back(0);
    uint32_t unkTotal = (uint32_t)(unkReq.size() + 4 + unkBody.size());
    unkReq.push_back((unkTotal>>24)&0xFF); unkReq.push_back((unkTotal>>16)&0xFF);
    unkReq.push_back((unkTotal>>8)&0xFF); unkReq.push_back(unkTotal&0xFF);
    unkReq.insert(unkReq.end(), unkBody.begin(), unkBody.end());
    milenage_wire::Request parsedUnk;
    CHECK(milenage_wire::parseRequest(unkReq.data(), unkReq.size(), parsedUnk) == milenage_wire::Error::UNKNOWN_CRITICAL_TAG,
          "wire parser rejects unknown critical tag");

    // Oversized request.
    std::vector<uint8_t> oversized(SOFTHSM_MILENAGE_MAX_REQUEST_LEN + 1, 0);
    milenage_wire::Request parsedOversized;
    CHECK(milenage_wire::parseRequest(oversized.data(), oversized.size(), parsedOversized) == milenage_wire::Error::TOO_LARGE,
          "wire parser rejects a request over the 4096-byte cap");

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
