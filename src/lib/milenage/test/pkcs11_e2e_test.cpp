// End-to-end PKCS#11-level test for the Milenage vendor mechanisms,
// driven against the real built libsofthsm2.so via dlopen + the
// standard C_GetFunctionList entry point. Not part of any build
// system yet -- see doc/MILENAGE-5G-AKA-DESIGN.md section 17.
//
// Build:
//   g++ -std=c++17 -I<repo>/src/lib/pkcs11 -I<repo>/src/lib/milenage \
//       pkcs11_e2e_test.cpp -ldl -o /tmp/pkcs11_e2e_test
// Run (module path is the just-built libsofthsm2.so):
//   SOFTHSM2_CONF=/tmp/milenage_e2e/softhsm2.conf \
//   /tmp/pkcs11_e2e_test /path/to/libsofthsm2.so

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <vector>
#include <string>

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"
#include "softhsm_milenage.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } else { printf("PASS: %s\n", msg); } } while (0)
#define CHECKRV(rv, expected, msg) do { CK_RV _rv = (rv); if (_rv != (expected)) { printf("FAIL: %s (rv=0x%lx)\n", msg, (unsigned long)_rv); failures++; } else { printf("PASS: %s\n", msg); } } while (0)

static CK_FUNCTION_LIST_PTR fl = nullptr;

static void appendTlv(std::vector<CK_BYTE> &v, uint16_t tag, const std::vector<CK_BYTE> &val)
{
    v.push_back((tag >> 8) & 0xFF); v.push_back(tag & 0xFF);
    uint32_t len = (uint32_t)val.size();
    v.push_back((len >> 24) & 0xFF); v.push_back((len >> 16) & 0xFF);
    v.push_back((len >> 8) & 0xFF); v.push_back(len & 0xFF);
    v.insert(v.end(), val.begin(), val.end());
}

static std::vector<CK_BYTE> buildRequest(uint8_t op, const std::vector<std::pair<uint16_t, std::vector<CK_BYTE>>> &fields)
{
    std::vector<CK_BYTE> body;
    for (auto &f : fields) appendTlv(body, f.first, f.second);
    std::vector<CK_BYTE> out;
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

struct ParsedResponse {
    std::vector<CK_BYTE> raw;
    std::vector<std::pair<uint16_t, std::vector<CK_BYTE>>> fields;
};

static ParsedResponse parseResponse(const std::vector<CK_BYTE> &r)
{
    ParsedResponse out;
    out.raw = r;
    size_t pos = 12;
    while (pos + 6 <= r.size()) {
        uint16_t tag = (r[pos] << 8) | r[pos+1];
        uint32_t len = (r[pos+2] << 24) | (r[pos+3] << 16) | (r[pos+4] << 8) | r[pos+5];
        pos += 6;
        std::vector<CK_BYTE> val(r.begin() + pos, r.begin() + pos + len);
        out.fields.push_back({tag, val});
        pos += len;
    }
    return out;
}

static std::vector<CK_BYTE> field(const ParsedResponse &r, uint16_t tag)
{
    for (auto &f : r.fields) if (f.first == tag) return f.second;
    return {};
}

static std::vector<CK_BYTE> s2v(const std::string &s) { return std::vector<CK_BYTE>(s.begin(), s.end()); }

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <path-to-libsofthsm2.so>\n", argv[0]); return 2; }

    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    typedef CK_RV (*GetFunctionListFn)(CK_FUNCTION_LIST_PTR_PTR);
    GetFunctionListFn getFl = (GetFunctionListFn)dlsym(handle, "C_GetFunctionList");
    if (!getFl) { fprintf(stderr, "no C_GetFunctionList\n"); return 2; }
    CHECK(getFl(&fl) == CKR_OK, "C_GetFunctionList");

    CHECK(fl->C_Initialize(NULL_PTR) == CKR_OK, "C_Initialize");

    CK_SLOT_ID slots[16];
    CK_ULONG nslots = 16;
    CHECK(fl->C_GetSlotList(CK_TRUE, slots, &nslots) == CKR_OK, "C_GetSlotList");
    CHECK(nslots >= 1, "at least one initialized slot");
    CK_SLOT_ID slot = slots[0];

    CK_SESSION_HANDLE session;
    CHECK(fl->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session) == CKR_OK, "C_OpenSession");

    CK_UTF8CHAR pin[] = "5678";
    CHECK(fl->C_Login(session, CKU_USER, pin, 4) == CKR_OK, "C_Login as normal user");

    // --- Generate the Master Storage Key with the exact required template ---
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG valueLen = SOFTHSM_MILENAGE_MASTER_KEY_VALUE_LEN;
    CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
    CK_UTF8CHAR label[] = SOFTHSM_MILENAGE_MASTER_KEY_LABEL;
    CK_BYTE id[] = { SOFTHSM_MILENAGE_MASTER_KEY_ID_BYTE };
    CK_MECHANISM_TYPE allowed[] = {
        CKM_SOFTHSM_5G_HE_AV_WRAPPED,
        CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED,
        CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED,
    };

    CK_ATTRIBUTE keyTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
        { CKA_SENSITIVE, &ckTrue, sizeof(ckTrue) },
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_MODIFIABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_COPYABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) },
        { CKA_ENCRYPT, &ckFalse, sizeof(ckFalse) },
        { CKA_DECRYPT, &ckFalse, sizeof(ckFalse) },
        { CKA_WRAP, &ckFalse, sizeof(ckFalse) },
        { CKA_UNWRAP, &ckFalse, sizeof(ckFalse) },
        { CKA_DERIVE, &ckFalse, sizeof(ckFalse) },
        { CKA_LABEL, label, sizeof(label) - 1 },
        { CKA_ID, id, sizeof(id) },
        { CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed) },
    };
    CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE masterKey;
    CK_RV genRv = fl->C_GenerateKey(session, &genMech, keyTemplate, sizeof(keyTemplate)/sizeof(keyTemplate[0]), &masterKey);
    CHECK(genRv == CKR_OK, "C_GenerateKey creates the Master Storage Key with the full required template");
    if (genRv != CKR_OK) { fprintf(stderr, "C_GenerateKey rv=0x%lx\n", (unsigned long)genRv); }

    // Master key must not be usable through ordinary AES encrypt.
    CK_MECHANISM aesEcbMech = { CKM_AES_ECB, NULL_PTR, 0 };
    CK_RV encInitRv = fl->C_EncryptInit(session, &aesEcbMech, masterKey);
    CHECK(encInitRv != CKR_OK, "Master Storage Key cannot be used through ordinary CKM_AES_ECB (CKA_ENCRYPT=FALSE / not in CKA_ALLOWED_MECHANISMS)");

    // Master key must not be extractable via C_GetAttributeValue(CKA_VALUE).
    CK_ATTRIBUTE valueAttr = { CKA_VALUE, NULL_PTR, 0 };
    CK_RV getAttrRv = fl->C_GetAttributeValue(session, masterKey, &valueAttr, 1);
    CHECK(getAttrRv != CKR_OK || (CK_LONG)valueAttr.ulValueLen < 0,
          "Master Storage Key value is not retrievable via C_GetAttributeValue");

    std::string supi = "imsi-001010123456789";
    CK_BYTE plainK[16] = {0x46,0x5b,0x5c,0xe8,0xb1,0x99,0xb4,0x9f,0xaa,0x5f,0x0a,0x2e,0xe2,0x38,0xa6,0xbc};
    CK_BYTE plainOpc[16] = {0xcd,0x63,0xcb,0x71,0x95,0x4a,0x9f,0x4e,0x48,0xa5,0x99,0x4e,0x37,0xa0,0x2b,0xaf};

    // --- Provision ---
    auto provReq = buildRequest(SOFTHSM_MILENAGE_OP_PROVISION, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_K, std::vector<CK_BYTE>(plainK, plainK+16)},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC, std::vector<CK_BYTE>(plainOpc, plainOpc+16)},
    });
    CK_MECHANISM provMech = { CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED, NULL_PTR, 0 };
    CHECKRV(fl->C_SignInit(session, &provMech, masterKey), CKR_OK, "C_SignInit(PROVISION)");

    // Output-size query must succeed and must be exact/fixed, without touching crypto.
    CK_ULONG provLen = 0;
    CHECK(fl->C_Sign(session, provReq.data(), (CK_ULONG)provReq.size(), NULL_PTR, &provLen) == CKR_OK, "C_Sign size query (PROVISION)");
    CHECK(provLen > 0, "PROVISION size query returns a positive length");

    std::vector<CK_BYTE> provResp(provLen);
    CK_ULONG provLen2 = provLen;
    CK_RV provRv = fl->C_Sign(session, provReq.data(), (CK_ULONG)provReq.size(), provResp.data(), &provLen2);
    CHECK(provRv == CKR_OK, "C_Sign(PROVISION) succeeds");
    auto provParsed = parseResponse(provResp);
    auto wrappedK = field(provParsed, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K);
    auto wrappedOpc = field(provParsed, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC);
    CHECK(!wrappedK.empty() && !wrappedOpc.empty(), "PROVISION response contains wrapped K and OPc");

    // C_SignUpdate/C_SignFinal must be rejected for these mechanisms.
    CHECK(fl->C_SignInit(session, &provMech, masterKey) == CKR_OK, "C_SignInit(PROVISION) again for multipart-rejection test");
    CK_BYTE dummyPart[1] = {0};
    CHECK(fl->C_SignUpdate(session, dummyPart, 1) == CKR_FUNCTION_NOT_SUPPORTED, "C_SignUpdate rejected for Milenage mechanism");
    CK_ULONG dummyLen = 0;
    CHECK(fl->C_SignFinal(session, NULL_PTR, &dummyLen) != CKR_OK, "C_SignFinal rejected for Milenage mechanism");

    // --- 5G HE AV ---
    CK_BYTE sqn[6] = {0xff,0x9b,0xb4,0xd0,0xb6,0x07};
    CK_BYTE amf[2] = {0xb9,0xb9};
    std::string snn = "5G:mnc001.mcc001.3gppnetwork.org";
    auto avReq = buildRequest(SOFTHSM_MILENAGE_OP_5G_HE_AV, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_SQN, std::vector<CK_BYTE>(sqn, sqn+6)},
        {SOFTHSM_MILENAGE_TAG_AMF, std::vector<CK_BYTE>(amf, amf+2)},
        {SOFTHSM_MILENAGE_TAG_SNN, s2v(snn)},
    });
    CK_MECHANISM avMech = { CKM_SOFTHSM_5G_HE_AV_WRAPPED, NULL_PTR, 0 };
    CHECKRV(fl->C_SignInit(session, &avMech, masterKey), CKR_OK, "C_SignInit(5G_HE_AV)");
    CK_ULONG avLen = 0;
    CHECK(fl->C_Sign(session, avReq.data(), (CK_ULONG)avReq.size(), NULL_PTR, &avLen) == CKR_OK, "C_Sign size query (5G_HE_AV)");
    std::vector<CK_BYTE> avResp(avLen);
    CK_ULONG avLen2 = avLen;
    CHECK(fl->C_Sign(session, avReq.data(), (CK_ULONG)avReq.size(), avResp.data(), &avLen2) == CKR_OK, "C_Sign(5G_HE_AV) succeeds");
    auto avParsed = parseResponse(avResp);
    auto rand16 = field(avParsed, SOFTHSM_MILENAGE_TAG_OUT_RAND);
    auto autn = field(avParsed, SOFTHSM_MILENAGE_TAG_OUT_AUTN);
    auto xresStar = field(avParsed, SOFTHSM_MILENAGE_TAG_OUT_XRES_STAR);
    auto kausf = field(avParsed, SOFTHSM_MILENAGE_TAG_OUT_KAUSF);
    CHECK(rand16.size() == 16, "AV response RAND is 16 bytes");
    CHECK(autn.size() == 16, "AV response AUTN is 16 bytes");
    CHECK(xresStar.size() == 16, "AV response XRES* is 16 bytes");
    CHECK(kausf.size() == 32, "AV response KAUSF is 32 bytes");
    CHECK(avParsed.fields.size() == 4, "AV response contains exactly 4 fields (no RES/CK/IK/AK/K/OPc leak)");

    // Wrong SUPI must be rejected.
    auto avReqWrong = buildRequest(SOFTHSM_MILENAGE_OP_5G_HE_AV, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v("imsi-999999999999999")},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_SQN, std::vector<CK_BYTE>(sqn, sqn+6)},
        {SOFTHSM_MILENAGE_TAG_AMF, std::vector<CK_BYTE>(amf, amf+2)},
        {SOFTHSM_MILENAGE_TAG_SNN, s2v(snn)},
    });
    CHECK(fl->C_SignInit(session, &avMech, masterKey) == CKR_OK, "C_SignInit(5G_HE_AV) for wrong-SUPI test");
    CK_BYTE tmpBuf[256]; CK_ULONG tmpLen = sizeof(tmpBuf);
    CHECK(fl->C_Sign(session, avReqWrong.data(), (CK_ULONG)avReqWrong.size(), tmpBuf, &tmpLen) != CKR_OK,
          "5G_HE_AV rejects wrong SUPI binding");

    // --- Resync: garbage AUTS must be rejected with CKR_SIGNATURE_INVALID ---
    CK_BYTE randFixed[16]; for (int i=0;i<16;i++) randFixed[i]=(CK_BYTE)(0x10+i);
    CK_BYTE garbageAuts[14]; for (int i=0;i<14;i++) garbageAuts[i]=(CK_BYTE)(0xAA ^ i);
    auto resyncReq = buildRequest(SOFTHSM_MILENAGE_OP_RESYNC, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_RAND, std::vector<CK_BYTE>(randFixed, randFixed+16)},
        {SOFTHSM_MILENAGE_TAG_AUTS, std::vector<CK_BYTE>(garbageAuts, garbageAuts+14)},
    });
    CK_MECHANISM resyncMech = { CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED, NULL_PTR, 0 };
    CHECKRV(fl->C_SignInit(session, &resyncMech, masterKey), CKR_OK, "C_SignInit(RESYNC)");
    CK_BYTE resyncBuf[64]; CK_ULONG resyncLen = sizeof(resyncBuf);
    CK_RV resyncRv = fl->C_Sign(session, resyncReq.data(), (CK_ULONG)resyncReq.size(), resyncBuf, &resyncLen);
    CHECK(resyncRv == CKR_SIGNATURE_INVALID, "RESYNC with invalid MAC-S returns CKR_SIGNATURE_INVALID");

    // Login required: log out and confirm operations are refused.
    CHECK(fl->C_Logout(session) == CKR_OK, "C_Logout");
    CK_RV signInitAfterLogout = fl->C_SignInit(session, &avMech, masterKey);
    CHECK(signInitAfterLogout != CKR_OK, "5G_HE_AV C_SignInit refused after logout (login required)");

    fl->C_CloseSession(session);
    fl->C_Finalize(NULL_PTR);

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
