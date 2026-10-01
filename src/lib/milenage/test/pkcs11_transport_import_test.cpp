// End-to-end PKCS#11-level test for CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED
// (WITH_MILENAGE_TRANSPORT_IMPORT), driven against the real built
// libsofthsm2.so via dlopen, exactly like pkcs11_e2e_test.cpp.
//
// This test plays the role of the external "secure provisioning
// authority" from doc/MILENAGE-5G-AKA-DESIGN.md section 6 itself: it
// builds a transport-wrapped package using its own independent
// AES-KWP call directly against OpenSSL EVP (deliberately not calling
// any src/lib/milenage/ internals -- this test only ever talks to
// SoftHSM through the public PKCS#11 API), matching the plaintext
// layout documented in softhsm_milenage.h
// (SOFTHSM_MILENAGE_TRANSPORT_*), then verifies SoftHSM can unwrap it
// under a real Transport KEK object and re-wrap the secrets under a
// real Master Storage Key object, returning only wrapped_k/wrapped_opc.
//
// Build/run: see src/lib/milenage/test/CMakeLists.txt (target
// milenage-pkcs11-transport-import-test, only built when
// WITH_MILENAGE_TRANSPORT_IMPORT is on).

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>

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

// --- independent AES-KWP wrap, test-only, mirrors what an external
// authority would run; never calls into src/lib/milenage/. ---
static std::vector<uint8_t> aesKwpWrapIndependent(const uint8_t key[32], const uint8_t *pt, size_t ptLen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> out(ptLen + 16, 0);
    int outLen1 = 0, outLen2 = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap_pad(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    EVP_EncryptUpdate(ctx, out.data(), &outLen1, pt, (int)ptLen);
    EVP_EncryptFinal_ex(ctx, out.data() + outLen1, &outLen2);
    out.resize(outLen1 + outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

static std::vector<uint8_t> buildTransportPackage(const std::string &supi, uint8_t secretType,
                                                    const uint8_t secret[16], const uint8_t transportKek[32])
{
    uint8_t plaintext[SOFTHSM_MILENAGE_TRANSPORT_PLAINTEXT_LEN];
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(plaintext + 0, SOFTHSM_MILENAGE_TRANSPORT_MAGIC, 4);
    plaintext[4] = SOFTHSM_MILENAGE_TRANSPORT_VERSION;
    plaintext[5] = secretType;
    plaintext[6] = SOFTHSM_MILENAGE_TRANSPORT_KEY_VERSION;
    plaintext[7] = 0x00;
    std::string bindingInput = std::string(SOFTHSM_MILENAGE_TRANSPORT_BINDING_CONTEXT) + supi;
    SHA256((const unsigned char *)bindingInput.data(), bindingInput.size(), plaintext + 8);
    plaintext[40] = 0; // transaction_id_len
    plaintext[73] = 0x00;
    plaintext[74] = 0x10; // secret_length = 16
    memcpy(plaintext + 75, secret, 16);

    return aesKwpWrapIndependent(transportKek, plaintext, sizeof(plaintext));
}

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

static std::vector<std::pair<uint16_t, std::vector<uint8_t>>> parseFields(const std::vector<uint8_t> &r)
{
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> out;
    size_t pos = 12;
    while (pos + 6 <= r.size()) {
        uint16_t tag = (uint16_t)((r[pos] << 8) | r[pos+1]);
        uint32_t len = (uint32_t)((r[pos+2] << 24) | (r[pos+3] << 16) | (r[pos+4] << 8) | r[pos+5]);
        pos += 6;
        if (pos + len > r.size()) break;
        out.push_back({tag, std::vector<uint8_t>(r.begin()+pos, r.begin()+pos+len)});
        pos += len;
    }
    return out;
}
static std::vector<uint8_t> field(const std::vector<std::pair<uint16_t, std::vector<uint8_t>>> &fs, uint16_t tag)
{
    for (auto &f : fs) if (f.first == tag) return f.second;
    return {};
}
static std::vector<uint8_t> s2v(const std::string &s) { return std::vector<uint8_t>(s.begin(), s.end()); }

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <path-to-libsofthsm2.so>\n", argv[0]); return 2; }

    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    typedef CK_RV (*GetFunctionListFn)(CK_FUNCTION_LIST_PTR_PTR);
    GetFunctionListFn getFl = (GetFunctionListFn)dlsym(handle, "C_GetFunctionList");
    CHECK(getFl && getFl(&fl) == CKR_OK, "C_GetFunctionList");
    CHECK(fl->C_Initialize(NULL_PTR) == CKR_OK, "C_Initialize");

    CK_SLOT_ID slots[16]; CK_ULONG nslots = 16;
    CHECK(fl->C_GetSlotList(CK_TRUE, slots, &nslots) == CKR_OK && nslots >= 1, "C_GetSlotList");
    CK_SLOT_ID slot = slots[0];

    CK_SESSION_HANDLE session;
    CHECK(fl->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session) == CKR_OK, "C_OpenSession");
    CK_UTF8CHAR pin[] = "5678";
    CHECK(fl->C_Login(session, CKU_USER, pin, 4) == CKR_OK, "C_Login");

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;

    // --- Master Storage Key ---
    CK_ULONG masterValueLen = SOFTHSM_MILENAGE_MASTER_KEY_VALUE_LEN;
    CK_UTF8CHAR masterLabel[] = SOFTHSM_MILENAGE_MASTER_KEY_LABEL;
    CK_BYTE masterId[] = { SOFTHSM_MILENAGE_MASTER_KEY_ID_BYTE };
    CK_MECHANISM_TYPE masterAllowed[] = { CKM_SOFTHSM_5G_HE_AV_WRAPPED, CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED,
                                           CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED };
    CK_ATTRIBUTE masterTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) }, { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &masterValueLen, sizeof(masterValueLen) },
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) }, { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
        { CKA_SENSITIVE, &ckTrue, sizeof(ckTrue) }, { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_MODIFIABLE, &ckFalse, sizeof(ckFalse) }, { CKA_COPYABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) }, { CKA_ENCRYPT, &ckFalse, sizeof(ckFalse) },
        { CKA_DECRYPT, &ckFalse, sizeof(ckFalse) }, { CKA_WRAP, &ckFalse, sizeof(ckFalse) },
        { CKA_UNWRAP, &ckFalse, sizeof(ckFalse) }, { CKA_DERIVE, &ckFalse, sizeof(ckFalse) },
        { CKA_LABEL, masterLabel, sizeof(masterLabel) - 1 }, { CKA_ID, masterId, sizeof(masterId) },
        { CKA_ALLOWED_MECHANISMS, masterAllowed, sizeof(masterAllowed) },
    };
    CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE masterKeyHandle;
    CHECKRV(fl->C_GenerateKey(session, &genMech, masterTemplate, sizeof(masterTemplate)/sizeof(masterTemplate[0]), &masterKeyHandle),
            CKR_OK, "C_GenerateKey creates the Master Storage Key");

    // --- Transport KEK: separate key, separate label/id/allowed-mechanisms ---
    CK_ULONG transportValueLen = SOFTHSM_MILENAGE_TRANSPORT_KEK_VALUE_LEN;
    CK_UTF8CHAR transportLabel[] = SOFTHSM_MILENAGE_TRANSPORT_KEK_LABEL;
    CK_BYTE transportId[] = { SOFTHSM_MILENAGE_TRANSPORT_KEK_ID_BYTE };
    CK_MECHANISM_TYPE transportAllowed[] = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED };
    CK_ATTRIBUTE transportTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) }, { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &transportValueLen, sizeof(transportValueLen) },
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) }, { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
        { CKA_SENSITIVE, &ckTrue, sizeof(ckTrue) }, { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_MODIFIABLE, &ckFalse, sizeof(ckFalse) }, { CKA_COPYABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) }, { CKA_ENCRYPT, &ckFalse, sizeof(ckFalse) },
        { CKA_DECRYPT, &ckFalse, sizeof(ckFalse) }, { CKA_WRAP, &ckFalse, sizeof(ckFalse) },
        { CKA_UNWRAP, &ckFalse, sizeof(ckFalse) }, { CKA_DERIVE, &ckFalse, sizeof(ckFalse) },
        { CKA_LABEL, transportLabel, sizeof(transportLabel) - 1 }, { CKA_ID, transportId, sizeof(transportId) },
        { CKA_ALLOWED_MECHANISMS, transportAllowed, sizeof(transportAllowed) },
    };
    CK_OBJECT_HANDLE transportKekHandle;
    CHECKRV(fl->C_GenerateKey(session, &genMech, transportTemplate, sizeof(transportTemplate)/sizeof(transportTemplate[0]), &transportKekHandle),
            CKR_OK, "C_GenerateKey creates the Transport KEK");

    // Transport KEK must not be usable for ordinary AES ops either.
    CK_MECHANISM aesEcbMech = { CKM_AES_ECB, NULL_PTR, 0 };
    CHECK(fl->C_EncryptInit(session, &aesEcbMech, transportKekHandle) != CKR_OK,
          "Transport KEK cannot be used through ordinary CKM_AES_ECB");
    CK_ATTRIBUTE valueAttr = { CKA_VALUE, NULL_PTR, 0 };
    CK_RV getAttrRv = fl->C_GetAttributeValue(session, transportKekHandle, &valueAttr, 1);
    CHECK(getAttrRv != CKR_OK, "Transport KEK value is not retrievable via C_GetAttributeValue");

    // Master key must not work with the transport-import mechanism
    // (wrong key for this mechanism, since its CKA_ALLOWED_MECHANISMS
    // for THIS PoC does include CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED
    // for convenience of the secondary-key lookup path, but its
    // template is the Master Storage Key template, not the Transport
    // KEK template, so isValidTransportKek must reject it as hKey).
    CK_MECHANISM transportMechForMaster = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED, NULL_PTR, 0 };
    CHECK(fl->C_SignInit(session, &transportMechForMaster, masterKeyHandle) != CKR_OK,
          "Master Storage Key is rejected as the transport-import hKey (wrong key template)");

    std::string supi = "imsi-001010123456789";
    uint8_t plainK[16] = {0x46,0x5b,0x5c,0xe8,0xb1,0x99,0xb4,0x9f,0xaa,0x5f,0x0a,0x2e,0xe2,0x38,0xa6,0xbc};
    uint8_t plainOpc[16] = {0xcd,0x63,0xcb,0x71,0x95,0x4a,0x9f,0x4e,0x48,0xa5,0x99,0x4e,0x37,0xa0,0x2b,0xaf};

    // We need the plaintext Transport KEK bytes to build the test
    // package (this test plays the role of the external authority,
    // which by definition holds the Transport KEK in the real
    // deployment topology -- but SoftHSM's copy must remain
    // non-extractable, which we already checked above). For this
    // black-box test we generate our own local KEK bytes and import
    // them as the "Transport KEK" object via a second, non-Milenage
    // AES key generated with a known value... but C_GenerateKey never
    // reveals its output. Instead: this test constructs its
    // authority-side KEK out-of-band (as if delivered by a real key
    // ceremony) and provisions SoftHSM's Transport KEK object with
    // that exact value using CKM_AES_KEY_GEN's counterpart, C_CreateObject,
    // which is the standard PKCS#11 way to import externally-known
    // key material as a token object.
    uint8_t knownKekValue[32];
    for (int i = 0; i < 32; i++) knownKekValue[i] = (uint8_t)(0x40 + i);

    CK_OBJECT_HANDLE importedTransportKekHandle;
    CK_ATTRIBUTE importedTransportTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) }, { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE, knownKekValue, sizeof(knownKekValue) },
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) }, { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
        { CKA_SENSITIVE, &ckTrue, sizeof(ckTrue) }, { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_MODIFIABLE, &ckFalse, sizeof(ckFalse) }, { CKA_COPYABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) }, { CKA_ENCRYPT, &ckFalse, sizeof(ckFalse) },
        { CKA_DECRYPT, &ckFalse, sizeof(ckFalse) }, { CKA_WRAP, &ckFalse, sizeof(ckFalse) },
        { CKA_UNWRAP, &ckFalse, sizeof(ckFalse) }, { CKA_DERIVE, &ckFalse, sizeof(ckFalse) },
        { CKA_LABEL, transportLabel, sizeof(transportLabel) - 1 }, { CKA_ID, transportId, sizeof(transportId) },
        { CKA_ALLOWED_MECHANISMS, transportAllowed, sizeof(transportAllowed) },
    };
    CK_RV createRv = fl->C_CreateObject(session, importedTransportTemplate,
                                         sizeof(importedTransportTemplate)/sizeof(importedTransportTemplate[0]),
                                         &importedTransportKekHandle);
    CHECKRV(createRv, CKR_OK, "C_CreateObject imports a known-value Transport KEK for this black-box test");
    if (createRv != CKR_OK) { printf("\n%d failure(s)\n", failures); return 1; }

    auto transportK = buildTransportPackage(supi, SOFTHSM_MILENAGE_SECRET_TYPE_K, plainK, knownKekValue);
    auto transportOpc = buildTransportPackage(supi, SOFTHSM_MILENAGE_SECRET_TYPE_OPC, plainOpc, knownKekValue);

    auto req = buildRequest(SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K, transportK},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC, transportOpc},
    });

    CK_SOFTHSM_MILENAGE_TRANSPORT_IMPORT_PARAMS params;
    params.masterKeyHandle = masterKeyHandle;
    CK_MECHANISM importMech = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED, &params, sizeof(params) };
    CHECKRV(fl->C_SignInit(session, &importMech, importedTransportKekHandle), CKR_OK,
            "C_SignInit(IMPORT_TRANSPORT) with correct Transport KEK + master key param");

    CK_ULONG len = 0;
    CHECKRV(fl->C_Sign(session, req.data(), (CK_ULONG)req.size(), NULL_PTR, &len), CKR_OK, "C_Sign size query");
    std::vector<CK_BYTE> resp(len);
    CK_ULONG len2 = len;
    CK_RV signRv = fl->C_Sign(session, req.data(), (CK_ULONG)req.size(), resp.data(), &len2);
    CHECKRV(signRv, CKR_OK, "C_Sign(IMPORT_TRANSPORT) succeeds");

    auto fields = parseFields(resp);
    auto wrappedK = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K);
    auto wrappedOpc = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC);
    CHECK(!wrappedK.empty() && !wrappedOpc.empty(), "IMPORT_TRANSPORT response contains wrapped_k and wrapped_opc");
    CHECK(fields.size() == 2, "IMPORT_TRANSPORT response contains exactly wrapped_k and wrapped_opc (no plaintext leak)");

    // The resulting wrapped_k/wrapped_opc must actually work for AV generation.
    uint8_t sqn[6] = {0xff,0x9b,0xb4,0xd0,0xb6,0x07};
    uint8_t amf[2] = {0xb9,0xb9};
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
    CHECKRV(fl->C_SignInit(session, &avMech, masterKeyHandle), CKR_OK, "C_SignInit(5G_HE_AV) using transport-imported credentials");
    CK_ULONG avLen = 0;
    fl->C_Sign(session, avReq.data(), (CK_ULONG)avReq.size(), NULL_PTR, &avLen);
    std::vector<CK_BYTE> avResp(avLen);
    CK_ULONG avLen2 = avLen;
    CHECKRV(fl->C_Sign(session, avReq.data(), (CK_ULONG)avReq.size(), avResp.data(), &avLen2), CKR_OK,
            "5G HE AV generation succeeds using credentials imported via the transport path");

    // --- Negative: wrong Transport KEK rejects the package. ---
    uint8_t wrongKek[32];
    memcpy(wrongKek, knownKekValue, 32);
    wrongKek[0] ^= 0xFF;
    CK_ATTRIBUTE wrongKekTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) }, { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE, wrongKek, sizeof(wrongKek) },
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) }, { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
        { CKA_SENSITIVE, &ckTrue, sizeof(ckTrue) }, { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_MODIFIABLE, &ckFalse, sizeof(ckFalse) }, { CKA_COPYABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) }, { CKA_ENCRYPT, &ckFalse, sizeof(ckFalse) },
        { CKA_DECRYPT, &ckFalse, sizeof(ckFalse) }, { CKA_WRAP, &ckFalse, sizeof(ckFalse) },
        { CKA_UNWRAP, &ckFalse, sizeof(ckFalse) }, { CKA_DERIVE, &ckFalse, sizeof(ckFalse) },
        { CKA_LABEL, transportLabel, sizeof(transportLabel) - 1 }, { CKA_ID, transportId, sizeof(transportId) },
        { CKA_ALLOWED_MECHANISMS, transportAllowed, sizeof(transportAllowed) },
    };
    CK_OBJECT_HANDLE wrongKekHandle;
    fl->C_DestroyObject(session, importedTransportKekHandle); // avoid ambiguous label match
    CHECKRV(fl->C_CreateObject(session, wrongKekTemplate, sizeof(wrongKekTemplate)/sizeof(wrongKekTemplate[0]), &wrongKekHandle),
            CKR_OK, "C_CreateObject imports a deliberately-wrong Transport KEK");
    CK_MECHANISM importMech2 = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED, &params, sizeof(params) };
    CHECKRV(fl->C_SignInit(session, &importMech2, wrongKekHandle), CKR_OK, "C_SignInit with wrong Transport KEK object (structurally valid)");
    CK_BYTE tmpBuf[256]; CK_ULONG tmpLen = sizeof(tmpBuf);
    CK_RV wrongKekRv = fl->C_Sign(session, req.data(), (CK_ULONG)req.size(), tmpBuf, &tmpLen);
    CHECK(wrongKekRv != CKR_OK, "transport package wrapped under a different Transport KEK is rejected");

    // --- Negative: modified transport ciphertext is rejected. ---
    fl->C_DestroyObject(session, wrongKekHandle);
    CK_OBJECT_HANDLE reimportedHandle;
    fl->C_CreateObject(session, importedTransportTemplate, sizeof(importedTransportTemplate)/sizeof(importedTransportTemplate[0]), &reimportedHandle);
    auto tamperedK = transportK;
    tamperedK[tamperedK.size() - 1] ^= 0x01;
    auto tamperedReq = buildRequest(SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K, tamperedK},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC, transportOpc},
    });
    CK_MECHANISM importMech3 = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED, &params, sizeof(params) };
    CHECKRV(fl->C_SignInit(session, &importMech3, reimportedHandle), CKR_OK, "C_SignInit for tampered-ciphertext test");
    CK_ULONG tmpLen2 = sizeof(tmpBuf);
    CK_RV tamperedRv = fl->C_Sign(session, tamperedReq.data(), (CK_ULONG)tamperedReq.size(), tmpBuf, &tmpLen2);
    CHECK(tamperedRv != CKR_OK, "a modified transport-wrapped ciphertext is rejected");

    // --- Negative: wrong SUPI binding is rejected. ---
    CK_MECHANISM importMech4 = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED, &params, sizeof(params) };
    CHECKRV(fl->C_SignInit(session, &importMech4, reimportedHandle), CKR_OK, "C_SignInit for wrong-SUPI test");
    auto wrongSupiReq = buildRequest(SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v("imsi-999999999999999")},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K, transportK},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC, transportOpc},
    });
    CK_ULONG tmpLen3 = sizeof(tmpBuf);
    CK_RV wrongSupiRv = fl->C_Sign(session, wrongSupiReq.data(), (CK_ULONG)wrongSupiReq.size(), tmpBuf, &tmpLen3);
    CHECK(wrongSupiRv != CKR_OK, "transport package bound to a different SUPI is rejected");

    // --- Negative: K and OPc transport packages cannot be swapped. ---
    CK_MECHANISM importMech5 = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED, &params, sizeof(params) };
    CHECKRV(fl->C_SignInit(session, &importMech5, reimportedHandle), CKR_OK, "C_SignInit for swapped-secret-type test");
    auto swappedReq = buildRequest(SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K, transportOpc}, // swapped
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC, transportK}, // swapped
    });
    CK_ULONG tmpLen4 = sizeof(tmpBuf);
    CK_RV swappedRv = fl->C_Sign(session, swappedReq.data(), (CK_ULONG)swappedReq.size(), tmpBuf, &tmpLen4);
    CHECK(swappedRv != CKR_OK, "swapped K/OPc transport packages are rejected");

    fl->C_CloseSession(session);
    fl->C_Finalize(NULL_PTR);

    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
