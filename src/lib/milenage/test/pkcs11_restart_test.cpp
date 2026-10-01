// Cross-process persistence test: process A creates the Master Storage
// Key + provisions wrapped K/OPc and exits; process B (a fresh exec,
// fresh dlopen of the module) finds the same token/key by label and
// successfully generates a 5G HE AV from the wrapped values written by
// process A. This is the "wrapped credentials remain usable after
// process restart" requirement (design doc / spec section 15).
//
// Build:
//   g++ -std=c++17 -I<repo>/src/lib/pkcs11 -I<repo>/src/lib/milenage \
//       pkcs11_restart_test.cpp -ldl -o /tmp/pkcs11_restart_test
// Run:
//   SOFTHSM2_CONF=... /tmp/pkcs11_restart_test <module.so> provision <wrapped-file>
//   SOFTHSM2_CONF=... /tmp/pkcs11_restart_test <module.so> generate <wrapped-file>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <vector>
#include <string>
#include <fstream>

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

static std::vector<std::pair<uint16_t, std::vector<CK_BYTE>>> parseFields(const std::vector<CK_BYTE> &r)
{
    std::vector<std::pair<uint16_t, std::vector<CK_BYTE>>> out;
    size_t pos = 12;
    while (pos + 6 <= r.size()) {
        uint16_t tag = (r[pos] << 8) | r[pos+1];
        uint32_t len = (r[pos+2] << 24) | (r[pos+3] << 16) | (r[pos+4] << 8) | r[pos+5];
        pos += 6;
        out.push_back({tag, std::vector<CK_BYTE>(r.begin()+pos, r.begin()+pos+len)});
        pos += len;
    }
    return out;
}

static std::vector<CK_BYTE> field(const std::vector<std::pair<uint16_t, std::vector<CK_BYTE>>> &fs, uint16_t tag)
{
    for (auto &f : fs) if (f.first == tag) return f.second;
    return {};
}

static std::vector<CK_BYTE> s2v(const std::string &s) { return std::vector<CK_BYTE>(s.begin(), s.end()); }

static void writeHex(std::ofstream &f, const std::vector<CK_BYTE> &v)
{
    for (auto b : v) { char buf[3]; snprintf(buf, sizeof(buf), "%02x", b); f << buf; }
    f << "\n";
}

static std::vector<CK_BYTE> readHexLine(std::ifstream &f)
{
    std::string line; std::getline(f, line);
    std::vector<CK_BYTE> out;
    for (size_t i = 0; i + 1 < line.size(); i += 2) {
        out.push_back((CK_BYTE)strtol(line.substr(i, 2).c_str(), nullptr, 16));
    }
    return out;
}

static CK_SESSION_HANDLE openLoggedInSession(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session;
    if (fl->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session) != CKR_OK)
        { fprintf(stderr, "C_OpenSession failed\n"); exit(1); }
    CK_UTF8CHAR pin[] = "5678";
    if (fl->C_Login(session, CKU_USER, pin, 4) != CKR_OK)
        { fprintf(stderr, "C_Login failed\n"); exit(1); }
    return session;
}

static CK_OBJECT_HANDLE findMasterKeyByLabel(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_UTF8CHAR label[] = SOFTHSM_MILENAGE_MASTER_KEY_LABEL;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_LABEL, label, sizeof(label) - 1 },
    };
    if (fl->C_FindObjectsInit(session, tmpl, 2) != CKR_OK) { fprintf(stderr, "find init failed\n"); exit(1); }
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    fl->C_FindObjects(session, &handle, 1, &count);
    fl->C_FindObjectsFinal(session);
    if (count != 1) { fprintf(stderr, "expected exactly 1 master key by label, found %lu\n", (unsigned long)count); exit(1); }
    return handle;
}

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: %s <module.so> provision|generate <wrapped-file>\n", argv[0]); return 2; }
    std::string mode = argv[2];
    std::string wrappedFile = argv[3];

    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    typedef CK_RV (*GetFunctionListFn)(CK_FUNCTION_LIST_PTR_PTR);
    GetFunctionListFn getFl = (GetFunctionListFn)dlsym(handle, "C_GetFunctionList");
    if (!getFl || getFl(&fl) != CKR_OK) { fprintf(stderr, "C_GetFunctionList failed\n"); return 2; }
    if (fl->C_Initialize(NULL_PTR) != CKR_OK) { fprintf(stderr, "C_Initialize failed\n"); return 2; }

    CK_SLOT_ID slots[16]; CK_ULONG nslots = 16;
    if (fl->C_GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK || nslots < 1) { fprintf(stderr, "no slots\n"); return 2; }
    CK_SLOT_ID slot = slots[0];

    std::string supi = "imsi-001010123456789";

    if (mode == "provision")
    {
        CK_SESSION_HANDLE session = openLoggedInSession(slot);

        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_KEY_TYPE keyType = CKK_AES;
        CK_ULONG valueLen = SOFTHSM_MILENAGE_MASTER_KEY_VALUE_LEN;
        CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
        CK_UTF8CHAR label[] = SOFTHSM_MILENAGE_MASTER_KEY_LABEL;
        CK_BYTE id[] = { SOFTHSM_MILENAGE_MASTER_KEY_ID_BYTE };
        CK_MECHANISM_TYPE allowed[] = {
            CKM_SOFTHSM_5G_HE_AV_WRAPPED, CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED, CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED,
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
        if (fl->C_GenerateKey(session, &genMech, keyTemplate, sizeof(keyTemplate)/sizeof(keyTemplate[0]), &masterKey) != CKR_OK)
            { fprintf(stderr, "C_GenerateKey failed\n"); return 1; }

        CK_BYTE plainK[16] = {0x46,0x5b,0x5c,0xe8,0xb1,0x99,0xb4,0x9f,0xaa,0x5f,0x0a,0x2e,0xe2,0x38,0xa6,0xbc};
        CK_BYTE plainOpc[16] = {0xcd,0x63,0xcb,0x71,0x95,0x4a,0x9f,0x4e,0x48,0xa5,0x99,0x4e,0x37,0xa0,0x2b,0xaf};
        auto provReq = buildRequest(SOFTHSM_MILENAGE_OP_PROVISION, {
            {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
            {SOFTHSM_MILENAGE_TAG_PLAINTEXT_K, std::vector<CK_BYTE>(plainK, plainK+16)},
            {SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC, std::vector<CK_BYTE>(plainOpc, plainOpc+16)},
        });
        CK_MECHANISM provMech = { CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED, NULL_PTR, 0 };
        if (fl->C_SignInit(session, &provMech, masterKey) != CKR_OK) { fprintf(stderr, "SignInit(provision) failed\n"); return 1; }
        CK_ULONG len = 0;
        fl->C_Sign(session, provReq.data(), (CK_ULONG)provReq.size(), NULL_PTR, &len);
        std::vector<CK_BYTE> resp(len);
        CK_ULONG len2 = len;
        if (fl->C_Sign(session, provReq.data(), (CK_ULONG)provReq.size(), resp.data(), &len2) != CKR_OK)
            { fprintf(stderr, "Sign(provision) failed\n"); return 1; }
        auto fields = parseFields(resp);
        auto wrappedK = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K);
        auto wrappedOpc = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC);

        std::ofstream out(wrappedFile);
        writeHex(out, wrappedK);
        writeHex(out, wrappedOpc);
        out.close();

        fl->C_CloseSession(session);
        fl->C_Finalize(NULL_PTR);
        printf("PASS: provisioning process wrote wrapped K/OPc to %s\n", wrappedFile.c_str());
        return 0;
    }
    else if (mode == "generate")
    {
        std::ifstream in(wrappedFile);
        auto wrappedK = readHexLine(in);
        auto wrappedOpc = readHexLine(in);
        if (wrappedK.empty() || wrappedOpc.empty()) { fprintf(stderr, "FAIL: could not read wrapped values from %s\n", wrappedFile.c_str()); return 1; }

        CK_SESSION_HANDLE session = openLoggedInSession(slot);
        CK_OBJECT_HANDLE masterKey = findMasterKeyByLabel(session);
        printf("PASS: rediscovered Master Storage Key by label in a fresh process\n");

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
        if (fl->C_SignInit(session, &avMech, masterKey) != CKR_OK) { fprintf(stderr, "FAIL: SignInit(AV) failed in fresh process\n"); return 1; }
        CK_ULONG len = 0;
        fl->C_Sign(session, avReq.data(), (CK_ULONG)avReq.size(), NULL_PTR, &len);
        std::vector<CK_BYTE> resp(len);
        CK_ULONG len2 = len;
        CK_RV rv = fl->C_Sign(session, avReq.data(), (CK_ULONG)avReq.size(), resp.data(), &len2);
        if (rv != CKR_OK) { fprintf(stderr, "FAIL: Sign(AV) failed in fresh process, rv=0x%lx\n", (unsigned long)rv); return 1; }
        auto fields = parseFields(resp);
        auto rand16 = field(fields, SOFTHSM_MILENAGE_TAG_OUT_RAND);
        auto kausf = field(fields, SOFTHSM_MILENAGE_TAG_OUT_KAUSF);
        if (rand16.size() != 16 || kausf.size() != 32) { fprintf(stderr, "FAIL: unexpected AV response shape\n"); return 1; }
        printf("PASS: generated a valid 5G HE AV in a fresh process using wrapped credentials from a prior process\n");

        fl->C_CloseSession(session);
        fl->C_Finalize(NULL_PTR);
        return 0;
    }

    fprintf(stderr, "unknown mode\n");
    return 2;
}
