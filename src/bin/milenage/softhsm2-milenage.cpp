/*
 * softhsm2-milenage: provisioning / operation CLI for the Milenage /
 * 5G-AKA vendor PKCS#11 mechanisms. See
 * doc/MILENAGE-5G-AKA-DESIGN.md sections 8/13 for the full spec this
 * implements a subset of.
 *
 * Loads the PKCS#11 module at runtime via dlopen (same approach as
 * softhsm2-util), so it is a generic client of any PKCS#11 module that
 * implements these vendor mechanisms, not something linked against
 * libsofthsm2 internals.
 *
 * Implemented subcommands: create-master-key, provision,
 * generate-5g-av, resync, inspect, import-transport-kek,
 * import-transport-wrapped. There is no create-transport-kek: a Transport
 * KEK generated inside the HSM would be CKA_EXTRACTABLE=FALSE from the
 * moment it exists, so no external system could ever wrap anything under
 * the same value -- it must be generated externally and imported (see
 * contrib/systemd/external-scripts/ in the SoftHSMv2 repo for the
 * external-system side of this: KEK generation and K/OPc wrapping).
 *
 * Security notes (see design doc sections 4 and 8):
 *  - No --k, --opc, or literal --pin option exists anywhere in this
 *    file. PINs come only from --pin-file or --pin-fd. Plaintext K/OPc
 *    for `provision` come only from --input-fd (an already-open file
 *    descriptor) or stdin, never argv, never environment variables.
 *  - `provision`'s only output is the UDM-ready JSON fragment; no
 *    plaintext secret is ever printed, logged, or included in error
 *    text.
 *  - Core dumps are disabled for the whole process on startup.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <sys/resource.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/mman.h>

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "config.h"
#include "pkcs11.h"
#include "softhsm_milenage.h"

namespace {

// ---------------------------------------------------------------------
// Process hardening
// ---------------------------------------------------------------------

void hardenProcess()
{
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
}

void secureWipe(void *p, size_t n)
{
    if (p == nullptr || n == 0) return;
    volatile unsigned char *vp = (volatile unsigned char *)p;
    for (size_t i = 0; i < n; i++) vp[i] = 0;
}

// ---------------------------------------------------------------------
// Small utilities: hex, base64, error reporting
// ---------------------------------------------------------------------

void die(const std::string &msg)
{
    // Never include secret material in error text -- callers of this
    // function must ensure msg contains no key/PIN bytes.
    std::cerr << "softhsm2-milenage: error: " << msg << "\n";
    std::exit(1);
}

std::string toHex(const std::vector<uint8_t> &v)
{
    static const char *h = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) { s.push_back(h[b >> 4]); s.push_back(h[b & 0xF]); }
    return s;
}

std::vector<uint8_t> fromHex(const std::string &s)
{
    std::vector<uint8_t> out;
    if (s.size() % 2 != 0) die("hex value has odd length");
    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back((uint8_t)strtol(s.substr(i, 2).c_str(), nullptr, 16));
    }
    return out;
}

std::string toBase64(const std::vector<uint8_t> &v)
{
    static const char *tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 3 <= v.size()) {
        uint32_t n = (v[i] << 16) | (v[i+1] << 8) | v[i+2];
        out.push_back(tbl[(n >> 18) & 0x3F]);
        out.push_back(tbl[(n >> 12) & 0x3F]);
        out.push_back(tbl[(n >> 6) & 0x3F]);
        out.push_back(tbl[n & 0x3F]);
        i += 3;
    }
    size_t rem = v.size() - i;
    if (rem == 1) {
        uint32_t n = v[i] << 16;
        out.push_back(tbl[(n >> 18) & 0x3F]);
        out.push_back(tbl[(n >> 12) & 0x3F]);
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (v[i] << 16) | (v[i+1] << 8);
        out.push_back(tbl[(n >> 18) & 0x3F]);
        out.push_back(tbl[(n >> 12) & 0x3F]);
        out.push_back(tbl[(n >> 6) & 0x3F]);
        out += "=";
    }
    return out;
}

int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<uint8_t> fromBase64(const std::string &s)
{
    std::vector<uint8_t> out;
    int vals[4]; int n = 0;
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = b64val(c);
        if (v < 0) continue;
        vals[n++] = v;
        if (n == 4) {
            out.push_back((uint8_t)((vals[0] << 2) | (vals[1] >> 4)));
            out.push_back((uint8_t)((vals[1] << 4) | (vals[2] >> 2)));
            out.push_back((uint8_t)((vals[2] << 6) | vals[3]));
            n = 0;
        }
    }
    if (n == 2) {
        out.push_back((uint8_t)((vals[0] << 2) | (vals[1] >> 4)));
    } else if (n == 3) {
        out.push_back((uint8_t)((vals[0] << 2) | (vals[1] >> 4)));
        out.push_back((uint8_t)((vals[1] << 4) | (vals[2] >> 2)));
    }
    return out;
}

std::string jsonEscape(const std::string &s)
{
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

// ---------------------------------------------------------------------
// Wire format helpers (design doc section 10)
// ---------------------------------------------------------------------

void appendTlv(std::vector<uint8_t> &v, uint16_t tag, const std::vector<uint8_t> &val)
{
    v.push_back((tag >> 8) & 0xFF); v.push_back(tag & 0xFF);
    uint32_t len = (uint32_t)val.size();
    v.push_back((len >> 24) & 0xFF); v.push_back((len >> 16) & 0xFF);
    v.push_back((len >> 8) & 0xFF); v.push_back(len & 0xFF);
    v.insert(v.end(), val.begin(), val.end());
}

std::vector<uint8_t> buildRequest(uint8_t op, const std::vector<std::pair<uint16_t, std::vector<uint8_t>>> &fields)
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

std::vector<std::pair<uint16_t, std::vector<uint8_t>>> parseFields(const std::vector<uint8_t> &r)
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

std::vector<uint8_t> field(const std::vector<std::pair<uint16_t, std::vector<uint8_t>>> &fs, uint16_t tag)
{
    for (auto &f : fs) if (f.first == tag) return f.second;
    return {};
}

// ---------------------------------------------------------------------
// Common CLI option parsing
// ---------------------------------------------------------------------

struct CommonOpts {
    std::string module;
    std::string tokenLabel;
    std::string tokenSerial;
    long slotId = -1;
    std::string pinFile;
    int pinFd = -1;
    std::string masterKeyLabel = SOFTHSM_MILENAGE_MASTER_KEY_LABEL;
    uint8_t masterKeyId = SOFTHSM_MILENAGE_MASTER_KEY_ID_BYTE;
    std::string transportKekLabel = SOFTHSM_MILENAGE_TRANSPORT_KEK_LABEL;
    uint8_t transportKekId = SOFTHSM_MILENAGE_TRANSPORT_KEK_ID_BYTE;
};

std::string readPin(const CommonOpts &opts)
{
    if (!opts.pinFile.empty()) {
        std::ifstream f(opts.pinFile);
        if (!f) die("could not open --pin-file");
        std::string pin;
        std::getline(f, pin);
        while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) pin.pop_back();
        return pin;
    }
    if (opts.pinFd >= 0) {
        char buf[256];
        ssize_t n = read(opts.pinFd, buf, sizeof(buf) - 1);
        if (n <= 0) die("could not read --pin-fd");
        buf[n] = 0;
        std::string pin(buf);
        secureWipe(buf, sizeof(buf));
        while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) pin.pop_back();
        return pin;
    }
    die("a PIN is required: use --pin-file or --pin-fd (never a literal --pin)");
    return "";
}

// ---------------------------------------------------------------------
// PKCS#11 session/module plumbing
// ---------------------------------------------------------------------

struct Pkcs11Context {
    void *dlHandle = nullptr;
    CK_FUNCTION_LIST_PTR fl = nullptr;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    ~Pkcs11Context()
    {
        if (fl != nullptr && session != CK_INVALID_HANDLE) {
            fl->C_Logout(session);
            fl->C_CloseSession(session);
        }
        if (fl != nullptr) fl->C_Finalize(NULL_PTR);
        if (dlHandle != nullptr) dlclose(dlHandle);
    }
};

CK_SLOT_ID resolveSlot(Pkcs11Context &ctx, const CommonOpts &opts)
{
    CK_SLOT_ID slots[256];
    CK_ULONG nslots = 256;
    if (ctx.fl->C_GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK)
        die("C_GetSlotList failed");

    if (!opts.tokenLabel.empty() || !opts.tokenSerial.empty()) {
        std::vector<CK_SLOT_ID> matches;
        for (CK_ULONG i = 0; i < nslots; i++) {
            CK_TOKEN_INFO info;
            if (ctx.fl->C_GetTokenInfo(slots[i], &info) != CKR_OK) continue;
            bool labelOk = opts.tokenLabel.empty();
            if (!labelOk) {
                std::string label((char*)info.label, sizeof(info.label));
                size_t trimmed = label.find_last_not_of(' ');
                label = (trimmed == std::string::npos) ? "" : label.substr(0, trimmed + 1);
                labelOk = (label == opts.tokenLabel);
            }
            bool serialOk = opts.tokenSerial.empty();
            if (!serialOk) {
                std::string serial((char*)info.serialNumber, sizeof(info.serialNumber));
                size_t trimmed = serial.find_last_not_of(' ');
                serial = (trimmed == std::string::npos) ? "" : serial.substr(0, trimmed + 1);
                serialOk = (serial == opts.tokenSerial);
            }
            if (labelOk && serialOk) matches.push_back(slots[i]);
        }
        if (matches.empty()) die("no token matched --token-label/--token-serial");
        if (matches.size() > 1) die("ambiguous token match for --token-label/--token-serial (refusing to guess)");
        return matches[0];
    }

    if (opts.slotId >= 0) {
        return (CK_SLOT_ID)opts.slotId;
    }

    die("a token must be identified with --token-label or --token-serial (--slot-id is an explicit override only)");
    return 0;
}

void openSession(Pkcs11Context &ctx, const CommonOpts &opts)
{
    ctx.dlHandle = dlopen(opts.module.c_str(), RTLD_NOW);
    if (ctx.dlHandle == nullptr) die("could not load --module: " + std::string(dlerror()));

    typedef CK_RV (*GetFunctionListFn)(CK_FUNCTION_LIST_PTR_PTR);
    GetFunctionListFn getFl = (GetFunctionListFn)dlsym(ctx.dlHandle, "C_GetFunctionList");
    if (getFl == nullptr || getFl(&ctx.fl) != CKR_OK) die("C_GetFunctionList failed");
    if (ctx.fl->C_Initialize(NULL_PTR) != CKR_OK) die("C_Initialize failed");

    CK_SLOT_ID slot = resolveSlot(ctx, opts);
    if (ctx.fl->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &ctx.session) != CKR_OK)
        die("C_OpenSession failed");

    std::string pin = readPin(opts);
    CK_RV rv = ctx.fl->C_Login(ctx.session, CKU_USER, (CK_UTF8CHAR_PTR)pin.data(), (CK_ULONG)pin.size());
    secureWipe(&pin[0], pin.size());
    if (rv != CKR_OK) die("C_Login failed");
}

CK_OBJECT_HANDLE findMasterKey(Pkcs11Context &ctx, const CommonOpts &opts)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_LABEL, (void*)opts.masterKeyLabel.data(), (CK_ULONG)opts.masterKeyLabel.size() },
        { CKA_ID, &const_cast<CommonOpts&>(opts).masterKeyId, 1 },
    };
    if (ctx.fl->C_FindObjectsInit(ctx.session, tmpl, 3) != CKR_OK) die("C_FindObjectsInit failed");
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    ctx.fl->C_FindObjects(ctx.session, &handle, 1, &count);
    CK_ULONG extraCount = 0;
    CK_OBJECT_HANDLE extra;
    ctx.fl->C_FindObjects(ctx.session, &extra, 1, &extraCount);
    ctx.fl->C_FindObjectsFinal(ctx.session);
    if (count != 1) die("expected exactly one Master Storage Key matching --master-key-label/--master-key-id, found none or ambiguous");
    if (extraCount != 0) die("ambiguous Master Storage Key match (refusing to guess)");
    return handle;
}

// Looks up the Transport KEK the same way findMasterKey() looks up the
// Master Storage Key -- by CKA_CLASS/CKA_LABEL/CKA_ID match, refusing
// to guess if none or more than one match. Distinct key, distinct
// label/id (--transport-kek-label/--transport-kek-id), used only for
// CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED (see
// import-transport-kek / import-transport-wrapped below).
CK_OBJECT_HANDLE findTransportKek(Pkcs11Context &ctx, const CommonOpts &opts)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_LABEL, (void*)opts.transportKekLabel.data(), (CK_ULONG)opts.transportKekLabel.size() },
        { CKA_ID, &const_cast<CommonOpts&>(opts).transportKekId, 1 },
    };
    if (ctx.fl->C_FindObjectsInit(ctx.session, tmpl, 3) != CKR_OK) die("C_FindObjectsInit failed");
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    ctx.fl->C_FindObjects(ctx.session, &handle, 1, &count);
    CK_ULONG extraCount = 0;
    CK_OBJECT_HANDLE extra;
    ctx.fl->C_FindObjects(ctx.session, &extra, 1, &extraCount);
    ctx.fl->C_FindObjectsFinal(ctx.session);
    if (count != 1) die("expected exactly one Transport KEK matching --transport-kek-label/--transport-kek-id, "
                         "found none or ambiguous (run import-transport-kek first)");
    if (extraCount != 0) die("ambiguous Transport KEK match (refusing to guess)");
    return handle;
}

std::vector<uint8_t> doSignWithParam(Pkcs11Context &ctx, CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key,
                                      void *pParameter, CK_ULONG parameterLen, const std::vector<uint8_t> &request)
{
    CK_MECHANISM m = { mech, pParameter, parameterLen };
    if (ctx.fl->C_SignInit(ctx.session, &m, key) != CKR_OK) die("C_SignInit failed (check mechanism support / key template / login)");
    CK_ULONG len = 0;
    if (ctx.fl->C_Sign(ctx.session, (CK_BYTE_PTR)request.data(), (CK_ULONG)request.size(), NULL_PTR, &len) != CKR_OK)
        die("C_Sign size query failed");
    std::vector<uint8_t> resp(len);
    CK_ULONG len2 = len;
    CK_RV rv = ctx.fl->C_Sign(ctx.session, (CK_BYTE_PTR)request.data(), (CK_ULONG)request.size(), resp.data(), &len2);
    if (rv == CKR_SIGNATURE_INVALID) die("operation failed: invalid MAC-S (resynchronization check failed)");
    if (rv != CKR_OK) die("C_Sign failed (invalid or cross-bound wrapped credential, or malformed request)");
    return resp;
}

std::vector<uint8_t> doSign(Pkcs11Context &ctx, CK_MECHANISM_TYPE mech, CK_OBJECT_HANDLE key, const std::vector<uint8_t> &request)
{
    return doSignWithParam(ctx, mech, key, NULL_PTR, 0, request);
}

// ---------------------------------------------------------------------
// Output file handling (design doc section 13: mode 0600, no silent overwrite)
// ---------------------------------------------------------------------

void writeOutputFile(const std::string &path, const std::string &content, bool force)
{
    int flags = O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL);
    int fd = open(path.c_str(), flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno == EEXIST) die("output file already exists: " + path + " (use --force to overwrite)");
        die("could not create output file: " + path);
    }
    ssize_t written = write(fd, content.data(), content.size());
    close(fd);
    if (written < 0 || (size_t)written != content.size()) die("short write to output file: " + path);
}

// ---------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------

void cmdCreateMasterKey(Pkcs11Context &ctx, const CommonOpts &opts)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG valueLen = SOFTHSM_MILENAGE_MASTER_KEY_VALUE_LEN;
    CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
    // CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED is included
    // unconditionally (not just under WITH_MILENAGE_TRANSPORT_IMPORT):
    // this list is baked into the key at creation time and CKA_MODIFIABLE
    // is FALSE, so it can never be added later without recreating the
    // Master Storage Key (and thus invalidating every already-wrapped
    // subscriber credential under it). If the server wasn't built with
    // that mechanism it simply won't recognize it -- harmless to list.
    CK_MECHANISM_TYPE allowed[] = {
        CKM_SOFTHSM_5G_HE_AV_WRAPPED,
        CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED,
        CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED,
        CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED,
    };
    CK_ATTRIBUTE tmpl[] = {
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
        { CKA_LABEL, (void*)opts.masterKeyLabel.data(), (CK_ULONG)opts.masterKeyLabel.size() },
        { CKA_ID, &const_cast<CommonOpts&>(opts).masterKeyId, 1 },
        { CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed) },
    };
    CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE handle;
    if (ctx.fl->C_GenerateKey(ctx.session, &genMech, tmpl, sizeof(tmpl)/sizeof(tmpl[0]), &handle) != CKR_OK)
        die("C_GenerateKey failed");
    std::cout << "{\"created\": true, \"label\": \"" << jsonEscape(opts.masterKeyLabel) << "\"}\n";
}

std::vector<uint8_t> readAllFd(int fd)
{
    std::vector<uint8_t> out;
    uint8_t buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        out.insert(out.end(), buf, buf + n);
    }
    secureWipe(buf, sizeof(buf));
    return out;
}

// Reads exactly 32 bytes (16-byte K || 16-byte OPc) of plaintext
// credential input from an already-open file descriptor (--input-fd)
// or, if none was given, from stdin. Never argv, never an environment
// variable -- see design doc section 4 / 8.
//
// This whole command is compiled only when the CLI itself is built
// with WITH_MILENAGE_PLAINTEXT_PROVISIONING (propagated from the
// CMake option of the same name onto this target -- see
// src/bin/milenage/CMakeLists.txt), on top of also requiring the
// explicit runtime --allow-plaintext-test-provisioning flag (checked
// in main()) and the server independently refusing
// CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED unless it was built the same
// way. Three independent gates, none of which is sufficient alone,
// per task item 7. The production path is `import-transport-wrapped`.
#ifdef WITH_MILENAGE_PLAINTEXT_PROVISIONING
void cmdProvision(Pkcs11Context &ctx, const CommonOpts &opts, const std::string &supi,
                   int inputFd, const std::string &outputPath, bool force)
{
    std::cerr << "WARNING: plaintext credential provisioning is a development/PoC-only mode.\n"
                 "WARNING: it is not appropriate for production use. Prefer 'import-transport-wrapped'.\n";

    int fd = (inputFd >= 0) ? inputFd : STDIN_FILENO;
    std::vector<uint8_t> input = readAllFd(fd);
    // Best-effort: attempt to keep the plaintext credential buffer out
    // of swap while it is held. mlock() can fail (e.g. no privilege,
    // no RLIMIT_MEMLOCK) -- that is not treated as fatal, since the
    // buffer is still explicitly zeroed on every path regardless.
    bool locked = !input.empty() && mlock(input.data(), input.size()) == 0;
    if (input.size() != 32) {
        secureWipe(input.data(), input.size());
        if (locked) munlock(input.data(), input.size());
        die("credential input must be exactly 32 bytes (16-byte K followed by 16-byte OPc)");
    }
    std::vector<uint8_t> plainK(input.begin(), input.begin() + 16);
    std::vector<uint8_t> plainOpc(input.begin() + 16, input.end());
    secureWipe(input.data(), input.size());
    if (locked) munlock(input.data(), input.size());

    CK_OBJECT_HANDLE masterKey = findMasterKey(ctx, opts);

    auto req = buildRequest(SOFTHSM_MILENAGE_OP_PROVISION, {
        {SOFTHSM_MILENAGE_TAG_SUPI, std::vector<uint8_t>(supi.begin(), supi.end())},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_K, plainK},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC, plainOpc},
    });
    secureWipe(plainK.data(), plainK.size());
    secureWipe(plainOpc.data(), plainOpc.size());

    std::vector<uint8_t> resp = doSign(ctx, CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED, masterKey, req);
    secureWipe(req.data(), req.size());

    auto fields = parseFields(resp);
    auto wrappedK = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K);
    auto wrappedOpc = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC);
    secureWipe(resp.data(), resp.size());
    if (wrappedK.empty() || wrappedOpc.empty()) die("provisioning response missing wrapped K/OPc");

    std::ostringstream json;
    json << "{\n"
         << "  \"hsm\": true,\n"
         << "  \"wrapped_k\": \"" << toBase64(wrappedK) << "\",\n"
         << "  \"wrapped_opc\": \"" << toBase64(wrappedOpc) << "\",\n"
         << "  \"k\": null,\n"
         << "  \"op\": null,\n"
         << "  \"opc\": null\n"
         << "}\n";

    if (outputPath.empty()) {
        std::cout << json.str();
    } else {
        writeOutputFile(outputPath, json.str(), force);
    }
}
#endif // WITH_MILENAGE_PLAINTEXT_PROVISIONING

void cmdGenerateAv(Pkcs11Context &ctx, const CommonOpts &opts, const std::string &supi,
                    const std::string &wrappedKB64, const std::string &wrappedOpcB64,
                    const std::string &sqnHex, const std::string &amfHex, const std::string &snn)
{
    CK_OBJECT_HANDLE masterKey = findMasterKey(ctx, opts);
    auto req = buildRequest(SOFTHSM_MILENAGE_OP_5G_HE_AV, {
        {SOFTHSM_MILENAGE_TAG_SUPI, std::vector<uint8_t>(supi.begin(), supi.end())},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, fromBase64(wrappedKB64)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, fromBase64(wrappedOpcB64)},
        {SOFTHSM_MILENAGE_TAG_SQN, fromHex(sqnHex)},
        {SOFTHSM_MILENAGE_TAG_AMF, fromHex(amfHex)},
        {SOFTHSM_MILENAGE_TAG_SNN, std::vector<uint8_t>(snn.begin(), snn.end())},
    });
    std::vector<uint8_t> resp = doSign(ctx, CKM_SOFTHSM_5G_HE_AV_WRAPPED, masterKey, req);
    auto fields = parseFields(resp);

    std::cout << "{\n"
              << "  \"rand\": \"" << toHex(field(fields, SOFTHSM_MILENAGE_TAG_OUT_RAND)) << "\",\n"
              << "  \"autn\": \"" << toHex(field(fields, SOFTHSM_MILENAGE_TAG_OUT_AUTN)) << "\",\n"
              << "  \"xres_star\": \"" << toHex(field(fields, SOFTHSM_MILENAGE_TAG_OUT_XRES_STAR)) << "\",\n"
              << "  \"kausf\": \"" << toHex(field(fields, SOFTHSM_MILENAGE_TAG_OUT_KAUSF)) << "\"\n"
              << "}\n";
}

void cmdResync(Pkcs11Context &ctx, const CommonOpts &opts, const std::string &supi,
               const std::string &wrappedKB64, const std::string &wrappedOpcB64,
               const std::string &randHex, const std::string &autsHex)
{
    CK_OBJECT_HANDLE masterKey = findMasterKey(ctx, opts);
    auto req = buildRequest(SOFTHSM_MILENAGE_OP_RESYNC, {
        {SOFTHSM_MILENAGE_TAG_SUPI, std::vector<uint8_t>(supi.begin(), supi.end())},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, fromBase64(wrappedKB64)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, fromBase64(wrappedOpcB64)},
        {SOFTHSM_MILENAGE_TAG_RAND, fromHex(randHex)},
        {SOFTHSM_MILENAGE_TAG_AUTS, fromHex(autsHex)},
    });
    std::vector<uint8_t> resp = doSign(ctx, CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED, masterKey, req);
    auto fields = parseFields(resp);
    std::cout << "{\n  \"sqn_ms\": \"" << toHex(field(fields, SOFTHSM_MILENAGE_TAG_OUT_SQN_MS)) << "\"\n}\n";
}

void cmdInspect(Pkcs11Context &ctx, const CommonOpts &opts)
{
    CK_OBJECT_HANDLE masterKey = findMasterKey(ctx, opts);
    CK_BBOOL extractable = CK_TRUE, sensitive = CK_FALSE;
    CK_ATTRIBUTE attrs[] = {
        { CKA_EXTRACTABLE, &extractable, sizeof(extractable) },
        { CKA_SENSITIVE, &sensitive, sizeof(sensitive) },
    };
    ctx.fl->C_GetAttributeValue(ctx.session, masterKey, attrs, 2);
    std::cout << "{\n"
              << "  \"found\": true,\n"
              << "  \"label\": \"" << jsonEscape(opts.masterKeyLabel) << "\",\n"
              << "  \"extractable\": " << (extractable ? "true" : "false") << ",\n"
              << "  \"sensitive\": " << (sensitive ? "true" : "false") << "\n"
              << "}\n";
}

// Imports an externally-generated 32-byte Transport KEK into the
// token as a non-extractable AES-256 secret key object. The KEK's raw
// value is never generated by this tool and never held by the HSM in
// exportable form after this call -- it must already exist outside
// this host (see contrib/systemd/external-scripts/generate-transport-kek.sh),
// since the same raw value is also needed by whatever external system
// wraps subscriber K/OPc under it before calling import-transport-wrapped.
// Once imported, CKA_EXTRACTABLE=FALSE means this HSM can use the KEK
// to unwrap incoming transport packages, but can never be asked to
// hand the KEK's value back out again.
void cmdImportTransportKek(Pkcs11Context &ctx, const CommonOpts &opts, int inputFd)
{
    int fd = (inputFd >= 0) ? inputFd : STDIN_FILENO;
    std::vector<uint8_t> kek = readAllFd(fd);
    bool locked = !kek.empty() && mlock(kek.data(), kek.size()) == 0;
    if (kek.size() != SOFTHSM_MILENAGE_TRANSPORT_KEK_VALUE_LEN) {
        secureWipe(kek.data(), kek.size());
        if (locked) munlock(kek.data(), kek.size());
        die("Transport KEK input must be exactly 32 bytes (AES-256)");
    }

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
    CK_MECHANISM_TYPE allowed[] = { CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE, kek.data(), (CK_ULONG)kek.size() },
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
        { CKA_LABEL, (void*)opts.transportKekLabel.data(), (CK_ULONG)opts.transportKekLabel.size() },
        { CKA_ID, &const_cast<CommonOpts&>(opts).transportKekId, 1 },
        { CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed) },
    };
    CK_OBJECT_HANDLE handle;
    CK_RV rv = ctx.fl->C_CreateObject(ctx.session, tmpl, sizeof(tmpl)/sizeof(tmpl[0]), &handle);
    secureWipe(kek.data(), kek.size());
    if (locked) munlock(kek.data(), kek.size());
    if (rv != CKR_OK) die("C_CreateObject failed (Transport KEK may already exist under this label/id)");
    std::cout << "{\"imported\": true, \"label\": \"" << jsonEscape(opts.transportKekLabel) << "\"}\n";
}

// Submits a package that was already wrapped under the Transport KEK
// by an external system (see contrib/systemd/external-scripts/
// wrap-transport-package.py) and receives back K/OPc re-wrapped under
// this token's Master Storage Key -- the same output shape `provision`
// produces, but without this process, or any process on this host,
// ever holding plaintext K/OPc. The HSM performs the unwrap-then-rewrap
// internally in one PKCS#11 call (CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED);
// see doc/MILENAGE-5G-AKA-DESIGN.md section 6.
void cmdImportTransportWrapped(Pkcs11Context &ctx, const CommonOpts &opts, const std::string &supi,
                                const std::string &transportWrappedKB64, const std::string &transportWrappedOpcB64,
                                const std::string &outputPath, bool force)
{
    CK_OBJECT_HANDLE transportKek = findTransportKek(ctx, opts);
    CK_OBJECT_HANDLE masterKey = findMasterKey(ctx, opts);

    auto req = buildRequest(SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT, {
        {SOFTHSM_MILENAGE_TAG_SUPI, std::vector<uint8_t>(supi.begin(), supi.end())},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K, fromBase64(transportWrappedKB64)},
        {SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC, fromBase64(transportWrappedOpcB64)},
    });

    CK_SOFTHSM_MILENAGE_TRANSPORT_IMPORT_PARAMS params = { masterKey };
    std::vector<uint8_t> resp = doSignWithParam(ctx, CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED, transportKek,
                                                 &params, sizeof(params), req);

    auto fields = parseFields(resp);
    auto wrappedK = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K);
    auto wrappedOpc = field(fields, SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC);
    secureWipe(resp.data(), resp.size());
    if (wrappedK.empty() || wrappedOpc.empty()) die("import-transport-wrapped response missing wrapped K/OPc");

    std::ostringstream json;
    json << "{\n"
         << "  \"hsm\": true,\n"
         << "  \"wrapped_k\": \"" << toBase64(wrappedK) << "\",\n"
         << "  \"wrapped_opc\": \"" << toBase64(wrappedOpc) << "\",\n"
         << "  \"k\": null,\n"
         << "  \"op\": null,\n"
         << "  \"opc\": null\n"
         << "}\n";

    if (outputPath.empty()) {
        std::cout << json.str();
    } else {
        writeOutputFile(outputPath, json.str(), force);
    }
}

// ---------------------------------------------------------------------
// Argument parsing / main
// ---------------------------------------------------------------------

void printUsage()
{
    std::cerr <<
        "usage: softhsm2-milenage <command> [options]\n"
        "commands:\n"
        "  create-master-key   Generate the token's AES-256 Master Storage Key\n"
        "  provision           Wrap plaintext K/OPc under the Master Storage Key\n"
        "                      (plaintext read only from --input-fd or stdin)\n"
        "                      WARNING: if this build has WITH_MILENAGE_PLAINTEXT_PROVISIONING,\n"
        "                      this command works independently of whether a Transport KEK is\n"
        "                      configured or used -- having import-transport-wrapped working does\n"
        "                      NOT disable this. Rebuild without that flag to remove it entirely.\n"
        "  generate-5g-av      Generate a 5G HE AV from wrapped K/OPc\n"
        "  resync              Verify AUTS and recover SQN_MS\n"
        "  inspect             Report non-secret info about the Master Storage Key\n"
        "  import-transport-kek     Import an externally-generated Transport KEK\n"
        "                            (32 raw bytes, from --input-fd or stdin)\n"
        "  import-transport-wrapped Submit K/OPc wrapped under the Transport KEK by\n"
        "                            an external system; returns K/OPc re-wrapped\n"
        "                            under the Master Storage Key (production path;\n"
        "                            see contrib/systemd/external-scripts/)\n"
        "common options:\n"
        "  --module <path> --token-label <label> --token-serial <serial>\n"
        "  --slot-id <id> --pin-file <path> --pin-fd <fd>\n"
        "  --master-key-label <label> --master-key-id <hex-byte>\n"
        "  --transport-kek-label <label> --transport-kek-id <hex-byte>\n"
        "provision options (development/PoC only -- requires a build with\n"
        "  WITH_MILENAGE_PLAINTEXT_PROVISIONING; prefer import-transport-wrapped):\n"
        "  --supi <imsi-...> --input-fd <fd> --output <path> --force\n"
        "  --allow-plaintext-test-provisioning   (required, no default)\n"
        "generate-5g-av / resync options:\n"
        "  --supi <imsi-...> --wrapped-k <base64> --wrapped-opc <base64>\n"
        "  --sqn <hex12> --amf <hex4> --snn <string>   (generate-5g-av)\n"
        "  --rand <hex32> --auts <hex28>                (resync)\n"
        "import-transport-kek options:\n"
        "  --input-fd <fd>   (32 raw bytes; stdin if omitted)\n"
        "import-transport-wrapped options:\n"
        "  --supi <imsi-...> --transport-wrapped-k <base64> --transport-wrapped-opc <base64>\n"
        "  --output <path> --force\n"
        "No --k, --opc, or literal --pin option exists in this tool.\n";
}

std::string requireArg(int argc, char **argv, int &i)
{
    if (i + 1 >= argc) die(std::string("missing value for ") + argv[i]);
    return argv[++i];
}

} // namespace

int main(int argc, char **argv)
{
    hardenProcess();

    if (argc < 2) { printUsage(); return 2; }
    std::string command = argv[1];

    CommonOpts opts;
    std::string supi, wrappedK, wrappedOpc, sqnHex, amfHex, snn, randHex, autsHex, outputPath;
    std::string transportWrappedK, transportWrappedOpc;
    int inputFd = -1;
    bool force = false;
    bool allowPlaintextTestProvisioning = false;

    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--module") opts.module = requireArg(argc, argv, i);
        else if (a == "--token-label") opts.tokenLabel = requireArg(argc, argv, i);
        else if (a == "--token-serial") opts.tokenSerial = requireArg(argc, argv, i);
        else if (a == "--slot-id") opts.slotId = strtol(requireArg(argc, argv, i).c_str(), nullptr, 10);
        else if (a == "--pin-file") opts.pinFile = requireArg(argc, argv, i);
        else if (a == "--pin-fd") opts.pinFd = (int)strtol(requireArg(argc, argv, i).c_str(), nullptr, 10);
        else if (a == "--master-key-label") opts.masterKeyLabel = requireArg(argc, argv, i);
        else if (a == "--master-key-id") opts.masterKeyId = (uint8_t)strtol(requireArg(argc, argv, i).c_str(), nullptr, 16);
        else if (a == "--transport-kek-label") opts.transportKekLabel = requireArg(argc, argv, i);
        else if (a == "--transport-kek-id") opts.transportKekId = (uint8_t)strtol(requireArg(argc, argv, i).c_str(), nullptr, 16);
        else if (a == "--transport-wrapped-k") transportWrappedK = requireArg(argc, argv, i);
        else if (a == "--transport-wrapped-opc") transportWrappedOpc = requireArg(argc, argv, i);
        else if (a == "--supi") supi = requireArg(argc, argv, i);
        else if (a == "--wrapped-k") wrappedK = requireArg(argc, argv, i);
        else if (a == "--wrapped-opc") wrappedOpc = requireArg(argc, argv, i);
        else if (a == "--sqn") sqnHex = requireArg(argc, argv, i);
        else if (a == "--amf") amfHex = requireArg(argc, argv, i);
        else if (a == "--snn") snn = requireArg(argc, argv, i);
        else if (a == "--rand") randHex = requireArg(argc, argv, i);
        else if (a == "--auts") autsHex = requireArg(argc, argv, i);
        else if (a == "--input-fd") inputFd = (int)strtol(requireArg(argc, argv, i).c_str(), nullptr, 10);
        else if (a == "--output") outputPath = requireArg(argc, argv, i);
        else if (a == "--force") force = true;
        else if (a == "--allow-plaintext-test-provisioning") allowPlaintextTestProvisioning = true;
        else if (a == "--pin" || a == "--k" || a == "--opc") die("option " + a + " is refused for security reasons (see design doc section 4/8)");
        else die("unknown option: " + a);
    }

    if (opts.module.empty()) die("--module is required");

    Pkcs11Context ctx;
    openSession(ctx, opts);

    if (command == "create-master-key") {
        cmdCreateMasterKey(ctx, opts);
    } else if (command == "provision") {
#ifdef WITH_MILENAGE_PLAINTEXT_PROVISIONING
        if (supi.empty()) die("--supi is required");
        if (!allowPlaintextTestProvisioning)
            die("plaintext provisioning requires the explicit --allow-plaintext-test-provisioning flag; "
                "prefer 'import-transport-wrapped' for production use");
        cmdProvision(ctx, opts, supi, inputFd, outputPath, force);
#else
        (void)allowPlaintextTestProvisioning;
        die("this build does not include plaintext provisioning (WITH_MILENAGE_PLAINTEXT_PROVISIONING was not "
            "enabled); use 'import-transport-wrapped' instead");
#endif
    } else if (command == "generate-5g-av") {
        if (supi.empty() || wrappedK.empty() || wrappedOpc.empty() || sqnHex.empty() || amfHex.empty() || snn.empty())
            die("--supi, --wrapped-k, --wrapped-opc, --sqn, --amf, --snn are all required");
        cmdGenerateAv(ctx, opts, supi, wrappedK, wrappedOpc, sqnHex, amfHex, snn);
    } else if (command == "resync") {
        if (supi.empty() || wrappedK.empty() || wrappedOpc.empty() || randHex.empty() || autsHex.empty())
            die("--supi, --wrapped-k, --wrapped-opc, --rand, --auts are all required");
        cmdResync(ctx, opts, supi, wrappedK, wrappedOpc, randHex, autsHex);
    } else if (command == "inspect") {
        cmdInspect(ctx, opts);
    } else if (command == "import-transport-kek") {
        cmdImportTransportKek(ctx, opts, inputFd);
    } else if (command == "import-transport-wrapped") {
        if (supi.empty() || transportWrappedK.empty() || transportWrappedOpc.empty())
            die("--supi, --transport-wrapped-k, --transport-wrapped-opc are all required");
        cmdImportTransportWrapped(ctx, opts, supi, transportWrappedK, transportWrappedOpc, outputPath, force);
    } else if (command == "create-transport-kek") {
        die("command 'create-transport-kek' does not exist -- generating a Transport KEK inside the "
            "HSM would make it CKA_EXTRACTABLE=FALSE immediately, so no external system could ever "
            "wrap anything with the same value. Generate the KEK externally and use 'import-transport-kek' "
            "instead (see contrib/systemd/external-scripts/generate-transport-kek.sh).");
    } else {
        printUsage();
        return 2;
    }

    return 0;
}
