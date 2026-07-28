/*
 * softhsm2-milenaged: plain-TCP network front-end for the Milenage /
 * 5G-AKA vendor PKCS#11 mechanisms, so a 5G core component (e.g. an
 * Open5GS UDM) running on a different host/VM than SoftHSM can reach
 * it. See doc/MILENAGE-5G-AKA-DESIGN.md section 21.
 *
 * Model: this daemon dlopen's the PKCS#11 module in its own process
 * (same as softhsm2-milenage), logs in once at startup, and keeps one
 * PKCS#11 session + the Master Storage Key handle (and, if built with
 * WITH_MILENAGE_TRANSPORT_IMPORT, the Transport KEK handle) open for
 * its whole lifetime. It accepts TCP connections and, for each
 * connection, reads and answers a sequence of daemon-framed requests
 * until the client disconnects. One connection at a time is processed
 * (the PKCS#11 session is not safe to share across concurrent
 * C_SignInit/C_Sign pairs) -- this matches the "1 UDM : 1 HSM" model
 * this was built for; it is not designed to fan out to many
 * concurrent clients.
 *
 * *** SECURITY WARNING ***
 * This is a PLAINTEXT, UNAUTHENTICATED TCP service. There is no TLS,
 * no client authentication, and no integrity protection on the wire
 * beyond what AES-KWP already provides for the wrapped-credential
 * payloads themselves. Anyone who can reach the listening ip:port can
 * request AVs/resync for any wrapped credential they can supply, and
 * can observe every request/response on the wire. This is acceptable
 * ONLY on a network segment that is already fully trusted (e.g. a
 * private VLAN between the UDM host and the HSM host with no other
 * tenants), exactly the same trust assumption SoftHSMv2 already makes
 * about its host process (design doc section 3). Do not expose this
 * port on any network you would not also expose the Master Storage
 * Key on directly. TLS/mTLS is explicitly out of scope for this
 * iteration by request; add it before using this outside a fully
 * trusted network.
 *
 * The plaintext-provisioning operation (CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED,
 * which carries raw K/OPc bytes on the wire) is UNCONDITIONALLY
 * REFUSED by this daemon regardless of build flags -- see
 * handleRequest() below. Sending plaintext K/OPc over an
 * unauthenticated TCP socket is not an acceptable tradeoff at any
 * configuration. Use `softhsm2-milenage provision` locally on the HSM
 * host (or, once implemented end to end, `import-transport-wrapped`)
 * for provisioning instead.
 *
 * Daemon TCP framing (distinct from, and wrapping, the S5GM wire
 * format the PKCS#11 mechanisms themselves speak -- see
 * softhsm_milenage.h):
 *
 *   request  := <S5GM message>                      (client -> daemon)
 *   response := u32be payload_len | u8 status | payload   (daemon -> client)
 *                 status 0 = OK,    payload = an S5GM response message
 *                 status 1 = ERROR, payload = short UTF-8 error text (no secrets)
 *
 * The request has no outer daemon framing because the S5GM header
 * itself is self-describing (magic + total_length at fixed offsets),
 * so the daemon reads the 12-byte header first, then exactly
 * total_length-12 more bytes.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

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

void die(const std::string &msg)
{
    std::cerr << "softhsm2-milenaged: error: " << msg << "\n";
    std::exit(1);
}

void logInfo(const std::string &msg)
{
    std::cerr << "softhsm2-milenaged: " << msg << "\n";
}

// ---------------------------------------------------------------------
// PKCS#11 plumbing (same approach as softhsm2-milenage.cpp)
// ---------------------------------------------------------------------

struct Options {
    std::string module;
    std::string tokenLabel;
    std::string tokenSerial;
    long slotId = -1;
    std::string pinFile;
    int pinFd = -1;
    std::string masterKeyLabel = SOFTHSM_MILENAGE_MASTER_KEY_LABEL;
    uint8_t masterKeyId = SOFTHSM_MILENAGE_MASTER_KEY_ID_BYTE;
#ifdef WITH_MILENAGE_TRANSPORT_IMPORT
    std::string transportKekLabel = SOFTHSM_MILENAGE_TRANSPORT_KEK_LABEL;
    uint8_t transportKekId = SOFTHSM_MILENAGE_TRANSPORT_KEK_ID_BYTE;
#endif
    std::string listenAddr = "127.0.0.1";
    int listenPort = -1;
};

std::string readPin(const Options &opts)
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
        memset(buf, 0, sizeof(buf));
        while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) pin.pop_back();
        return pin;
    }
    die("a PIN is required: use --pin-file or --pin-fd");
    return "";
}

struct Pkcs11Context {
    void *dlHandle = nullptr;
    CK_FUNCTION_LIST_PTR fl = nullptr;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE masterKeyHandle = CK_INVALID_HANDLE;
#ifdef WITH_MILENAGE_TRANSPORT_IMPORT
    CK_OBJECT_HANDLE transportKekHandle = CK_INVALID_HANDLE;
    bool haveTransportKek = false;
#endif
};

CK_SLOT_ID resolveSlot(Pkcs11Context &ctx, const Options &opts)
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
    if (opts.slotId >= 0) return (CK_SLOT_ID)opts.slotId;
    die("a token must be identified with --token-label or --token-serial");
    return 0;
}

CK_OBJECT_HANDLE findKeyByLabelId(Pkcs11Context &ctx, const std::string &label, uint8_t id)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_LABEL, (void*)label.data(), (CK_ULONG)label.size() },
        { CKA_ID, &id, 1 },
    };
    if (ctx.fl->C_FindObjectsInit(ctx.session, tmpl, 3) != CKR_OK) die("C_FindObjectsInit failed");
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    ctx.fl->C_FindObjects(ctx.session, &handle, 1, &count);
    CK_ULONG extraCount = 0;
    CK_OBJECT_HANDLE extra;
    ctx.fl->C_FindObjects(ctx.session, &extra, 1, &extraCount);
    ctx.fl->C_FindObjectsFinal(ctx.session);
    if (count != 1 || extraCount != 0) die("expected exactly one key matching label/id, found none or ambiguous");
    return handle;
}

void setupPkcs11(Pkcs11Context &ctx, const Options &opts)
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
    if (!pin.empty()) memset(&pin[0], 0, pin.size());
    if (rv != CKR_OK) die("C_Login failed");

    ctx.masterKeyHandle = findKeyByLabelId(ctx, opts.masterKeyLabel, opts.masterKeyId);
    logInfo("logged in, Master Storage Key found (label=" + opts.masterKeyLabel + ")");

#ifdef WITH_MILENAGE_TRANSPORT_IMPORT
    // Optional: only required if a transport-import request actually
    // arrives. Looked up eagerly here anyway so a misconfiguration is
    // caught at startup rather than on the first request.
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_LABEL, (void*)opts.transportKekLabel.data(), (CK_ULONG)opts.transportKekLabel.size() },
        { CKA_ID, &const_cast<Options&>(opts).transportKekId, 1 },
    };
    if (ctx.fl->C_FindObjectsInit(ctx.session, tmpl, 3) == CKR_OK) {
        CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
        CK_ULONG count = 0;
        ctx.fl->C_FindObjects(ctx.session, &handle, 1, &count);
        ctx.fl->C_FindObjectsFinal(ctx.session);
        if (count == 1) {
            ctx.transportKekHandle = handle;
            ctx.haveTransportKek = true;
            logInfo("Transport KEK found (label=" + opts.transportKekLabel + ")");
        } else {
            logInfo("no Transport KEK found -- transport-import requests will be refused");
        }
    }
#endif
}

// ---------------------------------------------------------------------
// Wire-level helpers
// ---------------------------------------------------------------------

uint32_t readU32BE(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool readExact(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

bool writeExact(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

void sendDaemonFrame(int fd, uint8_t status, const std::vector<uint8_t> &payload)
{
    uint32_t len = (uint32_t)payload.size();
    uint8_t header[5];
    header[0] = (uint8_t)((len >> 24) & 0xFF);
    header[1] = (uint8_t)((len >> 16) & 0xFF);
    header[2] = (uint8_t)((len >> 8) & 0xFF);
    header[3] = (uint8_t)(len & 0xFF);
    header[4] = status;
    if (!writeExact(fd, header, sizeof(header))) return;
    if (!payload.empty()) writeExact(fd, payload.data(), payload.size());
}

void sendError(int fd, const std::string &msg)
{
    sendDaemonFrame(fd, 1, std::vector<uint8_t>(msg.begin(), msg.end()));
}

// ---------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------

CK_RV doSign(Pkcs11Context &ctx, CK_MECHANISM &mech, CK_OBJECT_HANDLE key,
             const std::vector<uint8_t> &request, std::vector<uint8_t> &response)
{
    if (ctx.fl->C_SignInit(ctx.session, &mech, key) != CKR_OK) return CKR_GENERAL_ERROR;
    CK_ULONG len = 0;
    CK_RV rv = ctx.fl->C_Sign(ctx.session, (CK_BYTE_PTR)request.data(), (CK_ULONG)request.size(), NULL_PTR, &len);
    if (rv != CKR_OK) return rv;
    response.assign(len, 0);
    CK_ULONG len2 = len;
    return ctx.fl->C_Sign(ctx.session, (CK_BYTE_PTR)request.data(), (CK_ULONG)request.size(), response.data(), &len2);
}

// Handles exactly one S5GM request read from the connection and
// writes exactly one daemon-framed response. Returns false if the
// connection should be closed (I/O error).
bool handleRequest(Pkcs11Context &ctx, int connFd)
{
    uint8_t header[12];
    if (!readExact(connFd, header, sizeof(header))) return false;

    if (memcmp(header, SOFTHSM_MILENAGE_WIRE_MAGIC, 4) != 0) {
        sendError(connFd, "bad magic");
        return false; // desynchronized framing, must close
    }
    uint32_t totalLen = readU32BE(header + 8);
    if (totalLen < sizeof(header) || totalLen > SOFTHSM_MILENAGE_MAX_REQUEST_LEN) {
        sendError(connFd, "invalid request length");
        return false;
    }

    std::vector<uint8_t> request(totalLen);
    memcpy(request.data(), header, sizeof(header));
    if (totalLen > sizeof(header)) {
        if (!readExact(connFd, request.data() + sizeof(header), totalLen - sizeof(header))) return false;
    }

    uint8_t operation = header[5];

    // Plaintext provisioning is never accepted over this network
    // daemon, regardless of build flags -- see file header.
    if (operation == SOFTHSM_MILENAGE_OP_PROVISION) {
        sendError(connFd, "plaintext provisioning is not available over the network daemon; "
                           "use softhsm2-milenage locally on the HSM host, or transport-wrapped import");
        return true;
    }

    CK_MECHANISM mech = { 0, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
#ifdef WITH_MILENAGE_TRANSPORT_IMPORT
    CK_SOFTHSM_MILENAGE_TRANSPORT_IMPORT_PARAMS transportParams;
#endif

    switch (operation) {
        case SOFTHSM_MILENAGE_OP_5G_HE_AV:
            mech.mechanism = CKM_SOFTHSM_5G_HE_AV_WRAPPED;
            key = ctx.masterKeyHandle;
            break;
        case SOFTHSM_MILENAGE_OP_RESYNC:
            mech.mechanism = CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED;
            key = ctx.masterKeyHandle;
            break;
#ifdef WITH_MILENAGE_TRANSPORT_IMPORT
        case SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT:
            if (!ctx.haveTransportKek) {
                sendError(connFd, "no Transport KEK configured on this daemon");
                return true;
            }
            transportParams.masterKeyHandle = ctx.masterKeyHandle;
            mech.mechanism = CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED;
            mech.pParameter = &transportParams;
            mech.ulParameterLen = sizeof(transportParams);
            key = ctx.transportKekHandle;
            break;
#endif
        default:
            sendError(connFd, "unsupported or unrecognized operation for this daemon");
            return true;
    }

    std::vector<uint8_t> response;
    CK_RV rv = doSign(ctx, mech, key, request, response);
    if (rv == CKR_SIGNATURE_INVALID) {
        sendError(connFd, "signature invalid (resynchronization check failed)");
        return true;
    }
    if (rv != CKR_OK) {
        sendError(connFd, "operation failed");
        return true;
    }

    sendDaemonFrame(connFd, 0, response);
    if (!response.empty()) memset(response.data(), 0, response.size());
    return true;
}

void printUsage()
{
    std::cerr <<
        "usage: softhsm2-milenaged --module <path> --token-label <label> \\\n"
        "         --pin-file <path> --listen-port <port> [--listen-addr <ip>] \\\n"
        "         [--master-key-label <label>] [--master-key-id <hex-byte>]\n"
#ifdef WITH_MILENAGE_TRANSPORT_IMPORT
        "         [--transport-kek-label <label>] [--transport-kek-id <hex-byte>]\n"
#endif
        "\n"
        "SECURITY WARNING: plaintext, unauthenticated TCP. Only run on a fully\n"
        "trusted network segment. See the file header comment for detail.\n";
}

} // namespace

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    Options opts;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) die("missing value for " + a);
            return argv[++i];
        };
        if (a == "--module") opts.module = next();
        else if (a == "--token-label") opts.tokenLabel = next();
        else if (a == "--token-serial") opts.tokenSerial = next();
        else if (a == "--slot-id") opts.slotId = strtol(next().c_str(), nullptr, 10);
        else if (a == "--pin-file") opts.pinFile = next();
        else if (a == "--pin-fd") opts.pinFd = (int)strtol(next().c_str(), nullptr, 10);
        else if (a == "--master-key-label") opts.masterKeyLabel = next();
        else if (a == "--master-key-id") opts.masterKeyId = (uint8_t)strtol(next().c_str(), nullptr, 16);
#ifdef WITH_MILENAGE_TRANSPORT_IMPORT
        else if (a == "--transport-kek-label") opts.transportKekLabel = next();
        else if (a == "--transport-kek-id") opts.transportKekId = (uint8_t)strtol(next().c_str(), nullptr, 16);
#endif
        else if (a == "--listen-addr") opts.listenAddr = next();
        else if (a == "--listen-port") opts.listenPort = (int)strtol(next().c_str(), nullptr, 10);
        else if (a == "--pin") die("--pin is refused for security reasons; use --pin-file or --pin-fd");
        else { printUsage(); die("unknown option: " + a); }
    }

    if (opts.module.empty() || opts.listenPort < 0) { printUsage(); die("--module and --listen-port are required"); }

    Pkcs11Context ctx;
    setupPkcs11(ctx, opts);

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) die("socket() failed");
    int one = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)opts.listenPort);
    if (inet_pton(AF_INET, opts.listenAddr.c_str(), &addr.sin_addr) != 1)
        die("invalid --listen-addr");

    if (bind(listenFd, (struct sockaddr*)&addr, sizeof(addr)) != 0) die("bind() failed");
    if (listen(listenFd, 16) != 0) die("listen() failed");

    logInfo("listening on " + opts.listenAddr + ":" + std::to_string(opts.listenPort) +
            " (PLAINTEXT TCP, no TLS -- trusted-network-only, see file header)");

    for (;;) {
        struct sockaddr_in peer;
        socklen_t peerLen = sizeof(peer);
        int connFd = accept(listenFd, (struct sockaddr*)&peer, &peerLen);
        if (connFd < 0) continue;

        int noDelay = 1;
        setsockopt(connFd, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay));

        char peerStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, peerStr, sizeof(peerStr));
        logInfo(std::string("connection from ") + peerStr + ":" + std::to_string(ntohs(peer.sin_port)));

        while (handleRequest(ctx, connFd)) {
            // keep serving requests on this connection until it closes
            // or a framing error forces a close.
        }
        close(connFd);
        logInfo("connection closed");
    }

    return 0;
}
