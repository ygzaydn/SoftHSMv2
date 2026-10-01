// End-to-end test for softhsm-gsm over a real TCP connection.
// Does NOT start the daemon itself -- see
// src/lib/milenage/test/run_daemon_ctest.sh, which provisions a
// token, starts the daemon in the background, runs this client
// against 127.0.0.1:<port>, and tears everything down. Speaks the
// daemon TCP framing documented in softhsm-gsm.cpp's header
// comment (u32be length | u8 status | payload), wrapping the same
// S5GM wire format used everywhere else in this codebase.

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

static std::vector<uint8_t> fromHex(const std::string &s)
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back((uint8_t)strtol(s.substr(i, 2).c_str(), nullptr, 16));
    }
    return out;
}
static std::vector<uint8_t> fromBase64(const std::string &s)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    int vals[4]; int n = 0;
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = val(c);
        if (v < 0) continue;
        vals[n++] = v;
        if (n == 4) {
            out.push_back((uint8_t)((vals[0] << 2) | (vals[1] >> 4)));
            out.push_back((uint8_t)((vals[1] << 4) | (vals[2] >> 2)));
            out.push_back((uint8_t)((vals[2] << 6) | vals[3]));
            n = 0;
        }
    }
    if (n == 2) out.push_back((uint8_t)((vals[0] << 2) | (vals[1] >> 4)));
    else if (n == 3) {
        out.push_back((uint8_t)((vals[0] << 2) | (vals[1] >> 4)));
        out.push_back((uint8_t)((vals[1] << 4) | (vals[2] >> 2)));
    }
    return out;
}

// --- TCP client with the daemon framing ---

static int connectTo(const std::string &host, int port)
{
    if (host.compare(0, 5, "unix:") == 0) {
        std::string path = host.substr(5);
        struct sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;
        if (path.size() >= sizeof(addr.sun_path)) return -1;
        memcpy(addr.sun_path, path.c_str(), path.size() + 1);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
        return fd;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    return fd;
}

static bool readExact(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

// Sends an S5GM request, reads back the daemon-framed response.
// status: 0 on success, 1 on daemon-reported error. Returns false on
// a transport-level failure (connection dropped etc).
static bool roundTrip(int fd, const std::vector<uint8_t> &request, uint8_t &status, std::vector<uint8_t> &payload)
{
    ssize_t sent = 0;
    while (sent < (ssize_t)request.size()) {
        ssize_t n = write(fd, request.data() + sent, request.size() - sent);
        if (n <= 0) return false;
        sent += n;
    }
    uint8_t header[5];
    if (!readExact(fd, header, sizeof(header))) return false;
    uint32_t len = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) | ((uint32_t)header[2] << 8) | header[3];
    status = header[4];
    payload.assign(len, 0);
    if (len > 0 && !readExact(fd, payload.data(), len)) return false;
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 6) {
        fprintf(stderr, "usage: %s <host> <port> <supi> <wrapped_k_b64> <wrapped_opc_b64>\n", argv[0]);
        return 2;
    }
    std::string host = argv[1];
    int port = atoi(argv[2]);
    std::string supi = argv[3];
    auto wrappedK = fromBase64(argv[4]);
    auto wrappedOpc = fromBase64(argv[5]);

    // --- 5G HE AV over TCP ---
    int fd = connectTo(host, port);
    CHECK(fd >= 0, "TCP connect to daemon");
    if (fd < 0) { printf("\n%d failure(s)\n", failures); return 1; }

    uint8_t sqn[6] = {0xff,0x9b,0xb4,0xd0,0xb6,0x07};
    uint8_t amf[2] = {0xb9,0xb9};
    std::string snn = "5G:mnc001.mcc001.3gppnetwork.org";
    auto avReq = buildRequest(SOFTHSM_MILENAGE_OP_5G_HE_AV, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_SQN, std::vector<uint8_t>(sqn, sqn+6)},
        {SOFTHSM_MILENAGE_TAG_AMF, std::vector<uint8_t>(amf, amf+2)},
        {SOFTHSM_MILENAGE_TAG_SNN, s2v(snn)},
    });
    uint8_t status; std::vector<uint8_t> payload;
    CHECK(roundTrip(fd, avReq, status, payload), "AV request round trip over TCP");
    CHECK(status == 0, "AV request succeeds (daemon status OK)");
    auto fields = parseFields(payload);
    CHECK(field(fields, SOFTHSM_MILENAGE_TAG_OUT_RAND).size() == 16, "AV response RAND is 16 bytes");
    CHECK(field(fields, SOFTHSM_MILENAGE_TAG_OUT_AUTN).size() == 16, "AV response AUTN is 16 bytes");
    CHECK(field(fields, SOFTHSM_MILENAGE_TAG_OUT_XRES_STAR).size() == 16, "AV response XRES* is 16 bytes");
    CHECK(field(fields, SOFTHSM_MILENAGE_TAG_OUT_KAUSF).size() == 32, "AV response KAUSF is 32 bytes");

    // --- multiple requests on the same connection ---
    uint8_t status2; std::vector<uint8_t> payload2;
    CHECK(roundTrip(fd, avReq, status2, payload2), "second AV request on the same TCP connection");
    CHECK(status2 == 0, "second AV request succeeds");
    auto fields2 = parseFields(payload2);
    CHECK(field(fields, SOFTHSM_MILENAGE_TAG_OUT_RAND) != field(fields2, SOFTHSM_MILENAGE_TAG_OUT_RAND),
          "fresh RAND per request over the daemon (RNG actually used, not cached)");

    // --- resync with a garbage AUTS: daemon must report signature-invalid status ---
    uint8_t randFixed[16]; for (int i=0;i<16;i++) randFixed[i]=(uint8_t)(0x10+i);
    uint8_t garbageAuts[14]; for (int i=0;i<14;i++) garbageAuts[i]=(uint8_t)(0xAA ^ i);
    auto resyncReq = buildRequest(SOFTHSM_MILENAGE_OP_RESYNC, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_K, wrappedK},
        {SOFTHSM_MILENAGE_TAG_WRAPPED_OPC, wrappedOpc},
        {SOFTHSM_MILENAGE_TAG_RAND, std::vector<uint8_t>(randFixed, randFixed+16)},
        {SOFTHSM_MILENAGE_TAG_AUTS, std::vector<uint8_t>(garbageAuts, garbageAuts+14)},
    });
    uint8_t status3; std::vector<uint8_t> payload3;
    CHECK(roundTrip(fd, resyncReq, status3, payload3), "resync request round trip over TCP");
    CHECK(status3 == 1, "resync with invalid AUTS reports daemon error status");

    // --- plaintext provisioning must be refused unconditionally over the daemon ---
    uint8_t plainK[16] = {0}; uint8_t plainOpc[16] = {0};
    auto provReq = buildRequest(SOFTHSM_MILENAGE_OP_PROVISION, {
        {SOFTHSM_MILENAGE_TAG_SUPI, s2v(supi)},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_K, std::vector<uint8_t>(plainK, plainK+16)},
        {SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC, std::vector<uint8_t>(plainOpc, plainOpc+16)},
    });
    uint8_t status4; std::vector<uint8_t> payload4;
    CHECK(roundTrip(fd, provReq, status4, payload4), "provision request round trip over TCP");
    CHECK(status4 == 1, "plaintext provisioning is refused by the daemon regardless of build flags");
    std::string errMsg(payload4.begin(), payload4.end());
    CHECK(errMsg.find("plaintext") != std::string::npos, "provisioning refusal message explains why (no secrets in it)");

    close(fd);
    printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
