#include "WireCodec.h"

#include <cstring>
#include <set>

namespace milenage_wire {

namespace {

constexpr size_t HEADER_LEN = 4 /*magic*/ + 1 /*version*/ + 1 /*operation*/ + 2 /*reserved*/ + 4 /*total_length*/;
constexpr size_t TLV_HEADER_LEN = 2 /*tag*/ + 4 /*length*/;

uint32_t readU32BE(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t readU16BE(const uint8_t *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

void writeU32BE(std::vector<uint8_t> &out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void writeU16BE(std::vector<uint8_t> &out, uint16_t v)
{
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

/* All tags this codec version understands. A tag not in this set is a
 * hard parse failure -- there is no "optional/non-critical" tag range
 * defined yet. */
bool isKnownTag(uint16_t tag)
{
    static const std::set<uint16_t> known = {
        SOFTHSM_MILENAGE_TAG_SUPI,
        SOFTHSM_MILENAGE_TAG_WRAPPED_K,
        SOFTHSM_MILENAGE_TAG_WRAPPED_OPC,
        SOFTHSM_MILENAGE_TAG_SQN,
        SOFTHSM_MILENAGE_TAG_AMF,
        SOFTHSM_MILENAGE_TAG_SNN,
        SOFTHSM_MILENAGE_TAG_RAND,
        SOFTHSM_MILENAGE_TAG_AUTS,
        SOFTHSM_MILENAGE_TAG_PLAINTEXT_K,
        SOFTHSM_MILENAGE_TAG_PLAINTEXT_OPC,
        SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_K,
        SOFTHSM_MILENAGE_TAG_TRANSPORT_WRAPPED_OPC,
        SOFTHSM_MILENAGE_TAG_OUT_RAND,
        SOFTHSM_MILENAGE_TAG_OUT_AUTN,
        SOFTHSM_MILENAGE_TAG_OUT_XRES_STAR,
        SOFTHSM_MILENAGE_TAG_OUT_KAUSF,
        SOFTHSM_MILENAGE_TAG_OUT_SQN_MS,
        SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_K,
        SOFTHSM_MILENAGE_TAG_OUT_WRAPPED_OPC,
    };
    return known.count(tag) != 0;
}

bool isValidOperation(uint8_t op)
{
    switch (op) {
        case SOFTHSM_MILENAGE_OP_PROVISION:
        case SOFTHSM_MILENAGE_OP_5G_HE_AV:
        case SOFTHSM_MILENAGE_OP_RESYNC:
        case SOFTHSM_MILENAGE_OP_IMPORT_TRANSPORT:
        case SOFTHSM_MILENAGE_OP_RAW_TEST:
            return true;
        default:
            return false;
    }
}

} // namespace

Error parseRequest(const uint8_t *data, size_t len, Request &out)
{
    if (len > SOFTHSM_MILENAGE_MAX_REQUEST_LEN) {
        return Error::TOO_LARGE;
    }
    if (len < HEADER_LEN) {
        return Error::TRUNCATED;
    }
    if (std::memcmp(data, SOFTHSM_MILENAGE_WIRE_MAGIC, 4) != 0) {
        return Error::BAD_MAGIC;
    }
    uint8_t version = data[4];
    if (version != SOFTHSM_MILENAGE_WIRE_VERSION) {
        return Error::BAD_VERSION;
    }
    uint8_t operation = data[5];
    if (!isValidOperation(operation)) {
        return Error::BAD_OPERATION;
    }
    /* bytes [6,7] reserved, ignored other than being present */
    uint32_t totalLength = readU32BE(data + 8);
    if (totalLength != len) {
        return Error::LENGTH_MISMATCH;
    }

    out.operation = operation;
    out.fields.clear();

    size_t pos = HEADER_LEN;
    while (pos < len) {
        if (len - pos < TLV_HEADER_LEN) {
            return Error::TRUNCATED;
        }
        uint16_t tag = readU16BE(data + pos);
        uint32_t fieldLen = readU32BE(data + pos + 2);
        pos += TLV_HEADER_LEN;

        /* overflow check: pos + fieldLen must not wrap and must fit
         * within the buffer. */
        if (fieldLen > len || pos > len - fieldLen) {
            return Error::INTEGER_OVERFLOW;
        }
        if (!isKnownTag(tag)) {
            return Error::UNKNOWN_CRITICAL_TAG;
        }
        if (out.fields.count(tag) != 0) {
            return Error::DUPLICATE_TAG;
        }
        out.fields.emplace(tag, std::vector<uint8_t>(data + pos, data + pos + fieldLen));
        pos += fieldLen;
    }

    return Error::OK;
}

Error buildResponse(uint8_t operation,
                     const std::vector<std::pair<uint16_t, std::vector<uint8_t>>> &fields,
                     std::vector<uint8_t> &out)
{
    out.clear();
    out.insert(out.end(), SOFTHSM_MILENAGE_WIRE_MAGIC, SOFTHSM_MILENAGE_WIRE_MAGIC + 4);
    out.push_back(SOFTHSM_MILENAGE_WIRE_VERSION);
    out.push_back(operation);
    out.push_back(0x00);
    out.push_back(0x00); /* reserved */

    size_t lengthPos = out.size();
    writeU32BE(out, 0); /* placeholder, patched below */

    for (const auto &f : fields) {
        writeU16BE(out, f.first);
        writeU32BE(out, static_cast<uint32_t>(f.second.size()));
        out.insert(out.end(), f.second.begin(), f.second.end());
    }

    if (out.size() > SOFTHSM_MILENAGE_MAX_RESPONSE_LEN) {
        out.clear();
        return Error::TOO_LARGE;
    }

    uint32_t total = static_cast<uint32_t>(out.size());
    out[lengthPos + 0] = static_cast<uint8_t>((total >> 24) & 0xFF);
    out[lengthPos + 1] = static_cast<uint8_t>((total >> 16) & 0xFF);
    out[lengthPos + 2] = static_cast<uint8_t>((total >> 8) & 0xFF);
    out[lengthPos + 3] = static_cast<uint8_t>(total & 0xFF);

    return Error::OK;
}

} // namespace milenage_wire
