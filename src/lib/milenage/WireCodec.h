/*
 * Request/response TLV wire codec (design doc section 10).
 *
 * This is transport-format logic only: it has no knowledge of PKCS#11
 * session/key state. It is used by MilenageService (see
 * MilenageService.h) which is in turn intended to be called from the
 * PKCS#11 C_SignInit/C_Sign dispatch for the vendor mechanisms -- that
 * dispatch wiring does not exist yet, see doc/MILENAGE-5G-AKA-DESIGN.md
 * section 17.
 */

#ifndef SOFTHSM_MILENAGE_WIRE_CODEC_H
#define SOFTHSM_MILENAGE_WIRE_CODEC_H

#include <cstdint>
#include <cstddef>
#include <map>
#include <vector>

#include "softhsm_milenage.h"

namespace milenage_wire {

enum class Error {
    OK,
    TOO_LARGE,
    TRUNCATED,
    BAD_MAGIC,
    BAD_VERSION,
    BAD_OPERATION,
    DUPLICATE_TAG,
    UNKNOWN_CRITICAL_TAG,
    INTEGER_OVERFLOW,
    LENGTH_MISMATCH
};

struct Request {
    uint8_t operation = 0;
    /* Every tag currently defined is treated as critical: an unknown
     * tag in a request is a hard parse failure rather than being
     * silently skipped, per design doc section 10 ("reject ... unknown
     * critical fields"). This codec defines no non-critical tags. */
    std::map<uint16_t, std::vector<uint8_t>> fields;
};

/* Parses a full request buffer (header + TLVs) per design doc section
 * 10. Rejects: bad magic/version, length overruns the
 * SOFTHSM_MILENAGE_MAX_REQUEST_LEN cap, truncated TLVs, integer
 * overflow while summing TLV lengths, duplicate mandatory tags, and
 * any tag not in the fixed enum in softhsm_milenage.h. Does not
 * validate field *semantics* (that is the caller's job, e.g.
 * MilenageService) -- only wire-level structure. */
Error parseRequest(const uint8_t *data, size_t len, Request &out);

/* Builds a response buffer: header + TLVs from `fields`, in the order
 * given. Fails if the encoded size would exceed
 * SOFTHSM_MILENAGE_MAX_RESPONSE_LEN. */
Error buildResponse(uint8_t operation,
                     const std::vector<std::pair<uint16_t, std::vector<uint8_t>>> &fields,
                     std::vector<uint8_t> &out);

} // namespace milenage_wire

#endif // SOFTHSM_MILENAGE_WIRE_CODEC_H
