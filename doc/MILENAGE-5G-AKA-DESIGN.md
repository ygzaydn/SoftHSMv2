# Milenage / 5G-AKA Wrapped Credential Design (SoftHSMv2)

Status: **design + skeleton only** — not yet functionally implemented.
Base commit: `f12916ee8c6eb5c0025786479fcbf6b38480b134`
Branch: `feature/milenage-5g-wrapped-credentials`

## 1. Purpose

Extend SoftHSMv2 with a vendor-defined PKCS#11 interface so an Open5GS UDM can:

- store `wrapped_k` / `wrapped_opc` (Base64) instead of plaintext `k`/`op`/`opc`,
- request a 5G HE Authentication Vector (`RAND`, `AUTN`, `XRES*`, `KAUSF`) per
  authentication attempt without plaintext subscriber keys ever leaving the token,
- run Milenage resynchronization (`RAND`, `AUTS` → `SQN_MS`) the same way.

This document, and the accompanying header/stub files, are the first commit of a
multi-commit effort. **No cryptographic code is implemented yet** — see
"Implementation status" at the bottom for exactly what exists vs. what remains.

## 2. Non-goals for this phase

Open5GS changes, MongoDB migration, WebUI changes, LTE/EPS AV, TUAK/COMP128,
multiple/rotating master keys, remote HSM APIs, vendor SDK integration,
production secret-manager integration. See spec section 17 for the full list.

## 3. Critical security disclosure

**SoftHSMv2 is a software PKCS#11 implementation, not a hardware security
boundary.** All key material — including the Master Storage Key and any
transient plaintext K/OPc during an operation — exists in the memory of the
`libsofthsm2.so` process (or the process that has loaded it) at some point.
A privileged attacker who can read that process's memory (root, ptrace,
core dump, hypervisor introspection, swap access) can recover key material
regardless of the `CKA_EXTRACTABLE=FALSE` / `CKA_SENSITIVE=TRUE` attributes
described below. Those attributes stop extraction *through the PKCS#11 API*
by well-behaved callers; they are not a defense against a compromised host.
This document's "the key never leaves the token" language means "never
leaves via the PKCS#11 API surface," not "is physically isolated from the
host," because SoftHSMv2 has no such isolation. Anyone deploying this for
real subscriber credentials should treat the host running softhsm2 as
being inside the trust boundary that protects K/OPc, exactly as if it held
the plaintext.

## 4. Architecture

```
Open5GS UDM / MongoDB
    security.hsm = true
    security.wrapped_k   (base64)
    security.wrapped_opc (base64)
    security.amf
    security.sqn
             |
             | SUPI, wrapped K, wrapped OPc, SQN, AMF, SNN
             v
SoftHSMv2 custom PKCS#11 mechanisms (this document)
    AES-256 Master Storage Key (non-extractable, token object)
    AES-KWP unwrap (RFC 5649)
    Milenage (TS 35.206/35.207/35.208)
    5G AKA KDF (TS 33.501)
             |
             v
    RAND, AUTN, XRES*, KAUSF
```

Rules (unchanged from spec, restated for the implementer):

- Exactly one persistent Master Storage Key per token.
- Plaintext subscriber K/OPc are **never** persistent PKCS#11 objects.
- Wrapped K/OPc live in MongoDB as Base64; PKCS#11 requests carry decoded
  binary blobs.
- SQN stays in UDM. SoftHSM is stateless with respect to SQN — it only
  recovers `SQN_MS` during resync and returns it to the caller.
- When `security.hsm = true`, Open5GS must never fall back to plaintext
  `k`/`op`/`opc` (future Open5GS-side enforcement, out of scope here).

## 5. Key roles

### 5.1 Master Storage Key

Protects `wrapped_k` / `wrapped_opc` at rest in the UDM database. Generated
inside the token with `C_GenerateKey` / `CKM_AES_KEY_GEN`. Exactly one
instance exists; rotation is out of scope for this phase.

Required template (`src/lib/milenage/softhsm_milenage.h` §"Master key
template" mirrors this in code comments):

```
CKA_CLASS               = CKO_SECRET_KEY
CKA_KEY_TYPE            = CKK_AES
CKA_VALUE_LEN           = 32
CKA_TOKEN                = CK_TRUE
CKA_PRIVATE               = CK_TRUE
CKA_SENSITIVE            = CK_TRUE
CKA_EXTRACTABLE          = CK_FALSE
CKA_MODIFIABLE           = CK_FALSE
CKA_COPYABLE              = CK_FALSE
CKA_SIGN                = CK_TRUE
CKA_ENCRYPT              = CK_FALSE
CKA_DECRYPT              = CK_FALSE
CKA_WRAP                 = CK_FALSE
CKA_UNWRAP               = CK_FALSE
CKA_DERIVE               = CK_FALSE
CKA_LABEL                = "open5gs-milenage-master"
CKA_ID                   = 0x01
CKA_ALLOWED_MECHANISMS   = { CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED,
                              CKM_SOFTHSM_5G_HE_AV_WRAPPED,
                              CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED }
```

`CKA_SIGN = CK_TRUE` is intentional: the vendor mechanisms are dispatched
through `C_SignInit`/`C_Sign` (see §7), which requires the sign capability
on the key object even though the "signature" produced is really a wrapped
response blob, not a MAC over caller data. Every mechanism implementation
must independently re-verify all of CLASS/KEY_TYPE/EXTRACTABLE/SENSITIVE/
ALLOWED_MECHANISMS/LABEL/ID at operation time — never trust that a key
handle matching the label was provisioned correctly, since a malicious or
buggy caller could pass a handle to an unrelated AES key.

### 5.2 Optional Transport KEK

A separate, optional AES-256 key used **only** to receive K/OPc that were
already encrypted by an upstream system before reaching this host. It is
never used for AV generation and is not the key that protects `wrapped_k`/
`wrapped_opc` in the database — that's always the Master Storage Key. See
§6 provisioning modes.

**Implementation status for this phase: designed, not implemented.** The
`CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED` mechanism ID is reserved
(§8) and the CLI subcommands are documented (§10) but neither has code yet.

## 6. Provisioning modes

Initial provisioning always has a trust gap: *something* must have handled
plaintext K/OPc at least once (SIM personalization time), and this system
cannot prove the provisioning operator never saw it. Two modes:

1. **Preferred: transport-wrapped import.** K/OPc arrive already encrypted
   under the Transport KEK by an upstream system. The CLI process's
   application-level buffers only ever hold ciphertext; SoftHSM unwraps
   internally and rewraps under the Master Storage Key. (Not implemented
   this phase — see §5.2.)
2. **PoC plaintext mode**, gated by `WITH_MILENAGE_PLAINTEXT_PROVISIONING`
   (default `OFF`). When built, plaintext K/OPc may only enter via stdin,
   an explicit inherited file descriptor (`--input-fd`), or a protected
   binary file — never argv, never environment variables. The CLI must
   disable core dumps (`prctl(PR_SET_DUMPABLE, 0)` / `setrlimit(RLIMIT_CORE,
   0)`), attempt `mlock()` on secret buffers, and zero all buffers
   immediately after the `C_Sign` call returns, on every exit path
   including errors.

## 7. PKCS#11 operation model

SoftHSMv2's existing single-part sign path (`C_SignInit` → `C_Sign`) is
reused as the transport for these vendor mechanisms, matching how other
non-standard/opaque mechanisms are layered onto the PKCS#11 sign verbs in
this codebase's mechanism dispatch (`src/lib/SoftHSM.cpp`, `CryptoFactory`
mechanism tables under `src/lib/crypto/`). Multipart is explicitly
unsupported:

```c
C_SignInit(session, &mechanism, master_key_handle);
C_Sign(session, request, request_len, response, &response_len);
```

`C_SignUpdate` / `C_SignFinal` on these mechanisms must return
`CKR_FUNCTION_NOT_SUPPORTED`. An output-size query (`pSignature == NULL`)
must return only the required buffer length and must **not** unwrap any
credential or generate RAND — this is a specific required test (spec §15).

## 8. Vendor-defined mechanisms

Defined in the new installed header `src/lib/milenage/softhsm_milenage.h`,
under `CKM_VENDOR_DEFINED`, using a SoftHSM-specific block distinct from
known Thales/Luna vendor ranges:

| Mechanism | Value | Status |
|---|---|---|
| `CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED` | `CKM_VENDOR_DEFINED + 0x5347 0001` | reserved, unimplemented |
| `CKM_SOFTHSM_5G_HE_AV_WRAPPED` | `CKM_VENDOR_DEFINED + 0x5347 0002` | reserved, unimplemented |
| `CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED` | `CKM_VENDOR_DEFINED + 0x5347 0003` | reserved, unimplemented |
| `CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED` (optional) | `CKM_VENDOR_DEFINED + 0x5347 0004` | reserved, unimplemented |
| `CKM_SOFTHSM_MILENAGE_RAW_TEST` (test-only) | `CKM_VENDOR_DEFINED + 0x5347 00FF` | reserved, unimplemented |

`0x5347` = ASCII "SG" (5G), chosen to avoid collision with real vendor
allocations; still within the private `CKM_VENDOR_DEFINED` space so it
cannot collide with any current or future RSA PKCS#11 standard mechanism.

## 9. Wrapped credential envelope

AES Key Wrap with Padding, RFC 5649 / NIST SP 800-38F, over a versioned
plaintext envelope — never ECB/CBC/GCM/custom encryption:

```
magic              4 bytes  "S5GC"
version            1 byte   0x01
algorithm          1 byte   0x01 = Milenage AES-128
secret_type        1 byte   0x01 = K, 0x02 = OPc
reserved           1 byte   0x00
subscriber_binding 32 bytes SHA-256("open5gs-milenage-v1:" || canonical SUPI)
secret_length       2 bytes big-endian, must be 16
secret_value       16 bytes
```

Canonical SUPI (v1): `imsi-<5..15 decimal digits>`, matched exactly
(no case folding needed — digits only).

K and OPc are wrapped **separately** (two independent envelopes/blobs),
each carrying its own `subscriber_binding`, so that swapping a K blob and
an OPc blob between subscribers, or attaching either to the wrong
subscriber, fails the binding check rather than silently producing a
wrong-but-valid-looking AV. Binding comparison must be constant-time.
Any unwrap/integrity/envelope/binding failure returns one generic
`CKR_FUNCTION_FAILED`-class error — no distinguishing error codes, so a
caller cannot use error-oracle behavior to probe which check failed.

## 10. Wire format (request/response TLV)

Binary, versioned, no native pointers/structs on the wire:

```
Header:
  magic        "S5GM"      4 bytes
  version      uint8
  operation    uint8
  reserved     uint16      0
  total_length uint32 BE

TLV:
  tag          uint16 BE
  length       uint32 BE
  value        byte[length]
```

Limits: request ≤ 4096 B, response ≤ 1024 B, wrapped blob ≤ 256 B,
SNN ≤ 255 B, SUPI ≤ 32 B. Parsers must reject duplicate mandatory fields,
unknown critical fields, integer overflow, truncated TLVs, and
non-canonical SUPI. Tag numbering and the operation enum are defined in
`softhsm_milenage.h`.

## 11. Operations

### 11.1 `CKM_SOFTHSM_5G_HE_AV_WRAPPED`

In: SUPI, wrapped_k, wrapped_opc, SQN (6B), AMF (2B), SNN (1-255B).
Steps: validate session/login/mechanism/key → parse+validate request →
unwrap+validate K/OPc → generate fresh 16B RAND via SoftHSM RNG → Milenage
→ build AUTN → derive XRES*/KAUSF → wipe everything else → return.
Out: RAND(16), AUTN(16), XRES*(16), KAUSF(32). Never RES/CK/IK/AK/K/OPc.

### 11.2 `CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED`

In: SUPI, wrapped_k, wrapped_opc, RAND(16), AUTS(14).
Steps: unwrap+validate K/OPc → recover SQN_MS via f5* → compute MAC-S via
f1* → constant-time compare → on success return SQN_MS, on failure return
`CKR_SIGNATURE_INVALID`. SQN is never persisted or updated by SoftHSM.

### 11.3 `CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED`

In (PoC plaintext mode only, or via transport-wrapped import): SUPI,
K(16), OPc(16). Out: wrapped_k, wrapped_opc (each independently wrapped
under the Master Storage Key per §9). No plaintext K/OPc object is ever
created as a PKCS#11 object of any kind.

## 12. Milenage / 5G-AKA algorithm scope (phase 1)

Milenage only (not TUAK/COMP128), AES-128 K, 16-byte OPc, 8-byte RES,
5G-AKA only. Required primitives: OP→OPc helper, f1, f1*, f2, f3, f4, f5,
f5*, AUTN generation, AUTS verification + SQN_MS recovery, XRES*
derivation, KAUSF derivation — implemented independently from the 3GPP
specs' pseudocode style (not copied from Open5GS or any proprietary SDK),
built on SoftHSM's existing Botan-backed AES/HMAC-SHA-256/RNG primitives
(`src/lib/crypto/BotanAES.*`, `src/lib/crypto/BotanCryptoFactory.*`) and
its secure-memory wipe helpers. **Not implemented yet in this phase** —
see status table below.

## 13. Provisioning CLI (`softhsm2-milenage`)

Subcommands: `create-master-key`, `provision`, `generate-5g-av`, `resync`,
`inspect`, and optionally `create-transport-kek`,
`import-transport-wrapped`. Common options: `--module --token-label
--token-serial --slot-id --pin-file --pin-fd --master-key-label
--master-key-id`. Token label/serial preferred over slot id; ambiguous
matches are refused. No `--k`/`--opc`/literal `--pin` argv options ever;
no secrets in env vars; secrets never printed/logged; output files created
`0600` and never silently overwritten. `provision` prints only:

```json
{"hsm": true, "wrapped_k": "...", "wrapped_opc": "...", "k": null, "op": null, "opc": null}
```

**Not implemented yet in this phase** — see status table.

## 14. Build options

All default `OFF`/unset so existing SoftHSM behavior and builds are
unaffected:

| Option | Default | Effect |
|---|---|---|
| `WITH_MILENAGE` | OFF | builds the milenage subsystem + CLI at all |
| `WITH_MILENAGE_RAW_TESTS` | OFF | builds `CKM_SOFTHSM_MILENAGE_RAW_TEST` |
| `WITH_MILENAGE_TEST_RAND` | OFF | allows caller-supplied RAND (KAT tests) |
| `WITH_MILENAGE_PLAINTEXT_PROVISIONING` | OFF | allows plaintext K/OPc input path |
| `WITH_MILENAGE_TRANSPORT_IMPORT` | OFF | builds transport-KEK import mechanism/CLI |

CMake and Autotools definitions for these flags are **not yet added** to
`CMakeLists.txt` / `configure.ac` — see status table.

## 15. Future Open5GS UDM configuration (documentation only, not implemented)

```yaml
udm:
  hsm:
    enabled: true
    pkcs11_module: /usr/local/lib/softhsm/libsofthsm2.so
    token_label: open5gs-milenage
    token_serial: null
    slot_id: null
    user_pin_file: /run/secrets/open5gs-hsm-pin
    master_key_label: open5gs-milenage-master
    master_key_id: "01"
    wrapped_encoding: base64
```

Never a literal PIN in YAML — only a protected file path (or a future
secret-manager integration, out of scope).

## 16. Required tests (spec §15) — status

None of the tests below exist yet; all are TODO for follow-up commits.
Listed here so scope isn't lost: TS 35.208 Milenage KATs, OP→OPc KAT, full
5G HE AV KAT, AUTS success/failure resync, RFC 5649 AES-KWP vectors,
master-key non-extractability + API restriction, provisioning
wrapped-only output, no persistent plaintext K/OPc objects, wrapped
credentials survive process restart, wrong/cross/swapped/modified/
truncated binding rejections, login-required, output-size-query doesn't
unwrap/generate RAND, invalid MAC-S doesn't return SQN_MS, plaintext/raw
mechanisms absent from default builds, CLI argv/output/permission tests.

## 17. Implementation status (source of truth — do not trust section
headers above that describe target behavior as if built)

Implemented in this commit:
- This design document.
- `src/lib/milenage/softhsm_milenage.h`: mechanism ID constants, wire
  format tag/opcode enums, envelope struct layout constants, Master Key
  template constants — as compile-time constants/comments only, **no
  logic**.
- Directory skeleton `src/lib/milenage/` with stub `.cpp`/`.h` files
  containing function signatures for the primitives in §12 and
  `TODO(milenage)` markers, so the follow-up commit has a concrete shape
  to fill in. These stubs are **not wired into `SoftHSM.cpp`'s mechanism
  dispatch, not added to any CMakeLists/Makefile.am, and not compiled**.
- `testing/run-open5gs-milenage-poc.sh`: **not created this phase**.

Not implemented (all of §§2-16 beyond the above): actual Milenage/5G-AKA
math, AES-KWP wrap/unwrap, wire-format parser, PKCS#11 mechanism dispatch
wiring, Master Key generation/attribute-enforcement code, the CLI tool,
Transport KEK, all build-flag wiring, and all tests. Nothing in this
phase has been compiled, executed, or otherwise validated — there is no
test evidence to report because no test-eligible code exists yet.
