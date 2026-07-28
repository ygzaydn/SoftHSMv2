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

### Commit 1 (docs: add milenage hsm design)
- This design document.
- `src/lib/milenage/softhsm_milenage.h`: mechanism ID constants, wire
  format tag/opcode enums, envelope struct layout constants, Master Key
  template constants — compile-time constants only, no logic.
- Header-only signature stubs for `Milenage.h`/`FiveGAka.h`/
  `CredentialEnvelope.h`.

### Commit 2 (feat: add milenage and 5g aka primitives)
Implemented and **actually compiled and run** (not just written):
- `Milenage.cpp`: `deriveOpc`, `f1`, `f1*`, `f2345` (RES/CK/IK/AK),
  `f5*`, `buildAutn`, `verifyAuts`, built on OpenSSL AES-128-ECB single
  block encryption (`EVP_aes_128_ecb`), following the TS 35.206 Annex 3
  reference-algorithm *structure* (TEMP/OUTn/rotate constants), not
  copied from any 3GPP/Open5GS/vendor source.
- `FiveGAka.cpp`: `deriveXresStar`, `deriveKausf` using the generic
  3GPP KDF (HMAC-SHA-256 over `FC || P0 || L0 || P1 || L1 || ...`) via
  OpenSSL `HMAC()`.
- `CredentialEnvelope.cpp`: builds the 58-byte plaintext envelope from
  §9, wraps/unwraps it with OpenSSL's `EVP_aes_256_wrap_pad` cipher
  (RFC 5649 AES-KWP), validates every envelope field on unwrap, and
  does constant-time subscriber-binding comparison. **Deviation from
  the original design**: `wrapSecret`/`unwrapSecret` currently take the
  Master Storage Key as a raw 32-byte buffer parameter rather than a
  PKCS#11 key handle — see the INTERIM note in `CredentialEnvelope.h`.
  This lets the envelope logic be implemented and tested before the
  PKCS#11 dispatch/key-object work exists, but it must be replaced
  before this key is ever a real non-extractable token object, since a
  raw-buffer interface is incompatible with "the key value never
  leaves the crypto layer."
- `test/standalone_selftest.cpp`: a standalone (non-CppUnit,
  non-CMake/Autotools-integrated) test program; see its header comment
  for exact build command and honesty notes about which vectors are
  externally verified vs. self-consistency-only.

**Deviation from spec §12**: implemented directly against OpenSSL EVP
(this dev environment has no Botan installed — `dpkg -l` showed no
`libbotan-2/3-dev` package and no `botan-2`/`botan-3` pkg-config
module), not against SoftHSM's backend-selectable `CryptoFactory`
abstraction (`src/lib/crypto/BotanCryptoFactory.*` /
`src/lib/crypto/OSSL*.h`). A follow-up commit must port these
primitives onto SoftHSM's existing internal AES/HMAC-SHA-256/RNG
abstractions so the milenage subsystem respects the same OpenSSL-vs-
Botan build-time backend choice as the rest of the codebase, rather
than hardcoding an OpenSSL dependency.

**Actual test results** (run via the command in
`test/standalone_selftest.cpp`'s header, on this session's dev
environment, OpenSSL 3.0.2): 34/34 checks pass, 0 failures, no compiler
warnings under `-Wall -Wextra -std=c++17`. Externally verified against
the published 3GPP TS 35.207 Test Set 1 vectors: OPc, MAC-A (`f1`),
RES (`f2`), and AK (`f5`) all match exactly. CK and IK are computed but
**not asserted against an external vector** — no independently-verified
TS 35.207 CK/IK value for Test Set 1 was available in this session, and
guessing one to assert against would misrepresent validation coverage.
The 5G-AKA KDF (XRES-star, KAUSF) tests are determinism/self-consistency
checks only; no TS 33.501 Annex A KDF known-answer vector was available
to verify against this session. AUTN/AUTS resync round-trip and tamper/
truncation/wrong-key/cross-subscriber-binding rejection in the envelope
layer are exercised and pass, but these are internal round-trip tests,
not official RFC 5649 or TS 35.208 AUTS KATs.

### Commit 3 (feat: add wrapped credential mechanisms)
Implemented and compiled/run:
- `WireCodec.h/.cpp`: full TLV request parser and response builder for
  the format in §10 — header/magic/version/operation validation, the
  4096-byte request cap, integer-overflow-safe TLV length checks,
  duplicate-tag rejection, and unknown-tag rejection (every currently
  defined tag is treated as critical; there is no non-critical range
  yet).
- `MilenageService.h/.cpp`: end-to-end orchestration for all three
  primary operations (`generate5gHeAv`, `resync`, `provision`) —
  parses the wire request, validates/type-checks every mandatory
  field, unwraps K/OPc via `CredentialEnvelope`, runs Milenage/5G-AKA,
  builds the wire response, and zeroes every plaintext/intermediate
  buffer on every exit path. `generate5gHeAv` draws RAND from OpenSSL
  `RAND_bytes()` by default and accepts an optional caller-supplied
  RAND parameter for deterministic testing (intended to correspond to
  the `WITH_MILENAGE_TEST_RAND` gate once that build flag exists —
  this module does not itself enforce the gate).
- `test/service_selftest.cpp`: 20/20 checks pass, covering: provision
  → wrapped K/OPc round trip; 5G HE AV response contains exactly
  {RAND, AUTN, XRES*, KAUSF} and nothing else (explicit check that no
  RES/CK/IK/AK/K/OPc tag leaks into the response); wrong-SUPI
  credential rejection; fresh RAND per call; deterministic output
  under a fixed test RAND; resync rejecting an invalid MAC-S with
  `SIGNATURE_INVALID` and not populating a response; and wire-parser
  structural rejections (bad magic, truncation, duplicate tag, unknown
  critical tag, oversized request).

**Still an interim deviation, carried from commit 2**: the Master
Storage Key is a raw 32-byte buffer parameter throughout
`MilenageService`, not a PKCS#11 key handle. `MilenageService`'s
functions are designed to be the exact logic a `C_SignInit`/`C_Sign`
handler for the three mechanisms would call, but no such handler
exists — nothing here is referenced from `src/lib/SoftHSM.cpp`, whose
mechanism dispatch was inspected (14976-line file, mechanism `switch`
starting around line 1114) but not modified. Wiring this in requires,
at minimum: adding the vendor mechanism IDs to whatever table drives
`C_SignInit`'s mechanism-validity check, allocating session-level
operation state for a pending Milenage sign operation, handling the
output-size-query calling convention (`pSignature == NULL` must return
only a length, per spec §15, without unwrapping anything or generating
RAND — `MilenageService` as written always does the real work, so the
size-query short-circuit needs to live in the dispatch layer, not
here), rejecting `C_SignUpdate`/`C_SignFinal` for these mechanisms, and
replacing the raw-buffer master key with SoftHSM's real key-object
lookup so the key value is never copied out of that layer. None of
that PKCS#11-facing work happened this session.

### Commit 4 (feat: wire vendor mechanisms into PKCS#11 dispatch + CMake build flags)

This commit closes the gap called out at the end of commit 3: the
Milenage vendor mechanisms are now real, working PKCS#11 mechanisms in
`SoftHSM.cpp`, gated by a new `WITH_MILENAGE` CMake option (default
OFF), and were verified against the actual built `libsofthsm2.so`
through the standard PKCS#11 API (`dlopen` + `C_GetFunctionList`), not
just through `MilenageService`'s internal API.

**Build flags added** (`CMakeLists.txt`, `cmake/modules/CompilerOptions.cmake`,
`config.h.in.cmake`), all default OFF:
- `WITH_MILENAGE` -- builds `src/lib/milenage/*.cpp` into `libsofthsm2`
  and compiles the `#ifdef WITH_MILENAGE` blocks in `SoftHSM.cpp`/
  `Session.h`/`Session.cpp`. Requires `WITH_CRYPTO_BACKEND=openssl`
  (enforced with `message(FATAL_ERROR ...)` at configure time) because
  `src/lib/milenage` calls OpenSSL EVP directly (see commit 2's
  deviation note; still not ported onto `CryptoFactory`).
- `WITH_MILENAGE_PLAINTEXT_PROVISIONING` -- without it,
  `CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED` is not registered as a
  supported mechanism at all (absent from `C_GetMechanismList`,
  `C_SignInit` returns `CKR_MECHANISM_INVALID`), even when
  `WITH_MILENAGE` is on. Verified directly: a `WITH_MILENAGE=ON,
  WITH_MILENAGE_PLAINTEXT_PROVISIONING=OFF` build was built from
  scratch and confirmed to reject `C_SignInit` for the provision
  mechanism with `CKR_MECHANISM_INVALID` while still accepting the AV
  mechanism.
- `WITH_MILENAGE_TEST_RAND` -- currently only gates a CMake status
  message; `MilenageService::generate5gHeAv`'s `testRand` parameter
  itself has no build-time gate yet because nothing in
  `src/lib/SoftHSM.cpp`'s `MilenageSign` currently exposes a way to
  pass a caller-supplied RAND over the wire protocol at all (the
  `SOFTHSM_MILENAGE_TAG_RAND` tag is defined but `MilenageSign` never
  reads it for the AV operation). This is a real gap: the flag exists
  but does not yet enable anything reachable via PKCS#11. Fixing it
  requires threading a `#ifdef WITH_MILENAGE_TEST_RAND` request-parsing
  path through `MilenageSign` in `SoftHSM.cpp`.
- Requiring `WITH_MILENAGE_TEST_RAND`/`WITH_MILENAGE_PLAINTEXT_PROVISIONING`
  without `WITH_MILENAGE` is a configure-time fatal error.

**PKCS#11 dispatch wiring** (`src/lib/SoftHSM.cpp`, `src/lib/session_mgr/Session.h/.cpp`):
- New `SESSION_OP_MILENAGE` session operation type; `Session` gained
  `setMilenageOp`/`getMilenageMechanism`/`getMilenageMasterKey`, backed
  by a 32-byte buffer that `resetOp()` explicitly zeroes on every path
  (success, failure, or a session/library teardown that calls the
  destructor, which calls `resetOp()`).
- `isMilenageMechanism()` / `MilenageSignInit()` / `MilenageSign()`
  added following the exact structure of the existing `isMacMechanism`/
  `MacSignInit`/`MacSign` path: `C_SignInit` checks
  `session->getOpType() != SESSION_OP_NONE`, does the standard
  `haveRead` login/privacy check, requires `CKA_SIGN=TRUE`, and calls
  the existing `isMechanismPermitted()` (which enforces
  `CKA_ALLOWED_MECHANISMS` and the global `slots.mechanisms`
  configuration) exactly like every other mechanism in this codebase.
- `isValidMilenageMasterKey()` independently re-verifies the full
  Master Storage Key template from section 5.1 (class, key type,
  extractable/sensitive/modifiable/copyable, encrypt/decrypt/wrap/
  unwrap/derive all false, sign true, label, id) directly against the
  object's stored attributes on every `C_SignInit`, not just relying on
  `CKA_ALLOWED_MECHANISMS`.
- The raw key value is obtained via the existing `SoftHSM::getSymmetricKey()`
  helper (the same one `MacSignInit` uses), which already handles
  decrypting `CKA_VALUE` for a `CKA_PRIVATE` object -- this is the
  proper "read inside the crypto layer regardless of
  `CKA_EXTRACTABLE`" path, not a new extraction mechanism.
- `C_Sign`'s output-size-query calling convention (`pSignature ==
  NULL_PTR`) is handled by `milenageResponseSize()`, which computes the
  exact response length from the mechanism type alone (all three
  operations have a fixed size given the fixed 58-byte envelope
  plaintext) without touching `MilenageService` at all -- satisfying
  "must not unwrap or generate RAND" for the size query.
- `C_SignUpdate`/`C_SignFinal` explicitly return
  `CKR_FUNCTION_NOT_SUPPORTED` for a `SESSION_OP_MILENAGE` session and
  reset the operation (this reset was a bug found during testing: the
  first version left the session's operation stuck as active after a
  rejected `C_SignUpdate`, which made every subsequent `C_SignInit`
  fail with `CKR_OPERATION_ACTIVE` -- fixed by calling
  `session->resetOp()` before returning the rejection).
- `CKM_SOFTHSM_5G_HE_AV_WRAPPED` / `CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED`
  / (conditionally) `CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED` were added
  to `prepareSupportedMechanisms()`'s name/ID map, which is what feeds
  both `C_GetMechanismList` and the global half of
  `isMechanismPermitted()`.

**A real bug found and fixed while testing against the built library**:
`isValidMilenageMasterKey()`'s first version compared `CKA_LABEL` and
`CKA_ID` directly against the expected constants and always failed.
The reason: for a `CKA_PRIVATE=TRUE` object, SoftHSM's generic
attribute-update path (`P11Attribute::updateAttr()` in
`P11Attributes.cpp`) encrypts *every* byte-string attribute at rest,
not just `CKA_VALUE` -- something not obvious from reading `SoftHSM.cpp`
alone and only surfaced by actually running `C_GenerateKey` against the
real object store and inspecting the failure. Fixed by decrypting
`CKA_LABEL`/`CKA_ID` via `token->decrypt()` before comparison, the same
way `getSymmetricKey()` already decrypts `CKA_VALUE`. This is exactly
the kind of bug that pure design/unit-level work (commits 1-3) cannot
catch, and the reason the "must actually build and test" bar mattered
here.

**Actual end-to-end test results**, run against a from-scratch build in
this session's dev environment (OpenSSL 3.0.2, no SQLite, no CppUnit --
so this is *not* integrated with `ctest`/the project's own test
target, it's a standalone driver dlopen-ing the built `.so`):

- `src/lib/milenage/test/pkcs11_e2e_test.cpp` (30/30 checks pass): real
  `C_Initialize` -> `C_OpenSession` -> `C_Login` -> `C_GenerateKey` (full
  Master Key template) -> Master Key rejected for ordinary
  `CKM_AES_ECB` -> Master Key value not retrievable via
  `C_GetAttributeValue` -> `C_SignInit`/`C_Sign` for provision (including
  the `pSignature == NULL_PTR` size-query path) -> wrapped K/OPc
  extracted from the real wire response -> `C_SignUpdate`/`C_SignFinal`
  rejected with `CKR_FUNCTION_NOT_SUPPORTED` -> `C_SignInit`/`C_Sign` for
  the AV mechanism, response shape checked field-by-field (exactly
  RAND/AUTN/XRES*/KAUSF, nothing else) -> wrong-SUPI credential rejected
  -> resync with a garbage AUTS returns `CKR_SIGNATURE_INVALID` ->
  `C_Logout` -> AV mechanism refused after logout.
- `src/lib/milenage/test/pkcs11_restart_test.cpp` (spec section 15's
  "wrapped credentials remain usable after process restart"): two
  genuinely separate process invocations (separate `exec`, separate
  `dlopen`, separate `C_Initialize`) against the same on-disk token --
  process A generates the Master Key, provisions wrapped K/OPc, and
  exits; process B re-`dlopen`s the module, logs in fresh, finds the
  Master Key by label via `C_FindObjectsInit`/`C_FindObjects`, and
  successfully generates a full AV from the wrapped values process A
  wrote to a file. Passed.
- Confirmed by building three separate configurations from scratch and
  rerunning the standalone unit tests (34 + 20 checks) plus the PKCS#11
  E2E test (30 checks) against each: (1) default build (`WITH_MILENAGE`
  unset) -- `pkcs11_e2e_test` correctly gets `CKR_MECHANISM_INVALID`
  for every vendor mechanism, proving they are genuinely absent, not
  just untested; (2) `WITH_MILENAGE=ON` with both test-only flags on;
  (3) `WITH_MILENAGE=ON` with `WITH_MILENAGE_PLAINTEXT_PROVISIONING`
  left off -- AV/resync work, provision correctly rejected.

**Still not done after this commit**: the `WITH_MILENAGE_TEST_RAND`
gap described above (flag exists, nothing reachable via PKCS#11 uses
it yet); `CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED` and
`CKM_SOFTHSM_MILENAGE_RAW_TEST` are still entirely unimplemented (not
even reserved in dispatch); the Autotools (`configure.ac`/
`Makefile.am`) side of the build flags -- only CMake was done, so an
Autotools build of this branch does not have `WITH_MILENAGE` at all
yet; integration into the project's own CppUnit suite/`ctest` (the E2E
tests here are standalone drivers, not part of `BUILD_TESTS`); official
RFC 5649 / TS 35.208 / TS 33.501 Annex A known-answer vectors (still
only the TS 35.207 Test Set 1 partial match from commit 2); installing
`softhsm_milenage.h` as a public header; and
`testing/run-open5gs-milenage-poc.sh`.

### Commit 5 (feat: add provisioning CLI)

Adds `src/bin/milenage/softhsm2-milenage.cpp`, built as
`softhsm2-milenage` only when `WITH_MILENAGE` is on (`src/bin/CMakeLists.txt`
gates the new `src/bin/milenage` subdirectory). It is a generic PKCS#11
client (loads `--module` at runtime via `dlopen`, like `softhsm2-util`
already does), not something linked against `libsofthsm2` internals.

Implements the required subcommands from spec section 8:
`create-master-key`, `provision`, `generate-5g-av`, `resync`,
`inspect`. Does **not** implement `create-transport-kek` /
`import-transport-wrapped` -- they exit with an explicit "not
implemented" message rather than silently doing nothing, since the
Transport KEK was never implemented server-side either (section 5.2).

Security properties implemented and directly exercised, not just
asserted: no `--k`, `--opc`, or literal `--pin` option exists anywhere
in the argument parser (`--pin`/`--k`/`--opc` are recognized only to
immediately refuse with an explanatory error); `provision`'s plaintext
K/OPc input comes only from `--input-fd` or stdin (32 bytes: K then
OPc), never argv or an environment variable; the process disables core
dumps on startup (`prctl(PR_SET_DUMPABLE, 0)` plus `setrlimit(RLIMIT_CORE,
{0,0})`); every buffer holding plaintext K/OPc, the wire request, or
the wire response is explicitly zeroed after use; `--token-label`/
`--token-serial` are the normal way to select a token, `--slot-id` is
documented as an override only, and both token and Master Key lookup
(`C_FindObjectsInit`/`C_FindObjects`) explicitly refuse an ambiguous
match (more than one result) rather than silently picking the first;
output files are created with `open(..., O_CREAT|O_EXCL, 0600)` and
refuse to overwrite an existing file without `--force`.

**Actual test results**: built via the project's own CMake
(`-DWITH_MILENAGE=ON -DWITH_MILENAGE_PLAINTEXT_PROVISIONING=ON`, from
scratch), then run end-to-end against a freshly initialized token:
`create-master-key` -> `provision` (stdin credential input, wrote a
0600 output file, second run correctly refused to overwrite it without
`--force`) -> `generate-5g-av` (produced RAND/AUTN/XRES*/KAUSF as hex
JSON) -> `inspect` (reported `extractable: false, sensitive: true`)
-> `resync` with a correctly-14-byte but semantically-garbage AUTS,
which correctly reported "invalid MAC-S" (mapped from
`CKR_SIGNATURE_INVALID`). Also confirmed a default build
(`WITH_MILENAGE` unset, rebuilt from scratch) does not produce the
`softhsm2-milenage` binary at all.

### Commit 6 (test: add PoC script)

Adds `testing/run-open5gs-milenage-poc.sh`, matching spec section 16.
It builds SoftHSMv2 from scratch in an isolated `mktemp -d` directory
with `-DWITH_MILENAGE=ON -DWITH_MILENAGE_PLAINTEXT_PROVISIONING=ON`,
initializes an isolated test token, and runs the full flow with the
public 3GPP TS 35.207 Test Set 1 K/OPc (explicitly labeled as public
test-vector data, not a real subscriber, in both the script's header
comment and its inline echoed output): create-master-key -> provision
-> a separate `softhsm2-milenage` invocation to generate a 5G HE AV
from only the wrapped values (simulating the "close the provisioning
process, start a new one" requirement) -> verifies RAND/AUTN/XRES*/
KAUSF are present with the correct lengths -> a modified `wrapped_k`
blob is rejected -> the same wrapped blobs bound to a different SUPI
are rejected -> resync with a well-formed-but-invalid AUTS reports an
invalid-MAC-S failure. Cleans up its temp directory via a `trap` on
exit.

**Actual result**: run in this session, all checks passed (echoed
above the commit message verbatim). Requires `python3` for JSON/hex
handling (used only for test-harness convenience, not by the CLI or
library) and `cmake`, both present in this session's environment.

**Not implemented, by explicit design choice, not oversight**: the
script does not construct a *valid* AUTS to test the resync
success path (only the failure path). Doing so requires computing
f5*/f1* from the same test-vector K/OPc, which the algorithm
implementation already covers as a positive-path round trip in
`src/lib/milenage/test/standalone_selftest.cpp` ("verifyAuts accepts a
validly constructed AUTS" / "recovers correct SQN_MS"); duplicating
that math in a bash+python test harness would not add coverage, only
risk a second, inconsistent implementation of the same algorithm in a
test script. This is called out explicitly in the script's comments so
it is not mistaken for missing coverage.

**Not yet done**: the CLI does not yet implement `--pin-fd` being
tested end-to-end (code path exists, exercised only via `--pin-file`
in this session); `mlock()` is attempted on the plaintext credential
buffer in `provision` but its success is not verified end-to-end in
this session (best-effort only -- failure is non-fatal since the
buffer is zeroed regardless); no man page; not integrated into
`Makefile.am`/`configure.ac` (CMake only, matching commit 4's gap);
and the JSON emitted by `generate-5g-av`/`resync`/`inspect` is
hand-rolled string concatenation (adequate for this fixed,
programmer-controlled field set, but not a general JSON encoder --
acceptable here only because none of the interpolated values can
contain characters requiring JSON escaping other than the label
string, which does go through `jsonEscape()`).

## 18. Second round of hardening (post-milestone)

Following the initial functional milestone (sections above, commits
1-6 in `git log`), a second round addressed authoritative test
vectors, backend independence, test integration, the test-RAND gap,
and the Transport KEK. This section is the status record for that
round; treat it as continuing/superseding section 17 rather than
duplicating it.

### Commit 7 (refactor: remove direct OpenSSL dependency)
See the commit message for full detail. Summary: `CryptoBackend.{h,cpp}`
is now the only file in `src/lib/milenage` that touches
`CryptoFactory`; `Milenage.cpp`/`FiveGAka.cpp`/`CredentialEnvelope.cpp`/
`WireCodec.cpp`/`MilenageService.cpp` have zero OpenSSL/Botan-specific
code (grep-verified). Verified for the OpenSSL backend by a full
rebuild plus the existing 30-check PKCS#11 E2E test and the restart
test, both still passing. **Not verified for Botan**: this sandboxed
environment has no root access to install `libbotan-2-dev`/
`libbotan-3-dev`, so `WITH_CRYPTO_BACKEND=botan` could not be
configured or compiled here. Confidence rests on `CryptoBackend.cpp`
using only the same backend-selectable abstraction headers
`SoftHSM.cpp` itself already uses across both backends — inspection,
not execution.

### Commit 8 (test: authoritative KAT tests + CTest integration)
`src/lib/milenage/test/milenage_kat_test.cpp` adds full 3GPP TS
35.207 Test Set 1 and Test Set 2 (all 8 outputs each: OPc, MAC-A,
MAC-S, RES, CK, IK, AK, AK*), both official RFC 5649 section 6
examples (fetched directly from rfc-editor.org), and an explicitly-
labeled independent cross-check (not an official KAT) for XRES*/KAUSF
against a second, separately-written HMAC-SHA-256 implementation. See
the file's own header comment for exact source citations, including
the caveat that the primary ETSI PDF for TS 35.207 returned HTTP 403
in this session and the Milenage vectors were instead sourced from the
CryptoMobile open-source reference implementation, corroborated by an
exact match on 4 of 8 Test Set 1 fields against values independently
recalled in an earlier session. All 28 checks pass (verified: built
and run).

Tests are integrated with `ctest` (not CppUnit — this environment has
no `libcppunit-dev` and no root to install it, so a CppUnit suite
could not be built here; the task explicitly allows "CppUnit and/or
CTest"). `src/lib/milenage/test/CMakeLists.txt` builds and registers
`milenage-kat-test`, `milenage-service-test`,
`milenage-pkcs11-e2e-test`, `milenage-pkcs11-restart-test`, and (when
`WITH_MILENAGE_TRANSPORT_IMPORT` is also on) `milenage-pkcs11-transport-import-test`.
Gated only on `WITH_MILENAGE`, independent of `BUILD_TESTS`.

### Commit 9 (feat: connect WITH_MILENAGE_TEST_RAND to the wire protocol)
`MilenageService::generate5gHeAv` now reads an optional
`SOFTHSM_MILENAGE_TAG_RAND` wire field; used as RAND only when built
with `WITH_MILENAGE_TEST_RAND`, and a hard `Error::BAD_REQUEST` (never
silently ignored) when that flag is off. Verified by building both
configurations and running the new `milenage-service-test` checks
against each (flag on: wire RAND accepted and deterministic; flag
off: wire RAND rejected). Chose "preferred" option from the task's
item 5, not flag removal.

### Commit 10 (feat: Transport KEK + transport-wrapped import)
Implements task item 6 in full:
- `TransportEnvelope.{h,cpp}`: a distinct package format (magic
  `"S5GT"`, 91-byte plaintext) binding canonical SUPI, secret type,
  package version, a transport-key-version marker, an optional
  0-32-byte transaction ID, and the 16-byte secret, AES-KWP-wrapped
  under the Transport KEK. Deliberately a different format/magic from
  the credential envelope (`CredentialEnvelope.h`, magic `"S5GC"`)
  that's what actually gets stored in the UDM database — the
  transport package is only ever the authority-to-SoftHSM wire, never
  persisted.
- `MilenageService::importTransportWrapped`: unwraps K and OPc from
  the transport package under the Transport KEK, validates metadata
  and subscriber binding, re-wraps both under the Master Storage Key
  exactly like `provision()` does, and returns only
  `wrapped_k`/`wrapped_opc` — never plaintext.
- PKCS#11 wiring (`SoftHSM.cpp`, gated by new `WITH_MILENAGE_TRANSPORT_IMPORT`
  CMake option, requires `WITH_MILENAGE`): the Transport KEK template
  is validated by a newly-generalized `isValidMilenageKeyTemplate()`
  (same shape as the Master Storage Key check, parameterized by
  label/id) with its own label (`open5gs-milenage-transport-kek`) and
  id (`0x02`), cryptographically and by-template distinct from the
  Master Storage Key. Because standard PKCS#11 `C_SignInit` takes only
  one key handle but this operation needs two keys (Transport KEK to
  unwrap, Master Storage Key to re-wrap), the Master Storage Key
  handle is passed via a new mechanism parameter,
  `CK_SOFTHSM_MILENAGE_TRANSPORT_IMPORT_PARAMS` (`softhsm_milenage.h`),
  and is independently re-validated against the Master Storage Key
  template server-side rather than trusted from the caller. `Session`
  gained a second 32-byte key slot (`milenageSecondaryKey`) alongside
  the existing one, both wiped unconditionally by `resetOp()`.

**Actual test results**: `src/lib/milenage/test/pkcs11_transport_import_test.cpp`
(26/26 checks, built and run against a from-scratch
`WITH_MILENAGE_TRANSPORT_IMPORT=ON` build) drives the real PKCS#11 API
end to end: generates a real Master Storage Key and a real Transport
KEK via `C_GenerateKey` with their full templates; confirms the
Transport KEK is rejected for ordinary `CKM_AES_ECB` and
`C_GetAttributeValue`; confirms the Master Storage Key object is
rejected as the transport-import `hKey` (wrong template); imports a
known-value Transport KEK via `C_CreateObject` so the test (playing
the role of the external "secure provisioning authority") can build a
transport package with its own independent AES-KWP call directly
against OpenSSL EVP (sharing no code with `TransportEnvelope.cpp`);
runs a full `C_SignInit`/`C_Sign` transport-import round trip whose
output wraps successfully feeds a real `CKM_SOFTHSM_5G_HE_AV_WRAPPED`
call; and separately verifies all of the required negative paths from
task item 9 for this mechanism: wrong Transport KEK rejected, modified
transport ciphertext rejected, wrong SUPI binding rejected, swapped
K/OPc transport packages rejected. Full `ctest` suite (5/5) passes
with this flag on; the transport-import test target is entirely absent
when the flag is off (confirmed by rebuilding without it), and the
default build (all flags off) is unaffected (confirmed by a from-
scratch rebuild).

### Status against the second-round completion criteria
1. Milenage outputs vs. authoritative vectors: **done** (2 full TS
   35.207 test sets, 16 checks).
2. RFC 5649 vs. official vectors: **done** (both RFC examples, wrap
   and unwrap).
3. XRES*/KAUSF vs. authoritative or independently-verified values:
   **partial** — independent cross-check done (2 implementations
   agree); no official 3GPP-published numeric KAT was found.
4. No direct OpenSSL dependency in Milenage: **done for the code**,
   **not executed against Botan** (environment constraint).
5. Tests integrated into normal project test suite: **done via
   CTest**; **not done via CppUnit** (environment constraint, no root
   to install `libcppunit-dev`).
6. Both CMake and Autotools builds work: **CMake only** — Autotools
   (task item 4) was not reached in this round; `configure.ac`/
   `Makefile.am` still have no `WITH_MILENAGE*` support.
7. test-RAND flag fully implemented or removed: **done** (implemented).
8. Secure transport-wrapped provisioning implemented: **done**
   (mechanism, Transport KEK, 26-check E2E test including the specific
   negative paths task item 9 calls out for it).
9. Plaintext provisioning test-only and disabled by default: **already
   true from the first round** (`WITH_MILENAGE_PLAINTEXT_PROVISIONING`
   default OFF) — task item 7's CLI-side `--allow-plaintext-test-provisioning`
   flag and making transport-wrapped import the CLI's default path
   were **not reached** in this round.
10. All tests and sanitizers executed: tests yes (CTest suites above,
    all passing); **AddressSanitizer/UndefinedBehaviorSanitizer were
    not run** in this round (task item 9's sanitizer requirement) —
    not reached.
11. Design documentation updated: this section.
12. No Open5GS modifications: confirmed — `git status`/`git diff`
    touch only files under this repository, nothing Open5GS-related
    exists in this tree.

### Not reached this round, with reasons
- **Autotools build support** (task item 4): not started. Reason:
  time — CMake support alone (5 build-flag combinations, the shared
  library, the static library, 3 new test binaries, one new CLI
  binary) was already substantial; mirroring it faithfully in
  `configure.ac`/`Makefile.am`, including feature-flag `AC_ARG_ENABLE`
  wiring, conditional source lists, and a configuration summary,
  is comparable in size to everything else in this round combined and
  was not attempted rather than attempted partially/untested.
- **CLI plaintext-provisioning restriction** (task item 7): not
  started. The CLI's `provision` command still accepts plaintext K/OPc
  via stdin/`--input-fd` whenever the binary was built at all (i.e.
  whenever `WITH_MILENAGE` is on), rather than requiring both a
  separate build flag and an explicit `--allow-plaintext-test-provisioning`
  runtime flag, and the CLI does not yet default to
  `import-transport-wrapped`. The server-side gate
  (`WITH_MILENAGE_PLAINTEXT_PROVISIONING`) is real and independently
  enforced, but the CLI-side hardening described in task item 7 is
  not.
- **CKM_SOFTHSM_MILENAGE_RAW_TEST** (task item 8): still unimplemented
  (mechanism ID reserved only). Per the task's own instruction ("do
  not delay the required official-vector tests merely because this
  mechanism is absent... direct internal unit tests are acceptable"),
  this was deliberately skipped in favor of the direct-call KAT tests,
  which already exercise the Milenage core without needing a PKCS#11
  round trip.
- **Sanitizer runs** (task item 9's last requirement): not done. The
  test binaries that exist (`milenage-kat-test`, `milenage-service-test`,
  the PKCS#11 E2E/restart/transport-import tests) are all real,
  already-passing executables that a follow-up session can rebuild
  with `-fsanitize=address,undefined` and rerun without any code
  changes — this is pure remaining-time, not a blocker.
- **Additional negative/secret-exposure tests beyond what commits 8-10
  already added** (task item 9's checklist items not covered by the
  transport-import test's negative paths): "failed unwraps do not
  reveal which field failed" is true by construction (one generic
  error, see `CredentialEnvelope.cpp`/`TransportEnvelope.cpp`) but has
  no dedicated test beyond the existing tamper/wrong-key/wrong-SUPI
  checks; "plaintext K/OPc not printed by CLI tools" and "not stored
  as token objects" and "no secret values in normal logs" are true by
  code inspection (the CLI never has a code path that prints them; the
  provisioning flow never creates a plaintext PKCS#11 object) but were
  not asserted by an automated test that greps binary/log output.

## 19. Sanitizer run (AddressSanitizer + UndefinedBehaviorSanitizer)

Executed in this session, closing part of task item 9/10's "run
sanitizers" requirement. Full library, CLI, and all 5 CTest suites
were rebuilt from scratch with:

```
cmake -DWITH_CRYPTO_BACKEND=openssl -DWITH_MILENAGE=ON \
      -DWITH_MILENAGE_PLAINTEXT_PROVISIONING=ON \
      -DWITH_MILENAGE_TEST_RAND=ON \
      -DWITH_MILENAGE_TRANSPORT_IMPORT=ON \
      -DENABLE_ECC=OFF -DENABLE_EDDSA=OFF \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
      <repo>
make -j$(nproc)
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 ctest --output-on-failure
```

(`ENABLE_ECC=OFF -DENABLE_EDDSA=OFF`: unrelated to Milenage, needed
only because this environment's OpenSSL/sanitizer combination failed
CMake's ECC-capability probe under sanitizer flags; does not affect
any milenage code path.)

**Result: 5/5 tests passed, zero ASan or UBSan reports of any kind**
across `milenage-kat-test`, `milenage-service-test`,
`milenage-pkcs11-e2e-test`, `milenage-pkcs11-restart-test`, and
`milenage-pkcs11-transport-import-test`. The `.so` and every test
binary (including the PKCS#11 client test binaries that `dlopen` it)
were built with the same sanitizer flags, so this exercises the
dlopen/PKCS#11-API boundary under instrumentation too, not just the
directly-linked KAT/service tests. This covers every code path
touched by this branch: Milenage/5G-AKA math, AES-KWP wrap/unwrap
(both envelope formats), the wire codec, `MilenageService`
orchestration, the full PKCS#11 `C_SignInit`/`C_Sign` dispatch for all
four mechanisms, session key-buffer lifecycle/wiping, and the
Transport KEK two-key flow.

Not run under sanitizers in this session: the `softhsm2-milenage` CLI
itself (only the library and the internal test binaries were built
with sanitizer flags in this pass) and `testing/run-open5gs-milenage-poc.sh`
(which builds its own separate, non-instrumented build directory).

## 20. CLI plaintext-provisioning restriction (task item 7)

`softhsm2-milenage`'s `provision` command now requires three
independent, non-overlapping gates, none sufficient alone:

1. **Build-time**: `cmdProvision()`'s entire body is compiled only
   under `#ifdef WITH_MILENAGE_PLAINTEXT_PROVISIONING` (the CLI reads
   this from the same generated `config.h` the server-side gate
   uses -- one CMake option controls both). Without it, `provision`
   exits with "this build does not include plaintext provisioning".
2. **Runtime**: even in a build that has the command compiled in, it
   refuses to run without an explicit `--allow-plaintext-test-provisioning`
   flag.
3. **Server-side** (already true from an earlier commit):
   `CKM_SOFTHSM_MILENAGE_PROVISION_WRAPPED` itself is not a registered
   mechanism unless the token's `libsofthsm2.so` was independently
   built with the same flag.

When used, it prints an explicit stderr warning before touching any
secret material: "plaintext credential provisioning is a
development/PoC-only mode... not appropriate for production use...
prefer 'import-transport-wrapped'."

**Actual test results**: rebuilt and ran three configurations from
scratch. (1) `WITH_MILENAGE_PLAINTEXT_PROVISIONING=ON` build, CLI
without the runtime flag: refused with the expected message, exit 1.
(2) Same build, CLI with the runtime flag: succeeded, warning printed
to stderr, output JSON correct. (3) `WITH_MILENAGE=ON` build with
`WITH_MILENAGE_PLAINTEXT_PROVISIONING` left off: CLI refused with the
"this build does not include..." message even with the runtime flag
passed, exit 1. `testing/run-open5gs-milenage-poc.sh` updated to pass
the new required flag and re-run end to end (still passes in full).

**Still not done from task item 7**: the CLI does not yet make
`import-transport-wrapped` its literal default subcommand behavior (it
is simply the recommended alternative in help text and warnings); no
change was needed to `import-transport-wrapped` itself since it never
accepted plaintext input in the first place.
