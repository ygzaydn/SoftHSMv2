# src/lib/milenage

Built into `libsofthsm2` and wired into real PKCS#11 dispatch
(`C_SignInit`/`C_Sign` in `src/lib/SoftHSM.cpp`) when CMake is
configured with `-DWITH_MILENAGE=ON` (default OFF, requires
`-DWITH_CRYPTO_BACKEND=openssl`). Not yet ported to Autotools
(`configure.ac`/`Makefile.am`). See `doc/MILENAGE-5G-AKA-DESIGN.md`
(especially section 17) for the design and current
implementation-status source of truth.

- `softhsm_milenage.h` — vendor mechanism IDs, wire-format tags,
  envelope layout constants, master-key template constants.
- `Milenage.h` / `Milenage.cpp` — TS 35.206 Milenage primitives (f1,
  f1*, f2-f5, f5*, AUTN build, AUTS verify), implemented against
  OpenSSL EVP AES-128-ECB. Verified against published TS 35.207 Test
  Set 1 for OPc/MAC-A/RES/AK (see test file below).
- `FiveGAka.h` / `FiveGAka.cpp` — XRES*/KAUSF KDF (TS 33.501), built on
  the generic 3GPP HMAC-SHA-256 KDF via OpenSSL. Not yet checked
  against an official TS 33.501 Annex A vector.
- `CredentialEnvelope.h` / `CredentialEnvelope.cpp` — envelope build/
  parse plus AES-KWP (RFC 5649) wrap/unwrap and constant-time
  subscriber-binding checks via OpenSSL `EVP_aes_256_wrap_pad`. Takes
  the Master Storage Key as a raw 32-byte buffer for now — see the
  INTERIM note in the header; this must become a PKCS#11-key-backed
  interface before it touches a real non-extractable token key.
- `test/standalone_selftest.cpp` — standalone test program (build
  command in its header comment); not yet integrated into the
  project's CppUnit suite or build system. 34/34 checks passing as of
  the last run in this session; see design doc section 17 for exactly
  which checks are externally-vector-verified vs. self-consistency
  only.

Implemented against OpenSSL EVP directly rather than SoftHSM's
Botan/OpenSSL-selectable `CryptoFactory` abstraction, because this dev
environment has no Botan installed. Porting onto that abstraction is
still open — see design doc section 17.

## PKCS#11 dispatch

`src/lib/SoftHSM.cpp` gains, under `#ifdef WITH_MILENAGE`:
`isMilenageMechanism()`, `isValidMilenageMasterKey()`,
`milenageResponseSize()`, `SoftHSM::MilenageSignInit()`,
`SoftHSM::MilenageSign()`, and dispatch branches in `C_SignInit`,
`C_Sign`, `C_SignUpdate` (rejects with `CKR_FUNCTION_NOT_SUPPORTED`),
and `C_SignFinal` (same). `src/lib/session_mgr/Session.h`/`.cpp` gain a
`SESSION_OP_MILENAGE` op type and a 32-byte Master Key buffer that
`resetOp()` zeroes on every path.

Verified with real PKCS#11-level tests (dlopen the built `.so`, drive
it through the standard `C_GetFunctionList` entry point) rather than
only through `MilenageService`'s internal API — see
`test/pkcs11_e2e_test.cpp` (30/30 checks) and
`test/pkcs11_restart_test.cpp` (cross-process persistence, two separate
`exec`s). Build/run commands are in each file's header comment. Both
were also run against a default build (`WITH_MILENAGE` unset) to
confirm the vendor mechanisms are genuinely absent
(`CKR_MECHANISM_INVALID`), and against a
`WITH_MILENAGE=ON,WITH_MILENAGE_PLAINTEXT_PROVISIONING=OFF` build to
confirm the provisioning mechanism specifically is gated off while
AV/resync remain available.

- `WireCodec.h` / `WireCodec.cpp` — TLV request/response codec for the
  wire format in the design doc §10 (magic/version/operation
  validation, size caps, overflow-safe TLV parsing, duplicate/unknown
  tag rejection).
- `MilenageService.h` / `MilenageService.cpp` — end-to-end handlers for
  the three primary operations (`generate5gHeAv`, `resync`,
  `provision`), the logic intended to eventually sit behind
  `C_SignInit`/`C_Sign` for the vendor mechanisms. **Not actually wired
  into PKCS#11 dispatch** — see design doc §17 for exactly what's
  missing to get there (session state, output-size-query
  short-circuit, real key-object lookup instead of a raw key buffer).
- `test/service_selftest.cpp` — 20/20 checks passing as of the last run
  in this session, covering provisioning round trip, AV
  generation/response-shape, credential-binding rejection, resync
  MAC-S rejection, and wire-parser structural rejections.
