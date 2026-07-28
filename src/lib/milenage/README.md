# src/lib/milenage

Not yet wired into any CMakeLists.txt / Makefile.am, not compiled or
linked as part of libsofthsm2, not wired into PKCS#11 mechanism
dispatch. See `doc/MILENAGE-5G-AKA-DESIGN.md` (especially section 17)
for the design and current implementation-status source of truth.

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
