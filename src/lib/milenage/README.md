# src/lib/milenage — skeleton only

Not yet wired into any CMakeLists.txt / Makefile.am, not compiled, not
linked into libsofthsm2. See `doc/MILENAGE-5G-AKA-DESIGN.md` for the
design and the current implementation-status list.

Files here are header-only signature stubs for the follow-up
implementation commit:

- `softhsm_milenage.h` — public vendor mechanism IDs, wire-format tags,
  envelope layout constants, master-key template constants. Real
  constants, safe to depend on.
- `Milenage.h` — TS 35.206/35.208 primitive signatures (f1, f1*, f2-f5,
  f5*, AUTN build, AUTS verify). No `.cpp`, no implementation.
- `FiveGAka.h` — XRES*/KAUSF KDF signatures (TS 33.501). No `.cpp`, no
  implementation.
- `CredentialEnvelope.h` — wrap/unwrap envelope signatures (RFC 5649
  AES-KWP + binding checks). No `.cpp`, no implementation.
