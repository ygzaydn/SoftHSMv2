# Methodology: how SoftHSM-backed 5G-AKA authentication works

This document explains what this system actually does: what the 5G
core asks of the HSM, what goes over the wire, and what happens inside
the HSM on each request. It assumes you already know how to install and
operate the service (see `README.md` and `USAGE.md`); this is about the
mechanism, not the commands.

## The problem this solves

In a stock Open5GS deployment, the UDM holds each subscriber's
permanent key `K` and operator constant `OPc` in plaintext in MongoDB,
and computes Milenage/5G-AKA itself, in-process. Anyone with MongoDB
access — a backup, a misconfigured network share, an operator with
read access to the wrong database — can read every subscriber's raw
key material.

This system moves that computation into SoftHSM: the UDM (and UDR)
never hold plaintext `K`/`OPc` for HSM-backed subscribers. They hold
only `K`/`OPc` that has been wrapped (encrypted) under an AES-256 key —
the **Master Storage Key** — that exists only inside the HSM's token
storage and never leaves it. The UDM sends the wrapped blob and the
per-authentication parameters to the HSM over the network; the HSM
unwraps, runs the actual Milenage/5G-AKA math internally, and returns
only the outputs a 3GPP 5G-AKA exchange needs — never the key itself.

## Actors and where they run

```
 ┌─────────────────────────┐        plain TCP        ┌──────────────────────────┐
 │   Open5GS UDM (+ UDR)    │  ─────────────────────▶ │   softhsm-gsm           │
 │   lib/hsm (S5GM client)  │  ◀───────────────────── │   (this host)            │
 └─────────────────────────┘      S5GM protocol       └──────────────┬───────────┘
                                                                       │ PKCS#11
                                                                       ▼
                                                          ┌────────────────────────┐
                                                          │ SoftHSM token storage   │
                                                          │ - Master Storage Key    │
                                                          │ - (per-subscriber       │
                                                          │    wrapped K/OPc lives  │
                                                          │    in MongoDB, not      │
                                                          │    here — see below)    │
                                                          └────────────────────────┘
```

- **UDM/UDR** (`lib/hsm`, `src/udm`, `src/udr` in the Open5GS tree):
  decides whether a subscriber is HSM-backed (`security.hsm: true` in
  MongoDB), and if so, calls out to the HSM instead of computing
  Milenage locally.
- **`softhsm-gsm`** (this repository, `src/bin/milenage/`): a
  small TCP daemon that translates network requests into PKCS#11 calls
  against the SoftHSM library it's linked against. It holds one open
  PKCS#11 session and the Master Storage Key handle for its whole
  lifetime.
- **SoftHSM token storage** (`/opt/softhsm2/tokens`): where
  the Master Storage Key physically lives, protected by the token's PIN.
  Only the daemon process (running as the `softhsm` user) has any
  access to it.

Only the **Master Storage Key** lives inside the token. Each
subscriber's wrapped `K`/`OPc` is small enough to store as an ordinary
database field (`security.wrapped_k` / `security.wrapped_opc` in
MongoDB, base64-encoded) — the HSM doesn't need to know about
subscribers ahead of time; it just unwraps whatever wrapped blob it's
handed, using the one key it does hold.

## What the 5G core asks for, and when

There are exactly two request types the UDM sends to the HSM, both
described below. Both happen during the standard 3GPP 5G-AKA exchange
(TS 33.501) — this system does not change that exchange's shape at all,
it only changes *where* the cryptographic computation happens.

### 1. Generate a 5G Home Environment Authentication Vector (5G-HE-AV)

Triggered whenever the UDM needs to hand an AMF a fresh authentication
vector for a subscriber — i.e. on every Nudm_UEAuthentication
`Authenticate` request the UDM receives (normal registration,
periodic re-authentication, etc.).

**UDM sends:**

| Field | Meaning |
| --- | --- |
| SUPI | subscriber identifier, e.g. `imsi-999700000012345` |
| wrapped K | the subscriber's permanent key, wrapped (from MongoDB) |
| wrapped OPc | the subscriber's operator constant, wrapped (from MongoDB) |
| SQN | the sequence number to use for this vector (UDM/UDR still owns SQN state — see "Who owns SQN" below) |
| AMF | Authentication Management Field |
| SNN | Serving Network Name (used to derive KAUSF per TS 33.501 Annex A.2) |

**HSM does, internally, without ever exposing intermediate values:**

1. Unwrap `K` and `OPc` using the Master Storage Key (AES Key Wrap
   with Padding, RFC 5649).
2. Run Milenage f1–f5/f5* with the unwrapped `K`/`OPc` and the given
   RAND (generated fresh, internally, by the HSM — see below),
   SQN, AMF to get MAC-A, RES, CK, IK, AK.
3. Compute AUTN = (SQN ⊕ AK) || AMF || MAC-A.
4. Derive XRES* and KAUSF from RES/CK/IK per TS 33.501 Annex A.4 and
   A.2, using RAND and SNN.
5. Discard the unwrapped `K`/`OPc` and all intermediate values
   (MAC-A, AK, RES, CK, IK) — they never leave the function that
   computed them.

**HSM returns:** RAND (the one it generated), AUTN, XRES*, KAUSF.
Nothing else. In particular it never returns `K`, `OPc`, MAC-A, AK,
RES, CK, or IK.

The UDM/AUSF then run the completely standard 5G-AKA exchange with
these four values exactly as if it had computed them locally — the AMF
and the UE-side USIM are unaware anything is different.

### 2. Resynchronization (SQN recovery after a sync failure)

Triggered when a USIM reports a synchronization failure (its own SQN
has drifted from what the network last used) — the AMF forwards a
resync request up through AUSF to UDM.

**UDM sends:** SUPI, wrapped K, wrapped OPc, RAND (from the failed
attempt), AUTS (the resynchronization token the USIM computed).

**HSM does:** unwraps `K`/`OPc`, runs Milenage f5*/f1* to verify AUTS
authenticity (this also authenticates that the request really came from
a USIM holding the right key, not a forged resync attempt) and recovers
the USIM's actual SQN (SQN_MS).

**HSM returns:** SQN_MS (or a signature-verification failure if AUTS
doesn't check out).

The UDM then updates its own stored SQN state to the recovered value.

## What the HSM never receives or returns

- Plaintext `K`/`OPc` — never sent over the network by the UDM at
  authentication time (only ever handled, briefly, at provisioning
  time — see "Provisioning" below, and only in development/PoC mode).
- The daemon never returns `K`, `OPc`, or any Milenage intermediate
  (MAC-A, AK, RES, CK, IK) in any response, success or failure.
- The wire protocol has no operation that reads the Master Storage Key
  out of the token in any form — only PKCS#11 mechanisms that use it
  internally during a sign/wrap/unwrap operation.

## Who owns SQN

The HSM is stateless with respect to sequence numbers. It receives an
SQN as an input (for AV generation) or returns a recovered one (for
resync) but never stores or tracks SQN state itself. SQN bookkeeping —
incrementing per successful AV, persisting across restarts, detecting
out-of-range values — remains entirely the UDM/UDR's responsibility,
backed by MongoDB, exactly as in the stock (non-HSM) Open5GS
implementation. This is why a resync can happen even against an
HSM-backed subscriber: the UDM's locally-tracked SQN estimate can still
drift from the USIM's, the same as with plaintext subscribers; the HSM
just does the verification/recovery math instead of the UDM doing it
in-process.

## The wire protocol (S5GM)

Requests and responses are TLV-encoded (tag/length/value) inside a
fixed 12-byte header:

```
magic(4)="S5GM" | version(1) | operation(1) | reserved(2) | total_length(4, big-endian, includes header)
```

Operations: `PROVISION` (0x01), `5G_HE_AV` (0x02), `RESYNC` (0x03),
`IMPORT_TRANSPORT` (0x04).

`PROVISION` is unconditionally refused by `softhsm-gsm` over the
network, regardless of build flags — it would mean sending plaintext
`K`/`OPc` over the wire, which this daemon never allows; see the file
header comment in `src/bin/milenage/softhsm-gsm.cpp`. It is only
ever available locally, via `softhsm2 provision` on the HSM host itself.

`IMPORT_TRANSPORT` is different: it never carries plaintext `K`/`OPc`
(the whole point of the Transport KEK is that it doesn't need to), so
the daemon *can* accept it over the network if it was started with a
Transport KEK configured (`--transport-kek-label`/`--transport-kek-id`)
— this package's `contrib/systemd/` setup does not do this by default
and instead uses `softhsm2 import-transport-wrapped` locally on the HSM
host (see `USAGE.md` step 5); enabling it over the network is a valid
choice if your provisioning system genuinely needs to reach the HSM
remotely, at the cost of one more thing reachable on that trusted
network segment.

This TLV/header protocol is a thin daemon-level framing around the
same PKCS#11 vendor mechanisms (`CKM_SOFTHSM_5G_HE_AV_WRAPPED`,
`CKM_SOFTHSM_MILENAGE_RESYNC_WRAPPED`, and — if a Transport KEK is
configured — `CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED`) that the
local `softhsm2-milenage` CLI uses directly via PKCS#11 — the daemon
exists only to expose those same mechanisms to a process running on a
different host, since PKCS#11 itself is not a network protocol.

The daemon-level TCP framing (distinct from, and wrapping, S5GM itself)
is:

```
request  := <S5GM message>                          (client -> daemon)
response := u32be payload_len | u8 status | payload  (daemon -> client)
              status 0 = OK,    payload = an S5GM response message
              status 1 = ERROR, payload = short UTF-8 error text (no secrets)
```

**This channel is plaintext, unauthenticated TCP.** There is no TLS, no
client authentication. It is only appropriate on a network segment
already as trusted as the HSM host's own process memory (see the
Security notes in `README.md`). Anyone who can reach the port can
request AVs/resync for any wrapped credential they can supply — the
protection this system provides is entirely about keeping `K`/`OPc`
out of the UDM/database, not about authenticating who can ask the HSM
to compute with a *given* wrapped credential.

## Provisioning: how a subscriber gets a wrapped K/OPc in the first place

Before any of the above can happen for a subscriber, their `K`/`OPc`
must be wrapped under the Master Storage Key once, and the result
stored wherever the UDR reads subscriber records from (MongoDB,
normally). This is a one-time, offline operation per subscriber — not
part of the authentication path, and not something the UDM ever
triggers at runtime.

There are two ways to get a wrapped credential into the database, and
they differ in exactly one thing: whether plaintext `K`/`OPc` ever
exists in a process on this HSM host.

**Development/PoC mode: `softhsm2 provision`.** Reads plaintext
`K`/`OPc` from stdin, wraps it under the Master Storage Key, and writes
out `wrapped_k`/`wrapped_opc`. The CLI itself warns about this every
time it runs. Plaintext key material transits this host's process
memory (briefly) during provisioning — never written to disk unwrapped,
never sent over any network, but present in this host's RAM for a
moment. Requires a build with `WITH_MILENAGE_PLAINTEXT_PROVISIONING`
and the explicit `--allow-plaintext-test-provisioning` flag.

**Production mode: the Transport KEK / `import-transport-wrapped`
flow.** The subscriber's `K`/`OPc` is wrapped under a separate
Transport KEK *before* it ever reaches this host — by whatever external
system issues SIM/USIM credentials — and the HSM only ever
unwraps-and-rewraps the already-encrypted package under the Master
Storage Key. Plaintext `K`/`OPc` never exists in any process on this
HSM host at all. This is implemented end to end:

- The Transport KEK itself is generated *outside* the HSM
  (`external-scripts/generate-transport-kek.sh` — a plain `openssl
  rand`, nothing HSM-specific) and then imported into the token
  (`softhsm2 import-transport-kek`) as `CKA_EXTRACTABLE=FALSE`, so from
  that point on the HSM can use it to unwrap incoming packages but can
  never be asked to give the KEK's value back out. It has to be
  generated outside and imported, rather than generated inside the HSM,
  precisely because the external wrapping tool needs the same raw value
  too — a key generated as non-extractable inside the HSM could never
  leave to reach that external tool in the first place.
- The wrapping itself (`external-scripts/wrap-transport-package.py`)
  is deliberately independent of the SoftHSMv2 codebase — it only
  reimplements the documented on-wire package format
  (`src/lib/milenage/TransportEnvelope.cpp`/`.h` in the SoftHSMv2 tree)
  using the standalone `cryptography` Python package. That's the point:
  a real external system has no reason to depend on SoftHSMv2 at all,
  only on the documented format.
- `softhsm2 import-transport-wrapped` performs the unwrap-under-Transport-KEK,
  rewrap-under-Master-Storage-Key step inside a single PKCS#11 call
  (`CKM_SOFTHSM_MILENAGE_IMPORT_TRANSPORT_WRAPPED`), and returns
  `wrapped_k`/`wrapped_opc` — the exact same shape `provision` produces,
  just without this host ever holding the plaintext.

See `USAGE.md` step 5 for the full worked command sequence, including
writing the result into MongoDB and testing registration.

## Trust boundary summary

| Holds plaintext K/OPc? | Component |
| --- | --- |
| No, never | UDM, UDR, MongoDB, network between UDM and HSM, and (in production mode) this HSM host itself |
| Briefly, at provisioning time only (PoC mode only) | whoever runs `softhsm2 provision` on the HSM host |
| Briefly, at provisioning time only (production mode) | whatever external system runs `wrap-transport-package.py` — never this HSM host |
| Yes, always, but never exposes it | the Master Storage Key inside the SoftHSM token, and the Milenage computation running inside `softhsm-gsm`'s process for the duration of a single request |

If this HSM host is compromised, the Master Storage Key and the
in-flight computation are exposed — this system does not defend
against that. What it defends against is the far more common case: a
database leak, a misdirected backup, or overly broad read access to
MongoDB, none of which expose any subscriber's actual key material,
because that material was never stored there in usable form.
