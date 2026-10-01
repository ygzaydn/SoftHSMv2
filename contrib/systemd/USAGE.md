# softhsm-gsm: installation, subscriber onboarding, and daily operation

This document covers the full lifecycle of running `softhsm-gsm` as
a systemd service: installing it, initializing the token, generating the
Master Storage Key, onboarding (provisioning) subscribers, running the
daemon, and day-to-day operational commands. Every command below is
self-contained and uses only what this package installs.

## 0) Build and install

```bash
# From the parent directory containing both repositories:
cd open5gs-scripts/hsm-scripts
sudo ./install.sh
```

`install.sh` builds the current source tree itself — you don't need to
build first. On every run it configures with:

| Flag | Purpose |
| --- | --- |
| `WITH_CRYPTO_BACKEND=openssl` | crypto backend for AES-KWP/CMAC used by Milenage wrapping. |
| `WITH_MILENAGE=ON` | required — builds the Milenage/5G-AKA vendor mechanisms, the `softhsm2-milenage` CLI, and `softhsm-gsm`. |
| `WITH_MILENAGE_PLAINTEXT_PROVISIONING=OFF` | Disables the development-only plaintext `provision` command. Use transport-wrapped import (step 5). |
| `WITH_MILENAGE_TRANSPORT_IMPORT=ON` | required for the Transport KEK / `import-transport-wrapped` flow (step 5). |
| `WITH_MILENAGE_TEST_RAND=OFF` | Uses the normal random source for RAND generation. |

On every run (including re-runs) it reconfigures and rebuilds before
installing, so a previously cached development build cannot silently
leave plaintext provisioning or deterministic test RAND enabled.

It then installs:

- the daemon (`softhsm-gsm`) and PKCS#11 module (`libsofthsm2.so`)
  under `/usr/local`
- a `softhsm2` command on your `PATH` (`/usr/local/bin/softhsm2`) — a
  thin wrapper around the underlying `softhsm2-milenage` binary that
  already knows this host's module path, token label, and PIN file, so
  you don't have to pass `--module`/`--token-label`/`--pin-file` on
  every call
- a dedicated `softhsm` system user/group
- `/opt/softhsm2/etc/{softhsm2.conf,gsm.env,gsm-pin}` (active config
  generated from the checked-in examples; existing values are preserved,
  with missing SoftHSM defaults added)
- the `softhsm2-gsm.service` systemd unit, installed, enabled, and
  started

If this is a fresh token store (no `--migrate-from-token-dir`, nothing
already there), it also **interactively prompts you** — on a real
terminal — for:

- token label, listen address, and listen port (defaults:
  `open5gs-milenage`, `127.0.0.1`, `9999` — press Enter to accept)
- a User PIN and an SO-PIN (leave either blank to have one
  auto-generated)

and then runs the token initialization and Master Storage Key creation
itself, so the service comes up ready to onboard subscribers rather
than sitting in a restart loop waiting for you to do it by hand. Both
values are printed once at the end — the User PIN is also saved to
`/opt/softhsm2/etc/gsm-pin` (the daemon and the
`softhsm2` wrapper read it from there afterwards); the SO-PIN is **not**
saved anywhere, write it down if you want it for future re-initialization.

If `install.sh` isn't run from an interactive terminal (e.g. from
another script), it skips the prompts and auto-generates both PINs and
the default label/address/port, printing them at the end the same way.

Check it's on your PATH and see all available commands:

```bash
sudo softhsm2 --help
```

## 2) Check status: `softhsm2 summary`

At any point after installing — right after install, after initializing
the token, after onboarding subscribers, or just to check on things —
run:

```bash
sudo softhsm2 summary
```

This reports, in one place: whether the systemd service is active and
enabled, the configured listen address/port, which slot (if any) reports
the configured token label and its serial/initialization state, how much
is on disk in the token store, whether a Master Storage Key exists, the
PIN file's ownership/permissions, and the daemon log file's size and
last-write time. It does not, and cannot, report how many subscribers
are provisioned or list any of them — wrapped K/OPc values are handed
back to the caller at provisioning time and aren't stored inside the
token itself, so there's nothing inside the HSM to enumerate. Track
subscriber counts in whatever database holds `wrapped_k`/`wrapped_opc`.

## 3) Token initialization and the Master Storage Key

On a fresh install, `install.sh` (step 0) already did this for you — it
prompted for the User PIN/SO-PIN, ran the token initialization, and
created the Master Storage Key. Verify it worked:

```bash
sudo softhsm2 inspect
```

This prints the Master Storage Key's non-secret metadata (label, id,
extractability). If it instead reports nothing is present, something
went wrong during install — check
`journalctl -u softhsm-gsm` and the log file (step 7), then you
can run the same two steps by hand:

```bash
PIN=$(sudo cat /opt/softhsm2/etc/gsm-pin)
SO_PIN=$(openssl rand -hex 8)   # only needed if you must re-initialize; see step 11

sudo -u softhsm softhsm2-util --module /usr/local/lib/softhsm/libsofthsm2.so \
    --init-token --free --label open5gs-milenage \
    --so-pin "$SO_PIN" --pin "$PIN"

sudo softhsm2 create-master-key
```

The token label above (`open5gs-milenage` by default) must match
`TOKEN_LABEL` in `/opt/softhsm2/etc/gsm.env`.

One AES-256 Master Storage Key per token; running `create-master-key`
twice on the same token fails. Every subscriber's wrapped K/OPc is
wrapped under this key.

## 4) Onboard a subscriber (provision wrapped K/OPc)

**This development-only path is disabled by the installer.** Use the
transport-wrapped import flow in step 5 on an installed host. The
example below requires a separate development build configured with
`WITH_MILENAGE_PLAINTEXT_PROVISIONING=ON`.

Wraps a subscriber's plaintext K/OPc under the Master Storage Key and
writes the resulting `wrapped_k`/`wrapped_opc` (base64) to a JSON file.
This is development/PoC provisioning: plaintext K/OPc is read only from
`--input-fd`/stdin (never from argv, never logged), and requires a build
with `WITH_MILENAGE_PLAINTEXT_PROVISIONING` plus the explicit
`--allow-plaintext-test-provisioning` flag.

```bash
K_HEX=465B5CE8B199B49FAA5F0A2EE238A6BC
OPC_HEX=E8ED289DEBA952E4283B54E88E6183CA

echo -n "${K_HEX}${OPC_HEX}" | xxd -r -p \
| sudo softhsm2 provision \
    --supi "imsi-999700000012345" \
    --input-fd 0 \
    --output /tmp/999700000012345.json \
    --allow-plaintext-test-provisioning
```

Take the resulting `wrapped_k`/`wrapped_opc` values and store them on the
subscriber's record wherever your subscriber database lives (e.g. as
`security.hsm = true`, `security.wrapped_k`, `security.wrapped_opc`) —
**and set `security.k`/`security.opc` to `null` in the same update** if
the record already has plaintext values in those fields (e.g. from
creating it with `open5gs-dbctl add`). Otherwise the real K/OPc stays
sitting in the database at rest even though nothing ever reads it for
an HSM subscriber — see the worked example in step 5 for a
`db.subscribers.updateOne()` that does both at once. This package does
not manage the subscriber database itself.

For production onboarding, use the transport-wrapped import flow (step
5 below) instead — it never exposes K/OPc in plaintext to any process
on this host.

`softhsm2 provision` fails with "this build does not include plaintext
provisioning" on the installed build. Reconfiguring the source with
that option enabled is for isolated development only; running
`install.sh` again restores the production default.

## 5) Production onboarding (Transport KEK, `import-transport-wrapped`)

Unlike `provision` above, this path never has this host (or any process
on it) hold plaintext K/OPc. The Transport KEK is generated and used
*outside* this host (see `external-scripts/` and `METHODOLOGY.md`
"Provisioning" for the full explanation of why); this HSM only ever
receives K/OPc already wrapped under it.

**One-time setup, per Transport KEK** (not per subscriber):

```bash
sudo ./external-scripts/generate-transport-kek.sh
# writes /opt/softhsm2/etc/transport-kek (32 raw bytes, mode 600)

sudo softhsm2 import-transport-kek --input-fd 0 \
    < /opt/softhsm2/etc/transport-kek
```

After this, the KEK is `CKA_EXTRACTABLE=FALSE` inside the token — the
HSM can use it to unwrap incoming packages, but can never be asked to
hand its value back out. The copy on disk at
`/opt/softhsm2/etc/transport-kek` is what any external
wrapping tool (including `wrap-transport-package.py`) needs — treat it
with the same care as the token PIN.

**Per subscriber**, on whatever system has (or is trusted to briefly
handle) the subscriber's real K/OPc:

```bash
pip install cryptography   # once, wherever you run this

python3 external-scripts/wrap-transport-package.py \
    --supi imsi-999700000012345 \
    --kek-file /opt/softhsm2/etc/transport-kek \
    --k-hex 465B5CE8B199B49FAA5F0A2EE238A6BC \
    --opc-hex E8ED289DEBA952E4283B54E88E6183CA
```

This prints `transport_wrapped_k`/`transport_wrapped_opc` (base64).
Feed those to the HSM:

```bash
sudo softhsm2 import-transport-wrapped \
    --supi imsi-999700000012345 \
    --transport-wrapped-k '<transport_wrapped_k from above>' \
    --transport-wrapped-opc '<transport_wrapped_opc from above>'
```

which returns `wrapped_k`/`wrapped_opc` — store those on the
subscriber's record exactly as in step 4's plaintext path
(`security.hsm = true`, `security.wrapped_k`, `security.wrapped_opc`).

### Worked example: onboarding one subscriber end to end

Everything above in one concrete run, from a clean install through a
successful test registration, for `imsi-999700000012345`. This is the
exact sequence to follow for a real subscriber — swap in the real
SUPI/K/OPc and, in production, run the K/OPc-handling step (2) on the
external system that actually has them, not on the HSM host.

**1. Generate and import the Transport KEK** (once per deployment, not
per subscriber — skip if already done):

```bash
sudo ./external-scripts/generate-transport-kek.sh
sudo softhsm2 import-transport-kek --input-fd 0 \
    < /opt/softhsm2/etc/transport-kek
```

**2. Wrap the subscriber's K/OPc under the Transport KEK** (on the
external provisioning system, in production; here, for a local
test, on the HSM host itself):

```bash
python3 ./external-scripts/wrap-transport-package.py \
    --supi imsi-999700000012345 \
    --kek-file /opt/softhsm2/etc/transport-kek \
    --k-hex 465B5CE8B199B49FAA5F0A2EE238A6BC \
    --opc-hex E8ED289DEBA952E4283B54E88E6183CA
```

This prints JSON with `transport_wrapped_k`/`transport_wrapped_opc`.

**3. Submit the transport-wrapped package to the HSM**, getting back
the values that actually go in the database:

```bash
sudo softhsm2 import-transport-wrapped \
    --supi imsi-999700000012345 \
    --transport-wrapped-k '<transport_wrapped_k from step 2>' \
    --transport-wrapped-opc '<transport_wrapped_opc from step 2>'
```

This prints `{"hsm": true, "wrapped_k": "...", "wrapped_opc": "...", ...}`.

**4. Write the subscriber into Open5GS's database.** Create the base
subscriber record however you normally would (e.g. Open5GS's own
`misc/db/open5gs-dbctl add <imsi> <dummy-k> <dummy-opc>`, or the WebUI).
**Use an obviously-fake K/OPc for this step, never the subscriber's real
one** — `open5gs-dbctl add` writes them straight into `security.k`/
`security.opc` as plaintext, and the next command below only adds the
HSM fields on top, it does not remove them. Then set the HSM fields
**and null out the plaintext ones in the same update**:

```javascript
// mongosh
db.subscribers.updateOne(
  { imsi: "999700000012345" },
  { $set: {
      "security.hsm": true,
      "security.wrapped_k": "<wrapped_k from step 3>",
      "security.wrapped_opc": "<wrapped_opc from step 3>",
      "security.k": null,
      "security.opc": null
  }}
);
```

**5. Restart the UDM** (it caches `udm.hsm.*` config at startup, and if
it was already running against this token before you recreated it,
restarting also clears any stale connection state):

```bash
sudo systemctl restart open5gs-udmd   # or however your deployment manages it
```

**6. Test registration.** With a UE simulator (e.g. UERANSIM) configured
with `supi: imsi-999700000012345` and the same plaintext `key`/`op` used
in step 2 (the UE side needs the real K/OPc to compute its own
Milenage, exactly like a real SIM would — only the HSM's copy is
wrapped), attempt registration and confirm both sides:

```bash
# UE simulator log should show:
#   Initial Registration is successful

# UDM log (sudo journalctl -u open5gs-udmd, or wherever it logs) should show:
sudo grep -i "imsi-999700000012345" /path/to/udm.log
#   ... HSM 5G-HE-AV request
#   ... HSM 5G-HE-AV success
```

If the UE registers and the UDM log shows `HSM 5G-HE-AV success` (not
`failed`), the subscriber is fully onboarded and authenticating through
the HSM. A `HSM resync request`/`success` pair appearing too is normal
on a subscriber's first ever authentication (the UDM's initial SQN
guess is often out of range) and isn't a problem.

**Important — existing Master Storage Keys must be recreated to use
this.** `CKA_ALLOWED_MECHANISMS` is baked into the Master Storage Key
at creation time and can never be changed afterward
(`CKA_MODIFIABLE=FALSE`). A Master Storage Key created before this
feature existed does not have `import-transport-wrapped` in its allowed
mechanism list, and `import-transport-wrapped` will fail against it
with a generic `C_SignInit failed` error. There is no in-place fix —
you must reset the token (step 11) and re-provision every subscriber
under a fresh Master Storage Key. Do this before this token has real
subscribers in production; if it already does, plan the cutover (new
token or reset window) accordingly.

## 6) Start / stop / restart the service

```bash
sudo systemctl start softhsm-gsm
sudo systemctl stop softhsm-gsm
sudo systemctl restart softhsm-gsm     # required after any config change
sudo systemctl status softhsm-gsm
sudo systemctl enable softhsm-gsm      # start automatically on boot
sudo systemctl disable softhsm-gsm
```

Configuration files:

```bash
sudo nano /opt/softhsm2/etc/gsm.env     # TOKEN_LABEL, LISTEN_ADDR, LISTEN_PORT
sudo nano /opt/softhsm2/etc/softhsm2.conf     # token directory, log level, etc.
sudo systemctl restart softhsm-gsm  # apply changes
```

## 7) Logs

```bash
sudo tail -f /opt/softhsm2/logs/softhsm-gsm.log
journalctl -u softhsm-gsm -f
```

Logs include AV/resync request and response events (SUPI, operation
name, RAND/AUTN/XRES*/KAUSF in hex). PIN, K, OPc, and wrapped
K/OPc are never logged.

Each line is timestamped and colored (`MM/DD HH:MM:SS.mmm: [soft-hsm]
INFO: ...`) in the same style as Open5GS's own logs, so this daemon's
log reads consistently next to the UDM log it's paired with — `tail
-f` and `less -R` render the colors, plain `cat` shows the raw ANSI
codes.

The log file is archived, not truncated, on every stop: when the
service stops (manually, on restart, or after a crash-restart), the
current log is renamed to
`softhsm-gsm-<UTC-ish local timestamp, YYYYMMDDTHHMMSS>.log` in
the same directory, and a fresh `softhsm-gsm.log` is created the
next time it starts. Nothing is deleted automatically — old archives
accumulate under `/opt/softhsm2/logs/` until you clean them
up yourself.

## 8) Generate a 5G HE AV (smoke test)

With a subscriber provisioned as in step 4 or 5:

```bash
WRAPPED_K=$(grep -o '"wrapped_k":"[^"]*"' /tmp/999700000012345.json | cut -d'"' -f4)
WRAPPED_OPC=$(grep -o '"wrapped_opc":"[^"]*"' /tmp/999700000012345.json | cut -d'"' -f4)

sudo softhsm2 generate-5g-av \
    --supi "imsi-999700000012345" \
    --wrapped-k "$WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
    --sqn 000000000001 --amf 8000 --snn "5G:mnc001.mcc001.3gppnetwork.org"
```

This exercises the token directly through the CLI (not the network
daemon). To confirm `softhsm-gsm` itself is reachable over TCP,
connect to `LISTEN_ADDR:LISTEN_PORT` (from `/opt/softhsm2/etc/gsm.env`)
and send an S5GM `GENERATE_5G_HE_AV` request with the same wrapped
credentials and parameters; a healthy daemon returns a successful S5GM
response containing RAND/AUTN/XRES*/KAUSF.

## 9) Resynchronization

If a USIM reports a sync failure (RAND + AUTS from the failed attempt),
recover SQN_MS:

```bash
sudo softhsm2 resync \
    --supi "imsi-999700000012345" \
    --wrapped-k "$WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
    --rand "<rand-hex32>" --auts "<auts-hex28>"
```

## 10) Preventing token conflicts

Only one process may hold the token's PIN session at a time. If you
previously ran `softhsm-gsm` manually (outside systemd) against
the same token directory, stop that process before starting the service,
and don't run both simultaneously.

## 11) Destructive: reset the token

Wipes all keys and all wrapped subscriber credentials on this token.
There is no undo — subscribers provisioned under it must be re-onboarded
from step 4 onward, against a fresh Master Storage Key created during step 3.

```bash
sudo systemctl stop softhsm-gsm
sudo rm -rf /opt/softhsm2/tokens/*
sudo rm -f /opt/softhsm2/etc/gsm-pin
# then repeat step 3 (init token and create master key)
```

## 12) Uninstall

Removes everything `install.sh` created:

```bash
sudo ./uninstall.sh
```

This stops and removes the systemd unit, the `softhsm2` wrapper, the
binaries and PKCS#11 module (using the installed manifest under
`/opt/softhsm2/etc/`, even if `build/` was deleted), and
the `softhsm` system user and group on a full uninstall. It always removes
`/opt/softhsm2/etc` and `/opt/softhsm2/logs`
without prompting (config is regenerated on reinstall; logs aren't
meant to outlive the service). It prompts before deleting
`/opt/softhsm2/tokens`, since that permanently destroys the
Master Storage Key and every subscriber's wrapped credentials:

```bash
sudo ./uninstall.sh --keep-tokens   # preserve /opt/softhsm2/tokens
sudo ./uninstall.sh --yes           # don't prompt before deleting it
```

`--keep-tokens` is what you want before reinstalling on the same host,
or before migrating the token store elsewhere with
`install.sh --migrate-from-token-dir`. It also retains the `softhsm`
account and wrapped credential files, preserving their ownership.

## Configuration reference

All state this package manages lives in one of these places. Nothing
else needs to be tracked or backed up separately.

| Path | Contents | Who reads it |
| --- | --- | --- |
| `/usr/local/bin/softhsm2-milenage` | CLI binary. | invoked by the `softhsm2` wrapper. |
| `/usr/local/bin/softhsm-gsm` | daemon binary. | invoked by the systemd unit. |
| `/usr/local/bin/softhsm2` | the wrapper described in step 0 — the only command you're expected to type by hand. | you. |
| `/usr/local/bin/softhsm-gsm-rotate-log` | archives the log file on every service stop (see step 7). Not meant to be run by hand. | the systemd unit (`ExecStopPost=`). |
| `/usr/local/lib/softhsm/libsofthsm2.so` | PKCS#11 module. | both binaries above, path is baked into the `softhsm2` wrapper and the systemd unit. |
| `/opt/softhsm2/etc/softhsm2.conf` | Token directory, object store permissions, log file, and mechanism settings. | every PKCS#11 client (`softhsm2-util`, `softhsm2-milenage`, `softhsm-gsm`) via `SOFTHSM2_CONF`. |
| `/opt/softhsm2/etc/gsm.env` | `TOKEN_LABEL`, `LISTEN_ADDR`, `LISTEN_PORT`. | the systemd unit (`EnvironmentFile=`) and the `softhsm2` wrapper (sourced directly, so both always agree on the token label). |
| `/opt/softhsm2/etc/gsm-pin` | the token's user PIN, plaintext, mode `640`, owner `root:softhsm`. | the systemd unit and the `softhsm2` wrapper. Never printed, logged, or accepted as a command-line argument. |
| `/opt/softhsm2/tokens/` | the actual token: Master Storage Key, Transport KEK (if imported), and every subscriber's wrapped K/OPc. | `softhsm-gsm`, `softhsm2` wrapper commands — this directory is the one thing worth backing up. |
| `/opt/softhsm2/etc/transport-kek` | the raw 32-byte Transport KEK (see step 5) — NOT created by `install.sh`, only by `external-scripts/generate-transport-kek.sh`. Mode 600, owner `root:root` (not `softhsm`) — the daemon has no need for it. | `external-scripts/wrap-transport-package.py`, and whatever imported it into the token once via `softhsm2 import-transport-kek`. |
| `/opt/softhsm2/logs/softhsm-gsm.log` | daemon operational log (see step 7). | you, via `tail`/`journalctl`. |
| `/opt/softhsm2/logs/softhsm-pkcs11.log` | PKCS#11 library log; rotated separately from daemon stdout/stderr. | every PKCS#11 client through `log.file` in `softhsm2.conf`. |

### Why `--module` isn't something you set

`softhsm2-milenage` and `softhsm-gsm` both take `--module` as a
raw CLI flag, because the underlying binaries are generic PKCS#11
tools that don't assume any particular install layout. On a host
installed by `install.sh`, though, there's exactly one module
(`/usr/local/lib/softhsm/libsofthsm2.so`) and exactly one systemd unit
using it — there's nothing for a second value to mean. The `softhsm2`
wrapper (step 0) and the systemd unit hard-code that path so you never
type it. The only two values that legitimately vary per-deployment are
the token label and the listen address/port, and both of those already
live in `/opt/softhsm2/etc/gsm.env` rather than being passed by hand
each time. If you ever run more than one token on the same host (e.g.
to separate environments), that's the point where `--module` stops
being fixed — see "Running more than one token" below.

### Running more than one token on the same host

This package assumes one token, one `softhsm-gsm` instance, one
`softhsm2` wrapper. To run a second, independent token (a different
`TOKEN_LABEL`, its own Master Storage Key, its own listen port), you'd
need a second `/opt/softhsm2/etc/gsm.env`, a second systemd unit
(copy `softhsm2-gsm.service` under a new name and point its
`EnvironmentFile=` at the new env file), and a second wrapper script (a
copy of `softhsm2-wrapper.sh` under a different name, pointed at that
env file). This isn't automated by `install.sh` — it only sets up the
single-token case described above.
