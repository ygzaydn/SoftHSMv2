# Running softhsm-gsm as a systemd service

`softhsm-gsm` speaks the S5GM protocol over TCP or a Unix domain socket
(see `doc/MILENAGE-5G-AKA-DESIGN.md`). This directory packages it as a
proper systemd service instead of a manually-backgrounded process.

Docs in this directory:
- **README.md** (this file) — install/uninstall, service basics.
- **USAGE.md** — the full command reference, step by step, including
  subscriber onboarding (both PoC and production).
- **METHODOLOGY.md** — how the system works: what the 5G core asks the
  HSM for and why, the wire protocol, the trust boundary.
- **external-scripts/** — the external-system side of production
  onboarding (Transport KEK generation, K/OPc wrapping); see
  `external-scripts/README.md`.

What this package sets up:

- runs as a dedicated `softhsm` system user, not root or your login user
- config under `/opt/softhsm2/etc/` (`softhsm2.conf`, `gsm.env`, `gsm-pin`)
- token store under `/opt/softhsm2/tokens/`
- logs under `/opt/softhsm2/logs/softhsm-gsm.log`
- `Restart=on-failure`, starts on boot (`systemctl enable`)
- sandboxed via systemd hardening directives (`ProtectSystem=strict`,
  `NoNewPrivileges`, `PrivateDevices`, etc.)
- a `softhsm2` convenience command on `PATH`, pre-configured for this
  host's module/token/PIN, so day-to-day operations don't require
  repeating `--module`/`--token-label`/`--pin-file` by hand

## Install

On another Ubuntu host, place `SoftHSMv2` and `open5gs-scripts` side by
side, then install the build prerequisites (CMake, a C++ compiler, Make,
OpenSSL headers, and pkg-config). Start the installer from the scripts
directory:

```sh
sudo apt update
sudo apt install -y build-essential cmake pkg-config libssl-dev
cd open5gs-scripts/hsm-scripts
sudo ./install.sh
systemctl status softhsm2-gsm.service
```

If the repositories are not siblings, pass the SoftHSM source path:
`sudo env HSM_REPO=/path/to/SoftHSMv2 ./install.sh`.

The fresh install creates a new token and Master Storage Key. Subscriber
credentials wrapped for a different token must be provisioned again.
To move an existing deployment instead, stop its daemon and transfer the
token directory, User PIN file, and any wrapped credential files securely;
use the migration options below for the token and PIN. Keep the token,
Master Storage Key, PIN, and wrapped subscriber data together.

It builds the current source tree itself (configuring on first run,
rebuilding on every run) and installs the binaries/PKCS#11 module into
`/usr/local`, creates the `softhsm` system user, and writes default
config into `/opt/softhsm2/etc/` (without overwriting
anything already there). On a fresh token store it also **prompts you**
for a token label, listen address/port, and a User PIN/SO-PIN (or
auto-generates any of them if run without a terminal), then initializes
the token and creates the Master Storage Key itself — the service comes
up ready to onboard subscribers rather than needing manual setup
afterwards. It installs the `softhsm2` wrapper command and installs,
enables, and starts the systemd unit.

Moving an existing token from another install of this same daemon (a
different host, or a prior standalone setup)? Pass
`--migrate-from-token-dir <path>` (and optionally
`--migrate-from-pin-file <path>`) to copy it into place instead of
starting fresh:

```
sudo ./install.sh --migrate-from-token-dir /path/to/old/tokens \
                   --migrate-from-pin-file /path/to/old/pin
```

## After install

```
sudo systemctl status softhsm2-gsm
sudo softhsm2 --help
sudo softhsm2 summary
sudo tail -f /opt/softhsm2/logs/softhsm-gsm.log
```

For Open5GS on the same host, set
`LISTEN_UNIX=/run/softhsm-gsm/gsm.sock` in
`/opt/softhsm2/etc/gsm.env` and restart the service.
This enables the Unix socket alongside TCP. The socket and its parent
directory are accessible to the `softhsm` group; add the Open5GS UDM
service account to that group, then restart UDM so it gains membership.
Configure the S5GM client in Open5GS to connect to that pathname with
`AF_UNIX` and `SOCK_STREAM`; request and response framing is identical
to TCP. This repository does not contain the Open5GS client code, so
its connection setting must be changed in that deployment separately.

Existing installations using the former `softhsm2-milenaged` directory
must retain their token store and PIN. Stop the old service and install
with `--migrate-from-token-dir /opt/softhsm2-milenaged/tokens` and
`--migrate-from-pin-file /opt/softhsm2-milenaged/config/milenaged-pin`.
The installer refuses to initialize a new token while it detects an
unmigrated old token store. Update the Open5GS socket pathname and
service references after migration.

`softhsm2 summary` gives a one-shot overview of the deployment: service
state, listen address, token slot/label/serial, Master Storage Key
presence, PIN file permissions, and log file status.

Only one process may hold a given token at a time — stop any other
`softhsm-gsm` instance pointed at the same token store before
starting this one.

For the full command set — initializing the token, generating the
Master Storage Key, onboarding subscribers (both the PoC plaintext path
and the production Transport KEK path), generating AVs, running resync,
checking status, and resetting the token — see `USAGE.md` in this
directory. For a single, complete walkthrough of onboarding one
subscriber in production mode end to end (KEK generation through a
successful test registration), see `USAGE.md` step 5.

## Uninstall

```
sudo ./uninstall.sh
```

Stops and removes the systemd unit, the `softhsm2` wrapper, the
installed binaries/PKCS#11 module, `/opt/softhsm2/etc`, `/opt/softhsm2/logs`,
and the `softhsm` system user/group. It prompts before deleting
`/opt/softhsm2/tokens` (the token store) since that destroys the Master
Storage Key and makes every subscriber's wrapped credentials
unrecoverable — pass `--keep-tokens` to preserve it (e.g. before
reinstalling, or to migrate it elsewhere with
`install.sh --migrate-from-token-dir`), or `--yes` to skip the prompt in
a non-interactive script.

## Security notes

- No TLS/authentication on the wire — loopback-only by default
  (`LISTEN_ADDR=127.0.0.1` in `gsm.env`). Only bind to a
  non-loopback address on a network segment you already trust as much
  as this host's own process memory.
- The PIN file at `/opt/softhsm2/etc/gsm-pin` unlocks the token; keep
  it mode `640`, owner `root:softhsm`.
