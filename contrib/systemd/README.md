# Running softhsm2-milenaged as a systemd service

`softhsm2-milenaged` is a plain-TCP daemon that speaks the S5GM protocol
(see `doc/MILENAGE-5G-AKA-DESIGN.md`). This directory packages it as a
proper systemd service instead of a manually-backgrounded process:

- runs as a dedicated `softhsm` system user, not root or your login user
- config under `/etc/softhsm2/` (`softhsm2.conf`, `milenaged.env`, `milenaged-pin`)
- token store under `/var/lib/softhsm2/tokens/`
- logs under `/var/log/softhsm/softhsm2-milenaged.log`
- `Restart=on-failure`, starts on boot (`systemctl enable`)
- sandboxed via systemd hardening directives (`ProtectSystem=strict`,
  `NoNewPrivileges`, `PrivateDevices`, etc.)

## Install

```
sudo ./install.sh
```

This builds on the already-built `../../build` tree, `cmake --install`s
the binaries/PKCS#11 module to `/usr/local`, creates the `softhsm`
user, writes default config, and -- unless you pass `--fresh-token-dir`
-- migrates the existing dev token store from
`~/open5gs-scripts/hsm-scripts/tokens/` so already-provisioned
subscribers keep working without re-provisioning.

## After install

```
sudo systemctl status softhsm2-milenaged
sudo tail -f /var/log/softhsm/softhsm2-milenaged.log
```

Stop the old manually-started dev daemon
(`open5gs-scripts/hsm-scripts/08-stop-daemon.sh`) if it's still
running -- only one process should hold the token at a time.

Point `udm.hsm.host`/`udm.hsm.port` in the UDM config at this host, as
before. `token_label`/`master_key_label`/`master_key_id`/`user_pin` in
that config are for logging parity only (see `lib/hsm/ogs-hsm.h` in the
open5gs tree) -- they don't need to change unless you re-provision under
a different label.

## Security notes (unchanged from the dev daemon)

- No TLS/authentication on the wire -- loopback-only by default
  (`LISTEN_ADDR=127.0.0.1` in `milenaged.env`). Only bind to a
  non-loopback address on a network segment you already trust as much
  as this host's own process memory.
- The PIN file at `/etc/softhsm2/milenaged-pin` unlocks the token same
  as before; keep it mode 640, owner `root:softhsm`.
