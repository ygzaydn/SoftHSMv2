# External-system scripts (not part of the HSM's trust boundary)

Everything in this directory represents work that happens **outside**
`softhsm-gsm` and outside the SoftHSM token — the "external
secure provisioning authority" side of the Transport KEK flow described
in `../METHODOLOGY.md` ("Provisioning"). In a real deployment these
scripts (or equivalents) run on a separate system, not this HSM host —
they're included here so one host can stand in for both sides during
setup/testing.

Nothing here touches PKCS#11, `libsofthsm2.so`, or the token. That's
the point: this is exactly the amount of logic an external system needs
to participate, and no more.

## `generate-transport-kek.sh`

Generates the raw 32-byte (AES-256) Transport KEK and writes it to
`/opt/softhsm2/etc/transport-kek` (mode 600, root-only —
deliberately not readable by the `softhsm` user the daemon runs as,
since the daemon never needs this file).

```bash
sudo ./generate-transport-kek.sh
```

## `wrap-transport-package.py`

Wraps a subscriber's K/OPc under that same KEK, producing the exact
package format `softhsm2 import-transport-wrapped` expects. Needs only
the `cryptography` Python package — no SoftHSMv2 build, no PKCS#11.

```bash
pip install cryptography   # once

python3 wrap-transport-package.py \
    --supi imsi-999700000012345 \
    --kek-file /opt/softhsm2/etc/transport-kek \
    --k-hex 465B5CE8B199B49FAA5F0A2EE238A6BC \
    --opc-hex E8ED289DEBA952E4283B54E88E6183CA
```

Prints `transport_wrapped_k`/`transport_wrapped_opc` (base64) — feed
those straight into:

```bash
sudo softhsm2 import-transport-wrapped --supi imsi-999700000012345 \
    --transport-wrapped-k '<transport_wrapped_k>' \
    --transport-wrapped-opc '<transport_wrapped_opc>'
```

which returns `wrapped_k`/`wrapped_opc` — the values that actually go
into the subscriber database — without this HSM host, or any process on
it, ever holding plaintext K/OPc. See `--help` on the script for the
stdin-based input path (preferred over `--k-hex`/`--opc-hex` outside of
local testing, since argv-based secrets land in shell history).

## The full onboarding sequence

```bash
# once per Transport KEK (not per subscriber):
sudo ./generate-transport-kek.sh
sudo softhsm2 import-transport-kek --input-fd 0 \
    < /opt/softhsm2/etc/transport-kek

# per subscriber:
python3 wrap-transport-package.py --supi imsi-... \
    --kek-file /opt/softhsm2/etc/transport-kek \
    --k-hex <K> --opc-hex <OPc>
# then paste transport_wrapped_k/transport_wrapped_opc into:
sudo softhsm2 import-transport-wrapped --supi imsi-... \
    --transport-wrapped-k '...' --transport-wrapped-opc '...'
```

See `USAGE.md`'s "Production onboarding" section for the same sequence
with more context.
