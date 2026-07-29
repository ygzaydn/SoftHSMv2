#!/bin/bash
# Generates a Transport KEK (32 raw bytes, AES-256) -- the key an
# external subscriber-provisioning system uses to wrap K/OPc before it
# ever reaches this HSM host. See ../METHODOLOGY.md "Provisioning" and
# README.md in this directory for what this is and why it can't be
# generated inside the HSM.
#
# In a real deployment this script (or equivalent) runs on the SEPARATE
# system that issues SIM/USIM credentials, not on the HSM host -- the
# whole point of the Transport KEK is that plaintext K/OPc never
# reaches the HSM host except already wrapped under this value. It's
# included here so the same host can act as both sides for PoC/testing.
#
# usage: generate-transport-kek.sh [output-path]
#   output-path defaults to /opt/softhsm2-milenaged/config/transport-kek
#
# After running this:
#   1. Import the SAME raw value into the HSM (this makes it
#      unextractable from that point on):
#        sudo softhsm2 import-transport-kek --input-fd 0 \
#            < /opt/softhsm2-milenaged/config/transport-kek
#   2. Use wrap-transport-package.py, pointed at the same file, on
#      whatever system will be wrapping subscriber K/OPc.
set -euo pipefail

OUT="${1:-/opt/softhsm2-milenaged/config/transport-kek}"

if [ -e "$OUT" ]; then
    echo "error: $OUT already exists -- refusing to overwrite a Transport KEK that may already be in use." >&2
    echo "       If you are rotating it, move the old file aside first and re-import a new one" >&2
    echo "       under a different --transport-kek-label/--transport-kek-id." >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
umask 077
openssl rand -out "$OUT" 32
chmod 600 "$OUT"

echo "Transport KEK written to $OUT (32 bytes, mode 600)."
echo ""
echo "This file is as sensitive as the Master Storage Key's PIN -- anyone"
echo "who has it can produce packages this HSM will accept as genuine."
echo "Keep it off any host/backup that doesn't strictly need it, and treat"
echo "it as the property of whatever external system does the wrapping,"
echo "not of this HSM host."
echo ""
echo "Next: import the same value into the HSM, then use it with"
echo "wrap-transport-package.py to onboard subscribers. See README.md."
