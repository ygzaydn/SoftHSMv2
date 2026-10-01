#!/bin/bash
# softhsm2: convenience wrapper around softhsm2-milenage, pre-configured
# for this host's installed module, token label, and PIN file so callers
# don't need to repeat --module/--token-label/--pin-file on every
# invocation. Installed as /usr/local/bin/softhsm2 by install.sh.
#
# usage: softhsm2 <command> [options]
#   softhsm2 --help
#   softhsm2 create-master-key
#   softhsm2 inspect
#   softhsm2 provision --supi <imsi-...> --input-fd 0 --output <path> \
#       --allow-plaintext-test-provisioning [< raw-K-then-OPc-bytes]
#   softhsm2 generate-5g-av --supi <imsi-...> --wrapped-k <b64> \
#       --wrapped-opc <b64> --sqn <hex12> --amf <hex4> --snn <string>
#   softhsm2 resync --supi <imsi-...> --wrapped-k <b64> --wrapped-opc <b64> \
#       --rand <hex32> --auts <hex28>
#   softhsm2 summary
#
# Any option you pass explicitly overrides this wrapper's defaults, since
# it appends its defaults after your arguments and the underlying tool
# takes the last occurrence of a repeated option.
set -euo pipefail

REAL_CLI=/usr/local/bin/softhsm2-milenage
UTIL=/usr/local/bin/softhsm2-util
MODULE=/usr/local/lib/softhsm/libsofthsm2.so
BASE_DIR=/opt/softhsm2
CONF="$BASE_DIR/etc/softhsm2.conf"
PIN_FILE="$BASE_DIR/etc/gsm-pin"
ENV_FILE="$BASE_DIR/etc/gsm.env"
TOKEN_DIR="$BASE_DIR/tokens"
LOG_FILE="$BASE_DIR/logs/softhsm-gsm.log"

TOKEN_LABEL=open5gs-milenage
LISTEN_ADDR=""
LISTEN_PORT=""
[ -r "$ENV_FILE" ] && . "$ENV_FILE"

export SOFTHSM2_CONF="$CONF"

if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    # softhsm2-milenage prints usage on zero arguments; calling it with
    # --module etc. still set would instead try to open a PKCS#11 session
    # and fail before reaching the usage text, so pass no arguments at all.
    exec "$REAL_CLI"
fi

if [ "$1" = "summary" ] || [ "$1" = "--summary" ]; then
    echo "== Service =="
    if command -v systemctl >/dev/null 2>&1; then
        state="$(systemctl is-active softhsm2-gsm.service 2>/dev/null || true)"
        enabled="$(systemctl is-enabled softhsm2-gsm.service 2>/dev/null || true)"
        echo "  softhsm2-gsm.service: ${state:-unknown} (${enabled:-unknown})"
    else
        echo "  systemctl not available on this host"
    fi
    echo "  listening on: ${LISTEN_ADDR:-<unset>}:${LISTEN_PORT:-<unset>}  (from $ENV_FILE)"
    if [ -n "${LISTEN_UNIX:-}" ]; then
        echo "  Unix socket: $LISTEN_UNIX"
    fi

    echo "== Token =="
    echo "  configured label: $TOKEN_LABEL  (from $ENV_FILE)"
    if [ -x "$UTIL" ]; then
        SLOT_BLOCK="$("$UTIL" --module "$MODULE" --show-slots 2>/dev/null | awk -v label="$TOKEN_LABEL" '
            /^Slot / { slot=$0; buf="" }
            { buf = buf $0 ORS }
            /Label:/ {
                l = $0
                sub(/^ *Label: */, "", l)
                sub(/ *$/, "", l)
                if (l == label) { printf "%s", buf }
            }
        ' || true)"
        if [ -n "$SLOT_BLOCK" ]; then
            printf '%s\n' "$SLOT_BLOCK" | sed 's/^/  /'
        else
            echo "  no slot currently reports label '$TOKEN_LABEL'"
            echo "  (token store empty, PIN not initialized yet, or daemon holds an exclusive session)"
        fi
    else
        echo "  softhsm2-util not found at $UTIL"
    fi

    if [ -d "$TOKEN_DIR" ]; then
        obj_count="$(find "$TOKEN_DIR" -type f 2>/dev/null | wc -l)"
        du_h="$(du -sh "$TOKEN_DIR" 2>/dev/null | cut -f1)"
        echo "  token store: $TOKEN_DIR ($obj_count files on disk, ${du_h:-unknown} total)"
    fi

    echo "== Master Storage Key =="
    if inspect_out="$("$REAL_CLI" inspect --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" 2>&1)"; then
        echo "$inspect_out" | sed 's/^/  /'
    else
        echo "  not present, or token/PIN not ready yet (run: softhsm2 create-master-key)"
    fi

    echo "== PIN file =="
    if [ -f "$PIN_FILE" ]; then
        perms="$(stat -c '%U:%G %a' "$PIN_FILE" 2>/dev/null || echo unknown)"
        echo "  $PIN_FILE  ($perms)"
    else
        echo "  $PIN_FILE does not exist yet"
    fi

    echo "== Log =="
    if [ -f "$LOG_FILE" ]; then
        size_h="$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)"
        mtime="$(stat -c '%y' "$LOG_FILE" 2>/dev/null | cut -d. -f1)"
        echo "  $LOG_FILE (${size_h:-unknown}, last written $mtime)"
    else
        echo "  $LOG_FILE does not exist yet"
    fi

    echo
    echo "Note: this summarizes the token and service, not individual"
    echo "subscribers -- wrapped K/OPc values are handed back to the caller"
    echo "at provisioning time and are not enumerable from inside the token."
    exit 0
fi

exec "$REAL_CLI" "$@" \
    --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE"
