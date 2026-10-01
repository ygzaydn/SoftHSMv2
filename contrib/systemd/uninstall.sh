#!/bin/bash
# Removes everything install.sh created: the systemd unit, the softhsm2
# wrapper, the installed binaries/PKCS#11 module, /opt/softhsm2
# (config, tokens, logs -- with confirmation for the tokens), and the
# system user/group. Must be run as root.
#
# usage: uninstall.sh [--keep-tokens] [--yes]
#
# --keep-tokens   leave /opt/softhsm2/tokens in place, e.g. if
#                 you intend to reinstall or migrate it elsewhere with
#                 `install.sh --migrate-from-token-dir`.
# --yes           don't prompt for confirmation before deleting the
#                 token store (still destructive -- use in scripts only
#                 once you're sure).
#
# Without --keep-tokens, deleting the token store destroys the Master
# Storage Key and makes every subscriber's wrapped_k/wrapped_opc
# unrecoverable. There is no undo.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must be run as root (sudo $0)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"
BASE_DIR=/opt/softhsm2
TOKEN_DIR="$BASE_DIR/tokens"

KEEP_TOKENS=0
ASSUME_YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        --keep-tokens) KEEP_TOKENS=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

echo "==> stopping and disabling softhsm2-gsm.service"
systemctl stop softhsm2-gsm.service 2>/dev/null || true
systemctl disable softhsm2-gsm.service 2>/dev/null || true
rm -f /etc/systemd/system/softhsm2-gsm.service
rm -f /etc/systemd/system/softhsm2-gsm-alert.service
systemctl daemon-reload

echo "==> removing /usr/local/bin/softhsm2 (wrapper)"
rm -f /usr/local/bin/softhsm2

echo "==> removing /usr/local/bin/softhsm-gsm-rotate-log"
rm -f /usr/local/bin/softhsm-gsm-rotate-log

echo "==> removing /etc/logrotate.d/softhsm-gsm"
rm -f /etc/logrotate.d/softhsm-gsm

echo "==> removing installed binaries and PKCS#11 module"
if [ -f "$BUILD_DIR/install_manifest.txt" ]; then
    echo "    using $BUILD_DIR/install_manifest.txt"
    while IFS= read -r f; do
        [ -n "$f" ] && [ -f "$f" ] && rm -f "$f" && echo "    removed $f"
    done < "$BUILD_DIR/install_manifest.txt"
else
    echo "    no install_manifest.txt found, removing known fixed paths"
    for f in \
        /usr/local/bin/softhsm2-milenage \
        /usr/local/bin/softhsm-gsm \
        /usr/local/bin/softhsm2-util \
        /usr/local/bin/softhsm2-keyconv \
        /usr/local/bin/softhsm2-dump-file \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2-static.a
    do
        [ -f "$f" ] && rm -f "$f" && echo "    removed $f"
    done
    rmdir /usr/local/lib/softhsm 2>/dev/null || true
fi

if [ "$KEEP_TOKENS" -eq 1 ]; then
    echo "==> --keep-tokens given: removing config, logs and tools, leaving $TOKEN_DIR in place"
    rm -rf "$BASE_DIR/etc" "$BASE_DIR/logs" "$BASE_DIR/sbin" "$BASE_DIR/pids"
else
    if [ -d "$TOKEN_DIR" ] && [ -n "$(ls -A "$TOKEN_DIR" 2>/dev/null)" ]; then
        if [ "$ASSUME_YES" -ne 1 ]; then
            echo ""
            echo "WARNING: $TOKEN_DIR contains data -- deleting it destroys the"
            echo "Master Storage Key and makes every subscriber's wrapped_k/wrapped_opc"
            echo "permanently unrecoverable."
            read -r -p "Type 'yes' to delete the token store, anything else to keep it: " CONFIRM
            if [ "$CONFIRM" != "yes" ]; then
                echo "keeping $TOKEN_DIR -- rerun with --keep-tokens to suppress this prompt next time"
                KEEP_TOKENS=1
            fi
        fi
    fi
    if [ "$KEEP_TOKENS" -eq 1 ]; then
        echo "==> removing config, logs and tools, leaving $TOKEN_DIR in place"
        rm -rf "$BASE_DIR/etc" "$BASE_DIR/logs" "$BASE_DIR/sbin" "$BASE_DIR/pids"
    else
        echo "==> removing $BASE_DIR"
        rm -rf "$BASE_DIR"
    fi
fi

echo "==> removing system user/group 'softhsm'"
getent passwd softhsm >/dev/null && userdel softhsm 2>/dev/null || true
getent group softhsm >/dev/null && groupdel softhsm 2>/dev/null || true

echo ""
echo "Done. Remaining, if anything:"
ls -la "$BASE_DIR" 2>/dev/null || echo "  (nothing left)"
