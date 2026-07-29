#!/bin/bash
# Builds and installs softhsm2-milenaged as a systemd service, and (on a
# fresh token store) walks you through initializing the token and
# creating the Master Storage Key so the service comes up ready to use:
#   build    -> ../../build (configured + rebuilt so you always install
#                the current source tree, not a stale binary)
#   binary   -> /usr/local/bin/softhsm2-milenaged (+ softhsm2-milenage CLI)
#   wrapper  -> /usr/local/bin/softhsm2
#   module   -> /usr/local/lib/softhsm/libsofthsm2.so
#   config   -> /opt/softhsm2-milenaged/config/{softhsm2.conf,milenaged.env,milenaged-pin}
#   tokens   -> /opt/softhsm2-milenaged/tokens
#   logs     -> /opt/softhsm2-milenaged/logs/softhsm2-milenaged.log
#   service  -> softhsm system user, softhsm2-milenaged.service
#
# Must be run as root (sudo). Safe to re-run (idempotent where possible;
# an already-initialized token or existing config is never overwritten
# or re-prompted for).
#
# usage: install.sh [--migrate-from-token-dir <path>] [--migrate-from-pin-file <path>]
#
# If you're moving an existing token from another install of this same
# daemon, pass --migrate-from-token-dir pointing at its token directory
# (and optionally --migrate-from-pin-file pointing at its PIN file) to
# copy them into place instead of being prompted to create a new one.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must be run as root (sudo $0)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"
BASE_DIR=/opt/softhsm2-milenaged
CONFIG_DIR="$BASE_DIR/config"
TOKEN_DIR="$BASE_DIR/tokens"
LOG_DIR="$BASE_DIR/logs"
REAL_CLI=/usr/local/bin/softhsm2-milenage
UTIL=/usr/local/bin/softhsm2-util
MODULE=/usr/local/lib/softhsm/libsofthsm2.so

MIGRATE_TOKEN_DIR=""
MIGRATE_PIN_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --migrate-from-token-dir) MIGRATE_TOKEN_DIR="${2:?--migrate-from-token-dir requires a path}"; shift 2 ;;
        --migrate-from-pin-file) MIGRATE_PIN_FILE="${2:?--migrate-from-pin-file requires a path}"; shift 2 ;;
        --fresh-token-dir) shift ;; # accepted for backward compatibility, this is the default now
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

echo "==> configuring and building SoftHSMv2 (latest source tree)"
mkdir -p "$BUILD_DIR"
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    (cd "$BUILD_DIR" && cmake -DWITH_CRYPTO_BACKEND=openssl \
        -DWITH_MILENAGE=ON \
        -DWITH_MILENAGE_PLAINTEXT_PROVISIONING=ON \
        -DWITH_MILENAGE_TRANSPORT_IMPORT=ON \
        "$REPO_ROOT")
fi
(cd "$BUILD_DIR" && make -j"$(nproc)")

if [ ! -x "$BUILD_DIR/src/bin/milenage/softhsm2-milenaged" ]; then
    echo "error: build did not produce $BUILD_DIR/src/bin/milenage/softhsm2-milenaged" >&2
    exit 1
fi

echo "==> installing binaries and PKCS#11 module to /usr/local (cmake install)"
cmake --install "$BUILD_DIR"

if [ ! -x /usr/local/bin/softhsm2-milenaged ]; then
    echo "error: cmake --install did not produce /usr/local/bin/softhsm2-milenaged" >&2
    exit 1
fi

echo "==> creating system user/group 'softhsm'"
if ! getent group softhsm >/dev/null; then
    groupadd --system softhsm
fi
if ! getent passwd softhsm >/dev/null; then
    useradd --system --gid softhsm --home-dir "$BASE_DIR" \
        --shell /usr/sbin/nologin --comment "SoftHSM Milenage daemon" softhsm
fi

echo "==> creating $BASE_DIR (config, tokens, logs)"
mkdir -p "$CONFIG_DIR" "$TOKEN_DIR" "$LOG_DIR"
chown root:softhsm "$BASE_DIR"
chmod 750 "$BASE_DIR"
chown root:softhsm "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chown softhsm:softhsm "$TOKEN_DIR"
chmod 750 "$TOKEN_DIR"
# Created explicitly (not left to the unit's ReadWritePaths= alone)
# so the directory unconditionally exists, with the right ownership,
# before ExecStart runs.
chown softhsm:softhsm "$LOG_DIR"
chmod 750 "$LOG_DIR"

if [ ! -f "$CONFIG_DIR/softhsm2.conf" ]; then
    install -o root -g softhsm -m 640 \
        "$SCRIPT_DIR/softhsm2.conf.example" "$CONFIG_DIR/softhsm2.conf"
    echo "    wrote $CONFIG_DIR/softhsm2.conf"
else
    echo "    $CONFIG_DIR/softhsm2.conf already exists, not overwriting"
fi

TOKEN_LABEL="open5gs-milenage"
LISTEN_ADDR="127.0.0.1"
LISTEN_PORT="9999"
if [ ! -f "$CONFIG_DIR/milenaged.env" ]; then
    echo ""
    echo "==> daemon network/token settings"
    if [ -t 0 ]; then
        read -r -p "Token label [$TOKEN_LABEL]: " ans; [ -n "$ans" ] && TOKEN_LABEL="$ans"
        read -r -p "Listen address [$LISTEN_ADDR]: " ans; [ -n "$ans" ] && LISTEN_ADDR="$ans"
        read -r -p "Listen port [$LISTEN_PORT]: " ans; [ -n "$ans" ] && LISTEN_PORT="$ans"
    else
        echo "    no TTY attached -- using defaults (label=$TOKEN_LABEL, $LISTEN_ADDR:$LISTEN_PORT)"
    fi
    {
        echo "# Written by install.sh. See milenaged.env.example for a description"
        echo "# of these settings."
        echo "TOKEN_LABEL=$TOKEN_LABEL"
        echo "LISTEN_ADDR=$LISTEN_ADDR"
        echo "LISTEN_PORT=$LISTEN_PORT"
    } > "$CONFIG_DIR/milenaged.env"
    chown root:softhsm "$CONFIG_DIR/milenaged.env"
    chmod 640 "$CONFIG_DIR/milenaged.env"
    echo "    wrote $CONFIG_DIR/milenaged.env"
else
    # shellcheck source=/dev/null
    . "$CONFIG_DIR/milenaged.env"
    echo "    $CONFIG_DIR/milenaged.env already exists, not overwriting (label=$TOKEN_LABEL, $LISTEN_ADDR:$LISTEN_PORT)"
fi

NEED_TOKEN_INIT=0
if [ -n "$MIGRATE_TOKEN_DIR" ]; then
    if [ ! -d "$MIGRATE_TOKEN_DIR" ]; then
        echo "error: --migrate-from-token-dir $MIGRATE_TOKEN_DIR does not exist" >&2
        exit 1
    fi
    if [ -n "$(ls -A "$TOKEN_DIR" 2>/dev/null)" ]; then
        echo "==> $TOKEN_DIR already has data, not touching it (ignoring --migrate-from-token-dir)"
    else
        echo "==> migrating token store from $MIGRATE_TOKEN_DIR"
        cp -a "$MIGRATE_TOKEN_DIR/." "$TOKEN_DIR/"
        chown -R softhsm:softhsm "$TOKEN_DIR"
        echo "    migrated (already-provisioned subscribers keep working)"
    fi
    if [ -n "$MIGRATE_PIN_FILE" ] && [ ! -f "$CONFIG_DIR/milenaged-pin" ]; then
        if [ ! -f "$MIGRATE_PIN_FILE" ]; then
            echo "error: --migrate-from-pin-file $MIGRATE_PIN_FILE does not exist" >&2
            exit 1
        fi
        install -o root -g softhsm -m 640 "$MIGRATE_PIN_FILE" "$CONFIG_DIR/milenaged-pin"
        echo "    copied PIN from $MIGRATE_PIN_FILE to $CONFIG_DIR/milenaged-pin"
    fi
elif [ -n "$(ls -A "$TOKEN_DIR" 2>/dev/null)" ]; then
    echo "==> $TOKEN_DIR already has data, not touching it"
else
    NEED_TOKEN_INIT=1
fi

if [ "$NEED_TOKEN_INIT" -eq 1 ]; then
    echo ""
    echo "==> token initialization (first-time setup)"
    echo "    This token has no data yet. Set a PIN and SO-PIN now to"
    echo "    initialize it and create the Master Storage Key."
    PIN=""
    SO_PIN=""
    if [ -t 0 ]; then
        while [ -z "$PIN" ]; do
            read -r -s -p "User PIN (leave blank to auto-generate): " PIN; echo
            if [ -z "$PIN" ]; then
                PIN="$(openssl rand -hex 8)"
                echo "    generated PIN: $PIN  (shown once -- also saved to $CONFIG_DIR/milenaged-pin)"
            fi
        done
        while [ -z "$SO_PIN" ]; do
            read -r -s -p "SO-PIN / security officer PIN (leave blank to auto-generate): " SO_PIN; echo
            if [ -z "$SO_PIN" ]; then
                SO_PIN="$(openssl rand -hex 8)"
                echo "    generated SO-PIN: $SO_PIN  (shown once -- write this down, it is NOT saved anywhere)"
            fi
        done
    else
        PIN="$(openssl rand -hex 8)"
        SO_PIN="$(openssl rand -hex 8)"
        echo "    no TTY attached -- auto-generated PIN and SO-PIN (printed at the end)"
    fi

    printf '%s' "$PIN" > "$CONFIG_DIR/milenaged-pin"
    chown root:softhsm "$CONFIG_DIR/milenaged-pin"
    chmod 640 "$CONFIG_DIR/milenaged-pin"

    # NOTE: `VAR=val sudo cmd` does NOT reliably pass VAR through --
    # sudo's default env_reset strips it before the target user's
    # process ever sees it. `sudo ... env VAR=val cmd` sets it in the
    # environment sudo itself constructs for the child, which works
    # regardless of env_reset/env_keep configuration.
    echo "==> initializing token '$TOKEN_LABEL'"
    sudo -u softhsm env SOFTHSM2_CONF="$CONFIG_DIR/softhsm2.conf" \
        "$UTIL" --module "$MODULE" --init-token --free \
            --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$PIN"

    echo "==> creating the Master Storage Key"
    sudo -u softhsm env SOFTHSM2_CONF="$CONFIG_DIR/softhsm2.conf" \
        "$REAL_CLI" create-master-key \
            --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$CONFIG_DIR/milenaged-pin"

    if [ -z "$(ls -A "$TOKEN_DIR" 2>/dev/null)" ]; then
        echo "error: token initialization reported success, but $TOKEN_DIR is still empty." >&2
        echo "       Check $CONFIG_DIR/softhsm2.conf's directories.tokendir --" >&2
        echo "       the token may have been written to the wrong location." >&2
        exit 1
    fi

    TOKEN_INITIALIZED=1
    PIN_TO_PRINT="$PIN"
    SO_PIN_TO_PRINT="$SO_PIN"
    unset PIN SO_PIN
else
    TOKEN_INITIALIZED=0
fi

echo "==> installing softhsm2 wrapper command to /usr/local/bin/softhsm2"
install -m 755 "$SCRIPT_DIR/softhsm2-wrapper.sh" /usr/local/bin/softhsm2

echo "==> installing log-rotation helper to /usr/local/bin/softhsm2-milenaged-rotate-log"
install -m 755 "$SCRIPT_DIR/rotate-log.sh" /usr/local/bin/softhsm2-milenaged-rotate-log

echo "==> installing systemd unit"
install -m 644 "$SCRIPT_DIR/softhsm2-milenaged.service" \
    /etc/systemd/system/softhsm2-milenaged.service
systemctl daemon-reload

echo "==> enabling and (re)starting softhsm2-milenaged.service"
# `enable --now` only starts the unit if it wasn't already running --
# on a reinstall (new binary, changed config) that would silently leave
# the OLD process running. `restart` starts it either way and always
# picks up whatever was just installed.
systemctl enable softhsm2-milenaged.service
systemctl restart softhsm2-milenaged.service

sleep 1
systemctl --no-pager status softhsm2-milenaged.service || true

cat <<EOF

Done. Everything for this service lives under $BASE_DIR:

  config:  $CONFIG_DIR/softhsm2.conf, $CONFIG_DIR/milenaged.env
  PIN:     $CONFIG_DIR/milenaged-pin  (root:softhsm, mode 640)
  tokens:  $TOKEN_DIR     (softhsm:softhsm)
  logs:    $LOG_DIR/softhsm2-milenaged.log
  wrapper: softhsm2 --help
  service: systemctl {status,restart,stop} softhsm2-milenaged

See USAGE.md in this directory for onboarding subscribers.
EOF

if [ "${TOKEN_INITIALIZED:-0}" -eq 1 ]; then
cat <<EOF

IMPORTANT -- write these down now, they are only shown this once:

  User PIN: $PIN_TO_PRINT   (also saved to $CONFIG_DIR/milenaged-pin -- the
                             daemon and the softhsm2 wrapper read it from
                             there, you will not need to type it again)
  SO-PIN:   $SO_PIN_TO_PRINT   (NOT saved anywhere -- needed only if you ever
                             have to re-initialize this token)
EOF
fi
