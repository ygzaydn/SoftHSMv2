#!/bin/bash
# Installs softhsm2-milenaged as a systemd service:
#   binary   -> /usr/local/bin/softhsm2-milenaged (+ softhsm2-milenage CLI)
#   module   -> /usr/local/lib/softhsm/libsofthsm2.so
#   config   -> /etc/softhsm2/{softhsm2.conf,milenaged.env,milenaged-pin}
#   tokens   -> /var/lib/softhsm2/tokens
#   logs     -> /var/log/softhsm/softhsm2-milenaged.log
#   service  -> softhsm-milenaged system user, softhsm2-milenaged.service
#
# Must be run as root (sudo). Safe to re-run (idempotent where possible).
#
# By default this MIGRATES the existing dev token store from
# open5gs-scripts/hsm-scripts/tokens/ (if present) so already-provisioned
# subscribers keep working -- it does not re-provision anything or touch
# plaintext K/OPc. Pass --fresh-token-dir to skip the migration and start
# with an empty token store instead.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must be run as root (sudo $0)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"

FRESH_TOKEN_DIR=0
[ "${1:-}" = "--fresh-token-dir" ] && FRESH_TOKEN_DIR=1

DEV_HSM_SCRIPTS_DIR="/home/aselsan/open5gs-scripts/hsm-scripts"
DEV_TOKEN_DIR="$DEV_HSM_SCRIPTS_DIR/tokens"
DEV_PIN_FILE="$DEV_HSM_SCRIPTS_DIR/secrets/pin.txt"

if [ ! -x "$BUILD_DIR/src/bin/milenage/softhsm2-milenaged" ]; then
    echo "error: $BUILD_DIR/src/bin/milenage/softhsm2-milenaged not built -- build SoftHSMv2 first" >&2
    exit 1
fi

echo "==> installing binaries and PKCS#11 module to /usr/local (cmake install)"
cmake --install "$BUILD_DIR" --component runtime 2>/dev/null || \
    (cd "$BUILD_DIR" && make install)

echo "==> creating system user/group 'softhsm'"
if ! getent group softhsm >/dev/null; then
    groupadd --system softhsm
fi
if ! getent passwd softhsm >/dev/null; then
    useradd --system --gid softhsm --home-dir /var/lib/softhsm2 \
        --shell /usr/sbin/nologin --comment "SoftHSM Milenage daemon" softhsm
fi

echo "==> creating /etc/softhsm2, /var/lib/softhsm2"
mkdir -p /etc/softhsm2
mkdir -p /var/lib/softhsm2/tokens
chown -R softhsm:softhsm /var/lib/softhsm2
chmod 750 /var/lib/softhsm2 /var/lib/softhsm2/tokens

if [ ! -f /etc/softhsm2/softhsm2.conf ]; then
    install -o root -g softhsm -m 640 \
        "$SCRIPT_DIR/softhsm2.conf.example" /etc/softhsm2/softhsm2.conf
    echo "    wrote /etc/softhsm2/softhsm2.conf"
else
    echo "    /etc/softhsm2/softhsm2.conf already exists, not overwriting"
fi

if [ ! -f /etc/softhsm2/milenaged.env ]; then
    install -o root -g softhsm -m 640 \
        "$SCRIPT_DIR/milenaged.env.example" /etc/softhsm2/milenaged.env
    echo "    wrote /etc/softhsm2/milenaged.env"
else
    echo "    /etc/softhsm2/milenaged.env already exists, not overwriting"
fi

if [ ! -f /etc/softhsm2/milenaged-pin ]; then
    if [ -f "$DEV_PIN_FILE" ]; then
        install -o root -g softhsm -m 640 "$DEV_PIN_FILE" /etc/softhsm2/milenaged-pin
        echo "    copied PIN from $DEV_PIN_FILE to /etc/softhsm2/milenaged-pin"
    else
        echo "error: no /etc/softhsm2/milenaged-pin and no dev PIN file at $DEV_PIN_FILE" >&2
        echo "       create /etc/softhsm2/milenaged-pin yourself (mode 640, owner root:softhsm)" >&2
        exit 1
    fi
else
    echo "    /etc/softhsm2/milenaged-pin already exists, not overwriting"
fi

if [ "$FRESH_TOKEN_DIR" -eq 0 ] && [ -d "$DEV_TOKEN_DIR" ] && \
        [ -z "$(ls -A /var/lib/softhsm2/tokens 2>/dev/null)" ]; then
    echo "==> migrating existing dev token store from $DEV_TOKEN_DIR"
    cp -a "$DEV_TOKEN_DIR/." /var/lib/softhsm2/tokens/
    chown -R softhsm:softhsm /var/lib/softhsm2/tokens
    echo "    migrated (already-provisioned subscribers keep working)"
elif [ -n "$(ls -A /var/lib/softhsm2/tokens 2>/dev/null)" ]; then
    echo "==> /var/lib/softhsm2/tokens already has data, not touching it"
fi

echo "==> installing systemd unit"
install -m 644 "$SCRIPT_DIR/softhsm2-milenaged.service" \
    /etc/systemd/system/softhsm2-milenaged.service
systemctl daemon-reload

echo "==> enabling and starting softhsm2-milenaged.service"
systemctl enable --now softhsm2-milenaged.service

sleep 1
systemctl --no-pager status softhsm2-milenaged.service || true

cat <<'EOF'

Done.

  config:  /etc/softhsm2/softhsm2.conf, /etc/softhsm2/milenaged.env
  PIN:     /etc/softhsm2/milenaged-pin  (root:softhsm, mode 640)
  tokens:  /var/lib/softhsm2/tokens     (softhsm:softhsm)
  logs:    /var/log/softhsm/softhsm2-milenaged.log
  service: systemctl {status,restart,stop} softhsm2-milenaged

Point udm.hsm.host/port at wherever this host is reachable (still
127.0.0.1:9999 if UDM runs on the same host). If you were running the
dev daemon from open5gs-scripts/hsm-scripts/07-start-daemon.sh, stop
it now (08-stop-daemon.sh) -- both processes hold the same PKCS#11
token and only one should be running at a time.
EOF
