#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The installer records the checkout it built from. When run directly from
# this repository, derive that path from the script's own location.
HSM_REPO_DEFAULT=""
if [ -r "$SCRIPT_DIR/hsm-source-dir" ]; then
    IFS= read -r HSM_REPO_DEFAULT < "$SCRIPT_DIR/hsm-source-dir"
elif [ -f "$SCRIPT_DIR/../../../CMakeLists.txt" ]; then
    HSM_REPO_DEFAULT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
fi
# Shared environment for all hsm-scripts scripts.
set -a
MONGO_URI="mongodb://localhost/open5gs"
HSM_REPO=${HSM_REPO:-$HSM_REPO_DEFAULT}
REPO=${OPEN5GS_REPO:-$(dirname "$HSM_REPO")/open5gs}
HSM_BUILD=$HSM_REPO/build
SCRIPTS_DIR=$SCRIPT_DIR
BASE_DIR=/opt/softhsm2
SECRETS_DIR=$BASE_DIR/etc
TOKEN_DIR=$BASE_DIR/tokens
WRAPPED_DIR=$BASE_DIR/wrapped
LOGDIR=$BASE_DIR/logs
PIDDIR=$BASE_DIR/pids

MODULE=/usr/local/lib/softhsm/libsofthsm2.so
UTIL=/usr/local/bin/softhsm2-util
CLI=/usr/local/bin/softhsm2-milenage
DAEMON=/usr/local/bin/softhsm-gsm

SOFTHSM2_CONF=$BASE_DIR/etc/softhsm2.conf
TOKEN_LABEL=open5gs-milenage
SO_PIN_FILE=$SECRETS_DIR/gsm-so-pin
PIN_FILE=$SECRETS_DIR/gsm-pin

DAEMON_LISTEN_ADDR=127.0.0.1
DAEMON_LISTEN_PORT=9999
DAEMON_UNIX_SOCKET=${DAEMON_UNIX_SOCKET:-}
if [ -r "$SECRETS_DIR/gsm.env" ]; then
    . "$SECRETS_DIR/gsm.env"
    DAEMON_LISTEN_ADDR=${LISTEN_ADDR:-$DAEMON_LISTEN_ADDR}
    DAEMON_LISTEN_PORT=${LISTEN_PORT:-$DAEMON_LISTEN_PORT}
    DAEMON_UNIX_SOCKET=${LISTEN_UNIX:-$DAEMON_UNIX_SOCKET}
fi
DAEMON_PIDFILE=$PIDDIR/softhsm-gsm.pid
DAEMON_LOGFILE=$LOGDIR/softhsm-gsm.log
set +a

if [ ! -d "$SECRETS_DIR" ]; then
    echo "Missing $SECRETS_DIR. Install or migrate the GSM configuration first." >&2
    exit 1
fi
mkdir -p "$TOKEN_DIR" "$WRAPPED_DIR" "$LOGDIR" "$PIDDIR"

# Write softhsm2.conf if it doesn't exist yet (idempotent: scripts that
# source this file should not clobber an already-initialized token).
if [ ! -f "$SOFTHSM2_CONF" ]; then
	cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF
fi

require_built() {
	for f in "$MODULE" "$UTIL" "$CLI"; do
		if [ ! -x "$f" ] && [ ! -f "$f" ]; then
			echo "error: $f not found -- run contrib/systemd/install.sh first" >&2
			return 1
		fi
	done
}

require_token() {
	if [ ! -f "$PIN_FILE" ]; then
		echo "error: no PIN file at $PIN_FILE -- run hsm.sh init-token first" >&2
		return 1
	fi
}


# build: consolidated from hsm.sh build
cmd_build() {

if [ -z "$HSM_REPO" ] || [ ! -f "$HSM_REPO/CMakeLists.txt" ]; then
	echo "error: SoftHSM source not found at '$HSM_REPO'; set HSM_REPO to the checkout path" >&2
	return 1
fi

mkdir -p "$HSM_BUILD"
cd "$HSM_BUILD"

cmake -DWITH_CRYPTO_BACKEND=openssl \
      -DWITH_MILENAGE=ON \
      -DWITH_MILENAGE_TEST_RAND=OFF \
      -DWITH_MILENAGE_PLAINTEXT_PROVISIONING=OFF \
      -DWITH_MILENAGE_TRANSPORT_IMPORT=ON \
      "$HSM_REPO"

make -j"$(nproc)"
cmake --install "$HSM_BUILD"

echo ""
echo "built:"
ls -la "$MODULE" "$UTIL" "$CLI" "$DAEMON"

}

# init-token: consolidated from hsm.sh init-token
cmd_init_token() {
require_built

FORCE=0
CUSTOM_PIN=""
CUSTOM_SO_PIN=""
while [ $# -gt 0 ]; do
	case "$1" in
		--force) FORCE=1; shift ;;
		--pin) CUSTOM_PIN="${2:?--pin requires a value}"; shift 2 ;;
		--so-pin) CUSTOM_SO_PIN="${2:?--so-pin requires a value}"; shift 2 ;;
		*) echo "unknown option: $1" >&2; return 1 ;;
	esac
done

if [ -f "$PIN_FILE" ] && [ "$FORCE" -ne 1 ]; then
	echo "token already initialized (PIN file exists at $PIN_FILE)."
	echo "pass --force to wipe the token directory and re-init (DESTROYS all keys)."
	return 0
fi

if [ "$FORCE" -eq 1 ]; then
	echo "WARNING: wiping $TOKEN_DIR in 3 seconds (Ctrl-C to abort)..."
	sleep 3
	rm -rf "${TOKEN_DIR:?}"/*
	rm -f "$SO_PIN_FILE" "$PIN_FILE"
fi

# Use the given PIN, or generate a random one, or reuse whatever is
# already on disk. Never echoed, never passed as another program's
# argv -- written straight to 0600 files.
umask 077
if [ -n "$CUSTOM_SO_PIN" ]; then
	printf '%s\n' "$CUSTOM_SO_PIN" > "$SO_PIN_FILE"
elif [ ! -f "$SO_PIN_FILE" ]; then
	tr -dc '0-9' < /dev/urandom | head -c 8 > "$SO_PIN_FILE"
	echo "" >> "$SO_PIN_FILE"
fi
if [ -n "$CUSTOM_PIN" ]; then
	printf '%s\n' "$CUSTOM_PIN" > "$PIN_FILE"
elif [ ! -f "$PIN_FILE" ]; then
	tr -dc '0-9' < /dev/urandom | head -c 8 > "$PIN_FILE"
	echo "" >> "$PIN_FILE"
fi
chmod 600 "$SO_PIN_FILE" "$PIN_FILE"

SO_PIN=$(cat "$SO_PIN_FILE")
PIN=$(cat "$PIN_FILE")

"$UTIL" --module "$MODULE" --init-token --free --label "$TOKEN_LABEL" \
	--so-pin "$SO_PIN" --pin "$PIN" || return $?

unset SO_PIN PIN CUSTOM_PIN CUSTOM_SO_PIN

echo ""
echo "token '$TOKEN_LABEL' initialized."
echo "SO-PIN file: $SO_PIN_FILE (only needed to re-init the token)"
echo "PIN file:    $PIN_FILE (needed by every other hsm-scripts script)"

}

# create-master-key: consolidated from hsm.sh create-master-key
cmd_create_master_key() {
require_built
require_token

if "$CLI" inspect --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" >/dev/null 2>&1; then
	echo "a Master Storage Key already exists on this token. Not creating another."
	"$CLI" inspect --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE"
	return 0
fi

"$CLI" create-master-key --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE"

echo ""
"$CLI" inspect --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE"

}

# provision: consolidated from hsm.sh provision
cmd_provision() {
set -o pipefail
require_built
require_token

IMSI="${1:?usage: $0 <imsi> <k-hex> <opc-hex> [--force]}"
K_HEX="${2:?usage: $0 <imsi> <k-hex> <opc-hex> [--force]}"
OPC_HEX="${3:?usage: $0 <imsi> <k-hex> <opc-hex> [--force]}"
FORCE_FLAG=""
[ "${4:-}" = "--force" ] && FORCE_FLAG="--force"

if [ "${#K_HEX}" -ne 32 ] || [ "${#OPC_HEX}" -ne 32 ]; then
	echo "error: K and OPc must each be exactly 32 hex characters (16 bytes)" >&2
	return 1
fi

SUPI="imsi-$IMSI"
OUT="$WRAPPED_DIR/$IMSI.json"

printf '%s' "$K_HEX$OPC_HEX" | python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' | \
"$CLI" provision --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" \
	--supi "$SUPI" --output "$OUT" --allow-plaintext-test-provisioning $FORCE_FLAG

HSM_PROVISION_IMSI="$IMSI" HSM_PROVISION_JSON="$OUT" mongosh --quiet "$MONGO_URI" --eval '
const fs = require("fs");
const imsi = process.env.HSM_PROVISION_IMSI;
const credentials = JSON.parse(fs.readFileSync(process.env.HSM_PROVISION_JSON, "utf8"));
if (!/^[0-9]{5,15}$/.test(imsi) || credentials.hsm !== true ||
    typeof credentials.wrapped_k !== "string" || !credentials.wrapped_k ||
    typeof credentials.wrapped_opc !== "string" || !credentials.wrapped_opc) {
    throw new Error("invalid HSM provisioning output");
}
const result = db.subscribers.updateOne(
    {imsi: imsi},
    {$set: {
        "security.hsm": true,
        "security.wrapped_k": credentials.wrapped_k,
        "security.wrapped_opc": credentials.wrapped_opc,
        "security.k": null,
        "security.op": null,
        "security.opc": null
    }}
);
if (result.matchedCount !== 1) {
    throw new Error("MongoDB subscriber not found for IMSI " + imsi);
}
print("MongoDB subscriber security updated for IMSI " + imsi);
'

echo "wrapped credentials written to $OUT"

}

# generate-av: consolidated from hsm.sh generate-av
cmd_generate_av() {
require_built
require_token

IMSI="${1:?usage: $0 <imsi> [sqn-hex12] [amf-hex4] [snn]}"
SQN="${2:-000000000001}"
AMF="${3:-8000}"
SNN="${4:-5G:mnc001.mcc001.3gppnetwork.org}"

JSON="$WRAPPED_DIR/$IMSI.json"
if [ ! -f "$JSON" ]; then
	echo "error: no wrapped credentials for imsi-$IMSI at $JSON -- run hsm.sh provision first" >&2
	return 1
fi

WRAPPED_K=$(python3 -c "import json; print(json.load(open('$JSON'))['wrapped_k'])")
WRAPPED_OPC=$(python3 -c "import json; print(json.load(open('$JSON'))['wrapped_opc'])")

"$CLI" generate-5g-av --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" \
	--supi "imsi-$IMSI" --wrapped-k "$WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
	--sqn "$SQN" --amf "$AMF" --snn "$SNN"

}

# resync: consolidated from hsm.sh resync
cmd_resync() {
require_built
require_token

IMSI="${1:?usage: $0 <imsi> <rand-hex32> <auts-hex28>}"
RAND="${2:?usage: $0 <imsi> <rand-hex32> <auts-hex28>}"
AUTS="${3:?usage: $0 <imsi> <rand-hex32> <auts-hex28>}"

JSON="$WRAPPED_DIR/$IMSI.json"
if [ ! -f "$JSON" ]; then
	echo "error: no wrapped credentials for imsi-$IMSI at $JSON -- run hsm.sh provision first" >&2
	return 1
fi

WRAPPED_K=$(python3 -c "import json; print(json.load(open('$JSON'))['wrapped_k'])")
WRAPPED_OPC=$(python3 -c "import json; print(json.load(open('$JSON'))['wrapped_opc'])")

"$CLI" resync --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" \
	--supi "imsi-$IMSI" --wrapped-k "$WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
	--rand "$RAND" --auts "$AUTS"

}

# start: consolidated from hsm.sh start
cmd_start() {
require_built
require_token

if [ -f "$DAEMON_PIDFILE" ] && kill -0 "$(cat "$DAEMON_PIDFILE")" 2>/dev/null; then
	echo "softhsm-gsm already running (pid $(cat "$DAEMON_PIDFILE"))"
	return 0
fi

LISTEN_ARGS=(--listen-addr "$DAEMON_LISTEN_ADDR" --listen-port "$DAEMON_LISTEN_PORT")
ENDPOINT="$DAEMON_LISTEN_ADDR:$DAEMON_LISTEN_PORT"
if [ -n "$DAEMON_UNIX_SOCKET" ]; then
	LISTEN_ARGS+=(--listen-unix "$DAEMON_UNIX_SOCKET")
	ENDPOINT="$ENDPOINT and $DAEMON_UNIX_SOCKET"
fi
nohup "$DAEMON" --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" \
	"${LISTEN_ARGS[@]}" > "$DAEMON_LOGFILE" 2>&1 &
echo $! > "$DAEMON_PIDFILE"
disown

sleep 1
if ! kill -0 "$(cat "$DAEMON_PIDFILE")" 2>/dev/null; then
	echo "daemon failed to start, log:"
	cat "$DAEMON_LOGFILE"
	rm -f "$DAEMON_PIDFILE"
	return 1
fi

echo "softhsm-gsm started (pid $(cat "$DAEMON_PIDFILE")), listening on $ENDPOINT"
echo "log: $DAEMON_LOGFILE"

}

# stop: consolidated from hsm.sh stop
cmd_stop() {

if [ -f "$DAEMON_PIDFILE" ]; then
	pid=$(cat "$DAEMON_PIDFILE")
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		echo "softhsm-gsm stopped (pid $pid)"
	fi
	rm -f "$DAEMON_PIDFILE"
else
	echo "no pidfile at $DAEMON_PIDFILE (not running, or started outside this script)"
fi

pkill -f "$DAEMON --module" 2>/dev/null || true

if [ -n "$DAEMON_UNIX_SOCKET" ] && [ -S "$DAEMON_UNIX_SOCKET" ]; then
	rm -f "$DAEMON_UNIX_SOCKET"
fi

}

# smoke-test: consolidated from hsm.sh smoke-test
cmd_smoke_test() {

IMSI="${1:?usage: $0 <imsi> [host] [port]}"
HOST="${2:-${DAEMON_UNIX_SOCKET:+unix:$DAEMON_UNIX_SOCKET}}"
HOST="${HOST:-$DAEMON_LISTEN_ADDR}"
PORT="${3:-$DAEMON_LISTEN_PORT}"

JSON="$WRAPPED_DIR/$IMSI.json"
if [ ! -f "$JSON" ]; then
	echo "error: no wrapped credentials for imsi-$IMSI at $JSON -- run hsm.sh provision first" >&2
	return 1
fi

python3 "$SCRIPT_DIR/lib/daemon_client.py" "$HOST" "$PORT" "imsi-$IMSI" "$JSON"

}

# seed-subscribers: consolidated from hsm.sh seed-subscribers
cmd_seed_subscribers() {
require_built
require_token

K="465B5CE8B199B49FAA5F0A2EE238A6BC"
OPC="E8ED289DEBA952E4283B54E88E6183CA"

for imsi in 999700000000001 999700000000002 999700000000003 999700000000004 999700000000005; do
	exists=$(HSM_SEED_IMSI="$imsi" mongosh --quiet "$MONGO_URI" --eval '
		print(db.subscribers.countDocuments({imsi: process.env.HSM_SEED_IMSI}));
	')
	if [ "$exists" = "0" ]; then
		bash "$REPO/misc/db/open5gs-dbctl" "--db_uri=$MONGO_URI" add "$imsi" "$K" "$OPC" >/dev/null
	elif [ "$exists" != "1" ]; then
		echo "error: expected one MongoDB subscriber for IMSI $imsi, got: $exists" >&2
		return 1
	fi
	"$SCRIPT_DIR/hsm.sh" provision "$imsi" "$K" "$OPC" --force
	echo ""
done

echo "done. wrapped credentials under $WRAPPED_DIR/"
ls "$WRAPPED_DIR"

}

# full-demo: consolidated from hsm.sh full-demo
cmd_full_demo() {

pass=0
fail=0
check() {
	if [ "$1" -eq 0 ]; then
		echo "PASS: $2"
		pass=$((pass + 1))
	else
		echo "FAIL: $2"
		fail=$((fail + 1))
	fi
}

echo "== 1. build =="
[ -x "$CLI" ] || "$SCRIPT_DIR/hsm.sh" build
check $? "softhsm2-milenage built"

echo "== 2. init token =="
"$SCRIPT_DIR/hsm.sh" init-token
check $? "token ready"

echo "== 3. master key =="
"$SCRIPT_DIR/hsm.sh" create-master-key
check $? "master key ready"

echo "== 4. provision test subscriber =="
TEST_IMSI="999700000099999"
"$SCRIPT_DIR/hsm.sh" provision "$TEST_IMSI" \
	465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA --force
check $? "subscriber provisioned, wrapped credentials on disk"

echo "== 5. generate-5g-av (local CLI, no daemon) =="
"$SCRIPT_DIR/hsm.sh" generate-av "$TEST_IMSI" >/dev/null
check $? "local AV generation"

echo "== 6. start daemon =="
"$SCRIPT_DIR/hsm.sh" start
check $? "daemon started"

echo "== 7. AV over real TCP =="
"$SCRIPT_DIR/hsm.sh" smoke-test "$TEST_IMSI" >/dev/null
check $? "AV generated over TCP"

echo "== 8. resync rejection (garbage AUTS must fail) =="
if "$SCRIPT_DIR/hsm.sh" resync "$TEST_IMSI" \
	101112131415161718191a1b1c1d1e1f 0102030405060708090a0b0c0d0e >/dev/null 2>&1; then
	check 1 "resync with garbage AUTS correctly rejected"
else
	check 0 "resync with garbage AUTS correctly rejected"
fi

echo "== 9. stop daemon =="
"$SCRIPT_DIR/hsm.sh" stop
check $? "daemon stopped"

echo ""
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

}

# dry-run: consolidated from hsm.sh dry-run
cmd_dry_run() {
require_built
require_token

IMSI="${1:-999700000012345}"
K="${2:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${3:-E8ED289DEBA952E4283B54E88E6183CA}"

hr() { printf '%.0s-' {1..70}; echo; }

hr
echo "1) PROVISION  imsi-$IMSI"
hr
"$SCRIPT_DIR/hsm.sh" provision "$IMSI" "$K" "$OPC" --force

WAS_RUNNING=0
if [ -f "$DAEMON_PIDFILE" ] && kill -0 "$(cat "$DAEMON_PIDFILE")" 2>/dev/null; then
	WAS_RUNNING=1
fi
[ "$WAS_RUNNING" -eq 0 ] && "$SCRIPT_DIR/hsm.sh" start

CLIENT_HOST="${DAEMON_UNIX_SOCKET:+unix:$DAEMON_UNIX_SOCKET}"
CLIENT_HOST="${CLIENT_HOST:-$DAEMON_LISTEN_ADDR}"
hr
echo "2) 5G HE AV  (SQN=000000000001, via the daemon)"
hr
python3 "$SCRIPT_DIR/lib/daemon_client.py" "$CLIENT_HOST" "$DAEMON_LISTEN_PORT" \
	"imsi-$IMSI" "$WRAPPED_DIR/$IMSI.json" 000000000001 8000

hr
echo "3) 5G HE AV again (SQN=000000000002 -- proves RAND/AUTN/XRES*/KAUSF"
echo "   all change per call, not just RAND)"
hr
python3 "$SCRIPT_DIR/lib/daemon_client.py" "$CLIENT_HOST" "$DAEMON_LISTEN_PORT" \
	"imsi-$IMSI" "$WRAPPED_DIR/$IMSI.json" 000000000002 8000

hr
echo "4) RESYNC with a deliberately-garbage AUTS (must be rejected)"
hr
"$SCRIPT_DIR/hsm.sh" resync "$IMSI" \
	101112131415161718191a1b1c1d1e1f 0102030405060708090a0b0c0d0e || echo "(rejected as expected)"

hr
echo "5) inspect() -- non-secret Master Storage Key info"
hr
"$CLI" inspect --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE"

[ "$WAS_RUNNING" -eq 0 ] && "$SCRIPT_DIR/hsm.sh" stop

hr
echo "wrapped credentials saved at: $WRAPPED_DIR/$IMSI.json"
echo "daemon log:                  $DAEMON_LOGFILE"

}

SERVICE=softhsm2-gsm.service

service_installed() { [ -f "/etc/systemd/system/$SERVICE" ]; }
service_active() { service_installed && systemctl is-active --quiet "$SERVICE"; }

cmd_service_start() {
    if service_installed; then sudo systemctl start "$SERVICE"; else cmd_start; fi
}
cmd_service_stop() {
    if service_installed; then sudo systemctl stop "$SERVICE"; else cmd_stop; fi
}
cmd_service_restart() {
    if service_installed; then sudo systemctl restart "$SERVICE"; else cmd_stop; cmd_start; fi
}

with_service_paused() {
    local command_name="$1" was_active=0 result=0
    shift
    if service_active; then
        sudo systemctl stop "$SERVICE"
        was_active=1
    fi
    "$SCRIPT_DIR/hsm.sh" "__raw-$command_name" "$@" || result=$?
    if [ "$was_active" -eq 1 ]; then sudo systemctl start "$SERVICE" || result=$?; fi
    return "$result"
}

cmd_prepare_token() {
    local was_active=0 result=0
    if service_active; then sudo systemctl stop "$SERVICE"; was_active=1; fi
    "$SCRIPT_DIR/hsm.sh" __raw-cmd_init_token "$@" || result=$?
    if [ "$result" -eq 0 ]; then
        "$SCRIPT_DIR/hsm.sh" __raw-cmd_create_master_key || result=$?
    fi
    if [ "$was_active" -eq 1 ] && [ "$result" -eq 0 ]; then
        sudo systemctl start "$SERVICE" || result=$?
    fi
    return "$result"
}

cmd_status() {
    local state="not installed" token_count=0
    if service_installed; then state="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"; fi
    token_count="$(find "$TOKEN_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)"
    printf '\n%s\t%s\n' 'Component' 'Status / path'
    printf '%s\t%s\n' 'Service' "$SERVICE ($state)"
    printf '%s\t%s\n' 'Token label' "$TOKEN_LABEL"
    printf '%s\t%s\n' 'Token directory' "$TOKEN_DIR ($token_count token)"
    printf '%s\t%s\n' 'User PIN file' "$PIN_FILE"
    printf '%s\t%s\n' 'SO PIN file' "$SO_PIN_FILE"
    printf '%s\t%s\n' 'TCP endpoint' "$DAEMON_LISTEN_ADDR:$DAEMON_LISTEN_PORT"
    printf '%s\t%s\n' 'Unix socket' '/run/softhsm-gsm/gsm.sock'
    if [ -f "$PIN_FILE" ] && [ -x "$CLI" ]; then
        if "$CLI" inspect --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" >/dev/null 2>&1; then
            printf '%s\t%s\n' 'Master Storage Key' 'present'
        else
            printf '%s\t%s\n' 'Master Storage Key' 'missing or PIN invalid'
        fi
    fi
    echo
}

cmd_change_pin() {
    local mode="${1:-}"
    case "$mode" in user|so|reset-user) ;; *) echo 'Usage: hsm.sh change-pin {user|so|reset-user}' >&2; return 2;; esac
    require_built
    python3 - "$MODULE" "$TOKEN_LABEL" "$PIN_FILE" "$SO_PIN_FILE" "$mode" <<'PY'
import ctypes as c
import getpass
import os
import pathlib
import sys
import tempfile

module, label, user_file, so_file, mode = sys.argv[1:]
old_file = so_file if mode in ('so', 'reset-user') else user_file
new_file = so_file if mode == 'so' else user_file
old_pin = pathlib.Path(old_file).read_text().strip().encode()
new_pin = getpass.getpass('New PIN: ').encode()
again = getpass.getpass('Confirm new PIN: ').encode()
if len(new_pin) < 4 or len(new_pin) > 255 or new_pin != again:
    sys.exit('PIN must be at least 4 characters and both entries must match')
lib = c.CDLL(module)
for name in ('C_Initialize', 'C_Finalize', 'C_GetSlotList', 'C_GetTokenInfo',
             'C_OpenSession', 'C_Login', 'C_SetPIN', 'C_InitPIN', 'C_CloseSession'):
    getattr(lib, name).restype = c.c_ulong
def ok(rv, operation):
    if rv != 0:
        sys.exit(f'{operation} failed: PKCS#11 0x{rv:x}')
ok(lib.C_Initialize(None), 'C_Initialize')
count = c.c_ulong()
ok(lib.C_GetSlotList(1, None, c.byref(count)), 'C_GetSlotList')
slots = (c.c_ulong * count.value)()
ok(lib.C_GetSlotList(1, slots, c.byref(count)), 'C_GetSlotList')
slot = None
for candidate in slots:
    info = c.create_string_buffer(512)
    if lib.C_GetTokenInfo(candidate, info) == 0 and info.raw[:32].decode(errors='ignore').strip() == label:
        slot = candidate
        break
if slot is None:
    sys.exit('Token label not found: ' + label)
session = c.c_ulong()
ok(lib.C_OpenSession(slot, 6, None, None, c.byref(session)), 'C_OpenSession')
ok(lib.C_Login(session.value, 0 if mode in ('so', 'reset-user') else 1,
               old_pin, len(old_pin)), 'C_Login')
if mode == 'reset-user':
    ok(lib.C_InitPIN(session.value, new_pin, len(new_pin)), 'C_InitPIN')
else:
    ok(lib.C_SetPIN(session.value, old_pin, len(old_pin), new_pin, len(new_pin)), 'C_SetPIN')
lib.C_CloseSession(session.value)
lib.C_Finalize(None)
target = pathlib.Path(new_file)
fd, temp = tempfile.mkstemp(dir=target.parent, prefix='.pin-')
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(new_pin + b'\n')
    os.replace(temp, target)
except BaseException:
    os.unlink(temp)
    raise
print('PIN changed; the PIN file was updated.')
PY
}

cmd_import_kek() {
    local file="${1:?Usage: hsm.sh import-kek <32-byte-file>}"
    require_built; require_token
    [ "$(stat -c %s "$file")" -eq 32 ] || { echo 'KEK file must contain exactly 32 bytes' >&2; return 2; }
    "$CLI" import-transport-kek --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" < "$file"
}

cmd_import_wrapped() {
    local imsi="${1:?Usage: hsm.sh import-wrapped <imsi> <wrapped-k-b64> <wrapped-opc-b64>}"
    local transport_k="${2:?transport-wrapped-k required}" transport_opc="${3:?transport-wrapped-opc required}"
    require_built; require_token
    "$CLI" import-transport-wrapped --module "$MODULE" --token-label "$TOKEN_LABEL" --pin-file "$PIN_FILE" \
        --supi "imsi-$imsi" --transport-wrapped-k "$transport_k" --transport-wrapped-opc "$transport_opc" \
        --output "$WRAPPED_DIR/$imsi.json" --force
    HSM_PROVISION_IMSI="$imsi" HSM_PROVISION_JSON="$WRAPPED_DIR/$imsi.json" mongosh --quiet "$MONGO_URI" --eval '
const fs=require("fs"), i=process.env.HSM_PROVISION_IMSI;
const c=JSON.parse(fs.readFileSync(process.env.HSM_PROVISION_JSON,"utf8"));
if (!/^[0-9]{5,15}$/.test(i) || !c.wrapped_k || !c.wrapped_opc) throw new Error("invalid subscriber data");
const r=db.subscribers.updateOne({imsi:i},{$set:{"security.hsm":true,"security.wrapped_k":c.wrapped_k,"security.wrapped_opc":c.wrapped_opc,"security.k":null,"security.op":null,"security.opc":null}});
if (r.matchedCount!==1) throw new Error("subscriber not found: "+i);
print("MongoDB updated: "+i);'
}

cmd_reset_all() {
    local confirm
    echo 'This deletes the token, all keys, PIN files, and local wrapped credentials.'
    echo 'Existing wrapped credentials in MongoDB must be provisioned again.'
    read -r -p 'Type RESET to continue: ' confirm
    [ "$confirm" = RESET ] || { echo 'Cancelled.'; return 1; }
    cmd_service_stop || return $?
    find "$TOKEN_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + || return $?
    find "$WRAPPED_DIR" -mindepth 1 -maxdepth 1 -type f -name '*.json' -delete || return $?
    rm -f "$PIN_FILE" "$SO_PIN_FILE" || return $?
    cmd_init_token || return $?
    cmd_create_master_key || return $?
    cmd_service_start || return $?
    echo 'New token is ready. Reimport the Transport KEK and reprovision all HSM subscribers.'
}

print_menu() {
    cat <<'MENU'

SoftHSM GSM management

No	Command	Purpose
1	status	Show service, token, PIN files, and endpoints.
		Example: ./hsm.sh status
2	build	Build SoftHSM, the PKCS#11 module, and GSM tools.
		Example: ./hsm.sh build
3	init-token	Initialize a token and create its Master Storage Key.
		Example: ./hsm.sh init-token
4	provision	Development only (disabled by installed build): wrap K/OPc and update MongoDB.
		Example: ./hsm.sh provision 999700000012345 <K-hex> <OPc-hex> --force
5	generate-av	Generate a local 5G authentication vector.
		Example: ./hsm.sh generate-av 999700000012345
6	resync	Verify AUTS and recover the subscriber SQN.
		Example: ./hsm.sh resync 999700000012345 <RAND-hex> <AUTS-hex>
7	TCP smoke test	Request an AV through 127.0.0.1:9999.
		Example: ./hsm.sh smoke-test 999700000012345 127.0.0.1 9999
8	Unix smoke test	Request an AV through /run/softhsm-gsm/gsm.sock.
		Example: ./hsm.sh smoke-test 999700000012345 unix:/run/softhsm-gsm/gsm.sock 0
9	change-pin	Change user/SO PIN, or reset the user PIN with SO PIN.
		Example: ./hsm.sh change-pin reset-user
10	start	Start softhsm2-gsm.service.
		Example: ./hsm.sh start
11	stop	Stop softhsm2-gsm.service.
		Example: ./hsm.sh stop
12	restart	Restart softhsm2-gsm.service.
		Example: ./hsm.sh restart
13	logs	Show the latest service journal entries.
		Example: ./hsm.sh logs
14	reset	Destroy and recreate the token, PINs, and Master Storage Key.
		Example: ./hsm.sh reset
15	seed-subscribers	Provision five development subscribers.
		Example: ./hsm.sh seed-subscribers
16	import-kek	Import a 32-byte Transport KEK into the token.
		Example: ./hsm.sh import-kek /secure/path/transport-kek
17	import-wrapped	Import transport-wrapped K/OPc and update MongoDB.
		Example: ./hsm.sh import-wrapped 999700000012345 <K-b64> <OPc-b64>
0	exit	Close the menu.
		Example: select 0
MENU
}

dispatch() {
    local command_name="$1"; shift
    case "$command_name" in
        help|-h|--help) print_menu ;;
        status) cmd_status ;;
        build) cmd_build "$@" ;;
        init-token) cmd_prepare_token "$@" ;;
        create-master-key) with_service_paused cmd_create_master_key "$@" ;;
        provision) with_service_paused cmd_provision "$@" ;;
        generate-av) cmd_generate_av "$@" ;;
        resync) cmd_resync "$@" ;;
        smoke-test) cmd_smoke_test "$@" ;;
        seed-subscribers) with_service_paused cmd_seed_subscribers "$@" ;;
        full-demo) cmd_full_demo "$@" ;;
        dry-run) cmd_dry_run "$@" ;;
        start) cmd_service_start ;;
        stop) cmd_service_stop ;;
        restart) cmd_service_restart ;;
        logs) journalctl -u "$SERVICE" -n 50 --no-pager ;;
        change-pin) with_service_paused cmd_change_pin "$@" ;;
        import-kek) with_service_paused cmd_import_kek "$@" ;;
        import-wrapped) with_service_paused cmd_import_wrapped "$@" ;;
        __raw-cmd_init_token) cmd_init_token "$@" ;;
        __raw-cmd_create_master_key) cmd_create_master_key "$@" ;;
        __raw-cmd_provision) cmd_provision "$@" ;;
        __raw-cmd_seed_subscribers) cmd_seed_subscribers "$@" ;;
        __raw-cmd_change_pin) cmd_change_pin "$@" ;;
        __raw-cmd_import_kek) cmd_import_kek "$@" ;;
        __raw-cmd_import_wrapped) cmd_import_wrapped "$@" ;;
        reset) cmd_reset_all ;;
        *) echo "Unknown command: $command_name" >&2; print_menu; return 2 ;;
    esac
}

menu() {
    local choice imsi k opc rand auts file mode
    while true; do
        print_menu
        read -r -p 'Select a number: ' choice || return 0
        case "$choice" in
            0) return 0 ;;
            1) dispatch status ;;
            2) dispatch build ;;
            3) dispatch init-token ;;
            4) read -r -p 'IMSI (digits only): ' imsi; read -r -s -p 'K (32 hex characters): ' k; echo; read -r -s -p 'OPc (32 hex characters): ' opc; echo; dispatch provision "$imsi" "$k" "$opc" --force; unset k opc ;;
            5) read -r -p 'IMSI: ' imsi; dispatch generate-av "$imsi" ;;
            6) read -r -p 'IMSI: ' imsi; read -r -p 'RAND (32 hex): ' rand; read -r -p 'AUTS (28 hex): ' auts; dispatch resync "$imsi" "$rand" "$auts" ;;
            7) read -r -p 'IMSI: ' imsi; dispatch smoke-test "$imsi" 127.0.0.1 9999 ;;
            8) read -r -p 'IMSI: ' imsi; dispatch smoke-test "$imsi" unix:/run/softhsm-gsm/gsm.sock 0 ;;
            9) echo 'user=change user PIN, so=change SO PIN, reset-user=reset user PIN using SO PIN'; read -r -p 'Mode: ' mode; dispatch change-pin "$mode" ;;
            10) dispatch start ;;
            11) dispatch stop ;;
            12) dispatch restart ;;
            13) dispatch logs ;;
            14) dispatch reset ;;
            15) dispatch seed-subscribers ;;
            16) read -r -p 'Path to 32-byte KEK file: ' file; dispatch import-kek "$file" ;;
            17) read -r -p 'IMSI: ' imsi; read -r -s -p 'Transport wrapped K (base64): ' k; echo; read -r -s -p 'Transport wrapped OPc (base64): ' opc; echo; dispatch import-wrapped "$imsi" "$k" "$opc"; unset k opc ;;
            *) echo 'Invalid selection.' ;;
        esac || echo 'Operation failed. See the error above.'
        echo
        read -r -p 'Press Enter to return to the menu: ' _ || return 0
    done
}

if [ "$#" -eq 0 ]; then
    if [ -t 0 ]; then menu; else print_menu; fi
else
    dispatch "$@"
fi
