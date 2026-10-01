#!/usr/bin/env bash
# CTest wrapper for softhsm-gsm: initializes an isolated token,
# provisions one test subscriber locally (via softhsm2-milenage, not
# over the network), starts the daemon in the background on a free
# port, runs the TCP client test against it, then tears everything
# down. Invoked by CMake via add_test() -- see CMakeLists.txt in this
# directory.
#
#   run_daemon_ctest.sh <module.so> <softhsm2-util> <softhsm2-milenage> \
#                        <softhsm-gsm> <daemon-tcp-client-test>
set -uo pipefail

MODULE="$1"
UTIL="$2"
CLI="$3"
DAEMON="$4"
CLIENT="$5"
MODE="${6:-tcp}"

WORKDIR="$(mktemp -d /tmp/milenage-daemon-ctest.XXXXXX)"
DAEMON_PID=""

cleanup() {
	if [ -n "$DAEMON_PID" ]; then
		kill "$DAEMON_PID" 2>/dev/null
		wait "$DAEMON_PID" 2>/dev/null
	fi
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$WORKDIR/tokens"
cat > "$WORKDIR/softhsm2.conf" <<EOF
directories.tokendir = $WORKDIR/tokens
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF
export SOFTHSM2_CONF="$WORKDIR/softhsm2.conf"

"$UTIL" --module "$MODULE" --init-token --free --label daemon-ctest \
	--so-pin 1234 --pin 5678 > "$WORKDIR/init.log" 2>&1 || { echo "init-token failed"; cat "$WORKDIR/init.log"; exit 1; }
echo 5678 > "$WORKDIR/pin.txt"

"$CLI" create-master-key --module "$MODULE" --token-label daemon-ctest \
	--pin-file "$WORKDIR/pin.txt" > "$WORKDIR/create-key.log" 2>&1 || { echo "create-master-key failed"; cat "$WORKDIR/create-key.log"; exit 1; }

SUPI="imsi-001010123456789"
python3 -c "
import sys
k = bytes.fromhex('465b5ce8b199b49faa5f0a2ee238a6bc')
opc = bytes.fromhex('cd63cb71954a9f4e48a5994e37a02baf')
sys.stdout.buffer.write(k + opc)
" | "$CLI" provision --module "$MODULE" --token-label daemon-ctest --pin-file "$WORKDIR/pin.txt" \
	--supi "$SUPI" --output "$WORKDIR/sub.json" --allow-plaintext-test-provisioning \
	> "$WORKDIR/provision.log" 2>&1 || { echo "provision failed"; cat "$WORKDIR/provision.log"; exit 1; }

WRAPPED_K=$(python3 -c "import json; print(json.load(open('$WORKDIR/sub.json'))['wrapped_k'])")
WRAPPED_OPC=$(python3 -c "import json; print(json.load(open('$WORKDIR/sub.json'))['wrapped_opc'])")

PORT=$((20000 + (RANDOM % 20000)))

if [ "$MODE" = both ]; then
	"$DAEMON" --module "$MODULE" --token-label daemon-ctest --pin-file "$WORKDIR/pin.txt" \
		--listen-addr 127.0.0.1 --listen-port "$PORT" \
		--listen-unix "$WORKDIR/gsm.sock" > "$WORKDIR/daemon.log" 2>&1 &
elif [ "$MODE" = unix ]; then
	"$DAEMON" --module "$MODULE" --token-label daemon-ctest --pin-file "$WORKDIR/pin.txt" \
		--listen-unix "$WORKDIR/gsm.sock" > "$WORKDIR/daemon.log" 2>&1 &
else
	"$DAEMON" --module "$MODULE" --token-label daemon-ctest --pin-file "$WORKDIR/pin.txt" \
		--listen-addr 127.0.0.1 --listen-port "$PORT" > "$WORKDIR/daemon.log" 2>&1 &
fi
DAEMON_PID=$!

# Wait for the daemon to start listening (poll, generous timeout).
for i in $(seq 1 50); do
	if [ "$MODE" = both ]; then
		grep -q "listening on Unix socket" "$WORKDIR/daemon.log" 2>/dev/null && \
		grep -q "listening on 127.0.0.1:" "$WORKDIR/daemon.log" 2>/dev/null && break
	elif grep -q "listening on" "$WORKDIR/daemon.log" 2>/dev/null; then
		break
	fi
	if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
		echo "daemon exited before listening; log:"
		cat "$WORKDIR/daemon.log"
		exit 1
	fi
	sleep 0.1
done

if [ "$MODE" = both ]; then
	"$CLIENT" 127.0.0.1 "$PORT" "$SUPI" "$WRAPPED_K" "$WRAPPED_OPC" && \
	"$CLIENT" "unix:$WORKDIR/gsm.sock" 0 "$SUPI" "$WRAPPED_K" "$WRAPPED_OPC"
elif [ "$MODE" = unix ]; then
	"$CLIENT" "unix:$WORKDIR/gsm.sock" 0 "$SUPI" "$WRAPPED_K" "$WRAPPED_OPC"
else
	"$CLIENT" 127.0.0.1 "$PORT" "$SUPI" "$WRAPPED_K" "$WRAPPED_OPC"
fi
RESULT=$?

echo "--- daemon log ---"
cat "$WORKDIR/daemon.log"

exit $RESULT
