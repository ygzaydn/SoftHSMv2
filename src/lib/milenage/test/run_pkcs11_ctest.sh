#!/usr/bin/env bash
# CTest wrapper for the PKCS#11-level Milenage tests: builds an
# isolated token directory, initializes a fresh test token, runs the
# given test binary against it, and cleans up. Invoked by CMake via
# add_test() in this directory's CMakeLists.txt -- not meant to be run
# manually, though it can be:
#   run_pkcs11_ctest.sh <e2e|restart> <module.so> <softhsm2-util> <test-binary>
set -euo pipefail

MODE="$1"
MODULE="$2"
UTIL="$3"
TESTBIN="$4"

WORKDIR="$(mktemp -d /tmp/milenage-ctest.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR/tokens"
cat > "$WORKDIR/softhsm2.conf" <<EOF
directories.tokendir = $WORKDIR/tokens
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF
export SOFTHSM2_CONF="$WORKDIR/softhsm2.conf"

"$UTIL" --module "$MODULE" --init-token --free --label ctest-milenage \
	--so-pin 1234 --pin 5678 > "$WORKDIR/init.log" 2>&1

if [ "$MODE" = "e2e" ]; then
	exec "$TESTBIN" "$MODULE"
elif [ "$MODE" = "restart" ]; then
	"$TESTBIN" "$MODULE" provision "$WORKDIR/wrapped.hex"
	exec "$TESTBIN" "$MODULE" generate "$WORKDIR/wrapped.hex"
else
	echo "unknown mode: $MODE" >&2
	exit 2
fi
