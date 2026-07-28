#!/usr/bin/env bash
#
# Milenage / 5G-AKA wrapped-credential PoC (design doc section 16).
#
# Builds SoftHSMv2 with -DWITH_MILENAGE=ON in an isolated directory,
# initializes an isolated test token, provisions ONE subscriber using
# well-known 3GPP TS 35.207 Test Set 1 test-vector values (public test
# data, not a real subscriber), closes that process, starts a
# completely separate process to rediscover the token and Master
# Storage Key, generates a 5G HE AV from the wrapped values, and runs
# the negative-path checks required by design doc section 16: a
# modified wrapped blob is rejected, a cross-subscriber-bound blob is
# rejected, and Milenage resynchronization works.
#
# This script requires WITH_MILENAGE_PLAINTEXT_PROVISIONING (an
# explicit development/PoC-only build option -- see
# doc/MILENAGE-5G-AKA-DESIGN.md section 4) so it can provision the
# public test vector without a Transport KEK ceremony, which is not
# implemented in this branch (see design doc section 17).
#
# All key material below is PUBLIC 3GPP CONFORMANCE TEST DATA
# (3GPP TS 35.207 Test Set 1), not a real subscriber credential.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WORKDIR="$(mktemp -d /tmp/milenage-poc.XXXXXX)"
BUILD_DIR="$WORKDIR/build"
TOKEN_DIR="$WORKDIR/tokens"
CONF="$WORKDIR/softhsm2.conf"
PIN_FILE="$WORKDIR/pin.txt"
CRED_FILE="$WORKDIR/cred.bin"
SUBSCRIBER_JSON="$WORKDIR/subscriber-hsm.json"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== Milenage / 5G-AKA PoC: work dir $WORKDIR =="

mkdir -p "$BUILD_DIR" "$TOKEN_DIR"

cat > "$CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF

echo "-- Building SoftHSMv2 with WITH_MILENAGE=ON (PoC provisioning mode) --"
(
	cd "$BUILD_DIR"
	cmake -DWITH_CRYPTO_BACKEND=openssl \
	      -DWITH_MILENAGE=ON \
	      -DWITH_MILENAGE_PLAINTEXT_PROVISIONING=ON \
	      "$REPO_ROOT" > "$WORKDIR/cmake.log" 2>&1
	make -j"$(nproc)" > "$WORKDIR/make.log" 2>&1
) || { echo "BUILD FAILED -- see $WORKDIR/cmake.log / $WORKDIR/make.log"; exit 1; }

MODULE="$BUILD_DIR/src/lib/libsofthsm2.so"
UTIL="$BUILD_DIR/src/bin/util/softhsm2-util"
CLI="$BUILD_DIR/src/bin/milenage/softhsm2-milenage"

for f in "$MODULE" "$UTIL" "$CLI"; do
	[ -x "$f" ] || { echo "FAIL: expected build output missing: $f"; exit 1; }
done
echo "PASS: build produced libsofthsm2.so, softhsm2-util, softhsm2-milenage"

export SOFTHSM2_CONF="$CONF"

echo "-- Initializing an isolated test token --"
"$UTIL" --module "$MODULE" --init-token --free --label milenage-poc \
	--so-pin 1234 --pin 5678 > "$WORKDIR/init.log" 2>&1
echo "PASS: test token initialized"
echo "5678" > "$PIN_FILE"

echo "-- create-master-key --"
"$CLI" create-master-key --module "$MODULE" --token-label milenage-poc --pin-file "$PIN_FILE"
echo "PASS: Master Storage Key created"

# Public 3GPP TS 35.207 Test Set 1 K/OPc (NOT a real subscriber).
SUPI="imsi-001010123456789"
python3 -c "
import sys
k = bytes.fromhex('465b5ce8b199b49faa5f0a2ee238a6bc')
opc = bytes.fromhex('cd63cb71954a9f4e48a5994e37a02baf')
sys.stdout.buffer.write(k + opc)
" > "$CRED_FILE"

echo "-- provision (PoC plaintext mode, public test-vector data) --"
"$CLI" provision --module "$MODULE" --token-label milenage-poc --pin-file "$PIN_FILE" \
	--supi "$SUPI" --output "$SUBSCRIBER_JSON" < "$CRED_FILE"
echo "PASS: provisioning process wrote a UDM-ready JSON fragment"

WRAPPED_K=$(python3 -c "import json; print(json.load(open('$SUBSCRIBER_JSON'))['wrapped_k'])")
WRAPPED_OPC=$(python3 -c "import json; print(json.load(open('$SUBSCRIBER_JSON'))['wrapped_opc'])")

if python3 -c "import json,sys; d=json.load(open('$SUBSCRIBER_JSON')); sys.exit(0 if d['k'] is None and d['op'] is None and d['opc'] is None else 1)"; then
	echo "PASS: provisioning output contains only null plaintext fields"
else
	echo "FAIL: provisioning output leaked a plaintext field"; exit 1
fi

echo "-- (simulated process restart: rediscovering token/key in a fresh softhsm2-milenage invocation) --"
SQN="ff9bb4d0b607"
AMF="b9b9"
SNN="5G:mnc001.mcc001.3gppnetwork.org"

AV_JSON="$WORKDIR/av.json"
"$CLI" generate-5g-av --module "$MODULE" --token-label milenage-poc --pin-file "$PIN_FILE" \
	--supi "$SUPI" --wrapped-k "$WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
	--sqn "$SQN" --amf "$AMF" --snn "$SNN" > "$AV_JSON"
echo "PASS: 5G HE AV generated from wrapped credentials in a separate process"

for field in rand autn xres_star kausf; do
	python3 -c "
import json, sys
d = json.load(open('$AV_JSON'))
v = d.get('$field')
sys.exit(0 if isinstance(v, str) and len(v) > 0 else 1)
" || { echo "FAIL: AV response missing/empty field: $field"; exit 1; }
done
echo "PASS: RAND, AUTN, XRES*, and KAUSF are all present in the AV response"

RAND_LEN=$(python3 -c "import json; print(len(json.load(open('$AV_JSON'))['rand']))")
AUTN_LEN=$(python3 -c "import json; print(len(json.load(open('$AV_JSON'))['autn']))")
XRES_LEN=$(python3 -c "import json; print(len(json.load(open('$AV_JSON'))['xres_star']))")
KAUSF_LEN=$(python3 -c "import json; print(len(json.load(open('$AV_JSON'))['kausf']))")
[ "$RAND_LEN" = 32 ] && [ "$AUTN_LEN" = 32 ] && [ "$XRES_LEN" = 32 ] && [ "$KAUSF_LEN" = 64 ] \
	|| { echo "FAIL: unexpected AV field length(s)"; exit 1; }
echo "PASS: RAND/AUTN/XRES* are 16 bytes and KAUSF is 32 bytes, as required"

echo "-- negative path: modified wrapped blob must be rejected --"
BAD_WRAPPED_K=$(python3 -c "
import base64
raw = bytearray(base64.b64decode('$WRAPPED_K'))
raw[-1] ^= 0x01
print(base64.b64encode(bytes(raw)).decode())
")
if "$CLI" generate-5g-av --module "$MODULE" --token-label milenage-poc --pin-file "$PIN_FILE" \
	--supi "$SUPI" --wrapped-k "$BAD_WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
	--sqn "$SQN" --amf "$AMF" --snn "$SNN" > /dev/null 2>"$WORKDIR/bad_blob.log"; then
	echo "FAIL: a modified wrapped_k blob was accepted"; exit 1
fi
echo "PASS: a modified wrapped_k blob was rejected"

echo "-- negative path: cross-subscriber-bound blob must be rejected --"
OTHER_SUPI="imsi-001010999999999"
if "$CLI" generate-5g-av --module "$MODULE" --token-label milenage-poc --pin-file "$PIN_FILE" \
	--supi "$OTHER_SUPI" --wrapped-k "$WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
	--sqn "$SQN" --amf "$AMF" --snn "$SNN" > /dev/null 2>"$WORKDIR/cross_supi.log"; then
	echo "FAIL: wrapped credentials bound to a different SUPI were accepted"; exit 1
fi
echo "PASS: wrapped credentials bound to a different SUPI were rejected"

echo "-- resynchronization --"
# A correctly-14-byte but semantically-invalid AUTS must be rejected
# with an invalid-MAC-S failure; this script does not attempt to
# construct a valid AUTS (that requires an f5*/f1* implementation this
# script deliberately does not duplicate -- see
# src/lib/milenage/test/standalone_selftest.cpp for the positive-path
# resync round trip against the algorithm implementation directly).
RAND_HEX=$(python3 -c "print(bytes(range(0x10,0x20)).hex())")
AUTS_HEX=$(python3 -c "print(bytes([0xAA ^ i for i in range(14)]).hex())")
if "$CLI" resync --module "$MODULE" --token-label milenage-poc --pin-file "$PIN_FILE" \
	--supi "$SUPI" --wrapped-k "$WRAPPED_K" --wrapped-opc "$WRAPPED_OPC" \
	--rand "$RAND_HEX" --auts "$AUTS_HEX" > /dev/null 2>"$WORKDIR/resync.log"; then
	echo "FAIL: an invalid AUTS was accepted by resync"; exit 1
fi
grep -qi "invalid MAC-S" "$WORKDIR/resync.log" \
	&& echo "PASS: resync correctly reports an invalid MAC-S for a garbage AUTS" \
	|| { echo "FAIL: resync failed for an unexpected reason:"; cat "$WORKDIR/resync.log"; exit 1; }

echo ""
echo "== All PoC checks passed =="
echo "Reminder: SoftHSMv2 is a software PKCS#11 implementation, not a"
echo "hardware security boundary -- see doc/MILENAGE-5G-AKA-DESIGN.md"
echo "section 3 before using this design for real subscriber credentials."
