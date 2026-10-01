#!/usr/bin/env python3
"""
wrap-transport-package.py -- stands in for "the external secure
provisioning authority" (see ../METHODOLOGY.md "Provisioning"): wraps a
subscriber's K/OPc under the Transport KEK, producing exactly the
package format `softhsm2 import-transport-wrapped` expects.

This is deliberately independent of the SoftHSMv2 source tree -- it
only needs the `cryptography` package (`pip install cryptography`) and
reimplements the documented wire format from scratch. In a real
deployment, this logic runs on whatever system issues SIM/USIM
credentials, which has no access to (and no reason to access) the
SoftHSMv2 codebase; this script is what "no access to the HSM's source,
only the documented format" looks like in practice.

Package format (see src/lib/milenage/TransportEnvelope.cpp and
softhsm_milenage.h in the SoftHSMv2 tree for the authoritative
definition this must match byte-for-byte):

  91-byte plaintext, AES-KWP (RFC 5649) wrapped under the 32-byte
  Transport KEK:
    offset  0..3   magic              b"S5GT"
    offset  4      package version    0x01
    offset  5      secret type        0x01 = K, 0x02 = OPc
    offset  6      transport-key ver  0x01
    offset  7      reserved           0x00
    offset  8..39  subscriber binding SHA-256("open5gs-milenage-transport-v1:" + supi)
    offset  40     transaction id len 0..32 (0 if unused)
    offset  41..72 transaction id     left-justified, zero-padded
    offset  73     reserved           0x00
    offset  74     secret length      0x10 (16, big-endian high byte first)
    offset  75..90 secret             the 16-byte K or OPc value

usage:
  echo -n '<32 raw bytes: 16-byte K followed by 16-byte OPc>' | \\
      wrap-transport-package.py --supi imsi-999700000012345 \\
          --kek-file /opt/softhsm2/etc/transport-kek

  # or, more conveniently, from hex:
  wrap-transport-package.py --supi imsi-999700000012345 \\
      --k-hex 465B5CE8B199B49FAA5F0A2EE238A6BC \\
      --opc-hex E8ED289DEBA952E4283B54E88E6183CA \\
      --kek-file /opt/softhsm2/etc/transport-kek

Prints a JSON object with transport_wrapped_k / transport_wrapped_opc
(base64) -- feed these straight to:

  sudo softhsm2 import-transport-wrapped --supi imsi-... \\
      --transport-wrapped-k '<transport_wrapped_k>' \\
      --transport-wrapped-opc '<transport_wrapped_opc>'

K/OPc are read from --k-hex/--opc-hex, or (if omitted) 32 raw bytes
(K||OPc) from stdin -- never from argv in that path, same convention
`softhsm2 provision` uses. --k-hex/--opc-hex are provided for
convenience but land in shell history / process listing like any
argv-based secret; prefer the stdin path for anything beyond local
testing.
"""
import argparse
import base64
import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
except ImportError:
    sys.stderr.write(
        "error: the 'cryptography' package is required (pip install cryptography)\n"
    )
    sys.exit(1)

MAGIC = b"S5GT"
PACKAGE_VERSION = 0x01
TRANSPORT_KEY_VERSION = 0x01
BINDING_CONTEXT = b"open5gs-milenage-transport-v1:"
SECRET_TYPE_K = 0x01
SECRET_TYPE_OPC = 0x02
PLAINTEXT_LEN = 91
KEK_LEN = 32
SECRET_LEN = 16
MAX_TRANSACTION_ID_LEN = 32


def is_canonical_supi(supi: str) -> bool:
    if not supi.startswith("imsi-"):
        return False
    digits = supi[len("imsi-"):]
    return 5 <= len(digits) <= 15 and digits.isdigit()


def wrap_package(supi: str, secret_type: int, secret: bytes, kek: bytes,
                  transaction_id: bytes = b"") -> bytes:
    if not is_canonical_supi(supi):
        raise ValueError("SUPI must be canonical: 'imsi-' followed by 5-15 digits")
    if len(secret) != SECRET_LEN:
        raise ValueError("secret must be exactly 16 bytes")
    if len(kek) != KEK_LEN:
        raise ValueError("Transport KEK must be exactly 32 bytes")
    if len(transaction_id) > MAX_TRANSACTION_ID_LEN:
        raise ValueError("transaction id must be at most 32 bytes")

    binding = hashlib.sha256(BINDING_CONTEXT + supi.encode("utf-8")).digest()

    plaintext = bytearray(PLAINTEXT_LEN)
    plaintext[0:4] = MAGIC
    plaintext[4] = PACKAGE_VERSION
    plaintext[5] = secret_type
    plaintext[6] = TRANSPORT_KEY_VERSION
    plaintext[7] = 0x00
    plaintext[8:40] = binding
    plaintext[40] = len(transaction_id)
    plaintext[41:41 + len(transaction_id)] = transaction_id
    plaintext[73] = 0x00
    plaintext[74] = 0x10  # secret length, 16, per the fixed-width big-endian-style field
    plaintext[75:91] = secret

    return aes_key_wrap_with_padding(kek, bytes(plaintext))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--supi", required=True, help="e.g. imsi-999700000012345")
    p.add_argument("--kek-file", required=True,
                    help="path to the raw 32-byte Transport KEK "
                         "(e.g. /opt/softhsm2/etc/transport-kek)")
    p.add_argument("--k-hex", help="16-byte K as 32 hex chars (omit to read from stdin instead)")
    p.add_argument("--opc-hex", help="16-byte OPc as 32 hex chars (omit to read from stdin instead)")
    p.add_argument("--transaction-id", default="",
                    help="optional provisioning transaction id (<=32 bytes, UTF-8)")
    args = p.parse_args()

    with open(args.kek_file, "rb") as f:
        kek = f.read()
    if len(kek) != KEK_LEN:
        sys.stderr.write(f"error: {args.kek_file} is {len(kek)} bytes, expected 32\n")
        return 1

    if args.k_hex is not None or args.opc_hex is not None:
        if args.k_hex is None or args.opc_hex is None:
            sys.stderr.write("error: --k-hex and --opc-hex must be given together\n")
            return 1
        k = bytes.fromhex(args.k_hex)
        opc = bytes.fromhex(args.opc_hex)
    else:
        raw = sys.stdin.buffer.read()
        if len(raw) != 32:
            sys.stderr.write(
                f"error: stdin must be exactly 32 raw bytes (16-byte K followed by "
                f"16-byte OPc), got {len(raw)}\n"
            )
            return 1
        k, opc = raw[:16], raw[16:]

    txn_id = args.transaction_id.encode("utf-8")

    try:
        wrapped_k = wrap_package(args.supi, SECRET_TYPE_K, k, kek, txn_id)
        wrapped_opc = wrap_package(args.supi, SECRET_TYPE_OPC, opc, kek, txn_id)
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1

    print(json.dumps({
        "supi": args.supi,
        "transport_wrapped_k": base64.b64encode(wrapped_k).decode("ascii"),
        "transport_wrapped_opc": base64.b64encode(wrapped_opc).decode("ascii"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
