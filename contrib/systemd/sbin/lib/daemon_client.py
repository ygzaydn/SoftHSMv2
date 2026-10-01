#!/usr/bin/env python3
"""
Minimal reference client for softhsm-gsm's wire protocol.

Implements, independently of the C++ code, exactly what's documented
in SoftHSMv2's src/bin/milenage/softhsm-gsm.cpp header comment
and src/lib/milenage/softhsm_milenage.h:

  S5GM request  (client -> daemon):
    magic "S5GM"(4) | version(1) | operation(1) | reserved(2) | total_len(4 BE)
    then TLVs: tag(2 BE) | length(4 BE) | value

  daemon response (daemon -> client):
    payload_len(4 BE) | status(1: 0=OK,1=ERROR) | payload
    payload on OK is itself an S5GM message (TLV response fields)

This file is meant as copy-paste-able reference for whoever writes the
real Open5GS-side client, not a production library.
"""
import base64
import json
import socket
import struct
import sys

WIRE_MAGIC = b"S5GM"
WIRE_VERSION = 1

OP_5G_HE_AV = 0x02
OP_RESYNC = 0x03

TAG_SUPI = 0x0001
TAG_WRAPPED_K = 0x0002
TAG_WRAPPED_OPC = 0x0003
TAG_SQN = 0x0004
TAG_AMF = 0x0005
TAG_SNN = 0x0006
TAG_RAND = 0x0007
TAG_AUTS = 0x0008

TAG_OUT_RAND = 0x0101
TAG_OUT_AUTN = 0x0102
TAG_OUT_XRES_STAR = 0x0103
TAG_OUT_KAUSF = 0x0104
TAG_OUT_SQN_MS = 0x0105


def build_request(operation, fields):
    body = b""
    for tag, value in fields:
        body += struct.pack(">HI", tag, len(value)) + value
    header_len = 4 + 1 + 1 + 2 + 4
    total_len = header_len + len(body)
    header = WIRE_MAGIC + struct.pack(">BBHI", WIRE_VERSION, operation, 0, total_len)
    return header + body


def parse_fields(payload):
    fields = {}
    pos = 12
    while pos + 6 <= len(payload):
        tag, length = struct.unpack(">HI", payload[pos:pos + 6])
        pos += 6
        fields[tag] = payload[pos:pos + length]
        pos += length
    return fields


def round_trip(sock, request):
    sock.sendall(request)
    header = _read_exact(sock, 5)
    (length,) = struct.unpack(">I", header[:4])
    status = header[4]
    payload = _read_exact(sock, length) if length else b""
    return status, payload


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by daemon")
        buf += chunk
    return buf


def generate_5g_he_av(sock, supi, wrapped_k, wrapped_opc, sqn, amf, snn):
    req = build_request(OP_5G_HE_AV, [
        (TAG_SUPI, supi.encode()),
        (TAG_WRAPPED_K, wrapped_k),
        (TAG_WRAPPED_OPC, wrapped_opc),
        (TAG_SQN, sqn),
        (TAG_AMF, amf),
        (TAG_SNN, snn.encode()),
    ])
    status, payload = round_trip(sock, req)
    if status != 0:
        raise RuntimeError("daemon error: " + payload.decode(errors="replace"))
    return parse_fields(payload)


def resync(sock, supi, wrapped_k, wrapped_opc, rand_, auts):
    req = build_request(OP_RESYNC, [
        (TAG_SUPI, supi.encode()),
        (TAG_WRAPPED_K, wrapped_k),
        (TAG_WRAPPED_OPC, wrapped_opc),
        (TAG_RAND, rand_),
        (TAG_AUTS, auts),
    ])
    status, payload = round_trip(sock, req)
    if status != 0:
        raise RuntimeError("daemon error: " + payload.decode(errors="replace"))
    return parse_fields(payload)


def _main():
    if len(sys.argv) < 5:
        print(f"usage: {sys.argv[0]} <host> <port> <supi> <wrapped-json-file> "
              f"[sqn-hex12] [amf-hex4] [snn]", file=sys.stderr)
        sys.exit(2)

    host, port, supi, json_path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    sqn = bytes.fromhex(sys.argv[5]) if len(sys.argv) > 5 else bytes.fromhex("000000000001")
    amf = bytes.fromhex(sys.argv[6]) if len(sys.argv) > 6 else bytes.fromhex("8000")
    snn = sys.argv[7] if len(sys.argv) > 7 else "5G:mnc001.mcc001.3gppnetwork.org"

    with open(json_path) as f:
        doc = json.load(f)
    wrapped_k = base64.b64decode(doc["wrapped_k"])
    wrapped_opc = base64.b64decode(doc["wrapped_opc"])

    if host.startswith("unix:"):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(host[5:])
    else:
        sock = socket.create_connection((host, port), timeout=5)
    with sock:
        fields = generate_5g_he_av(sock, supi, wrapped_k, wrapped_opc, sqn, amf, snn)

    print(json.dumps({
        "rand": fields[TAG_OUT_RAND].hex(),
        "autn": fields[TAG_OUT_AUTN].hex(),
        "xres_star": fields[TAG_OUT_XRES_STAR].hex(),
        "kausf": fields[TAG_OUT_KAUSF].hex(),
    }, indent=2))


if __name__ == "__main__":
    _main()
