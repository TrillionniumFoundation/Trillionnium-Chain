"""Independent struct/hashlib framing checks; never imports or invokes Rust."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "formal/pon-nakamoto-v1/vectors/cell-storage-owner-vectors-v1.json"


def digest(data):
    return hashlib.sha256(data).digest()


def context(family, runtime=5):
    family = family.encode("ascii")
    return bytes([len(family)]) + family + b"".join(bytes([v]) * 32 for v in [1, 2, 3, 4, runtime])


def manifest(ctx, data):
    full = digest(data)
    return b"TCM1" + ctx + struct.pack(">Q", len(data)) + full + struct.pack(">III", 4 * 1024 * 1024, 1, len(data)) + full


def mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11D
        b >>= 1
    return result


def shard_vector():
    source = bytes((n * 37 + 19) % 251 for n in range(200_003))
    ctx = context("provider-native-v1")
    source_manifest = digest(b"trnm.cell-manifest.v1\0" + manifest(ctx, source))
    width = (len(source) + 3) // 4
    padded = source + bytes(width * 4 - len(source))
    data = [padded[n * width:(n + 1) * width] for n in range(4)]
    for row in [(27, 28, 18, 20), (28, 27, 20, 18)]:
        tables = [[mul(coefficient, value) for value in range(256)] for coefficient in row]
        data.append(bytes(tables[0][data[0][i]] ^ tables[1][data[1][i]] ^ tables[2][data[2][i]] ^ tables[3][data[3][i]] for i in range(width)))
    prefix = source_manifest + struct.pack(">II", 0, len(source)) + digest(source)
    wires = [b"CRS1" + prefix + struct.pack(">BI", slot, width) + body for slot, body in enumerate(data)]
    codeword = b"CRC1" + prefix + b"".join(digest(b"trnm.cell-rs46-shard.v1\0" + wire) for wire in wires)
    placement = b"".join(bytes([base + slot]) * 32 for slot in range(6) for base in [10, 20, 30, 40, 50, 60])
    provider = digest(b"trnm.cell-rs46-provider-store.v1\0" + struct.pack(">Q", 7) + placement[:192])
    stored_manifest = manifest(ctx, wires[0])
    wire = b"CSP1" + bytes([1]) * 32 + provider + struct.pack(">Q", 7) + bytes([101]) * 32
    wire += struct.pack(">QQQB", 10, 20, 2 * len(wires[0]), 0) + codeword + placement + struct.pack(">I", len(stored_manifest)) + stored_manifest
    return {"wire_bytes": len(wire), "wire_sha512": hashlib.sha512(wire).hexdigest(), "operation": digest(b"trnm.cell-rs46-provider-slot.v1\0" + wire).hex()}


def host_vector():
    wire = b"CHB1" + bytes([6]) * 32 + struct.pack(">Q", 9) + bytes([7]) * 64 + bytes([8]) * 64
    wire += bytes([9]) * 32 + bytes([10]) * 32 + struct.pack(">QQ", 2, 1) + context("host-handoff-vector-v1")
    for path in [b"worker.py", b"runtime.json"]:
        wire += struct.pack(">H", len(path)) + path
    wire += bytes([11]) * 32
    return {"wire_bytes": len(wire), "commitment": hashlib.sha512(b"TRNM/Cell/HostSealedDualContext/v1\0" + wire).hexdigest()}


def snapshot_vector():
    first, interval, maximum = 0x0102030405, 0x010203, 3
    wire = b"CPS1" + b"".join(bytes([v]) * 32 for v in (17, 34, 51, 68))
    wire += struct.pack(">QQI", first, interval, maximum)
    return {"wire_bytes": len(wire), "wire_hex": wire.hex(),
            "first_due_height": first, "interval_heights": interval,
            "maximum_snapshots": maximum,
            "due_heights": [first + ordinal * interval for ordinal in range(maximum)],
            "commitment": digest(b"trnm.cell-periodic-snapshot-policy.v1\0" + wire).hex()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    if arguments.check and arguments.write:
        parser.error("choose --check or --write")
    result = {"schema": "cell-storage-owner-vectors-v1", "csp1": shard_vector(),
              "chb1": host_vector(), "cps1": snapshot_vector()}
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.check:
        if OUTPUT.read_text() != encoded:
            raise SystemExit("FAIL: independent storage owner vectors differ")
        print("PASS: CSP1, CHB1 and CPS1 independent canonical vectors")
    elif arguments.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(encoded)
    else:
        print(encoded, end="")
