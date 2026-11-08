#!/usr/bin/env python3
"""Independent TCV1 framing vector; never imports or invokes the Rust encoder."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "formal/pon-nakamoto-v1/vectors/cell-complete-version-v1.json"

def u16(n): return n.to_bytes(2, "big")
def u32(n): return n.to_bytes(4, "big")
def u64(n): return n.to_bytes(8, "big")
def h(data): return hashlib.sha256(data).digest()
def framed(data): return u32(len(data)) + data

def ctx(runtime):
    family = b"complete-version-test"
    return bytes([len(family)]) + family + b"".join(bytes([n])*32 for n in (1, 2, 3, 4)) + runtime

def cell(context, seed):
    payload = bytes((seed + i % 251) % 256 for i in range(32769))
    pieces = [payload[i:i+16384] for i in range(0, len(payload), 16384)]
    wire = b"TCM1" + context + u64(len(payload)) + h(payload) + u32(16384) + u32(len(pieces))
    wire += b"".join(u32(len(piece)) + h(piece) for piece in pieces)
    return {"wire": wire, "id": h(b"trnm.cell-manifest.v1\0"+wire), "payload": h(payload), "size": len(payload)}

def closure(context, generation, profile, roots, files):
    release = b"TCR1" + context + u32(len(files)) + b"".join(sorted(row[2]["id"] for row in files))
    wire = b"TCD1" + u64(generation) + bytes([profile])*32 + framed(release)
    wire += u16(len(roots)) + b"".join(u16(i) for i in roots) + u16(len(files))
    for name, role, manifest, deps in files:
        path = name.encode("ascii")
        wire += u16(len(path)) + path + bytes([role]) + manifest["id"] + manifest["payload"] + u64(manifest["size"])
        wire += u16(len(deps)) + b"".join(u16(i) for i in deps)
    return wire

def vector():
    environment_context = ctx(bytes([5])*32)
    libraries = cell(environment_context, 11)
    runtime = cell(environment_context, 12)
    environment = closure(environment_context, 1, 6, [1], [("libraries.bin", 6, libraries, []), ("runtime.bin", 6, runtime, [0])])
    environment_id = h(b"trnm.cell-dependency-closure.v1\0" + environment)
    model_context = ctx(environment_id)
    base, tokenizer = cell(model_context, 21), cell(model_context, 22)
    model_closure = closure(model_context, 2, 7, [0], [("base.bin", 1, base, [1]), ("tokenizer.json", 2, tokenizer, [])])
    router = h(b"trnm.cell-model-router-roster.v1\0" + u16(0))
    model = b"TMR1" + framed(model_closure) + router + bytes([0])
    manifests = sorted([libraries, runtime, base, tokenizer], key=lambda row: row["id"])
    wire = b"TCV1" + framed(model) + framed(environment) + u16(len(manifests))
    wire += b"".join(framed(row["wire"]) for row in manifests)
    return {"schema": "trnm-cell-complete-version-vector-v1", "scope": "synthetic byte framing; no model execution or current authority",
            "wire_hex": wire.hex(), "wire_bytes": len(wire),
            "commitment_sha512": hashlib.sha512(b"TRNM/Cell/CompleteVersion/v1\0" + wire).hexdigest(),
            "model_root": h(b"trnm.cell-model-release-root.v1\0" + model).hex(),
            "environment_closure": environment_id.hex(), "payload_bytes": 4*32769, "chunk_scans": 12}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = json.dumps(vector(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if TARGET.read_text() != result: raise SystemExit("complete version vector differs")
    else:
        TARGET.write_text(result)
    print("complete version independent framing: PASS")
