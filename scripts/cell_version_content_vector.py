#!/usr/bin/env python3
"""Independent hashlib/struct framing for TCV2 and the unsigned CPV4 header.

This builds synthetic payloads and never invokes or imports a Rust encoder.
It does not generate a cryptographic signature or establish any authority.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import cell_complete_version_vector as v1

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "formal/pon-nakamoto-v1/vectors/cell-version-content-v2.json"


def vector():
    metadata_vector = v1.vector()
    metadata = bytes.fromhex(metadata_vector["wire_hex"])
    environment_context = v1.ctx(bytes([5]) * 32)
    model_context = v1.ctx(bytes.fromhex(metadata_vector["environment_closure"]))
    files = []
    for context, seed in [(environment_context, 11), (environment_context, 12),
                          (model_context, 21), (model_context, 22)]:
        legacy = v1.cell(context, seed)
        payload = bytes((seed + i % 251) % 256 for i in range(32769))
        chunks = [payload[i:i + 16384] for i in range(0, len(payload), 16384)]
        strong_payload = hashlib.sha512(b"TRNM/Cell/PayloadContent/v2\0" +
                                       struct.pack(">Q", len(payload)) + payload).digest()
        strong_chunks = [hashlib.sha512(b"TRNM/Cell/ChunkContent/v2\0" +
                                       struct.pack(">I", len(chunk)) + chunk).digest()
                         for chunk in chunks]
        files.append((legacy["id"], strong_payload, strong_chunks))
    files.sort(key=lambda row: row[0])
    wire = b"TCV2" + struct.pack(">I", len(metadata)) + metadata + struct.pack(">H", len(files))
    for locator, payload_digest, chunk_digests in files:
        wire += locator + payload_digest + struct.pack(">I", len(chunk_digests)) + b"".join(chunk_digests)
    commitment = hashlib.sha512(b"TRNM/Cell/CompleteVersionContent/v2\0" + wire).digest()
    header = (b"CPV4" + bytes([4, 0x65, 0, 0]) + bytes([6]) * 32 + bytes([7]) * 32 +
              commitment + bytes([8]) * 32 + bytes([9]) * 64 + struct.pack(">QQQQ", 2, 4, 200, 900))
    assert len(header) == 264
    return {
        "schema": "trnm-cell-version-content-vector-v2",
        "scope": "synthetic actual-byte framing and unsigned header; no signature, availability or execution",
        "wire_hex": wire.hex(), "wire_bytes": len(wire), "commitment_sha512": commitment.hex(),
        "cpv4_unsigned_header_hex": header.hex(),
        "cpv4_unsigned_message_sha512": hashlib.sha512(
            b"TRNM/Cell/CompleteVersionContent/ML-DSA-65/v4\0" + header).hexdigest(),
        "files": [{"locator": locator.hex(), "payload_sha512": payload.hex(),
                   "chunks_sha512": [chunk.hex() for chunk in chunks]} for locator, payload, chunks in files],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(vector(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if TARGET.read_text() != encoded:
            raise SystemExit("full content independent vector differs")
    else:
        TARGET.write_text(encoded)
    print("full content independent framing: PASS")
