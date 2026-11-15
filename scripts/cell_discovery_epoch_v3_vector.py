#!/usr/bin/env python3
"""Independent canonical-byte vectors; no ML-DSA signing or acceptance claim."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "formal/pon-nakamoto-v1/vectors/cell-discovery-epoch-v3.json"


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def endpoint(ip: str, port: int) -> bytes:
    address = ipaddress.ip_address(ip)
    raw = address.packed
    if address.version == 4:
        raw = bytes(12) + raw
    return bytes([address.version]) + raw + struct.pack(">H", port)


def described(raw: bytes) -> dict:
    return {"bytes": len(raw), "hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()}


def render() -> str:
    base = b"".join(bytes([index]) * 32 for index in range(1, 7))
    request = base + u64(6_000_000)
    unsigned = (
        b"CDP3\x03\x65\x00\x00" + request + bytes([7]) * 32 + u64(9)
        + endpoint("192.0.2.20", 4060) + u64(42)
        + u64(1_800_000_001) + u64(1_800_000_120)
    )
    statement = b"TRNM/Cell/Provider/Epoch/Statement/v3\0" + unsigned
    provider_message = b"TRNM/Cell/Provider/Epoch/ML-DSA-65/v3\0" + unsigned
    assert len(request) == 200 and len(unsigned) == 291

    # Separate bounded lookup transcript. These public test values are never
    # a source of production nonces, signing keys or authorization rosters.
    auth_request = base + u64(3)
    query = (
        b"CDQ3\x03\x65\x01\x00" + struct.pack(">I", 0)
        + bytes([7]) * 32 + auth_request + endpoint("127.0.0.1", 19001)
        + bytes([8]) * 32 + u64(9) + u64(1000) + u64(1010)
    )
    reply = b"CDS3\x03\x65\x00\x00" + u64(1001) + u64(1010) + struct.pack(">I", 1) + b"\x00"
    reply_message = b"TRNM/Cell/Discovery/Reply/ML-DSA-65/v3\0" + query + reply
    assert len(query) == 319 and len(reply) == 29
    value = {
        "schema": "trnm-cell-discovery-epoch-v3-encoding-vectors",
        "scope": "Canonical unsigned bytes and signature-message construction only; no valid signature, cryptographic acceptance, network service or deployment evidence.",
        "provider": {
            "request": described(request),
            "unsigned_record": described(unsigned),
            "signature_message": described(provider_message),
            "statement_digest_sha256": hashlib.sha256(statement).hexdigest(),
            "record_wire_bytes_with_ml_dsa_65_signature": 3600,
            "parameters": {
                "epoch": 6_000_000, "epoch_seconds": 300,
                "base_field_repeated_bytes": [1, 2, 3, 4, 5, 6],
                "owner_repeated_byte": 7, "generation": 9,
                "endpoint": "192.0.2.20:4060", "sequence": 42,
                "issued_unix_seconds": 1_800_000_001,
                "expires_unix_seconds": 1_800_000_120, "withdrawn": False,
            },
        },
        "authenticated_lookup": {
            "query": described(query),
            "unsigned_reply": described(reply),
            "reply_signature_message": described(reply_message),
            "parameters": {"nonce_repeated_byte": 7, "bootstrap_key_repeated_byte": 8,
                           "generation": 9, "epoch": 3, "endpoint": "127.0.0.1:19001",
                           "query_issued": 1000, "reply_issued": 1001, "expires": 1010,
                           "kind": 1, "status": 0, "body_hex": "00"},
        },
    }
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    content = render()
    if args.write:
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        DESTINATION.write_text(content, encoding="utf-8")
    elif DESTINATION.read_text(encoding="utf-8") != content:
        raise SystemExit("Cell discovery epoch V3 encoding vector differs")
    print("Cell discovery epoch V3 canonical encoding vectors: PASS (encoding only)")


if __name__ == "__main__":
    main()
