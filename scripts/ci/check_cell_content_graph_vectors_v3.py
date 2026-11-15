#!/usr/bin/env python3
"""Independent TCG3/CCH1 framing vector; no Rust imports or security claims."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/cell-content-graph-v3/vectors.json"
PROFILE = bytes([0x42]) * 64  # Synthetic encoding-only label, not a selected profile.
DOMAIN = b"TRNM/CPQ1/FullContent/SHA512/v1\0"


def vector() -> dict:
    objects = []

    def observe(name: str, kind: int, instance: int, content: bytes) -> bytes:
        header = (b"CCH1" + PROFILE + bytes([kind]) + bytes([instance]) * 64
                  + struct.pack(">QQ", 1, len(content)))
        claim = header + hashlib.sha512(DOMAIN + header + content).digest()
        assert len(claim) == 213
        objects.append({"name": name, "claim_hex": claim.hex(),
                        "content_hex": content.hex()})
        return claim

    shared = [observe(name, 4, instance, name.encode("ascii")) for instance, name
              in ((101, "tokenizer"), (102, "layout"), (103, "runtime"))]

    def node(instance: int, base: bytes | None, parent: bytes | None) -> bytes:
        payload = observe(f"payload-{instance}", 4, instance,
                          f"payload-{instance}".encode("ascii"))
        family = b"vector-cell"
        content = b"TCG3" + bytes([len(family)]) + family + payload
        links = [(2 if base else 0, base), (2 if parent else 0, parent)]
        links.extend((1, claim) for claim in shared)
        for role, (kind, claim) in enumerate(links, 1):
            content += bytes([role, kind])
            if claim is not None:
                content += claim
        return observe(f"node-{instance}", 3, instance, content)

    first = node(1, None, None)
    second = node(2, first, None)
    root = node(3, second, first)
    total = sum(len(bytes.fromhex(obj["content_hex"])) for obj in objects)
    return {
        "schema": "trnm-cell-content-graph-v3-vectors",
        "profile_ids_are_synthetic_test_labels": True,
        "scope": "three-level declared DAG framing and complete-byte readback only",
        "root_claim_hex": root.hex(),
        "objects": objects,
        "expected": {"nodes": 3, "objects": 9, "edges": 15,
                     "maximum_node_depth": 3, "content_bytes": total,
                     "reserved_bytes": total + len(objects)},
    }


def encoded() -> bytes:
    return (json.dumps(vector(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def check() -> int:
    actual = FIXTURE.read_bytes()
    if actual != encoded():
        raise ValueError("TCG3 vector bytes differ from independent framing")
    return len(vector()["objects"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_bytes(encoded())
    elif sys.argv[1:]:
        raise SystemExit("usage: check_cell_content_graph_vectors_v3.py [--write]")
    print(json.dumps({"result": "PASS", "objects": check(), "native_execution": False}))
