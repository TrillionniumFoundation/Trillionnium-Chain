#!/usr/bin/env python3
"""Separate stdlib byte oracle for the storage-local TRNMSM01 record.

This checks the retained vector and this Python codec, not Rust execution,
checkpoint trust, filesystem durability, or independent review. The fixture is
not a consensus wire vector. Use --emit-vector only when reviewing this local
storage format; ordinary execution is read-only.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "trillionnium/crates/trnm-durable-file-adapters-v0/tests/vectors/snapshot_manifest_v1.hex"
LAYOUT = struct.Struct(">8s32s32sQQ32s32sIIQ32s32s32s")
MAGIC = b"TRNMSM01"
DOMAIN = b"trnm.snapshot-staging-manifest.v1"
FIELDS = ("chain", "protocol", "height", "epoch", "state", "chunks",
          "count", "maximum", "total", "schema", "checkpoint", "manifest")


def h(domain: bytes, *parts: bytes) -> bytes:
    encoded = b"".join(struct.pack(">Q", len(p)) + p for p in (domain, *parts))
    return hashlib.sha256(encoded).digest()


def binding(value: dict) -> bytes:
    return h(b"trnm.state-sync.snapshot-header.v0",
             value["chain"], value["protocol"], struct.pack(">Q", value["height"]),
             struct.pack(">Q", value["epoch"]), value["state"],
             struct.pack(">I", value["count"]), struct.pack(">I", value["maximum"]),
             struct.pack(">Q", value["total"]), value["schema"], value["checkpoint"])


def manifest_digest(value: dict) -> bytes:
    return h(b"trnm.state-sync.snapshot-manifest.v0", binding(value), value["chunks"])


def sample(epoch: int = 1) -> dict:
    value = {"chain": bytes([1]) * 32, "protocol": bytes([2]) * 32,
             "height": 2, "epoch": epoch, "state": bytes([3]) * 32,
             "count": 2, "maximum": 1024, "total": 2,
             "schema": bytes([5]) * 32, "checkpoint": bytes([6]) * 32}
    prefix = binding(value)
    leaves = [h(b"trnm.state-sync.snapshot-chunk.v0", prefix, struct.pack(">I", i), body)
              for i, body in enumerate((b"a", b"b"))]
    value["chunks"] = h(b"trnm.state-sync.chunk-node.v0", *leaves)
    value["manifest"] = manifest_digest(value)
    return value


def pack(value: dict) -> bytes:
    """Unchecked encoder for both positive controls and bounded negative inputs."""
    prefix = LAYOUT.pack(MAGIC, *(value[key] for key in FIELDS))
    assert len(prefix) == 264
    return prefix + h(DOMAIN, prefix)


def decode(record: bytes) -> dict:
    if len(record) != 296 or record[:8] != MAGIC:
        raise ValueError("exact storage version/length required")
    if record[264:] != h(DOMAIN, record[:264]):
        raise ValueError("storage checksum mismatch")
    value = dict(zip(FIELDS, LAYOUT.unpack(record[:264])[1:]))
    if not (0 < value["count"] <= 65_536
            and 0 < value["maximum"] <= 4 * 1024 * 1024
            and value["count"] <= value["total"] <= 512 * 1024**3
            and value["total"] <= value["count"] * value["maximum"]
            and value["height"] > 0 and value["epoch"] >= 0):
        raise ValueError("invalid storage dimensions")
    if any(value[key] == bytes(32) for key in
           ("chain", "protocol", "state", "chunks", "schema", "checkpoint", "manifest")):
        raise ValueError("zero binding")
    if value["manifest"] != manifest_digest(value):
        raise ValueError("canonical manifest mismatch")
    return value


class SnapshotManifestReferenceTests(unittest.TestCase):
    def test_native_epoch_zero_is_not_an_implicit_genesis_anchor(self):
        value = sample(epoch=0)
        self.assertEqual(decode(pack(value)), value)
        value["height"] = 0
        value["manifest"] = manifest_digest(value)
        with self.assertRaises(ValueError):
            decode(pack(value))

    def test_retained_bytes_match_separate_reference_and_round_trip(self):
        expected = bytes.fromhex(VECTOR.read_text(encoding="ascii").strip())
        self.assertEqual(pack(sample()), expected)
        self.assertEqual(decode(expected), sample())

    def test_each_byte_mutation_rejects(self):
        original = pack(sample())
        for index in range(len(original)):
            changed = bytearray(original)
            changed[index] ^= 1
            with self.assertRaises(ValueError, msg=f"byte {index}"):
                decode(bytes(changed))

    def test_all_prefixes_and_trailing_bytes_reject(self):
        original = pack(sample())
        for end in range(len(original)):
            with self.assertRaises(ValueError):
                decode(original[:end])
        with self.assertRaises(ValueError):
            decode(original + b"\0")

    def test_rewritten_storage_checksum_cannot_hide_canonical_manifest_drift(self):
        value = sample()
        value["maximum"] += 1
        with self.assertRaisesRegex(ValueError, "canonical manifest"):
            decode(pack(value))

    def test_canonical_and_checksummed_out_of_bounds_records_reject(self):
        for key, invalid in (("count", 0), ("count", 65_537), ("maximum", 0),
                             ("maximum", 4 * 1024 * 1024 + 1), ("total", 1),
                             ("total", 2049), ("height", 0)):
            value = sample()
            value[key] = invalid
            value["manifest"] = manifest_digest(value)
            with self.assertRaises(ValueError, msg=key):
                decode(pack(value))

    def test_zero_bindings_and_legacy_layout_are_not_migrated(self):
        for key in ("chain", "protocol", "state", "chunks", "schema", "checkpoint"):
            value = sample()
            value[key] = bytes(32)
            value["manifest"] = manifest_digest(value)
            with self.assertRaises(ValueError, msg=key):
                decode(pack(value))
        with self.assertRaises(ValueError):
            decode(b"TRNMSM00" + bytes(116))

    def test_self_consistent_record_does_not_authenticate_a_trust_context(self):
        expected = sample()
        foreign = dict(expected)
        foreign["chain"] = bytes([77]) * 32
        foreign["manifest"] = manifest_digest(foreign)
        self.assertEqual(decode(pack(foreign)), foreign)
        self.assertNotEqual(foreign["manifest"], expected["manifest"])
        # Context admission must still compare the independently trusted chain,
        # checkpoint/root and original chunk commitment. Shape alone is not trust.


if __name__ == "__main__":
    if sys.argv[1:] == ["--emit-vector"]:
        VECTOR.parent.mkdir(parents=True, exist_ok=True)
        VECTOR.write_text(pack(sample()).hex() + "\n", encoding="ascii")
        print(f"storage_vector_bytes=296 sha256={hashlib.sha256(pack(sample())).hexdigest()}")
    elif sys.argv[1:]:
        raise SystemExit("usage: test_snapshot_manifest_reference_v1.py [--emit-vector]")
    else:
        unittest.main(verbosity=2)
