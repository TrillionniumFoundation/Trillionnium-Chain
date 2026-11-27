"""Retained DA namespace validation and canonical typed identity bytes."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_protocol_context import ROOT, locked_reference

SOURCE = ROOT / "hia/src/data_availability/typed_object_id.hepta"
CALLER = Path(__file__).with_name("rust_da_typed_object_id_reference.rs")
DIGESTS = (bytes(32), bytes(range(32)), b"\xff" * 32)


def wire(namespace, kind, digest=DIGESTS[1]):
    return struct.pack("<BH", namespace, kind) + digest


class DaTypedObjectId(unittest.TestCase):
    def test_exact_original_namespace_and_typed_object_encoding(self):
        original = [(wire(0, kind, digest), 0) for kind in range(1, 7) for digest in DIGESTS]
        original += [(wire(ns, 1), 2 if ns == 1 else 3) for ns in range(1, 256)]
        with tempfile.TemporaryDirectory(prefix="trnm-da-object-id-") as directory:
            raw = locked_reference(Path(directory), b"".join(item for item, _ in original), CALLER)
        offset = 0
        panel = []
        for item, expected in original:
            size = 35 if expected == 0 else 0
            self.assertEqual(raw[offset], expected)
            observed = raw[offset + 1:offset + 1 + size]
            self.assertEqual(observed, item if size else b"")
            panel.append((item, expected, observed, 42))
            offset += 1 + size
        self.assertEqual(offset, len(raw))
        shape = wire(0, 6)
        panel += [(shape, 0, shape, 35), (shape, 102, b"", 34), (shape, 102, b"", 0),
                  (shape[:-1], 100, b"", 42), (shape + b"x", 100, b"", 42),
                  (wire(0, 0), 4, b"", 42), (wire(0, 7), 4, b"", 42),
                  (wire(0, 257), 4, b"", 42), (wire(0, 65535), 4, b"", 0),
                  (wire(1, 65535), 2, b"", 0), (wire(2, 65535), 3, b"", 0)]
        hashes = set()
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, backend=backend, byte_exports=("f0",)) as module:
                hashes.add(module.artifact_sha256)
                for start in range(0, len(panel), 120):
                    subset = panel[start:start + 120]
                    requests = [("f0", [item, b"N" * room, b"W" * 23]) for item, _, _, room in subset]
                    for result, (item, code, value, room) in zip(module.call_many(requests, timeout=55), subset, strict=True):
                        self.assertEqual(result.require_returned().value, code, item.hex())
                        self.assertEqual(result.arguments, [item, value + b"N" * (room - len(value)), b"W" * 23])
        self.assertEqual(len(hashes), 2)
