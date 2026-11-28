"""Private native RootStatementV3 successor-identity parity with the original."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_root_recovery_checkpoint import ROOT, original

SOURCE = ROOT / "hia/src/release_bundle/root_successor_identity_v3.hepta"
REFERENCE = ROOT / "hia/tests/rust_root_successor_identity_reference.rs"


class RootSuccessorIdentityTests(unittest.TestCase):
    def test_original_successor_statement_operation_identity(self):
        with tempfile.TemporaryDirectory(prefix="m15-root-successor-id-") as tmp:
            oracle = original(Path(tmp), reference=REFERENCE)
        rows = []
        while oracle:
            status, n = struct.unpack_from("<II", oracle)
            size = 64 if status == 0 else 0
            self.assertLessEqual(8 + n + size, len(oracle))
            rows.append((oracle[8:8 + n], status, oracle[8 + n:8 + n + size]))
            oracle = oracle[8 + n + size:]
        self.assertEqual([status for _, status, _ in rows], [0]*6 + [9, 9, 2, 3, 1, 1, 5])
        self.assertEqual(len({value for _, status, value in rows if status == 0}), 6)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                sentinel = b"O" * 72
                scratch = b"W" * 132264
                calls = [("f0", [data, sentinel, scratch]) for data, _, _ in rows]
                for call, (data, status, value) in zip(native.call_many(calls), rows, strict=True):
                    got = call.require_returned()
                    self.assertEqual(got.value, status)
                    self.assertEqual(got.arguments[:2], [data, value + sentinel[len(value):]])
                    self.assertEqual(got.arguments[2][132256:], scratch[132256:])
                for output, work in ((sentinel[:63], scratch), (sentinel, scratch[:132255])):
                    args = [rows[0][0], output, work]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (102, args))
