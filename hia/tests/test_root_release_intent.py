"""Compare native private V3 release value checks against the unchanged public Rust API."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_root_recovery_checkpoint import ROOT, original

SOURCE = ROOT / "hia/src/release_bundle/root_release_intent_v3.hepta"
REFERENCE = ROOT / "hia/tests/rust_root_release_intent_reference.rs"


class RootReleaseIntentTests(unittest.TestCase):
    def test_original_decode_and_match_inert_release_value_bytes(self):
        with tempfile.TemporaryDirectory(prefix="m15-root-release-intent-") as temp:
            ref = original(Path(temp), reference=REFERENCE)
        rows = []
        while ref:
            status, n = struct.unpack_from("<II", ref)
            self.assertLessEqual(n, len(ref) - 8)
            rows.append((ref[8:8 + n], status))
            ref = ref[8 + n:]
        self.assertEqual([status for _, status in rows],
                         [0, 4, 4, 4, 4, 0, 0, 0, 4, 1, 2, 1, 1, 3, 3, 1, 3])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                work = b"W" * 132264
                sentinel = b"unchanged"
                cases = [([payload, sentinel, work], status) for payload, status in rows]
                cases.extend([
                    ([rows[0][0], sentinel, work[:132255]], 102),
                    ([rows[0][0][:23], sentinel, work], 102),
                    ([rows[0][0] + bytes(65536), sentinel, work], 102),
                    ([bytes([255]) * 8 + rows[0][0][8:], sentinel, work], 102),
                ])
                results = native.call_many([("f0", args) for args, _ in cases])
                for result, (args, status) in zip(results, cases, strict=True):
                    got = result.require_returned()
                    self.assertEqual(got.value, status)
                    self.assertEqual(got.arguments[:2], args[:2])
                    self.assertEqual(got.arguments[2][132256:], args[2][132256:])
                    if status == 102:
                        self.assertEqual(got.arguments, args)
