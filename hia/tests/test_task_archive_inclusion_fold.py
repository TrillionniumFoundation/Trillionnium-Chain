"""Compose the native record hash with the original ordered archive proof fold."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, SOURCE as HASH, original

SOURCE = ROOT / "hia/src/task_kernel/archive_inclusion_fold.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_inclusion_fold_reference.rs"


class TaskArchiveInclusionFoldTests(unittest.TestCase):
    def test_planner_leaf_inclusion_and_public_verifier_parity(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-fold-") as directory:
            reference = original(Path(directory), REFERENCE)
            raw = execute([reference]).stdout
        rows = []
        offset = 0
        while offset < len(raw):
            status, record_len = struct.unpack_from("<II", raw, offset)
            start = offset + 8
            record = raw[start:start+record_len]
            start += record_len
            width, index, depth = struct.unpack_from("<IIQ", raw, start)
            body = raw[start:start+80+depth*32]
            self.assertEqual(len(body), 80+depth*32)
            rows.append((status, record, width, index, depth, body))
            offset = start + len(body)
        self.assertEqual(offset, len(raw))
        self.assertEqual({w for status, _, w, _, _, _ in rows if status == 0},
                         {1, 2, 3, 5, 8, 4096})
        self.assertEqual({status for status, *_ in rows}, {0, 1, 13, 23})
        for status, _, width, index, depth, body in rows:
            if status == 0:
                self.assertEqual(depth, (width - 1).bit_length())
                if index == width-1 and width > 1:
                    self.assertEqual(body[48:80] == body[80:112], bool(width & 1))
        for mode in ("direct", "selfhost"):
            with (self.subTest(backend=mode),
                  NativeModule(HASH, byte_exports=("f0",), backend=mode) as hashing,
                  NativeModule(SOURCE, byte_exports=("f0",), backend=mode) as folding):
                for status, record, _, _, _, body in rows:
                    request = b"\1" + record
                    digest = hashing.call("f0", [request, bytes(32), bytes(1264)]).require_returned()
                    self.assertEqual((digest.value, digest.arguments[1]), (0, body[48:80]))
                    from_native = body[:48] + digest.arguments[1] + body[80:]
                    args = [from_native, b"o"*17, b"s"*1344]
                    got = folding.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (status, args[:2]))
                    if status in (1, 13):
                        self.assertEqual(got.arguments[2], args[2])
                frame = next(body for status, _, w, _, _, body in rows if status == 0 and w == 2)
                over_depth = frame[:8] + struct.pack("<Q", 13) + frame[16:]
                for test_frame, n, expected in [(frame[:-1], 1344, 100), (frame+b"\0", 1344, 100),
                                                (over_depth, 1344, 100), (frame, 1343, 102)]:
                    args = [test_frame, b"A"*17, b"B"*n]
                    result = folding.call("f0", args).require_returned()
                    self.assertEqual((result.value, result.arguments), (expected, args))
