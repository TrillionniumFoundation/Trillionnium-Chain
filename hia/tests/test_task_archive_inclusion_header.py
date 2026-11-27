"""Original typed retention and header, feeding the native hash and proof fold."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, SOURCE as HASH, original
from hia.tests.test_task_archive_inclusion_fold import SOURCE as FOLD

VERIFY = ROOT / "hia/src/task_kernel/archive_inclusion_verify.hepta"
HEADER = ROOT / "hia/src/task_kernel/archive_inclusion_header.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_inclusion_header_reference.rs"


def typed_rows():
    with tempfile.TemporaryDirectory(prefix="m10-archive-header-") as directory:
        executable = original(Path(directory), REFERENCE)
        raw = execute([executable]).stdout
    parsed = []
    while raw:
        code, ls, lr, lp = struct.unpack_from("<4I", raw)
        s, r, p = 16, 16+ls, 16+ls+lr
        if p+lp > len(raw):
            raise ValueError("Truncated original typed row")
        parsed.append((code, raw[s:r], raw[r:p], raw[p:p+lp]))
        raw = raw[p+lp:]
    return parsed


def packet(seal, record, proof):
    return struct.pack("<2Q", len(seal), len(record)) + seal + record + proof


ORIGINAL_STATUSES = [0, 23, 13, 20, 13, 22, 13, 13, 13, 13, 22, 13, 13, 1, 13, 0, 0, 0]


class TaskArchiveInclusionHeaderTests(unittest.TestCase):
    def test_exact_public_verifier_order_and_native_join(self):
        parsed = typed_rows()
        self.assertEqual([row[0] for row in parsed], ORIGINAL_STATUSES)
        for mode in ("direct", "selfhost"):
            with (self.subTest(backend=mode),
                  NativeModule(HEADER, byte_exports=("f0",), backend=mode) as header,
                  NativeModule(HASH, byte_exports=("f0",), backend=mode) as hashing,
                  NativeModule(FOLD, byte_exports=("f0",), backend=mode) as folding):
                for code, seal, record, proof in parsed:
                    args = [packet(seal, record, proof), b"y"*11, b"z"*1264]
                    stage = header.call("f0", args).require_returned()
                    self.assertEqual(stage.arguments[:2], args[:2])
                    self.assertEqual(stage.value, 0 if code == 23 else code)
                    if stage.value:
                        continue
                    digest = hashing.call("f0", [b"\1"+record, bytes(32), bytes(1264)]).require_returned()
                    self.assertEqual(digest.value, 0)
                    count = struct.unpack_from("<I", seal, len(seal)-60)[0]
                    index, depth = struct.unpack_from("<II", proof, 34)
                    folded = struct.pack("<IIQ", count, index, depth)+seal[-32:]+digest.arguments[1]+proof[42:]
                    result = folding.call("f0", [folded, b"v"*17, bytes(1344)]).require_returned()
                    self.assertEqual((result.value, result.arguments[:2]), (code, [folded, b"v"*17]))
                _, s, r, p = parsed[0]
                valid = struct.pack("<2Q", len(s), len(r))+s+r+p
                for malformed_packet, cap, status in [(valid[:-1],1264,100),(valid+b"\0",1264,100),
                                            (valid,1263,102)]:
                    args = [malformed_packet, b"y"*11, bytes(cap)]
                    result = header.call("f0", args).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, args))


    def test_one_call_typed_original_inclusion_verifier(self):
        parsed = typed_rows()
        self.assertEqual([row[0] for row in parsed], ORIGINAL_STATUSES)
        self.assertEqual([struct.unpack_from("<I", row[3], 38)[0] for row in parsed[-3:]],
                         [0, 3, 12])
        for mode in ("direct", "selfhost"):
            with self.subTest(backend=mode), NativeModule(VERIFY, byte_exports=("f0",),
                                                            backend=mode) as verify:
                requests = [[packet(*row[1:]), b"Y"*17, b"Z"*1353] for row in parsed]
                replies = verify.call_many([("f0", args) for args in requests])
                for row, args, got in zip(parsed, requests, replies, strict=True):
                    result = got.require_returned()
                    self.assertEqual((result.value, result.arguments[:2]), (row[0], args[:2]))
                    self.assertEqual(result.arguments[2][1344:], args[2][1344:])
                valid = requests[0][0]
                for data, cap, expected in [(valid[:-1],1344,100), (valid+b"\0",1344,100),
                                            (valid,1343,102)]:
                    args = [data, b"U"*17, b"V"*cap]
                    result = verify.call("f0", args).require_returned()
                    self.assertEqual((result.value, result.arguments), (expected, args))
