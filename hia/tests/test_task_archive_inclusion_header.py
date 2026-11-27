"""Original typed retention and header, feeding the native hash and proof fold."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, SOURCE as HASH, original
from hia.tests.test_task_archive_inclusion_fold import SOURCE as FOLD

HEADER = ROOT / "hia/src/task_kernel/archive_inclusion_header.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_inclusion_header_reference.rs"


class TaskArchiveInclusionHeaderTests(unittest.TestCase):
    def test_exact_public_verifier_order_and_native_join(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-header-") as directory:
            executable = original(Path(directory), REFERENCE)
            raw = execute([executable]).stdout
        parsed = []
        while raw:
            code, ls, lr, lp = struct.unpack_from("<4I", raw)
            s, r, p = 16, 16+ls, 16+ls+lr
            parsed.append((code, raw[s:r], raw[r:p], raw[p:p+lp]))
            raw = raw[p+lp:]
        self.assertEqual([x[0] for x in parsed],
                         [0, 23, 13, 20, 13, 22, 13, 13, 13, 13, 22, 13, 13, 1, 13])
        for mode in ("direct", "selfhost"):
            with (self.subTest(backend=mode),
                  NativeModule(HEADER, byte_exports=("f0",), backend=mode) as header,
                  NativeModule(HASH, byte_exports=("f0",), backend=mode) as hashing,
                  NativeModule(FOLD, byte_exports=("f0",), backend=mode) as folding):
                for code, seal, record, proof in parsed:
                    packet = struct.pack("<2Q", len(seal), len(record))+seal+record+proof
                    args = [packet, b"y"*11, b"z"*1264]
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
                for packet, cap, status in [(valid[:-1],1264,100),(valid+b"\0",1264,100),
                                            (valid,1263,102)]:
                    args = [packet, b"y"*11, bytes(cap)]
                    result = header.call("f0", args).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, args))
