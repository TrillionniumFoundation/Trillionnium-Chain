"""One immutable generated DA chunk and the actual private Rust inclusion path."""
from pathlib import Path
import re
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_chunk_inclusion_path import unchanged_original_observation

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/chunk_bound_inclusion.hepta"
HARNESS = Path(__file__).with_name("rust_da_chunk_bound_inclusion_harness.rs")
MARKER = b"TRNM_DA_BOUND_INCLUSION_COMPARATOR_V1"
SELECTOR = "retrieval::hia_da_chunk_path_fixture::original_bound_chunk_observe"
WORK = 1472
OUTPUT = b"\xa5" * 39
SCRATCH = b"\x6d" * (WORK+11)


def captures(data):
    i = 0
    while i < len(data):
        code, n = struct.unpack_from("<BI", data, i)
        at = i + 5
        frame = data[at:at+n]
        if code not in (0, 6, 50, 51, 52, 53, 54, 55) or len(frame) != n or n < 253:
            raise ValueError("Invalid original private chunk comparison")
        yield frame, code
        i = at + n


def change(data, at, value):
    return data[:at] + value + data[at+len(value):]


class DaChunkBoundInclusion(unittest.TestCase):
    def test_private_merkle_continuation_is_frozen_except_native_handoff(self):
        previous = SOURCE.with_name("chunk_inclusion_path.hepta").read_text()
        old_tail = previous[previous.index("block scan("):].split("\nend\n", 1)[0] + "\n"
        designed = re.sub(r"(?m)^block (bad_index|malformed|short)\(\)\n[^\n]*\n[^\n]*\n",
                          "", old_tail)
        new = SOURCE.read_text().split("\nfn dax_path", 1)[1]
        self.assertEqual(new[new.index("block scan("):].split("\nend\n", 1)[0] + "\n",
                         designed)

    def test_actual_private_rust_chunk_leaf_and_path_with_two_stock_emitters(self):
        with tempfile.TemporaryDirectory(prefix="trnm-da-bound-inclusion-original-") as tmp:
            raw, rlib_sha = unchanged_original_observation(
                Path(tmp), harness=HARNESS, marker=MARKER, test=SELECTOR,
                capture_limit=4*1024*1024)
        print("Original non-test rlib bytes unchanged:", rlib_sha)
        actual = list(captures(raw))
        self.assertEqual(len(actual), 29)
        self.assertEqual(sum(code == 0 for _, code in actual), 20)
        self.assertEqual({code for _, code in actual}, {0, 6, 50, 51, 52, 53, 54, 55})
        self.assertEqual([len(x[0]) for x in actual[-2:]], [MAX_EXTENT, MAX_EXTENT+1])
        self.assertEqual([x[1] for x in actual[-2:]], [0, 0])
        self.assertEqual(actual[1][0][32:64], actual[2][0][32:64])
        self.assertEqual([actual[1][1], actual[2][1]], [0, 55])  # same coordinate/expected root, changed chunk bytes
        bare = actual[0][0]
        middle = actual[1][0]
        chunk = 76 + 37 * struct.unpack_from("<I", middle, 72)[0]
        c = struct.unpack_from("<I", middle, chunk+36)[0]
        a = struct.unpack_from("<I", middle, chunk+117+c)[0]
        at_index = chunk+173+c+a-12
        controls = [
            (b"", 100, 0), (bare[:252], 100, WORK), (bare[1:], 100, WORK),
            (change(bare, 5, b"\x01"), 100, WORK),
            (change(bare, 0, b"FCD1"), 100, WORK),
            (change(bare, 0, b"\xff"*32), 100, WORK),
            (change(bare, 72, b"\xff"*4), 100, WORK),
            (change(middle, chunk+36, b"\xff"*4), 100, WORK),
            (change(middle, chunk+40, b"\xff"), 100, WORK),
            (middle[:-1], 100, WORK), (middle+b"\0", 100, WORK),
            (change(middle, at_index, struct.pack("<I", 1)), 56, WORK),
            (change(middle, 64, struct.pack("<I", 1)), 56, WORK),
            (middle, 102, WORK-1), (middle, 0, WORK),
        ]
        cases = [(frame, code, len(SCRATCH)) for frame, code in actual[:-1]] + controls
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                found = native.call_many([("f0", [frame, OUTPUT, SCRATCH[:extent]])
                                          for frame, _, extent in cases], timeout=60)
                for i, ((frame, code, extent), item) in enumerate(zip(cases, found, strict=True)):
                    self.assertEqual(item.require_returned().value, code, i)
                    self.assertEqual(item.arguments[:2], [frame, OUTPUT], i)
                    self.assertEqual(item.arguments[2][WORK:], SCRATCH[WORK:extent], i)
