"""Qualify the actual public Rust DA coordinate and both pinned native emitters."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/attestation_coordinate.hepta"
ADAPTER = Path(__file__).with_name("rust_da_attestation_coordinate_reference.rs")
CODEC = ROOT / "trillionnium/crates/trnm-data-availability/src/codec.rs"
DOMAIN = b"trnm.portable.v2.da-attestation-conflict-coordinate.candidate.v1"
WORK = 1280
OUT = b"\xa5" * 41
SCRATCH = b"\x6d" * (WORK + 13)


def num(width, n):
    return n.to_bytes(width, "little")


def vector(blob):
    return num(4, len(blob)) + blob


def fields(chain=b"dot-chain", author=b"fixture-author"):
    return [
        num(2, 1), num(2, 1), bytes(range(32)), vector(chain), num(4, 1),
        b"\xa1" * 32, b"\x00", num(8, 29), b"\x10" * 32, b"\x11" * 32,
        b"\x12" * 32, b"\x13" * 32, num(8, 55), b"\x14" * 32,
        vector(author), num(8, 37), num(8, 38), b"\x15" * 32,
    ]


def digest(parts):
    admitted = [*parts[1:8], *parts[13:16]]
    return hashlib.sha256(vector(DOMAIN) + b"".join(admitted)).digest()


def changed(parts, field, value):
    result = list(parts)
    result[field] = value
    return result


class DaAttestationCoordinate(unittest.TestCase):
    def test_actual_original_typed_coordinate_and_both_pinned_backends(self):
        codec_before = hashlib.sha256(CODEC.read_bytes()).digest()
        main = fields()
        bound = fields(b"z", b"p" * (MAX_EXTENT - 306))
        off_bound = fields(b"z", b"p" * (MAX_EXTENT - 305))
        coordinate = digest(main)
        covered = {
            1: num(2, 5), 2: b"x" * 32, 3: vector("鏈○🙂".encode()), 4: num(4, 0),
            5: b"x" * 32, 6: b"\xff", 7: num(8, 0), 13: b"x" * 32,
            14: vector(b""), 15: num(8, 0),
        }
        ignored = {i: bytes([main[i][0] ^ 0x7f]) + main[i][1:]
                   for i in (0, 8, 9, 10, 11, 12, 16, 17)}
        changed_in = [changed(main, i, v) for i, v in covered.items()]
        changed_out = [changed(main, i, v) for i, v in ignored.items()]
        for case in changed_in:
            self.assertNotEqual(digest(case), coordinate)
        for case in changed_out:
            self.assertEqual(digest(case), coordinate)
        all_valid = [main, *changed_in, *changed_out, fields(b"", b""), bound, off_bound]
        valid_wire = [b"".join(parts) for parts in all_valid]
        self.assertEqual([len(r) for r in valid_wire[-2:]], [MAX_EXTENT, MAX_EXTENT + 1])
        wire = valid_wire[0]
        author_extent = 253 + len(b"dot-chain")
        invalid = [
            b"", wire[:304], wire[:-1], wire+b"\0", wire[:36]+b"\xff"*4+wire[40:],
            wire[:40]+b"\xff"+wire[41:],
            wire[:author_extent]+b"\xff"*4+wire[author_extent+4:],
        ]
        with tempfile.TemporaryDirectory(prefix="trnm-da-attestation-coordinate-") as tmp:
            observations = locked_reference(
                Path(tmp), b"".join(map(vector, [*valid_wire, *invalid])), caller=ADAPTER)
        self.assertEqual(hashlib.sha256(CODEC.read_bytes()).digest(), codec_before)
        expected = [digest(parts) for parts in all_valid]
        self.assertEqual(observations, b"".join(b"\x00"+v for v in expected)+b"\x64"*len(invalid))
        cases = [(w, 0, v, len(OUT), len(SCRATCH))
                 for w, v in zip(valid_wire[:-1], expected[:-1], strict=True)]
        cases += [(w, 100, b"", len(OUT), len(SCRATCH)) for w in invalid]
        cases += [(wire, 102, b"", 31, WORK), (wire, 102, b"", len(OUT), WORK-1),
                  (wire, 0, coordinate, 32, WORK), (b"", 100, b"", 0, 0)]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                actual = native.call_many([
                    ("f0", [w, OUT[:o], SCRATCH[:s]]) for w, _, _, o, s in cases], timeout=60)
                for i, ((w, status, result, o, s), record) in enumerate(zip(cases, actual, strict=True)):
                    self.assertEqual(record.require_returned().value, status, (backend, i))
                    self.assertEqual(record.arguments[:2], [w, result+OUT[len(result):o]], (backend, i))
                    self.assertEqual(record.arguments[2][WORK:], SCRATCH[WORK:s], (backend, i))


if __name__ == "__main__":
    unittest.main()
