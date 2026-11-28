"""Original SBOM typed ordered aggregate at and above the private 64-row ABI."""
import hashlib
from pathlib import Path
import struct
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_sbom_digest import BASE, ROOT, SOURCE as SMALL, frame, sorted_leaf_hashes
from hia.tests.test_release_unsigned_candidate import locked_original_report

SOURCE = ROOT / "hia/src/release_bundle/sbom_ordered_256.hepta"
REFERENCE = Path(__file__).with_name("rust_release_sbom_ordered_reference.rs")
DOMAIN = b"trnm.release.sbom.v0"
WORK = 16384


def roster(n):
    # Long shared prefixes drive full field walks; repeated exact rows remain
    # repeated. The dimensions deliberately exercise uneven and power-of-two runs.
    return [(
        b"pkg" + b"a" * 505 + bytes(f"{i % 19:04}", "ascii"),
        b"v" + b"x" * 251 + bytes(f"{i % 11:04}", "ascii"),
        bytes([i % 3]) * 32, bytes([i % 17]) * 32,
        b"L" + b"z" * 507 + bytes(f"{i % 7:04}", "ascii"),
        i % 2 == 0,
    ) for i in range(n)]


class ReleaseSbomOrdered256(unittest.TestCase):
    def test_original_ordered_digests_and_existing_small_abi(self):
        counts = (0, 1, 2, 3, 63, 64, 65, 95, 127, 128, 129, 255, 256)
        rows = [roster(n)[::-1] for n in counts]
        rows.extend([
            roster(256),  # original sort erases input order
            [BASE] * 256, # exact duplicates must retain multiplicity
            [BASE] * 255 + [(BASE[0], BASE[1], BASE[2], BASE[3], BASE[4], False)],
        ])
        frames = [frame(row, pad=0x9B) for row in rows]
        report = locked_original_report(REFERENCE, b"".join(frames))
        self.assertFalse(report.stderr)
        expected = [hashlib.sha256(DOMAIN + sorted_leaf_hashes(row)).digest() for row in rows]
        self.assertEqual(report.stdout, b"".join(expected))
        self.assertEqual(expected[12], expected[13])
        self.assertNotEqual(expected[14], expected[15])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, backend=backend, byte_exports=("f0",),
            ) as native, NativeModule(SMALL, backend=backend, byte_exports=("f0",)) as small:
                sentinel, work = b"O"*39, b"W"*(WORK+8)
                for packet, digest in zip(frames, expected, strict=True):
                    out = native.call("f0", [packet, sentinel, work]).require_returned()
                    self.assertEqual((out.value,out.arguments[:2]), (0,[packet,digest+sentinel[32:]]))
                    self.assertEqual(out.arguments[2][WORK:], work[WORK:])
                for i in (0, 3, 5):
                    packet = frames[i]
                    out = small.call("f0", [packet, sentinel, work]).require_returned()
                    self.assertEqual((out.value,out.arguments[1]), (0,expected[i]+sentinel[32:]))
                args = [frames[6], sentinel, work]
                out = small.call("f0", args).require_returned()
                self.assertEqual((out.value,out.arguments), (100,args))

    def test_large_guard_and_truncation_do_not_publish(self):
        packet = frame(roster(65))
        too_many = frame(roster(257))
        malformed = [
            too_many, packet[:-1], packet+b"x",
            packet[:2]+struct.pack("<H",513)+packet[4:],
            packet[:8]+b"x"+packet[9:],
        ]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, backend=backend, byte_exports=("f0",),
            ) as native:
                out, work = b"O"*32, b"W"*WORK
                controls = [([p,out,work],100) for p in malformed] + [
                    ([packet,out[:-1],work],102), ([packet,out,work[:-1]],102),
                ]
                for call,(args,status) in zip(
                    native.call_many([("f0",a) for a,_ in controls]), controls, strict=True,
                ):
                    got=call.require_returned()
                    self.assertEqual((got.value,got.arguments), (status,args))
