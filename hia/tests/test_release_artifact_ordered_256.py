"""Actual original artifact aggregation with the common bounded merge driver."""
import hashlib
from pathlib import Path
import struct
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_artifact_set_digest import BASE, ROOT, SOURCE as LEGACY, frame, transcript
from hia.tests.test_release_unsigned_candidate import locked_original_report

SOURCE = ROOT / "hia/src/release_bundle/artifact_set_ordered_256.hepta"
ADAPTER = Path(__file__).with_name("rust_release_artifact_ordered_reference.rs")
WORK = 16384


def roster(n):
    sizes = (0, 1, 255, 256, 65535, 65536, 1 << 63, (1 << 64) - 1)
    return [(
        b"n" * 508 + f"{i % 5:04}".encode(), b"m" * 252 + f"{i % 3:04}".encode(),
        sizes[i % 8], bytes([i % 4]) * 32, bool(i % 2),
        bytes([i % 11]) * 32, bytes([i % 7]) * 32,
    ) for i in range(n)]


def packet(r):
    return frame(0, r, pad=0xAE)[1:]


class ReleaseArtifactOrdered256(unittest.TestCase):
    def test_actual_original_artifact_aggregate_and_legacy_extent(self):
        sizes = (0, 1, 3, 63, 64, 65, 95, 127, 128, 129, 255, 256)
        rows = [roster(n)[::-1] for n in sizes]
        rows += [roster(256), [BASE]*256,
                 [BASE]*255 + [(BASE[0],BASE[1],BASE[2],BASE[3],False,BASE[5],BASE[6])]]
        frames = [packet(row) for row in rows]
        expected = [hashlib.sha256(transcript(row)).digest() for row in rows]
        result = locked_original_report(ADAPTER,b"".join(frames))
        self.assertEqual((result.stdout,result.stderr),(b"".join(expected),b""))
        self.assertEqual(expected[11],expected[12])
        self.assertNotEqual(expected[13],expected[14])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native, NativeModule(LEGACY,backend=backend,byte_exports=("f0",)) as old:
                out, work = b"Q"*39, b"W"*(WORK+9)
                for frame0,digest in zip(frames,expected,strict=True):
                    got=native.call("f0",[frame0,out,work]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(0,[frame0,digest+out[32:]]))
                    self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                for i in (0,2,4):
                    args=[b"\0"+frames[i],out,work]
                    got=old.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments[1]),(0,expected[i]+out[32:]))
                args=[b"\0"+frames[5],out,work]
                got=old.call("f0",args).require_returned()
                self.assertEqual((got.value,got.arguments),(100,args))

    def test_wire_and_extent_controls_have_no_publication(self):
        data=packet(roster(65))
        invalid=[packet(roster(257)),data[:-1],data+b"x",
                 data[:2]+struct.pack("<H",513)+data[4:],
                 data[:14]+b"\x02"+data[15:]]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native:
                out,work=b"O"*32,b"W"*WORK
                cases=[([i,out,work],100) for i in invalid]+[
                    ([data,out[:-1],work],102),([data,out,work[:-1]],102),
                ]
                got=native.call_many([("f0",args) for args,_ in cases])
                for call,(args,status) in zip(got,cases,strict=True):
                    value=call.require_returned()
                    self.assertEqual((value.value,value.arguments),(status,args))
