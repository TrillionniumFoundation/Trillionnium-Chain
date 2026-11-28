"""Original digest-only V0 builder provenance and native heapsort parity."""
from pathlib import Path
import struct
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_builder_provenance import (
    ROOT, SOURCE as LEGACY, FIXED, ZERO, BUILD_INPUT, byte_digest, declared, pack,
)
from hia.tests.test_release_unsigned_candidate import locked_original_report

SOURCE = ROOT / "hia/src/release_bundle/builder_provenance_ordered_256.hepta"
ADAPTER = Path(__file__).with_name("rust_release_provenance_ordered_reference.rs")
WORK = 14336


def roster(n):
    return [(b"x"*508 + f"{i % 13:04}".encode(), byte_digest(i % 17),
             byte_digest(i % 11)) for i in range(n)]


class ReleaseProvenanceOrdered256(unittest.TestCase):
    def test_original_digest_order_and_existing_private_limits(self):
        sizes=(0,1,3,63,64,65,95,127,128,129,255,256)
        rows=[(FIXED, roster(n)[::-1], ZERO) for n in sizes]
        rows += [
            (FIXED, roster(256), byte_digest(99)),
            (FIXED, [BUILD_INPUT]*256, ZERO),
            (FIXED, [BUILD_INPUT]*255+[(*BUILD_INPUT[:2],byte_digest(80))], ZERO),
            ((*FIXED[:5], byte_digest(119), FIXED[6]), roster(256), ZERO),
            ((*FIXED[:6], byte_digest(110)), roster(256), ZERO),
            ((byte_digest(98), *FIXED[1:]), roster(256), ZERO),
        ]
        packets=[pack(0,f,r,d,pad=0xA9) for f,r,d in rows]
        expected=[declared(f,r) for f,r,_ in rows]
        witness=locked_original_report(ADAPTER,b"".join(packets))
        self.assertEqual((witness.stdout,witness.stderr),(b"".join(expected),b""))
        self.assertEqual(expected[11],expected[12])
        self.assertNotEqual(expected[13],expected[14])
        self.assertEqual(len(set(expected[15:]+[expected[12]])),4)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native, NativeModule(LEGACY,backend=backend,byte_exports=("f0",)) as old:
                out,work=b"O"*38,b"W"*(WORK+8)
                for packet,digest in zip(packets,expected,strict=True):
                    got=native.call("f0",[packet,out,work]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(0,[packet,digest+out[32:]]))
                    self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                for i in (0,2,4):
                    args=[pack(0,*rows[i]),out,work]
                    got=old.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments[1]),(0,expected[i]+out[32:]))
                for mode in (0,1):
                    args=[pack(mode,FIXED,roster(65),ZERO),out,work]
                    got=old.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(100,args))

    def test_bounded_digest_only_input_and_nonpublication(self):
        packet=pack(0,FIXED,roster(65),ZERO)
        invalid=[
            pack(0,FIXED,roster(257),ZERO), packet[:-1], packet+b"X",
            b"\x01"+packet[1:], packet[:259]+struct.pack("<H",513)+packet[261:],
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native:
                out,work=b"O"*32,b"W"*WORK
                cases=[([p,out,work],100) for p in invalid]+[
                    ([packet,out[:-1],work],102),([packet,out,work[:-1]],102),
                ]
                actual=native.call_many([("f0",args) for args,_ in cases])
                for call,(args,status) in zip(actual,cases,strict=True):
                    got=call.require_returned()
                    self.assertEqual((got.value,got.arguments),(status,args))
