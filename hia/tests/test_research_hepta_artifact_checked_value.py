"""Atomic composition of the exact old pure Hepta value methods."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_research_hepta_artifact_value import ROOT, OUT, WORK, locked_original

SOURCE=ROOT/"hia/src/research_protocol/hepta_artifact_checked_value.hepta"
REFERENCE=Path(__file__).with_name("rust_research_hepta_artifact_checked_value_reference.rs")


class HeptaArtifactCheckedValueTests(unittest.TestCase):
    def test_locked_original_sequential_value_and_atomic_refusal_dual(self):
        with tempfile.TemporaryDirectory(prefix="tria-hepta-checked-value-") as d:
            raw=locked_original(Path(d),adapter=REFERENCE)
        rows=[]
        while raw:
            status,n=struct.unpack_from("<II",raw)
            self.assertEqual(n,464)
            pkt_end=8+n
            expected=b""
            if status==0:
                length=struct.unpack_from("<Q",raw,pkt_end+32)[0]
                self.assertLessEqual(40+length,OUT)
                expected=raw[pkt_end:pkt_end+40+length]
            self.assertLessEqual(pkt_end+len(expected),len(raw))
            rows.append((status,raw[8:pkt_end],expected))
            raw=raw[pkt_end+len(expected):]
        self.assertEqual(len(rows),41)
        self.assertEqual({s for s,_,_ in rows},set(range(21)))
        self.assertGreater(sum(s==0 for s,_,_ in rows),1)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native:
                out,work=b"U"*(OUT+9),b"W"*(WORK+11)
                requests=[("f0",[inp,out,work]) for _,inp,_ in rows]
                for result,(status,pkt,expected) in zip(native.call_many(requests),rows,strict=True):
                    got=result.require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),
                                     (status,[pkt,expected+out[len(expected):]]))
                    if status:
                        self.assertEqual(got.arguments[2],work)
                    else:
                        self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                good=rows[0][1]
                blocked=rows[1][1] # original before-creation result beats capacity
                controls=[([good[:456],out,work],100),([good+b"x",out,work],100),
                          ([good,out[:OUT-1],work],102),([good,out,work[:WORK-1]],102),
                          ([blocked,b"",b""],19)]
                for args,status in controls:
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(status,args))
