"""Exact original offline Hepta typed status and no output authority."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_research_hepta_artifact_value import ROOT, locked_original

SOURCE=ROOT/"hia/src/research_protocol/hepta_artifact_check.hepta"
ADAPTER=Path(__file__).with_name("rust_research_hepta_artifact_check_reference.rs")


class HeptaArtifactCheckTests(unittest.TestCase):
    def test_locked_original_offline_priority_and_inclusive_window(self):
        with tempfile.TemporaryDirectory(prefix="trnm-hepta-offline-check-") as d:
            raw=locked_original(Path(d),adapter=ADAPTER)
        rows=[]
        while raw:
            status,n=struct.unpack_from("<II",raw)
            self.assertIn(n,(456,464))
            self.assertGreaterEqual(len(raw),n+8)
            rows.append((raw[8:8+n],status))
            raw=raw[8+n:]
        self.assertEqual([s for _,s in rows],[0,19,0,0,20]+
            [s for i in range(1,13) for s in (i,i)]+
            [13,14,15,16,17,17,18,18,0,19,0,18])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as module:
                out,work=b"O"*31,b"W"*137
                seed=rows[0][0]
                cases=[([inp,out,work],code) for inp,code in rows]+[
                    ([seed[:-1],out,work],100),
                    ([seed+b"x",out,work],100),
                    ([seed+bytes(9),out,work],100),
                    ([b"bad!"+seed[4:],out,work],100),
                    ([seed[:4]+b"\x02"+seed[5:],out,work],100),
                    ([seed[:5]+b"\x01"+seed[6:],out,work],100),
                    ([seed,b"",b""],0),
                ]
                results=module.call_many([("f0",a) for a,_ in cases])
                for call,(args,code) in zip(results,cases,strict=True):
                    got=call.require_returned()
                    self.assertEqual((got.value,got.arguments),(code,args))
