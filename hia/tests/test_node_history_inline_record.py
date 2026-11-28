"""Original SQL storage classes before fixed-width history metadata checks."""
from collections import Counter
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.history_inline_record_original import ROOT, SOURCES, original
from hia.tests.native_support import NativeModule
from hia.tools.qualify import sources

SOURCE = ROOT / "hia/src/node/history_inline_record.hepta"


class NodeHistoryInlineRecordTests(unittest.TestCase):
    def test_locked_inline_record_same_held_sql_values_both_stock(self):
        bound = sources()
        for name in ("store/history_page.rs","store.rs"):
            key = "crates/trnm-pon-node/src/" + name
            self.assertEqual(bound["trillionnium/" + key], SOURCES[key])
        with tempfile.TemporaryDirectory(prefix="trnm-original-history-inline-") as temp:
            observations = original(Path(temp))
        rows = []
        at = 0
        while at < len(observations):
            in_n,code,out_n = struct.unpack_from("<III",observations,at)
            at += 12
            raw = observations[at:at+in_n]
            at += in_n
            expect = observations[at:at+out_n]
            at += out_n
            self.assertEqual(len(raw),in_n)
            self.assertEqual(len(expect),144 if code==0 else 0)
            rows.append((raw,code,expect))
        self.assertEqual(at,len(observations))
        self.assertEqual(Counter(code for _,code,_ in rows),
                         {0:3,10:3,11:4,12:4,13:4,14:2,30:9,31:5})
        target = rows[0][0]
        envelope = [
            target[:71], target+b"x", b"HIR2"+target[4:],
            target[:8]+struct.pack("<Q",5)+target[16:],
            target[:16]+struct.pack("<Q",4097)+target[24:],
            target[:32]+struct.pack("<Q",7)+target[40:],
            b"x"*16457,
        ]
        output,scratch = b"O"*151,b"W"*17
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native:
                matrix = rows + [(x,100,b"") for x in envelope]
                calls = [("f0",[raw,output,scratch]) for raw,_,_ in matrix]
                for (raw,code,value),reply in zip(matrix,native.call_many(calls),strict=True):
                    checked=reply.require_returned()
                    self.assertEqual((checked.abi_status,checked.value,checked.arguments),
                                     (0,code,[raw,value+output[len(value):],scratch]))
                for row,want in ((rows[0],102),(rows[-1],31)):
                    args=[row[0],output[:143],b""]
                    reply=native.call("f0",args).require_returned()
                    self.assertEqual((reply.value,reply.arguments),(want,args))
