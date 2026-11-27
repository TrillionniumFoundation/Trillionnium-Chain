"""A second genuine SHM mutation uses the first mutation's own ledger effects."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/two_shm_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_two_shm_replay_reference.rs"


class SqliteTwoShmReplayTests(unittest.TestCase):
    def test_original_object_and_evidence_update_across_two_actions(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-two-shm-") as directory:
            log = execute([original_adapter(Path(directory), ADAPTER)]).stdout
        records = []
        while log:
            family, width = struct.unpack_from("<2Q", log)
            native_input = log[16:16+width]
            fixed = log[16+width:208+width]
            state = struct.unpack("<24Q",fixed)
            end = 208+width
            segments = []
            for status in state[18:20]:
                if status == 0:
                    size, = struct.unpack_from("<Q",log,end)
                    self.assertLessEqual(size,512)
                    segments.append(log[end:end+8+size])
                    end += 8+size
                else:
                    self.assertEqual(status,13)
            records.append((family,native_input,state,segments,fixed+b"".join(segments)))
            log = log[end:]
        self.assertEqual(len(records),14)
        for i in (0,7):
            cases = records[i:i+7]
            self.assertEqual([r[0] for r in cases],list(range(7)))
            self.assertEqual([r[2][18:20] for r in cases],[(0,0),(13,0),(13,13),(13,13),(0,0),(0,13),(0,13)])
            self.assertEqual([r[2][20:22] for r in cases[:5]],[(10,9),(32,31),(1,0),(1,0),(1,0)])
            self.assertEqual([r[2][22] for r in cases[3:5]],[2,0])
            self.assertEqual(json.loads(cases[1][3][0][8:])["shm_references"],31)
            self.assertEqual([json.loads(b[8:])["action"] for b in cases[0][3]], ["shm-reference","underlying-shm-unmap"])
        sample = records[0][1]
        def replace(i,v):
            return sample[:i*8]+struct.pack("<Q",v)+sample[i*8+8:]
        bad=[(sample[:391],1300,100),(sample[:392]+b"x"*513,1300,100),
             (sample[:392]+b"\xed\xa0\x80",1300,100)]
        bad.extend((replace(i,v),1300,100) for i,v in ((0,6),(1,1281),(1,0),(3,8),(8,0),(12,4),
                   (13,1025),(14,257),(20,3),(21,1),(25,32)))
        bad.extend((body,len(exp)-1,102) for _,body,_,_,exp in records)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as n:
                good=[([body,b"\x33"*(len(exp)+pad),b"\x18"*10],exp) for _,body,_,_,exp in records for pad in (0,519)]
                answers=n.call_many([("f0",args) for args,_ in good])
                for (args,expected),result in zip(good,answers,strict=True):
                    self.assertEqual((result.require_returned().value,result.arguments),
                                     (0,[args[0],expected+args[1][len(expected):],args[2]]))
                answers=n.call_many([("f0",[raw,b"\x19"*size,b"\x87"*8]) for raw,size,_ in bad])
                for (raw,size,status),result in zip(bad,answers,strict=True):
                    self.assertEqual((result.require_returned().value,result.arguments),
                                     (status,[raw,b"\x19"*size,b"\x87"*8]))
