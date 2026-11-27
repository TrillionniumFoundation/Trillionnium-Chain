"""Two original recorder attempts reuse only the first attempt's derived state."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/cumulative_record_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_cumulative_record_replay_reference.rs"


class SqliteCumulativeRecordReplayTests(unittest.TestCase):
    def test_original_cumulative_state_capacity_and_exact_bytes(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-cumulative-evidence-") as directory:
            data = execute([original_adapter(Path(directory), ADAPTER)]).stdout
        cases = []
        while data:
            case, n = struct.unpack_from("<2Q", data)
            body = data[16:16+n]
            statuses, diags, outputs = [], [], []
            offset = 16+n
            for _ in range(2):
                status, *diag = struct.unpack_from("<10Q", data, offset)
                statuses.append(status)
                diags.append(diag)
                offset += 80
                if status == 0:
                    length, = struct.unpack_from("<Q", data, offset)
                    self.assertLessEqual(length, 512)
                    self.assertEqual(len(data[offset:offset+8+length]), 8+length)
                    outputs.append(data[offset:offset+8+length])
                    offset += 8+length
            fixed = struct.pack("<20Q", *(diags[0]+diags[1]+statuses))
            cases.append((case, body, statuses, diags, outputs, fixed+b"".join(outputs)))
            data = data[offset:]
        self.assertEqual(len(cases),14)
        for i in (0,7):
            rows = cases[i:i+7]
            self.assertEqual([r[0] for r in rows],list(range(7)))
            self.assertEqual([r[2] for r in rows], [[0,0],[0,13],[13,13],[0,13],[13,13],[0,13],[13,13]])
            self.assertEqual([json.loads(b[8:])["sequence"] for b in rows[0][4]], [9,10])
            self.assertEqual(len(rows[0][4][1])-len(rows[0][4][0]),1)
            self.assertEqual(len(rows[5][4][0]),520)
            self.assertEqual([d[2] for d in rows[5][3]], [10,10])
            self.assertEqual([d[5] for d in rows[2][3]], [2,3])
            self.assertEqual([d[6:8] for d in rows[6][3]], [[2,14],[2,14]])

        fixture = cases[0][1]
        def replace(i, v):
            return fixture[:i*8]+struct.pack("<Q",v)+fixture[i*8+8:]
        bad = [(fixture[:159],1200,100),(fixture[:160]+b"x"*513,1200,100),
               (fixture[:160]+b"\xed\xa0\x80",1200,100)]
        bad.extend((replace(i,v),1200,100) for i,v in ((0,0),(1,1281),(1,0),(5,2),(12,8),
                  (13,1025),(14,257),(15,1000000),(16,2),(18,1)))
        bad.extend((body,len(expected)-1,102) for _,body,_,_,_,expected in cases)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as n:
                good = [([body,b"\x56"*(len(expected)+pad),b"\xb1"*11],expected)
                        for _,body,_,_,_,expected in cases for pad in (0,511)]
                replies=n.call_many([("f0",args) for args,_ in good])
                for (args,expected),found in zip(good,replies,strict=True):
                    self.assertEqual((found.require_returned().value,found.arguments),
                                     (0,[args[0],expected+args[1][len(expected):],args[2]]))
                replies=n.call_many([("f0",[raw,b"\x72"*size,b"\x33"*13]) for raw,size,_ in bad])
                for (raw,size,status),found in zip(bad,replies,strict=True):
                    self.assertEqual((found.require_returned().value,found.arguments),
                                     (status,[raw,b"\x72"*size,b"\x33"*13]))
