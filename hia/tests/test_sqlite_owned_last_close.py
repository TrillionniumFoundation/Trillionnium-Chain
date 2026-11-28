"""Actual original held WAL/SHM names joined with last-close chronology."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_real_vfs_receipt_fold import original_owner

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/"hia/src/sqlite_io_boundary/owned_last_close.hepta"
ADAPTER = ROOT/"hia/tests/rust_sqlite_owned_last_close_reference.rs"


class SqliteOwnedLastCloseTests(unittest.TestCase):
    def test_held_original_owned_wal_and_shm_last_close(self):
        cases = []
        with tempfile.TemporaryDirectory(prefix="trnm-m15-owned-close-") as td:
            scratch = Path(td)
            fixture = original_owner(scratch, ADAPTER)
            for policy in (1,2):
                root = scratch/f"owner-{policy}"
                root.mkdir(mode=0o700)
                data = execute([fixture,root,str(policy)],timeout=30).stdout
                raw, want = data[:-56],data[-56:]
                self.assertGreater(len(raw),568)
                h = struct.unpack_from("<15Q",raw)
                self.assertEqual((h[0],h[11:15]),(policy,(7,1,7,1)))
                self.assertEqual((h[8]-h[5],h[9]-h[6]),(int(policy==1),5))
                self.assertEqual(struct.unpack_from("<Q",want,8)[0],h[10]-h[7])
                self.assertGreater(struct.unpack_from("<Q",want,24)[0],0)
                cases.append((raw,want))
        v1 = cases[0][0]
        v2 = cases[1][0]
        def alter(raw,at,val):
            return raw[:at]+struct.pack("<Q",val)+raw[at+8:]
        bad = [(v1[:567],56,100),(v2[:-1],56,100),(v1+b"x",56,100),(v2,55,102)]
        for pkt,at,value in (
            (v1,0,0),(v1,32,0),(v2,64,999),(v2,72,999),(v2,80,0),
            (v1,88,1),(v2,96,3),(v1,104,3),(v1,112,7),
            (v1,120+5*8,99),(v2,232+8*8,999),(v2,344+12*8,0),
            (v1,456+10*8,1),(v2,456,55),
            (v1,568,103),(v1,576,10),(v1,584,0),(v2,592,99),(v2,576+5*8,1),
        ):
            bad.append((alter(pkt,at,value),56,100))
        off = 576+104
        bad.append((v2[:off]+b"x"+v2[off+1:],56,100))
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as n:
                good = [([raw,b"\x43"*(56+pad),b"\x64"*7],want)
                        for raw,want in cases for pad in (0,9)]
                result = n.call_many([("f0",a) for a,_ in good])
                for (a,want),o in zip(good,result,strict=True):
                    self.assertEqual((o.require_returned().value,o.arguments),(0,[a[0],want+a[1][56:],a[2]]))
                args = [[raw,b"\x81"*size,b"\x67"*9] for raw,size,_ in bad]
                for a,(_,_,status),o in zip(args,bad,n.call_many([("f0",x) for x in args]),strict=True):
                    self.assertEqual((o.require_returned().value,o.arguments),(status,a))
