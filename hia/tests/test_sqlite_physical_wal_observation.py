"""Original VFS-owned WAL metadata and silent inter-event observation checks."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_real_vfs_receipt_fold import original_owner

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/"hia/src/sqlite_io_boundary/physical_wal_observation.hepta"
ADAPTER = ROOT/"hia/tests/rust_sqlite_physical_wal_reference.rs"


class SqlitePhysicalWalObservationTests(unittest.TestCase):
    def test_original_owner_updates_length_and_blocks_without_rebinding(self):
        rows = []
        with tempfile.TemporaryDirectory(prefix="trnm-m15-physical-wal-") as here:
            owned = Path(here)
            actual = original_owner(owned,ADAPTER)
            for policy in (1,2):
                root = owned/f"owner-{policy}"
                root.mkdir(mode=0o700)
                data = execute([actual,root,str(policy)],timeout=30).stdout
                self.assertEqual(len(data),552)
                body,out = data[:440],data[440:]
                self.assertEqual(struct.unpack_from("<Q",body)[0],policy)
                fields = struct.unpack("<14Q",out)
                self.assertLess(fields[3],fields[4])
                self.assertLess(fields[4],fields[5])
                if policy==2:
                    self.assertEqual(fields[9:13],(65536,65536,65536,0))
                else:
                    self.assertEqual(fields[9:12],fields[3:6])
                    self.assertGreater(fields[12],0)
                self.assertGreater(fields[13],0)
                rows.append((body,out))
        body = rows[1][0]
        def at(phase,field):
            return 8+144*phase+8*field
        def reject(phase,field,value):
            i=at(phase,field)
            return body[:i]+struct.pack("<Q",value)+body[i+8:]
        def get(phase,field):
            return struct.unpack_from("<Q",body,at(phase,field))[0]
        malformed = [(body[:-1],112,100),(body+b"x",112,100),
                     (struct.pack("<Q",3)+body[8:],112,100),(body,111,102)]
        for phase,field,value in (
            (1,1,get(1,1)+1),(1,2,get(1,2)+1),(1,3,get(1,3)+1),(1,4,get(1,4)+1),
            (1,9,get(1,9)+1),(1,10,get(1,10)+1),(1,11,65535),
            (1,12,1025),(1,13,257),(1,14,get(0,14)),(1,15,2),
            (2,16,get(2,16)+1),(2,17,0),
        ):
            malformed.append((reject(phase,field,value),112,100))
        # Even a self-consistent named/receipt length pair must not go backwards.
        width = get(0,5)
        reverse = bytearray(reject(1,5,width))
        struct.pack_into("<Q",reverse,at(1,9),width)
        malformed.append((bytes(reverse),112,100))
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as n:
                cases = [([raw,b"\x82"*(112+pad),b"\x41"*17],want)
                         for raw,want in rows for pad in (0,7)]
                replies = n.call_many([("f0",a) for a,_ in cases])
                for (a,want),result in zip(cases,replies,strict=True):
                    self.assertEqual((result.require_returned().value,result.arguments),
                                     (0,[a[0],want+a[1][112:],a[2]]))
                bad = [[raw,b"\x38"*size,b"\x92"*8] for raw,size,_ in malformed]
                for a,(_,_,status),result in zip(bad,malformed,n.call_many([("f0",v) for v in bad]),strict=True):
                    self.assertEqual((result.require_returned().value,result.arguments),(status,a))
