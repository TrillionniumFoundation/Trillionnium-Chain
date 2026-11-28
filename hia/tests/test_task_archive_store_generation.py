"""Full original persisted batch and independently reacquired SQL rows, no writes by HIA."""
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import shutil
import sqlite3
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import CRATE, ROOT, original
from hia.tests.test_task_archive_store_inventory import inventory_packet, SOURCE as INVENTORY
from hia.tests.test_task_archive_store_seal_chain import (
    ARCHIVE_STORE_SHA256, REFERENCE, SOURCE as RELATIONAL,
    packet as link_packet, read_snapshot as read_links,
)

SOURCE = ROOT / "hia/src/task_kernel/archive_store_generation.hepta"


def generation_packets(db, policy):
    """Capture all generations and acquired records in a single read-only SQLite transaction."""
    with closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True)) as conn, conn:
        conn.execute("BEGIN DEFERRED")
        seals = conn.execute("SELECT batch_sequence,seal_hash,seal FROM task_archive_seals_v1 "
                             "ORDER BY batch_sequence").fetchall()
        rows = conn.execute("SELECT batch_sequence,task_id,record_hash,record "
                            "FROM task_archive_records_v1 ORDER BY batch_sequence,task_id DESC").fetchall()
    result = []
    for sequence, digest, batch in seals:
        acquired = [(key, h, body) for seq, key, h, body in rows if seq==sequence]
        context, = struct.unpack_from("<I",batch,34)
        seal_len = context+294
        initial = struct.pack("<QQ",len(policy),seal_len)+policy+batch
        footer = struct.pack("<QQ32s",sequence,len(acquired),digest)
        packed = b"".join(struct.pack("<Q32s32s",len(body),key,h)+body
                          for key,h,body in acquired)
        result.append((initial+footer+packed, batch, len(acquired)))
    return result


class TaskArchiveStoreGenerationTests(unittest.TestCase):
    def test_actual_full_generation_sorted_reacquisition_and_exact_stored_batch(self):
        self.assertEqual(sha256((CRATE/"src/archive_store.rs").read_bytes()).hexdigest(),ARCHIVE_STORE_SHA256)
        with tempfile.TemporaryDirectory(prefix="m10-store-generation-") as directory:
            root = Path(directory)
            oracle = original(root,REFERENCE)
            execute([oracle,"create-inventory",root])
            policy = execute([oracle,"policy"]).stdout
            cases = []
            for name,n in (("chain-1",1),("chain-2",2),("chain-8",8),("inventory-full",8),("inventory-wide",1)):
                db = root/f"{name}.sqlite"
                actual = generation_packets(db,policy)
                raw = execute([oracle,"read",db,str(n)]).stdout
                self.assertEqual(raw[:4],bytes(4))
                at = 36
                self.assertEqual(len(actual),n)
                for packet,batch,_ in actual:
                    _, body_n = struct.unpack_from("<II",raw,at)
                    body = raw[at+40:at+40+body_n]
                    self.assertEqual(batch,body)
                    cases.append((packet,0,struct.pack("<Q",body_n)+body))
                    at += 40+body_n
                self.assertEqual(len(raw),at)
            self.assertEqual(len(cases),20)
            self.assertEqual((len(cases[-1][0]),len(cases[-1][2])),(14268,6914))

            db = root/"chain-2.sqlite"
            original_capture = generation_packets(db,policy)
            changed = execute([oracle,"changed-batch"],input=original_capture[1][1]).stdout
            with closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True)) as c:
                body, = c.execute("SELECT record FROM task_archive_records_v1 WHERE batch_sequence=2").fetchone()
            new_row = execute([oracle,"changed-row"],input=body).stdout
            bad_batch = [
                ("UPDATE task_archive_seals_v1 SET seal=? WHERE batch_sequence=2",(changed,),23),
                ("UPDATE task_archive_records_v1 SET record_hash=?,record=? WHERE batch_sequence=2",
                  (new_row[:32],new_row[32:]),13),
                ("UPDATE task_archive_records_v1 SET task_id=? WHERE batch_sequence=2",(b"K"*32,),23),
                ("UPDATE task_archive_records_v1 SET record_hash=? WHERE batch_sequence=2",(b"H"*32,),23),
                ("DELETE FROM task_archive_records_v1 WHERE batch_sequence=2",(),1),
                ("INSERT INTO task_archive_records_v1 SELECT 2,task_id,record,record_hash "
                 "FROM task_archive_records_v1 WHERE batch_sequence=1",(),13),
                ("UPDATE task_archive_seals_v1 SET seal_hash=? WHERE batch_sequence=2",(b"S"*32,),23),
                ("UPDATE task_archive_records_v1 SET record=? WHERE batch_sequence=2",(body+b"\0",),2),
            ]
            for i,(stmt,args,code) in enumerate(bad_batch):
                copy = root/f"mismatch-{i}.sqlite"
                shutil.copyfile(db,copy)
                with closing(sqlite3.connect(copy)) as conn, conn:
                    conn.execute(stmt,args)
                original_rc, = struct.unpack("<I",execute([oracle,"read",copy,"2"]).stdout)
                self.assertEqual(original_rc,code)
                acquired = generation_packets(copy,policy)
                self.assertEqual(acquired[0],original_capture[0])
                cases.append((acquired[1][0],code,b""))
                if i == 0:
                    relational_clean = link_packet(*read_links(copy))
                    inventory_clean = inventory_packet(copy)

        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native:
                args = [[inp,b"X"*6922,b"Y"*1808] for inp,_,_ in cases]
                calls = native.call_many([("f0",a) for a in args])
                for i,((inp,code,output),a,reply) in enumerate(zip(cases,args,calls,strict=True)):
                    with self.subTest(case=i):
                        got = reply.require_returned()
                        self.assertEqual((got.value,got.arguments[:2]),(code,[inp,output+a[1][len(output):]]))
                        self.assertEqual(got.arguments[2][1800:],a[2][1800:])
                one = cases[0][0]
                for inp,out,scratch,code in ((one[:-1],6914,1800,2),(one+b"\0",6914,1800,100),
                                             (one,6913,1800,102),(one,6914,1799,102)):
                    a = [inp,b"X"*out,b"Y"*scratch]
                    got = native.call("f0",a).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(code,a[:2]))
                    if code == 102:
                        self.assertEqual(got.arguments[2],a[2])
            for source,inp,n,s in ((RELATIONAL,relational_clean,80,1264),(INVENTORY,inventory_clean,32,1488)):
                with NativeModule(source,byte_exports=("f0",),backend=backend) as previous:
                    self.assertEqual(previous.call("f0",[inp,b"X"*n,b"Y"*s]).require_returned().value,0)
