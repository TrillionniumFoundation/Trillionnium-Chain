"""One native audit of all typed data captured from an original held SQLite snapshot."""
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
from hia.tests.test_task_archive_store_seal_chain import ARCHIVE_STORE_SHA256, REFERENCE

SOURCE = ROOT / "hia/src/task_kernel/archive_store_audit.hepta"


def held_packet(db, policy):
    """Transport exact column bytes, not a pre-admitted batch, seal, or inventory."""
    with closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True)) as conn, conn:
        conn.execute("BEGIN DEFERRED")
        columns = conn.execute(
            "SELECT schema_version,generation,last_batch_sequence,last_seal_hash,live_root,policy_hash "
            "FROM task_archive_metadata_v1 WHERE singleton=1").fetchone()
        live = conn.execute("SELECT task_id,record_hash,record FROM task_archive_live_records_v1 "
                            "ORDER BY task_id").fetchall()
        seals = conn.execute("SELECT batch_sequence,generation,live_root_before,live_root_after,seal_hash,seal "
                             "FROM task_archive_seals_v1 ORDER BY batch_sequence").fetchall()
        rows = conn.execute("SELECT batch_sequence,task_id,record_hash,record FROM task_archive_records_v1 "
                            "ORDER BY batch_sequence,task_id DESC").fetchall()
    def packed(rows):
        return b"".join(struct.pack("<Q32s32s",len(record),key,digest)+record
                        for key,digest,record in rows)
    frames = [struct.pack("<QQ",len(policy),len(seals)),policy,
              struct.pack("<qqq32s32s32sQ",*columns,len(live)),packed(live)]
    for seq,g,before,after,digest,batch in seals:
        seal_size = 294+struct.unpack_from("<I",batch,34)[0]
        cohort = [(key,h,record) for group,key,h,record in rows if group==seq]
        body = batch+struct.pack("<qQ32s",seq,len(cohort),digest)+packed(cohort)
        frames.extend((struct.pack("<QQq32s32s",88+len(body),seal_size,g,before,after),body))
    return b"".join(frames)


class TaskArchiveStoreAuditTests(unittest.TestCase):
    def test_original_held_archive_audit_and_first_failures(self):
        self.assertEqual(sha256((CRATE/"src/archive_store.rs").read_bytes()).hexdigest(),ARCHIVE_STORE_SHA256)
        with tempfile.TemporaryDirectory(prefix="m10-store-audit-") as directory:
            root = Path(directory)
            oracle = original(root,REFERENCE)
            execute([oracle,"create-inventory",root])
            policy = execute([oracle,"policy"]).stdout
            cases = []
            for name,n in (("inventory-empty",0),("chain-0",0),("chain-1",1),("chain-2",2),
                           ("chain-8",8),("inventory-full",8),("inventory-wide",1)):
                db = root/f"{name}.sqlite"
                verdict = execute([oracle,"read",db,str(n)]).stdout
                self.assertEqual(verdict[:4],bytes(4))
                packet = held_packet(db,policy)
                cases.append((packet,0,verdict[4:36]))

            baseline = root/"chain-2.sqlite"
            with closing(sqlite3.connect(baseline.as_uri()+"?mode=ro",uri=True)) as conn:
                archived, = conn.execute(
                    "SELECT record FROM task_archive_records_v1 WHERE batch_sequence=2").fetchone()
                batch, = conn.execute("SELECT seal FROM task_archive_seals_v1 WHERE batch_sequence=2").fetchone()
                active, = conn.execute("SELECT record FROM task_archive_live_records_v1").fetchone()
            revised = execute([oracle,"changed-row"],input=archived).stdout
            changed = execute([oracle,"changed-batch"],input=batch).stdout
            bad_digest = b"X"*32
            live_error = ("UPDATE task_archive_live_records_v1 SET record=?",(active+b"\0",))
            from_archive = ("UPDATE task_archive_records_v1 SET record=?,record_hash=? WHERE batch_sequence=2",
                            (revised[32:],revised[:32]))
            incompatible_root = ("UPDATE task_archive_seals_v1 SET live_root_after=? WHERE batch_sequence=1",
                                 (bad_digest,))
            checks = (
                (23,(("UPDATE task_archive_seals_v1 SET seal=? WHERE batch_sequence=2",(changed,)),)),
                (13,(from_archive,)),
                (1,(("DELETE FROM task_archive_records_v1 WHERE batch_sequence=2",()),)),
                (23,(("UPDATE task_archive_metadata_v1 SET last_seal_hash=?",(bad_digest,)),)),
                (22,(("UPDATE task_archive_metadata_v1 SET policy_hash=?",(bad_digest,)),from_archive)),
                (2,(live_error,from_archive)),
                (23,(incompatible_root,from_archive)),  # Chain predecessor first, before acquired row.
                (13,(("UPDATE task_archive_metadata_v1 SET last_seal_hash=?",(bad_digest,)),from_archive)),
                (23,(incompatible_root,("UPDATE task_archive_seals_v1 SET live_root_before=? "
                                        "WHERE batch_sequence=2",(bad_digest,)))),
            )
            for i,(expected,changes) in enumerate(checks):
                db = root/f"mismatch-{i}.sqlite"
                shutil.copyfile(baseline,db)
                with closing(sqlite3.connect(db)) as conn, conn:
                    for sql,args in changes:
                        conn.execute(sql,args)
                rc, = struct.unpack("<I",execute([oracle,"read",db,"2"]).stdout)
                self.assertEqual(rc,expected,i)
                cases.append((held_packet(db,policy),rc,b""))

        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native:
                args = [[p,b"X"*40,b"Y"*2408] for p,_,_ in cases]
                calls = native.call_many([("f0",a) for a in args])
                for i,((p,status,out),a,call) in enumerate(zip(cases,args,calls,strict=True)):
                    with self.subTest(case=i):
                        got = call.require_returned()
                        self.assertEqual((got.value,got.arguments[:2]),(status,[p,out+a[1][len(out):]]))
                        self.assertEqual(got.arguments[2][2400:],a[2][2400:])
                p = cases[3][0]
                for raw,o,w,rc in ((p[:-1],32,2400,100),(p+b"\0",32,2400,100),
                                   (p,31,2400,102),(p,32,2399,102)):
                    a = [raw,b"X"*o,b"Y"*w]
                    got = native.call("f0",a).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(rc,a[:2]))
                    if rc==102:
                        self.assertEqual(got.arguments[2],a[2])
