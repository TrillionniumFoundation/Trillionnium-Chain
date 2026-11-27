"""Complete bounded persisted inventory reconstruction versus immutable Rust store audit."""
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
from hia.tests.test_task_archive_store_seal_chain import (
    ARCHIVE_STORE_SHA256, REFERENCE, SOURCE as LINK_SOURCE,
    packet as link_packet, read_snapshot as read_links,
)

SOURCE = ROOT / "hia/src/task_kernel/archive_store_inventory.hepta"


def inventory_packet(db):
    """Capture column bytes and membership from one held read-only SQLite snapshot."""
    with closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True)) as conn, conn:
        conn.execute("BEGIN DEFERRED")
        generation, live = conn.execute(
            "SELECT generation,live_root FROM task_archive_metadata_v1 WHERE singleton=1").fetchone()
        links = conn.execute(
            "SELECT live_root_before,live_root_after FROM task_archive_seals_v1 ORDER BY batch_sequence").fetchall()
        rows = conn.execute(
            "SELECT 0,task_id,record_hash,record FROM task_archive_live_records_v1 "
            "UNION ALL SELECT batch_sequence,task_id,record_hash,record FROM task_archive_records_v1 "
            "ORDER BY 1 DESC,2 DESC").fetchall()
    if generation != len(links):
        raise ValueError("fixture profile requires a complete chronological journal capture")
    return (struct.pack("<QQ32s",len(rows),generation,live)
            + b"".join(a+b for a,b in links)
            + b"".join(struct.pack("<QQ32s32s",group,len(body),key,digest)+body
                       for group,key,digest,body in rows))


class TaskArchiveStoreInventoryTests(unittest.TestCase):
    def test_original_live_inventory_and_every_historical_membership_root(self):
        self.assertEqual(sha256((CRATE/"src/archive_store.rs").read_bytes()).hexdigest(),ARCHIVE_STORE_SHA256)
        with tempfile.TemporaryDirectory(prefix="m10-store-inventory-") as directory:
            root = Path(directory)
            oracle = original(root,REFERENCE)
            execute([oracle,"create-inventory",root])
            cases = []
            for name, n in (("inventory-empty",0),("chain-0",0),("chain-1",1),("chain-2",2),
                            ("chain-8",8),("inventory-full",8)):
                db = root/f"{name}.sqlite"
                packet = inventory_packet(db)
                observed = execute([oracle,"read",db,str(n)]).stdout
                self.assertEqual(int.from_bytes(observed[:4],"little"),0)
                self.assertEqual(observed[4:36],packet[16:48])
                cases.append((packet,0,observed[4:36]))
            self.assertEqual(len(cases[-1][0]),14032)

            false_link = b"V"*32
            controls = (
                (("UPDATE task_archive_seals_v1 SET live_root_before=? WHERE batch_sequence=1",
                  (false_link,)),),
                (("UPDATE task_archive_seals_v1 SET live_root_after=? WHERE batch_sequence=1",(false_link,)),
                 ("UPDATE task_archive_seals_v1 SET live_root_before=? WHERE batch_sequence=2",(false_link,))),
                (("UPDATE task_archive_metadata_v1 SET live_root=?",(false_link,)),
                 ("UPDATE task_archive_seals_v1 SET live_root_after=? WHERE batch_sequence=2",(false_link,))),
                (("UPDATE task_archive_live_records_v1 SET record_hash=?",(false_link,)),),
                (("UPDATE task_archive_records_v1 SET record_hash=? WHERE batch_sequence=2",(false_link,)),),
                (("UPDATE task_archive_records_v1 SET task_id=? WHERE batch_sequence=1",(false_link,)),),
                (("DELETE FROM task_archive_records_v1 WHERE batch_sequence=2",()),),
                (("INSERT INTO task_archive_records_v1 "
                   "SELECT 2,task_id,record,record_hash FROM task_archive_records_v1 WHERE batch_sequence=1",()),),
            )
            relational_only = []
            for i, stmts in enumerate(controls):
                db = root/f"control-{i}.sqlite"
                shutil.copyfile(root/"chain-2.sqlite",db)
                with closing(sqlite3.connect(db)) as conn, conn:
                    for stmt,args in stmts:
                        conn.execute(stmt,args)
                rc, = struct.unpack("<I",execute([oracle,"read",db,"2"]).stdout)
                self.assertEqual(rc,{6:1,7:13}.get(i,23))
                # Original full audit's zero archived-row error is its batch-count
                # InvalidBounds (extra row: InvalidState); inventory reports bad membership.
                cases.append((inventory_packet(db),23,b""))
                if i<3:
                    relational_only.append(link_packet(*read_links(db)))

        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),backend=backend) as native:
                requests = [[inp,b"X"*40,b"Y"*1496] for inp,_,_ in cases]
                for (inp,code,digest),args,reply in zip(cases,requests,native.call_many([("f0",a) for a in requests]),strict=True):
                    got = reply.require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(code,[inp,digest+args[1][len(digest):]]))
                    self.assertEqual(got.arguments[2][1488:],args[2][1488:])
                one = cases[2][0]
                for inp, osize, scratch, code in ((one[:-1],32,1488,100),(one+b"\0",32,1488,100),
                                                  (one,31,1488,102),(one,32,1487,102)):
                    args = [inp,b"X"*osize,b"Y"*scratch]
                    got = native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(code,args[:2]))
                    if code == 102:
                        self.assertEqual(got.arguments[2],args[2])
            with self.subTest(backend=backend), NativeModule(LINK_SOURCE,byte_exports=("f0",),backend=backend) as previous:
                for raw in relational_only:
                    got = previous.call("f0",[raw,b"X"*80,b"Y"*1264]).require_returned()
                    self.assertEqual(got.value,0)
