"""Original disposable archive owner cold read versus bounded native seal-chain readback."""
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

SOURCE = ROOT / "hia/src/task_kernel/archive_store_seal_chain.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_store_seal_chain_reference.rs"
ARCHIVE_STORE_SHA256 = "b836e92e336b044c837b4b3a0857d421f65cec6cf712cf060823a33b5b581615"


def read_snapshot(path):
    """Mechanical SQLite snapshot only; no acceptance or synthesized seal digest."""
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as conn, conn:
        conn.execute("BEGIN DEFERRED")
        meta = conn.execute("SELECT generation,last_batch_sequence,last_seal_hash,live_root "
                            "FROM task_archive_metadata_v1 WHERE singleton=1").fetchone()
        rows = conn.execute("SELECT batch_sequence,generation,seal_hash,live_root_before,"
                            "live_root_after,seal FROM task_archive_seals_v1 ORDER BY batch_sequence").fetchall()
        return meta, rows


def packet(meta, rows):
    g, q, tail, live = meta
    pieces = [struct.pack("<Qqq32s32s",len(rows),g,q,tail,live)]
    for sequence, generation, digest, before, after, body in rows:
        context, = struct.unpack_from("<I",body,34)
        end = 294 + context
        # The captured prefix is unchanged from SQLite's original whole Batch bytes.
        pieces += [struct.pack("<Qqq32s32s32s",end,sequence,generation,digest,before,after),body[:end]]
    return b"".join(pieces)


class TaskArchiveStoreSealChainTests(unittest.TestCase):
    def test_original_cold_store_held_sqlite_seal_chain_and_terminal_identity(self):
        self.assertEqual(sha256((CRATE/"src/archive_store.rs").read_bytes()).hexdigest(),ARCHIVE_STORE_SHA256)
        with tempfile.TemporaryDirectory(prefix="m10-store-seal-chain-") as directory:
            root = Path(directory)
            oracle = original(root, REFERENCE)
            execute([oracle,"create",root])
            cases = []
            for n in (0, 1, 2, 8):
                db = root/f"chain-{n}.sqlite"
                meta, rows = read_snapshot(db)
                raw = execute([oracle, "read", db, str(n)]).stdout
                self.assertEqual(struct.unpack_from("<I",raw)[0],0)
                self.assertEqual(raw[4:36],meta[3])
                cursor = 36
                for row in rows:
                    width, body = struct.unpack_from("<II",raw,cursor)
                    self.assertEqual(raw[cursor+8:cursor+40],row[2])
                    self.assertEqual(raw[cursor+40:cursor+40+body],row[-1])
                    self.assertEqual(width, 806)
                    cursor += 40+body
                self.assertEqual(cursor,len(raw))
                inp = packet(meta,rows)
                cases.append((inp, 0, inp[8:88]))
            self.assertEqual(len(cases[-1][0]),7496)

            # Corruption/refusal checks only in independent disposable local copies.
            mutations = (
                ("UPDATE task_archive_seals_v1 SET generation=9 WHERE batch_sequence=2", ()),
                ("UPDATE task_archive_seals_v1 SET seal_hash=? WHERE batch_sequence=2",(b"M"*32,)),
                ("UPDATE task_archive_seals_v1 SET live_root_before=? WHERE batch_sequence=2",(b"R"*32,)),
                ("UPDATE task_archive_seals_v1 SET live_root_after=? WHERE batch_sequence=1",(bytes(32),)),
                ("UPDATE task_archive_metadata_v1 SET last_batch_sequence=1",()),
                ("UPDATE task_archive_metadata_v1 SET last_seal_hash=?",(b"T"*32,)),
                ("UPDATE task_archive_metadata_v1 SET generation=5",()),
            )
            original_rows = read_snapshot(root/"chain-2.sqlite")[1]
            altered = execute([oracle,"wrong-link"],input=original_rows[1][-1]).stdout
            mutations += (("UPDATE task_archive_seals_v1 SET seal_hash=?,seal=? WHERE batch_sequence=2",
                           (altered[:32],altered[32:])),)
            for i,(sql,params) in enumerate(mutations):
                db = root/f"case-{i}.sqlite"
                shutil.copyfile(root/"chain-2.sqlite", db)
                with closing(sqlite3.connect(db)) as conn, conn:
                    conn.execute(sql, params)
                inp = packet(*read_snapshot(db))
                code, = struct.unpack("<I", execute([oracle,"read",db,"2"]).stdout)
                self.assertEqual(code,23)
                cases.append((inp,code,b""))

        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                requests = [[inp,b"X"*88,b"Y"*1272] for inp,_,_ in cases]
                for (inp,code,identity),args,reply in zip(cases,requests,native.call_many([("f0",x) for x in requests]),strict=True):
                    got = reply.require_returned()
                    expected = identity + args[1][len(identity):]
                    self.assertEqual((got.value,got.arguments[:2]),(code,[inp,expected]))
                    self.assertEqual(got.arguments[2][1264:],args[2][1264:])
                one = cases[1][0]
                for inp,out_size,scratch,code in ((one[:-1],80,1264,100),(one+b"\0",80,1264,100),
                                                   (one,79,1264,102),(one,80,1263,102)):
                    args = [inp,b"X"*out_size,b"Y"*scratch]
                    got = native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(code,args[:2]))
                    if code == 102:
                        self.assertEqual(got.arguments[2],args[2])
