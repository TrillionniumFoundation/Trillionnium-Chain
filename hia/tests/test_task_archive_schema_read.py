"""Actual closed original archive schema and metadata read using the pinned provider."""
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import CRATE, ROOT, original
from hia.tests.test_task_archive_store_seal_chain import ARCHIVE_STORE_SHA256, REFERENCE

PLATFORM = ROOT/"hia/platform/task_kernel"
SOURCE = PLATFORM/"archive_schema_read.hepta"


def metadata(path):
    with closing(sqlite3.connect(path.as_uri()+"?mode=ro",uri=True)) as c:
        v = c.execute("SELECT schema_version,generation,last_batch_sequence,last_seal_hash,live_root,policy_hash "
                      "FROM task_archive_metadata_v1 WHERE singleton=1").fetchone()
    return "".join(f"{x:016X}" for x in v[:3])+b"".join(v[3:]).hex().upper()


class TaskArchiveSchemaReadTests(unittest.TestCase):
    def test_actual_original_archive_closed_schema_and_native_metadata_capture(self):
        self.assertEqual(sha256((CRATE/"src/archive_store.rs").read_bytes()).hexdigest(),ARCHIVE_STORE_SHA256)
        with tempfile.TemporaryDirectory(prefix="m10-archive-schema-") as temporary:
            root = Path(temporary).resolve()
            owned = root/"owned"
            owned.mkdir(mode=0o700)
            ref = original(root,REFERENCE)
            execute([ref,"create-inventory",owned])
            expected_policy = execute([ref,"policy-hash"]).stdout
            cargo = Path(os.environ.get("CARGO_HOME",Path.home()/".cargo"))
            [dependency] = sorted(cargo.glob("registry/src/*/libsqlite3-sys-0.39.1"))
            provider = ProviderBuild(dependency,root/"provider").run()
            provenance = Reader()
            check_provider(provenance.read,provider.parent,ROOT)
            p = [str(provider),provenance.checked[str(provider)]["sha256"]]
            cases = [(owned/x,0,n) for x,n in (("inventory-empty.sqlite",0),("chain-2.sqlite",2),("inventory-full.sqlite",8))]
            baseline = owned/"inventory-empty.sqlite"
            changes = [
                (0,("DROP TABLE task_archive_legal_holds_v1",
                    "cReAtE\nTABLE\ttask_archive_legal_holds_v1 ( task_id BLOB PRIMARY KEY CHECK (length(task_id) = 32) ) WITHOUT\nROWID")),
                (22,("CREATE TABLE archive_test_extraneous (id INTEGER)",)),
                (22,("DROP TABLE task_archive_legal_holds_v1",
                     "CREATE TABLE task_archive_legal_holds_v1 (task_id BLOB PRIMARY KEY, note TEXT) WITHOUT ROWID")),
                (22,("PRAGMA user_version=3",)),
                (22,("PRAGMA application_id=0",)),
                (22,("UPDATE task_archive_metadata_v1 SET policy_hash=zeroblob(32)",)),
                (22,("UPDATE task_archive_metadata_v1 SET schema_version=2",)),
            ]
            for i,(status,sql) in enumerate(changes):
                copy = owned/f"case-{i}.sqlite"
                shutil.copyfile(baseline,copy)
                with closing(sqlite3.connect(copy)) as c, c:
                    for sentence in sql:
                        c.execute(sentence).fetchall()
                cases.append((copy,status,0))
            expected = []
            for db,status,count in cases:
                captured = execute([ref,"read",db,str(count)]).stdout
                self.assertEqual(int.from_bytes(captured[:4],"little"),status,db.name)
                if status==0:
                    projection = metadata(db)
                    self.assertEqual(bytes.fromhex(projection[112:176]),captured[4:36])
                else:
                    projection = None
                expected.append(projection)

            for backend in ("direct","selfhost"):
                with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native:
                    for (db,status,_),projection in zip(cases,expected,strict=True):
                        with self.subTest(db=db.name):
                            before = db.read_bytes()
                            listing = sorted(x.name for x in owned.iterdir())
                            msg = {"reader":[str(native.library),native.artifact_sha256],"provider":p,
                                   "directory":str(owned),"db":str(db),"expected":expected_policy.hex()}
                            child = subprocess.run([sys.executable,"-I","-S","-B",
                                                    str(PLATFORM/"archive_schema_fixture_host.py")],
                                                   input=json.dumps(msg),capture_output=True,text=True,timeout=30)
                            self.assertEqual((child.returncode,child.stderr),(0,""))
                            got = json.loads(child.stdout)
                            self.assertEqual((got["status"],got["result"]),(status,projection))
                            self.assertEqual(got["transcript"][0],[1,2,24])
                            if status==0:
                                self.assertEqual((got["transcript"][-1],got["released"]),([160,3,24],0))
                            else:
                                self.assertGreater(got["released"],0)
                            self.assertEqual(db.read_bytes(),before)
                            self.assertEqual(sorted(x.name for x in owned.iterdir()),listing)
