"""Native fixed SQL acquires the exact whole held audit packet before opaque reborrow."""
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
from hia.tests.test_task_archive_schema_read import PLATFORM
from hia.tests.test_task_archive_store_audit import SOURCE as AUDIT_SOURCE, held_packet
from hia.tests.test_task_archive_store_seal_chain import ARCHIVE_STORE_SHA256, REFERENCE

SOURCE = PLATFORM/"archive_snapshot_read.hepta"


class TaskArchiveSnapshotReadTests(unittest.TestCase):
    def test_actual_original_single_held_provider_acquisition_and_native_archive_audit(self):
        self.assertEqual(sha256((CRATE/"src/archive_store.rs").read_bytes()).hexdigest(),ARCHIVE_STORE_SHA256)
        with tempfile.TemporaryDirectory(prefix="m10-archive-schema-snapshot-") as temporary:
            root = Path(temporary).resolve()
            owned = root/"owned"
            owned.mkdir(mode=0o700)
            ref = original(root,REFERENCE)
            execute([ref,"create-inventory",owned])
            expected_policy = execute([ref,"policy-hash"]).stdout
            policy = execute([ref,"policy"]).stdout
            cargo = Path(os.environ.get("CARGO_HOME",Path.home()/".cargo"))
            [dependency] = sorted(cargo.glob("registry/src/*/libsqlite3-sys-0.39.1"))
            provider = ProviderBuild(dependency,root/"provider").run()
            provenance = Reader()
            check_provider(provenance.read,provider.parent,ROOT)
            p = [str(provider),provenance.checked[str(provider)]["sha256"]]
            cases = [(owned/x,0,n) for x,n in (("inventory-empty.sqlite",0),("chain-0.sqlite",0),
                                              ("chain-2.sqlite",2),("inventory-full.sqlite",8),
                                              ("inventory-wide.sqlite",1))]
            baseline = owned/"chain-2.sqlite"
            with closing(sqlite3.connect(baseline.as_uri()+"?mode=ro",uri=True)) as conn:
                batch, = conn.execute("SELECT seal FROM task_archive_seals_v1 WHERE batch_sequence=2").fetchone()
                row, = conn.execute("SELECT record FROM task_archive_records_v1 WHERE batch_sequence=2").fetchone()
            changed = execute([ref,"changed-batch"],input=batch).stdout
            revised = execute([ref,"changed-row"],input=row).stdout
            controls = (
                (23,("UPDATE task_archive_seals_v1 SET seal=? WHERE batch_sequence=2",(changed,))),
                (13,("UPDATE task_archive_records_v1 SET record=?,record_hash=? WHERE batch_sequence=2",
                     (revised[32:],revised[:32]))),
                (1,("DELETE FROM task_archive_records_v1 WHERE batch_sequence=2",())),
                (23,("UPDATE task_archive_seals_v1 SET live_root_before=zeroblob(32) WHERE batch_sequence=2",())),
            )
            for i,(status,(sql,args)) in enumerate(controls):
                db = owned/f"negative-{i}.sqlite"
                shutil.copyfile(baseline,db)
                with closing(sqlite3.connect(db)) as conn, conn:
                    conn.execute(sql,args)
                cases.append((db,status,2))
            original_observations = []
            for db,status,count in cases:
                raw = execute([ref,"read",db,str(count)]).stdout
                self.assertEqual(int.from_bytes(raw[:4],"little"),status)
                packet = held_packet(db,policy)  # independent reference only; never input to native capture
                original_observations.append((raw[4:36].hex() if not status else None,
                                              len(packet),sha256(packet).hexdigest()))
            for backend in ("direct","selfhost"):
                with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native,                         NativeModule(AUDIT_SOURCE,byte_exports=("f0",),backend=backend) as audit:
                    for (db,status,_),(native_root,size,digest) in zip(cases,original_observations,strict=True):
                        with self.subTest(db=db.name):
                            before = db.read_bytes()
                            listing = sorted(x.name for x in owned.iterdir())
                            msg = {"reader":[str(native.library),native.artifact_sha256],
                                   "audit":[str(audit.library),audit.artifact_sha256],
                                   "provider":p,"directory":str(owned),"db":str(db),
                                   "expected":expected_policy.hex(),"policy":policy.hex()}
                            child = subprocess.run([sys.executable,"-I","-S","-B",
                                                    str(PLATFORM/"archive_schema_fixture_host.py")],
                                                   input=json.dumps(msg),capture_output=True,text=True,timeout=30)
                            self.assertEqual((child.returncode,child.stderr),(0,""))
                            got = json.loads(child.stdout)
                            self.assertEqual((got["status"],got["result"]),(status,native_root))
                            self.assertEqual((got["capture_length"],got["capture_sha256"]),(size,digest))
                            self.assertEqual(got["transcript"][0],[1,2,24])
                            self.assertEqual(got["transcript"][-1],[160,3,24])
                            self.assertEqual(got["released"],0)
                            self.assertEqual(db.read_bytes(),before)
                            self.assertEqual(sorted(x.name for x in owned.iterdir()),listing)
