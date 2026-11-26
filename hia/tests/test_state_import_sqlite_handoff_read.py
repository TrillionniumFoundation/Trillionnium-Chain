"""Native held SQLite read of two real, original M13 handoff revisions."""
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, _build_original, _run
from hia.tests.test_state_import_sqlite_cold_read import OWNER, ROOT

ADAPTER = ROOT / "hia/tests/rust_state_import_handoff_read_reference.rs"


def retained_fixture(raw):
    """Select exact original cfg(test) code, not a replacement policy."""
    start = raw.index(b"#[cfg(test)]\nmod tests {")
    tests = raw[start:]
    pieces = (
        (b"    fn d(byte: u8)", b"    struct WeightOne;"),
        (b"    fn row(byte: u8)", b"\n    }\n"),
        (b"    fn verified_fixture()", b"\n    }\n"),
    )
    extracted = []
    for first, last in pieces:
        at = tests.index(first)
        end = tests.index(last, at)
        if last.startswith(b"\n"):
            end += len(last)
        extracted.append(tests[at:end])
    return b"use trnm_state_import::*;\nuse std::convert::Infallible;\nuse std::io::Write;\nuse sha2::{Digest, Sha256};\n" + b"\n".join(extracted)


def actual_raw(path):
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        [(revision, digest, record)] = connection.execute(
            "SELECT revision, record_digest, record FROM migration_handoff_record_v0")
    return struct.pack(">Q", revision) + digest + record


def alter(path, sql, *bindings):
    with sqlite3.connect(path) as connection:
        connection.execute(sql, bindings)


class StateImportSqliteHandoffRead(unittest.TestCase):
    def test_actual_original_handoff_revisions_and_held_wal_snapshot(self):
        source = CRATE / "src/lib.rs"
        source_before = hashlib.sha256(source.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-handoff-") as tmp, NativeModule(
            OWNER / "handoff_read.hepta", byte_exports=("f0",), backend="selfhost"
        ) as native:
            directory = Path(tmp).resolve()
            adapter = directory / "original-handoff.rs"
            adapter.write_bytes(retained_fixture(source.read_bytes()) + ADAPTER.read_bytes())
            original, dependency = _build_original(directory, adapter, ("sha2",))
            provider = ProviderBuild(dependency, directory / "provider").run()
            provenance = Reader()
            check_provider(provenance.read, provider.parent, ROOT)
            provider_digest = provenance.checked[str(provider)]["sha256"]
            owned = directory / "owned"
            owned.mkdir(mode=0o700)

            def initialize(name):
                db = owned / (name + ".db")
                _run([original, "init", db])
                return db

            def read_original(db):
                observation = _run([original, "read", db]).stdout
                data = actual_raw(db)
                self.assertEqual((observation, len(data)), (data[:40], 423))
                self.assertEqual(data[8:40], data[-32:])
                return data

            def invoke(db, *, advance=False):
                msg = {
                    "reader": [str(native.library), native.artifact_sha256],
                    "provider": [str(provider), provider_digest],
                    "directory": str(owned), "database": str(db), "handoff": True,
                    "advance": str(original) if advance else None,
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(msg), capture_output=True, text=True, check=False, timeout=55,
                )
                self.assertEqual((child.returncode, child.stderr), (0, ""))
                return json.loads(child.stdout)

            db = initialize("handoff")
            old = read_original(db)
            self.assertEqual((old[:8], old[46]), (bytes(8), 1))
            first = invoke(db)
            self.assertEqual((first["status"], first["result"], first["released"]), (0, old.hex(), 0))
            self.assertEqual(first["transcript"][-1], [18, 3, 24])
            self.assertEqual(read_original(db), old)
            held = invoke(db, advance=True)
            self.assertEqual((held["status"], held["result"], held["advanced"], held["released"]),
                             (0, old.hex(), True, 0))
            new = read_original(db)
            self.assertEqual((new[:8], new[46]), (bytes(7) + b"\1", 2))
            self.assertNotEqual(old[8:40], new[8:40])
            cold = invoke(db)
            self.assertEqual((cold["status"], cold["result"], cold["released"]), (0, new.hex(), 0))
            self.assertEqual(cold["transcript"][-1], [18, 3, 24])
            self.assertNotIn(6, [row[1] for row in cold["transcript"]])

            for name, sql, bindings in (
                ("column-revision", "UPDATE migration_handoff_record_v0 SET revision=4", ()),
                ("column-digest", "UPDATE migration_handoff_record_v0 SET record_digest=zeroblob(32)", ()),
                ("wrong-version", "PRAGMA user_version=2", ()),
                ("wrong-type", "PRAGMA application_id=0", ()),
                ("extra-db-object", "CREATE TABLE unrelated(x INTEGER) STRICT", ()),
                ("wrong-record", "UPDATE migration_handoff_record_v0 SET record=?",
                 (old[40:61] + bytes((old[61] ^ 128,)) + old[62:],)),
                ("trailing-record", "UPDATE migration_handoff_record_v0 SET record=?", (old[40:] + b"\0",)),
                ("missing-row", "DELETE FROM migration_handoff_record_v0", ()),
            ):
                with self.subTest(name=name):
                    bad = initialize(name)
                    alter(bad, sql, *bindings)
                    original_refusal = subprocess.run([original, "read", bad], capture_output=True, timeout=15)
                    self.assertNotEqual(original_refusal.returncode, 0)
                    self.assertEqual(original_refusal.stdout, b"")
                    denied = invoke(bad)
                    self.assertEqual((denied["status"], denied["result"], denied["released"]), (100, None, 2))  # reset reclaimed the statement and connection
                    self.assertNotIn([18, 3, 24], denied["transcript"])
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), source_before)
