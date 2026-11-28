"""Original full-sized StateImport rows via bounded native SQLite reads."""
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
from hia.tests.test_state_import_snapshot_shadow import _build_original, _run
from hia.tests.test_state_import_sqlite_cold_read import EXPECTED, OWNER, ROOT, projection


class StateImportSqliteDigestScan(unittest.TestCase):
    def test_original_full_value_and_bounded_held_digest_only_read(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-digest-scan-") as tmp, NativeModule(
            OWNER / "digest_scan.hepta", byte_exports=("f0",), backend="selfhost",
        ) as native, NativeModule(OWNER / "cold_read.hepta", byte_exports=("f0",), backend="selfhost") as raw_native:
            directory = Path(tmp).resolve()
            original, dependency = _build_original(directory)
            provider = ProviderBuild(dependency, directory / "provider").run()
            verification = Reader()
            check_provider(verification.read, provider.parent, ROOT)
            provider_digest = verification.checked[str(provider)]["sha256"]
            owned = directory / "owned"
            owned.mkdir(mode=0o700)
            db = owned / "stream.db"
            _run([original, "seed-stream", db])

            def expected():
                data = _run([original, "read-digest", db], timeout=30).stdout
                self.assertEqual(len(data), 240)
                return projection(data + bytes(32))

            def invoke(image=native, advance=False):
                msg = {
                    "reader": [str(image.library), image.artifact_sha256],
                    "provider": [str(provider), provider_digest],
                    "directory": str(owned), "database": str(db),
                    "expected": EXPECTED,
                    "advance": str(original) if advance else None,
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(msg), capture_output=True, text=True, check=False, timeout=60,
                )
                self.assertEqual((child.returncode, child.stderr), (0, ""))
                return json.loads(child.stdout)

            first = expected()
            with sqlite3.connect(db) as query:
                dims = query.execute(
                    "SELECT length(value) FROM migration_delta_rows_v0 ORDER BY namespace,key"
                ).fetchall()
            self.assertEqual(dims, [(0,), (1,), (65535,), (65536,), (65537,), (1 << 24,)])
            got = invoke()
            self.assertEqual((got["status"], got["result"], got["released"]), (0, first, 0))
            self.assertEqual(len(got["result"]), 489)
            self.assertEqual(got["transcript"][-1], [18, 3, 24])
            columns = [n for p, op, n in got["transcript"] if (p, op) == (13, 8)]
            self.assertEqual(len(columns), 6 + 1 + 1 + 1 + 2 + 256)
            self.assertEqual(columns.count(65536 + 24), 258)
            self.assertLessEqual(max(columns), 65536 + 24)
            default = invoke(raw_native)
            self.assertEqual((default["status"], default["result"]), (100, None))

            held = invoke(advance=True)
            self.assertEqual((held["status"], held["result"], held["advanced"]), (0, first, True))
            second = expected()
            self.assertNotEqual(first, second)
            cold = invoke()
            self.assertEqual((cold["status"], cold["result"], len(cold["result"])), (0, second, 489))

            # The same real original DB is now corrupted in a disposable fixture.
            # The +1 row remains correctly typed, but the original bound refuses it.
            with sqlite3.connect(db) as change:
                [(old_value,)] = change.execute("SELECT value FROM migration_delta_rows_v0 WHERE key=X'0100FF'").fetchall()
                change.execute("UPDATE migration_delta_rows_v0 SET value=? WHERE key=X'0100FF'", (bytes((old_value[0] ^ 1,)),))
            corrupt = invoke()
            self.assertEqual((corrupt["status"], corrupt["result"], corrupt["transcript"][-1]), (100, None, [12, 7, 24]))
            rust_corrupt = subprocess.run([original, "read-digest", db], capture_output=True, timeout=30)
            self.assertNotEqual(rust_corrupt.returncode, 0)
            with sqlite3.connect(db) as change:
                change.execute("UPDATE migration_delta_rows_v0 SET value=? WHERE key=X'0100FF'", (old_value,))
                change.execute("UPDATE migration_delta_rows_v0 SET value=zeroblob(?) WHERE key=X'0000FF'",
                               ((1 << 24) + 1,))
            original_refusal = subprocess.run([original, "read-digest", db], capture_output=True, timeout=30)
            self.assertNotEqual(original_refusal.returncode, 0)
            self.assertEqual(original_refusal.stdout, b"")
            oversized = invoke()
            self.assertEqual((oversized["status"], oversized["result"]), (100, None))
            self.assertNotIn([15, 5, 24], oversized["transcript"])


            # Change the persisted schema only in a separate owned copy so
            # equal tuples can exist. Calculate the matching canonical row SHA
            # independently; ordering, rather than hash inequality, must refuse.
            db = owned / "duplicate.db"
            _run([original, "seed", db, "1"])
            with sqlite3.connect(db) as change:
                [r] = change.execute("SELECT namespace,key,value FROM migration_delta_rows_v0").fetchall()
                change.execute("DROP TABLE migration_delta_rows_v0")
                change.execute("CREATE TABLE migration_delta_rows_v0 (namespace BLOB, key BLOB, value BLOB) STRICT")
                change.executemany("INSERT INTO migration_delta_rows_v0 VALUES(?,?,?)", (r, r))
                parts = (b"trnm.migration.export-row.v0", *r)
                leaf = hashlib.sha256(b"".join(struct.pack(">Q", len(part)) + part for part in parts)).digest()
                checked_digest = hashlib.sha256(b"trnm.migration.target-rows.v0" + leaf * 2).digest()
                change.execute("UPDATE migration_delta_meta_v0 SET rows_digest=?,row_count=2", (checked_digest,))
            rust_duplicate = subprocess.run([original, "read-digest", db], capture_output=True, timeout=30)
            self.assertNotEqual(rust_duplicate.returncode, 0)
            denied = invoke()
            self.assertEqual((denied["status"], denied["result"]), (100, None))
            self.assertEqual(denied["transcript"][-1][:2], [13, 8])
            self.assertNotIn([15, 5, 24], denied["transcript"])
