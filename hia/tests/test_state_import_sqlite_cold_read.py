"""Execute the actual native SQLite read continuation against the original owner."""
import hashlib
import json
import re
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

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/state_import_sqlite"
EXPECTED = (b"\x0a" * 32 + b"\x0b" * 32).hex()


def projection(original):
    """Translate original private fixture bytes; not a candidate validator."""
    fields = [original[i:i + 32] for i in range(0, 192, 32)]
    fields.extend((original[192:200], original[200:208], original[208:240]))
    lines = [":".join(part.hex().upper() for part in fields)]
    p = 272
    while p < len(original):
        sizes = struct.unpack_from("<III", original, p)
        p += 44
        parts = []
        for size in sizes:
            parts.append(original[p:p + size].hex().upper())
            p += size
        lines.append(":".join(parts))
    if p != len(original):
        raise ValueError("Incomplete original owner frame")
    return "\n".join(lines) + "\n"


class StateImportSqliteColdRead(unittest.TestCase):
    def test_native_sqlite_owner_cold_read_and_held_wal_generation(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-cold-read-") as tmp, NativeModule(
            OWNER / "cold_read.hepta", byte_exports=("f0",), backend="selfhost",
        ) as reader:
            directory = Path(tmp).resolve()
            writer, dependency = _build_original(directory)
            provider_dir = directory / "provider"
            provider = ProviderBuild(dependency, provider_dir).run()
            provenance = Reader()
            check_provider(provenance.read, provider_dir, ROOT)
            digest = provenance.checked[str(provider)]["sha256"]
            self.assertEqual(hashlib.sha256(provider.read_bytes()).hexdigest(), digest)
            cases = directory / "owned"
            cases.mkdir(mode=0o700)

            def original(db):
                return projection(_run([writer, "export", db]).stdout)

            def invoke(db, *, advance=False, expected=EXPECTED):
                req = {"reader": [str(reader.library), reader.artifact_sha256],
                       "provider": [str(provider), digest], "directory": str(cases),
                       "database": str(db), "expected": expected,
                       "advance": str(writer) if advance else None}
                answer = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(req), text=True, timeout=45, capture_output=True, check=False,
                )
                self.assertEqual(answer.returncode, 0, answer.stderr)
                self.assertEqual(answer.stderr, "")
                return json.loads(answer.stdout)

            for count in (0, 1, 17, 257):
                db = cases / f"valid-{count}.db"
                _run([writer, "seed", db, str(count)])
                expected = original(db)
                before = db.read_bytes()
                got = invoke(db, advance=count == 257)
                self.assertEqual((got["status"], got["result"], got["released"]), (0, expected, 0))
                self.assertEqual(got["transcript"][-1][:2], [18, 3])  # actual CLOSE before publication
                self.assertEqual(got["advanced"], count == 257)
                if count == 257:
                    successor = original(db)
                    self.assertNotEqual(successor, expected)
                    new = invoke(db)
                    self.assertEqual((new["status"], new["result"], new["released"]), (0, successor, 0))
                    self.assertEqual(len(successor.splitlines()), 257)
                    self.assertEqual(len(expected.splitlines()), 258)
                else:
                    self.assertEqual(db.read_bytes(), before)

            rich = cases / "boundary-prefix-and-binary.db"
            _run([writer, "seed-rich", rich])
            rich_expected = original(rich)
            rich_read = invoke(rich)
            self.assertEqual((rich_read["status"], rich_read["result"], rich_read["released"]),
                             (0, rich_expected, 0))
            self.assertEqual(len(rich_expected.splitlines()), 9)

            def refusal(db, **kwargs):
                got = invoke(db, **kwargs)
                self.assertEqual((got["status"], got["result"]), (100, None))
                self.assertGreater(got["released"], 0)
                return got

            refusal(db, expected="FF" * 64)
            for i, change in enumerate((
                "PRAGMA application_id=10",
                "PRAGMA user_version=2",
                "UPDATE migration_delta_meta_v0 SET source_context_digest=zeroblob(32)",
                "UPDATE migration_delta_meta_v0 SET row_count=0",
                "CREATE TABLE unrelated (extra INTEGER)",
                "UPDATE migration_delta_rows_v0 SET namespace='text-not-blob'",
                "UPDATE migration_delta_rows_v0 SET value=X'000AFF' WHERE key=X'0001'",
                "UPDATE migration_delta_meta_v0 SET rows_digest=zeroblob(32)",
            )):
                with self.subTest(change=change):
                    invalid = cases / f"invalid-{i}.db"
                    _run([writer, "seed", invalid, "3"])
                    with sqlite3.connect(invalid) as db_edit:
                        db_edit.execute(change)
                    db_edit.close()
                    self.assertNotEqual(subprocess.run(
                        [writer, "export", invalid], capture_output=True, timeout=30,
                    ).returncode, 0)
                    before = invalid.read_bytes()
                    got = refusal(invalid)
                    if i >= 6:
                        # The original BLOB types and row count remain valid.
                        # The last read must be actual SQLITE_DONE: it was
                        # the recomputed digest which withheld COMMIT/output.
                        self.assertEqual(got["transcript"][-1], [12, 7, 24])
                        self.assertNotIn([15, 5, 24], got["transcript"])
                    self.assertEqual(invalid.read_bytes(), before)

            def recompute_rows(connection):
                """Make only the checksum coherent, not the invalid row."""
                rows = connection.execute(
                    "SELECT namespace,key,value FROM migration_delta_rows_v0 ORDER BY namespace,key"
                ).fetchall()
                framed = lambda b: struct.pack(">Q", len(b)) + b
                domain = framed(b"trnm.migration.export-row.v0")
                leaves = [hashlib.sha256(domain + b"".join(framed(v) for v in row)).digest()
                          for row in rows]
                digest = hashlib.sha256(b"trnm.migration.target-rows.v0" + b"".join(leaves)).digest()
                connection.execute("UPDATE migration_delta_meta_v0 SET rows_digest=?,row_count=?",
                                   (digest, len(leaves)))

            # Bind coverage to all original exact case-sensitive prefixes.
            raw_source = (ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs").read_bytes()
            predicate = raw_source.split(b"pub fn forbidden_authority_namespace", 1)[1].split(b"];")[0]
            prefixes = re.findall(rb'b"([a-z_]+)"', predicate)
            self.assertEqual(len(prefixes), 7)
            cases_bad = [("reserved-" + str(i), "namespace", name + bytes((0, 255)))
                         for i, name in enumerate(prefixes)]
            cases_bad += [("empty-namespace", "namespace", b""), ("empty-key", "key", b""),
                          ("wide-namespace", "namespace", bytes(129)),
                          ("wide-key", "key", bytes(65537))]
            for label, field, value in cases_bad:
                with self.subTest(row=label):
                    corrupt = cases / (label + ".db")
                    _run([writer, "seed", corrupt, "1"])
                    with sqlite3.connect(corrupt) as connection:
                        connection.execute(f"UPDATE migration_delta_rows_v0 SET {field}=?", (value,))
                        recompute_rows(connection)
                    denied = subprocess.run([writer, "export", corrupt], capture_output=True, timeout=30)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertEqual(denied.stdout, b"")
                    halted = refusal(corrupt)
                    self.assertEqual(halted["transcript"][-1][:2], [13, 8])
                    self.assertNotIn([15, 5, 24], halted["transcript"])

            duplicate = cases / "matching-digest-duplicate.db"
            _run([writer, "seed", duplicate, "1"])
            with sqlite3.connect(duplicate) as connection:
                [one] = connection.execute("SELECT namespace,key,value FROM migration_delta_rows_v0").fetchall()
                connection.execute("DROP TABLE migration_delta_rows_v0")
                connection.execute("CREATE TABLE migration_delta_rows_v0 (namespace BLOB, key BLOB, value BLOB) STRICT")
                connection.executemany("INSERT INTO migration_delta_rows_v0 VALUES(?,?,?)", (one, one))
                recompute_rows(connection)
            original_denied = subprocess.run([writer, "export", duplicate], capture_output=True, timeout=30)
            self.assertNotEqual(original_denied.returncode, 0)
            self.assertEqual(original_denied.stdout, b"")
            second_denied = refusal(duplicate)
            self.assertEqual([e[:2] for e in second_denied["transcript"]].count([13, 8]), 2)
            self.assertEqual(second_denied["transcript"][-1][:2], [13, 8])
