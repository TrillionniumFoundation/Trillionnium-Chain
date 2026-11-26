"""The exact native lstat sequence gates real digest-only SQLite OPEN."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import _build_original, _run
from hia.tests.test_state_import_sqlite_cold_read import EXPECTED, OWNER, ROOT, projection


class StateImportSqliteCheckedDigest(unittest.TestCase):
    def test_original_path_refusals_precede_open_and_same_path_reads_held(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-checked-digest-") as tmp, NativeModule(
            OWNER / "checked_digest_scan.hepta", byte_exports=("f0",), backend="selfhost"
        ) as image, NativeModule(OWNER / "digest_scan.hepta", byte_exports=("f0",), backend="selfhost") as older:
            directory = Path(tmp).resolve()
            original, dependency = _build_original(directory)
            provider = ProviderBuild(dependency, directory / "provider").run()
            verification = Reader()
            check_provider(verification.read, provider.parent, ROOT)
            provider_digest = verification.checked[str(provider)]["sha256"]
            owned = directory / "owned"
            owned.mkdir(mode=0o700)

            def invoke(path, *, checked=True, advance=False):
                module = image if checked else older
                msg = {
                    "checked_digest": checked,
                    "reader": [str(module.library), module.artifact_sha256],
                    "provider": [str(provider), provider_digest],
                    "directory": str(owned), "database": str(path),
                    "expected": EXPECTED, "advance": str(original) if advance else None,
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(msg), capture_output=True, text=True, check=False, timeout=60,
                )
                self.assertEqual((child.returncode, child.stderr), (0, ""))
                return json.loads(child.stdout)

            def golden(path):
                raw = _run([original, "read-digest", path]).stdout
                self.assertEqual(len(raw), 240)
                return projection(raw + bytes(32))

            def denied(path, expected_paths):
                rust = subprocess.run([original, "read-digest", path], capture_output=True, timeout=25)
                self.assertNotEqual(rust.returncode, 0)
                self.assertEqual(rust.stdout, b"")
                got = invoke(path)
                self.assertEqual((got["status"], got["result"], got["released"]), (100, None, 0))
                self.assertEqual(got["path_calls"], [[15, os.fsencode(p).hex()] for p in expected_paths])
                self.assertTrue(all(op == 15 for _, op, _ in got["transcript"]))

            db = owned / "values.db"
            _run([original, "seed-stream", db])
            estimate = golden(db)
            allowed_paths = [db, *db.parents, *[str(db) + s for s in ("-wal", "-shm", "-journal")]]
            allowed_calls = [[15, os.fsencode(p).hex()] for p in allowed_paths] + [[2, os.fsencode(db).hex()]]
            checked = invoke(db, advance=True)
            self.assertEqual((checked["status"], checked["result"], checked["released"], checked["advanced"]),
                             (0, estimate, 0, True))
            self.assertEqual(checked["path_calls"], allowed_calls)
            self.assertEqual([x[1] for x in checked["transcript"][:len(allowed_calls)]],
                             [x[0] for x in allowed_calls])
            self.assertEqual(checked["transcript"][-1], [18, 3, 24])
            self.assertNotEqual(golden(db), estimate)
            newer = invoke(db)
            self.assertEqual((newer["status"], newer["result"], len(newer["result"])), (0, golden(db), 489))
            self.assertEqual(newer["path_calls"], allowed_calls)
            default = invoke(db, checked=False)
            self.assertEqual((default["status"], default["result"]), (0, newer["result"]))
            self.assertNotIn("path_calls", default)
            self.assertEqual(default["transcript"][0][:2], [1, 2])

            missing = owned / "missing.db"
            denied(missing, [missing])
            final_link = owned / "symlink.db"
            final_link.symlink_to(db)
            denied(final_link, [final_link])
            nested = owned / "inner"
            nested.mkdir()
            nested_db = nested / "nested.db"
            _run([original, "seed", nested_db, "1"])
            linked_parent = owned / "link-parent"
            linked_parent.symlink_to(nested, target_is_directory=True)
            linked_db = linked_parent / nested_db.name
            denied(linked_db, [linked_db, linked_parent])
            target = owned / "ordinary-fixture"
            target.write_bytes(b"owned sidecar target with no external effects")
            suffixes = ("-wal", "-shm", "-journal")
            for index, side_suffix in enumerate(suffixes):
                # Do not touch the live WAL/SHM of the held-read comparison.
                side_db = owned / f"sidecar-{index}.db"
                _run([original, "seed", side_db, "1"])
                candidates = [Path(str(side_db) + s) for s in suffixes]
                side = Path(str(side_db) + side_suffix)
                if side.exists():
                    side.rename(owned / f"original-sidecar-{index}")
                side.symlink_to(target)
                try:
                    denied(side_db, [side_db, *side_db.parents, *candidates[:index+1]])
                finally:
                    side.unlink()
