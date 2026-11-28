"""Execute one exact original-compatible non-replacing SQLite INSERT."""
import json
from pathlib import Path
import signal
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
from hia.tests.test_state_import_sqlite_delete_write import original_rows


class StateImportSqliteInsertWrite(unittest.TestCase):
    def test_native_insert_proves_absence_and_rolls_back_real_process_death(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-insert-delta-") as tmp, NativeModule(
            OWNER / "empty_write.hepta", byte_exports=("f0",), backend="selfhost",
        ) as reader:
            directory = Path(tmp).resolve()
            writer, dependency = _build_original(directory)
            provider_dir = directory / "provider"
            provider = ProviderBuild(dependency, provider_dir).run()
            provenance = Reader()
            check_provider(provenance.read, provider_dir, ROOT)
            provider_digest = provenance.checked[str(provider)]["sha256"]
            cases = directory / "owned"
            cases.mkdir(mode=0o700)

            def seed(name, count):
                db = cases / (name + ".db")
                _run([writer, "seed", db, str(count)])
                return db

            def export(db):
                return _run([writer, "export", db]).stdout

            def call(db, proposal, *, kill=None):
                request = {
                    "reader": [str(reader.library), reader.artifact_sha256],
                    "provider": [str(provider), provider_digest], "directory": str(cases),
                    "database": str(db), "expected": EXPECTED, "empty_delta": proposal.hex(),
                    "advance": None, "kill_after_update": kill == "meta",
                    "kill_after_row": kill == "row",
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(request), text=True, timeout=45, capture_output=True, check=False,
                )
                if kill:
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (-signal.SIGKILL, "", ""))
                    return None
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stderr, "")
                return json.loads(child.stdout)

            for count, value_len in ((0, 0), (17, 128)):
                with self.subTest(count=count, value_len=value_len):
                    oracle = seed(f"original-{count}", count)
                    before = export(oracle)
                    _run([writer, "insert-advance", oracle])
                    after = export(oracle)
                    self.assertEqual(int.from_bytes(after[192:200], "big"), count + 1)
                    self.assertEqual(int.from_bytes(after[200:208], "big"), 1)
                    self.assertNotEqual(before[128:160], after[128:160])
                    original = original_rows(before)
                    successor = original_rows(after)
                    [inserted] = [row for row in successor if row not in original]
                    self.assertEqual([row for row in successor if row != inserted], original)
                    ns, key, _, value = inserted
                    self.assertEqual(len(value), value_len)
                    prefix = b"INS1M13!" + struct.pack("<QQ", len(ns), len(key))
                    prefix += ns.ljust(64, b"\0") + key.ljust(64, b"\0") + bytes(32)
                    prefix += after[128:192] + struct.pack("<QQ", count + 1, len(value))
                    prefix += value.ljust(128, b"\0")
                    proposal = prefix + (projection(before)[:489] + projection(after)[:489]).encode()
                    proposal += after[96:128] + after[208:240]
                    self.assertEqual(len(proposal), 1434)

                    candidate = seed(f"candidate-{count}", count)
                    got = call(candidate, proposal)
                    self.assertEqual((got["status"], got["result"], got["released"]), (0, projection(after), 0))
                    self.assertEqual(got["transcript"][-1], [18, 3, 24])
                    for actual in ([36, 6, 24], [35, 10, 24], [28, 10, 24]):
                        self.assertIn(actual, got["transcript"])
                    self.assertEqual(export(candidate), after)
                    stale = call(candidate, proposal)
                    self.assertEqual((stale["status"], stale["result"]), (100, None))
                    self.assertNotIn([30, 5, 24], stale["transcript"])
                    self.assertEqual(export(candidate), after)

                    for label, offset in (("successor-digest", 184), ("insert-width", 257)):
                        refused = seed(f"{label}-{count}", count)
                        bad = proposal[:offset] + bytes((proposal[offset] ^ 1,)) + proposal[offset + 1:]
                        denied = call(refused, bad)
                        self.assertEqual((denied["status"], denied["result"]), (100, None))
                        self.assertEqual([35, 10, 24] in denied["transcript"], label == "successor-digest")
                        self.assertNotIn([15, 5, 24], denied["transcript"])
                        self.assertEqual(export(refused), before)

                    if original:
                        clash = seed("key-already-present", count)
                        _, existing_key, _, _ = original[0]
                        same_key = proposal[:16] + struct.pack("<Q", len(existing_key)) + proposal[24:88]
                        same_key += existing_key.ljust(64, b"\0") + proposal[152:]
                        denied = call(clash, same_key)
                        self.assertEqual((denied["status"], denied["result"]), (100, None))
                        self.assertNotIn([30, 5, 24], denied["transcript"])
                        self.assertEqual(export(clash), before)

                    for cut in ("row", "meta"):
                        killed = seed(f"{cut}-interrupted-{count}", count)
                        call(killed, proposal, kill=cut)
                        self.assertEqual(export(killed), before)
