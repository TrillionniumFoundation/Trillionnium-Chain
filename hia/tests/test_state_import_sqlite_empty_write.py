"""Execute one original-compatible local empty-delta SQLite transition in HIA."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import _build_original, _run
from hia.tests.test_state_import_sqlite_cold_read import EXPECTED, OWNER, ROOT, projection


class StateImportSqliteEmptyWrite(unittest.TestCase):
    def test_native_empty_delta_commit_stale_refusal_and_actual_process_rollback(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-empty-delta-") as tmp, NativeModule(
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

            def call(db, proposal, kill=False):
                message = {
                    "reader": [str(reader.library), reader.artifact_sha256],
                    "provider": [str(provider), provider_digest], "directory": str(cases),
                    "database": str(db), "expected": EXPECTED, "empty_delta": proposal.hex(),
                    "advance": None, "kill_after_update": kill,
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(message), text=True, timeout=45, capture_output=True, check=False,
                )
                if kill:
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (-signal.SIGKILL, "", ""))
                    return None
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stderr, "")
                return json.loads(child.stdout)

            for count in (0, 17):
                with self.subTest(count=count):
                    oracle_db = seed(f"original-{count}", count)
                    before = export(oracle_db)
                    _run([writer, "empty-advance", oracle_db])
                    after = export(oracle_db)
                    self.assertEqual((before[200:208], after[200:208]), (bytes(8), bytes(7) + b"\1"))
                    self.assertEqual(before[128:200], after[128:200])  # rows, root and count
                    self.assertEqual(before[272:], after[272:])  # every original physical row value
                    self.assertNotEqual(before[96:128], after[96:128])
                    self.assertNotEqual(after[208:240], bytes(32))
                    proposal = (projection(before)[:489] + projection(after)[:489]).encode()
                    proposal += after[96:128] + after[208:240]

                    candidate = seed(f"candidate-{count}", count)
                    self.assertEqual(export(candidate), before)
                    got = call(candidate, proposal)
                    self.assertEqual((got["status"], got["result"], got["released"]), (0, projection(after), 0))
                    self.assertEqual(got["transcript"][-1], [18, 3, 24])
                    self.assertIn([28, 10, 24], got["transcript"])
                    committed = export(candidate)
                    self.assertEqual(committed, after)

                    # The original owner treats its exact immutable replay as
                    # idempotent. This one-generation staging proposal refuses
                    # stale reuse instead; it cannot create a second generation.
                    _run([writer, "empty-advance", oracle_db])
                    self.assertEqual(export(oracle_db), after)
                    stale = call(candidate, proposal)
                    self.assertEqual((stale["status"], stale["result"]), (100, None))
                    self.assertNotIn([28, 10, 24], stale["transcript"])
                    self.assertEqual(export(candidate), committed)

                    interrupted = seed(f"killed-{count}", count)
                    call(interrupted, proposal, kill=True)
                    self.assertEqual(export(interrupted), before)

                    incorrect = seed(f"wrong-successor-{count}", count)
                    changed_expected = proposal[:489] + b"F" + proposal[490:]
                    rejected = call(incorrect, changed_expected)
                    self.assertEqual((rejected["status"], rejected["result"]), (100, None))
                    self.assertIn([28, 10, 24], rejected["transcript"])
                    self.assertNotIn([15, 5, 24], rejected["transcript"])
                    self.assertEqual(export(incorrect), before)
