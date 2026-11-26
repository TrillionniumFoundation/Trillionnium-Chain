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
    def test_native_empty_applies_once_and_exact_original_replay_has_no_sql_changes(self):
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

            def call(db, proposal, kill=False, kill_replay=False):
                message = {
                    "reader": [str(reader.library), reader.artifact_sha256],
                    "provider": [str(provider), provider_digest], "directory": str(cases),
                    "database": str(db), "expected": EXPECTED, "empty_delta": proposal.hex(),
                    "advance": None, "kill_after_update": kill,
                    "kill_before_empty_readback_commit": kill_replay,
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(message), text=True, timeout=45, capture_output=True, check=False,
                )
                if kill or kill_replay:
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (-signal.SIGKILL, "", ""))
                    return None
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stderr, "")
                return json.loads(child.stdout)

            for count in (0, 17):
                with self.subTest(count=count):
                    oracle_db = seed(f"original-{count}", count)
                    before = export(oracle_db)
                    receipt = _run([writer, "empty-receipt", oracle_db]).stdout
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

                    self.assertEqual(receipt, after[200:208] + after[208:240])
                    replay_receipt = _run([writer, "empty-receipt", oracle_db]).stdout
                    self.assertEqual(replay_receipt, receipt)
                    self.assertEqual(export(oracle_db), after)

                    replay = call(candidate, proposal)
                    self.assertEqual((replay["status"], replay["result"], replay["released"]),
                                     (0, projection(after), 0))
                    self.assertEqual(replay["transcript"][-1], [18, 3, 24])
                    self.assertIn([15, 5, 24], replay["transcript"])
                    self.assertNotIn([23, 5, 24], replay["transcript"])
                    self.assertNotIn([28, 10, 24], replay["transcript"])
                    self.assertNotIn([35, 10, 24], replay["transcript"])
                    self.assertEqual(export(candidate), committed)
                    call(candidate, proposal, kill_replay=True)
                    self.assertEqual(export(candidate), committed)

                    different = bytes((after[208] ^ 1,)) + after[209:240]
                    forged = proposal[:(489+424)] + different.hex().upper().encode() + proposal[(489+488):1010] + different
                    wrong_context = proposal[:978] + bytes((proposal[978] ^ 0x80,)) + proposal[979:]
                    wrong_source = proposal[:130] + bytes((proposal[130] ^ 1,)) + proposal[131:]
                    wrong_pre_fields = proposal[:195] + bytes((proposal[195] ^ 1,)) + proposal[196:]
                    before_gen_off = 407
                    wrong_generation = (proposal[:before_gen_off] + b"0000000000000001"
                                        + proposal[before_gen_off + 16:])
                    for wrong in (forged, wrong_context, wrong_source, wrong_pre_fields, wrong_generation):
                        denied = call(candidate, wrong)
                        self.assertEqual((denied["status"], denied["result"], denied["transcript"]),
                                         (100, None, []))
                        self.assertEqual(export(candidate), committed)

                    interrupted = seed(f"killed-{count}", count)
                    call(interrupted, proposal, kill=True)
                    self.assertEqual(export(interrupted), before)

                    incorrect = seed(f"wrong-successor-{count}", count)
                    changed_expected = proposal[:489] + b"F" + proposal[490:]
                    rejected = call(incorrect, changed_expected)
                    self.assertEqual((rejected["status"], rejected["result"]), (100, None))
                    self.assertEqual(rejected["transcript"], [])
                    self.assertNotIn([15, 5, 24], rejected["transcript"])
                    self.assertEqual(export(incorrect), before)
