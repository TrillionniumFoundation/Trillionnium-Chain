"""Validate actual original execution bytes in one held native SQLite read."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


class SettlementExecutionJournalReadTests(unittest.TestCase):
    def test_bound_execution_and_receipt_coordinates_inside_original_held_store(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-execution-journal-")))
            modules = {key: stack.enter_context(NativeModule(src, byte_exports=("f0",), backend="selfhost"))
                       for key, src in {
                           "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                           "checksum": OWNER / "checksum_journal_read.hepta",
                           "execution": OWNER / "execution_journal_read.hepta",
                       }.items()}
            original, source = original_adapter(root, marker=True)
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            inputs = [root / f"retained-{i}" for i in range(5)]
            for path, data in zip(inputs, retained_commands(), strict=True):
                path.write_bytes(data)
            owned = root / "fixture"
            owned.mkdir(mode=0o700)

            def seed(label, full=True):
                store = owned / f"{label} #?.db"
                operations = [*inputs[1:4], "-", "-", inputs[4]] if full else []
                launch = execute([original, "seed-receipts", store, inputs[0], "0" if full else "1", *operations])
                self.assertEqual((len(launch.stdout), launch.stderr), (1018, b""))
                return store, launch.stdout

            def invoke(store, binder, lane, hold=False):
                module, uri = modules[lane], modules["uri"]
                req = {"reader": [str(module.library), module.artifact_sha256],
                       "uri": [str(uri.library), uri.artifact_sha256],
                       "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                       "directory": str(owned), "database": str(store),
                       "writer": str(original) if hold else None,
                       "journal_binding": binder.hex()}
                result = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(req).encode(), timeout=45)
                self.assertEqual(result.stderr, b"")
                return json.loads(result.stdout)

            for count in (0, 4):
                named = f"real-execution-{count}"
                store, binder = seed(named, count > 0)
                expected = execute([original, "verify-journal", store, inputs[0]]).stdout
                before = store.read_bytes()
                for lane in ("checksum", "execution"):
                    hold = count == 4 and lane == "execution"
                    status = invoke(store, binder, lane, hold)
                    self.assertEqual((status["status"], status["held"], status["released"]), (0, hold, 0), status)
                    self.assertEqual(bytes.fromhex(status["projection"]), expected)
                    trace = status["transcript"]
                    self.assertEqual(trace[-2:], [[55, 9, 24], [56, 3, 24]])
                    self.assertEqual(sum((p, op) == (62, 8) for p, op, _ in trace), count)
                    self.assertEqual(sum(op == 2 for _, op, _ in trace), 1)
                    self.assertEqual(sum(op == 3 for _, op, _ in trace), 1)
                self.assertEqual(store.read_bytes(), before)

            for mode in ("schema", "old-height", "coordinate", "context", "trailing"):
                with self.subTest(mode=mode):
                    store, binder = seed(mode)
                    expected = execute([original, "verify-journal", store, inputs[0]]).stdout
                    changed = execute([original, "fixture-execution-context-drift", store, inputs[0], mode]).stdout
                    check = execute([original, "inspect-operation-checksums", store, inputs[0]]).stdout
                    self.assertEqual((len(changed), check[-32:]), (32, changed))
                    self.assertEqual(execute([original, "inspect-journal-root", store, inputs[0]]).stdout, expected[-32:])
                    before = store.read_bytes()
                    prior = invoke(store, binder, "checksum")
                    self.assertEqual((prior["status"], prior["released"]), (0, 0), prior)
                    self.assertEqual(bytes.fromhex(prior["projection"]), expected)
                    native = invoke(store, binder, "execution")
                    self.assertEqual((native["status"], native["projection"]), (100, None), native)
                    self.assertGreater(native["released"], 0)
                    self.assertEqual(native["transcript"][-1][:2], [54, 8])
                    self.assertFalse(any(op == 3 for _, op, _ in native["transcript"]))
                    original_result = subprocess.run([original, "verify-journal", store, inputs[0]],
                                                     capture_output=True, check=False, timeout=45)
                    self.assertNotEqual(original_result.returncode, 0)
                    self.assertEqual(original_result.stdout, b"")
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())
