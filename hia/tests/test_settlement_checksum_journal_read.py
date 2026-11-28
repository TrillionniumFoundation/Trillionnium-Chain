"""Compare the native held operation-row checksum with actual original storage."""
from contextlib import ExitStack
import json
from pathlib import Path
import struct
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


class SettlementChecksumJournalReadTests(unittest.TestCase):
    def test_original_operation_checksums_and_same_root_refusals(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-checksum-journal-")))
            modules = {key: stack.enter_context(NativeModule(src, byte_exports=("f0",), backend="selfhost"))
                       for key, src in {
                           "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                           "command": OWNER / "command_journal_read.hepta",
                           "checksum": OWNER / "checksum_journal_read.hepta",
                       }.items()}
            original, source = original_adapter(root, marker=True)
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            inputs = [root / f"retained-{i}" for i in range(5)]
            for path, content in zip(inputs, retained_commands(), strict=True):
                path.write_bytes(content)
            owned = root / "owned"
            owned.mkdir(mode=0o700)

            def seed(name, full=True):
                store = owned / f"{name} #?.db"
                commands = [*inputs[1:4], "-", "-", inputs[4]] if full else []
                result = execute([original, "seed-receipts", store, inputs[0], "0" if full else "1", *commands])
                self.assertEqual((len(result.stdout), result.stderr), (1018, b""))
                return store, result.stdout

            def observe(store, binding, lane, hold=False):
                mod, uri = modules[lane], modules["uri"]
                req = {"reader": [str(mod.library), mod.artifact_sha256],
                       "uri": [str(uri.library), uri.artifact_sha256],
                       "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                       "directory": str(owned), "database": str(store),
                       "writer": str(original) if hold else None,
                       "journal_binding": binding.hex()}
                result = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(req).encode(), timeout=45)
                self.assertEqual(result.stderr, b"")
                return json.loads(result.stdout)

            for count in (0, 4):
                with self.subTest(count=count):
                    store, binding = seed(f"genuine-{count}", count > 0)
                    pristine = store.read_bytes()
                    expected = execute([original, "verify-journal", store, inputs[0]]).stdout
                    checks = execute([original, "inspect-operation-checksums", store, inputs[0]]).stdout
                    self.assertEqual((len(expected), len(checks)), (219, count * 40))
                    self.assertEqual(struct.unpack_from("<Q", expected, 42)[0], count)
                    execution_lengths = [struct.unpack_from("<Q", checks, p)[0] for p in range(0, len(checks), 40)]
                    for lane in ("command", "checksum"):
                        hold = lane == "checksum" and count > 0
                        result = observe(store, binding, lane, hold)
                        self.assertEqual((result["status"], result["held"], result["released"]), (0, hold, 0), result)
                        self.assertEqual(bytes.fromhex(result["projection"]), expected)
                        trace = result["transcript"]
                        self.assertEqual(trace[-2:], [[55, 9, 24], [56, 3, 24]])
                        self.assertEqual((sum(op == 2 for _, op, _ in trace), sum(op == 3 for _, op, _ in trace)), (1, 1))
                        lengths = execution_lengths if lane == "checksum" else []
                        self.assertEqual([size - 24 for phase, op, size in trace if (phase, op) == (62, 8)], lengths)
                        self.assertEqual([size for phase, op, size in trace if (phase, op) == (63, 8)], [56] * len(lengths))
                        self.assertEqual(sum((p, op) == (61, 8) for p, op, _ in trace), len(lengths))
                    self.assertEqual(store.read_bytes(), pristine)

            for case, phase, error in (("checksum", 54, b"journal row checksum differs"),
                                       ("raw-execution", 54, b"journal row checksum differs"),
                                       ("checksum-width", 63, b"operation checksum must be exactly 32 bytes"),
                                       ("oversized-execution", 61, b"journal row checksum differs")):
                with self.subTest(case=case):
                    store, binding = seed(case)
                    expected = execute([original, "verify-journal", store, inputs[0]]).stdout
                    checks = execute([original, "inspect-operation-checksums", store, inputs[0]]).stdout
                    self.assertEqual(execute([original, "fixture-row-checksum-drift",
                                              store, inputs[0], case]).stdout, checks)
                    self.assertEqual(execute([original, "inspect-journal-root", store, inputs[0]]).stdout,
                                     expected[-32:])
                    before = store.read_bytes()
                    command = observe(store, binding, "command")
                    self.assertEqual((command["status"], command["released"]), (0, 0), command)
                    self.assertEqual(bytes.fromhex(command["projection"]), expected)
                    rejected = observe(store, binding, "checksum")
                    self.assertEqual((rejected["status"], rejected["projection"]), (100, None), rejected)
                    self.assertGreater(rejected["released"], 0)
                    self.assertEqual(rejected["transcript"][-1][:2], [phase, 8])
                    self.assertFalse(any(op == 3 for _, op, _ in rejected["transcript"]))
                    if case == "oversized-execution":
                        self.assertEqual(sum(p == 62 for p, _, _ in rejected["transcript"]), 3)
                    retained = subprocess.run([original, "verify-journal", store, inputs[0]],
                                              capture_output=True, timeout=45, check=False)
                    self.assertNotEqual(retained.returncode, 0)
                    self.assertEqual(retained.stdout, b"")
                    self.assertIn(error, retained.stderr)
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())
