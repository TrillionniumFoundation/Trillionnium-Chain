"""Original ordered command identity inside a real held SQLite journal read."""
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


class SettlementCommandJournalReadTests(unittest.TestCase):
    def test_original_typed_commands_receipts_and_same_root_refusals(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-command-journal-")))
            modules = {key: stack.enter_context(NativeModule(src, byte_exports=("f0",), backend="selfhost"))
                       for key, src in {
                           "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                           "raw": OWNER / "journal_read.hepta",
                           "receipt": OWNER / "identity_journal_read.hepta",
                           "command": OWNER / "command_journal_read.hepta",
                       }.items()}
            original, source = original_adapter(root, marker=True)
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            inputs = [root / f"retained-{i}" for i in range(5)]
            for target, command in zip(inputs, retained_commands(), strict=True):
                target.write_bytes(command)
            owned = root / "owned"
            owned.mkdir(mode=0o700)

            def seed(label, full=True):
                store = owned / f"{label} #?.db"
                actions = [*inputs[1:4], "-", "-", inputs[4]] if full else []
                out = execute([original, "seed-receipts", store, inputs[0], "0" if full else "1", *actions])
                self.assertEqual((len(out.stdout), out.stderr), (1018, b""))
                return store, out.stdout

            def observe(store, binding, mode, hold=False):
                module, uri = modules[mode], modules["uri"]
                request = {"reader": [str(module.library), module.artifact_sha256],
                           "uri": [str(uri.library), uri.artifact_sha256],
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(owned), "database": str(store),
                           "writer": str(original) if hold else None,
                           "journal_binding": binding.hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            for count in (0, 4):
                store, binding = seed(f"original {count} commands", full=count != 0)
                before = store.read_bytes()
                expected = execute([original, "verify-journal", store, inputs[0]]).stdout
                self.assertEqual((len(expected), struct.unpack_from("<Q", expected, 42)[0]), (219, count))
                if count:
                    actual = execute([original, "original-receipt-fixtures", store, inputs[0]]).stdout
                    parsed, start = [], 0
                    while start < len(actual):
                        width = struct.unpack_from("<H", actual, start)[0]
                        parsed.append(struct.unpack_from("<H", actual, start+42)[0])
                        start += 44 + width
                    self.assertEqual(parsed, [24, 24, 25, 26])
                    self.assertEqual(actual[-33], 1)
                for lane in ("raw", "receipt", "command"):
                    result = observe(store, binding, lane, hold=count > 0 and lane == "command")
                    self.assertEqual((result["status"], result["held"], result["released"]),
                                     (0, count > 0 and lane == "command", 0), result)
                    self.assertEqual(bytes.fromhex(result["projection"]), expected)
                    trace = result["transcript"]
                    self.assertEqual(trace[-2:], [[55, 9, 24], [56, 3, 24]])
                    self.assertEqual((sum(op == 2 for _, op, _ in trace), sum(op == 3 for _, op, _ in trace)),
                                     (1, 1))
                    for phase in (59, 60):
                        self.assertEqual(sum(p == phase and op == 8 for p, op, _ in trace),
                                         count if lane == "command" else 0)
                    if count and lane == "command":
                        self.assertEqual([n-24 for p, op, n in trace if p == 60 and op == 8],
                                         [868, 900, 2689, 240])
                self.assertEqual(store.read_bytes(), before)

            for guard, failed, diagnostic in (("changed-id", 60, b"journal operation ID differs"),
                                               ("trailing", 60, b"NonCanonical"),
                                               ("nested-option", 60, b"NonCanonical"),
                                               ("oversized", 59, b"NonCanonical"),
                                               ("kind", 54, b"journal receipt differs from deterministic replay")):
                with self.subTest(guard=guard):
                    store, binding = seed(guard)
                    pristine = execute([original, "verify-journal", store, inputs[0]]).stdout
                    if guard == "kind":
                        rebound = execute([original, "fixture-rebind-mutated-receipt",
                                           store, inputs[0], guard]).stdout
                        self.assertNotEqual(rebound, pristine[-32:])
                    else:
                        execute([original, "fixture-command-identity-drift", store, inputs[0], guard])
                        rebound = pristine[-32:]
                    self.assertEqual(execute([original, "inspect-journal-root", store, inputs[0]]).stdout,
                                     rebound)
                    before = store.read_bytes()
                    for lane in ("raw", "receipt"):
                        accepted = observe(store, binding, lane)
                        self.assertEqual((accepted["status"], accepted["released"]), (0, 0), accepted)
                        projection = bytes.fromhex(accepted["projection"])
                        self.assertEqual((projection[122:154], projection[-32:]), (rebound, rebound))
                        if guard != "kind":
                            self.assertEqual(projection, pristine)
                    native = observe(store, binding, "command")
                    self.assertEqual((native["status"], native["projection"]), (100, None), native)
                    self.assertEqual(native["transcript"][-1][:2], [failed, 8])
                    if guard == "oversized":
                        self.assertEqual(sum(p == 60 for p, _, _ in native["transcript"]), 3)
                    self.assertFalse(any(op == 3 for _, op, _ in native["transcript"]))
                    self.assertGreater(native["released"], 0)
                    retained = subprocess.run([original, "verify-journal", store, inputs[0]],
                                              capture_output=True, check=False, timeout=45)
                    self.assertNotEqual(retained.returncode, 0)
                    self.assertEqual(retained.stdout, b"")
                    self.assertIn(diagnostic, retained.stderr)
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name+"-journal").exists())
