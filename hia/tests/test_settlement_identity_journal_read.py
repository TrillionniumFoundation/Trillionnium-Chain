"""Genuine held original receipt data, with separate canonical identity tests."""
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


class SettlementIdentityJournalReadTests(unittest.TestCase):
    def test_original_typed_receipts_in_held_journal_and_coherent_refusals(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-identity-")))
            modules = {key: stack.enter_context(NativeModule(src, byte_exports=("f0",), backend="selfhost"))
                       for key, src in {
                           "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                           "raw": OWNER / "journal_read.hepta",
                           "strict": OWNER / "identity_journal_read.hepta",
                       }.items()}
            original, source = original_adapter(root, marker=True)
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            inputs = [root / f"retained-{i}" for i in range(5)]
            for target, data in zip(inputs, retained_commands(), strict=True):
                target.write_bytes(data)
            owned = root / "owned"
            owned.mkdir(mode=0o700)

            def seed(label):
                store = owned / f"{label} #?.db"
                out = execute([original, "seed-receipts", store, inputs[0],
                               "0", *inputs[1:4], "-", "-", inputs[4]], timeout=60)
                self.assertEqual((len(out.stdout), out.stderr), (1018, b""))
                return store, out.stdout

            def image(key):
                module = modules[key]
                return [str(module.library), module.artifact_sha256]

            def observe(store, binding, mode, hold=False):
                request = {"uri": image("uri"), "reader": image(mode),
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(owned), "database": str(store),
                           "writer": str(original) if hold else None,
                           "journal_binding": binding.hex()}
                got = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                              input=json.dumps(request).encode(), timeout=45)
                self.assertEqual(got.stderr, b"")
                return json.loads(got.stdout)

            intact, binding = seed("four actual committed receipts")
            pristine = intact.read_bytes()
            projected = execute([original, "verify-journal", intact, inputs[0]], timeout=60).stdout
            original_rows = execute([original, "original-receipt-fixtures", intact, inputs[0]]).stdout
            self.assertEqual(struct.unpack_from("<Q", projected, 42)[0], 4)
            self.assertEqual(original_rows[-33], 1)
            self.assertEqual(struct.unpack_from("<H", original_rows, len(original_rows)-225)[0], 181)
            strict = observe(intact, binding, "strict", hold=True)
            self.assertEqual((strict["status"], strict["held"], strict["released"]), (0, True, 0), strict)
            self.assertEqual(bytes.fromhex(strict["projection"]), projected)
            trace = strict["transcript"]
            for phase in (53, 57, 58, 54):
                self.assertEqual(sum(p == phase and op == 8 for p, op, _ in trace), 4)
            self.assertEqual(trace[-2:], [[55, 9, 24], [56, 3, 24]])
            self.assertEqual(sum(op == 2 for _, op, _ in trace), 1)
            self.assertEqual(sum(op == 3 for _, op, _ in trace), 1)
            self.assertEqual(intact.read_bytes(), pristine)

            for mutation in ("trailing", "id", "sequence"):
                with self.subTest(mutation=mutation):
                    store, binding = seed(f"root-consistent disposable {mutation}")
                    rebuilt = execute([original, "fixture-rebind-mutated-receipt", store, inputs[0], mutation]).stdout
                    before = store.read_bytes()
                    self.assertEqual(len(rebuilt), 32)
                    self.assertNotEqual(rebuilt, projected[-32:])
                    self.assertEqual(execute([original, "inspect-journal-root", store, inputs[0]]).stdout, rebuilt)

                    raw = observe(store, binding, "raw")
                    self.assertEqual((raw["status"], raw["held"], raw["released"]), (0, False, 0), raw)
                    accepted = bytes.fromhex(raw["projection"])
                    self.assertEqual((accepted[122:154], accepted[-32:]), (rebuilt, rebuilt))
                    self.assertEqual(raw["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                    self.assertFalse(any(p in (57, 58) for p, _, _ in raw["transcript"]))

                    origin = subprocess.run([original, "verify-journal", store, inputs[0]],
                                            capture_output=True, timeout=45, check=False)
                    self.assertNotEqual(origin.returncode, 0)
                    self.assertEqual(origin.stdout, b"")
                    self.assertIn(b"NonCanonical" if mutation == "trailing"
                                  else b"journal receipt differs from deterministic replay", origin.stderr)
                    rejected = observe(store, binding, "strict")
                    self.assertEqual((rejected["status"], rejected["projection"]), (100, None), rejected)
                    self.assertEqual(rejected["transcript"][-1][:2], [54, 8])
                    self.assertFalse(any(op == 3 for _, op, _ in rejected["transcript"]))
                    self.assertGreater(rejected["released"], 0)
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name+"-journal").exists())
