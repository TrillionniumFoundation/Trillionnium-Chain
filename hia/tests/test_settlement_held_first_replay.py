"""One actual original AdmitReceipt replay performed while SQLite remains held."""
from contextlib import ExitStack
import json
from pathlib import Path
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


class SettlementHeldFirstReplayTests(unittest.TestCase):
    def test_actual_sealed_engine_before_the_original_snapshot_closes(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-held-first-replay-")))
            modules = {
                key: stack.enter_context(NativeModule(src, byte_exports=("f0",), backend="selfhost"))
                for key, src in {
                    "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                    "execution": OWNER / "execution_journal_read.hepta",
                    "replay": OWNER / "held_first_replay.hepta",
                }.items()
            }
            original, source = original_adapter(root, marker=True)
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            builds = root / "build"
            answer = execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                              "--output", builds], timeout=200)
            report = json.loads(answer.stdout)
            self.assertEqual((report["status"], report["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))
            public = builds / "public"
            self.assertEqual(json.loads((public / "build.json").read_bytes())["artifact"], report["artifact"])
            owned = root / "owned"
            owned.mkdir(mode=0o700)
            files = [root / f"retained-{i}" for i in range(3)]
            for file, data in zip(files, list(retained_commands())[:3], strict=True):
                file.write_bytes(data)
            uri = modules["uri"]

            def invoke(store, binder, *, lane="replay", lock=False, control=None):
                module = modules[lane]
                req = {"reader": [str(module.library), module.artifact_sha256],
                       "uri": [str(uri.library), uri.artifact_sha256],
                       "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                       "directory": str(owned), "database": str(store),
                       "writer": str(original) if lock else None, "journal_binding": binder.hex()}
                if lane == "replay":
                    req["first_replay_engine"] = [str(public), report["artifact"]["sha256"]]
                if control:
                    req["first_replay_fixture_control"] = control
                result = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(req).encode(), timeout=60)
                self.assertEqual(result.stderr, b"")
                return json.loads(result.stdout)

            for count in (0, 1, 2):
                with self.subTest(real_original_commands=count):
                    store = owned / f"original #{count}?.db"
                    binding = execute([original, "seed-receipts", store, files[0], "0", *files[1:1+count]]).stdout
                    before = store.read_bytes()
                    observed = invoke(store, binding, lock=count == 1)
                    if count != 1:
                        self.assertEqual((observed["status"], observed["projection"], observed["replay_calls"]),
                                         (100, None, 0))
                        self.assertGreater(observed["released"], 0)
                    else:
                        expected = execute([original, "verify-journal", store, files[0]]).stdout
                        control = invoke(store, binding, lane="execution")
                        self.assertEqual((observed["status"], observed["replay_calls"], observed["released"]),
                                         (0, 1, 0))
                        self.assertTrue(observed["held"])
                        self.assertTrue(observed["replay_held"])
                        self.assertEqual(bytes.fromhex(observed["projection"]), expected)
                        self.assertEqual(observed["transcript"], control["transcript"])
                        self.assertEqual(observed["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        for mismatch in ("count", "id", "root", "state"):
                            refused = invoke(store, binding, control=mismatch)
                            self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                             (100, None, 1))
                            self.assertEqual(refused["transcript"][-1][:2], [54, 8])
                            self.assertGreater(refused["released"], 0)
                            self.assertFalse(any(op == 3 for _, op, _ in refused["transcript"]))
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())
