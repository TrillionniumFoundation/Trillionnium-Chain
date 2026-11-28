"""Read a strict original state within one test-owned SQLite snapshot."""
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


class SettlementHeldStateShapeTests(unittest.TestCase):
    def test_typed_held_state_and_original_rejection_of_rebound_bytes(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-held-state-shape-")))
            modules = {
                key: stack.enter_context(NativeModule(src, byte_exports=("f0",), backend="selfhost"))
                for key, src in {
                    "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                    "raw": OWNER / "state_root_read.hepta",
                    "typed": OWNER / "held_state_shape.hepta",
                }.items()
            }
            original, source = original_adapter(root, marker=True)
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            inputs = [root / f"retained-{i}" for i in range(5)]
            for path, content in zip(inputs, retained_commands(), strict=True):
                path.write_bytes(content)
            fixtures = root / "owned"
            fixtures.mkdir(mode=0o700)
            uri = modules["uri"]

            def read(which, store, configuration, *, held=False):
                module = modules[which]
                message = {"reader": [str(module.library), module.artifact_sha256],
                           "uri": [str(uri.library), uri.artifact_sha256],
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(fixtures), "database": str(store),
                           "writer": str(original) if held else None,
                           "metadata_config": configuration.hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(message).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            variants = (
                ([], "option"), (inputs[1:3], None), (inputs[1:4], None),
                ([*inputs[1:4], "-", "-", inputs[4]], "tail"),
            )
            for i, (commands, corruption) in enumerate(variants):
                with self.subTest(stage=i):
                    store = fixtures / f"genuine stage {i} #?.db"
                    seed = execute([original, "seed-receipts", store, inputs[0], "0", *commands]).stdout
                    self.assertEqual(len(seed), 1018)
                    configuration = seed[104:]
                    expected = execute([original, "observe-actual-state-root", store, inputs[0]]).stdout[:32]
                    old_file = store.read_bytes()
                    raw = read("raw", store, configuration)
                    typed = read("typed", store, configuration, held=(i == 3))
                    self.assertEqual((typed["status"], typed["held"], typed["released"]), (0, i == 3, 0))
                    self.assertEqual((typed["projection"], typed["transcript"]),
                                     (raw["projection"], raw["transcript"]))
                    self.assertEqual(typed["transcript"][-1], [34, 3, 24])
                    self.assertEqual(bytes.fromhex(typed["projection"])[50:82], expected)
                    self.assertEqual(store.read_bytes(), old_file)
                    if corruption is None:
                        continue

                    rebound = execute([original, "fixture-noncanonical-state", store, inputs[0], corruption]).stdout
                    self.assertEqual(len(rebound), 64)
                    changed = store.read_bytes()
                    former = read("raw", store, configuration)
                    self.assertEqual(former["status"], 0)
                    former_projection = bytes.fromhex(former["projection"])
                    self.assertEqual(former_projection[50:82], rebound[:32])
                    self.assertEqual(former_projection[-32:], rebound[32:])
                    guarded = read("typed", store, configuration, held=(i == 3))
                    self.assertEqual((guarded["status"], guarded["projection"]), (100, None))
                    self.assertEqual(guarded["transcript"][-1][:2], [27, 8])
                    self.assertGreater(guarded["released"], 0)
                    original_check = subprocess.run([original, "observe-actual-state-root", store, inputs[0]],
                                                    capture_output=True, check=False, timeout=45)
                    self.assertNotEqual(original_check.returncode, 0)
                    self.assertEqual(original_check.stdout, b"")
                    self.assertEqual(store.read_bytes(), changed)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())
