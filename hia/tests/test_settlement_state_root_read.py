"""Check the original raw Settlement state root inside one native read snapshot."""
from contextlib import ExitStack
import hashlib
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


def raw_digest(data):
    domain = b"trnm.portable.v2.consumption-settlement-state-root.candidate.v1"
    return hashlib.sha256(len(domain).to_bytes(4, "little") + domain + data).digest()


class SettlementRawStateRootReadTests(unittest.TestCase):
    def test_original_state_root_and_checksum_consistent_canonical_drift(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-state-root-")))
            modules = {key: stack.enter_context(NativeModule(src, byte_exports=("f0",), backend="selfhost"))
                       for key, src in {
                           "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                           "metadata": OWNER / "metadata_read.hepta",
                           "root": OWNER / "state_root_read.hepta",
                       }.items()}
            original, source = original_adapter(root, marker=True)
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            inputs = [root / f"retained-{i}" for i in range(5)]
            for path, content in zip(inputs, retained_commands(), strict=True):
                path.write_bytes(content)
            fixtures = root / "owned"
            fixtures.mkdir(mode=0o700)

            def seed(label, full):
                store = fixtures / f"{label} #?.db"
                commands = [*inputs[1:4], "-", "-", inputs[4]] if full else []
                bind = execute([original, "seed-receipts", store, inputs[0], "0" if full else "1", *commands])
                self.assertEqual((len(bind.stdout), bind.stderr), (1018, b""))
                return store, bind.stdout[104:]

            def invoke(store, configuration, mode, hold=False):
                module, uri = modules[mode], modules["uri"]
                message = {"reader": [str(module.library), module.artifact_sha256],
                           "uri": [str(uri.library), uri.artifact_sha256],
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(fixtures), "database": str(store),
                           "writer": str(original) if hold else None,
                           "metadata_config": configuration.hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(message).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            for full in (False, True):
                with self.subTest(full=full):
                    store, configuration = seed(f"actual-{full}", full)
                    original_state = execute([original, "observe-actual-state-root", store, inputs[0]]).stdout
                    root_hash, raw = original_state[:32], original_state[32:]
                    self.assertEqual(raw_digest(raw), root_hash)
                    pre = store.read_bytes()
                    former = invoke(store, configuration, "metadata")
                    guarded = invoke(store, configuration, "root", hold=full)
                    self.assertEqual((guarded["status"], guarded["held"], guarded["released"]), (0, full, 0))
                    projection = bytes.fromhex(guarded["projection"])
                    self.assertEqual((len(projection), projection[50:82]), (147, root_hash))
                    self.assertEqual(guarded["projection"], former["projection"])
                    self.assertEqual(guarded["transcript"][-1], [34, 3, 24])
                    self.assertEqual(store.read_bytes(), pre)

                    altered = execute([original, "fixture-state-root-drift", store, inputs[0]]).stdout
                    old, new, new_body = altered[:32], altered[32:64], altered[64:]
                    self.assertEqual((old, raw_digest(new_body), len(new_body)), (root_hash, new, len(raw)))
                    self.assertNotEqual(new, old)
                    snapshot = store.read_bytes()
                    former = invoke(store, configuration, "metadata")
                    guarded = invoke(store, configuration, "root")
                    self.assertEqual(former["status"], 0)
                    checksum_only = bytes.fromhex(former["projection"])
                    self.assertEqual(checksum_only[:115], projection[:115])
                    self.assertNotEqual(checksum_only[115:], projection[115:])
                    self.assertEqual((guarded["status"], guarded["projection"]), (100, None))
                    self.assertEqual(guarded["transcript"][-1][:2], [28, 8])
                    self.assertGreater(guarded["released"], 0)
                    verified = subprocess.run([original, "observe-actual-state-root", store, inputs[0]],
                                              capture_output=True, check=False, timeout=45)
                    self.assertNotEqual(verified.returncode, 0)
                    self.assertEqual(verified.stdout, b"")
                    self.assertEqual(store.read_bytes(), snapshot)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())
