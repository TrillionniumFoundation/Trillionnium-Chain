"""Check one actual original SQLite AdmitReceipt against a fresh HIA Engine."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hia.platform.service_settlement.qualification.native import Capture, PublicEngine
from hia.platform.state_import_sqlite.qualification_host import sealed_library
from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_kernel_state_shape import frames
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


class SettlementFirstNativeReplayTests(unittest.TestCase):
    def test_real_first_admission_reconstructs_complete_original_transition(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-first-native-replay-") as tmp:
            root = Path(tmp)
            original_dir = root / "original"
            original_dir.mkdir()
            original, dependency = original_adapter(original_dir, marker=True)
            inputs = [root / f"original-input-{i}" for i in range(3)]
            for path, body in zip(inputs, list(retained_commands())[:3], strict=True):
                path.write_bytes(body)
            builds = root / "fresh-build"
            output = execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                              "--output", builds], timeout=200)
            report = json.loads(output.stdout)
            self.assertEqual((report["status"], report["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))
            public = builds / "public"
            public_meta = json.loads((public / "build.json").read_bytes())
            self.assertEqual(public_meta["artifact"], report["artifact"])
            image = public / "settlement-engine.so"

            stores = [root / f"genuine-stage-{i}.db" for i in range(3)]
            for i, store in enumerate(stores):
                execute([original, "seed-receipts", store, inputs[0], "0", *inputs[1:1 + i]])
            fixtures_before = {store: store.read_bytes() for store in stores}
            observer = [original, "observe-first-native-replay-witness"]
            for outside in (stores[0], stores[2]):
                refusal = subprocess.run([*observer, outside, inputs[0], stores[0]],
                                         capture_output=True, check=False, timeout=30)
                self.assertNotEqual(refusal.returncode, 0)
                self.assertEqual(refusal.stdout, b"")

            original_fields = list(frames(execute([*observer, stores[1], inputs[0], stores[0]]).stdout))
            self.assertEqual(tuple(map(len, original_fields)),
                             (882, 32, 8, 32, 32, 163, 868, 149, 32, 279, 32, 1196))
            (trust, store_id, height_raw, block_id, op_id, execution, command,
             receipt, prior_root, old_state, later_root, later_state) = original_fields
            self.assertEqual(trust, inputs[0].read_bytes())
            self.assertEqual(command, inputs[1].read_bytes())
            self.assertEqual(int.from_bytes(height_raw, "little"), 10)

            trace = root / "owned-observations"
            trace.mkdir()
            capture = Capture(trace)
            try:
                with sealed_library(image, report["artifact"]["sha256"]) as sealed:
                    engine = PublicEngine(public, capture,
                                          observed_image=(sealed._name, report["artifact"]))
                    with ExitStack() as stack:
                        def owned(*args, **kwargs):
                            handle = engine.owned(*args, **kwargs)
                            stack.callback(engine.drop, handle)
                            return handle

                        genesis = owned("engine_new", body=trust)
                        self.assertEqual(engine.kind(genesis), 1)
                        self.assertEqual(engine.view("engine_trust", genesis), trust)
                        self.assertEqual(engine.view("engine_state_root", genesis), prior_root)
                        self.assertEqual(engine.view("engine_state", genesis), old_state)
                        self.assertEqual(engine.scalar("engine_history_count", genesis), 0)
                        validated = owned("engine_validate_execution", genesis, body=execution)
                        self.assertEqual((engine.kind(validated), engine.view("bytes_view", validated)), (4, b""))
                        native_id = owned("operation_id", body=command)
                        self.assertEqual(engine.kind(native_id), 2)
                        actual_id = engine.view("bytes_view", native_id)
                        self.assertEqual(actual_id, op_id)
                        height = int.from_bytes(height_raw, "little")
                        successor = owned("engine_apply", genesis, body=command, height=height)
                        self.assertEqual(engine.kind(successor), 1)
                        self.assertEqual(engine.scalar("engine_history_count", successor), 1)
                        self.assertEqual(engine.scalar("engine_history_count", genesis), 0)
                        self.assertEqual(engine.view("engine_state", genesis), old_state)
                        actual_root = engine.view("engine_state_root", successor)
                        self.assertEqual(actual_root, later_root)
                        copied = owned("engine_state_copy", successor)
                        self.assertEqual((engine.kind(copied), engine.view("bytes_view", copied)), (3, later_state))
                        self.assertEqual(engine.view("engine_state", successor), later_state)
                    self.assertEqual(engine.live, {})
            finally:
                capture.close()
            observed = [json.loads(line) for line in (trace / "calls.jsonl").read_text().splitlines()]
            self.assertEqual([r["scalar_inputs"] for r in observed if r["function"] == "engine_apply"],
                             [{"height": 10}])
            self.assertFalse(any(r["function"] == "engine_replay" for r in observed))

            packet = receipt + store_id + actual_id + height_raw + block_id + actual_root
            self.assertEqual(len(packet), 285)
            for backend in ("direct", "selfhost"):
                with self.subTest(backend=backend), NativeModule(
                        OWNER / "first_replay_receipt_join.hepta", byte_exports=("f0",), backend=backend) as join:
                    good = join.call("f0", [packet, b"\x92"*156, b"\x93"*149]).require_returned()
                    self.assertEqual((good.value, good.arguments[1]), (0, receipt + b"\x92"*7))
                    specimens = []
                    for offset in range(len(packet)):
                        variant = bytearray(packet)
                        variant[offset] ^= 1
                        specimens.append(bytes(variant))
                    for start in range(0, len(specimens), 32):
                        rows = specimens[start:start+32]
                        calls = [("f0", [row, b"\x92"*156, b"\x93"*149]) for row in rows]
                        results = join.call_many(calls)
                        for (_, args), result in zip(calls, results, strict=True):
                            refused = result.require_returned()
                            self.assertEqual((refused.value, refused.arguments[1]), (100, args[1]))
                    for raw, osize, wsize, code in (
                        (packet, 148, 149, 102), (packet, 149, 148, 102),
                        (packet[:-1], 149, 149, 100), (packet + b"\0", 149, 149, 100),
                    ):
                        args = [raw, b"\x92"*osize, b"\x93"*wsize]
                        r = join.call("f0", args).require_returned()
                        self.assertEqual((r.value, r.arguments), (code, args))
            raw = execute([original, "observe-genesis-receipt-preview", stores[1], inputs[0], stores[0]]).stdout
            frame, original_command, expected = frames(raw)
            self.assertEqual((original_command, expected[112:]), (command, receipt))
            provider = ProviderBuild(dependency, root/"provider").run()
            check = Reader()
            check_provider(check.read, provider.parent, ROOT)
            owned_dir = root/"owned"
            owned_dir.mkdir(mode=0o700)
            source_db = owned_dir/"actual pristine genesis #?.db"
            binding = execute([original, "seed-receipts", source_db, inputs[0], "0"]).stdout
            exact_original = execute([original, "verify-journal", source_db, inputs[0]]).stdout
            self.assertEqual(exact_original[42:50], bytes(8))
            source_before = source_db.read_bytes()
            def image(module):
                return [str(module.library), module.artifact_sha256]

            for backend in ("direct", "selfhost"):
                with ExitStack() as stack, self.subTest(genesis_preview=backend):
                    uri = stack.enter_context(NativeModule(
                        ROOT/"hia/src/service_settlement/read_only_store_uri.hepta", byte_exports=("f0",),
                        backend=backend))
                    reader = stack.enter_context(NativeModule(
                        OWNER/"journal_read.hepta", byte_exports=("f0",), backend=backend))
                    pre = stack.enter_context(NativeModule(
                        OWNER/"preview_genesis_receipt.hepta", byte_exports=("f0",), backend=backend))
                    codec = stack.enter_context(NativeModule(
                        OWNER/"receipt_command_id.hepta", byte_exports=("f0",), backend=backend))
                    req = dict(uri=image(uri), reader=image(reader),
                               provider=[str(provider), check.checked[str(provider)]["sha256"]],
                               directory=str(owned_dir), database=str(source_db), journal_binding=binding.hex())
                    def invoke(source, candidate=None, cmd=command):
                        args = dict(source)
                        if candidate is not None:
                            args.update(genesis_preview=image(pre), genesis_receipt_command=image(codec),
                                        genesis_engine=[str(public), report["artifact"]["sha256"]],
                                        genesis_frame=candidate.hex(), genesis_command=cmd.hex())
                        rt = execute([sys.executable, "-B", "-I", "-S", OWNER/"schema_fixture_host.py"],
                                     input=json.dumps(args).encode(), timeout=45)
                        self.assertEqual(rt.stderr, b"")
                        return json.loads(rt.stdout)
                    got = invoke(req, frame)
                    self.assertEqual(got.pop("genesis_preview"), [0, expected.hex(), 1])
                    self.assertEqual(bytes.fromhex(got["projection"]), exact_original)
                    self.assertEqual((got["status"], got["released"], got["transcript"][-1]), (0, 0, [56,3,24]))
                    self.assertEqual(invoke(req), got)
                    for bad, bad_command in ((bytes([frame[0]+1])+frame[1:], command),
                                             (frame[:8]+bytes(32)+frame[40:], command),
                                             (frame, command+b"\0")):
                        self.assertEqual(invoke(req, bad, bad_command)["genesis_preview"], [100, None, 0])
            self.assertEqual(source_db.read_bytes(), source_before)
            self.assertFalse(source_db.with_name(source_db.name+"-journal").exists())
            for store in stores:
                self.assertEqual(store.read_bytes(), fixtures_before[store])
