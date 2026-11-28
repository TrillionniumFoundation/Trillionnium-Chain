"""Actual held original Store replay with measured, bounded widths."""
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_kernel_state_shape import frames
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_state_root_read import raw_digest

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


class SettlementHeldVariableStreamReplayTests(unittest.TestCase):
    def test_one_sealed_stream_routes_from_original_verified_count(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-var-stream-")))
            original, source = original_adapter(tmp, marker=True, same_block=True)
            provider = ProviderBuild(source, tmp / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            images = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for name, path in {
                          "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                          "variable": OWNER / "held_variable_stream_replay.hepta",
                          "execution": OWNER / "execution_journal_read.hepta",
                      }.items()}
            out = tmp / "engine"
            engine = json.loads(execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                                        "--output", out], timeout=200).stdout)
            self.assertEqual((engine["status"], engine["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))
            owned = tmp / "owned"
            owned.mkdir(mode=0o700)

            def invoke(path, binding, lane, *, failed=None, ordinal=None):
                def image(name):
                    module = images[name]
                    return [str(module.library), module.artifact_sha256]

                request = {"reader": image(lane), "uri": image("uri"),
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(owned), "database": str(path),
                           "journal_binding": binding.hex()}
                if lane == "variable":
                    request["first_replay_engine"] = [str(out/"public"), engine["artifact"]["sha256"]]
                    request["variable_stream_fixture"] = True
                if lane == "variable" and failed is None:
                    request["writer"] = str(original)
                if failed is not None:
                    request.update(first_replay_fixture_control=failed, first_replay_fixture_control_step=ordinal)
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=60)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            for mode, count in (("short", 1), ("utf8-pair", 2), ("short-rollup", 3), ("utf8-settle", 4)):
                with self.subTest(fixture=mode):
                    original_bytes = list(frames(execute([tmp/"same-block-fixture", mode]).stdout))
                    trust = original_bytes[0]
                    commands = [original_bytes[i] for i in (1, 4, 6, 8)[:count]]
                    final_state = original_bytes[(3, 5, 7, 9)[count-1]]
                    paths = [tmp/f"{mode}-{i}" for i in range(count+1)]
                    for path, raw in zip(paths, (trust, *commands), strict=True):
                        path.write_bytes(raw)
                    db = owned/f"actual {mode} stream #?.db"
                    order = [*paths[1:4], "-", "-", paths[4]] if count == 4 else paths[1:]
                    held = execute([original, "seed-receipts", db, paths[0], "0", *order]).stdout
                    pristine = db.read_bytes()
                    actual = execute([original, "verify-journal", db, paths[0]]).stdout
                    settled, root, stored, *results = frames(execute(
                        [original, "observe-settled-state-id", db, paths[0]]).stdout)
                    self.assertEqual((root, stored, len(results)),
                                     (raw_digest(final_state), final_state, count*3))
                    self.assertEqual(settled, bytes([1])+original_bytes[-1] if count == 4 else bytes(33))
                    self.assertEqual(results[1::3], commands)
                    native = invoke(db, held, "variable")
                    reference = invoke(db, held, "execution")
                    self.assertEqual(reference["status"], 0, reference)
                    self.assertEqual(bytes.fromhex(reference["projection"]), actual)
                    self.assertTrue(native["held"], native)
                    if count == 3:
                        self.assertEqual((native["status"], native["projection"], native["replay_calls"],
                                          native["replay_locks"]), (100, None, 0, 0), native)
                        self.assertGreater(native["released"], 0)
                        self.assertNotIn(50, [phase for phase, _, _ in native["transcript"]])
                    else:
                        self.assertEqual((native["status"], native["replay_calls"], native["replay_locks"],
                                          native["released"]), (0, count, count, 0), native)
                        self.assertEqual(bytes.fromhex(native["projection"]), actual)
                        self.assertEqual(native["transcript"], reference["transcript"])
                        self.assertEqual(native["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        denied = invoke(db, held, "variable", failed="root", ordinal=count)
                        self.assertEqual((denied["status"], denied["projection"], denied["replay_calls"]),
                                         (100, None, count), denied)
                        self.assertGreater(denied["released"], 0)
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
