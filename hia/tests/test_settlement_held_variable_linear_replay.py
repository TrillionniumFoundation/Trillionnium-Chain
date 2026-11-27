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


class SettlementHeldVariableLinearReplayTests(unittest.TestCase):
    def test_actual_linear_receipt_capacity_and_outside_refusal(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-var-linear-")))
            original, source = original_adapter(tmp, marker=True, same_block=True)
            provider = ProviderBuild(source, tmp / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            images = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for name, path in {
                          "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                          "variable": OWNER / "held_variable_stream_replay.hepta",
                          "cursor": OWNER / "held_cursor_variable_linear_replay.hepta",
                          "execution": OWNER / "execution_journal_read.hepta",
                      }.items()}
            out = tmp / "engine"
            engine = json.loads(execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                                        "--output", out], timeout=200).stdout)
            self.assertEqual((engine["status"], engine["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))
            owned = tmp / "owned"
            owned.mkdir(mode=0o700)

            def invoke(path, binding, lane, *, failed=None, ordinal=4):
                def image(name):
                    module = images[name]
                    return [str(module.library), module.artifact_sha256]

                request = {"reader": image(lane), "uri": image("uri"),
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(owned), "database": str(path),
                           "journal_binding": binding.hex()}
                if lane in ("variable", "cursor"):
                    request["first_replay_engine"] = [str(out/"public"), engine["artifact"]["sha256"]]
                    request["variable_stream_fixture"] = True
                    if lane == "cursor":
                        request["linear_stream_fixture"] = True
                if lane == "cursor" and failed is None:
                    request["writer"] = str(original)
                if failed is not None:
                    request.update(first_replay_fixture_control=failed, first_replay_fixture_control_step=ordinal)
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=60)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            for mode, count in (("short", 5), ("utf8", 6), ("short", 7), ("utf8", 8), ("utf8", 9)):
                with self.subTest(fixture=mode, rows=count):
                    trust, *signed = frames(execute([tmp/"same-block-fixture", mode+"-linear-admits"]).stdout)
                    self.assertEqual(len(signed), 9)
                    commands = signed[:count]
                    paths = [tmp/f"{mode}-{i}" for i in range(count+1)]
                    for path, raw in zip(paths, (trust, *commands), strict=True):
                        path.write_bytes(raw)
                    db = owned/f"actual {mode} {count} committed receipts #?.db"
                    held = execute([original, "seed-receipts", db, paths[0], "0", *paths[1:]]).stdout
                    pristine = db.read_bytes()
                    actual = execute([original, "verify-journal", db, paths[0]]).stdout
                    settled, root, state, *rows = frames(execute(
                        [original, "observe-settled-state-id", db, paths[0]]).stdout)
                    self.assertEqual((settled, root, len(rows)), (bytes(33), raw_digest(state), 3*count))
                    for i, (execution, command, receipt) in enumerate(zip(rows[0::3], rows[1::3], rows[2::3])):
                        self.assertEqual(command, commands[i])
                        self.assertEqual((int.from_bytes(execution[-40:-32], "little"),
                                          int.from_bytes(execution[-80:-72], "little"),
                                          int.from_bytes(receipt[74:76], "little")), (10+i, 9+i, 24))
                        self.assertEqual((len(receipt),receipt[-1]), (149, 0))
                        self.assertEqual(execution[-40:], receipt[76:116])
                    denied = invoke(db, held, "variable")
                    self.assertEqual((denied["status"], denied["projection"], denied["replay_calls"]),
                                     (100, None, 0), denied)
                    cursor = invoke(db, held, "cursor")
                    independent = invoke(db, held, "execution")
                    self.assertEqual(independent["status"], 0, independent)
                    self.assertEqual(bytes.fromhex(independent["projection"]), actual)
                    self.assertTrue(cursor["held"])
                    if count == 9:
                        self.assertEqual((cursor["status"], cursor["projection"], cursor["replay_calls"],
                                          cursor["replay_locks"]), (100, None, 0, 0), cursor)
                        self.assertGreater(cursor["released"], 0)
                        self.assertNotIn(50, [phase for phase, _, _ in cursor["transcript"]])
                    else:
                        self.assertEqual((cursor["status"], cursor["replay_calls"], cursor["replay_locks"],
                                          cursor["released"]), (0, count, count, 0), cursor)
                        self.assertEqual(bytes.fromhex(cursor["projection"]), actual)
                        self.assertEqual(cursor["transcript"], independent["transcript"])
                        self.assertEqual(cursor["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        for ordinal, control in ((1, "root"), (4, "id"), (count, "state")):
                            refused = invoke(db, held, "cursor", failed=control, ordinal=ordinal)
                            self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                             (100, None, ordinal), refused)
                            self.assertGreater(refused["released"], 0)
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
