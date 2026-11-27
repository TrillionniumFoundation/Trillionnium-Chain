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


class SettlementHeldVariableRollupReplayTests(unittest.TestCase):
    def test_actual_measured_three_row_terminal_rollup(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-var-three-")))
            original, source = original_adapter(tmp, marker=True, same_block=True)
            provider = ProviderBuild(source, tmp / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            images = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for name, path in {
                          "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                          "variable": OWNER / "held_variable_stream_replay.hepta",
                          "cursor": OWNER / "held_cursor_variable_rollup_replay.hepta",
                          "fixed": OWNER / "held_rollup_replay.hepta",
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
                if lane in ("fixed", "variable", "cursor"):
                    request["first_replay_engine"] = [str(out/"public"), engine["artifact"]["sha256"]]
                    if lane == "fixed":
                        request["receipt_replay_limit"] = 3
                    else:
                        request["variable_stream_fixture"] = True
                if lane == "cursor" and failed is None:
                    request["writer"] = str(original)
                if failed is not None:
                    request.update(first_replay_fixture_control=failed, first_replay_fixture_control_step=ordinal)
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=60)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            extents = set()
            for mode in ("short", "utf8"):
                with self.subTest(fixture=mode):
                    trust, one, _, state1, two, state2, three, state3 = frames(
                        execute([tmp/"same-block-fixture", mode+"-rollup"]).stdout)
                    commands = (one, two, three)
                    states = (state1, state2, state3)
                    paths = [tmp/f"{mode}-{i}" for i in range(4)]
                    for path, raw in zip(paths, (trust, *commands), strict=True):
                        path.write_bytes(raw)
                    db = owned/f"actual {mode} rollup #?.db"
                    held = execute([original, "seed-receipts", db, paths[0], "0", *paths[1:]]).stdout
                    pristine = db.read_bytes()
                    actual = execute([original, "verify-journal", db, paths[0]]).stdout
                    settled, root, stored, *rows = frames(execute(
                        [original, "observe-settled-state-id", db, paths[0]]).stdout)
                    self.assertEqual((settled, root, stored, len(rows)),
                                     (bytes(33), raw_digest(state3), state3, 9))
                    extents.add((len(trust), len(rows[0]), *(len(cmd) for cmd in commands),
                                 *(len(state) for state in states)))
                    for i, (height, parent, kind) in enumerate(zip((10,11,12), (9,10,11), (24,24,25))):
                        execution, command, receipt = rows[i*3:i*3+3]
                        self.assertEqual(command, commands[i])
                        self.assertEqual((int.from_bytes(execution[-40:-32], "little"),
                                          int.from_bytes(execution[-80:-72], "little"),
                                          int.from_bytes(receipt[74:76], "little")), (height, parent, kind))
                        self.assertEqual(receipt[116:], raw_digest(states[i])+bytes(1))
                        self.assertEqual(execution[-40:], receipt[76:116])
                    for lane in ("fixed", "variable"):
                        denied = invoke(db, held, lane)
                        self.assertEqual((denied["status"], denied["projection"], denied["replay_calls"]),
                                         (100, None, 0), denied)
                    cursor = invoke(db, held, "cursor")
                    independent = invoke(db, held, "execution")
                    self.assertEqual((cursor["status"], cursor["replay_calls"], cursor["replay_locks"],
                                      cursor["released"]), (0, 3, 3, 0), cursor)
                    self.assertTrue(cursor["held"])
                    self.assertEqual(bytes.fromhex(cursor["projection"]), actual)
                    self.assertEqual(cursor["transcript"], independent["transcript"])
                    self.assertEqual(cursor["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                    for ordinal, control in ((1, "root"), (2, "id"), (3, "state")):
                        refused = invoke(db, held, "cursor", failed=control, ordinal=ordinal)
                        self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                         (100, None, ordinal), refused)
                        self.assertGreater(refused["released"], 0)
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
            self.assertEqual(len(extents), 2)
