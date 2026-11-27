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


class SettlementHeldVariableSettleReplayTests(unittest.TestCase):
    def test_actual_mixed_variable_replay_preserves_challenge_intervals(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-var-mixed-")))
            original, source = original_adapter(tmp, marker=True, same_block=True)
            provider = ProviderBuild(source, tmp / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            images = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for name, path in {
                          "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                          "variable": OWNER / "held_variable_settle_replay.hepta",
                          "fixed": OWNER / "held_settle_replay.hepta",
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
                if lane in ("fixed", "variable"):
                    request["first_replay_engine"] = [str(out/"public"), engine["artifact"]["sha256"]]
                    request["variable_settle_fixture"] = lane == "variable"
                    request["receipt_replay_limit"] = 4
                if lane == "variable" and failed is None:
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
                    fields = frames(execute([tmp/"same-block-fixture", mode+"-settle"]).stdout)
                    trust, one, genesis, state1, two, state2, three, state3, four, state4, identity = fields
                    commands = (one, two, three, four)
                    states = (state1, state2, state3, state4)
                    paths = [tmp/f"{mode}-{i}" for i in range(5)]
                    for path, raw in zip(paths, (trust, *commands), strict=True):
                        path.write_bytes(raw)
                    db = owned/f"actual {mode} settlement #?.db"
                    held = execute([original, "seed-receipts", db, paths[0], "0",
                                    *paths[1:4], "-", "-", paths[4]]).stdout
                    pristine = db.read_bytes()
                    actual = execute([original, "verify-journal", db, paths[0]]).stdout
                    settled, root, stored, *rows = frames(execute(
                        [original, "observe-settled-state-id", db, paths[0]]).stdout)
                    self.assertEqual((settled, root, stored, len(rows)),
                                     (bytes([1])+identity, raw_digest(state4), state4, 12))
                    extents.add((len(trust), len(rows[0]), *(len(command) for command in commands),
                                 *(len(state) for state in states)))
                    for i, (height, parent, kind) in enumerate(zip((10,11,12,15), (9,10,11,14), (24,24,25,26))):
                        execution, command, receipt = rows[i*3:i*3+3]
                        self.assertEqual(command, commands[i])
                        self.assertEqual((int.from_bytes(execution[-40:-32], "little"),
                                          int.from_bytes(execution[-80:-72], "little"),
                                          int.from_bytes(receipt[74:76], "little")), (height, parent, kind))
                        optional = bytes([1])+identity if i == 3 else bytes(1)
                        self.assertEqual(receipt[116:], raw_digest(states[i])+optional)
                        self.assertEqual(execution[-40:], receipt[76:116])
                    before = invoke(db, held, "fixed")
                    self.assertEqual((before["status"], before["projection"], before["replay_calls"]),
                                     (100, None, 0), before)
                    native = invoke(db, held, "variable")
                    independent = invoke(db, held, "execution")
                    self.assertEqual((native["status"], native["replay_calls"], native["replay_locks"],
                                      native["released"]), (0, 4, 4, 0), native)
                    self.assertTrue(native["held"])
                    self.assertEqual(bytes.fromhex(native["projection"]), actual)
                    self.assertEqual(native["transcript"], independent["transcript"])
                    self.assertEqual(native["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                    # Corrupt actual sealed replies after the observed engine call, not any Store bytes.
                    for ordinal, control in ((1, "root"), (3, "id"), (4, "state")):
                        refused = invoke(db, held, "variable", failed=control, ordinal=ordinal)
                        self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                         (100, None, ordinal), refused)
                        self.assertGreater(refused["released"], 0)
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
            self.assertEqual(len(extents), 2)
