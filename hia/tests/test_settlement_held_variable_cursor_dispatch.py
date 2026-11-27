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


class SettlementHeldVariableCursorDispatchTests(unittest.TestCase):
    def test_actual_original_rollup_mixed_and_linear_cursor_dispatch(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-var-dispatch-")))
            original, source = original_adapter(tmp, marker=True, same_block=True)
            provider = ProviderBuild(source, tmp / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            images = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for name, path in {
                          "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                          "cursor": OWNER / "held_cursor_variable_dispatch.hepta",
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
                if lane == "cursor":
                    request["first_replay_engine"] = [str(out/"public"), engine["artifact"]["sha256"]]
                    request["variable_stream_fixture"] = True
                    if lane == "cursor":
                        request["cursor_stream_fixture"] = True
                if lane == "cursor" and failed is None:
                    request["writer"] = str(original)
                if failed is not None:
                    request.update(first_replay_fixture_control=failed, first_replay_fixture_control_step=ordinal)
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=60)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            specs = (
                ("rollup", "short-rollup", (1, 4, 6), True, None),
                ("settle", "utf8-settle", (1, 4, 6, "-", "-", 8), True, None),
                ("linear-six", "utf8-linear-admits", (1, 2, 3, 4, 5, 6), True, None),
                ("wrong-third-kind", "short-linear-admits", (1, 2, 3), False, 2),
                ("wrong-four-markers", "utf8-linear-admits", (1, 2, 3, 4), False, 0),
            )
            for name, fixture, indices, accepted, denied_after in specs:
                with self.subTest(fixture=name):
                    fields = list(frames(execute([tmp/"same-block-fixture", fixture]).stdout))
                    trust = fields[0]
                    paths = {}
                    for index in (0, *(i for i in indices if i != "-")):
                        paths[index] = tmp/f"{name}-{index}"
                        paths[index].write_bytes(fields[index])
                    db = owned/f"actual {name} checked dispatch #?.db"
                    held = execute([original, "seed-receipts", db, paths[0], "0",
                                    *(paths[i] if i != "-" else "-" for i in indices)]).stdout
                    pristine = db.read_bytes()
                    original_out = execute([original, "verify-journal", db, paths[0]]).stdout
                    settled, expected_root, terminal, *rows = frames(execute(
                        [original, "observe-settled-state-id", db, paths[0]]).stdout)
                    count = sum(i != "-" for i in indices)
                    command = [fields[i] for i in indices if i != "-"]
                    self.assertEqual(rows[1::3], command)
                    self.assertEqual(len(rows), 3*count)
                    self.assertEqual(expected_root, raw_digest(terminal))
                    self.assertEqual(settled[0], int(name == "settle"))
                    cursor = invoke(db, held, "cursor")
                    independent = invoke(db, held, "execution")
                    self.assertEqual(independent["status"], 0, independent)
                    self.assertEqual(bytes.fromhex(independent["projection"]), original_out)
                    self.assertTrue(cursor["held"])
                    if accepted:
                        self.assertEqual((cursor["status"], cursor["replay_calls"], cursor["replay_locks"],
                                          cursor["released"]), (0, count, count, 0), cursor)
                        self.assertEqual(bytes.fromhex(cursor["projection"]), original_out)
                        self.assertEqual(cursor["transcript"], independent["transcript"])
                        self.assertEqual(cursor["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        refused = invoke(db, held, "cursor", failed="root", ordinal=count)
                        self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                         (100, None, count), refused)
                        self.assertGreater(refused["released"], 0)
                    else:
                        self.assertEqual((cursor["status"], cursor["projection"], cursor["replay_calls"],
                                          cursor["replay_locks"]), (100, None, denied_after, denied_after), cursor)
                        self.assertGreater(cursor["released"], 0)
                        self.assertNotIn(56, [phase for phase, _, _ in cursor["transcript"]])
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
