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
    def test_actual_original_short_rollup_mixed_and_linear_cursor_dispatch(self):
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
            images["cursor-direct"] = stack.enter_context(NativeModule(
                OWNER / "held_cursor_variable_dispatch.hepta", byte_exports=("f0",), backend="direct"))
            for backend in ("direct", "selfhost"):
                images["mixed-" + backend] = stack.enter_context(NativeModule(
                    OWNER / "held_mixed_plan_replay.hepta", byte_exports=("f0",), backend=backend))
            physical_images = {
                backend: {
                    name: stack.enter_context(NativeModule(OWNER / source, byte_exports=("f0",), backend=backend))
                    for name, source in {
                        "path_gate": "store_path_preflight.hepta", "header_reader": "store_header_read.hepta",
                        "post_open_path": "store_post_open_path.hepta",
                    }.items()
                }
                for backend in ("direct", "selfhost")
            }
            lifecycle_images = {
                backend: stack.enter_context(NativeModule(
                    OWNER / "store_open_lifecycle.hepta", byte_exports=("f0",), backend=backend))
                for backend in ("direct", "selfhost")
            }
            out = tmp / "engine"
            engine = json.loads(execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                                        "--output", out], timeout=200).stdout)
            self.assertEqual((engine["status"], engine["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))
            owned = tmp / "owned"
            owned.mkdir(mode=0o700)

            def invoke(path, binding, lane, *, failed=None, ordinal=4, physical=None, lifecycle=None):
                def image(name):
                    module = images[name]
                    return [str(module.library), module.artifact_sha256]

                request = {"reader": image(lane), "uri": image("uri"),
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(owned), "database": str(path),
                           "journal_binding": binding.hex()}
                if physical is not None:
                    request.update({name: [str(module.library), module.artifact_sha256]
                                    for name, module in physical_images[physical].items()})
                if lifecycle is not None:
                    module = lifecycle_images[lifecycle]
                    request["open_lifecycle"] = [str(module.library), module.artifact_sha256]
                if lane != "execution":
                    request["first_replay_engine"] = [str(out/"public"), engine["artifact"]["sha256"]]
                    request["variable_stream_fixture"] = True
                    if lane.startswith("mixed-"):
                        request["mixed_plan_fixture"] = True
                    else:
                        request["cursor_stream_fixture"] = True
                if lane != "execution" and failed is None:
                    request["writer"] = str(original)
                if failed is not None:
                    request.update(first_replay_fixture_control=failed, first_replay_fixture_control_step=ordinal)
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=60)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            specs = (
                ("one", "short", (1,), True, None),
                ("linear-two", "utf8-pair", (1, 4), True, None),
                ("fixed-same-block", None, (1, 2), True, None),
                ("measured-same-block", "short-same-block", (1, 2), True, None),
                ("rollup", "short-rollup", (1, 4, 6), True, None),
                ("settle", "utf8-settle", (1, 4, 6, "-", "-", 8), True, None),
                ("linear-six", "utf8-linear-admits", (1, 2, 3, 4, 5, 6), True, None),
                ("wrong-third-kind", "short-linear-admits", (1, 2, 3), False, 2),
                ("wrong-four-markers", "utf8-linear-admits", (1, 2, 3, 4), False, 0),
            )
            for name, fixture, indices, accepted, denied_after in specs:
                with self.subTest(fixture=name):
                    fixture_cmd = [tmp/"same-block-fixture"] + ([fixture] if fixture else [])
                    fields = list(frames(execute(fixture_cmd).stdout))
                    trust = fields[0]
                    paths = {}
                    for index in (0, *(i for i in indices if i != "-")):
                        paths[index] = tmp/f"{name}-{index}"
                        paths[index].write_bytes(fields[index])
                    db = owned/f"actual {name} checked dispatch #?.db"
                    seed = "seed-same-block" if "same-block" in name else "seed-receipts"
                    held = execute([original, seed, db, paths[0], "0",
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
                    if "same-block" in name:
                        first, second = rows[0], rows[3]
                        self.assertEqual(first[-40:], second[-40:])
                        self.assertEqual(second[-80:-40], first[-40:])
                        dimensions = (len(held) - 104, len(first), len(terminal))
                        if name == "fixed-same-block":
                            self.assertEqual(dimensions, (914, 163, 2172))
                        else:
                            for actual_width, old_width in zip(dimensions, (914, 163, 2172), strict=True):
                                self.assertNotEqual(actual_width, old_width)
                    cursor = invoke(db, held, "cursor")
                    independent = invoke(db, held, "execution")
                    self.assertEqual(independent["status"], 0, independent)
                    self.assertEqual(bytes.fromhex(independent["projection"]), original_out)
                    self.assertTrue(cursor["held"])
                    if name == "fixed-same-block":
                        self.assertEqual(cursor["replay_profile"], 5)
                    if name == "measured-same-block":
                        self.assertEqual(cursor["replay_profile"], 11)
                        alternate = invoke(db, held, "cursor-direct")
                        self.assertEqual(alternate, cursor)
                        bad_parent = invoke(db, held, "cursor", failed="root", ordinal=1)
                        self.assertEqual((bad_parent["status"], bad_parent["projection"], bad_parent["replay_calls"],
                                          bad_parent["replay_profile"]), (100, None, 1, 11))
                        self.assertGreater(bad_parent["released"], 0)
                    if accepted:
                        self.assertEqual((cursor["status"], cursor["replay_calls"], cursor["replay_locks"],
                                          cursor["released"]), (0, count, count, 0), cursor)
                        self.assertEqual(bytes.fromhex(cursor["projection"]), original_out)
                        self.assertEqual(cursor["transcript"], independent["transcript"])
                        self.assertEqual(cursor["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        if name == "settle":
                            for lane in ("mixed-selfhost", "mixed-direct"):
                                with self.subTest(planned=lane):
                                    planned = invoke(db, held, lane)
                                    self.assertEqual(planned, {**cursor, "replay_profile": 13})
                            drift = invoke(db, held, "mixed-selfhost", failed="root", ordinal=3)
                            self.assertEqual((drift["status"], drift["projection"], drift["replay_calls"]),
                                             (100, None, 3))
                            self.assertGreater(drift["released"], 0)
                            later = owned / "mixed after original trailing checkpoint.db"
                            trailing_binding = execute([original, "seed-receipts", later, paths[0], "0",
                                                        *(paths[i] if i != "-" else "-" for i in indices), "-"]).stdout
                            trailing_ref = execute([original, "verify-journal", later, paths[0]]).stdout
                            self.assertNotEqual(trailing_ref, original_out)
                            trailing_before = later.read_bytes()
                            for lane in ("mixed-selfhost", "mixed-direct"):
                                with self.subTest(trailing=lane):
                                    trailing = invoke(later, trailing_binding, lane)
                                    self.assertEqual((trailing["status"], trailing["replay_profile"], trailing["replay_calls"],
                                                      trailing["replay_locks"], trailing["released"]), (0, 13, 4, 4, 0))
                                    self.assertEqual(bytes.fromhex(trailing["projection"]), trailing_ref)
                            self.assertEqual(later.read_bytes(), trailing_before)
                            for backend in physical_images:
                                with self.subTest(physical=backend):
                                    fully_held = invoke(db, held, "cursor", physical=backend)
                                    self.assertEqual(fully_held, {
                                        **cursor, "path_checks": [[i, 15, 24] for i in range(1, 5)],
                                        "header_checks": [[17, 24], [29, 44], [18, 24]], "post_open_checks": [[15, 24]],
                                        "transcript": [cursor["transcript"][0], [1, 15, 24], *cursor["transcript"][1:]],
                                    })
                            for backend in lifecycle_images:
                                with self.subTest(composed=backend):
                                    composed = invoke(db, held, "cursor", lifecycle=backend)
                                    trace = [[1, 15, 24]] * 4 + [[3, 17, 24], [3, 29, 44], [3, 18, 24],
                                                               [5, 2, 24], [6, 15, 24]]
                                    self.assertEqual(composed, {
                                        **cursor, "open_lifecycle": trace,
                                        "transcript": [cursor["transcript"][0], [1, 15, 24], *cursor["transcript"][1:]],
                                    })
                        refused = invoke(db, held, "cursor", failed="root", ordinal=count)
                        self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                         (100, None, count), refused)
                        self.assertGreater(refused["released"], 0)
                    else:
                        if name == "wrong-four-markers":
                            rejected_plan = invoke(db, held, "mixed-selfhost")
                            self.assertEqual((rejected_plan["status"], rejected_plan["projection"]),
                                             (100, None), rejected_plan)
                        self.assertEqual((cursor["status"], cursor["projection"], cursor["replay_calls"],
                                          cursor["replay_locks"]), (100, None, denied_after, denied_after), cursor)
                        self.assertGreater(cursor["released"], 0)
                        self.assertNotIn(56, [phase for phase, _, _ in cursor["transcript"]])
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
