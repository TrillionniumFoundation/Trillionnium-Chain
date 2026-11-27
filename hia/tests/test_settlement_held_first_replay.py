"""One actual original AdmitReceipt replay performed while SQLite remains held."""
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
from hia.tests.test_settlement_kernel_state_shape import frames
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
                    "pair": OWNER / "held_pair_replay.hepta",
                    "rollup": OWNER / "held_rollup_replay.hepta",
                    "settle": OWNER / "held_settle_replay.hepta",
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
            files = [root / f"retained-{i}" for i in range(5)]
            for file, data in zip(files, list(retained_commands()), strict=True):
                file.write_bytes(data)
            uri = modules["uri"]

            def invoke(store, binder, *, lane="replay", lock=False, control=None, step=None):
                module = modules[lane]
                req = {"reader": [str(module.library), module.artifact_sha256],
                       "uri": [str(uri.library), uri.artifact_sha256],
                       "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                       "directory": str(owned), "database": str(store),
                       "writer": str(original) if lock else None, "journal_binding": binder.hex()}
                if lane in ("replay", "pair", "rollup", "settle"):
                    req["first_replay_engine"] = [str(public), report["artifact"]["sha256"]]
                    req["receipt_replay_limit"] = {"replay": 1, "pair": 2, "rollup": 3, "settle": 4}[lane]
                if control:
                    req["first_replay_fixture_control"] = control
                if step is not None:
                    req["first_replay_fixture_control_step"] = step
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


            for label, commands, empty_tail in (
                ("one", files[1:2], "0"), ("two", files[1:3], "0"),
                ("two-with-empty-tail", files[1:3], "1"), ("rollup", files[1:4], "0"),
            ):
                with self.subTest(pair_fixture=label):
                    store = owned / f"actual pair {label}?.db"
                    binding = execute([original, "seed-receipts", store, files[0], empty_tail, *commands]).stdout
                    before = store.read_bytes()
                    result = invoke(store, binding, lane="pair", lock=label == "two")
                    if label == "two":
                        expected = execute([original, "verify-journal", store, files[0]]).stdout
                        control = invoke(store, binding, lane="execution")
                        self.assertEqual((result["status"], result["replay_calls"], result["replay_locks"],
                                          result["released"]), (0, 2, 2, 0))
                        self.assertEqual(bytes.fromhex(result["projection"]), expected)
                        self.assertEqual(result["transcript"], control["transcript"])
                        self.assertEqual(result["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        for ordinal, control in ((1, "root"), (2, "state"), (2, "count")):
                            refused = invoke(store, binding, lane="pair", control=control, step=ordinal)
                            self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                             (100, None, ordinal))
                            self.assertGreater(refused["released"], 0)
                            self.assertEqual(refused["transcript"][-1][:2], [54, 8])
                    else:
                        self.assertEqual((result["status"], result["projection"], result["replay_calls"]),
                                         (100, None, 1 if empty_tail == "1" else 0))
                        self.assertGreater(result["released"], 0)
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())

            for label, commands, empty_tail in (
                ("two", files[1:3], "0"), ("three", files[1:4], "0"),
                ("rollup-with-empty-tail", files[1:4], "1"),
            ):
                with self.subTest(rollup_fixture=label):
                    store = owned / f"original rollup {label}?.db"
                    binding = execute([original, "seed-receipts", store, files[0], empty_tail, *commands]).stdout
                    before = store.read_bytes()
                    result = invoke(store, binding, lane="rollup", lock=label == "three")
                    if label == "three":
                        expected = execute([original, "verify-journal", store, files[0]]).stdout
                        root_and_state = execute([original, "observe-actual-state-root", store, files[0]]).stdout
                        self.assertEqual(len(root_and_state), 32 + 3185)
                        self.assertEqual((result["status"], result["replay_calls"], result["replay_locks"],
                                          result["released"]), (0, 3, 3, 0), result)
                        self.assertEqual(bytes.fromhex(result["projection"]), expected)
                        self.assertEqual(result["transcript"], invoke(store, binding, lane="execution")["transcript"])
                        self.assertEqual(result["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        self.assertEqual(expected[90:122], root_and_state[:32])
                        for ordinal, control in ((2, "root"), (3, "state"), (3, "id")):
                            refused = invoke(store, binding, lane="rollup", control=control, step=ordinal)
                            self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                             (100, None, ordinal))
                            self.assertGreater(refused["released"], 0)
                            self.assertEqual(refused["transcript"][-1][:2], [54, 8])
                    else:
                        self.assertEqual((result["status"], result["projection"], result["replay_calls"]),
                                         (100, None, 2 if empty_tail == "1" else 0), result)
                        self.assertGreater(result["released"], 0)
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())

            for label in ("real-settle", "prefix", "interval"):
                with self.subTest(settle_fixture=label):
                    store = owned / f"original settle {label}?.db"
                    binding = execute([original, "seed-receipts", store, files[0], "0",
                                       *files[1:4], "-", "-", files[4]]).stdout
                    expected = execute([original, "verify-journal", store, files[0]]).stdout
                    witness = execute([original, "observe-settled-state-id", store, files[0]]).stdout
                    settle_id, final_root, canonical, *operations = frames(witness)
                    self.assertEqual((len(canonical), len(operations), len(operations[-1]), settle_id[0]),
                                     (4870, 12, 181, 1))
                    self.assertEqual(operations[-1][148:], settle_id)
                    self.assertEqual(expected[90:122], final_root)
                    if label != "real-settle":
                        execute([original, "fixture-empty-marker-interval-drift", store, files[0], label])
                        refusal = subprocess.run([original, "verify-journal", store, files[0]],
                                                 capture_output=True, check=False, timeout=30)
                        self.assertNotEqual(refusal.returncode, 0)
                        self.assertEqual(refusal.stdout, b"")
                    before = store.read_bytes()
                    former = invoke(store, binding, lane="execution")
                    self.assertEqual(former["status"], 0, former)
                    original_read = invoke(store, binding, lane="settle", lock=label == "real-settle")
                    if label == "real-settle":
                        self.assertEqual((original_read["status"], original_read["replay_calls"],
                                          original_read["replay_locks"], original_read["released"]),
                                         (0, 4, 4, 0), original_read)
                        self.assertEqual(bytes.fromhex(original_read["projection"]), expected)
                        self.assertEqual(original_read["transcript"], former["transcript"])
                        self.assertEqual(original_read["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                        refused = invoke(store, binding, lane="settle", control="state", step=4)
                        self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                         (100, None, 4), refused)
                        self.assertGreater(refused["released"], 0)
                    else:
                        # Missing valid Settle interval now refuses before an Engine
                        # call. A root mismatch still needs the replayed root table.
                        early = label == "interval"
                        self.assertEqual((original_read["status"], original_read["projection"],
                                          original_read["replay_calls"]),
                                         (100, None, 0 if early else 4), original_read)
                        self.assertGreater(original_read["released"], 0)
                        self.assertEqual(original_read["transcript"][-1],
                                         [54, 8, 173] if early else [52, 7, 24])
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())

            roots = {}
            cases = [(before, str(after)) for before in (2, 3, 4) for after in range(3)]
            cases += [(5, "0"), (2, "3"), (4, "3")]
            for empty_count, trailing in cases:
                with self.subTest(actual_empty_before_settle=empty_count, trailing=trailing):
                    store = owned / f"delayed settle {empty_count}+{trailing}?.db"
                    binding = execute([original, "seed-receipts", store, files[0], trailing,
                                       *files[1:4], *(["-"] * empty_count), files[4]]).stdout
                    expected = execute([original, "verify-journal", store, files[0]]).stdout
                    self.assertEqual(int.from_bytes(expected[:8], "little"), empty_count + 5 + int(trailing))
                    _, terminal_root, canonical, *ops = frames(
                        execute([original, "observe-settled-state-id", store, files[0]]).stdout)
                    self.assertEqual((len(canonical), len(ops)), (4870, 12))
                    self.assertEqual(int.from_bytes(ops[-3][123:131], "little"), 13 + empty_count)
                    self.assertEqual(expected[90:122], terminal_root)
                    before = store.read_bytes()
                    competing = empty_count == 4 and trailing == "2"
                    guarded = invoke(store, binding, lane="settle", lock=competing)
                    if empty_count <= 4 and int(trailing) <= 2:
                        self.assertEqual((guarded["status"], guarded["replay_calls"], guarded["released"]),
                                         (0, 4, 0), guarded)
                        self.assertEqual(guarded["replay_locks"], 4 if competing else 0)
                        self.assertEqual(bytes.fromhex(guarded["projection"]), expected)
                        self.assertEqual(guarded["transcript"], invoke(store, binding, lane="execution")["transcript"])
                        self.assertEqual(int.from_bytes(expected[50:58], "little"),
                                         13 + empty_count + int(trailing))
                        _, prefixes, markers = frames(execute(
                            [original, "observe-actual-journal-prefixes", store, files[0]]).stdout)
                        self.assertEqual(len(prefixes), 160)
                        self.assertEqual(len(markers), (empty_count + 5 + int(trailing)) * 80)
                        settle_at = (4 + empty_count) * 80
                        self.assertEqual(markers[settle_at:settle_at+16],
                                         (3).to_bytes(8, "little") + (4).to_bytes(8, "little"))
                        for at in range(settle_at+80, len(markers), 80):
                            self.assertEqual(markers[at:at+80],
                                             (4).to_bytes(8, "little") * 2 + prefixes[-32:] * 2)
                        if empty_count in roots:
                            self.assertEqual(roots[empty_count], (terminal_root, prefixes[-32:]))
                        else:
                            self.assertNotIn((terminal_root, prefixes[-32:]), roots.values())
                            roots[empty_count] = terminal_root, prefixes[-32:]
                    else:
                        self.assertEqual((guarded["status"], guarded["projection"], guarded["replay_calls"]),
                                         (100, None, 0), guarded)
                        self.assertGreater(guarded["released"], 0)
                    self.assertEqual(store.read_bytes(), before)
                    self.assertFalse(store.with_name(store.name + "-journal").exists())

            store = owned / "owned trailing state drift.db"
            binding = execute([original, "seed-receipts", store, files[0], "2",
                               *files[1:4], "-", "-", files[4]]).stdout
            before = execute([original, "verify-journal", store, files[0]]).stdout
            execute([original, "fixture-trailing-empty-state-drift", store, files[0]])
            immutable = store.read_bytes()
            retained = subprocess.run([original, "verify-journal", store, files[0]],
                                      capture_output=True, timeout=30, check=False)
            self.assertNotEqual(retained.returncode, 0)
            self.assertIn(b"committed-block marker target state differs from its operation range",
                          retained.stderr)
            weaker = invoke(store, binding, lane="execution")
            self.assertEqual((weaker["status"], weaker["released"]), (0, 0), weaker)
            self.assertEqual(bytes.fromhex(weaker["projection"])[40:], before[40:])
            denied = invoke(store, binding, lane="settle")
            self.assertEqual((denied["status"], denied["projection"], denied["replay_calls"]),
                             (100, None, 4), denied)
            self.assertEqual(denied["transcript"][-1], [52, 7, 24])
            self.assertGreater(denied["released"], 0)
            self.assertEqual(store.read_bytes(), immutable)
            self.assertFalse(store.with_name(store.name + "-journal").exists())
