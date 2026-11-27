"""Actual held original Store replay with measured, bounded widths."""
from contextlib import ExitStack
import json
import struct
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


class SettlementHeldVariableFirstReplayTests(unittest.TestCase):
    def test_measured_original_utf8_context_lengths_through_sealed_held_apply(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-var-replay-")))
            original, source = original_adapter(tmp, marker=True, same_block=True)
            provider = ProviderBuild(source, tmp / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            images = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for name, path in {
                          "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                          "variable": OWNER / "held_variable_first_replay.hepta",
                          "fixed": OWNER / "held_first_replay.hepta",
                          "execution": OWNER / "execution_journal_read.hepta",
                      }.items()}
            out = tmp / "engine"
            engine = json.loads(execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                                        "--output", out], timeout=200).stdout)
            self.assertEqual((engine["status"], engine["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))
            owned = tmp / "owned"
            owned.mkdir(mode=0o700)

            def invoke(path, binding, lane, *, failed=None):
                def image(name):
                    module = images[name]
                    return [str(module.library), module.artifact_sha256]

                request = {"reader": image(lane), "uri": image("uri"),
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(owned), "database": str(path),
                           "journal_binding": binding.hex()}
                if lane in ("fixed", "variable"):
                    request["first_replay_engine"] = [str(out/"public"), engine["artifact"]["sha256"]]
                    request["variable_first_fixture"] = lane == "variable"
                if lane == "variable" and failed is None:
                    request["writer"] = str(original)
                if failed is not None:
                    request["first_replay_fixture_control"] = failed
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=60)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            extents = set()
            for mode in ("short", "utf8"):
                with self.subTest(fixture=mode):
                    trust, command, genesis, state = frames(execute([tmp/"same-block-fixture", mode]).stdout)
                    paths = [tmp/f"{mode}-{label}" for label in ("trust", "command")]
                    for file, raw in zip(paths, (trust, command), strict=True):
                        file.write_bytes(raw)
                    db = owned/f"actual {mode} original #?.db"
                    held = execute([original, "seed-receipts", db, paths[0], "0", paths[1]]).stdout
                    pristine = db.read_bytes()
                    actual = execute([original, "verify-journal", db, paths[0]]).stdout
                    settled, root, stored, execution, actual_command, receipt = frames(execute(
                        [original, "observe-settled-state-id", db, paths[0]]).stdout)
                    self.assertEqual((settled, root, stored, actual_command, len(receipt)),
                                     (bytes(33), raw_digest(state), state, command, 149))
                    delta = len(trust) - 882
                    self.assertNotEqual(delta, 0)
                    extents.add((len(held), len(execution), len(command), len(stored)))
                    self.assertEqual((len(held), len(execution), len(command), len(stored), len(genesis)),
                                     (1018+delta, 163+delta, 868+delta, 1196+delta, 279))
                    self.assertEqual((execution[-80:-72], execution[-40:-32]),
                                     ((9).to_bytes(8, "little"), (10).to_bytes(8, "little")))
                    earlier = invoke(db, held, "fixed")
                    self.assertEqual((earlier["status"], earlier["projection"], earlier["replay_calls"]),
                                     (100, None, 0), earlier)
                    native = invoke(db, held, "variable")
                    independent = invoke(db, held, "execution")
                    self.assertEqual((native["status"], native["replay_calls"], native["replay_locks"],
                                      native["released"]), (0, 1, 1, 0), native)
                    self.assertTrue(native["held"])
                    self.assertEqual(bytes.fromhex(native["projection"]), actual)
                    self.assertEqual(native["transcript"], independent["transcript"])
                    self.assertEqual(native["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
                    for control in ("id", "root", "state"):
                        denied = invoke(db, held, "variable", failed=control)
                        self.assertEqual((denied["status"], denied["projection"], denied["replay_calls"]),
                                         (100, None, 1), denied)
                        self.assertEqual(denied["transcript"][-1][:2], [54, 8])
                        self.assertGreater(denied["released"], 0)
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
            self.assertEqual(len(extents), 2)

            for backend, mode in (("direct", "short"), ("selfhost", "utf8")):
                with self.subTest(prospective=mode, backend=backend):
                    trust, first, _, _, second, _ = frames(execute(
                        [tmp/"same-block-fixture", mode+"-pair"]).stdout)
                    bundle, cmd1, cmd2 = (tmp/f"later-{mode}-{i}" for i in range(3))
                    for f, body in zip((bundle, cmd1, cmd2), (trust, first, second), strict=True):
                        f.write_bytes(body)
                    db = owned/f"actual later prospective {mode} #?.db"
                    binding = execute([original, "seed-receipts", db, bundle, "0", cmd1]).stdout
                    pristine = db.read_bytes()
                    source_bytes = execute([original, "verify-journal", db, bundle]).stdout
                    pre, reader, codec = [stack.enter_context(NativeModule(
                        OWNER/name, byte_exports=("f0",), backend=backend))
                        for name in ("preview_live_receipt.hepta", "held_variable_first_replay.hepta",
                                     "receipt_command_id.hepta")]

                    def image(module):
                        return [str(module.library), module.artifact_sha256]

                    req = dict(reader=image(reader), uri=image(images["uri"]),
                               provider=[str(provider), proof.checked[str(provider)]["sha256"]],
                               directory=str(owned), database=str(db), journal_binding=binding.hex(),
                               first_replay_engine=[str(out/"public"), engine["artifact"]["sha256"]],
                               variable_first_fixture=True, writer=str(original))
                    for tag, cmd in (("success", cmd2), ("duplicate", cmd1), ("old-genesis", cmd2)):
                        frame, command, witnessed = frames(execute(
                            [original, "observe-held-perspective-receipt", db, bundle, cmd, tag]).stdout)
                        status, = struct.unpack_from("<I", witnessed)
                        attempt = dict(req, live_preview=image(pre), live_preview_codec=image(codec),
                                       live_preview_frame=frame.hex(), live_preview_command=command.hex())
                        answer = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                         input=json.dumps(attempt).encode(), timeout=60)
                        self.assertEqual(answer.stderr, b"")
                        result = json.loads(answer.stdout)
                        self.assertEqual(result.pop("live_preview"),
                                         [status, witnessed[4:].hex() if status == 0 else None, int(status == 0)])
                        self.assertEqual(bytes.fromhex(result["projection"]), source_bytes)
                        self.assertEqual((result["status"], result["replay_calls"], result["released"],
                                          result["transcript"][-2:]), (0, 1, 0, [[55, 9, 24], [56, 3, 24]]))
                    self.assertEqual(execute([original, "verify-journal", db, bundle]).stdout, source_bytes)
                    self.assertEqual(db.read_bytes(), pristine)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())

            for backend in ("direct", "selfhost"):
                pre, reader, codec = [stack.enter_context(NativeModule(
                    OWNER/name, byte_exports=("f0",), backend=backend))
                    for name in ("preview_live_rollup.hepta", "held_variable_first_replay.hepta",
                                 "rollup_command_id.hepta")]
                for mode, tag, expected in (("preview-rollup", "rollup", 0),
                                            ("preview-unfinishable-rollup", "rollup-unfinishable", 101)):
                    with self.subTest(backend=backend, prospective=mode):
                        trust, first, rollup = frames(execute([tmp/"same-block-fixture", mode]).stdout)
                        files = [tmp/f"{backend}-{mode}-{i}" for i in range(3)]
                        for file, data in zip(files, (trust, first, rollup), strict=True):
                            file.write_bytes(data)
                        bundle, receipt_file, rollup_file = files
                        db = owned/f"original mixed prospective {backend} {mode} #?.db"
                        binding = execute([original, "seed-receipts", db, bundle, "0", receipt_file]).stdout
                        pristine = db.read_bytes()
                        source_bytes = execute([original, "verify-journal", db, bundle]).stdout
                        frame, command, value = frames(execute(
                            [original, "observe-held-perspective-receipt", db, bundle, rollup_file, tag]).stdout)
                        self.assertEqual((struct.unpack_from("<I", value)[0], command), (expected, rollup))

                        def seal(module):
                            return [str(module.library), module.artifact_sha256]

                        request = dict(reader=seal(reader), uri=seal(images["uri"]),
                                       provider=[str(provider), proof.checked[str(provider)]["sha256"]],
                                       directory=str(owned), database=str(db), journal_binding=binding.hex(),
                                       first_replay_engine=[str(out/"public"), engine["artifact"]["sha256"]],
                                       variable_first_fixture=True, writer=str(original),
                                       live_rollup_preview=seal(pre), live_preview_codec=seal(codec),
                                       live_preview_frame=frame.hex(), live_preview_command=command.hex())
                        got = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                      input=json.dumps(request).encode(), timeout=60)
                        self.assertEqual(got.stderr, b"")
                        answer = json.loads(got.stdout)
                        self.assertEqual(answer.pop("live_preview"),
                                         [expected, value[4:].hex() if expected == 0 else None, 1])
                        self.assertEqual(bytes.fromhex(answer["projection"]), source_bytes)
                        self.assertEqual((answer["status"], answer["released"], answer["transcript"][-2:]),
                                         (0, 0, [[55, 9, 24], [56, 3, 24]]))
                        self.assertEqual(execute([original, "verify-journal", db, bundle]).stdout, source_bytes)
                        self.assertEqual(db.read_bytes(), pristine)
                        self.assertFalse(db.with_name(db.name+"-journal").exists())
