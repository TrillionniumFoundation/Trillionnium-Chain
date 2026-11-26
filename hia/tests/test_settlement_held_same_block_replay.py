"""Actual original same-block receipt/rollup through the sealed held HIA replay."""
from contextlib import ExitStack
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_kernel_state_shape import frames
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_state_root_read import raw_digest
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


class SettlementHeldSameBlockReplayTests(unittest.TestCase):
    def test_real_receipt_and_rollup_share_exact_order_coordinates(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-held-same-")))
            original, source = original_adapter(root, marker=True, same_block=True)
            trust, receipt, rollup, genesis, intermediate, final = frames(
                execute([root / "same-block-fixture"]).stdout)
            self.assertEqual(tuple(map(len, (trust, receipt, rollup, genesis, intermediate, final))),
                             (882, 868, 1758, 279, 1196, 2172))
            owned = root / "owned"
            owned.mkdir(mode=0o700)
            inputs = [root / f"generated-{i}" for i in range(3)]
            for file, raw in zip(inputs, (trust, receipt, rollup), strict=True):
                file.write_bytes(raw)
            same = owned / "original same block #?.db"
            binding = execute([original, "seed-same-block", same, inputs[0], "0", *inputs[1:]]).stdout
            self.assertEqual(len(binding), 1018)
            before = same.read_bytes()
            expected = execute([original, "verify-journal", same, inputs[0]]).stdout
            optional_id, state_root, state, e1, command1, r1, e2, command2, r2 = frames(
                execute([original, "observe-settled-state-id", same, inputs[0]]).stdout)
            self.assertEqual((state, optional_id, state_root), (final, bytes(33), raw_digest(final)))
            self.assertEqual((command1, command2), (receipt, rollup))
            self.assertEqual((len(e1), len(e2), len(r1), len(r2)), (163, 163, 149, 149))
            self.assertEqual(e1[-40:], e2[-40:])
            self.assertEqual(e2[-80:-40], e1[-40:])
            self.assertEqual(r1[116:148], raw_digest(intermediate))
            self.assertEqual(r2[116:148], raw_digest(final))
            _, prefixes, marks = frames(execute([original, "observe-actual-journal-prefixes", same, inputs[0]]).stdout)
            self.assertEqual([m[:2] for m in struct.iter_unpack("<QQ32s32s", marks)], [(0, 0), (0, 2)])
            self.assertEqual((marks[16:48], marks[-64:-32], marks[-32:]),
                             (prefixes[:32], prefixes[:32], prefixes[-32:]))

            images = {key: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for key, path in (
                        ("uri", ROOT / "hia/src/service_settlement/read_only_store_uri.hepta"),
                        ("old", OWNER / "execution_journal_read.hepta"),
                        ("pair", OWNER / "held_pair_replay.hepta"),
                        ("same", OWNER / "held_same_block_replay.hepta"),
                      )}
            provider = ProviderBuild(source, root / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            native = root / "fresh-native"
            build = json.loads(execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                                        "--output", native], timeout=200).stdout)
            self.assertEqual((build["status"], build["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))

            def invoke(db, bind, lane, *, hold=False, mode=None, ordinal=None):
                def image(name):
                    m = images[name]
                    return [str(m.library), m.artifact_sha256]

                request = {"reader": image(lane), "uri": image("uri"),
                           "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                           "directory": str(owned), "database": str(db), "journal_binding": bind.hex(),
                           "writer": str(original) if hold else None}
                if lane != "old":
                    request.update(first_replay_engine=[str(native / "public"), build["artifact"]["sha256"]],
                                   receipt_replay_limit=2, same_block_fixture=lane == "same")
                if mode is not None:
                    request.update(first_replay_fixture_control=mode, first_replay_fixture_control_step=ordinal)
                return json.loads(execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                          input=json.dumps(request).encode(), timeout=60).stdout)

            observed = invoke(same, binding, "same", hold=True)
            legacy = invoke(same, binding, "old")
            self.assertEqual((observed["status"], observed["replay_calls"], observed["replay_locks"],
                              observed["released"]), (0, 2, 2, 0), observed)
            self.assertEqual(bytes.fromhex(observed["projection"]), expected)
            self.assertEqual(observed["transcript"], legacy["transcript"])
            self.assertEqual(observed["transcript"][-2:], [[55, 9, 24], [56, 3, 24]])
            for kind, position in (("root", 1), ("state", 2)):
                refused = invoke(same, binding, "same", mode=kind, ordinal=position)
                self.assertEqual((refused["status"], refused["projection"], refused["replay_calls"]),
                                 (100, None, position), refused)
                self.assertGreater(refused["released"], 0)
            self.assertEqual(invoke(same, binding, "pair")["replay_calls"], 0)
            self.assertEqual(same.read_bytes(), before)

            different = owned / "different blocks.db"
            ordinary = [root / f"consecutive-{i}" for i in range(3)]
            for file, raw in zip(ordinary, list(retained_commands())[:3], strict=True):
                file.write_bytes(raw)
            distinct = execute([original, "seed-receipts", different, ordinary[0], "0", *ordinary[1:]]).stdout
            rejected = invoke(different, distinct, "same")
            self.assertEqual((rejected["status"], rejected["replay_calls"], rejected["projection"]),
                             (100, 0, None))
