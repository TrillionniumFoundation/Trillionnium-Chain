"""Derive the final ID from actual canonical states and the sealed Engine successor."""
from contextlib import ExitStack
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from hia.platform.service_settlement.first_replay_fixture_engine import FixtureReplay
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_kernel_state_shape import frames
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_state_root_read import raw_digest
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


class SettlementStateIdentityTests(unittest.TestCase):
    def test_actual_typed_settlement_id_and_native_successor(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-settlement-state-id-")))
            original, _ = original_adapter(root, marker=True)
            inputs = [root / f"retained-{i}" for i in range(5)]
            for file, content in zip(inputs, retained_commands(), strict=True):
                file.write_bytes(content)

            cases = []
            stages = ([], inputs[1:4], [*inputs[1:4], "-", "-", inputs[4]])
            for i, steps in enumerate(stages):
                store = root / f"real original stage {i}?.db"
                execute([original, "seed-receipts", store, inputs[0], "0", *steps])
                snapshot = store.read_bytes()
                exact = execute([original, "observe-settled-state-id", store, inputs[0]]).stdout
                proof, root_hash, state, *journal = frames(exact)
                self.assertEqual((len(proof), len(root_hash), len(state), len(journal)),
                                 (33, 32, (279, 3185, 4870)[i], (0, 9, 12)[i]))
                self.assertEqual(raw_digest(state), root_hash)
                self.assertEqual(proof[0], int(i == 2))
                if i < 2:
                    self.assertEqual(proof, bytes(33))
                self.assertEqual(store.read_bytes(), snapshot)
                cases.append((state, proof))
            self.assertEqual(len(journal), 12)
            self.assertEqual(journal[-1][148:], proof)
            self.assertEqual(len(journal[-1]), 181)

            artifact = root / "native"
            receipt = execute([sys.executable, "-B", "-m", "hia.platform.service_settlement.build",
                               "--output", artifact], timeout=200)
            built = json.loads(receipt.stdout)
            self.assertEqual((built["status"], built["finalized"]),
                             ("EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", True))
            trust = inputs[0].read_bytes()
            replay = FixtureReplay.open(stack, artifact / "public", built["artifact"]["sha256"])
            heights = []
            for i in range(4):
                execution, command, actual_receipt = journal[i*3:i*3 + 3]
                self.assertEqual((len(execution), len(command), len(actual_receipt)),
                                 (163, (868, 900, 2689, 240)[i], (149, 149, 149, 181)[i]))
                height, = struct.unpack_from("<Q", execution, 123)
                heights.append(height)
                native = replay.apply(struct.pack("<Q", i + 1) + trust + execution + command)
                self.assertEqual(len(native), (1268, 2217, 3257, 4942)[i])
                self.assertEqual(native[:72], struct.pack("<Q", i + 1) + actual_receipt[42:74]
                                 + actual_receipt[116:148])
            self.assertEqual(heights, [10, 11, 12, 15])
            self.assertEqual(replay.calls.applies, 4)
            self.assertEqual(native[72:], state)
            cases.append((native[72:], proof))

            for backend in ("direct", "selfhost"):
                with self.subTest(backend=backend), NativeModule(
                        OWNER / "settlement_state_id.hepta", byte_exports=("f0",), backend=backend) as inspect:
                    for exact, expected in cases:
                        r = inspect.call("f0", [exact, b"\xa3"*37, b"\xa4"*len(exact)]).require_returned()
                        self.assertEqual((r.value, r.arguments[1]), (0, expected + b"\xa3"*4))
                    marker = state.index(proof)
                    invalid = [
                        (state + b"\0", 33, len(state) + 1, 100),
                        (state[:-1], 33, len(state), 100),
                        (state[:marker] + b"\xff" + state[marker + 1:], 33, len(state), 100),
                        (state, 32, len(state), 102),
                        (state, 33, len(state) - 1, 102),
                    ]
                    for raw, out_n, scratch_len, why in invalid:
                        args = [raw, b"\xab"*out_n, b"\xee"*scratch_len]
                        r = inspect.call("f0", args).require_returned()
                        self.assertEqual((r.value, r.arguments[1]), (why, args[1]))
