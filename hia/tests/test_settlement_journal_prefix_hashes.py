"""Byte-exact original journal prefix roots and every real marker interval root."""
from contextlib import ExitStack
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_kernel_state_shape import frames
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

OWNER = Path(__file__).resolve().parents[1] / "platform/service_settlement"


class SettlementJournalPrefixHashesTests(unittest.TestCase):
    def test_original_prefix_roots_distinguish_two_actual_empty_markers(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-prefix-roots-")))
            original, _ = original_adapter(root, marker=True)
            fixtures = [root / f"retained-{i}" for i in range(5)]
            for dest, data in zip(fixtures, retained_commands(), strict=True):
                dest.write_bytes(data)
            snapshots = ([], fixtures[1:2], fixtures[1:3], fixtures[1:4],
                         [*fixtures[1:4], "-", "-", fixtures[4]])
            cases = []
            for count, commands in enumerate(snapshots):
                store = root / f"owned prefix {count}?.db"
                execute([original, "seed-receipts", store, fixtures[0], "0", *commands])
                before = store.read_bytes()
                packet, expected, markers = frames(execute([original, "observe-actual-journal-prefixes",
                                                            store, fixtures[0]]).stdout)
                self.assertEqual(packet[:4], struct.pack("<I", count))
                self.assertEqual(len(expected), 32 * (count + 1))
                self.assertEqual([len(x) for x in frames(packet[4:])], [149] * min(3, count)
                                 + ([181] if count == 4 else []))
                self.assertEqual(len(markers), 80 * (count + (3 if count == 4 else 1)))
                self.assertEqual(store.read_bytes(), before)
                cases.append((packet, expected, markers))
            final, full, marker_proofs = cases[-1]
            self.assertEqual([pair[:2] for pair in struct.iter_unpack("<QQ32s32s", marker_proofs)],
                             [(0, 0), (0, 1), (1, 2), (2, 3), (3, 3), (3, 3), (3, 4)])
            self.assertEqual(len(set(full[i:i+32] for i in range(0, len(full), 32))), 5)

            for backend in ("direct", "selfhost"):
                with self.subTest(backend=backend), NativeModule(
                        OWNER / "journal_prefix_hashes.hepta", byte_exports=("f0",), backend=backend) as module:
                    for packet, expected, markers in cases:
                        call = module.call("f0", [packet, b"\x61"*(len(expected) + 7), b"\x62"*8192]).require_returned()
                        self.assertEqual((call.value, call.arguments[1]), (0, expected + b"\x61"*7))
                        actual = call.arguments[1][:len(expected)]
                        for start, end, root_from, root_to in struct.iter_unpack("<QQ32s32s", markers):
                            self.assertEqual(actual[start*32:(start+1)*32], root_from)
                            self.assertEqual(actual[end*32:(end+1)*32], root_to)
                    for raw, output, work, why in (
                        (final[:-1], 160, 8192, 100), (final+b"\0", 160, 8192, 100),
                        (b"\x05" + final[1:], 160, 8192, 100),
                        (final[:4] + b"\0"*4 + final[8:], 160, 8192, 100),
                        (final[:4] + b"\xff"*4 + final[8:], 160, 8192, 100),
                        (final, 159, 8192, 102), (final, 160, 8191, 102),
                    ):
                        args = [raw, b"\xa1"*output, b"\xa2"*work]
                        reply = module.call("f0", args).require_returned()
                        self.assertEqual((reply.value, reply.arguments[1]), (why, args[1]))
