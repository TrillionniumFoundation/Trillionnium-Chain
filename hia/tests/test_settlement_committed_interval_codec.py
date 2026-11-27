"""A generic native interval fold over an exact locked original held snapshot."""
from contextlib import ExitStack
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_kernel_state_shape import frames
from hia.tests.test_settlement_schema_read import execute, original_adapter

OWNER = Path(__file__).resolve().parents[1] / "platform/service_settlement"


class SettlementCommittedIntervalCodecTests(unittest.TestCase):
    def test_actual_original_interval_envelopes_and_coordinates(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-interval-")))
            original, _ = original_adapter(tmp, marker=True, same_block=True)
            packets = {}
            checksummed = {}
            patterns = {
                "empty": ("short", (), ((0, 0), (0, 0))),
                "same": (None, (1, 2), ((0, 0), (0, 2))),
                "rollup": ("short-rollup", (1, 4, 6), ((0, 0), (0, 1), (1, 2), (2, 3))),
                "settle": ("utf8-settle", (1, 4, 6, "-", "-", 8),
                           ((0, 0), (0, 1), (1, 2), (2, 3), (3, 3), (3, 3), (3, 4))),
                "six": ("six-admits", (1, 2, 3, 4, 5, 6), ((0, 0), *((i, i+1) for i in range(6)))),
            }
            for name, (fixture, command_indices, intervals) in patterns.items():
                with self.subTest(history=name):
                    command = [tmp/"same-block-fixture"] + ([fixture] if fixture else [])
                    exported = list(frames(execute(command).stdout))
                    files = {}
                    for i in (0, *(x for x in command_indices if x != "-")):
                        files[i] = tmp/f"{name}-{i}"
                        files[i].write_bytes(exported[i])
                    db = tmp/f"actual {name} intervals.db"
                    route = "seed-same-block" if name == "same" else "seed-receipts"
                    actual_binding = execute([original, route, db, files[0], "1" if name == "empty" else "0",
                                              *(files[x] if x != "-" else "-" for x in command_indices)]).stdout
                    actual_genesis = tmp/f"{name}-genesis"
                    actual_genesis.write_bytes(actual_binding[40:72])
                    before = db.read_bytes()
                    packet = execute([original, "observe-committed-interval-codec", db, files[0], actual_genesis]).stdout
                    self.assertEqual(db.read_bytes(), before)
                    self.assertFalse(db.with_name(db.name+"-journal").exists())
                    n, m = struct.unpack_from("<QQ", packet)
                    self.assertEqual(n, sum(x != "-" for x in command_indices))
                    self.assertEqual(m, len(intervals))
                    marker = 160 + 64 * (n + 1)
                    operation = marker + 296 * m
                    self.assertEqual(len(packet), operation + 152 * n)
                    self.assertEqual(tuple(struct.unpack_from("<QQ", packet, marker+296*i+88)
                                           for i in range(m)), intervals)
                    packets[name] = packet, marker, operation
                    checked = execute([original, "observe-checked-committed-interval-codec",
                                       db, files[0], actual_genesis]).stdout
                    extent, = struct.unpack_from("<Q", checked)
                    cut = 8 + extent
                    self.assertEqual(checked[8:cut], actual_binding[104:])
                    self.assertEqual(checked[cut:], packet)
                    checksummed[name] = checked, cut, marker, operation

            for backend in ("direct", "selfhost"):
                with self.subTest(backend=backend), NativeModule(
                        OWNER/"committed_interval_codec.hepta", byte_exports=("f0",), backend=backend) as native:
                    def check(packet, result):
                        call = native.call("f0", [packet, b"\x92"*12, b"\x91"*8192]).require_returned()
                        self.assertEqual((call.value, call.arguments[1]), (result, b"\x92"*12))

                    for packet, _, _ in packets.values():
                        check(packet, 0)
                    packet, marker, operation = packets["same"]
                    check(packet[:-1], 100)
                    check(packet+b"\0", 100)
                    # Alter only the disposable typed proof, never a real Store.
                    for offset in (0, 8, 56, 128, marker+296+88, marker+296+96,
                                   marker+296+136, marker+296+200, operation+152,
                                   operation+152+40, operation+152+80):
                        altered = bytearray(packet)
                        altered[offset] ^= 1
                        check(bytes(altered), 100)

                with self.subTest(checked_backend=backend), NativeModule(
                        OWNER/"checked_committed_interval_codec.hepta",
                        byte_exports=("f0",), backend=backend) as checked_native:
                    def verified(raw, wanted, scratch=32768):
                        answer = checked_native.call("f0", [raw, bytes([7])*8,
                                                           bytes([8])*scratch]).require_returned()
                        self.assertEqual((answer.value, answer.arguments[1]), (wanted, bytes([7])*8))

                    for raw, _, _, _ in checksummed.values():
                        verified(raw, 0)
                    raw, cut, marker, operation = checksummed["same"]
                    verified(raw, 100, 32767)
                    verified(raw[:-1], 100)
                    # Mismatch only the fixture config or the stored marker checksum.
                    # A second malformed field also demonstrates digest preflight wins.
                    for index in (8, cut+marker+296+264):
                        bad = bytearray(raw)
                        bad[index] ^= 1
                        verified(bytes(bad), 101)
                        bad[cut+operation+152] ^= 1
                        verified(bytes(bad), 101)
                    # Actual marker bytes/checksums stay unchanged; only the row join fails.
                    bad = bytearray(raw)
                    bad[cut+operation+152] ^= 1
                    verified(bytes(bad), 100)

                with self.subTest(cursor_backend=backend), NativeModule(
                        OWNER/"marker_dispatch_plan.hepta", byte_exports=("f0",), backend=backend) as cursor:
                    def plan(raw, capacity=1288):
                        return cursor.call("f0", [raw, b"q"*capacity, bytes(32768)]).require_returned()

                    indexes = {"empty": [], "same": [1, 1], "rollup": [1, 2, 3],
                               "settle": [1, 2, 3, 6], "six": [1, 2, 3, 4, 5, 6]}
                    for name, (raw, cut, marker, operation) in checksummed.items():
                        answer = plan(raw)
                        self.assertEqual(answer.value, 0)
                        actual = answer.arguments[1]
                        want = indexes[name]
                        count, = struct.unpack_from("<Q", actual)
                        self.assertEqual(count, len(want))
                        for index, marker_ordinal in enumerate(want):
                            emitted = actual[8+160*index:168+160*index]
                            seq, chosen = struct.unpack_from("<QQ", emitted)
                            self.assertEqual((seq, chosen), (index+1, marker_ordinal))
                            op = cut + operation + 152*index
                            self.assertEqual(emitted[16:96], raw[op:op+80])
                            genesis = cut + 160
                            before = genesis + 64*index
                            current = before + 64
                            self.assertEqual(emitted[96:128], raw[before:before+32])
                            self.assertEqual(emitted[128:160], raw[current:current+32])
                        used = 8 + 160*len(want)
                        self.assertEqual(actual[used:], b"q"*(1288-used))
                    raw, cut, marker, operation = checksummed["same"]
                    short = plan(raw, 327)
                    self.assertEqual((short.value, short.arguments[1]), (102, b"q"*327))
                    for offset, status in ((8, 101), (cut+operation+152, 100)):
                        changed = bytearray(raw)
                        changed[offset] ^= 1
                        rejected = plan(bytes(changed))
                        self.assertEqual((rejected.value, rejected.arguments[1]), (status, b"q"*1288))
