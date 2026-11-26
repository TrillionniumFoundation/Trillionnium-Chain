"""Original typed Settlement state bytes and roots, independently of SQLite readback."""
from contextlib import ExitStack
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_receipt_command_id import layout as receipt_layout
from hia.tests.test_settlement_rollup_command_id import top_layout
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_state_root_read import raw_digest
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

OWNER = Path(__file__).resolve().parents[1] / "platform/service_settlement"


def frame(raw):
    return struct.pack("<I", len(raw)) + raw


def frames(data):
    while data:
        width, = struct.unpack_from("<I", data)
        if len(data) < width + 4:
            raise ValueError("truncated original fixture diagnostic")
        yield data[4:4 + width]
        data = data[4 + width:]


class SettlementKernelStateShapeTests(unittest.TestCase):
    def test_original_typed_states_and_finite_private_profile(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-kernel-shape-")))
            modules = {
                backend: stack.enter_context(NativeModule(
                    OWNER / "kernel_state_shape.hepta", byte_exports=("f0",), backend=backend))
                for backend in ("direct", "selfhost")
            }
            original, _ = original_adapter(root, marker=True)
            commands = list(retained_commands())
            inputs = [root / f"retained-{i}" for i in range(5)]
            for path, content in zip(inputs, commands, strict=True):
                path.write_bytes(content)

            states, stores = [], []
            for i, journal in enumerate(([], inputs[1:3], inputs[1:4], [*inputs[1:4], "-", "-", inputs[4]])):
                store = root / f"original-{i}.db"
                execute([original, "seed-receipts", store, inputs[0], "0", *journal])
                stores.append((store, store.read_bytes()))
                observed = execute([original, "observe-kernel-state-shape", store, inputs[0]]).stdout
                self.assertEqual(int.from_bytes(observed[:8], "little"), (9, 11, 12, 15)[i])
                self.assertEqual(tuple(observed[8:16]), (
                    (0, 0, 0, 0, 0, 0, 0, 0),
                    (2, 0, 0, 0, 0, 0, 0, 0),
                    (2, 2, 1, 0, 0, 0, 0, 0),
                    (2, 2, 1, 1, 1, 1, 1, 1),
                )[i])
                digest, raw = observed[17:49], observed[49:]
                self.assertEqual(digest, raw_digest(raw))
                states.append((raw, digest + raw))

            # In the initial original state, account fields begin after 107 fixed
            # bytes. Keep the actual first account when constructing private
            # profile boundaries; the original structural decoder accepts 65.
            empty, funded, rolled, settled = (raw for raw, _ in states)
            self.assertEqual(empty[:6], b"\0" * 6)
            account_count, = struct.unpack_from("<I", empty, 107)
            self.assertGreater(account_count, 0)
            self.assertEqual(len(empty), 111 + account_count * 56)
            account = empty[111:167]
            cases = [(raw, 0, True) for raw, _ in states]
            cases += [(empty[:107] + struct.pack("<I", n) + account * n, 0 if n <= 64 else 100, True)
                      for n in (0, 1, 64, 65)]
            for raw, _ in states:
                cases += [(raw + tail, 100, False) for tail in (b"\0", b"\xff"*17)]
                for cut in sorted({0, 1, 4, 5, 6, 110, len(raw) - 1, *range(17, len(raw), 197)}):
                    cases.append((raw[:cut], 100, False))
            for i in (4, 5, 62, 63, 106):
                for tag in (2, 255):
                    cases.append((empty[:i] + bytes([tag]) + empty[i + 1:], 100, False))
            for i in (104, 105):
                for value in (2, 255):
                    cases.append((empty[:i] + bytes([value]) + empty[i + 1:], 0, True))
            for pos in (0, 107):
                cases.append((empty[:pos] + b"\xff"*4 + empty[pos+4:], 100, False))

            receipt1, receipt2 = commands[1][1:], commands[2][1:]
            self.assertEqual(funded[4:4 + len(receipt1)], receipt1)
            first_opt = 4 + len(receipt1) + 41
            second_opt = first_opt + 1 + 8 + len(receipt2) + 41
            self.assertEqual((funded[first_opt], funded[second_opt], rolled[first_opt]), (0, 0, 1))
            for raw, indices in ((funded, (first_opt, second_opt)), (rolled, (first_opt, second_opt + 32))):
                for i in indices:
                    cases += [(raw[:i] + b"\x02" + raw[i + 1:], 100, False), (raw[:i], 100, False)]
                    cases.append((raw[:i - 1] + b"\xff" + raw[i:], 0, True))  # opaque receipt status
            receipt_fields, _ = receipt_layout(commands[1])
            chain = 4 + receipt_fields["chain"][0] - 1
            n, = struct.unpack_from("<I", funded, chain)
            self.assertGreater(n, 0)
            for value, valid in (("原🌍".encode(), True), (b"\xf4\x90\x80\x80", False)):
                cases.append((funded[:chain] + frame(value) + funded[chain + 4 + n:], 0 if valid else 100, valid))

            rollup_presence = second_opt + 64 + 1 + 8
            _, _, nested_receipts = top_layout(commands[3])
            rollup_raw = commands[3][1:nested_receipts - 4]
            self.assertEqual(rolled[rollup_presence:rollup_presence + 1 + len(rollup_raw)], b"\1" + rollup_raw)
            rollup_consumed = rollup_presence + 1 + len(rollup_raw) + 57
            self.assertEqual((rolled[rollup_consumed], settled[rollup_consumed]), (0, 1))
            settled_presence = rollup_consumed + 33
            self.assertEqual(settled[settled_presence], 1)
            for pos in (rollup_presence, rollup_consumed, settled_presence):
                cases.append((settled[:pos] + b"\xff" + settled[pos + 1:], 100, False))
            cases.append((settled[:rollup_consumed - 1] + b"\xff" + settled[rollup_consumed:], 0, True))

            item = funded[4:first_opt + 9]
            signature, old = receipt_fields["consumer-signature"]
            signature -= 1  # Command variant is not stored.
            count = 32
            for more in (0, 1):
                pad, remainder = divmod(65536 + more - len(empty) - count * len(item), count)
                self.assertTrue(0 < old + pad < 4095)
                padded = [item[:signature] + frame(bytes(old + pad + (i < remainder)))
                          + item[signature + 4 + old:] for i in range(count)]
                raw = struct.pack("<I", count) + b"".join(padded) + empty[4:]
                self.assertEqual(len(raw), 65536 + more)
                cases.append((raw, 100 if more else 0, True))

            specimen = root / "owned-case-frames"
            specimen.write_bytes(b"".join(frame(raw) for raw, _, _ in cases))
            results = list(frames(execute([original, "classify-kernel-state-fixtures", specimen]).stdout))
            self.assertEqual(len(results), len(cases))
            self.assertEqual(results[:4], [expected for _, expected in states])
            for backend, module in modules.items():
                for start in range(0, len(cases), 12):
                    batch = cases[start:start + 12]
                    calls = [("f0", [raw, b"\x9c" * (len(raw) + 37), b"\xf3" * (len(raw) + 4096)])
                             for raw, _, _ in batch]
                    for i, (native, (_, args), (raw, status, typed)) in enumerate(
                            zip(module.call_many(calls), calls, batch, strict=True), start):
                        expected = results[i]
                        with self.subTest(backend=backend, index=i, size=len(raw)):
                            self.assertEqual(bool(expected), typed)
                            if typed:
                                self.assertEqual(expected, raw_digest(raw) + raw)
                            result = native.require_returned()
                            self.assertEqual(result.value, status)
                            self.assertEqual(result.arguments[1], args[1] if status else expected + b"\x9c"*5)
                for raw, output, scratch, status in (
                    (settled, len(settled) + 31, len(settled) + 4096, 102),
                    (settled, len(settled) + 32, len(settled) + 4095, 102),
                    (bytes(65537), 0, 0, 100),
                ):
                    args = [raw, b"\x9c"*output, b"\xf3"*scratch]
                    reply = module.call("f0", args).require_returned()
                    self.assertEqual((reply.value, reply.arguments), (status, args))
            for store, before in stores:
                self.assertEqual(store.read_bytes(), before)
