"""Original committed execution framing and local policy, without Order authority."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/platform/service_settlement/execution_context.hepta"


def packet(context, execution):
    return struct.pack("<I", len(context)) + context + execution


def cases_from(frame):
    off = 0
    parts = []
    while off < len(frame):
        n = struct.unpack_from("<I", frame, off)[0]
        off += 4
        parts.append(frame[off:off+n])
        off += n
    if off != len(frame):
        raise ValueError("Original fixture response had a partial extent")
    return parts


def put(buffer, offset, part):
    return buffer[:offset] + part + buffer[offset + len(part):]


class SettlementExecutionContextTests(unittest.TestCase):
    def test_original_committed_execution_and_static_classification(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-execution-context-") as tmp:
            root = Path(tmp)
            original, _ = original_adapter(root, marker=True)
            inputs = [root / f"command-{i}" for i in range(5)]
            for path, source in zip(inputs, retained_commands(), strict=True):
                path.write_bytes(source)
            owned = root / "owned"
            owned.mkdir(mode=0o700)
            store = owned / "real settled execution #?.db"
            execute([original, "seed-receipts", store, inputs[0], "0", *inputs[1:4], "-", "-", inputs[4]])
            before = store.read_bytes()
            context, *executions = cases_from(execute([original, "original-execution-fixtures",
                                                       store, inputs[0]]).stdout)
            self.assertEqual(len(executions), 4)
            self.assertTrue(all(x[2:-80] == context for x in executions))
            original_last = executions[-1]
            self.assertEqual(int.from_bytes(original_last[-40:-32], "little"), 15)
            cases = [(packet(context, raw), raw, 0, 0) for raw in executions]

            def add(trusted, raw, expected, native_expected=None):
                cases.append((packet(trusted, raw), raw, expected, expected if native_expected is None else native_expected))

            chain_width = struct.unpack_from("<I", context, 32)[0]
            for pos in (0, 36, 36+chain_width, len(context)-1):
                modified = put(context, pos, bytes([context[pos] ^ 1]))
                add(context, original_last[:2] + modified + original_last[-80:], 101)
            add(context, put(original_last, 0, b"\x02\0"), 101)
            for n in set((0, 1, 33, 34, 37, 38, 38+chain_width, len(original_last)-80,
                          len(original_last)-72, len(original_last)-40, len(original_last)-32, len(original_last)-1)):
                add(context, original_last[:n], 100)
            add(context, original_last + b"\0", 100)
            add(context + b"\0", original_last, 100)
            for chain in (b"\xc0\xaf", b"\xed\xa0\x80", b"\xe2\x82", b"\xf4\x90\x80\x80", b"\xff"):
                broken = context[:32] + struct.pack("<I", len(chain)) + chain + context[36+chain_width:]
                add(context, original_last[:2] + broken + original_last[-80:], 100)
            for chain in (b"", "链⛓𐍈".encode(), b"f"*4096, b"f"*4097):
                agreed = context[:32] + struct.pack("<I", len(chain)) + chain + context[36+chain_width:]
                add(agreed, original_last[:2] + agreed + original_last[-80:], 0, 100 if len(chain) > 4096 else 0)

            b0 = bytes(32)
            b1 = bytes([0x44])*32
            maximum = (1 << 64)-1
            for previous, current, left, right, expected in [
                (0, 0, b0, b0, 0), (0, 0, b0, b1, 103), (4, 5, b0, b0, 0),
                (4, 3, b0, b1, 103), ((1 << 63)-1, 1 << 63, b0, b1, 0),
                (1 << 63, (1 << 63)-1, b1, b0, 103), (maximum, maximum, b1, b1, 0),
                (maximum, maximum, b1, b0, 103), (maximum-1, maximum, b0, b1, 0),
            ]:
                tail = struct.pack("<Q", previous) + left + struct.pack("<Q", current) + right
                add(context, original_last[:-80] + tail, expected)
            # Structural precedes schema, and the independent context mismatch
            # precedes a regressing order coordinate as in retained Rust.
            add(context, put(original_last, 0, b"\x02\0")[:-1], 100)
            add(context, b"\x02\0" + original_last[2:-80] + struct.pack("<Q", 3) + b1 + bytes(40), 101)

            roster = root / "structural-inputs"
            roster.write_bytes(b"".join(struct.pack("<I", len(raw)) + raw for raw, *_ in cases))
            reference = execute([original, "classify-execution-fixtures", store, inputs[0], roster]).stdout
            self.assertEqual(reference, bytes(rust for _, _, rust, _ in cases))
            self.assertEqual(store.read_bytes(), before)

            for backend in ("direct", "selfhost"):
                with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                    for start in range(0, len(cases), 12):
                        group = cases[start:start+12]
                        args = [[raw, b"\xa6" * (len(body)+9), b"\x7c" * (len(raw)+11)] for raw, body, _, _ in group]
                        replies = native.call_many([("f0", a) for a in args])
                        for (_, body, _, expected), a, reply in zip(group, args, replies, strict=True):
                            self.assertEqual(reply.require_returned().value, expected)
                            expected_out = a[1] if expected else body + a[1][len(body):]
                            self.assertEqual((reply.arguments[0], reply.arguments[1]), (a[0], expected_out))
                            self.assertEqual(reply.arguments[2][len(a[0]):], a[2][len(a[0]):])
                    raw, body, *_ = cases[0]
                    for out_n, work_n, expected in ((len(body), len(raw), 0),
                                                     (len(body)-1, len(raw), 102),
                                                     (len(body), len(raw)-1, 102)):
                        output = b"\x55" * out_n
                        reply = native.call("f0", [raw, output, bytes(work_n)]).require_returned()
                        self.assertEqual((reply.value, reply.arguments[1]), (expected, output if expected else body))
