"""Native full Borsh AdmitRollup command against a genuinely committed Store."""
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_receipt_command_id import layout as receipt_layout
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

OWNER = Path(__file__).resolve().parents[1] / "platform/service_settlement"
DOMAIN = b"trnm.portable.v2.consumption-settlement-operation.candidate.v1"


def top_layout(raw):
    """Locate mutation positions in the retained fixture, not the oracle."""
    p, lengths = 35, {}

    def count(label, stride=0):
        nonlocal p
        n, = struct.unpack_from("<I", raw, p)
        lengths[label] = p, n
        p += 4 + n * stride
        return n

    count("chain", 1)
    p += 36 + 164
    count("meter", 1)
    p += 20
    count("ids", 32)
    p += 36
    for index in range(count("usages")):
        p += 2
        count(f"usage{index}-resource", 1)
        count(f"usage{index}-meter", 1)
        p += 54
    usage_end = p
    p += 144
    for label in ("provider", "consumer"):
        p += 91
        count(label, 1)
    count("nested")
    return lengths, usage_end, p


class SettlementRollupCommandIdentityTests(unittest.TestCase):
    def test_complete_original_rollup_and_nested_receipt_command_identity(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-rollup-id-") as tmp, NativeModule(
                OWNER / "rollup_command_id.hepta", byte_exports=("f0",), backend="selfhost") as module:
            root = Path(tmp)
            original, _ = original_adapter(root, marker=True)
            retained = list(retained_commands())
            inputs = [root / f"legitimate-original-{i}" for i in range(4)]
            for path, data in zip(inputs, retained[:4], strict=True):
                path.write_bytes(data)
            store = root / "actual committed rollup.db"
            execute([original, "seed-receipts", store, inputs[0], "0", *inputs[1:]])
            before = store.read_bytes()
            expected = execute([original, "original-rollup-command-fixture", store, inputs[0]]).stdout
            raw = expected[34:]
            self.assertEqual((expected[:2], raw), (b"\x19\0", retained[3]))
            self.assertEqual(len(raw), 2689)
            lengths, usage_end, nested = top_layout(raw)
            self.assertEqual(raw[nested:], retained[1][1:]+retained[2][1:])
            self.assertEqual((lengths["ids"][1], lengths["nested"][1], lengths["usages"][1]), (2, 2, 1))
            self.assertGreater(lengths["provider"][1], 0)
            self.assertGreater(lengths["consumer"][1], 0)

            cases = [(raw, 0, True), (raw+b"\0", 100, False), (b"", 100, False),
                     (b"\1" + bytes(65536), 102, False)]
            cases += [(variant, 101, False) for variant in (retained[1], retained[2], retained[4], b"\xff")]
            for pos, count in lengths.values():
                for cut in (pos, pos+1, pos+3):
                    cases.append((raw[:cut], 100, False))
                cases.append((raw[:pos]+b"\xff"*4+raw[pos+4:], 100, False))
            ids, id_count = lengths["ids"]
            vec = raw[ids+4:ids+4+id_count*32]
            for n in (0, 1, 64, 65):
                altered = raw[:ids]+struct.pack("<I", n)+vec[:32]*n+raw[ids+4+len(vec):]
                cases.append((altered, 100 if n > 64 else 0, True))
            usage, usage_count = lengths["usages"]
            usage_element = raw[usage+4:usage_end]
            for n in (0, 2, 64, 65):
                altered = raw[:usage]+struct.pack("<I", n)+usage_element*n+raw[usage_end:]
                cases.append((altered, 100 if n > 64 else 0, True))
            at = lengths["nested"][0]
            first, second = retained[1][1:], retained[2][1:]
            for n, pieces in ((0, b""), (1, second), (2, second+first), (32, first*32), (33, first*33)):
                cases.append((raw[:at]+struct.pack("<I", n)+pieces, 100 if n > 32 else 0, True))
            for offset, receipt in ((nested, retained[1]), (nested+len(first), retained[2])):
                fields, option = receipt_layout(receipt)
                old = receipt[option]
                self.assertIn(old, (0, 1))
                option += offset-1
                cases += [(raw[:option]+b"\x02"+raw[option+1:], 100, False),
                          (raw[:option+(32 if old else 0)], 100, False)]
                for pos, count in fields.values():
                    location = offset + pos - 1
                    cases.append((raw[:location]+b"\xff"*4+raw[location+4:], 100, False))
                utf, n = fields["chain"]
                utf += offset-1
                for value, valid in (("原🌍".encode(), True), (b"\xf4\x90\x80\x80", False)):
                    altered = raw[:utf]+struct.pack("<I", len(value))+value+raw[utf+n+4:]
                    cases.append((altered, 0 if valid else 100, valid))
            for label in ("chain", "meter", "provider", "consumer"):
                pos, count = lengths[label]
                values = (b"", "宇🚲é".encode(), b"\xc0\x80") if label == "chain" else (b"", b"\x00\xff")
                for value in values:
                    valid = value != b"\xc0\x80"
                    changed = raw[:pos]+struct.pack("<I", len(value))+value+raw[pos+4+count:]
                    cases.append((changed, 0 if valid else 100, valid))
            for at in (1, 34, ids+4, usage_end, nested-5, len(raw)-1):
                changed = bytearray(raw)
                changed[at] ^= 1
                cases.append((bytes(changed), 0, True))

            specimen = root / "disposable-borsh-frame.bin"
            for first in range(0, len(cases), 8):
                batch = cases[first:first+8]
                calls = [("f0", [row, b"\x9c"*(len(row)+38), b"\xf3"*(len(row)+2304)])
                         for row, _, _ in batch]
                results = module.call_many(calls)
                for index, ((row, code, valid), (_, args), native) in enumerate(
                        zip(batch, calls, results, strict=True), start=first):
                    specimen.write_bytes(row)
                    rust = subprocess.run([original, "decode-rollup-command-fixture", specimen],
                                          capture_output=True, check=False, timeout=20)
                    result = native.require_returned()
                    self.assertEqual((result.value, rust.returncode == 0),
                                     (code or (34+len(row)), valid), (index, len(row), code, rust.stderr))
                    if valid:
                        digest = hashlib.sha256(struct.pack("<I", len(DOMAIN))+DOMAIN+row).digest()
                        self.assertEqual(rust.stdout, b"\x19\0"+digest+row)
                        if row == raw:
                            self.assertEqual(rust.stdout, expected)
                    else:
                        self.assertEqual(rust.stdout, b"")
                    self.assertEqual(result.arguments[1], args[1] if code else rust.stdout+b"\x9c"*4)
            for out_n, scratch_n in ((len(raw)+33, len(raw)+2304), (len(raw)+34, len(raw)+2303)):
                args = [raw, b"\x9c"*out_n, b"\xf3"*scratch_n]
                answer = module.call("f0", args).require_returned()
                self.assertEqual((answer.value, answer.arguments), (102, args))
            self.assertEqual(store.read_bytes(), before)
