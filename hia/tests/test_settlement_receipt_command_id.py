"""Canonical AdmitReceipt command and original operation ID from SQLite."""
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute, original_adapter
from hia.tests.test_settlement_transition_receipt_decode import retained_commands

OWNER = Path(__file__).resolve().parents[1] / "platform/service_settlement"
DOMAIN = b"trnm.portable.v2.consumption-settlement-operation.candidate.v1"


def layout(raw):
    """Identify test mutation positions in the retained fixture, not the oracle."""
    lengths = {}
    p = 35

    def count(label):
        nonlocal p
        n, = struct.unpack_from("<I", raw, p)
        lengths[label] = (p, n)
        p += 4
        return n

    def bytevec(label):
        nonlocal p
        n = count(label)
        p += n

    def usages(label):
        nonlocal p
        for index in range(count(label)):
            p += 2
            bytevec(f"{label}.{index}.resource")
            bytevec(f"{label}.{index}.meter")
            p += 54

    bytevec("chain")
    p += 36 + 164
    bytevec("body-meter")
    p += 28
    usages("usage")
    option = p
    p += 1 + 32 * raw[option]
    usages("cumulative")
    p += 112
    for signature in ("provider-signature", "consumer-signature"):
        p += 91
        bytevec(signature)
    if p != len(raw):
        raise AssertionError((p, len(raw), lengths))
    return lengths, option


class SettlementReceiptCommandIdentityTests(unittest.TestCase):
    def test_canonical_admission_and_original_operation_id(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-admit-id-") as tmp, NativeModule(
                OWNER / "receipt_command_id.hepta", byte_exports=("f0",), backend="selfhost") as module:
            root = Path(tmp)
            original, _ = original_adapter(root, marker=True)
            payloads = list(retained_commands())
            files = [root / f"original-{i}" for i in range(5)]
            for path, raw in zip(files, payloads, strict=True):
                path.write_bytes(raw)
            store = root / "actual admitted receipt.db"
            execute([original, "seed-receipts", store, files[0], "0", *files[1:3]])
            before = store.read_bytes()
            rows = execute([original, "original-receipt-command-fixtures", store, files[0]]).stdout
            actual = {}
            pos = 0
            for raw, opt in zip(payloads[1:3], (0, 1), strict=True):
                n, = struct.unpack_from("<H", rows, pos)
                output = rows[pos+2:pos+2+n]
                pos += n+2
                self.assertEqual((output[:2], output[34:]), (b"\x18\0", raw))
                lengths, option = layout(raw)
                self.assertEqual(raw[option], opt)
                self.assertGreater(lengths["usage"][1], 0)
                self.assertGreater(lengths["cumulative"][1], 0)
                self.assertGreater(lengths["provider-signature"][1], 0)
                self.assertGreater(lengths["consumer-signature"][1], 0)
                actual[raw] = output
            self.assertEqual(pos, len(rows))

            cases = [(x, 101, False) for x in (*payloads[3:], b"\xff")]
            cases.append((b"", 100, False))
            for raw in actual:
                lengths, option = layout(raw)
                cases += [(raw, 0, True), (raw+b"\0", 100, False),
                          (raw[:option]+b"\x02"+raw[option+1:], 100, False),
                          (raw[:option], 100, False)]
                if raw[option] == 1:
                    cases.append((raw[:option+32], 100, False))
                for label, (at, n) in lengths.items():
                    for cut in (at, at+3):
                        cases.append((raw[:cut], 100, False))
                    cases.append((raw[:at]+b"\xff"*4+raw[at+4:], 100, False))
                    if label not in ("usage", "cumulative"):
                        value = ("楚é😀".encode() if label == "chain" else b"\x80\x00\xff")
                        cases.append((raw[:at]+struct.pack("<I", len(value))+value+raw[at+4+n:], 0, True))
                    if label in ("usage", "cumulative"):
                        finish = at+4
                        # Real one-entry fixture: repeat the exact actual usage element in a
                        # structural test, without claiming it is admissible as policy.
                        self.assertEqual(n, 1)
                        for field in (f"{label}.0.resource", f"{label}.0.meter"):
                            start, size = lengths[field]
                            finish = start+4+size
                        finish += 54
                        entry = raw[at+4:finish]
                        for extent in (0, 2, 64, 65):
                            changed = raw[:at]+struct.pack("<I", extent)+entry*extent+raw[finish:]
                            cases.append((changed, 100 if extent == 65 else 0, True))
                chain, n = lengths["chain"]
                for text in (b"", b"x"*4096, b"x"*4097, b"\xed\xa0\x80", b"\xf0\x90"):
                    changed = raw[:chain]+struct.pack("<I", len(text))+text+raw[chain+4+n:]
                    cases.append((changed, 100 if text.startswith((b"\xed", b"\xf0")) or len(text)>4096 else 0,
                                  not text.startswith((b"\xed", b"\xf0"))))
                for where in (1, 34, option-1, len(raw)-1):
                    changed = bytearray(raw)
                    changed[where] ^= 1
                    cases.append((bytes(changed), 0, True))
            cases.append((b"\0"*65537, 102, False))

            pat = root / "disposable-command.bin"
            for first in range(0, len(cases), 10):
                batch = cases[first:first+10]
                calls = [("f0", [raw, b"\xc3"*(len(raw)+39), b"\xa7"*(len(raw)+2304)])
                         for raw, _, _ in batch]
                results = module.call_many(calls)
                for (raw, status, accepted), (_, args), native in zip(batch, calls, results, strict=True):
                    pat.write_bytes(raw)
                    rust = subprocess.run([original, "decode-receipt-command-fixture", pat],
                                          capture_output=True, check=False, timeout=20)
                    answer = native.require_returned()
                    self.assertEqual((answer.value, rust.returncode == 0),
                                     (status or (34+len(raw)), accepted), (raw[:8], len(raw), rust.stderr))
                    if accepted:
                        digest = hashlib.sha256(struct.pack("<I", len(DOMAIN))+DOMAIN+raw).digest()
                        self.assertEqual(rust.stdout, b"\x18\0"+digest+raw)
                        if raw in actual:
                            self.assertEqual(rust.stdout, actual[raw])
                    if status:
                        self.assertEqual(answer.arguments[1], args[1])
                    else:
                        self.assertEqual(answer.arguments[1], rust.stdout+b"\xc3"*5)
            for raw in actual:
                for out_n, scratch_n in ((len(raw)+33, len(raw)+2304), (len(raw)+34, len(raw)+2303)):
                    args = [raw, b"\xc3"*out_n, b"\xa7"*scratch_n]
                    answer = module.call("f0", args).require_returned()
                    self.assertEqual((answer.value, answer.arguments), (102, args))
            self.assertEqual(store.read_bytes(), before)
