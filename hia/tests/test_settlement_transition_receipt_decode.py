"""Exact retained Borsh receipt bytes and complete identity comparisons."""
import hashlib
import json
import lzma
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute, original_adapter

OWNER = Path(__file__).resolve().parents[1] / "platform/service_settlement"


def retained_commands():
    corpus = (OWNER / "qualification/fixtures.json.xz").read_bytes()
    if hashlib.sha256(corpus).hexdigest() != "bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26":
        raise ValueError("Original retained settlement command corpus differs")
    fixture = json.loads(lzma.decompress(corpus))["fixtures"][1]
    frame = bytes.fromhex(fixture["input"])
    if fixture["name"] != "complete-clone-replay-lifecycle" or frame[:8] != b"SSO10001":
        raise ValueError("Expected original complete settlement lifecycle")
    pos = 16
    for wanted in ((0, 0, 0, 882), (1, 0, 10, 868), (1, 0, 11, 900),
                   (2, 0, 0, 0), (3, 0, 0, 0), (1, 0, 12, 2689),
                   (1, 0, 14, 240), (2, 1, 0, 0), (1, 0, 15, 240)):
        action = struct.unpack_from("<4Q", frame, pos)
        if action != wanted:
            raise ValueError("Original receipt fixture action differs")
        pos += 32
        if action[-1] and action[2] != 14:  # retained NotMature negative, not a committed receipt
            yield frame[pos:pos+action[-1]]
        pos += action[-1]


class SettlementTransitionReceiptDecodeTests(unittest.TestCase):
    def test_complete_original_borsh_receipts_and_identity(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-receipt-") as tmp, NativeModule(
                OWNER / "transition_receipt_decode.hepta", byte_exports=("f0",), backend="selfhost") as reader:
            root = Path(tmp)
            original, _ = original_adapter(root, marker=True)
            inputs = [root / f"original-input-{i}" for i in range(5)]
            for path, content in zip(inputs, retained_commands(), strict=True):
                path.write_bytes(content)
            store = root / "retained disposable settlement.db"
            execute([original, "seed-receipts", store, inputs[0], "0", *inputs[1:4], "-", "-", inputs[4]], timeout=60)
            before = store.read_bytes()
            raw = execute([original, "original-receipt-fixtures", store, inputs[0]], timeout=60).stdout
            pos, good = 0, []
            for seq, tag, width in ((1, 24, 149), (2, 24, 149), (3, 25, 149), (4, 26, 181)):
                n, got_seq = struct.unpack_from("<HQ", raw, pos)
                got_kind = struct.unpack_from("<H", raw, pos+42)[0]
                self.assertEqual((got_seq, got_kind, n), (seq, tag, width))
                limit = pos+44+n
                good.append(raw[pos+2:limit])
                pos = limit
            self.assertEqual(pos, len(raw))

            staging = root / "receipt-frame.bin"
            cases = []
            for frame in good:
                cases.append((frame, len(frame)-42, len(frame)-42))
                for offset in range(42):  # all bytes of independent sequence, ID and kind
                    altered = bytearray(frame)
                    altered[offset] ^= 1
                    cases.append((bytes(altered), 181, 101))
                cases.extend((x, 181, 100) for x in
                             (frame[:-1], frame+b"\0", frame[:190]+b"\2"+frame[191:]))
                cases.append((frame, len(frame)-43, 102))
            cases.extend([(good[-1][:191], 181, 100), (good[0] + bytes(32), 181, 100),
                          (b"", 181, 100)])
            # Borsh accepts any u16 field as structural data; identity is supplied
            # independently by the caller and is not a native command digest.
            unknown = bytearray(good[0])
            unknown[40:42] = unknown[116:118] = b"\xff\xff"
            cases.append((bytes(unknown), 181, 149))

            for start in range(0, len(cases), 24):
                batch = cases[start:start+24]
                replies = reader.call_many([("f0", [x, b"\xa6"*cap, b"\x5d"*7]) for x, cap, _ in batch])
                for (framed, cap, code), got in zip(batch, replies, strict=True):
                    staging.write_bytes(framed)
                    reference = subprocess.run([original, "decode-receipt-fixture", staging],
                                               capture_output=True, timeout=20, check=False)
                    got = got.require_returned()
                    self.assertEqual(got.value, code, (len(framed), cap, reference.stderr))
                    if code >= 149:
                        self.assertEqual((reference.returncode, reference.stderr), (0, b""))
                        self.assertEqual(got.arguments[1], reference.stdout+b"\xa6"*(cap-code))
                    else:
                        self.assertEqual(reference.returncode == 0, code == 102, reference.stderr)
                        if code != 102:
                            self.assertEqual(reference.stdout, b"")
                        self.assertEqual(got.arguments[1], b"\xa6"*cap)
                    self.assertEqual(got.arguments[2], b"\x5d"*7)
            self.assertEqual(store.read_bytes(), before)
