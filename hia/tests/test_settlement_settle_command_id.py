"""Original Borsh Settle operation from a real retained, committed Store."""
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


class SettlementSettleCommandIdentityTests(unittest.TestCase):
    def test_canonical_settle_and_original_operation_id(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-settle-id-") as tmp, NativeModule(
                OWNER / "settle_command_id.hepta", byte_exports=("f0",), backend="selfhost") as module:
            root = Path(tmp)
            original, _ = original_adapter(root, marker=True)
            payloads = list(retained_commands())
            files = [root / f"real-input-{i}" for i in range(5)]
            for data, path in zip(payloads, files, strict=True):
                path.write_bytes(data)
            store = root / "original committed settle.db"
            execute([original, "seed-receipts", store, files[0], "0", *files[1:4], "-", "-", files[4]])
            before = store.read_bytes()
            expected = execute([original, "original-settle-command-fixture", store, files[0]]).stdout
            raw = expected[34:]
            self.assertEqual((expected[:2], raw), (b"\x1a\0", payloads[4]))
            self.assertEqual(len(raw), 240)
            count, = struct.unpack_from("<I", raw, 35)
            end = 39+count
            self.assertEqual(len(raw)-end, 192)

            def context(chain):
                return raw[:35]+struct.pack("<I", len(chain))+chain+raw[end:]

            cases = [(raw, 0), (context(b""), 0), (context(b"A\0Z"), 0),
                     (context("西😀é\U0010ffff".encode()), 0), (context(b"g"*4096), 0),
                     (context(b"g"*4097), 102), (context(b"g"*4096+"😀".encode()), 102)]
            cases += [(raw[:i], 100) for i in (0, 1, 2, 34, 35, 36, 38, 39, end, len(raw)-1)]
            cases += [(variant, 101) for variant in (*payloads[1:4], b"\x03", b"\xff"+raw[1:])]
            cases += [(bad, 100) for bad in (raw+b"\0", raw[:35]+b"\xff"*4+raw[39:],
                                             raw[:35]+struct.pack("<I", count-1)+raw[39:])]
            cases += [(context(chain), 100) for chain in (
                b"\x80", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
                b"\xf5\x80\x80\x80", b"\xe2\x82", b"\xf0\x90\x80",
                b"\xe0\x80\x80", b"\xe2\x82z", b"\xf0\x80\x80\x80", b"\xc2z",
            )]
            # Prove all fixed fields survive canonical round-trip and feed the digest.
            for index in (*range(1, 35), *range(end, len(raw))):
                altered = bytearray(raw)
                altered[index] ^= 1
                cases.append((bytes(altered), 0))

            scratch = root / "supplied-borsh.bin"
            for start in range(0, len(cases), 12):
                batch = cases[start:start+12]
                requests = [("f0", [row, b"\xa5"*(len(row)+39), b"\x71"*(len(row)+2304)])
                            for row, _ in batch]
                replies = module.call_many(requests)
                for (row, status), (_, initial), answer in zip(batch, requests, replies, strict=True):
                    scratch.write_bytes(row)
                    ref = subprocess.run([original, "decode-settle-command-fixture", scratch],
                                         capture_output=True, check=False, timeout=20)
                    result = answer.require_returned()
                    self.assertEqual(result.value, status or (len(row)+34), (len(row), status, ref.stderr))
                    if status == 0:
                        digest = hashlib.sha256(struct.pack("<I", len(DOMAIN))+DOMAIN+row).digest()
                        self.assertEqual((ref.returncode, ref.stdout, ref.stderr),
                                         (0, b"\x1a\0"+digest+row, b""))
                        self.assertEqual(result.arguments[1], ref.stdout+b"\xa5"*5)
                        if row == raw:
                            self.assertEqual(ref.stdout, expected)
                        else:
                            self.assertNotEqual(digest, expected[2:34])
                    else:
                        self.assertEqual(ref.returncode == 0, status == 102, ref.stderr)
                        if status != 102:
                            self.assertEqual(ref.stdout, b"")
                        self.assertEqual(result.arguments[1], initial[1])
                        if status != 100:
                            self.assertEqual(result.arguments[2], initial[2])

            for output, work in ((len(expected)-1, 2304+len(raw)),
                                 (len(expected), 2303+len(raw))):
                before_output = b"\xa5"*output
                before_work = b"\x71"*work
                result = module.call("f0", [raw, before_output, before_work]).require_returned()
                self.assertEqual((result.value, result.arguments[1:]), (102, [before_output, before_work]))
            self.assertEqual(store.read_bytes(), before)
