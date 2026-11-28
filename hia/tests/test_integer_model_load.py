"""Private single-call parity for the exact original bounded model snapshot load."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hia.tests.integer_model_material_original import build
from hia.tests.native_support import NativeModule
from hia.tests.test_integer_model_material import MARK, ROOT, cases, native_case, native_frame

SRC = ROOT / "hia/src/state/integer_model_load.hepta"
WORK_BYTES = 9014
WORK_MARK = b"\x49"


def snapshot(case):
    return b"IMD2" + native_frame(case)[4:] + bytes.fromhex(case["id"])


def outcomes():
    rows = [(case, code, bytes.fromhex(case["id"]) + expected[1] if code == 0 else b"")
            for case, expected, code in cases()]
    for original, code, payload in list(rows):
        if code:
            continue
        version = 3 if original["new"] else 2
        family = bytes.fromhex(original["family"])
        first_coeff = 48 if version == 3 else 46
        intents = [
            ([(4, b"\x07"), (38, b"\x01"), (first_coeff, b"\x00\x80")], 6),
            ([(6, bytes([family[0] ^ 1])), (first_coeff, b"\x00\x80")], 7),
            ([(37, bytes([family[-1] ^ 1]))], 7),
            ([(38, b"\x01"), (first_coeff, b"\x00\x80")], 7),
            ([(first_coeff, b"\x00\x80")], 9),
            ([(len(payload)-34, b"\x00\x80")], 9),
        ]
        if version == 3:
            intents += [
                ([(46, b"\x00"), (47, b"\x01"), (48, b"\x00\x80")], 7),
                ([(46, b"\x00"), (48, b"\x00\x80")], 8),
                ([(46, b"\x08")], 8),
            ]
        for edits, expected in intents:
            body = bytearray(payload[32:])
            for at, data in edits:
                body[at:at+len(data)] = data
            # Bind the corrupt bytes to their correct content digest: a digest
            # match cannot stand in for the original typed model validation.
            invalid = native_case(body, version, family)
            rows.append((invalid, expected, b""))
            invalid_other_digest = deepcopy(invalid)
            invalid_other_digest["id"] = original["id"]
            rows.append((invalid_other_digest, expected, b""))
        # Change canonical data and retain a stale expected content ID. The
        # mutated form still decodes fully, but must not publish any bytes.
        replacement = b"\x02\x00" if payload[-2:] == b"\x01\x00" else b"\x01\x00"
        mutated_body = payload[32:-2] + replacement
        mutated = native_case(mutated_body, version, family)
        rows.append((mutated, 0, bytes.fromhex(mutated["id"]) + mutated_body))
        wrong = deepcopy(mutated)
        wrong["id"] = original["id"]
        rows.append((wrong, 10, b""))
        for at in (0, 7, 8, 15, 16, 23, 24, 31):
            wrong = deepcopy(original)
            wrong_id = bytearray.fromhex(original["id"])
            wrong_id[at] ^= 0x80
            wrong["id"] = wrong_id.hex()
            rows.append((wrong, 10, b""))
        if version == 3:
            for active in range(1, 7):
                body = payload[32:78] + bytes([active]) + payload[79:]
                fresh = native_case(body, version, family)
                rows.append((fresh, 0, bytes.fromhex(fresh["id"]) + body))
    return rows


class IntegerModelSnapshotLoad(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {
            mode: cls.enterClassContext(NativeModule(SRC, backend=mode, byte_exports=("f0",)))
            for mode in ("direct", "selfhost")
        }
        if len({module.artifact_sha256 for module in cls.modules.values()}) != 2:
            raise ValueError("distinct pinned artifacts required")

    def emitted(self, rows):
        for backend, module in self.modules.items():
            for start in range(0, len(rows), 8):
                batch = rows[start:start+8]
                commands = [("f0", [wire, MARK*limit, WORK_MARK*work]) for wire, _, _, limit, work in batch]
                for n, (got, (_, args), (_, code, payload, _, work)) in enumerate(zip(
                        module.call_many(commands, timeout=40), commands, batch, strict=True)):
                    with self.subTest(backend=backend, index=start+n):
                        got.require_returned()
                        self.assertEqual(got.value, code)
                        self.assertEqual(got.arguments[0], args[0])
                        self.assertEqual(got.arguments[1], payload + args[1][len(payload):])
                        self.assertEqual(got.arguments[2][WORK_BYTES:], args[2][WORK_BYTES:])
                        if work < WORK_BYTES or code in (1, 2, 3, 4, 100):
                            self.assertEqual(got.arguments[2], args[2])

    def test_native_all_or_nothing_load(self):
        self.emitted([(snapshot(case), code, payload, len(payload)+19, WORK_BYTES+17)
                      for case, code, payload in outcomes()])

    def test_private_wire_and_exact_work_output_capacities(self):
        rows = outcomes()
        good, _, payload = rows[0]
        modern, _, wide = next(row for row in rows if row[1] == 0 and row[0]["new"])
        bad = deepcopy(good)
        bad["id"] = "00"*32
        old_wire, new_wire = native_frame(good), snapshot(good)
        self.emitted([
            (old_wire, 100, b"", len(payload), WORK_BYTES),
            (new_wire[:-1], 100, b"", len(payload), WORK_BYTES),
            (new_wire+b"x", 100, b"", len(payload), WORK_BYTES),
            (new_wire[:6]+b"\x01"+new_wire[7:], 100, b"", len(payload), WORK_BYTES),
            (new_wire[:4]+b"\x0b"+new_wire[5:], 100, b"", len(payload), WORK_BYTES),
            (new_wire, 102, b"", len(payload), WORK_BYTES-1),
            (new_wire, 102, b"", len(payload)-1, WORK_BYTES),
            (snapshot(bad), 10, b"", 0, WORK_BYTES),
            (new_wire, 0, payload, len(payload), WORK_BYTES),
            (snapshot(modern), 102, b"", len(wide)-1, WORK_BYTES),
            (snapshot(modern), 0, wide, len(wide), WORK_BYTES),
        ])

    @unittest.skipUnless(os.environ.get("HIA_M06_ORACLE_PREBUILT") or
                         os.environ.get("HIA_M06_LOCKED_CARGO_ORACLE") == "1",
                         "requires verified genuine Rust/Serde oracle; native tests always run")
    def test_exact_original_locked_snapshot_load(self):
        rows = outcomes()
        with tempfile.TemporaryDirectory(prefix="trnm-imd-") as directory:
            binary, proof = build(Path(directory))
            commands = b"".join(json.dumps(case).encode("ascii")+b"\n" for case, _, _ in rows)
            result = subprocess.run([binary], input=commands, check=True, capture_output=True, timeout=55)
            self.assertEqual(result.stderr, b"")
        self.assertIn(proof["mode"], ["verified-prebuilt-original-lock", "tiny-locked-offline-cargo"])
        raw = result.stdout
        at = 0
        observed = []
        for case, code, payload in rows:
            self.assertLess(at, len(raw))
            self.assertEqual(raw[at], code)
            at += 1
            width = 0 if code else 32 + (7758 if case["new"] else 7756)
            rust_payload = raw[at:at+width]
            self.assertEqual(rust_payload, payload)
            at += width
            observed.append((snapshot(case), code, rust_payload, len(rust_payload)+19, WORK_BYTES+17))
        self.assertEqual(at, len(raw))
        self.emitted(observed)
