"""Exact original DA author value comparison; no signing, registry or authorization."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/author_authority_value.hepta"
ADAPTER = Path(__file__).with_name("rust_da_author_authority_value_reference.rs")
P = (1 << 255) - 19
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
WORK = 140512
SCRATCH = b"\x79" * (WORK + 7)
CANARY = b"\xa5" * 327

# Public-only RFC8032 test-vector encodings; no secrets or signing operations.
PUBLIC = [
    bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
]


def point(y, sign=0):
    return (y | (sign << 255)).to_bytes(32, "little")


def req(key=PUBLIC[0], author=b"a", first=1, maximum=1, quota=1, outstanding=1):
    return key + struct.pack("<QQQI", first, maximum, quota, outstanding) + author


def original_packets(raw, count):
    offset = 0
    for _ in range(count):
        status, n = struct.unpack_from("<BI", raw, offset)
        offset += 5
        value = raw[offset:offset+n]
        if len(value) != n or status not in (0, 3, 6, 7) or (status and n):
            raise ValueError("invalid typed original result")
        yield status, value
        offset += n
    if offset != len(raw):
        raise ValueError("trailing original results")


class DaAuthorAuthorityValue(unittest.TestCase):
    def test_actual_rust_constructor_borsh_and_two_native_emitters(self):
        cases = [req(key) for key in PUBLIC]
        cases += [req(key, bytes(range(256)), U64, U64, U64, U32) for key in PUBLIC]
        cases += [req(PUBLIC[0], author) for author in (b"", b"a" * 257, b"\0\xff\t", bytes(range(255)), b"ok")]
        cases += [req(first=0), req(first=2, maximum=1), req(quota=0), req(outstanding=0)]
        cases += [req(point(1, 1), author=b""), req(point(2), first=0), req(point(1), quota=0)]
        group_at = len(cases)
        cases += [req(point(y, sign)) for sign in (0, 1) for y in [*range(19), *range(P-1, P+19)]]
        # Fixed raw coordinate probes, not purported private/public keypairs.
        cases += [req(hashlib.sha256(b"DA author point facts/" + bytes([i])).digest()) for i in range(12)]
        data = b"".join(struct.pack("<I", len(r)) + r for r in cases)
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-author-value-") as tmp:
            exact = list(original_packets(locked_reference(Path(tmp), data, caller=ADAPTER), len(cases)))
        self.assertEqual([s for s, _ in exact[:6]], [0] * 6)
        self.assertEqual([s for s, _ in exact[11:18]], [3] * 7)
        known = dict(zip(cases[group_at:], exact[group_at:], strict=True))
        for y in (0, 1, P-1, P, P+1):
            for sign in (0, 1):
                self.assertEqual(known[req(point(y, sign))], (7, b""))
        for sign in (0, 1):
            for y in range(19):
                self.assertEqual(known[req(point(y, sign))][0], known[req(point(P+y, sign))][0])
        self.assertEqual(set(s for s, _ in exact), {0, 3, 6, 7})

        for raw, (status, value) in zip(cases, exact, strict=True):
            if status == 0:
                self.assertEqual(value, struct.pack("<I", len(raw)-60) + raw[60:] + raw[:60])
        trials = [(raw, outcome, len(CANARY), len(SCRATCH)) for raw, outcome in zip(cases, exact, strict=True)]
        trials += [
            (b"", (100, b""), 0, 0), (cases[0][:59], (100, b""), 72, WORK),
            (cases[0], (102, b""), 64, WORK),
            (cases[0], exact[0], 65, WORK),
            (cases[3], (102, b""), 319, WORK),
            (cases[3], exact[3], 320, WORK),
            (cases[0], (102, b""), 65, WORK-1),
            (req(author=b""), (3, b""), 0, 0),
            (req(point(1, 1)), (7, b""), 0, WORK),
        ]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                for offset in range(0, len(trials), 12):
                    panel = trials[offset:offset+12]
                    result = native.call_many([("f0", [raw, CANARY[:cap], SCRATCH[:scratch]])
                                               for raw, _, cap, scratch in panel], timeout=45)
                    for i, ((raw, (status, value), cap, scratch), observed) in enumerate(zip(panel, result, strict=True), offset):
                        self.assertEqual(observed.require_returned().value, status, i)
                        self.assertEqual(observed.arguments[0], raw, i)
                        self.assertEqual(observed.arguments[1], value + CANARY[len(value):cap], i)
                        self.assertEqual(observed.arguments[2][WORK:], SCRATCH[WORK:scratch], i)
