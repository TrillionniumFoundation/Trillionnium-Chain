"""Public original DA member value vs both stock emitters; no committee authority."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_author_authority_value import PUBLIC, P, point
from hia.tests.test_da_batch_author_transcript import authored
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/member_definition.hepta"
ADAPTER = Path(__file__).with_name("rust_da_member_definition_reference.rs")
CODEC = ROOT / "trillionnium/crates/trnm-data-availability/src/codec.rs"
WORK = 140512
SCRATCH = b"\x79" * (WORK + 7)
NATIVE_RAW_LIMIT = MAX_EXTENT - 34
OUTPUT_SMALL = b"\xa5" * 219


def request(key=PUBLIC[0], weight=1, validator=None, storage=bytes(range(32)), bond=b"\x7f"*32):
    option = b"\x00" if validator is None else b"\x01"+struct.pack("<I", len(validator))+validator
    return key + weight.to_bytes(16, "little") + option + storage + bond


def records(raw, count):
    cursor = 0
    for _ in range(count):
        code, width = struct.unpack_from("<BI", raw, cursor)
        cursor += 5
        proposed = raw[cursor:cursor+width]
        cursor += len(proposed)
        if len(proposed) != width or code not in {0, 201, 202, 203} or (code and width):
            raise ValueError("Invalid original member observation")
        yield code, proposed
    if cursor != len(raw):
        raise ValueError("Original observation has trailing bytes")


class DaMemberDefinition(unittest.TestCase):
    def test_locked_public_original_and_two_native_emitters(self):
        panel = [request(key) for key in PUBLIC]
        panel += [request(weight=w) for w in (0, (1<<64)-1, 1<<64, 1<<127, (1<<128)-1)]
        panel += [request(validator=b""), request(validator=b"\xff\x00\x01"),
                  request(validator=bytes(range(256))), request(storage=b"\0"*32, bond=b"\0"*32)]
        panel += [request(key=point(1, 1), weight=0), request(key=point(2), weight=0)]
        begin = len(panel)
        panel += [request(key=point(y, sign)) for sign in (0, 1) for y in (*range(19), *range(P-1, P+19))]
        panel += [request(key=hashlib.sha256(b"DA member constructor raw point " + bytes([i])).digest())
                  for i in range(12)]
        panel += [request(validator=b"x" * (NATIVE_RAW_LIMIT-117)),
                  request(validator=b"x" * (NATIVE_RAW_LIMIT-116))]
        binding = hashlib.sha256(CODEC.read_bytes()).digest()
        inputs = b"".join(struct.pack("<I", len(raw))+raw for raw in panel)
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-member-") as tmp:
            exact = list(records(locked_reference(Path(tmp), inputs, caller=ADAPTER), len(panel)))
        self.assertEqual(hashlib.sha256(CODEC.read_bytes()).digest(), binding)
        self.assertEqual(len(panel), 106)
        self.assertEqual([code for code, _ in exact[:8]], [0, 0, 0, 201, 0, 0, 0, 0])
        self.assertEqual([item[0] for item in exact[12:14]], [201, 201])
        self.assertEqual({e[0] for e in exact}, {0, 201, 202, 203})
        self.assertNotEqual(exact[0][1][-32:], exact[8][1][-32:])  # None is not Some(empty).
        seen = dict(zip(panel[begin:], exact[begin:], strict=True))
        for y in (0, 1, P-1, P, P+1):
            for sign in (0, 1):
                self.assertEqual(seen[request(key=point(y, sign))], (203, b""))
        for original, (code, result) in zip(panel, exact, strict=True):
            if code == 0:
                body = b"\0\0"+original
                self.assertEqual(result, body+authored(b"trnm.portable.v2.da-member.v1", body))
        self.assertEqual([len(x) for x in panel[-2:]], [NATIVE_RAW_LIMIT, NATIVE_RAW_LIMIT+1])
        self.assertEqual([len(x[1]) for x in exact[-2:]], [MAX_EXTENT, MAX_EXTENT+1])
        known = panel[0]
        controls = [
            (b"", 100, b"", 0, 0),
            (known[:112], 100, b"", 200, WORK),
            (known+b"\x00", 100, b"", 200, WORK),
            (known[:48]+b"\x02"+known[49:], 100, b"", 200, WORK),
            (panel[8][:49]+b"\xff"*4+panel[8][53:], 100, b"", 200, WORK),
            (known, 102, b"", 200, WORK-1),
            (known, 102, b"", 146, WORK),
            (known, 0, exact[0][1], 147, WORK),
            (panel[12], 201, b"", 0, 0),
            (request(key=point(1, 1)), 203, b"", 0, WORK),
            (panel[-1], 100, b"", 0, WORK),
        ]
        probes = [(r, code, v, min(MAX_EXTENT, max(len(v)+5, len(OUTPUT_SMALL))), len(SCRATCH))
                  for r, (code, v) in zip(panel[:-1], exact[:-1], strict=True)] + controls
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                for at in range(0, len(probes), 10):
                    batch = probes[at:at+10]
                    measured = native.call_many(
                        [("f0", [raw, b"\xa5"*out, SCRATCH[:work]]) for raw, _, _, out, work in batch],
                        timeout=60)
                    for i, ((raw, code, val, out, work), result) in enumerate(
                            zip(batch, measured, strict=True), at):
                        self.assertEqual(result.require_returned().value, code, i)
                        self.assertEqual(result.arguments[:2], [raw, val+b"\xa5"*(out-len(val))], i)
                        self.assertEqual(result.arguments[2][WORK:], SCRATCH[WORK:work], i)
