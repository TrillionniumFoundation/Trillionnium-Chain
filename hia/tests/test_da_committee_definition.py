"""Original DA committee constructor as an offline value, not committee authority."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_author_authority_value import PUBLIC, P, point
from hia.tests.test_da_batch_author_transcript import authored
from hia.tests.test_da_member_definition import request
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/committee_definition.hepta"
ADAPTER = Path(__file__).with_name("rust_da_committee_definition_reference.rs")
CODEC = ROOT / "trillionnium/crates/trnm-data-availability/src/codec.rs"
WORK = 141536
TAIL = 28
OVERHEAD = 19
LIMIT = MAX_EXTENT - OVERHEAD
MAX_U128 = (1 << 128) - 1
HALF = MAX_U128 // 2
BOUNDS = (1, 2, 3, 4, 5)
OPTIONS = (None, b"", b"\x00\xff")
SCRATCH = b"\x79" * (WORK + 7)


def member(key=PUBLIC[0], weight=1, validator=None, *, scheme=0):
    body = struct.pack("<H", scheme) + request(key=key, weight=weight, validator=validator)
    return body + authored(b"trnm.portable.v2.da-member.v1", body)


def sorted_members(*rows):
    # Only cases intended to satisfy the original ordering are generated sorted.
    return sorted(rows, key=lambda row: row[-32:])


def context(chain=b"da", schema=1, version=1):
    return struct.pack("<H", schema) + bytes(range(32)) + struct.pack("<I", len(chain)) + chain + (
        struct.pack("<I", version) + b"\x83" * 32)


def frame(rows, *, ctx=None, bounds=BOUNDS, epoch=0):
    return (context() if ctx is None else ctx) + struct.pack("<QI", epoch, len(rows)) + b"".join(rows) + (
        struct.pack("<IQQII", *bounds))


def generated_public(n):
    # Generate public-only compressed coordinates with no scalar or keypair.
    # The unchanged original reparses them and reconstructs each accepted member.
    d = -121665 * pow(121666, -1, P) % P
    keys = []
    for i in range(256):
        y = int.from_bytes(hashlib.sha256(b"committee value fixtures/" + bytes([i])).digest(), "little") % P
        x2 = (y*y-1) * pow((d*y*y+1) % P, -1, P) % P
        if pow(x2, (P-1)//2, P) != 1:
            continue
        keys.append(point(y, i & 1))
        if len(keys) == n:
            return keys
    raise AssertionError("Insufficient generated committee fixture points")


def records(raw, count):
    cursor = 0
    for _ in range(count):
        code, width = struct.unpack_from("<BI", raw, cursor)
        cursor += 5
        proposed = raw[cursor:cursor+width]
        cursor += len(proposed)
        if len(proposed) != width or code not in {0, *range(201, 211)} or (code and width):
            raise ValueError("Invalid original committee observation")
        yield code, proposed
    if cursor != len(raw):
        raise ValueError("Original observation has trailing bytes")


class DaCommitteeDefinition(unittest.TestCase):
    def test_unchanged_public_original_and_two_stock_native_emitters(self):
        small = member()
        alien = member(key=PUBLIC[1])
        weak = member(key=point(1, 1))
        invalid = member(key=point(2))
        forged = invalid[:-1] + bytes([invalid[-1] ^ 1])
        upper = tuple(sorted_members(member(weight=MAX_U128), alien))
        duplicate = sorted_members(member(validator=b"first"), member(validator=b"other"))
        reversed_rows = sorted_members(small, alien)[::-1]
        signed_other = PUBLIC[0][:-1] + bytes([PUBLIC[0][-1] ^ 128])
        carry_threshold_total = ((1 << 64) * 3 - 2) // 2
        valid_bound_edges = (0xffffffff, (1 << 64)-1, (1 << 64)-1, 0xffffffff, 0xffffffff)
        guarded = (0, 2, 3, 4, 5)

        def row(rows, status=0, **kw):
            return frame(rows, **kw), status, sum(int.from_bytes(v[34:50], "little") for v in rows)

        panel = [row([member(weight=w)]) for w in (
            1, 2, 3, (1<<32)-1, 1<<32, (1<<64)-1, 1<<64, (1<<64)+1,
            carry_threshold_total, carry_threshold_total+1, (1<<96)-1, 1<<96, HALF-1, HALF,
        )]
        panel += [
            row(sorted_members(member(weight=(1<<64)-1), member(key=PUBLIC[1], weight=2))),
            row(sorted_members(small, member(key=signed_other))),  # same Y, different sign
            row(sorted_members(member(key=point(3)), member(key=point(P+3)))),  # same point, two raw keys
            row([small], bounds=valid_bound_edges, ctx=context(b"\0\x7f"+b"a"*126), epoch=(1<<64)-1),
            row([weak], 203), row([invalid], 202), row([forged], 201),
            row([member(scheme=1, key=point(1))], 201),
            row([member(weight=0, key=point(2))], 201),
            row([], 204, ctx=context(b"bad", schema=2), bounds=guarded),
            row([small, small], 205), row(duplicate, 205), row(reversed_rows, 205),
            row([*reversed_rows, forged], 205),
            row([reversed_rows[0], forged, reversed_rows[1]], 201),
            row([*upper, weak], 206, ctx=context(b"", schema=2), bounds=guarded),
            row([*upper], 206), row([member(weight=1<<127)], 207),
            row([member(weight=MAX_U128)], 207, ctx=context(), bounds=guarded),
            row([member(weight=1<<127), weak], 203, ctx=context(), bounds=guarded),
            row([small], 208, ctx=context(b"", version=2), bounds=guarded),
            row([small], 208, ctx=context(b"", schema=0), bounds=guarded),
            row([small], 209, ctx=context(b""), bounds=guarded),
            row([small], 209, ctx=context("普通".encode()), bounds=guarded),
            row([small], 209, ctx=context(b"a"*129), bounds=guarded),
        ]
        panel += [row([small], 210, bounds=tuple(0 if j == i else x for j, x in enumerate(BOUNDS)))
                  for i in range(5)]
        keys = generated_public(33)
        large = sorted_members(*(member(k, i+1, OPTIONS[i % 3]) for i, k in enumerate(keys)))
        panel += [row(large[:32]), row(large)]
        overhead = len(frame([member(validator=b"")]))
        panel += [row([member(validator=b"z"*(LIMIT-overhead + i))]) for i in (0, 1)]
        inputs = b"".join(struct.pack("<I", len(q)) + q for q, _, _ in panel)
        source = hashlib.sha256(CODEC.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-committee-") as tmp:
            exact = list(records(locked_reference(Path(tmp), inputs, caller=ADAPTER), len(panel)))
        self.assertEqual(source, hashlib.sha256(CODEC.read_bytes()).digest())
        self.assertEqual([x[0] for x in exact], [p[1] for p in panel])
        for (raw, status, total), (_, result) in zip(panel, exact, strict=True):
            if status == 0:
                ctx_len = 74 + struct.unpack_from("<I", raw, 34)[0]
                threshold = (total * 2 // 3 + 1).to_bytes(16, "little")
                self.assertEqual(result, b"\1\0"+raw[:ctx_len]+b"\0"+raw[ctx_len:-TAIL]+threshold+raw[-TAIL:])
        self.assertEqual([len(x[1]) for x in exact[-2:]], [MAX_EXTENT, MAX_EXTENT+1])
        probes = [(q, c, v, min(MAX_EXTENT, max(len(v)+7, 160)), len(SCRATCH))
                  for (q, _, _), (c, v) in zip(panel, exact, strict=True)
                  if q not in (panel[-1][0], panel[-3][0])]
        good = panel[0][0]
        start = len(context()) + 12
        probes += [
            (b"", 100, b"", 0, 0),
            (good[:113], 100, b"", 149, WORK),
            (frame([])+b"x", 100, b"", 149, WORK),
            (good[:34]+b"\xff"*4+good[38:], 100, b"", 149, WORK),
            (good[:start+50]+b"\x02"+good[start+51:], 100, b"", 149, WORK),
            (good[:start+50]+b"\x01"+b"\xff"*4+good[start+55:], 100, b"", 149, WORK),
            (good[:-TAIL]+b"x"+good[-TAIL:], 100, b"", 149, WORK),
            (good, 102, b"", 0, WORK-1),
            (good, 102, b"", len(exact[0][1])-1, WORK),
            (good, 0, exact[0][1], len(exact[0][1]), WORK),
            (panel[-3][0], 100, b"", 149, WORK),
            (panel[-1][0], 100, b"", 0, WORK),
        ]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                for at in range(0, len(probes), 7):
                    batch = probes[at:at+7]
                    measured = native.call_many(
                        [("f0", [raw, b"\xa5"*out, SCRATCH[:work]]) for raw, _, _, out, work in batch],
                        timeout=60)
                    for i, ((raw, code, val, out, work), result) in enumerate(
                            zip(batch, measured, strict=True), at):
                        self.assertEqual(result.require_returned().value, code, i)
                        self.assertEqual(result.arguments[:2], [raw, val+b"\xa5"*(out-len(val))], i)
                        self.assertEqual(result.arguments[2][WORK:], SCRATCH[WORK:work], i)
