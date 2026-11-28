"""Native complete DA descriptor revalidation and identity, without trust."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_author_authority_value import PUBLIC, P, point
from hia.tests.test_da_batch_author_transcript import authored
from hia.tests.test_da_committee_definition import (
    CODEC, HALF, MAX_U128, OPTIONS, SCRATCH, TAIL, WORK, context, frame,
    generated_public, member, sorted_members,
)
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/committee_id.hepta"
CONSTRUCTOR = SOURCE.with_name("committee_definition.hepta")
ADAPTER = Path(__file__).with_name("rust_da_committee_id_reference.rs")
DOMAIN = b"trnm.portable.v2.da-committee.v1"
STATUSES = {0, *range(201, 207), *range(208, 215)}


def descriptor(rows, threshold=None, *, ctx=None, namespace=0, schema=1, **kw):
    ctx = context() if ctx is None else ctx
    plain = frame(rows, ctx=ctx, **kw)
    if threshold is None:
        total = sum(int.from_bytes(row[34:50], "little") for row in rows)
        threshold = min(MAX_U128, total * 2 // 3 + 1)
    return (struct.pack("<H", schema) + ctx + bytes([namespace]) + plain[len(ctx):-TAIL]
            + threshold.to_bytes(16, "little") + plain[-TAIL:])


def records(raw, count):
    cursor = 0
    for _ in range(count):
        code, width = struct.unpack_from("<BI", raw, cursor)
        cursor += 5
        digest = raw[cursor:cursor+width]
        cursor += len(digest)
        if len(digest) != width or code not in STATUSES or width != (0 if code else 32):
            raise ValueError("Invalid original committee ID observation")
        yield code, digest
    if cursor != len(raw):
        raise ValueError("Original committee ID observation has trailing bytes")


class DaCommitteeId(unittest.TestCase):
    def test_locked_public_original_committee_id_and_two_stock_native_emitters(self):
        a = member()
        b = member(PUBLIC[1])
        weak = member(point(1, 1))
        invalid = member(point(2))
        wrong_hash = weak[:-1] + bytes([weak[-1] ^ 1])
        overweight = member(weight=1<<127)
        sorted_ok = sorted_members(a,b)
        sorted_sum = sorted_members(member(weight=MAX_U128), b)
        twice_key = sorted_members(member(validator=b"A"), member(validator=b"B"))
        tie = ((1 << 64) * 3 - 2) // 2

        def row(rows, status=0, **kw):
            return descriptor(rows, **kw), status

        panel = [
            row([a]), row([a], epoch=1), row([a], ctx=context(b"das")),
            row([a], ctx=context(b"\0\x7f"+b"a"*126)),
            row([a], bounds=(2, 2, 3, 4, 5)), row([a], bounds=(1, 3, 3, 4, 5)),
            row([a], bounds=(1, 2, 4, 4, 5)), row([a], bounds=(1, 2, 3, 5, 5)),
            row([a], bounds=(1, 2, 3, 4, 6)), row([b]),
            row([member(validator=b"")]), row([member(validator=b"\0\xff")]),
            row(sorted_ok), row(sorted_members(member(point(3)), member(point(P+3)))),
        ]
        panel += [row([member(weight=w)]) for w in ((1 << 64)-1, 1<<64, tie, tie+1, HALF)]
        panel += [
            row([], 204), row([wrong_hash], 201), row([weak], 203), row([invalid], 202),
            row([member(weight=0, key=point(2))], 201),
            row([member(scheme=1, key=point(1))], 201),
            row([a,a], 205), row(twice_key, 205), row(sorted_ok[::-1], 205),
            row([*sorted_ok[::-1], wrong_hash], 205),
            row([sorted_ok[1], wrong_hash, sorted_ok[0]], 201),
            row(sorted_sum, 206), row([*sorted_sum, weak], 206),
            row([overweight], 211), row([overweight, weak], 203),
            row([a], 212, threshold=0), row([a], 212, threshold=2),
            row([member(weight=9)], 212, threshold=6),
            row([member(weight=tie)], 212, threshold=(1<<64)+1),
            row([wrong_hash], 201, threshold=0),
            row([], 208, ctx=context(b"", schema=2), schema=9, namespace=1),
            row([weak], 208, ctx=context(b"", version=2), namespace=255),
            row([], 209, ctx=context(b""), namespace=1),
            row([weak], 209, ctx=context("完整".encode()), namespace=1),
            row([a], 209, ctx=context(b"z"*129)),
            row([], 213, namespace=1, schema=9),
            row([overweight], 214, namespace=255, bounds=(0, 2, 3, 4, 5)),
            row([weak], 210, schema=2, threshold=0), row([], 210, schema=0),
        ]
        bounds = (1, 2, 3, 4, 5)
        panel += [row([overweight], 210, bounds=bounds[:i]+(0,)+bounds[i+1:]) for i in range(5)]
        keys = generated_public(33)
        many = sorted_members(*(member(k, i+1, OPTIONS[i % 3]) for i,k in enumerate(keys)))
        panel += [row(many[:32]), row(many)]
        overhead = len(descriptor([member(validator=b"")]))
        panel += [row([member(validator=b"Q"*(MAX_EXTENT-overhead+i))]) for i in (0,1)]
        definition_source = CONSTRUCTOR.read_bytes()
        digest_source = SOURCE.read_bytes()
        # The exact member accumulation CFG and imported helper source used
        # for the constructor remain anchored; the enclosing validators differ.
        def member_scan(blob):
            return blob[blob.index(b"block loop("):blob.index(b"block threshold(")]
        self.assertEqual(member_scan(digest_source), member_scan(definition_source))
        inputs = b"".join(struct.pack("<I", len(q)) + q for q,_ in panel)
        codec = hashlib.sha256(CODEC.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-committee-id-") as tmp:
            exact = list(records(locked_reference(Path(tmp), inputs, caller=ADAPTER), len(panel)))
        self.assertEqual(hashlib.sha256(CODEC.read_bytes()).digest(), codec)
        self.assertEqual([x[0] for x in exact], [c for _,c in panel])
        self.assertEqual(set(c for c,_ in exact), STATUSES)
        self.assertEqual(len({digest for _, digest in exact[:19]}), 19)
        self.assertEqual([len(q) for q,_ in panel[-2:]], [MAX_EXTENT, MAX_EXTENT+1])
        for (raw, _), (code, digest) in zip(panel, exact, strict=True):
            if code == 0:
                self.assertEqual(digest, authored(DOMAIN, raw))
        good = panel[0][0]
        at = len(context()) + 15
        digest = exact[0][1]
        probes = [(q, c, val, 39, len(SCRATCH))
                  for (q,_), (c,val) in zip(panel, exact, strict=True)
                  if q not in (panel[-1][0],panel[-3][0])]
        probes += [
            (b"", 100, b"", 0, 0),
            (good[:132], 100, b"", 39, WORK),
            (good[:36]+b"\xff"*4+good[40:], 100, b"", 39, WORK),
            (good[:at+50]+b"\x02"+good[at+51:], 100, b"", 39, WORK),
            (good[:at+50]+b"\x01"+b"\xff"*4+good[at+55:], 100, b"", 39, WORK),
            (good[:-44]+b"x"+good[-44:], 100, b"", 39, WORK),
            (good[:at-4]+b"\xff"*4+good[at:], 100, b"", 39, WORK),
            (descriptor([])+b"x", 100, b"", 39, WORK),
            (panel[-3][0], 100, b"", 39, WORK),
            (good, 102, b"", 0, WORK-1),
            (good, 102, b"", 31, WORK),
            (good, 0, digest, 32, WORK),
        ]
        for backend in ("direct", "selfhost"):
            kwargs = {"max_input_extent": MAX_EXTENT+1} if backend == "selfhost" else {}
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend, **kwargs) as native:
                measured_probes = probes + ([(panel[-1][0], 100, b"", 39, WORK)] if kwargs else [])
                for offset in range(0, len(measured_probes), 7):
                    batch = measured_probes[offset:offset+7]
                    measured = native.call_many(
                        [("f0", [raw, b"\xa5"*out, SCRATCH[:work]]) for raw,_,_,out,work in batch],
                        timeout=60)
                    for i, ((raw, code, val, out, work), result) in enumerate(
                            zip(batch, measured, strict=True), offset):
                        self.assertEqual(result.require_returned().value, code, i)
                        self.assertEqual(result.arguments[:2], [raw, val+b"\xa5"*(out-len(val))], i)
                        self.assertEqual(result.arguments[2][WORK:], SCRATCH[WORK:work], i)
