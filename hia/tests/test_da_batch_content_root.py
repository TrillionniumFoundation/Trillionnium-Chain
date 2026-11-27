"""Locked original unsigned-batch content projection and both HIA backends."""
from hashlib import sha256
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_protocol_context import locked_reference

SOURCE = Path(__file__).resolve().parents[1] / "src/data_availability/batch_content_root.hepta"
ADAPTER = Path(__file__).with_name("rust_da_batch_content_root_reference.rs")
ITEM = b"trnm.portable.v2.da-transaction-item.candidate.v1"
LEAF = b"trnm.portable.v2.da-content-leaf.candidate.v1"
PARENT = b"trnm.portable.v2.da-merkle-parent.candidate.v1"
ROOT = b"trnm.portable.v2.da-merkle-root.candidate.v1"
WORK = 3072
OUT = 44
MARK = b"\xa7"


def u32(n):
    return struct.pack("<I", n)


def typed(data):
    return u32(len(data)) + data


def frame(rows):
    return u32(len(rows)) + b"".join(typed(row) for row in rows)


def domain_hash(domain, data):
    return sha256(typed(domain) + data).digest()


def independent(rows):
    leaves = []
    for i, row in enumerate(rows):
        item = domain_hash(ITEM, typed(row))
        leaves.append(domain_hash(LEAF, u32(i) + item + item))
    level = 0
    while len(leaves) > 1:
        paired = leaves + leaves[-1:] if len(leaves) % 2 else leaves
        leaves = [domain_hash(PARENT, typed(LEAF) + u32(level) + left + right)
                  for left, right in zip(paired[::2], paired[1::2], strict=True)]
        level += 1
    digest = domain_hash(ROOT, typed(LEAF) + u32(len(rows)) + leaves[0])
    return digest + struct.pack("<IQ", len(rows), len(frame(rows)))


def observed(raw, count):
    at = 0
    for _ in range(count):
        status = raw[at]
        at += 1
        if status not in (0, 40, 41, 100):
            raise ValueError("Unknown Rust unsigned content result")
        extent = OUT if not status else 0
        body = raw[at:at+extent]
        if len(body) != extent:
            raise ValueError("Short Rust unsigned content result")
        at += extent
        yield status, body
    if at != len(raw):
        raise ValueError("Trailing Rust unsigned content result")


class DaBatchContentRoot(unittest.TestCase):
    def test_original_unsigned_content_fields_and_two_pinned_hia_outputs(self):
        short = [b"\x00", b"\xff", b"\x00\xff"]
        thirty_three = [bytes([i])*i + bytes([255-i]) for i in range(33)]
        positives = [
            [short[0]], short[:2], short[1::-1], short, short[::-1],
            [b"A"*63+b"0", b"A"*63+b"1", b"A"*65+b"1"],
            [bytes(range(n)) for n in (1, 7, 8, 9, 55, 56, 57, 63, 64, 65, 127)],
            *(thirty_three[:count] for count in (4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33)),
        ]
        # Long, shared-prefix, unequal items of the same length must not be
        # deduplicated by length, a truncated prefix or by array order.
        prefixes = [b"Y"*((MAX_EXTENT-4)//4-5) + bytes([i]) for i in range(4)]
        positives += [prefixes, [b"Q"*(MAX_EXTENT-8)], [b"Q"*(MAX_EXTENT-7)]]
        negatives = [
            (frame([]), 40),
            (frame([b""]), 41),
            (frame([*short,b""]), 41),
            (frame([*short,short[0]]), 41),
            (frame([b"Y"*32768+b"A", b"Y"*32768+b"A"]), 41),
            (b"", 100), (u32(1), 100), (u32(1)+u32(3)+b"hi", 100),
            (frame([b"a"])+b"extra", 100), (frame([])+b"x", 100),
            (frame([b""])+b"extra", 100),
            (frame(short)[:-1], 100),
        ]
        cases = [(frame(rows), 0) for rows in positives] + negatives
        self.assertEqual(list(map(len, (cases[len(positives)-2][0],
                                       cases[len(positives)-1][0]))), [MAX_EXTENT, MAX_EXTENT+1])
        queries = b"".join(typed(raw) for raw, _ in cases)
        with tempfile.TemporaryDirectory(prefix="trnm-original-da-batch-content-") as tmp:
            exact = list(observed(locked_reference(Path(tmp), queries, caller=ADAPTER), len(cases)))
        self.assertEqual([c for c,_ in exact], [want for _,want in cases])
        self.assertEqual([body for _,body in exact[:len(positives)]],
                         [independent(rows) for rows in positives])
        self.assertNotEqual(exact[1][1][:32], exact[2][1][:32])
        self.assertNotEqual(exact[3][1][:32], exact[4][1][:32])

        over_count = positives.index(thirty_three)
        over_size = len(positives)-1
        accepted = [(raw, code, body, OUT+7, WORK+13)
                    for i, ((raw,_),(code,body)) in enumerate(zip(cases,exact,strict=True))
                    if i not in (over_count,over_size)]
        normal, body = cases[0][0], exact[0][1]
        accepted.extend([
            (cases[over_count][0],100,b"",OUT+7,WORK+13),
            (normal,102,b"",OUT-1,WORK),
            (normal,102,b"",OUT,WORK-1),
            (normal,0,body,OUT,WORK),
            (frame([]),40,b"",0,0),
            (normal,102,b"",0,0),
        ])
        for backend in ("direct","selfhost"):
            opts = {"max_input_extent": MAX_EXTENT+1} if backend == "selfhost" else {}
            samples = accepted + ([(cases[over_size][0],100,b"",OUT+7,WORK+13)] if opts else [])
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend, **opts) as native:
                for base in range(0,len(samples),6):
                    panel = samples[base:base+6]
                    actual = native.call_many([("f0", [raw, MARK*out, b"\xc5"*scratch])
                                               for raw,_,_,out,scratch in panel], timeout=60)
                    for i, ((raw, status, value, out, scratch), ran) in enumerate(
                            zip(panel, actual, strict=True), base):
                        self.assertEqual(ran.require_returned().value,status,(backend,i))
                        self.assertEqual(ran.arguments[:2],
                                         [raw, value+MARK*(out-len(value))],(backend,i))
                        self.assertEqual(ran.arguments[2][WORK:],
                                         b"\xc5"*max(0,scratch-WORK),(backend,i))
