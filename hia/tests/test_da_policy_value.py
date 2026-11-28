"""Original typed DA policy construction and hash, without runtime authority."""
import hashlib
from pathlib import Path
import re
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_author_authority_value import PUBLIC, P, point, req
from hia.tests.test_da_batch_author_transcript import authored
from hia.tests.test_da_committee_definition import MAX_U128, context, generated_public, member, sorted_members
from hia.tests.test_da_committee_id import DOMAIN as COMMITTEE_DOMAIN, descriptor
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/policy_value.hepta"
ADAPTER = Path(__file__).with_name("rust_da_policy_value_reference.rs")
DOMAIN = b"trnm.portable.v2.da-policy.candidate.v1"
COMMITTEE_SHA = "c500f5f96a597342a43a42c85ffde38f980c2b674fc0a06af04179f19022f7c5"
STATIC_STAGE = 141568
WORK = STATIC_STAGE + 10536
MAX_BODY = 10536
MARK = 0xA5
STATUSES = {0, 3, 6, 7, *range(201, 207), *range(208, 219)}
DEFAULT = (1, 2, 3, 4, 5, 6)
assert len(DOMAIN) == 39


def entry(key=PUBLIC[0], name=b"a", first=1, last=1, quota=1, sequences=1):
    return struct.pack("<I", len(name)) + name + req(key, name, first, last, quota, sequences)[:60]


def candidate(committee, authors, limits=DEFAULT):
    return (committee + struct.pack("<I", len(authors)) + b"".join(authors)
            + struct.pack("<IIIQQQI", *limits, len(committee)))


def reports(raw, count):
    at = 0
    for _ in range(count):
        status, size = struct.unpack_from("<BI", raw, at)
        start = at + 5
        at = start + size
        if status not in STATUSES or at > len(raw) or (status != 0 and size != 0):
            raise ValueError("Invalid original policy observation")
        yield status, raw[start:at]
    if at != len(raw):
        raise ValueError("Trailing original policy observations")


def validate_wire(query, report):
    committee_len = struct.unpack_from("<I", query, len(query) - 4)[0]
    chain_len = struct.unpack_from("<I", query, 36)[0]
    context_end = 2 + 74 + chain_len
    expected = (b"\x01\x00" + query[2:context_end] + query[context_end+1:context_end+9]
                + authored(COMMITTEE_DOMAIN, query[:committee_len]) + query[committee_len:-40]
                + query[committee_len-16:committee_len-4] + query[-40:-4])
    if report != expected + authored(DOMAIN, expected):
        raise AssertionError("Original Borsh body or original policy hash mismatch")


def derived_committee():
    # The bounded private prefix validator is mechanically identical to the
    # published original port except for its explicit extent and internal-only
    # destination. No input, key or previous committee decision is trusted.
    data = SOURCE.with_name("committee_id.hepta").read_bytes()
    if hashlib.sha256(data).hexdigest() != COMMITTEE_SHA:
        raise ValueError("Unknown original committee kernel")
    body = data.decode("ascii").split("\n", 1)[1]
    body = body[:body.index("\nend\n")+5]
    body = body.replace("fn f0(r:readbuf,o:mutbuf,w:mutbuf)", "fn dpp_committee(r:readbuf,w:mutbuf,n:u64)")
    body = body.replace(
        'block entry(r:readbuf,o:mutbuf,w:mutbuf)\n'
        '  raw:usize = buffer.len(r)\n'
        '  n:u64 = int.cast(raw) {"mode":"wrap"}',
        'block entry(r:readbuf,w:mutbuf,n:u64)',
    )
    body = body[:body.index("block output_size(")] + body[body.index("block digest("):]
    body = body.replace("branch same_x output_size(rx,ox,wx,nx)", "branch same_x digest(rx,ox,wx,nx)")
    body = body[:body.index("block publish(")] + """block publish()
  okay_s:u32 = const() {"value":0}
  ret(okay_s)
""" + body[body.index("block shape("):]
    body = body.replace("branch okay_z publish(oz,wz)", "branch okay_z publish()")
    result = re.sub(r"\bo(?:[1-9]|[a-z])?(?::mutbuf)?,", "", body)
    if re.search(r"(?<![.])\bo(?:[1-9]|[a-z])?\b", result):
        raise ValueError("Unexpected external output loan in private committee continuation")
    return result


class DaPolicyValue(unittest.TestCase):
    def test_original_constructor_wire_and_policy_hash_two_pinned_native_backends(self):
        src = SOURCE.read_text("ascii")
        self.assertEqual(src[src.index("fn dpp_committee("):], derived_committee())
        a, b, c = PUBLIC
        raw_a, raw_b = entry(a), entry(b, b"b")
        committee = descriptor([member()], bounds=(13, 16, 31, 40, 19))
        panel = []

        def add(authors, code=0, *, com=committee, limits=DEFAULT):
            panel.append((candidate(com, authors, limits), code))

        add([raw_a])
        add([raw_a, entry(c, b"a\0"), raw_b])
        add([entry(a, b"\x00"), entry(b, b"\xff"), entry(c, b"\xff\x00")])
        add([entry(point(3), b"a"), entry(point(P + 3), b"a\x00")])
        add([entry(a, b"x" * 256, 2**64-1, 2**64-1, 16, 19)], limits=(31,2,3,4,5,6))
        add([entry(a, b"\xff")], com=descriptor([member()], epoch=2**64-1, ctx=context(b"z"*128)))
        add([], 218)
        for i in range(6):
            add([entry(point(2), name=b"")], 215, limits=DEFAULT[:i]+(0,)+DEFAULT[i+1:])
        add([entry(point(2))], 216, limits=(32, 2, 3, 4, 5, 6))
        add([raw_a, raw_a], 217)
        add([raw_a, entry(a, b"b")], 217)
        add([raw_b, raw_a], 217)
        add([entry(a, b"x\x00"), entry(b, b"x")], 217)
        add([entry(a, quota=17)], 217)
        add([entry(a, sequences=20)], 217)
        add([raw_b, entry(point(1,1), b"a", quota=17)], 7)
        add([raw_b, entry(point(2), b"a", quota=17)], 6)
        add([entry(point(2), name=b"")], 3)
        add([entry(a, name=b"x"*257)], 3)
        add([entry(a, first=0)], 3)
        add([entry(a, first=3, last=2)], 3)
        add([entry(a, quota=0)], 3)
        add([entry(a, sequences=0)], 3)
        add([entry(a, quota=17), entry(point(2), b"b")], 217)

        key = member()
        wrong_hash = key[:-1] + bytes([key[-1] ^ 1])
        weak = member(point(1,1))
        invalid = member(point(2))
        huge = member(weight=MAX_U128)
        malformed_committees = [
            (descriptor([wrong_hash]), 201), (descriptor([invalid]), 202),
            (descriptor([weak]), 203), (descriptor([]), 204),
            (descriptor([key,key]), 205),
            (descriptor(sorted_members(huge, member(b))), 206),
            (descriptor([], ctx=context(b"", schema=2), namespace=255), 208),
            (descriptor([], ctx=context(b""), namespace=255), 209),
            (descriptor([key], bounds=(0,2,3,4,5)), 210),
            (descriptor([huge]), 211), (descriptor([key], threshold=0), 212),
            (descriptor([key], namespace=1), 213), (descriptor([key], namespace=255), 214),
        ]
        for bad, status in malformed_committees:
            add([entry(point(2), name=b"")], status, com=bad, limits=(0,2,3,4,5,6))

        pubkeys = generated_public(33)
        many = [entry(k, bytes([i])+b"x"*255) for i,k in enumerate(pubkeys)]
        wide_ctx = descriptor([member()], ctx=context(b"z"*128))
        add(many[:32], com=wide_ctx)
        first_wide = len(panel)-1
        add(many[:33], com=wide_ctx)
        overflow_count = len(panel)-1
        overhead = len(candidate(descriptor([member(validator=b"")]), [raw_a]))
        for d in (0,1):
            add([raw_a], com=descriptor([member(validator=b"Q"*(MAX_EXTENT-overhead+d))]))
        self.assertEqual([len(run) for run,_ in panel[-2:]], [MAX_EXTENT, MAX_EXTENT+1])

        queries = b"".join(struct.pack("<I", len(run))+run for run,_ in panel)
        with tempfile.TemporaryDirectory(prefix="trnm-da-policy-original-") as directory:
            original = list(reports(locked_reference(Path(directory), queries, caller=ADAPTER), len(panel)))
        self.assertEqual([status for status,_ in original], [want for _,want in panel])
        self.assertEqual(set(code for code,_ in original), STATUSES)
        self.assertEqual(len(original[first_wide][1]), MAX_BODY+32)
        for (run,_), (status,payload) in zip(panel,original,strict=True):
            if status == 0:
                validate_wire(run, payload)

        probes = [(run, status, value, len(value)+9, WORK+7)
                  for i, ((run,_),(status,value)) in enumerate(zip(panel,original,strict=True))
                  if i not in (overflow_count,len(panel)-1)]
        positive, success = panel[0][0], original[0][1]
        limit = STATIC_STAGE + len(success) - 32
        probes += [
            (panel[overflow_count][0],100,b"",17,WORK),
            (b"",100,b"",17,0),
            (positive[:-1],100,b"",17,WORK),
            (positive[:-4]+b"\x00"*4,100,b"",17,WORK),
            (positive[:-4]+b"\xff"*4,100,b"",17,WORK),
            (positive[:-40]+b"x"+positive[-40:],100,b"",17,WORK),
            (positive[:len(committee)] + b"\x01\x00\x00\x00\xff\xff\xff\xff" +
             positive[-40:],100,b"",17,WORK),
            (positive,102,b"",len(success)-1,limit),
            (positive,102,b"",len(success),limit-1),
            (positive,0,success,len(success),limit),
        ]
        for backend in ("direct", "selfhost"):
            kwargs = {"max_input_extent": MAX_EXTENT+1} if backend == "selfhost" else {}
            measured = probes + ([(panel[-1][0],100,b"",17,WORK)] if kwargs else [])
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend, **kwargs) as native:
                for begin in range(0,len(measured),10):
                    group = measured[begin:begin+10]
                    out = native.call_many([("f0", [run, bytes([MARK])*capacity, b"\x79"*work])
                                            for run,_,_,capacity,work in group], timeout=60)
                    for i, ((run,status,value,capacity,work),observed) in enumerate(zip(group,out,strict=True),begin):
                        self.assertEqual(observed.require_returned().value,status,(backend,i))
                        self.assertEqual(observed.arguments[0],run,(backend,i))
                        self.assertEqual(observed.arguments[1],value+bytes([MARK])*(capacity-len(value)),(backend,i))
                        self.assertEqual(observed.arguments[2][WORK:],b"\x79"*max(0,work-WORK),(backend,i))
