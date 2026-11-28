"""Actual original unsigned chunk plan/root and both unchanged HIA pipelines."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_batch_content_root import PARENT, ROOT, domain_hash, frame, typed, u32
from hia.tests.test_da_protocol_context import locked_reference

SOURCE = Path(__file__).resolve().parents[1] / "src/data_availability/batch_chunk_root.hepta"
ADAPTER = Path(__file__).with_name("rust_da_batch_chunk_root_reference.rs")
PROFILE = b"trnm.portable.v2.da-chunking-profile.v1"
COORDINATE = b"trnm.portable.v2.da-chunk-id.v1"
CHUNK_BYTES = b"trnm.portable.v2.da-chunk-bytes.v1"
CHUNK_LEAF = b"trnm.portable.v2.da-chunk-leaf.candidate.v1"
WORK = 3264
OUT = 68
MARK = b"\x91"
ORIGINAL = {0, 40, 41, 42, 100}


def independent(content, prefix, step):
    profile = domain_hash(PROFILE, struct.pack("<HBI", 1, 0, step))
    leaves = []
    for i, offset in enumerate(range(0, len(content), step)):
        payload = content[offset:offset+step]
        coord = prefix + profile + struct.pack("<IQ", i, len(payload))
        chunk = domain_hash(COORDINATE, coord)
        data = domain_hash(CHUNK_BYTES, typed(payload))
        leaves.append(domain_hash(CHUNK_LEAF, u32(i) + chunk + data))
    count = len(leaves)
    level = 0
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [domain_hash(PARENT, typed(CHUNK_LEAF) + u32(level) + a + b)
                  for a, b in zip(leaves[::2], leaves[1::2], strict=True)]
        level += 1
    return profile + domain_hash(ROOT, typed(CHUNK_LEAF) + u32(count) + leaves[0]) + u32(count)


def observed(raw, cases):
    at = 0
    for _ in range(cases):
        code, extent = struct.unpack_from("<BI", raw, at)
        start = at+5
        end = start+extent
        at = end + (0 if code else OUT)
        if code not in ORIGINAL or not 131 <= extent <= 513 or at > len(raw):
            raise ValueError("Unexpected original chunk commitment record")
        yield code, raw[start:end], raw[end:at]
    if at != len(raw):
        raise ValueError("Trailing original chunk commitment data")


def request(content, prefix, size, limit):
    return content + prefix + struct.pack("<III", size, limit, len(content))


class DaBatchChunkRoot(unittest.TestCase):
    def test_actual_original_chunk_fields_and_two_native_backends(self):
        source = frame([b"abc", b"zyx", b"foobar"])
        cap = MAX_EXTENT - 131 - 12
        boundary = [frame([b"Q"*(cap-8)]), frame([b"Q"*(cap-7)])]
        cases = [(source, size, 64, 0, 0) for size in (1, 2, 3, 4, 5, 7, 9, 12, 13, 26, 27, 28, 128)]
        cases += [(source, 7, 4, 0, 0),
                  (source, 7, 3, 0, 42),
                  (frame([b""]), 7, 1, 0, 41),
                  (frame([b"a", b"a"]), 2, 1, 0, 41),
                  (frame([]), 32, 1, 0, 40),
                  (frame([b"x"])+b"extra", 32, 1, 0, 100),
                  (u32(1)+u32(3)+b"ab", 32, 1, 0, 100),
                  (source, 7, 64, 1, 0),
                  (source, 7, 64, 2, 0),
                  (frame([b"zyx", b"abc", b"foobar"]), 7, 64, 0, 0),
                  (frame([b"Q"*24]), 1, 32, 0, 0)]
        over_count = len(cases)
        cases += [(frame([b"Q"*25]), 1, 64, 0, 0)]
        over_items = len(cases)
        cases += [(frame([bytes([i]) for i in range(33)]), 128, 64, 0, 0)]
        cases += [(raw, (len(raw)+2)//3, 64, 0, 0) for raw in boundary]
        corpus = b"".join(typed(struct.pack("<IIB", step, limit, variant)+raw)
                          for raw, step, limit, variant, _ in cases)
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-batch-chunk-") as tmp:
            rows = list(observed(locked_reference(Path(tmp),corpus,caller=ADAPTER),len(cases)))
        self.assertEqual([row[0] for row in rows],[x[4] for x in cases])
        self.assertEqual(rows[0][1], rows[1][1])
        variant_rows = [row for case,row in zip(cases,rows,strict=True) if case[3] in (1,2)]
        self.assertEqual(len(variant_rows),2)
        self.assertTrue(all(row[1] != rows[0][1] for row in variant_rows))
        self.assertTrue(all(row[2][32:64] != rows[5][2][32:64] for row in variant_rows))
        probes = []
        for j, ((raw, step, limit, _, wanted),(status, prefix, body)) in enumerate(zip(cases,rows,strict=True)):
            if wanted == 0:
                self.assertEqual(body, independent(raw,prefix,step), j)
            q = request(raw,prefix,step,limit)
            if j in (over_count,over_items):
                status,body = 100,b""
            probes.append((q,status,body,OUT+9,WORK+5))
        self.assertEqual([len(q[0]) for q in probes[-2:]], [MAX_EXTENT,MAX_EXTENT+1])
        above = (probes.pop()[0],100,b"",OUT+9,WORK+5)
        q, _, exp, _, _ = probes[4]
        at = len(source)
        controls = [
            (q,0,exp,OUT,WORK), (q,102,b"",OUT-1,WORK), (q,102,b"",OUT,WORK-1),
            (q[:-12]+b"\0"*4+q[-8:],100,b"",OUT,WORK),
            (q[:-8]+b"\0"*4+q[-4:],100,b"",OUT,WORK),
            (q[:-4]+u32(4),100,b"",OUT,WORK),
            (q[:at]+b"\x02"+q[at+1:],100,b"",OUT,WORK),
            (q[:at+40]+b"\xff"+q[at+41:],100,b"",OUT,WORK),
            (q[:at+77]+b"\x01"+q[at+78:],100,b"",OUT,WORK),
            (q[:-20]+b"\0"*8+q[-12:],100,b"",OUT,WORK),
        ]
        for backend in ("direct","selfhost"):
            opts = {"max_input_extent": MAX_EXTENT+1} if backend == "selfhost" else {}
            tests = probes + controls + ([above] if opts else [])
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend, **opts) as native:
                for start in range(0,len(tests),6):
                    panel=tests[start:start+6]
                    calls=native.call_many([("f0",[item,MARK*out,b"\xb4"*work])
                                            for item,_,_,out,work in panel],timeout=60)
                    for n, ((item,code,value,out,work), run) in enumerate(zip(panel,calls,strict=True),start):
                        self.assertEqual(run.require_returned().value,code,(backend,n))
                        self.assertEqual(run.arguments[:2],[item,value+MARK*(out-len(value))],(backend,n))
                        self.assertEqual(run.arguments[2][WORK:],b"\xb4"*max(0,work-WORK),(backend,n))
