"""Two held immutable TCM1 chunks and the original private one-slot state transition."""
from functools import lru_cache
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.cache_payload_transcript_original import original
from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import CHUNK, MARK, MAX_MANIFEST, SCRATCH, change
from hia.tests.test_da_cell_cache_payload_held_read import canonical, data

SOURCE=Path(__file__).parents[1]/"src/data_availability/cell_cache_payload_transcript.hepta"
STAGING=1536
RECORD=96
CAP=MAX_MANIFEST
SEEK, READ=0,1
U64_MAX=(1<<64)-1
SIZE=CHUNK


def request(m,a,b,ops):
    return struct.pack("<III",len(m),len(a),len(ops))+b"".join(
        struct.pack("<BQ",*op) for op in ops)+m+a+b


def observation(pos,slot,value=b"",code=0):
    return struct.pack("<QQQQ",code,pos,slot,len(value))+value+bytes(64-len(value))


@lru_cache(maxsize=1)
def cases():
    a=data(SIZE)
    b=b"second held row"
    m=canonical([a,b],width=SIZE)
    s=SIZE
    e=s+len(b)
    cross=((SEEK,s-3),(READ,64),(READ,4),(READ,3),(SEEK,s-1),(READ,8),(READ,0),(READ,64))
    results=((s-3,0),(s,1,a[-3:]),(s+4,2,b[:4]),(s+7,2,b[4:7]),
             (s-1,2),(s,1,a[-1:]),(s,1),(e,2,b))
    wrong_len=canonical([a,b[:3]],width=SIZE,size=e)
    ops=((READ,2),(SEEK,s),(READ,1),(READ,2),(SEEK,2),(READ,2),(SEEK,U64_MAX),(READ,1))
    miss=lambda code:((2,1,a[:2]),(s,1),(s,0,b"",code),(s,0,b"",code),
                      (2,0),(4,1,a[2:4]),(U64_MAX,1),(U64_MAX,1))
    right=((SEEK,e),(READ,64),(SEEK,s),(READ,0),(READ,64),(READ,64),(SEEK,0),(READ,2))
    one=CAP//2
    full_a=data(one)
    full_ops=((SEEK,one-5),(READ,64),(READ,64),(SEEK,one-1),(READ,2),(READ,2),(SEEK,U64_MAX),(READ,1))
    provisional=canonical([full_a,b],width=one)
    full_b=(b"Z"+data(one))[:CAP-len(request(provisional,full_a,b"",full_ops))]
    full=canonical([full_a,full_b],width=one)
    raw_max=request(full,full_a,full_b,full_ops)
    assert len(raw_max)==CAP
    values=((one-5,0),(one,1,full_a[-5:]),(one+64,2,full_b[:64]),
            (one-1,2),(one,1,full_a[-1:]),(one+2,2,full_b[:2]),(U64_MAX,2),(U64_MAX,2))
    equal_rows=canonical([a,a],width=SIZE)
    equal_seq=((SEEK,s-1),(READ,1),(READ,1),(SEEK,s-1),(READ,1))
    return [(request(equal_rows,a,a,equal_seq),
             ((s-1,0),(s,1,a[-1:]),(s+1,2,a[:1]),(s-1,2),(s,1,a[-1:]))),
            (request(m,a,b,cross),results),
            (request(m,a,b"",ops),miss(247)),
            (request(m,a,b[:-1]+b"!",ops),miss(247)),
            (request(wrong_len,a,b[:3],ops),miss(248)),
            (request(wrong_len,a,b"xyz",ops),miss(247)),
            (request(m,b"",b,right),((e,0),(e,0),(s,0),(s,0),(e,2,b),(e,2),(0,2),(0,0,b"",247))),
            (request(m,a,b,((READ,64),)),((64,1,a[:64]),)),
            (raw_max,values),
            (request(full,full_a,full_b[:-1]+bytes([full_b[-1]^1]),full_ops),
             ((one-5,0),(one,1,full_a[-5:]),(one,0,b"",247),(one-1,0),(one,1,full_a[-1:]),
              (one,0,b"",247),(U64_MAX,0),(U64_MAX,0)))]


def rust_cases():
    raw=b"".join(struct.pack("<I",len(frame))+frame for frame,_ in cases())
    with tempfile.TemporaryDirectory(prefix="trnm-held-transcript-rust-") as d:
        return original(Path(d),raw)


class DaCellCachePayloadTranscript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules={k:cls.enterClassContext(NativeModule(SOURCE,backend=k,byte_exports=("f0",)))
                     for k in ("direct","selfhost")}
        if len({x.artifact_sha256 for x in cls.modules.values()})!=2:
            raise ValueError("Both exact stock artifacts required")

    def invoke(self, m, frame, oracle=b"", code=0, *, output=None, work=None):
        o=MARK*(len(oracle)+7 if output is None else output)
        w=SCRATCH*(STAGING+len(oracle)+5 if work is None else work)
        actual=m.call("f0",[frame,o,w],timeout=45).require_returned()
        self.assertEqual((actual.abi_status,actual.value),(0,code))
        self.assertEqual(actual.arguments[:2],[frame,oracle+o[len(oracle):]])
        if code:
            self.assertEqual(actual.arguments[2],w)
        else:
            end=STAGING+len(oracle)
            self.assertEqual(actual.arguments[2][end:],w[end:])
            self.assertEqual(actual.arguments[2][1256:STAGING],w[1256:STAGING])

    def test_locked_original_and_stock_transcript(self):
        actual,digest=rust_cases()
        self.assertEqual(len(digest),64)
        off=0
        for index,(frame,records) in enumerate(cases()):
            expected=b"".join(observation(*r) for r in records)
            got=actual[off:off+len(expected)]
            self.assertEqual(got,expected,index)
            off+=len(expected)
            for k,m in self.modules.items():
                with self.subTest(stock=k,case=index):
                    self.invoke(m,frame,got,work=STAGING+len(got))
        self.assertEqual(off,len(actual))

    def test_atomic_late_invalid_control_and_loan_bounds(self):
        a=data(SIZE)
        b=b"tail"
        m=canonical([a,b],width=SIZE)
        legal=request(m,a,b,((READ,1),(SEEK,0)))
        good=observation(1,1,a[:1])+observation(0,1)
        for m0 in self.modules.values():
            self.invoke(m0,legal,good,output=len(good),work=STAGING+len(good))
            self.invoke(m0,legal,code=102,output=len(good)-1,work=STAGING+len(good))
            self.invoke(m0,legal,code=102,output=len(good),work=STAGING+len(good)-1)
            for bad in (change(legal,21,b"\x02"),request(m,a,b,((READ,1),(READ,65))),
                        legal[:12],change(legal,4,struct.pack("<I",CAP)),
                        request(m,a,b,()),request(m,a,b,((READ,1),)*9),
                        request(canonical([b"x"]),b"x",b"",((READ,1),))):
                self.invoke(m0,bad,code=100,output=len(good),work=STAGING+len(good))
            self.invoke(m0,request(m+b"x",a,b,((READ,1),)),code=7,work=0,output=0)
            with self.assertRaisesRegex(ValueError, "within the fixture extent"):
                m0.call("f0",[legal+b"\0"*(CAP+1-len(legal)),b"",b""])
