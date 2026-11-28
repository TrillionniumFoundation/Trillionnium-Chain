"""Original public readback and bounded 1024-key metadata on the same physical header."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_header_metadata import named
from hia.tests.test_da_cell_tensor_reader_framing import TENSOR, TENSOR_SHA, container, declare, loan
from hia.tests.test_da_cell_tensor_reader_readback import ORACLE, RESULT_BYTES, STATUS, field
from hia.tests.test_da_cell_tensor_reader_readback_three import (
    CAP, MAX_LOGICAL, SPLIT, cases as prior, payload, split,
)
from hia.tests.test_da_cell_tensor_reader_readback_wide import begin_wire
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests.tensor_readback_metadata_derivation import (
    DIGEST_SLOT, INTERVAL_BEGIN, INTERVAL_END, NAMES_END, SOURCE, WORK, derive,
)

ROSTER = 128
RANK = 8
META = 1024


def dense(records, count, alias):
    names=[b"k"*251+f"{(i*773+379)%count:04x}".encode() for i in range(count)]
    assert len(set(names)) == count
    if alias:
        # Same decoded key as the first, written with a different JSON spelling.
        names[-1]=br"\u006b"+names[0][1:]
    head=b'{"__metadata__":{'
    tail=b"}, "+b",".join(records)+b"}"
    used=len(head)+len(tail)+(len(names)-1)+sum(len(named(x,b'""')) for x in names)
    left=CAP-used
    fragments=[]
    for key in names:
        n=min(left,16384)
        fragments.append(named(key,b'"'+b"v"*n+b'"'))
        left-=n
    raw=head+b",".join(fragments)+tail
    assert left==0 and len(raw)==CAP
    return raw


def full(*, count=META, alias=False, wrong_digest=False, wide_roster=True, pin=None):
    # Exercise 127 additional full-length names, rank eight, and interval
    # reconstruction; the short first name is varied only for size congruence.
    others=[f"z{i:03d}".encode()+b"z"*251 for i in range(ROSTER-1)] if wide_roster else []
    base=(1,)*RANK
    for k in range(1,5):
        first=b"a"*k
        rough=[file(0,tensor(first,base),*(tensor(x,base) for x in others))]
        probe=loan([container()],scope=rough)
        prefix=begin_wire(probe)+8
        n=MAX_LOGICAL-CAP-prefix
        if n%4:
            continue
        actual=tuple([n//4-len(others),*base[1:]])
        assert 0 < actual[0] < 2**32
        start=4*len(others)
        row=field(first.decode(),actual,start,n).replace(b'"F32"',br'"\u0046\u0033\u0032"')
        tensor_rows=[field(x.decode(),base,p*4,(p+1)*4) for p,x in reversed(list(enumerate(others)))]
        raw=container(dense([*tensor_rows,row],count,alias),payload(n))
        binding=[file(0,tensor(first,actual),*(tensor(x,base) for x in others))]
        r=declare([raw],claims=[bytes(len(raw))]) if wrong_digest else None
        wire=loan([raw],r=r,scope=binding,pin=pin)
        assert len(wire)==MAX_LOGICAL and len(split(wire)[1])==CAP
        return wire
    raise AssertionError("Unaligned wide-roster fixture")


def cases():
    positive=full()
    parts=split(positive)
    edited_at=parts[1].index(b"v"*16)
    header_change=parts[1][:edited_at]+b"w"+parts[1][edited_at+1:]
    payload_change=parts[2][1:]+parts[2][:1]
    assert header_change!=parts[1] and payload_change!=parts[2]
    return prior()+[
        (positive,"ok",0),
        (full(wide_roster=False),"ok",0),
        (full(count=META+1),"tensor header JSON",217),
        (full(count=META+1,wrong_digest=True),"tensor header JSON",217),
        (full(count=META+1,wrong_digest=True,pin=bytes(32)),"tensor contract pin",211),
        (full(alias=True,wrong_digest=True),"tensor header JSON",217),
        (parts[0]+header_change+parts[2],"tensor payload digest",224),
        (parts[0]+parts[1]+payload_change,"tensor payload digest",224),
        (positive[:-1],"tensor actual file length",213),
    ]


class CellTensorReaderReadbackMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.read_bytes()!=derive():
            raise ValueError("Exact published reader and metadata binding drifted")
        cls.d=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.s=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=MAX_LOGICAL+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256 or "f1" in cls.s.exports:
            raise ValueError("Distinct stock public byte ABI profiles required")

    def invoke(self,m,fn,args,code,want=b"",*,n=RESULT_BYTES+7,w=WORK+11):
        out,work=MARK*n,SCRATCH*w
        observed=m.call(fn,[*args,out,work],timeout=54).require_returned()
        self.assertEqual(observed.abi_status,0)
        self.assertEqual(observed.value,code)
        self.assertEqual(observed.arguments[:-2],args)
        self.assertEqual(observed.arguments[-2],want+out[len(want):])
        self.assertEqual(observed.arguments[-1][WORK:],work[WORK:])
        return observed.arguments[-1]

    def test_actual_original_full_roster_and_exact_geometries(self):
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        items=cases()
        with tempfile.TemporaryDirectory(prefix="trnm-reader-1024-original-") as td:
            raw=b"".join(struct.pack("<I",len(data))+data for data,_,_ in items)
            actual=locked_reference(Path(td),raw,caller=ORACLE)
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        offset=0
        calls=[0,0,0]
        for index,(data,error,code) in enumerate(items):
            width,=struct.unpack_from("<H",actual,offset)
            offset+=2
            if width:
                self.assertEqual(actual[offset:offset+width].decode(),error)
                projection=b""
                offset+=width
            else:
                self.assertEqual(error,"ok")
                projection=actual[offset:offset+RESULT_BYTES]
                self.assertEqual(len(projection),RESULT_BYTES)
                offset+=RESULT_BYTES
            wanted=projection if code==0 else b""
            with self.subTest(index=index,backend="selfhost-f0"):
                self.invoke(self.s,"f0",[data],code,wanted)
                calls[0]+=1
            spans=split(data)
            self.assertEqual(b"".join(spans),data)
            if all(len(a)<=CAP for a in spans):
                with self.subTest(index=index,backend="direct-f1"):
                    self.invoke(self.d,"f1",spans,code,wanted)
                    calls[1]+=1
            if len(data)<=CAP:
                with self.subTest(index=index,backend="direct-f0"):
                    self.invoke(self.d,"f0",[data],code,wanted)
                    calls[2]+=1
        self.assertEqual(offset,len(actual))
        self.assertEqual(calls,[28,27,5])

    def test_scratch_lifetimes_and_atomic_capacity(self):
        raw=full()
        p,h,b=split(raw)
        self.assertEqual((len(h),len(raw)),(CAP,MAX_LOGICAL))
        self.assertEqual(NAMES_END,52640)
        # Complete output/interval phases can be observed with no publish
        # capacity. The live locator remains an offset within the declarations,
        # while the intervals have overwritten the dead metadata records.
        for m,fn,args in ((self.d,"f1",[p,h,b]),(self.s,"f0",[raw])):
            scratch=self.invoke(m,fn,args,102,n=RESULT_BYTES-1,w=WORK)
            locator,=struct.unpack_from("<Q",scratch,DIGEST_SLOT)
            self.assertGreater(locator,0)
            self.assertLessEqual(locator+32,len(p)-8)
            self.assertEqual(p[locator:locator+32],hashlib.sha256(p[-8:]+h+b).digest())
            self.assertEqual(struct.unpack_from("<QQ",scratch,INTERVAL_BEGIN),(0,4))
            self.assertEqual(struct.unpack_from("<QQ",scratch,INTERVAL_END-16),(508,len(b)))
            self.invoke(m,fn,args,102,w=WORK-1)
        self.invoke(self.d,"f1",[p,h[:-1],h[-1:]+b],SPLIT,n=0)
