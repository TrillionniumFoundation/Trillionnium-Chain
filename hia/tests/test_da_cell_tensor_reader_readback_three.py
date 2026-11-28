"""Independent actual public Cursor comparison for the full-height header profile."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_reader_framing import TENSOR, TENSOR_SHA, container, declare, loan
from hia.tests.test_da_cell_tensor_reader_readback import ORACLE, RESULT_BYTES, STATUS, WORK, field
from hia.tests.test_da_cell_tensor_reader_readback_wide import begin_wire, body_offset
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests.tensor_readback_three_derivation import SOURCE, derive

CAP=1<<20
MAX_LOGICAL=2*CAP
LIMIT=210
SPLIT=225


def payload(n):
    ring=bytes(range(251))
    return (ring*((n+250)//251))[:n]


def split(raw):
    a=begin_wire(raw)
    b=body_offset(raw)
    return [raw[:a+8],raw[a+8:b],raw[b:]]


def dense_json(tensor_field):
    first=b'{"__metadata__":{'+b",".join(
        f'"m{i:02d}":"'.encode()+b"x"*16384+b'"' for i in range(63)
    )+b',"m63":"'
    tail=b'"},'+tensor_field+b"}"
    limit=CAP-len(first)-len(tail)
    assert 0<limit<=16384
    return first+b"z"*limit+tail


def full(total):
    for k in range(1,5):
        name="a"*k
        probe=container(b"{"+field(name,[1],0,4)+b"}",payload(4))
        binding=[file(0,tensor(name.encode(),(1,)))]
        prefix=begin_wire(loan([probe],scope=binding))+8
        n=total-prefix-CAP
        if n%4:
            continue
        assert 0<n<CAP
        row=field(name,[n//4],0,n).replace(b'"F32"',br'"\u0046\u0033\u0032"')
        complete=container(dense_json(row),payload(n))
        out=loan([complete],scope=[file(0,tensor(name.encode(),(n//4,)))])
        assert len(out)==total and len(split(out)[1])==CAP
        return out
    raise AssertionError("fixture could not align positive F32 body")


def one(header, body, shape=(), *, dtype=1, pin=None, wrong_sha=False):
    content=container(header,body)
    r=declare([content],claims=[bytes(len(content))]) if wrong_sha else None
    return loan([content],r=r,scope=[file(0,tensor(b"a",shape,dtype=dtype))],pin=pin)


def cases():
    plain=field("a",[],0,4)
    escaped=plain.replace(b'"F32"',br'"F\u0033\u0032"')
    canon=b"{"+escaped+b"}"
    ordinary=[
        (one(canon,payload(4)),"ok",0),
        (one(b"{"+field("a",[2],0,4,"BF16")+b"}",payload(4),(2,),dtype=3),"ok",0),
        (one(b"{"+field("a",[],0,2,"F16")+b"}",payload(2),dtype=2),"ok",0),
        (one(dense_json(escaped),payload(4)),"ok",0),
        (one(canon+b" "*(CAP-len(canon)-1),payload(4)),"ok",0),
        (one(canon+b" "*(CAP-len(canon)),payload(4)),"ok",0),
        (full(MAX_LOGICAL-1),"ok",0),(full(MAX_LOGICAL),"ok",0),
        (full(MAX_LOGICAL+1),"ok",LIMIT),
        (one(canon+b" "*(CAP-len(canon)+1),payload(4)),"tensor header length",214),
        (one(canon,payload(4),pin=bytes(32),wrong_sha=True),"tensor contract pin",211),
        (one(b"{}"+b" "*(CAP-2),payload(4),wrong_sha=True),"tensor roster coverage",219),
        (one(dense_json(field("a",[],0,4,"UNKNOWN")),payload(4),wrong_sha=True),"tensor roster metadata",220),
        (one(dense_json(field("a",[],1,4)),payload(4),wrong_sha=True),"tensor data range",221),
        (one(dense_json(field("a",[],1,5)),payload(5),wrong_sha=True),"tensor overlap or hole",222),
        (one(dense_json(escaped),payload(5),wrong_sha=True),"tensor trailing data",223),
        (one(dense_json(escaped),payload(4),wrong_sha=True),"tensor payload digest",224),
        (one(dense_json(escaped)[:-2]+b";}",payload(4),wrong_sha=True),"tensor header JSON",217),
    ]
    x=container(canon,payload(4))
    ordinary.append((loan([x,x],index=1,scope=[file(0,tensor(b"a")),file(1,tensor(b"a"))]),"ok",0))
    return ordinary


class CellTensorReaderReadbackThree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.read_bytes().startswith(derive()):
            raise ValueError("Full-header readback source lost published CFG binding")
        cls.d=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.s=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=MAX_LOGICAL+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256 or "f1" in cls.s.exports:
            raise ValueError("Expected both distinct canonical stock emitter profiles")

    def invoke(self, m, fn, args, code, want=b"", *, n=RESULT_BYTES+3, w=WORK+9):
        out,work=MARK*n,SCRATCH*w
        got=m.call(fn,[*args,out,work],timeout=50).require_returned()
        self.assertEqual(got.value,code)
        self.assertEqual(got.arguments[:-2],args)
        self.assertEqual(got.arguments[-2],want+out[len(want):])
        self.assertEqual(got.arguments[-1][WORK:],work[WORK:])

    def test_complete_original_header_layout_and_digest(self):
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        rows=cases()
        with tempfile.TemporaryDirectory(prefix="trnm-reader-full-header-original-") as tmp:
            raw=b"".join(struct.pack("<I",len(v))+v for v,_,_ in rows)
            observed=locked_reference(Path(tmp),raw,caller=ORACLE)
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        at=0
        counts=[0,0,0]
        for ix,(data,error,status) in enumerate(rows):
            size,=struct.unpack_from("<H",observed,at)
            at+=2
            if size:
                self.assertEqual(observed[at:at+size].decode(),error)
                val=b""
                at+=size
            else:
                self.assertEqual(error,"ok")
                val=observed[at:at+RESULT_BYTES];at+=RESULT_BYTES
                self.assertEqual(len(val),RESULT_BYTES)
            expected=val if status==0 else b""
            with self.subTest(ix=ix,mode="selfhost-f0",logical=len(data)):
                self.invoke(self.s,"f0",[data],status,expected);counts[0]+=1
            spans=split(data)
            self.assertEqual(b"".join(spans),data)
            if all(len(q)<=CAP for q in spans):
                with self.subTest(ix=ix,mode="direct-f1",sizes=list(map(len,spans))):
                    self.invoke(self.d,"f1",spans,status,expected);counts[1]+=1
            if len(data)<=CAP:
                with self.subTest(ix=ix,mode="direct-f0",logical=len(data)):
                    self.invoke(self.d,"f0",[data],status,expected);counts[2]+=1
        self.assertEqual(at,len(observed))
        self.assertEqual(counts,[19,18,5])

    def test_three_physical_owners_and_atomic_refusals(self):
        data=full(MAX_LOGICAL)
        p,h,b=split(data)
        self.assertEqual((len(h),len(p)+len(h)+len(b)),(CAP,MAX_LOGICAL))
        self.assertGreater(len(b),900000)
        self.invoke(self.d,"f1",[p[:-1],h,b"\0"+b],SPLIT,n=0)
        self.invoke(self.d,"f1",[p,h[:-1],h[-1:]+b],SPLIT,n=0)
        self.invoke(self.d,"f1",[p+b[:1],h,b[1:]],SPLIT,n=0)
        self.invoke(self.d,"f1",[p,h,b[:-1]],STATUS["tensor actual file length"],n=0)
        self.invoke(self.d,"f1",[p,h,b[1:]+b[:1]],STATUS["tensor payload digest"],n=0)
        # Change ordinary metadata without invalidating JSON or any tensor
        # range. The original file-content digest still pins the old header.
        start=h.index(b'x'*16)
        changed=h[:start]+b'y'+h[start+1:]
        self.invoke(self.d,"f1",[p,changed,b],STATUS["tensor payload digest"],n=0)
        self.invoke(self.s,"f0",[p+changed+b],STATUS["tensor payload digest"],n=0)
        self.invoke(self.d,"f1",[p,h,b],102,n=RESULT_BYTES-1)
        self.invoke(self.d,"f1",[p,h,b],102,w=WORK-1)
