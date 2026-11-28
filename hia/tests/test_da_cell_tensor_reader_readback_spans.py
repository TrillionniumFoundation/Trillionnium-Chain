"""Full-count native immutable tensor readback against the frozen Rust public reader."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_header_spans import short_name
from hia.tests.test_da_cell_tensor_reader_framing import TENSOR, TENSOR_SHA, container, declare, loan
from hia.tests.test_da_cell_tensor_reader_readback import ORACLE, RESULT_BYTES, field
from hia.tests.test_da_cell_tensor_reader_readback_metadata import cases as inherited
from hia.tests.test_da_cell_tensor_reader_readback_three import CAP, MAX_LOGICAL, payload, split
from hia.tests.test_da_cell_tensor_reader_readback_wide import begin_wire
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests.tensor_header_spans_derivation import MAX_TENSORS
from hia.tests.tensor_readback_spans_derivation import DIGEST_SLOT, RANGE_BASE, RANGE_MASK, SOURCE, WORK, derive

META_COUNT=1024


def full(mode="good"):
    others=sorted(short_name(j).encode() for j in range(MAX_TENSORS-1))
    meta=b'"__metadata__":{'+b",".join(f'"m{j:04d}":""'.encode() for j in range(META_COUNT))+b"}"
    floor=4*len(others)
    for k in range(1,5):
        heavy=b"!"*k
        shape=(1,)*8
        sample=loan([container()],scope=[file(0,tensor(heavy,shape),*(tensor(x) for x in others))])
        prefix=begin_wire(sample)+8
        n=MAX_LOGICAL-CAP-prefix
        if n%4:
            continue
        assert floor<n<CAP
        shape=((n-floor)//4,*shape[1:])
        scope=[file(0,tensor(heavy,shape),*(tensor(x) for x in others))]
        # Insert physical intervals in descending order while declaring names
        # ascending. The first declared name occupies the last data interval.
        fields=[field(heavy.decode(),shape,floor,n).replace(b'"F32"',br'"\u0046\u0033\u0032"')]
        for j,name in reversed(list(enumerate(others))):
            if mode=="missing" and j==len(others)-1:
                continue
            lo=4*j
            if mode=="overlap" and j==1:
                lo=0
            dtype="F16" if mode=="dtype" and j==len(others)-1 else "F32"
            fields.append(field(name.decode(),[],lo,lo+4,dtype))
        fields.insert(len(fields)//2,meta)
        if mode=="excess":
            fields.append(field("~",[],0,4))
        head=b"{"+b",".join(fields)+b"}"
        assert len(head)<=CAP,(mode,len(head))
        head+=b" "*(CAP-len(head))
        body=payload(n)
        raw=container(head,body)
        r=declare([raw],claims=[bytes(len(raw))]) if mode!="good" else None
        wire=loan([raw],r=r,scope=scope)
        assert len(wire)==MAX_LOGICAL and len(split(wire)[1])==CAP
        return wire
    raise AssertionError("Unaligned 16384-tensor physical fixture")


def cases():
    p,h,b=split(full())
    at=h.index(b'm0000')
    new_h=h[:at]+b"n"+h[at+1:]
    return inherited()+[
        (p+h+b,"ok",0),
        (full("excess"),"tensor header JSON",217),
        (full("missing"),"tensor roster coverage",219),
        (full("dtype"),"tensor roster metadata",220),
        (full("overlap"),"tensor overlap or hole",222),
        (p+new_h+b,"tensor payload digest",224),
        (p+h+b[1:]+b[:1],"tensor payload digest",224),
    ]


class CellTensorReaderReadbackSpans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.read_bytes().startswith(derive()):
            raise ValueError("Exact published composed reader and compact parser binding drifted")
        cls.d=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.s=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=MAX_LOGICAL+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256 or "f1" in cls.s.exports:
            raise ValueError("Distinct stock profiles required")

    def invoke(self,m,fn,args,code,want=b"",*,n=RESULT_BYTES+5,w=WORK+9):
        out,work=MARK*n,SCRATCH*w
        observed=m.call(fn,[*args,out,work],timeout=58).require_returned()
        self.assertEqual(observed.abi_status,0)
        self.assertEqual(observed.value,code)
        self.assertEqual(observed.arguments[:-2],args)
        self.assertEqual(observed.arguments[-2],want+out[len(want):])
        self.assertEqual(observed.arguments[-1][WORK:],work[WORK:])
        return observed.arguments[-1]

    def test_original_public_full_roster_on_both_stocks(self):
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        inputs=cases()
        with tempfile.TemporaryDirectory(prefix="trnm-reader-16384-original-") as td:
            seq=b"".join(struct.pack("<I",len(data))+data for data,_,_ in inputs)
            raw=locked_reference(Path(td),seq,caller=ORACLE)
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        at=0
        make=[0,0,0]
        for ix,(data,error,expected) in enumerate(inputs):
            n,=struct.unpack_from("<H",raw,at)
            at+=2
            if n:
                self.assertEqual(raw[at:at+n].decode(),error)
                r=b""
            else:
                self.assertEqual(error,"ok")
                r=raw[at:at+RESULT_BYTES]
                self.assertEqual(len(r),RESULT_BYTES)
            at+=n or RESULT_BYTES
            if ix==28:
                self.assertEqual(int.from_bytes(r[66:74],"little"),MAX_TENSORS)
            result=r if expected==0 else b""
            with self.subTest(ix=ix,mode="selfhost-f0"):
                self.invoke(self.s,"f0",[data],expected,result)
                make[0]+=1
            spans=split(data)
            self.assertEqual(b"".join(spans),data)
            if all(len(i)<=CAP for i in spans):
                with self.subTest(ix=ix,mode="direct-f1"):
                    self.invoke(self.d,"f1",spans,expected,result)
                    make[1]+=1
            if len(data)<=CAP:
                with self.subTest(ix=ix,mode="direct-f0"):
                    self.invoke(self.d,"f0",[data],expected,result)
                    make[2]+=1
        self.assertEqual(at,len(raw))
        self.assertEqual(make,[35,34,5])

    def test_full_immutable_lifetimes_and_capacity(self):
        raw=full()
        p,h,b=split(raw)
        self.assertEqual((len(raw),len(h)),(MAX_LOGICAL,CAP))
        for m,fn,args in ((self.d,"f1",[p,h,b]),(self.s,"f0",[raw])):
            w=self.invoke(m,fn,args,102,n=RESULT_BYTES-1,w=WORK)
            locator,=struct.unpack_from("<Q",w,DIGEST_SLOT)
            self.assertGreater(locator,0)
            self.assertLessEqual(locator+32,len(p)-8)
            self.assertEqual(p[locator:locator+32],hashlib.sha256(p[-8:]+h+b).digest())
            first,=struct.unpack_from("<Q",w,RANGE_BASE)
            last,=struct.unpack_from("<Q",w,RANGE_BASE+8*(MAX_TENSORS-1))
            self.assertEqual((first>>22,first&RANGE_MASK),(0,4))
            self.assertEqual((last>>22,last&RANGE_MASK),(4*(MAX_TENSORS-1),len(b)))
            self.invoke(m,fn,args,102,w=WORK-1)
