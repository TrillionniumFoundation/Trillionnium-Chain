"""Actual original Cursor and wider immutable tensor body on both stock emitters."""
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
from hia.tests.test_da_cell_tensor_reader_readback_spans import cases as prior
from hia.tests.test_da_cell_tensor_reader_readback_three import payload, split
from hia.tests.test_da_cell_tensor_reader_readback_wide import begin_wire
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests.tensor_header_spans_derivation import MAX_TENSORS
from hia.tests.tensor_readback_four_derivation import BODY, CAP, LOGICAL, SOURCE, WORK, derive
from hia.tests.tensor_readback_spans_derivation import DIGEST_SLOT, RANGE_BASE, RANGE_MASK


def spans(frame):
    p,h,b=split(frame)
    return [p,h,b[:CAP],b[CAP:2*CAP],b[2*CAP:]]


def full(total, *, overlap=False):
    others=sorted(short_name(i).encode() for i in range(MAX_TENSORS-1))
    meta=b'"__metadata__":{'+b",".join(f'"m{j:04d}":""'.encode() for j in range(1024))+b"}"
    low=4*len(others)
    for k in range(1,5):
        first=b"!"*k
        base=(1,)*8
        guess=[file(0,tensor(first,base),*(tensor(x) for x in others))]
        prefix=begin_wire(loan([container()],scope=guess))+8
        n=total-CAP-prefix
        if n%4:
            continue
        assert low<n<=BODY
        shape=((n-low)//4,*base[1:])
        membership=[file(0,tensor(first,shape),*(tensor(x) for x in others))]
        fields=[field(first.decode(),shape,low,n).replace(b'"F32"',br'"\u0046\u0033\u0032"')]
        for j,name in reversed(list(enumerate(others))):
            at=0 if overlap and j==1 else 4*j
            fields.append(field(name.decode(),[],at,at+4))
        fields.insert(len(fields)//2,meta)
        header=b"{"+b",".join(fields)+b"}"
        assert len(header)<CAP
        header+=b" "*(CAP-len(header))
        b=container(header,payload(n))
        root=declare([b],claims=[bytes(len(b))]) if overlap else None
        out=loan([b],r=root,scope=membership)
        assert len(out)==total and all(len(x)<=CAP for x in spans(out))
        return out
    raise ValueError("Unaligned full synthetic geometry")


def new_cases():
    f=full(LOGICAL)
    p,h,a,b,c=spans(f)
    now=h.index(b"m0000")
    h2=h[:now]+b"n"+h[now+1:]
    n=BODY+4
    big=loan([container(b"{"+field("a",[n//4],0,n)+b"}",payload(n))],
              scope=[file(0,tensor(b"a",(n//4,)))])
    assert len(big)<=LOGICAL and len(spans(big)[-1])>CAP
    return [
        (f,"ok",0),(full(LOGICAL+1),"ok",210),
        (p+h2+a+b+c,"tensor payload digest",224),
        (p+h+b+a+c,"tensor payload digest",224),
        (p+h+a+b+c[1:]+c[:1],"tensor payload digest",224),
        (full(LOGICAL,overlap=True),"tensor overlap or hole",222),
        (big,"ok",225),
    ]


def cases():
    rows=[(data,error,0 if error=="ok" and status==210 else status)
          for data,error,status in prior()]
    return rows+new_cases()


class CellTensorReaderReadbackFour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.read_bytes()!=derive():
            raise ValueError("Exact published full-count reader derivation drifted")
        cls.d=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.s=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=LOGICAL+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256 or "f1" in cls.s.exports:
            raise ValueError("Distinct stock profiles required")

    def invoke(self,m,fn,args,code,want=b"",*,n=RESULT_BYTES+5,w=WORK+9):
        out,work=MARK*n,SCRATCH*w
        observed=m.call(fn,[*args,out,work],timeout=59).require_returned()
        self.assertEqual(observed.abi_status,0)
        self.assertEqual(observed.value,code)
        self.assertEqual(observed.arguments[:-2],args)
        self.assertEqual(observed.arguments[-2],want+out[len(want):])
        self.assertEqual(observed.arguments[-1][WORK:],work[WORK:])
        return observed.arguments[-1]

    def test_frozen_original_cursor_and_five_read_loans(self):
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        items=cases()
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-4m-original-") as tmp:
            raw=b"".join(struct.pack("<I",len(d))+d for d,_,_ in items)
            original=locked_reference(Path(tmp),raw,caller=ORACLE)
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        offset=0
        count=[0,0,0]
        for ix,(data,expected,status) in enumerate(items):
            n,=struct.unpack_from("<H",original,offset)
            offset+=2
            if n:
                self.assertEqual(original[offset:offset+n].decode(),expected)
                out=b""
            else:
                self.assertEqual(expected,"ok")
                out=original[offset:offset+RESULT_BYTES]
            offset+=n or RESULT_BYTES
            if ix==35:
                self.assertEqual(int.from_bytes(out[66:74],"little"),MAX_TENSORS)
                self.assertEqual(len(data),LOGICAL)
            want=out if status==0 else b""
            with self.subTest(ix=ix,engine="selfhost-f0"):
                self.invoke(self.s,"f0",[data],status,want)
                count[0]+=1
            cells=spans(data)
            self.assertEqual(b"".join(cells),data)
            if all(len(x)<=CAP for x in cells):
                with self.subTest(ix=ix,engine="direct-f1"):
                    self.invoke(self.d,"f1",cells,status,want)
                    count[1]+=1
            if len(data)<=CAP:
                with self.subTest(ix=ix,engine="direct-f0"):
                    self.invoke(self.d,"f0",[data],status,want)
                    count[2]+=1
        self.assertEqual(offset,len(original))
        self.assertEqual(count,[42,40,5])

    def test_all_live_ranges_and_atomic_wider_hash(self):
        frame=full(LOGICAL)
        p,h,a,b,c=spans(frame)
        self.assertEqual((len(frame),len(h),len(a),len(b)),(LOGICAL,CAP,CAP,CAP))
        self.assertGreater(len(c),800000)
        for m,fn,args in ((self.d,"f1",[p,h,a,b,c]),(self.s,"f0",[frame])):
            work=self.invoke(m,fn,args,102,n=RESULT_BYTES-1,w=WORK)
            locator,=struct.unpack_from("<Q",work,DIGEST_SLOT)
            self.assertGreater(locator,0)
            self.assertLessEqual(locator+32,len(p)-8)
            self.assertEqual(p[locator:locator+32],hashlib.sha256(p[-8:]+h+a+b+c).digest())
            lo,=struct.unpack_from("<Q",work,RANGE_BASE)
            hi,=struct.unpack_from("<Q",work,RANGE_BASE+8*(MAX_TENSORS-1))
            self.assertEqual((lo>>22,lo&RANGE_MASK),(0,4))
            self.assertEqual((hi>>22,hi&RANGE_MASK),(4*(MAX_TENSORS-1),len(a)+len(b)+len(c)))
            self.invoke(m,fn,args,102,w=WORK-1)
        # Physical fragmentation may change, but its exact logical byte order
        # may not. An uneven cut exercises a non-block-aligned SHA boundary.
        combo=a+b+c
        self.invoke(self.d,"f1",[p,h,combo[:CAP-1],combo[CAP-1:2*CAP-2],combo[2*CAP-2:]],102,n=0)
        self.invoke(self.d,"f1",[p,h,a,b,c[:-1]],213,n=0)
        self.invoke(self.d,"f1",[p,h[:-1],a,b,h[-1:]+c],225,n=0)
