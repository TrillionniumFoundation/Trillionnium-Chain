"""Native byte-view operations against genuine public resident Rust tensors."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_da_protocol_context import locked_reference

SRC=ROOT/"hia/src/data_availability/cell_tensor_view_bytes.hepta"
ORACLE=Path(__file__).with_name("rust_cell_tensor_view_bytes_reference.rs")
OLD=ROOT/"trillionnium/crates/trnm-data-availability/src/cell"
PINS={
    "residency/tensor.rs":"183097dee2b18671da09bc9dce4079139e14aa240fb9c80cab9f36c0d781ec60",
    "residency/tensor/tests.rs":"17346273fc47e24eb57933560e01d566c5a18cbfa4b25ebdd7afe6cd5b7ed6fe",
    "tensor.rs":"73499faf43769355947c598040ddedf9139341bb1a1745924425cd5f11f6c5e8",
    "residency.rs":"9e6b8f5ece6fad5290dec3e1c4923baf2426db05e6007500fd8b5036625fa9da",
    "manifest.rs":"cf945af731b8172d6b093bded63d546ac3f3a15756524e739a50187dcdaebdc5",
}
CAP=1<<20
WIDTH=16_384
N=4097
MAX=(1<<64)-1
NAME=("a","b","c","z")
DTYPE={"F32":1,"F16":2,"BF16":3}
RANGE="resident tensor byte range"
DT="resident tensor F32 dtype"
ELEMENT="resident tensor element range"
STATUS={RANGE:243,DT:244,ELEMENT:245}


def envelope(backing,op,dtype,width,start,length,arg=0,want=0,flags=0,reserved=0):
    return struct.pack("<4sBBHIIIIQQ",b"TVB1",op,dtype,flags,width,start,length,reserved,arg,want)+backing


def shape():
    n=N*4
    roles=zip(NAME,("F32","F16","BF16","F32"),([N],[2],[],[]),
              ([0,n],[n,n+4],[n+4,n+6],[n+6,n+10]),strict=True)
    return {name:{"dtype":dtype,"shape":dims,"data_offsets":offsets} for name,dtype,dims,offsets in roles}


def header_size():
    header=json.dumps(shape(),separators=(",",":")).encode()
    return 8+len(header)+(1-len(header))%4


def cases():
    cross=(WIDTH-header_size())//4
    left=WIDTH-header_size()
    rows=[]
    def add(t,op,arg=0,want=0,reason=None):
        rows.append((t,op,arg,want,reason))
    for t in range(4):
        add(t,0)
        n=(N*4,4,2,4)[t]
        add(t,1,0,n)
        add(t,1,n,0)
        add(t,1,n+1,0,RANGE)
        add(t,1,n-1,2,RANGE)
        add(t,1,MAX,0,RANGE)
    for index in (0,1,2,3,4,5,6,cross-1,cross,cross+1,N-1):
        add(0,2,index)
    add(3,2,0)
    add(3,2,1,0,RANGE)
    for t in (1,2):
        add(t,2,0,0,DT)
        add(t,2,MAX,0,DT)
    for index,reason in [(N,RANGE),((1<<62)-1,RANGE),(1<<62,ELEMENT),(MAX,ELEMENT)]:
        add(0,2,index,0,reason)
    add(0,1,left-1,3)
    add(0,1,left-7,17)
    add(0,1,left,1)
    return [(topo,*r) for topo in (0,1) for r in rows]


class CellTensorViewBytes(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def panel(self,rows):
        for backend,mod in self.modules.items():
            for i,(frame,code,data,nout) in enumerate(rows):
                with self.subTest(backend=backend,row=i,n=len(frame)):
                    o,w=MARK*nout,SCRATCH*17
                    got=mod.call("f0",[frame,o,w]).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],frame)
                    self.assertEqual(got.arguments[1],data+o[len(data):])
                    self.assertEqual(got.arguments[2],w)

    def test_genuine_resident_segments_copies_and_bits(self):
        def verify_original():
            self.assertEqual({k:hashlib.sha256((OLD/k).read_bytes()).hexdigest()
                              for k in PINS},PINS)
        rows=cases()
        verify_original()
        req=b"".join(struct.pack("<BBBQQ",topo,t,op,i,n) for topo,t,op,i,n,_ in rows)
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-view-reference-") as d:
            raw=locked_reference(Path(d),req,caller=ORACLE,extra_externs=("sha2",))
        verify_original()
        backing_n=struct.unpack_from("<I",raw)[0]
        backing=raw[4:4+backing_n]
        end=8+struct.unpack_from("<Q",backing)[0]
        self.assertEqual(end,header_size())
        self.assertEqual(json.loads(backing[8:end]),shape())
        self.assertEqual(end%4,1)
        pos=4+backing_n
        out=[]
        original=[]
        for index,(topo,t,op,i,n,reason) in enumerate(rows):
            tag,count=struct.unpack_from("<BI",raw,pos)
            pos+=5
            value=raw[pos:pos+count]
            pos+=count
            code=0
            if reason is not None:
                self.assertEqual(tag,1,index)
                self.assertEqual(value.decode(),reason,index)
                code=STATUS[reason]
                value=b""
            else:
                self.assertEqual(tag,0,index)
            chosen=shape()[NAME[t]]
            start,stop=chosen["data_offsets"]
            width=WIDTH if topo==0 else backing_n
            data=envelope(backing,op,DTYPE[chosen["dtype"]],width,end+start,stop-start,i,n)
            out.append((data,code,value,len(value)+7))
            original.append(value)
        self.assertEqual(pos,len(raw))
        seen={struct.unpack("<I",b)[0] for (_,t,op,_,_,e),b in zip(rows,original,strict=True)
              if t==0 and op==2 and not e}
        self.assertTrue({0x80000000,1,0x7f800000,0xff800000,0x7fc12345,
                         0x7f812345,0xffc00042,0x7fc1a55a}<=seen)
        self.assertEqual(struct.unpack_from("<III",original[0]),(2,WIDTH-end,N*4-WIDTH+end))
        self.assertEqual(struct.unpack_from("<II",original[len(rows)//2]),(1,N*4))
        self.panel(out)

    def test_private_extent_and_output_guards_before_publication(self):
        body=bytes(range(28))
        f3=envelope(body,0,1,len(body),1,4)
        r3=envelope(body,2,1,len(body),1,4)
        p3=envelope(body,1,1,len(body),1,4,0,4)
        exact=bytes(CAP-40)
        loan=envelope(exact,2,1,WIDTH,len(exact)-4,4)
        self.assertEqual(len(loan),CAP)
        self.panel([(f3,0,struct.pack("<II",1,4)+body[1:5],12),
                    (f3,102,b"",11),(r3,102,b"",3),(p3,102,b"",3),
                    (envelope(body,1,1,len(body),1,4,5,0),243,b"",0),
                    (envelope(body,1,1,len(body),1,4,0,MAX),243,b"",0),
                    (envelope(body,2,2,len(body),1,4,MAX,0),244,b"",0),
                    (envelope(body,2,1,len(body),1,4,MAX,0),245,b"",0),
                    (envelope(body,2,1,len(body),1,4,0,1),246,b"",0),
                    (envelope(body,0,1,len(body),1,4,0,1),246,b"",0),
                    (envelope(body,0,1,len(body),1,4,flags=1),240,b"",26),
                    (envelope(body,0,1,len(body),1,4,reserved=1),240,b"",26),
                    (envelope(body,0,8,len(body),1,4),240,b"",0),
                    (envelope(body,3,1,len(body),1,4),240,b"",0),
                    (envelope(body,0,1,0,1,4),242,b"",0),
                    (envelope(body,0,1,3,1,4),242,b"",0),
                    (envelope(body,0,1,29,1,4),242,b"",0),
                    (envelope(body,0,1,28,1,0),242,b"",0),
                    (envelope(body,0,1,28,1,3),242,b"",0),
                    (envelope(body,0,1,28,MAX & 0xffffffff,4),242,b"",0),
                    (envelope(body,0,1,28,25,4),242,b"",0),
                    (f3[:40],240,b"",0),
                    (loan,0,bytes(4),4)])
