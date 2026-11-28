"""Frozen original typed F32 bits from the same immutable verified named tensor."""
from functools import lru_cache
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_reader_framing import container, loan
from hia.tests.test_da_cell_tensor_reader_readback import field
from hia.tests.test_da_cell_tensor_reader_readback_selected import (
    CAP, LOGICAL, NAME_MAX, cases as selected_cases, physical, wire,
)
from hia.tests.test_da_cell_tensor_reader_readback_window import BYTE_RANGE, MAX, MISSING
from hia.tests.tensor_layout_original import real_layout
from hia.tests.tensor_readback_f32_derivation import MAX_FRAME_SUFFIX, SOURCE, WORK, derive

WRONG_DTYPE="resident tensor F32 dtype"
ELEMENT="resident tensor element range"
SPECIALS=(0x80000000,1,0x7f800000,0xff800000,0x7fc12345,0x7f812345,0xffc00042)
CROSS=0x7fc1a55a


def query(name, index):
    return struct.pack("<Q",index)+name


def special_container():
    width=16_384
    n=4097
    h=b"{"+field("bits",[n],0,4*n)+b"}"
    h+=b" "*((1-len(h))%4)
    base=8+len(h)
    cross=(width-base)//4
    assert (base+4*cross,base+4*(cross+1))==(width-3,width+1)
    words=[0x3f800000]*n
    words[:len(SPECIALS)]=SPECIALS
    words[cross]=CROSS
    body=struct.pack(f"<{n}I",*words)
    return loan([container(h,body)],scope=[file(0,tensor(b"bits",(n,)))]),cross,n


@lru_cache(maxsize=1)
def cases():
    b=selected_cases()
    simple=b[0][0]
    second=b[7][0]
    mixed=b[10][0]
    full,leader=b[15][:2]
    framed,cross,n=special_container()
    h=b"{"+field("é",[],0,4).replace("é".encode(),br"\u00e9")+b"}"
    unicode=loan([container(h,bytes.fromhex("0100c07f"))],scope=[file(0,tensor("é".encode()))])
    # Original chunk boundary and a different native segmentation both split
    # the same exact four-byte F32; none of the three paths sees a typed pointer.
    cross_cuts=(4*cross+1,4*cross+3)
    return [
        (simple,query(b"a",0),"ok",0,(1,3)),
        (simple,query(b"a",1),BYTE_RANGE,243,None),
        (simple,query(b"a",(1<<62)-1),BYTE_RANGE,243,None),
        (simple,query(b"a",1<<62),ELEMENT,245,None),
        (simple,query(b"a",MAX),ELEMENT,245,None),
        (simple,query(b"A",MAX),MISSING,226,None),
        (simple,query(b"",0),MISSING,226,None),
        (simple,query(b"x"*256,0),MISSING,226,None),
        (second,query(b"x",0),WRONG_DTYPE,244,None),
        (second,query(b"x",MAX),WRONG_DTYPE,244,None),
        (second,query(b"y",0),"ok",0,(1,3)),
        (second,query(b"a",0),MISSING,226,None),
        (mixed,query("𝄞".encode(),MAX),WRONG_DTYPE,244,None),
        (unicode,query("é".encode(),0),"ok",0,None),
        (unicode,query("e\u0301".encode(),0),MISSING,226,None),
        (b[13][0],query(NAME_MAX,0),"ok",0,None),
        (full,query(leader,500_000),"ok",0,None),
        (b[16][0],query(leader,MAX),"tensor payload digest",224,None),
        (b[18][0],query(b"missing",MAX),"tensor overlap or hole",222,None),
        (b[-1][0],query(b"missing",MAX),"tensor contract pin",211,None),
    ]+[(framed,query(b"bits",j),"ok",0,(1,3)) for j in range(len(SPECIALS))]+[
        (framed,query(b"bits",cross),"ok",0,cross_cuts),
        (framed,query(b"bits",n-1),"ok",0,None),
        (framed,query(b"bits",n),BYTE_RANGE,243,None),
    ]


def rust_cases():
    raw=b"".join(struct.pack("<IH",len(f)+2+len(q),len(q))+q+f for f,q,_,_,_ in cases())
    with tempfile.TemporaryDirectory(prefix="trnm-tensor-private-f32-") as directory:
        return real_layout(Path(directory),raw,f32=True)


class CellTensorReaderReadbackF32(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.read_bytes()!=derive():
            raise ValueError("Exact frozen immutable typed projection does not derive the recorded source")
        cls.direct=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.selfhost=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                        max_input_extent=LOGICAL+MAX_FRAME_SUFFIX))

    def invoke(self,m,f,args,code,value=b"",*,size=13,work=WORK+7):
        o,w=MARK*size,SCRATCH*work
        actual=m.call(f,[*args,o,w],timeout=59).require_returned()
        self.assertEqual((actual.abi_status,actual.value),(0,code))
        self.assertEqual(actual.arguments[:-2],args)
        self.assertEqual(actual.arguments[-2],value+o[len(value):])
        self.assertEqual(actual.arguments[-1][WORK:],w[WORK:])

    def test_frozen_original_same_loan_f32(self):
        raw,rlib=rust_cases()
        self.assertEqual(len(rlib),64)
        at=0
        counts=[0,0,0]
        for i,(frame,q,reason,code,cuts) in enumerate(cases()):
            n,=struct.unpack_from("<H",raw,at)
            at+=2
            if n:
                self.assertEqual(raw[at:at+n].decode(),reason)
                value=b""
                at+=n
            else:
                self.assertEqual(reason,"ok")
                value=raw[at:at+4]
                self.assertEqual(len(value),4)
                at+=4
                if 20<=i<20+len(SPECIALS):
                    self.assertEqual(struct.unpack("<I",value),(SPECIALS[i-20],))
                if i==27:
                    self.assertEqual(struct.unpack("<I",value),(CROSS,))
            if i==15:
                self.assertEqual(len(wire(frame,q)),LOGICAL+MAX_FRAME_SUFFIX)
            with self.subTest(i=i,stock="selfhost"):
                self.invoke(self.selfhost,"f0",[wire(frame,q)],code,value)
                counts[0]+=1
            with self.subTest(i=i,stock="direct-split"):
                self.invoke(self.direct,"f1",physical(frame,q,cuts),code,value)
                counts[1]+=1
            if len(wire(frame,q))<=CAP:
                with self.subTest(i=i,stock="direct-contiguous"):
                    self.invoke(self.direct,"f0",[wire(frame,q)],code,value)
                    counts[2]+=1
        self.assertEqual(at,len(raw))
        self.assertEqual(counts,[30,30,26])

    def test_f32_dtype_index_range_short_output_order_and_canaries(self):
        rows=cases()
        for m,f,args in ((self.direct,"f1",physical),(self.selfhost,"f0",lambda fr,q,c=None:[wire(fr,q)])):
            for index,expected in ((0,102),(3,245),(9,244),(17,224)):
                data,q,_,_,cuts=rows[index]
                self.invoke(m,f,args(data,q,cuts),expected,size=3)
            data,q,_,_,cuts=rows[0]
            self.invoke(m,f,args(data,q,cuts),102,size=4,work=WORK-1)
            self.invoke(m,f,args(data,q,cuts),0,bytes.fromhex("00000080"),size=4)
