"""Frozen resident byte-copy semantics on inert layout already verified on the same bytes."""
from functools import lru_cache
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_da_cell_tensor_reader_readback_selected import (
    CAP, LOGICAL, MAX_TENSORS, NAME_MAX, THE_MAX, cases as selected_cases, one_tensor,
    physical, wire,
)
from hia.tests.test_da_cell_tensor_reader_readback_four import spans
from hia.tests.test_da_cell_tensor_reader_readback_three import payload
from hia.tests.tensor_layout_original import real_layout
from hia.tests.tensor_readback_window_derivation import MAX_FRAME_SUFFIX, SOURCE, WORK, derive

BYTE_RANGE="resident tensor byte range"
MISSING="selected tensor missing"
MAX=(1<<64)-1


def query(name, relative, amount):
    return struct.pack("<QQ",relative,amount)+name


@lru_cache(maxsize=1)
def cases():
    base=selected_cases()
    simple=base[0][0]
    small=base[6][0]
    second=base[7][0]
    unicode=base[10][0]
    full,leader=base[15][:2]
    prefix,header,*body=spans(full)
    used=4*(MAX_TENSORS-1)
    large_bytes=sum(map(len,body))-used
    cross=2*CAP-used-2
    assert (len(prefix)+len(header)+sum(map(len,body)),large_bytes)==(LOGICAL,2968908)
    wide=one_tensor(b"cap",THE_MAX+16)
    return [
        (simple,query(b"a",1,2),"ok",0,(1,2)),
        (simple,query(b"a",4,0),"ok",0,None),
        (simple,query(b"a",4,1),BYTE_RANGE,243,None),
        (simple,query(b"a",5,0),BYTE_RANGE,243,None),
        (simple,query(b"a",MAX,0),BYTE_RANGE,243,None),
        (simple,query(b"a",3,2),BYTE_RANGE,243,None),
        (simple,query(b"absent",MAX,1),MISSING,226,None),
        (simple,query(b"\xff",1,2),MISSING,226,None),
        (simple,query(b"",0,0),MISSING,226,None),
        (simple,query(b"x"*256,0,0),MISSING,226,None),
        (small,query(b"a",1,11),"ok",0,(3,8)),
        (small,query(b"a",1,11),"ok",0,(0,4)),
        (second,query(b"x",1,1),"ok",0,(1,5)),
        (second,query(b"y",2,2),"ok",0,(1,3)),
        (second,query(b"a",0,0),MISSING,226,None),
        (unicode,query("é".encode(),1,1),"ok",0,(1,3)),
        (unicode,query("e\u0301".encode(),0,0),MISSING,226,None),
        (base[13][0],query(NAME_MAX,1,3),"ok",0,None),
        (full,query(leader,cross,7),"ok",0,None),
        (full,query(leader,large_bytes,0),"ok",0,None),
        (full,query(leader,large_bytes-5,5),"ok",0,None),
        (full,query(leader,large_bytes-5,6),BYTE_RANGE,243,None),
        (base[16][0],query(leader,MAX,1),"tensor payload digest",224,None),
        (base[18][0],query(b"absent",MAX,1),"tensor overlap or hole",222,None),
        (wide,query(b"cap",13,THE_MAX),"ok",0,(1,CAP-9)),
        (wide,query(b"cap",13,THE_MAX+2),"ok",102,None),
        (base[-1][0],query(b"absent",MAX,1),"tensor contract pin",211,None),
    ]


def rust_cases():
    raw=b"".join(struct.pack("<IH",len(f)+2+len(q),len(q))+q+f for f,q,_,_,_ in cases())
    with tempfile.TemporaryDirectory(prefix="trnm-tensor-private-window-") as scratch:
        return real_layout(Path(scratch),raw,window=True)


class CellTensorReaderReadbackWindow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.read_bytes()!=derive():
            raise ValueError("Exact immutable selected-reader derivation changed")
        cls.direct=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.selfhost=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                        max_input_extent=LOGICAL+MAX_FRAME_SUFFIX))

    def invoke(self,m,f,args,code,data=b"",*,size=None,work=WORK+7):
        fit=min(len(data)+9,CAP) if size is None else size
        o,w=MARK*fit,SCRATCH*work
        actual=m.call(f,[*args,o,w],timeout=59).require_returned()
        self.assertEqual((actual.abi_status,actual.value),(0,code))
        self.assertEqual(actual.arguments[:-2],args)
        self.assertEqual(actual.arguments[-2],data+o[len(data):])
        self.assertEqual(actual.arguments[-1][WORK:],w[WORK:])

    def test_frozen_native_window_for_exact_same_verified_selected_tensor(self):
        raw,rlib=rust_cases()
        self.assertEqual(len(rlib),64)
        at=0
        counts=[0,0,0]
        for i,(frame,q,expect,code,cuts) in enumerate(cases()):
            reason,=struct.unpack_from("<H",raw,at)
            at+=2
            result=b""
            if reason:
                self.assertEqual(raw[at:at+reason].decode(),expect)
                at+=reason
            else:
                self.assertEqual(expect,"ok")
                n,=struct.unpack_from("<Q",raw,at)
                self.assertEqual(n,int.from_bytes(q[8:16],"little"))
                if code==102:
                    self.assertGreater(n,THE_MAX)
                    at+=8
                else:
                    self.assertLessEqual(n,THE_MAX)
                    result=raw[at:at+n+8]
                    at+=8+n
            if i==17:
                self.assertEqual((len(wire(frame,q)),len(result)),(LOGICAL+MAX_FRAME_SUFFIX,11))
            if i==18:
                self.assertEqual(len(result),15)
                self.assertEqual(result[8:],payload(2*CAP+5)[2*CAP-2:])
            if i==24:
                self.assertEqual(len(result),CAP)
            with self.subTest(i=i,stock="selfhost"):
                self.invoke(self.selfhost,"f0",[wire(frame,q)],code,result)
                counts[0]+=1
            with self.subTest(i=i,stock="direct-split"):
                self.invoke(self.direct,"f1",physical(frame,q,cuts),code,result)
                counts[1]+=1
            if len(wire(frame,q))<=CAP:
                with self.subTest(i=i,stock="direct-contiguous"):
                    self.invoke(self.direct,"f0",[wire(frame,q)],code,result)
                    counts[2]+=1
        self.assertEqual(at,len(raw))
        self.assertEqual(counts,[27,27,18])

    def test_window_precedence_and_exact_output_canaries(self):
        frame=cases()[10][0]
        for m,f,wrap in ((self.direct,"f1",lambda f,q:physical(f,q,(3,8))),
                         (self.selfhost,"f0",lambda f,q:[wire(f,q)])):
            self.invoke(m,f,wrap(frame,query(b"a",1,11)),102,size=18)
            self.invoke(m,f,wrap(frame,query(b"a",1,11)),102,size=19,work=WORK-1)
            self.invoke(m,f,wrap(frame,query(b"a",2,MAX)),243,size=0)
            self.invoke(m,f,wrap(frame,query(b"missing",MAX,MAX)),226,size=0)
            self.invoke(m,f,wrap(frame,query(b"a",16,0)),0,struct.pack("<Q",0),size=8)
            self.invoke(m,f,wrap(frame,query(b"a",16,0)),102,size=7)
