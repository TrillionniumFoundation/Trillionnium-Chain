"""Original private immutable tensor range values, not a retained file view."""
import hashlib
import struct
import tempfile
from pathlib import Path
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_reader_framing import container, loan
from hia.tests.test_da_cell_tensor_reader_readback import field
from hia.tests.test_da_cell_tensor_reader_readback_four import cases as previous, full, spans
from hia.tests.tensor_layout_original import real_layout
from hia.tests.tensor_readback_four_derivation import CAP, LOGICAL
from hia.tests.tensor_readback_layout_derivation import BASE_SLOT, CANONICAL, READBACK, SOURCE, WIDTH, WORK, derive

MAX_TENSORS=16384


def cases():
    first=container()
    second=container(b"{"+field("y",[],0,4)+b","+field("x",[],4,6,"F16")+b"}",b"X"*6)
    selected=loan([first,second],index=1,
        scope=[file(0,tensor(b"a")),file(1,tensor(b"x",dtype=2),tensor(b"y"))])
    return previous()+[(selected,"ok",0)]


class CellTensorReaderReadbackLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.read_bytes().startswith(derive()):
            raise ValueError("Exact published reader layout derivation drifted")
        cls.d=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.s=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=LOGICAL+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256 or "f1" in cls.s.exports:
            raise ValueError("Distinct stock profiles required")

    def invoke(self,m,fn,args,status,val=b"",*,n=None,w=WORK+11):
        size=len(val)+7 if n is None else n
        output,scratch=MARK*size,SCRATCH*w
        observed=m.call(fn,[*args,output,scratch],timeout=59).require_returned()
        self.assertEqual(observed.abi_status,0)
        self.assertEqual(observed.value,status)
        self.assertEqual(observed.arguments[:-2],args)
        self.assertEqual(observed.arguments[-2],val+output[len(val):])
        self.assertEqual(observed.arguments[-1][WORK:],scratch[WORK:])
        return observed.arguments[-1]

    def test_exact_frozen_private_layout_of_same_selected_file(self):
        rows=cases()
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-private-layout-") as tmp:
            packet=b"".join(struct.pack("<I",len(data))+data for data,_,_ in rows)
            fresh,lib=real_layout(Path(tmp),packet)
        self.assertEqual(len(lib),64)
        at=0
        counts=[0,0,0]
        for i,(data,expected,status) in enumerate(rows):
            width,=struct.unpack_from("<H",fresh,at)
            at+=2
            p,h,*b=spans(data)
            if width:
                self.assertEqual(fresh[at:at+width].decode(),expected)
                actual=b""
                at+=width
            else:
                self.assertEqual(expected,"ok")
                tensors,=struct.unpack_from("<Q",fresh,at+66)
                n=READBACK+WIDTH*tensors
                actual=fresh[at:at+n]
                at+=n
                self.assertEqual(len(actual),n)
                self.assertEqual(actual[82:114],hashlib.sha256(p[-8:]+h+b"".join(b)).digest())
                pairs=list(struct.iter_unpack("<QQ",actual[READBACK:]))
                self.assertTrue(all(8+len(h)<=a and a+n<=8+len(h)+sum(map(len,b)) for a,n in pairs))
                if i==35:
                    self.assertEqual((len(data),tensors,n),(LOGICAL,MAX_TENSORS,262258))
                    # Canonical first name occupies the last physical interval.
                    self.assertEqual(pairs[0],(8+len(h)+4*(MAX_TENSORS-1),sum(map(len,b))-4*(MAX_TENSORS-1)))
                    self.assertEqual(pairs[-1],(8+len(h)+4*(MAX_TENSORS-2),4))
                if i==len(rows)-1:
                    self.assertEqual(int.from_bytes(actual[64:66],"little"),1)
                    self.assertEqual(pairs,[(8+len(h)+4,2),(8+len(h),4)])
            want=actual if status==0 else b""
            with self.subTest(ix=i,engine="selfhost-f0"):
                self.invoke(self.s,"f0",[data],status,want)
                counts[0]+=1
            cells=[p,h,*b]
            self.assertEqual(b"".join(cells),data)
            if all(len(x)<=CAP for x in cells):
                with self.subTest(ix=i,engine="direct-f1"):
                    self.invoke(self.d,"f1",cells,status,want)
                    counts[1]+=1
            if len(data)<=CAP:
                with self.subTest(ix=i,engine="direct-f0"):
                    self.invoke(self.d,"f0",[data],status,want)
                    counts[2]+=1
        self.assertEqual(at,len(fresh))
        self.assertEqual(counts,[43,41,6])

    def test_exact_capacity_and_transition_to_canonical_pairs(self):
        raw=full(LOGICAL)
        p,h,*b=spans(raw)
        for m,fn,inputs in ((self.d,"f1",[p,h,*b]),(self.s,"f0",[raw])):
            scratch=self.invoke(m,fn,inputs,102,n=READBACK+WIDTH*MAX_TENSORS-1,w=WORK)
            base,=struct.unpack_from("<Q",scratch,BASE_SLOT)
            first,=struct.unpack_from("<Q",scratch,CANONICAL)
            last,=struct.unpack_from("<Q",scratch,CANONICAL+8*(MAX_TENSORS-1))
            self.assertEqual(base,8+len(h))
            self.assertEqual(first>>22,4*(MAX_TENSORS-1))
            self.assertEqual(first&((1<<22)-1),sum(map(len,b)))
            self.assertEqual((last>>22,last&((1<<22)-1)),(4*(MAX_TENSORS-2),4*(MAX_TENSORS-1)))
            self.invoke(m,fn,inputs,102,n=0,w=WORK-1)
            # Semantic digest failure remains ahead of a short output loan.
            bad=[*b[:-1],b[-1][1:]+b[-1][:1]]
            inputs=[p,h,*bad] if fn=="f1" else [p+h+b"".join(bad)]
            self.invoke(m,fn,inputs,224,n=0,w=WORK)
