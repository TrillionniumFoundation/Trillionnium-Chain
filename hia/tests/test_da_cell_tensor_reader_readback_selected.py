"""Real frozen selected-file layout plus exact synthetic same-loan byte projection."""
from functools import lru_cache
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_header_spans import short_name
from hia.tests.test_da_cell_tensor_reader_framing import container, loan
from hia.tests.test_da_cell_tensor_reader_readback import field
from hia.tests.test_da_cell_tensor_reader_readback_four import CAP, LOGICAL, MAX_TENSORS, full, spans
from hia.tests.test_da_cell_tensor_reader_readback_three import payload
from hia.tests.tensor_layout_original import real_layout
from hia.tests.tensor_readback_selected_derivation import SOURCE, derive

WORK=840456
THE_MAX=CAP-8
NAME_MAX=b"z"*255


def wire(frame, name):
    return frame+name+struct.pack("<H",len(name))


def one_tensor(name, n, *, width=4, padded=0):
    label=name.decode()
    dtype="F32" if width==4 else "F16"
    assert n%width==0
    shape=(n//width,)
    header=b"{"+field(label,shape,0,n,dtype)+b"}"
    return loan([container(header.ljust(padded,b" "),payload(n))],
                scope=[file(0,tensor(name,shape,dtype=1 if width==4 else 2))])


def saturated():
    # The selected tensor is the first 4 physical bytes, but the second canonical
    # name. Pick the exact 4MiB envelope with 255 query bytes and a 1MiB header.
    for k in range(1,5):
        leader=b"!"*k
        rows=[file(0,tensor(leader,(1,)),tensor(NAME_MAX))]
        h0=b"{"+field(NAME_MAX.decode(),[],0,4)+b","+field(leader.decode(),[1],4,8)+b"}"
        probe=loan([container(h0,bytes(8))],scope=rows)
        prefix=spans(probe)[0]
        n=LOGICAL-len(prefix)-CAP
        if n%4:
            continue
        h=b"{"+field(NAME_MAX.decode(),[],0,4)+b","+field(leader.decode(),[n//4-1],4,n)+b"}"
        rows=[file(0,tensor(leader,(n//4-1,)),tensor(NAME_MAX))]
        frame=loan([container(h.ljust(CAP,b" "),payload(n))],scope=rows)
        assert len(frame)==LOGICAL
        return frame
    raise ValueError("Synthetic alignment unavailable")


@lru_cache(maxsize=1)
def cases():
    simple=loan([container()])
    shaped=one_tensor(b"a",16)
    second_header=b"{"+field("y",[],0,4)+b","+field("x",[],4,6,"F16")+b"}"
    second=loan([container(),container(second_header,b"abcdef")],index=1,
                scope=[file(0,tensor(b"a")),file(1,tensor(b"x",dtype=2),tensor(b"y"))])
    u1="é".encode()
    u2="𝄞".encode()
    uncommon=loan([container(b"{"+field("𝄞",[],0,2,"BF16")+b","+
                   field("é",[],2,4,"F16").replace(u1,br"\u00e9")+b"}",b"mnop")],
                 scope=[file(0,tensor(u1,dtype=2),tensor(u2,dtype=3))])
    last=max(short_name(j) for j in range(MAX_TENSORS-1)).encode()
    full_frame=full(LOGICAL)
    # The full generator selects the punctuation name width to align the exact
    # 4MiB envelope. Read that known synthetic declaration's first label.
    lead_at=38+40+4
    lead_n,=struct.unpack_from(">H",full_frame,lead_at)
    lead=full_frame[lead_at+2:lead_at+2+lead_n]
    assert lead in (b"!",b"!!",b"!!!",b"!!!!")
    p,h,*body=spans(full_frame)
    tail=body[-1]
    changed_full=p+h+b"".join(body[:-1])+tail[:-1]+bytes([tail[-1]^1])
    overlap=full(LOGICAL,overlap=True)
    return [
        (simple,b"a","ok",0,None),
        (simple,b"A","selected tensor missing",226,None),
        (simple,b"aa","selected tensor missing",226,None),
        (simple,b"","selected tensor missing",226,None),
        (simple,b"X"*256,"selected tensor missing",226,None),
        (simple,b"\xff","selected tensor missing",226,None),
        (shaped,b"a","ok",0,(1,6)),
        (second,b"x","ok",0,(1,5)),
        (second,b"y","ok",0,(1,3)),
        (second,b"a","selected tensor missing",226,None),
        (uncommon,u1,"ok",0,(1,3)),
        (uncommon,u2,"ok",0,(1,3)),
        (uncommon,"e\u0301".encode(),"selected tensor missing",226,None),
        (saturated(),NAME_MAX,"ok",0,None),
        (full_frame,last,"ok",0,None),
        (full_frame,lead,"ok",102,None),
        (changed_full,last,"tensor payload digest",224,None),
        (changed_full,b"missing","tensor payload digest",224,None),
        (overlap,b"missing","tensor overlap or hole",222,None),
        (one_tensor(b"big",THE_MAX),b"big","ok",0,(1,CAP-17)),
        (one_tensor(b"over",THE_MAX+2,width=2),b"over","ok",102,None),
        (b"\x00"+simple[1:],b"missing","tensor contract pin",211,None),
    ]


def physical(frame, name, cuts=None):
    p,h,*parts=spans(frame)
    if cuts is not None:
        a,b=cuts
        body=b"".join(parts)
        parts=[body[:a],body[a:b],body[b:]]
    assert b"".join((p,h,*parts))==frame
    assert all(len(i)<=CAP for i in (p,h,*parts,name))
    return [p,h,*parts,name]


def rust_cases():
    raw=b"".join(struct.pack("<I",len(d)+2+len(q))+struct.pack("<H",len(q))+q+d
                 for d,q,_,_,_ in cases())
    with tempfile.TemporaryDirectory(prefix="trnm-tensor-private-selected-") as scratch:
        return real_layout(Path(scratch),raw,selected=True)


class CellTensorReaderReadbackSelected(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.read_bytes()!=derive():
            raise ValueError("Exact published reader and new projection do not derive the recorded source")
        cls.direct=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0","f1")))
        cls.selfhost=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                        max_input_extent=LOGICAL+257))

    def invoke(self,m,f,args,code,out=b"",*,size=None,work=WORK+7):
        length=min(len(out)+9,CAP) if size is None else size
        written=MARK*length
        scratch=SCRATCH*work
        actual=m.call(f,[*args,written,scratch],timeout=59).require_returned()
        self.assertEqual((actual.abi_status,actual.value),(0,code))
        self.assertEqual(actual.arguments[:-2],args)
        self.assertEqual(actual.arguments[-2],out+written[len(out):])
        self.assertEqual(actual.arguments[-1][WORK:],scratch[WORK:])

    def test_locked_original_and_both_stock_selected_bytes(self):
        raw,lib=rust_cases()
        self.assertEqual(len(lib),64)
        at=0
        counts=[0,0,0]
        for i,(frame,name,expect,status,cuts) in enumerate(cases()):
            reason,=struct.unpack_from("<H",raw,at)
            at+=2
            result=b""
            if reason:
                self.assertEqual(raw[at:at+reason].decode(),expect)
                at+=reason
            else:
                self.assertEqual(expect,"ok")
                length,=struct.unpack_from("<Q",raw,at)
                seen=8+(length if length<=THE_MAX else 0)
                canonical=raw[at:at+seen]
                at+=seen
                if status==0:
                    self.assertLessEqual(length,THE_MAX)
                    result=canonical
                else:
                    self.assertEqual(status,102)
                    self.assertGreater(length,THE_MAX)
            if i==13:
                self.assertEqual((len(frame),len(name),len(wire(frame,name)),len(result)),
                                 (LOGICAL,255,LOGICAL+257,12))
            if i==19:
                self.assertEqual(len(result),CAP)
            with self.subTest(i=i,backend="selfhost-f0"):
                self.invoke(self.selfhost,"f0",[wire(frame,name)],status,result)
                counts[0]+=1
            with self.subTest(i=i,backend="direct-f1"):
                self.invoke(self.direct,"f1",physical(frame,name,cuts),status,result)
                counts[1]+=1
            if len(wire(frame,name))<=CAP:
                with self.subTest(i=i,backend="direct-f0"):
                    self.invoke(self.direct,"f0",[wire(frame,name)],status,result)
                    counts[2]+=1
        self.assertEqual(at,len(raw))
        self.assertEqual(counts,[22,22,14])

    def test_exact_late_refusals_capture_no_bytes(self):
        items=cases()
        small=items[6][0]
        name=b"a"
        self.invoke(self.direct,"f0",[wire(small,name)[:-2]+b"\xff\xff"],210,size=40)
        for m,f,args in ((self.direct,"f1",physical(small,name,(0,1))),
                         (self.selfhost,"f0",[wire(small,name)])):
            self.invoke(m,f,args,102,size=23)
            self.invoke(m,f,args,102,size=40,work=WORK-1)
            self.invoke(m,f,args,0,struct.pack("<Q",16)+payload(16),size=24)
        frame=items[16][0]
        self.invoke(self.direct,"f1",physical(frame,b"missing"),224,size=0)
        self.invoke(self.selfhost,"f0",[wire(frame,b"missing")],224,size=0)
