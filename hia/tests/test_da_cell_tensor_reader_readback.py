"""One immutable readback compared to actual original public verify_reader on synthetic bytes."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_reader_framing import (
    CAP, EARLY, GOOD, TENSOR, TENSOR_SHA, cases as framing_cases, container, declare, loan,
)
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests.tensor_readback_framing_derivation import SOURCE, WORK, assert_bound

ORACLE=Path(__file__).with_name("rust_cell_tensor_reader_readback_reference.rs")
RESULT_BYTES=114
HEADER_CAP=131072
OUTSIDE=218
STATUS={
    **EARLY,"ok":0, "tensor header JSON":217, "tensor roster coverage":219,
    "tensor roster metadata":220, "tensor data range":221, "tensor overlap or hole":222,
    "tensor trailing data":223,"tensor payload digest":224,
}


def saturated(total):
    # Keep the header small; exercise truly large payload hashing at the shared
    # native loan cap, not merely a standalone header profile refusal.
    amount=((total-1024)//4)*4
    row=field("a",[amount//4],0,amount)
    body=bytes(amount-5)+b"\x01\x88\xff\x00\xca"
    b=container(b"{"+row+b"}",body)
    spec=[file(0,tensor(b"a",(amount//4,)))]
    add=total-len(loan([b],scope=spec))
    assert 0<=add<=1024
    b=container(b"{"+row+b"}"+b" "*add,body)
    data=loan([b],scope=spec)
    assert len(data)==total
    return data


def long_header(n):
    value=container(GOOD+b" "*(n-len(GOOD)))
    assert int.from_bytes(value[:8],"little")==n
    return loan([value])


def field(name,shape,start,end,dtype="F32"):
    s=json.dumps({"shape":shape,"data_offsets":[start,end],"dtype":dtype},
                 ensure_ascii=True,separators=(",",":")).encode()
    return json.dumps(name,ensure_ascii=True).encode()+b":"+s


def complete_count(n):
    names=[f"z{i:03d}" for i in range(n)]
    # Source and physical order both differ from the original canonical
    # declaration order. Rust sorts JSON by name then sorts numeric intervals.
    body=b"{"+b",".join(field(name,[],(n-1-j)*4,(n-j)*4)
                         for j,name in reversed(tuple(enumerate(names))))+b"}"
    actual=container(body,bytes([4])*4*n)
    return loan([actual],scope=[file(0,*(tensor(name.encode()) for name in names))])


def meta_count(n):
    body=GOOD[:-1]+b',"__metadata__":{'+b",".join(
        f'"m{i:02d}":"note{i:02d}"'.encode() for i in range(n))+b"}}"
    return loan([container(body)])


def cases():
    ordinary=[]
    for wire,why in framing_cases():
        if len(wire)>=CAP:
            # These are separately accepted by Rust but exceed this narrower
            # JSON visitor's header ceiling even though one has a 1 MiB loan.
            ordinary.append((wire,why,OUTSIDE if len(wire)==CAP else None))
        else:
            ordinary.append((wire,why,STATUS[why]))
    good=container()
    physical=container(b"{"+field("a",[],4,8)+b","+field("b",[],0,4)+b"}",
                       bytes([0x77])*8)
    declared=[file(0,tensor(b"a"),tensor(b"b"))]

    def mixed(a,b,why,extra=bytes(8),wrong_sha=False):
        actual=container(b"{"+a+b","+b+b"}",extra)
        r=declare([actual],claims=[bytes(len(actual))]) if wrong_sha else None
        return (loan([actual],r=r,scope=declared),why,STATUS[why])

    a=field("a",[],0,4)
    b=field("b",[],4,8)
    wrong_b=field("b",[],4,8,"F16")
    bad_a=field("a",[],0,3)
    wrong_a=field("a",[1],0,4)
    extra=[
        (loan([physical],scope=declared),"ok",0),
        (loan([good,good],index=1,scope=[file(0,tensor(b"a")),file(1,tensor(b"a"))]),"ok",0),
        (saturated(CAP),"ok",0),(saturated(CAP+1),"ok",None),
        (long_header(HEADER_CAP),"ok",0),(long_header(HEADER_CAP+1),"ok",OUTSIDE),
        (complete_count(128),"ok",0),(complete_count(129),"ok",OUTSIDE),
        (meta_count(64),"ok",0),(meta_count(65),"ok",OUTSIDE),
        mixed(bad_a,wrong_b,"tensor data range",wrong_sha=True),
        mixed(wrong_a,field("b",[],4,9),"tensor roster metadata",wrong_sha=True),
        mixed(a,field("b",[],0,3),"tensor data range",wrong_sha=True),
        mixed(a,field("b",[],1,5),"tensor overlap or hole",wrong_sha=True),
        mixed(a,field("b",[],0,4),"tensor overlap or hole",wrong_sha=True),
        mixed(a,b,"tensor trailing data",bytes(9),wrong_sha=True),
        mixed(a,b,"tensor payload digest",wrong_sha=True),
    ]
    return ordinary+extra


class CellTensorReaderReadback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert_bound()
        cls.modules={b:cls.enterClassContext(NativeModule(SOURCE,backend=b,byte_exports=("f0",)))
                     for b in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.modules.values()})!=2:
            raise ValueError("both distinct stock tools required")

    def panel(self, rows):
        for b,m in self.modules.items():
            for index,(data,code,value,out_n,scratch) in enumerate(rows):
                with self.subTest(backend=b,case=index):
                    out,w=MARK*out_n,SCRATCH*scratch
                    r=m.call("f0",[data,out,w],timeout=35).require_returned()
                    self.assertEqual(r.value,code)
                    self.assertEqual(r.arguments[0],data)
                    self.assertEqual(r.arguments[1],value+out[len(value):])
                    self.assertEqual(r.arguments[2][WORK:],w[WORK:])

    def test_whole_immutable_stage_and_exact_frozen_original(self):
        original=cases()
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        with tempfile.TemporaryDirectory(prefix="trnm-reader-readback-original-") as td:
            req=b"".join(struct.pack("<I",len(d))+d for d,_,_ in original)
            raw=locked_reference(Path(td),req,caller=ORACLE)
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        at=0
        paired=[]
        for data,expected,native in original:
            n,=struct.unpack_from("<H",raw,at)
            at+=2
            if n:
                got=raw[at:at+n].decode()
                at+=n
                self.assertEqual(got,expected)
                observed=b""
            else:
                self.assertEqual(expected,"ok")
                observed=raw[at:at+RESULT_BYTES]
                at+=RESULT_BYTES
                self.assertEqual(len(observed),RESULT_BYTES)
            if len(data)>CAP:
                self.assertIsNone(native)
            else:
                self.assertIsNotNone(native)
                paired.append((data,native,observed if native==0 else b"",RESULT_BYTES+7,WORK+9))
        self.assertEqual(at,len(raw))
        self.panel(paired)

    def test_interface_limits_and_refusal_output_atomicity(self):
        b=container()
        data=loan([b])
        v=(data[:32]+data[44:76]+struct.pack("<HQQ",0,1,len(b))+hashlib.sha256(b).digest())
        self.assertEqual(len(v),RESULT_BYTES)
        self.panel([
            (data,0,v,RESULT_BYTES,WORK), (data,102,b"",RESULT_BYTES-1,WORK),
            (data,102,b"",RESULT_BYTES,WORK-1), (b"",210,b"",0,0),
            (data[:34]+bytes([255])*4+data[38:],210,b"",0,WORK),
            (loan([b],actual=container(data=bytes(4))),224,b"",0,WORK),
            (loan([b],actual=container(data=bytes(4)),pin=bytes(32)),211,b"",0,WORK),
            (loan([container(b"{broken}")]),217,b"",0,WORK),
        ])
