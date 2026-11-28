"""Scope-specific two-physical-loan Direct vs stock Selfhost and frozen public Rust."""
from collections import Counter
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_cell_tensor_contract import file, row as tensor
from hia.tests.test_da_cell_tensor_reader_framing import TENSOR, TENSOR_SHA, container, declare, loan
from hia.tests.test_da_cell_tensor_reader_readback import (
    ORACLE, RESULT_BYTES, STATUS, WORK, cases as old_cases, field,
)
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests.tensor_readback_wide_derivation import MAX_LOGICAL, MAX_SPAN, WIDE, derive

OUTSIDE = 210
SPLIT = 225


def begin_wire(data):
    n = int.from_bytes(data[34:38], "big")
    r = 38+n
    m = int.from_bytes(data[r:r+4], "big")
    return r+4+m


def body_offset(data):
    e = begin_wire(data)
    h = int.from_bytes(data[e:e+8], "little")
    return e+8+h


def wide(total, *, miss=False):
    # Near-max payload with actual nonuniform body; header stays tiny.
    n = ((total-1024)//4)*4
    src = bytes(range(251))
    body = (src * ((n+250)//251))[:n]
    row = b"{"+field("a",[n//4],0,n)+b"}"
    actual = container(row,body)
    spec = [file(0,tensor(b"a",(n//4,)))]
    pad = total-len(loan([actual],scope=spec))
    assert 0 <= pad <= 1024
    actual = container(row+b" "*pad,body)
    if miss:
        other = actual[:-1] + bytes([actual[-1]^1])
        r = declare([actual],claims=[other])
    else:
        r = None
    raw = loan([actual],r=r,scope=spec)
    assert len(raw)==total
    return raw


def corpus():
    result=[]
    for raw,error,status in old_cases():
        if status is not None: result.append((raw,error,status))
    # The prior +1 tests are valid original containers, now admitted where
    # they have the qualified small header (only the short-header case).
    result += [
        (wide(2*MAX_SPAN-257),"ok",0),
        (wide(MAX_SPAN+1),"ok",0),
        (wide(MAX_SPAN+8193),"ok",0),
        (wide(MAX_LOGICAL-1),"ok",0),
        (wide(MAX_LOGICAL),"ok",0),
        (wide(MAX_LOGICAL+1),"ok",OUTSIDE),
        (wide(MAX_LOGICAL,miss=True),"tensor payload digest",224),
    ]
    return result


class CellTensorReaderReadbackWide(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if WIDE.read_bytes()!=derive():
            raise ValueError("Wide immutable entry lost exact frozen CFG source binding")
        cls.d=cls.enterClassContext(NativeModule(WIDE,backend="direct",byte_exports=("f0","f1")))
        # Existing bounded Selfhost fixture opt-in; no generic limits change.
        cls.s=cls.enterClassContext(NativeModule(WIDE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=MAX_LOGICAL+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256 or "f1" in cls.s.exports:
            raise ValueError("Expected distinct stock artifacts and the legacy Selfhost export only")

    def invoke(self, module, name, args, code, result=b"", n=RESULT_BYTES+5, work=WORK+13):
        out,scratch=MARK*n,SCRATCH*work
        got=module.call(name,[*args,out,scratch],timeout=45).require_returned()
        self.assertEqual(got.value,code)
        self.assertEqual(got.arguments[:-2],args)
        self.assertEqual(got.arguments[-2],result+out[len(result):])
        self.assertEqual(got.arguments[-1][WORK:],scratch[WORK:])

    def test_real_original_and_both_unchanged_stock_paths(self):
        rows=corpus()
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        with tempfile.TemporaryDirectory(prefix="trnm-reader-wide-original-") as tmp:
            packet=b"".join(struct.pack("<I",len(raw))+raw for raw,_,_ in rows)
            original=locked_reference(Path(tmp),packet,caller=ORACLE)
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        at=0
        counts=Counter()
        for j,(raw,error,status) in enumerate(rows):
            n,=struct.unpack_from("<H",original,at)
            at+=2
            if n:
                self.assertEqual(original[at:at+n].decode(),error)
                at+=n
                obs=b""
            else:
                self.assertEqual(error,"ok")
                obs=original[at:at+RESULT_BYTES]; at+=RESULT_BYTES
                self.assertEqual(len(obs),RESULT_BYTES)
            value=obs if status==0 else b""
            with self.subTest(j=j,length=len(raw),abi="selfhost-f0"):
                self.invoke(self.s,"f0",[raw],status,value); counts["selfhost-f0"]+=1
            if len(raw)<=MAX_LOGICAL:
                k=min(MAX_SPAN,len(raw))
                self.assertLessEqual(len(raw)-k,MAX_SPAN)
                with self.subTest(j=j,length=len(raw),abi="direct-f1"):
                    self.invoke(self.d,"f1",[raw[:k],raw[k:]],status,value); counts["direct-f1"]+=1
            if len(raw)<=MAX_SPAN:
                with self.subTest(j=j,length=len(raw),abi="direct-f0"):
                    self.invoke(self.d,"f0",[raw],status,value); counts["direct-f0"]+=1
        self.assertEqual(at,len(original))
        self.assertEqual(counts,{"selfhost-f0":len(rows),"direct-f1":len(rows)-1,"direct-f0":52})

    def test_split_geometry_and_ordered_hash_are_native(self):
        wire=wide(MAX_SPAN+1)
        e=begin_wire(wire)
        q=body_offset(wire)
        raw=wire[e:]
        lo=MAX_SPAN-64
        v=(wire[:32]+wire[44:76]+struct.pack("<HQQ",0,1,len(raw))+hashlib.sha256(raw).digest())
        self.assertGreater(MAX_SPAN,q)
        for k in (lo-1,lo,lo+1,MAX_SPAN-1,MAX_SPAN):
            with self.subTest(split=k):
                self.invoke(self.d,"f1",[wire[:k],wire[k:]],0,v)
        # Shorter complete files can split at the exact header terminator or
        # across arbitrary SHA block positions inside the body.
        tiny=wide(4096)
        te,tq=begin_wire(tiny),body_offset(tiny)
        original=tiny[te:]
        value=tiny[:32]+tiny[44:76]+struct.pack("<HQQ",0,1,len(original))+hashlib.sha256(original).digest()
        for k in (tq,tq+1,tq+55,tq+56,tq+63,tq+64,len(tiny)):
            with self.subTest(split=k):
                self.invoke(self.d,"f1",[tiny[:k],tiny[k:]],0,value)
        for k in (te,te+7,te+8,tq-1):
            with self.subTest(invalid_split=k):
                self.invoke(self.d,"f1",[tiny[:k],tiny[k:]],SPLIT,n=3)
        s=tq+74
        p,t=tiny[:s],tiny[s:]
        self.invoke(self.d,"f1",[p,t+b"x"],STATUS["tensor actual file length"],n=0)
        self.invoke(self.d,"f1",[p,t[:-1]],STATUS["tensor actual file length"],n=0)
        self.invoke(self.d,"f1",[p,t[1:]+t[:1]],STATUS["tensor payload digest"],n=0)
        with_pin=bytes(32)+tiny[32:s]
        self.invoke(self.d,"f1",[with_pin,t],STATUS["tensor contract pin"],n=0)
        self.invoke(self.d,"f1",[p,t],102,n=RESULT_BYTES-1)
        self.invoke(self.d,"f1",[p,t],102,work=WORK-1)
        # The compiler remains stock: only the explicitly supported new entry
        # gains a wider logical input. No raw over-limit Direct f0 invocation.
        with self.assertRaises(ValueError):
            self.d.call("f0",[wire,MARK*RESULT_BYTES,SCRATCH*WORK])
