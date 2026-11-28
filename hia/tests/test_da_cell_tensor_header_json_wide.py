"""Frozen original private TensorHeader and two stock modes at exactly 1 MiB."""
import struct
from pathlib import Path
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_da_cell_tensor_header_json import (
    ENTRY, JSON, PRIVATE_LIMIT, field, fixtures as prior_fixtures,
    original_reference, packet,
)
from hia.tests.tensor_header_wide_derivation import WIDE, CAP, WORK, derive_core


def dense_metadata():
    # 63 exactly max decoded values, plus a non-empty 64th. Every byte of
    # the 1 MiB header is borrowed and parsed; this is not a padding-only case.
    pair=b",".join(f'"m{i:02d}":"'.encode()+b"x"*16384+b'"' for i in range(63))
    prefix=b'{"__metadata__":{'+pair+b',"m63":"'
    tail=b'"}}'
    n=CAP-len(prefix)-len(tail)
    assert 0<n<=16384
    text=prefix+b"z"*n+tail
    assert len(text)==CAP
    return text


def huge_dtype(escaped=False):
    blank=field(b"x",ENTRY.replace(b'"F32"',b'""'))
    n=CAP-len(blank)
    if escaped:
        # Original accepts arbitrary strings here. Span includes escapes from
        # 1/2/3/4-byte decoded scalars, an escaped quote, and a literal UTF-8.
        raw=br'\u0061\u00e9\u20ac\ud834\udd1e\"'+"π".encode()
        dtype=raw*(n//len(raw))+b"q"*(n%len(raw))
    else:
        dtype=b"a"*n
    text=field(b"x",ENTRY.replace(b'"F32"',b'"'+dtype+b'"'))
    assert len(text)==CAP
    return text


def corpus():
    old=prior_fixtures()
    rows=[(d,0 if code==PRIVATE_LIMIT and len(d)>(128<<10) else code)
          for d,code in old]
    dense=dense_metadata()
    many=huge_dtype()
    controls=[
        (dense,0),
        (many,0),
        (huge_dtype(escaped=True),0),
        (dense[:-2]+b"]}",JSON),
        (many[:-1]+b";",JSON),
        (dense+b" ",PRIVATE_LIMIT),
        (many+b" ",PRIVATE_LIMIT),
    ]
    assert all(len(d)<=CAP+1 for d,_ in rows+controls)
    return rows+controls


class CellTensorHeaderJsonWide(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not WIDE.read_bytes().startswith(derive_core()):
            raise ValueError("Wide source drifted from the exact published JSON parser")
        cls.d=cls.enterClassContext(NativeModule(WIDE,backend="direct",byte_exports=("f0",)))
        cls.s=cls.enterClassContext(NativeModule(WIDE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=CAP+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256:
            raise ValueError("both distinct stock artifacts required")

    def call_exact(self, module, data, code, value=b"", *, n=None, w=WORK+11):
        if n is None:
            n=min(CAP,len(value)+7)
        out,work=MARK*n,SCRATCH*w
        r=module.call("f0",[data,out,work],timeout=40).require_returned()
        self.assertEqual(r.value,code)
        self.assertEqual(r.arguments[0],data)
        self.assertEqual(r.arguments[1],value+out[len(value):])
        self.assertEqual(r.arguments[2][WORK:],work[WORK:])
        if w<WORK or len(data)>CAP:
            self.assertEqual(r.arguments[2],work)

    def test_original_raw_full_cap_and_typed_decoded_output(self):
        rows=corpus()
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-header-full-original-") as tmp:
            raw=original_reference(Path(tmp),packet([d for d,_ in rows]))
        p=0
        for j,(data,expected) in enumerate(rows):
            code,n=struct.unpack_from("<BI",raw,p)
            p+=5
            value=raw[p:p+n]
            p+=n
            self.assertEqual(code,0 if expected==PRIVATE_LIMIT else expected)
            self.assertEqual(len(value),n)
            if code==0:
                self.assertLessEqual(n,CAP)
            if expected!=0:
                value=b""
            with self.subTest(index=j,extent=len(data),backend="selfhost"):
                self.call_exact(self.s,data,expected,value)
            if len(data)<=CAP:
                with self.subTest(index=j,extent=len(data),backend="direct"):
                    self.call_exact(self.d,data,expected,value)
        self.assertEqual(p,len(raw))

    def test_atomic_full_projection_and_short_table_limits(self):
        raw=huge_dtype()
        blank=field(b"x",ENTRY.replace(b'"F32"',b'""'))
        count=CAP-len(blank)
        content=(struct.pack("<QQ",1,1)+b"x"+struct.pack("<Q",count)+b"a"*count
                 +struct.pack("<QQQ",0,0,4))
        self.assertLessEqual(len(content),CAP)
        self.assertGreater(len(content),128<<10)
        for m in (self.d,self.s):
            self.call_exact(m,raw,0,content,n=len(content),w=WORK)
            self.call_exact(m,raw,102,n=len(content)-1,w=WORK)
            self.call_exact(m,b"{}",102,n=8,w=WORK-1)
            self.call_exact(m,raw[:-1]+b"]",JSON,n=0,w=WORK)
