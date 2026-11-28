"""Bounded expanded metadata lookup compared with the frozen private Rust visitor."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_da_cell_tensor_header_json import (
    ENTRY, JSON, PRIVATE_LIMIT, field, many, original_reference, packet,
)
from hia.tests.test_da_cell_tensor_header_json_wide import corpus
from hia.tests.tensor_header_metadata_derivation import MAX_KEYS, SOURCE, WORK, derive

CAP = 1 << 20


def named(key, value=b'"m"'):
    return b'"'+key+b'":'+value


def metadata(rows, *, with_tensor=False):
    tail = b',"a":'+ENTRY if with_tensor else b""
    return b'{"__metadata__":{'+b",".join(rows)+b"}"+tail+b"}"


def full_header():
    # Deterministic permutation with full-length common-prefix keys. Make the
    # exact 1 MiB header without padding, including the actual 1024th key.
    keys = [b"x"*251+f"{(i*773+379)%MAX_KEYS:04x}".encode() for i in range(MAX_KEYS)]
    used = len(metadata([named(k,b'""') for k in keys],with_tensor=True))
    left = CAP-used
    rows = []
    for k in keys:
        n = min(16384,left)
        rows.append(named(k,b'"'+b"v"*n+b'"'))
        left -= n
    raw = metadata(rows,with_tensor=True)
    assert left == 0 and len(raw) == CAP and len(set(keys)) == MAX_KEYS
    return raw


def cases():
    rows = [(raw,0 if raw==many(65,True) else code) for raw,code in corpus()]
    prev = [named(f"r{ix:04d}".encode()) for ix in range(MAX_KEYS-1)]
    # At 1023 stored entries the forest contains every power-of-two size.
    # Query the first physical record of each disjoint run with an escaped
    # spelling; also cover the boundary before and after largest-run rollover.
    for ix in (0,512,768,896,960,992,1008,1016,1020,1022):
        encoded = br"\u0072"+f"{ix:04d}".encode()
        rows.append((metadata([*prev,named(encoded)]),JSON))
    dense = full_header()
    controls = [
        (metadata(prev),0),
        (metadata([*prev,named(b"new")],with_tensor=True),0),
        (many(MAX_KEYS+1,True),JSON),
        (metadata([*prev,named(b"new"),named(b"last",b"null")]),JSON),
        (metadata([*prev,named(b"r0000",b"false")]),JSON),
        (metadata([*prev,named(b"new",b'"'+b"x"*16385+b'"')]),JSON),
        (metadata([*prev,named(b"x"*256)]),JSON),
        (metadata([*prev,named(chr(0x3C0).encode(),b'""')]),0),
        (metadata([named(chr(0x3C0).encode()),named(br"\u03c0")]),JSON),
        (metadata([named(chr(0x1D11E).encode()),named(br"\ud834\udd1e")]),JSON),
        (metadata([named(br"\u0000"),named(br"\u0000")]),JSON),
        (metadata([named(b""),named(b"a"),named(b"ab"),named(b"abc"),named(b"b")]),0),
        (metadata([named(b""),named(b"a"),named(b"")]),JSON),
        (metadata([named(b"a"),named(b"ab"),named(br"a\u0062")]),JSON),
        (dense,0), (dense+b" ",PRIVATE_LIMIT),
    ]
    return rows+controls


class CellTensorHeaderMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.read_bytes().startswith(derive()):
            raise ValueError("Exact published wide parser derivation mismatch")
        cls.d=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0",)))
        cls.s=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=CAP+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256:
            raise ValueError("Both distinct stock emitters required")

    def invoke(self,m,raw,code,want=b"",*,size=None,worksize=WORK+11):
        if size is None:
            size=min(CAP,len(want)+11)
        o,w=MARK*size,SCRATCH*worksize
        observed=m.call("f0",[raw,o,w],timeout=50).require_returned()
        self.assertEqual(observed.value,code)
        self.assertEqual(observed.arguments[0],raw)
        self.assertEqual(observed.arguments[1],want+o[len(want):])
        self.assertEqual(observed.arguments[2][WORK:],w[WORK:])
        if worksize<WORK or len(raw)>CAP:
            self.assertEqual(observed.arguments[2],w)

    def test_frozen_original_and_both_max_key_rosters(self):
        entries=cases()
        with tempfile.TemporaryDirectory(prefix="trnm-metadata-1024-original-") as td:
            raw=original_reference(Path(td),packet([item for item,_ in entries]))
        p=0
        invoked=[0,0]
        for ix,(data,want) in enumerate(entries):
            code,n=struct.unpack_from("<BI",raw,p)
            p+=5
            result=raw[p:p+n]
            p+=n
            self.assertEqual(code,0 if want==PRIVATE_LIMIT else want)
            self.assertEqual(len(result),n)
            expected=result if want==0 else b""
            with self.subTest(index=ix,extent=len(data),backend="selfhost"):
                self.invoke(self.s,data,want,expected)
                invoked[0]+=1
            if len(data)<=CAP:
                with self.subTest(index=ix,extent=len(data),backend="direct"):
                    self.invoke(self.d,data,want,expected)
                    invoked[1]+=1
        self.assertEqual(p,len(raw))
        self.assertEqual(invoked,[len(entries),len(entries)-3])

    def test_profile_and_atomic_output_are_bounded(self):
        raw=full_header()
        for m in (self.d,self.s):
            self.invoke(m,raw,102,size=0)
            self.invoke(m,b"{}",102,size=8,worksize=WORK-1)
            self.invoke(m,many(MAX_KEYS+1,True),JSON,size=0)
        self.invoke(self.s,raw+b" ",PRIVATE_LIMIT,size=0)
