"""Actual frozen cache cursor arithmetic with real original TCM1 and both emitters."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.cache_payload_cursor_original import original
from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import CHUNK
from hia.tests.test_cell_manifest import (
    MARK, MAX_CELL, MAX_CHUNK, MAX_MANIFEST, SCRATCH, SRC as MANIFEST, cases as manifest_cases, wire,
)

SOURCE=MANIFEST.with_name("cell_cache_payload_cursor.hepta")
MAX=(1<<64)-1
MIN_SIGNED=-(1<<63)
MAX_SIGNED=(1<<63)-1
START,END,CURRENT,READ=range(4)
SEEK_REFUSAL=246


def request(manifest,op,position,arg):
    return struct.pack("<BQQ",op,position,arg&MAX)+manifest


def expect_seek(n):
    return struct.pack("<Q",n)


def expect_read(i,off,count,pos):
    return struct.pack("<QQQQ",i,off,count,pos)


def cases():
    data=wire(opaque=True)
    size=CHUNK+13
    out=[]
    def seek(manifest,op,pos,arg,next_):
        out.append((request(manifest,op,pos,arg),SEEK_REFUSAL if next_ is None else 0,
                    b"" if next_ is None else expect_seek(next_)))
    def read(manifest,pos,want,result):
        out.append((request(manifest,READ,pos,want),0,expect_read(*result)))
    for pos in (0,MAX):
        for arg in (0,1,size,size+1,MAX):
            seek(data,START,pos,arg,arg)
    for shift,next_ in ((-size-1,None),(-size,0),(-size+1,1),(-1,size-1),(0,size),
                        (1,size+1),(MAX_SIGNED,size+MAX_SIGNED),(MIN_SIGNED,None)):
        seek(data,END,MAX,shift,next_)
    for p,shift,next_ in ((0,-1,None),(1,-1,0),(0,0,0),(MAX,0,MAX),(MAX,1,None),
                          (MAX,-1,MAX-1),(MAX-1,1,MAX),(MAX-1,2,None),
                          (MAX_SIGNED,MIN_SIGNED,None),(1<<63,MIN_SIGNED,0),
                          (MAX,MIN_SIGNED,MAX_SIGNED),(0,MAX_SIGNED,MAX_SIGNED),
                          (1<<63,MAX_SIGNED,MAX),(1+(1<<63),MAX_SIGNED,None)):
        seek(data,CURRENT,p,shift,next_)
    for p,w,v in ((0,1,(0,0,1,1)),(0,0,(0,0,0,0)),(9,0,(0,0,0,9)),
                  (CHUNK-1,7,(0,CHUNK-1,1,CHUNK)),
                  (CHUNK,7,(1,0,7,CHUNK+7)),(CHUNK+1,MAX,(1,1,12,size)),
                  (size-1,1,(1,12,1,size)),(size,1,(0,0,0,size)),
                  (size+1,1,(0,0,0,size+1)),(MAX,MAX,(0,0,0,MAX))):
        read(data,p,w,v)
    tiny=wire(b"a",3,MAX_CHUNK)
    read(tiny,1,MAX,(0,1,2,3))
    read(tiny,2,0,(0,0,0,2))
    read(tiny,3,MAX,(0,0,0,3))
    full=wire(b"A"*64,MAX_CELL,MAX_CHUNK,opaque=True)
    read(full,MAX_CELL-1,MAX,(16383,MAX_CHUNK-1,1,MAX_CELL))
    read(full,MAX_CELL-MAX_CHUNK,MAX,(16383,0,MAX_CHUNK,MAX_CELL))
    read(full,MAX_CELL,1,(0,0,0,MAX_CELL))
    seek(full,END,MAX,-MAX_CELL,0)
    seek(full,END,0,MAX_SIGNED,MAX_SIGNED+MAX_CELL)
    near=wire(b"A"*64,MAX_CELL-1,MAX_CHUNK)
    read(near,MAX_CELL-2,2,(16383,MAX_CHUNK-2,1,MAX_CELL-1))
    # Invalid TCM1 still fails before extrapolating any numeric result.
    out.extend((request(raw,CURRENT,MAX,1),code,b"") for raw,code in manifest_cases() if code)
    return out


class DaCellCachePayloadCursor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules={k:cls.enterClassContext(NativeModule(SOURCE,backend=k,byte_exports=("f0",)))
                     for k in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.modules.values()})!=2:
            raise ValueError("Distinct stock binaries required")

    def invoke(self,m,data,expected,value=b"",*,size=None):
        n=len(value)+5 if size is None else size
        out,work=MARK*n,SCRATCH*9
        observed=m.call("f0",[data,out,work]).require_returned()
        self.assertEqual((observed.abi_status,observed.value),(0,expected))
        self.assertEqual(observed.arguments,[data,value+out[len(value):],work])

    def test_locked_original_seek_and_one_chunk_plan(self):
        rows=cases()
        stream=b"".join(struct.pack("<I",len(data))+data for data,_,_ in rows)
        with tempfile.TemporaryDirectory(prefix="trnm-cache-cursor-rust-") as d:
            raw,proof=original(Path(d),stream)
        self.assertEqual(len(proof),64)
        at=0
        for index,(data,expected,value) in enumerate(rows):
            self.assertEqual(raw[at],expected,index)
            at+=1
            self.assertEqual(raw[at:at+len(value)],value,index)
            verified=raw[at:at+len(value)]
            at+=len(value)
            for k,m in self.modules.items():
                with self.subTest(i=index,emit=k):
                    self.invoke(m,data,expected,verified)
        self.assertEqual(at,len(raw))

    def test_atomic_capacity_and_eof_after_seek(self):
        good=wire(opaque=True)
        cap=request(good,READ,CHUNK,0)
        upper=request(good,CURRENT,MAX,1)
        too_long=request(good,START,0,1)
        too_long+=bytes(MAX_MANIFEST-len(too_long))
        for m in self.modules.values():
            self.invoke(m,b"\0"*16,100,size=0)
            self.invoke(m,request(good,4,0,0),100,size=0)
            self.invoke(m,too_long,7,size=0)
            self.invoke(m,upper,246,size=0)
            self.invoke(m,cap,102,size=31)
            self.invoke(m,request(good,START,7,MAX),102,size=7)
            self.invoke(m,request(good,START,7,MAX),0,expect_seek(MAX),size=8)
            self.invoke(m,request(good,READ,MAX,2),0,expect_read(0,0,0,MAX),size=32)
