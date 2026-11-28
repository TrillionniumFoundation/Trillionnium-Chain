"""Same immutable TCM1-selected held bytes against the frozen arithmetic and hash."""
from functools import lru_cache
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.cache_payload_held_original import original
from hia.tests.cache_payload_held_plan import SOURCE, plan
from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import CHUNK, MARK, MAX_MANIFEST, SCRATCH, WORK, change, wire
from hia.tests.test_da_cell_cache_payload_cursor import MAX

PREFIX=16
ABSENT=247
LENGTH=248
CAP=MAX_MANIFEST


def data(n):
    ring=bytes(range(251))
    return (ring*((n+250)//251))[:n]


def canonical(chunks, *, size=None, width=CHUNK, family=b"held_fixture"):
    if size is None:
        size=sum(map(len,chunks))
    raw=wire(family,size,width)
    first=213+len(family)
    assert len(raw)==first+36*len(chunks)
    for i,c in enumerate(chunks):
        raw=change(raw,first+36*i+4,hashlib.sha256(c).digest())
    return raw


def request(manifest,chunk,pos,want):
    return struct.pack("<QQI",pos,want,len(manifest))+manifest+chunk


def copied(pos,value):
    return struct.pack("<QQ",pos+len(value),len(value))+value


@lru_cache(maxsize=1)
def cases():
    tiny=b"abcdefgh"
    small=canonical([tiny])
    first=data(CHUNK)
    tail=b"Second-row."
    m=canonical([first,tail])
    wrong_short=canonical([b"abc"],size=len(tiny))
    wrong_long=canonical([tiny+b"!"],size=len(tiny))
    p=canonical([b""],size=len(tiny))
    out=[]
    def add(manifest,payload,pos,want,code,value=b""):
        out.append((request(manifest,payload,pos,want),code,copied(pos,value) if code==0 else b""))
    add(small,tiny,0,MAX,0,tiny)
    add(small,tiny,1,3,0,tiny[1:4])
    add(small,tiny,len(tiny)-1,2,0,tiny[-1:])
    add(small,b"",1,3,ABSENT)
    add(small,tiny[:-1],1,3,ABSENT)
    add(small,b"Abcdefgh",1,3,ABSENT)
    add(small,b"invalid ignored chunk",len(tiny),1,0)
    add(small,b"",len(tiny)+1,MAX,0)
    add(small,b"x",MAX,MAX,0)
    add(small,b"invalid ignored chunk",1,0,0)
    add(wrong_short,b"abc",2,4,LENGTH)
    add(wrong_short,b"abx",2,4,ABSENT)
    add(wrong_long,tiny+b"!",2,4,LENGTH)
    add(p,b"",0,1,ABSENT)
    add(m,first,CHUNK-3,25,0,first[-3:])
    add(m,tail,CHUNK-3,1,ABSENT)
    add(m,tail,CHUNK,5,0,tail[:5])
    add(m,first,CHUNK,2,ABSENT)
    add(m,tail,CHUNK+3,MAX,0,tail[3:])
    add(m,tail,CHUNK+len(tail)-1,1,0,tail[-1:])
    add(m,b"",CHUNK+len(tail),MAX,0)
    full=canonical([data(1)],width=CAP,family=b"a")
    bytes_=data(CAP-20-len(full))
    full=canonical([bytes_],width=CAP,family=b"a")
    assert len(request(full,bytes_,0,MAX))==CAP
    add(full,bytes_,0,MAX,0,bytes_)
    add(full,bytes_,len(bytes_)-7,MAX,0,bytes_[-7:])
    add(full,bytes_[:-1]+b"Z",len(bytes_)-7,MAX,ABSENT)
    for size in (1,2,55,56,63,64,65,511,512,513):
        sample=data(size)
        add(canonical([sample]),sample,size//2,MAX,0,sample[size//2:])
    return out


def rust_cases():
    stream=b"".join(struct.pack("<I",len(w))+w for w,_,_ in cases())
    with tempfile.TemporaryDirectory(prefix="trnm-held-chunk-rust-") as tmp:
        return original(Path(tmp),stream)


class DaCellCachePayloadHeldRead(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.read_bytes().endswith(plan()):
            raise ValueError("Held read must use the exact checked cursor plan")
        cls.modules={k:cls.enterClassContext(NativeModule(SOURCE,backend=k,byte_exports=("f0",)))
                     for k in ("direct","selfhost")}
        if len({e.artifact_sha256 for e in cls.modules.values()})!=2:
            raise ValueError("Two distinct stock owners required")

    def invoke(self,m,frame,code,value=b"",*,n=None,w=WORK+7,clean=False):
        out=MARK*(len(value)+5 if n is None else n)
        scratch=SCRATCH*w
        got=m.call("f0",[frame,out,scratch],timeout=45).require_returned()
        self.assertEqual((got.abi_status,got.value),(0,code))
        self.assertEqual(got.arguments[:2],[frame,value+out[len(value):]])
        self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])
        if clean:
            self.assertEqual(got.arguments[2],scratch)

    def test_locked_original_selected_digest_length_and_one_chunk_copy(self):
        raw,proof=rust_cases()
        self.assertEqual(len(proof),64)
        at=0
        for j,(frame,code,value) in enumerate(cases()):
            self.assertEqual(raw[at],code,j)
            at+=1
            seen=raw[at:at+len(value)]
            self.assertEqual(seen,value,j)
            at+=len(value)
            for k,m in self.modules.items():
                with self.subTest(i=j,stock=k):
                    self.invoke(m,frame,code,seen)
        self.assertEqual(at,len(raw))

    def test_atomic_read_precedence_and_unexamined_eof_chunk(self):
        tiny=b"abcdefgh"
        m=canonical([tiny])
        for abi in self.modules.values():
            self.invoke(abi,request(m,tiny,1,4),102,n=19)
            self.invoke(abi,request(m,tiny,1,4),102,n=20,w=WORK-1,clean=True)
            self.invoke(abi,request(m,tiny,1,4),0,copied(1,b"bcde"),n=20,w=WORK)
            self.invoke(abi,request(m,b"x",1,4),ABSENT,n=0)
            self.invoke(abi,request(m,b"x",MAX,1),0,copied(MAX,b""),n=16,w=0,clean=True)
            self.invoke(abi,request(m,b"x",2,0),102,n=15,w=0,clean=True)
            self.invoke(abi,request(m,b"",2,1),ABSENT,n=0,w=0,clean=True)
            self.invoke(abi,request(canonical([b"x"],size=8),b"x",2,4),LENGTH,n=0)
            self.invoke(abi,request(m+b"x",tiny,MAX,0),7,n=0,w=0,clean=True)
            self.invoke(abi,struct.pack("<QQI",0,0,100),100,n=0,w=0,clean=True)
