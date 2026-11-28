"""Private windowed held-row qualification: synthetic bytes, no descriptors."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from hia.tests.cache_payload_held_original import original
from hia.tests.native_support import NativeModule
from hia.tests.test_da_cell_cache_payload_held_read import (
    ABSENT, CAP, LENGTH, MAX, canonical, copied, data, request,
)
from hia.tools.toolchain import HIA_ROOT

SOURCE = HIA_ROOT/"src/data_availability/cell_cache_payload_windowed.hepta"
WINDOW = 65536
CHUNK = 4194304

# Scoped test child owns the three loans while calling each native phase.
# Only the input window is overwritten between successful calls.
MEMORY_PROBE = """
import ctypes as c
import fcntl
import hashlib
import os
import struct
import sys
library, identity = sys.argv[1:]
binary = open(library,'rb').read()
if hashlib.sha256(binary).hexdigest()!=identity:
    raise ValueError("Wrong held native ELF")
image=os.memfd_create("private-windowed-memory-fixture",os.MFD_ALLOW_SEALING)
with os.fdopen(os.dup(image),'wb') as held:
    held.write(binary)
fcntl.fcntl(image,getattr(fcntl,'F_ADD_SEALS',1033),15)
entry=c.CDLL(f"/proc/self/fd/{image}").f0
os.close(image)
entry.argtypes=[c.c_void_p,c.c_size_t]*3
entry.restype=c.c_uint64
source=c.create_string_buffer(65544+7)
out=c.create_string_buffer(65552+9)
work=c.create_string_buffer(69632+11)
stream=sys.stdin.buffer
sink=sys.stdout.buffer
def invoke(msg,expected_code,publish=False,out_capacity=65552):
    c.memset(source,0xB1,len(source))
    c.memmove(source,msg,len(msg))
    stat=entry(source,len(msg),out,out_capacity,work,69632)
    assert stat==expected_code, (stat,expected_code,msg[:8].hex())
    assert source.raw==msg+b"\\xb1"*(len(source)-len(msg))
    assert work.raw[69632:]==b"\\xc3"*11
    if not publish:
        assert out.raw==b"\\xa5"*len(out)
    return stat
while hdr:=stream.read(20):
    ini_n,row_n,want_status,want_n,mode=struct.unpack("<5I",hdr)
    initial=stream.read(ini_n)
    c.memset(out,0xA5,len(out))
    c.memset(work,0,len(work))
    c.memset(c.addressof(work)+69632,0xC3,11)
    invoke(initial,102 if mode==3 else 0)
    if mode==3:
        assert row_n==0 and want_n==0
        sink.write(struct.pack("<II",102,0));continue
    if mode==1:
        invoke(initial,100)
    left=row_n
    while left:
        n=min(left,65536)
        data=stream.read(n)
        assert len(data)==n
        invoke(struct.pack("<Q",1)+data,0)
        left-=n
    if mode==2:
        invoke(struct.pack("<Q",1)+b"x",100)
    final=struct.pack("<Q",2)
    invoke(final,want_status,want_status==0)
    good=out.raw[:want_n]
    assert out.raw[want_n:]==b"\\xa5"*(len(out)-want_n)
    sink.write(struct.pack("<II",want_status,want_n)+good)
    c.memset(out,0xA5,len(out))
    invoke(final,100)
"""

class DaCellCachePayloadWindowed(unittest.TestCase):
    def test_locked_original_digest_width_publication_and_both_windowed_stocks(self):
        full=data(CHUNK)
        valid=canonical([full],width=CHUNK)
        # Exercise a 64 KiB output straddling input windows, and a tail.
        offset=WINDOW-1
        panel=[
            (valid,full,offset,WINDOW,0,copied(offset,full[offset:offset+WINDOW]),1),
            (valid,full,CHUNK-7,MAX,0,copied(CHUNK-7,full[-7:]),2),
            (valid,full[:-1]+bytes([full[-1]^1]),offset,37,ABSENT,b"",0),
            (canonical([full[:-1]],size=CHUNK,width=CHUNK),full[:-1],10,19,LENGTH,b"",0),
            (valid,full[:-1],10,19,ABSENT,b"",0),
            (valid,b"",10,1,ABSENT,b"",0),
            (valid,b"",0,0,0,copied(0,b""),0),
            (valid,b"",CHUNK,3,0,copied(CHUNK,b""),0),
        ]
        old=[request(m,raw,pos,want) for m,raw,pos,want,_,_,_ in panel]
        original_stream=b"".join(struct.pack("<I",len(x))+x for x in old)
        with tempfile.TemporaryDirectory(prefix="trnm-windowed-cache-original-") as tmp:
            locked,proof=original(Path(tmp),original_stream)
        self.assertEqual(len(proof),64)
        caps=panel+[(valid,b"",0,WINDOW+1,102,b"",3)]
        chunks=[]
        for m,raw,pos,want,code,body,mode in caps:
            init=struct.pack("<Q",0)+request(m,b"",pos,want)
            chunks.extend((struct.pack("<5I",len(init),len(raw),code,len(body),mode),init,raw))
        stimulus=b"".join(chunks)
        expected=b"".join(struct.pack("<II",code,len(body))+body for _,_,_,_,code,body,_ in caps)
        self.assertEqual(locked,b"".join(bytes([code])+body for _,_,_,_,code,body,_ in panel))
        ids=[]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,backend=backend,byte_exports=("f0",)) as native:
                ids.append(native.artifact_sha256)
                cmd=[sys.executable,"-I","-S","-B","-c",MEMORY_PROBE,
                     str(native.library),native.artifact_sha256]
                seen=subprocess.run(cmd,input=stimulus,capture_output=True,timeout=150,check=False)
                self.assertEqual((seen.returncode,seen.stderr),(0,b""))
                self.assertEqual(seen.stdout,expected)
        self.assertEqual(len(set(ids)),2)
