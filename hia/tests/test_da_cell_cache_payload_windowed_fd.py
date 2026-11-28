"""Physical sealed stream into stock HIA; Rust private transport only."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.platform.bench.main_build import exact_native_text
from hia.tests.cache_payload_held_original import original
from hia.tests.test_da_cell_cache_payload_held_read import ABSENT, LENGTH, MAX, canonical, copied, data, request
from hia.tests.test_da_cell_cache_payload_windowed import CHUNK, SOURCE, WINDOW
from hia.tests.test_worker_audit_sealed_query import check_nonpipe_sink
from hia.tests.test_worker_journal_audit_stdin import (
    ADD_SEALS, ALL_SEALS, GET_SEALS, SEAL_WRITE, _sealed_image,
)
from hia.tools.toolchain import HIA_ROOT, build_native

CALLER = Path(__file__).with_name("rust_cell_cache_payload_windowed_fd.rs")
OBJECT = "csw_fixture.o"
STOCK = (
    "ccef58ca56831617d69736104f16cb7665a8af17ae988aaefc1a1a5550164f20",
    "4b7ae3cd39a62f5cf8ba1ba37133f6964c41b4033f1042ba9289c83a04be5dc9",
    "ba84a9aa4b297eda21737c10e743a0c065a0a7f652c31ba01b8a52df29529e2c",
    "a4217157ed3d185ac8aa253e8e07973678d741b7089f12fe27e12c763d728df0",
)


def ran(*args):
    out = subprocess.run(args,check=True,capture_output=True,timeout=45)
    return out.stdout


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def link(directory):
    if (platform.system(),platform.machine())!=("Linux","x86_64"):
        raise ValueError("The fixed physical fixture is Linux x86-64 only")
    bound = json.loads((HIA_ROOT/"qualification/compiler-binding.json").read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256")!=bound:
        raise ValueError("Exact compiler pin required")
    obj = directory/OBJECT
    receipt,_=build_native(SOURCE,obj,kind="object",backend="selfhost",byte_exports=("f0",),
                           compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=bound)
    raw = obj.read_bytes()
    text = exact_native_text(raw)
    if (digest(raw),digest(text),receipt["compiler_wire_sha256"],
            receipt["chain_migration"]["composed_source_sha256"])!=STOCK:
        raise ValueError("Unexpected stock continuation")
    if receipt["artifact_sha256"]!=STOCK[0] or receipt["claims"]["fallback_used"]:
        raise ValueError("Native artifact has no exact stock proof")
    archive = directory/"libtrnm_cache_windowed_fixture.a"
    ran("ar","crsD",archive,obj)
    if ran("ar","t",archive)!=OBJECT.encode()+b"\n" or ran("ar","p",archive,OBJECT)!=raw:
        raise ValueError("Fixture archive must contain the exact one member")
    compiler = os.environ.get("TRNM_HIA_RUSTC","rustc")
    channel=tomllib.loads((HIA_ROOT.parent/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if ran(compiler,"--version").decode().split()[1]!=channel:
        raise ValueError("Fixture compiler must be the repository pinned Rust")
    driver=CALLER.read_bytes()
    captured=directory/"transport.rs"
    captured.write_bytes(driver)
    executable=directory/"transport"
    ran(compiler,"--edition=2021",captured,"-L",f"native={directory}",
        "-l","static=trnm_cache_windowed_fixture","-C","link-arg=-Wl,-z,noexecstack","-o",executable)
    image=executable.read_bytes()
    [sym]=[entry for entry in ran("nm","--defined-only",executable).splitlines()
           if entry.endswith(b" T f0")]
    address=int(sym.split()[0],16)
    h=struct.unpack_from("<16sHHIQQQIHHHHHH",image)
    if h[0][:7]!=b"\x7fELF\x02\x01\x01" or h[2]!=62 or h[9]!=56:
        raise ValueError("Wrong linked or executable architecture")
    segments=[struct.unpack_from("<IIQQQQQQ",image,h[5]+56*i) for i in range(h[10])]
    sites=[offset+address-base for k,f,offset,base,_,n,_,_ in segments
           if k==1 and f==5 and base<=address and address+len(text)<=base+n]
    stacks=[f for k,f,*_ in segments if k==0x6474e551]
    if (len(sites)!=1 or image[sites[0]:sites[0]+len(text)]!=text or stacks!=[6]
            or driver!=CALLER.read_bytes() or raw!=obj.read_bytes()):
        raise ValueError("Linked image/code/stack or captured source differs")
    return image


def observed(image,payload,*,seals=ALL_SEALS,offset=0):
    fd=os.memfd_create("fixed-private-cache-windowed-input",os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd),"wb") as source:
            source.write(payload)
        if seals:
            fcntl.fcntl(fd,ADD_SEALS,seals)
        fcntl_expected=fcntl.fcntl(fd,GET_SEALS)
        if fcntl_expected!=seals or os.lseek(fd,offset,os.SEEK_SET)!=offset:
            raise AssertionError("Wrong before state")
        before=os.fstat(fd)
        with _sealed_image(image) as exe:
            child=subprocess.run([f"/proc/self/fd/{exe}"],stdin=fd,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,pass_fds=(exe,),env={},close_fds=True,
                         timeout=30,check=False)
        at=os.lseek(fd,0,os.SEEK_CUR)
        after=os.fstat(fd)
        actual=os.pread(fd,len(payload)+1,0)
        if (actual!=payload or fcntl.fcntl(fd,GET_SEALS)!=seals or before.st_size!=len(payload)
                or (before.st_ino,before.st_dev,before.st_size)!=(after.st_ino,after.st_dev,after.st_size)
                or os.lseek(fd,0,os.SEEK_CUR)!=at or child.stderr or len(child.stdout)>WINDOW+16):
            raise AssertionError("Changed exact held input or output cap")
        return child,actual,at
    finally:
        os.close(fd)


class DaCellCachePayloadWindowedFd(unittest.TestCase):
    def test_original_locked_same_sealed_stream_via_linked_stock_owner(self):
        full=data(CHUNK)
        pos=WINDOW-1
        m=canonical([full],width=CHUNK)
        def entry(manifest,raw,p,w,s,value=b""):
            return request(manifest,raw,p,w),s,value
        panel=[
            entry(m,full,pos,WINDOW,0,copied(pos,full[pos:pos+WINDOW])),
            entry(m,full,CHUNK-7,MAX,0,copied(CHUNK-7,full[-7:])),
            entry(m,full[:-1]+bytes([full[-1]^1]),pos,32,ABSENT),
            entry(canonical([full[:-1]],size=CHUNK,width=CHUNK),full[:-1],10,19,LENGTH),
            entry(m,full[:-1],10,19,ABSENT),
            entry(m,b"",0,1,ABSENT),
            entry(m,b"",pos,0,0,copied(pos,b"")),
            entry(m,b"",CHUNK,2,0,copied(CHUNK,b"")),
        ]
        with tempfile.TemporaryDirectory(prefix="trnm-windowed-cache-fd-") as temp:
            root=Path(temp)
            image=link(root)
            raw_calls=[]
            for payload,status,value in panel:
                result,readback,at=observed(image,payload)
                self.assertEqual((result.returncode,result.stdout,at),
                                 (0 if status==0 else 74,value,len(payload)))
                raw_calls.append(struct.pack("<I",len(readback))+readback)
            path=root/"rust"
            path.mkdir()
            oracle,_=original(path,b"".join(raw_calls))
            self.assertEqual(oracle,b"".join(bytes([s])+value for _,s,value in panel))
            tiny=panel[-1][0]
            for raw,flags,initial,status,cursor in (
                (tiny,0,0,70,0),(tiny,ALL_SEALS & ~SEAL_WRITE,0,70,0),
                (tiny,ALL_SEALS,1,72,1),(b"x"*19,ALL_SEALS,0,73,0),
                (request(m,full+b"x",pos,WINDOW),ALL_SEALS,0,71,20),
                (b"x"*(CHUNK+WINDOW+1),ALL_SEALS,0,71,0),
                (tiny[:16]+struct.pack("<I",WINDOW)+tiny[20:],ALL_SEALS,0,73,20),
            ):
                result,_,at=observed(image,raw,seals=flags,offset=initial)
                self.assertEqual((result.returncode,result.stdout,at),(status,b"",cursor))
            self.assertEqual(check_nonpipe_sink(image,tiny)["status"],75)
