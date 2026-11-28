"""Emit a bounded static Linux x86-64 test carrier, never install or dispatch it."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess

from hia.platform.bench.main_build import exact_native_text
from hia.platform.build import inspect_executable
from hia.platform.integer_model_handoff.build import disassemble
from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_audit_sealed_query_lines.build import bounded
from hia.tests.native_support import NativeModule
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

EMITTER = Path(__file__).with_name("emitter.hepta")
KERNEL = HIA_ROOT/"src/data_availability/cell_cache_payload_windowed.hepta"
HEADER = 176
PREFIX = 1200
OUT = 111659
CARRIER = "519f7084c8decb2959c97ce552d979fe674dcdfeafde003a9698e26f7e33a269"
STOCK = (
    "ccef58ca56831617d69736104f16cb7665a8af17ae988aaefc1a1a5550164f20",
    "4b7ae3cd39a62f5cf8ba1ba37133f6964c41b4033f1042ba9289c83a04be5dc9",
    "ba84a9aa4b297eda21737c10e743a0c065a0a7f652c31ba01b8a52df29529e2c",
    "a4217157ed3d185ac8aa253e8e07973678d741b7089f12fe27e12c763d728df0",
)
SYSCALLS = {
    0x018:"fstat(fd0)",0x044:"fcntl(fd0,F_GET_SEALS)",0x075:"lseek(fd0,CUR)",
    0x091:"fstat(fd1)",0x0E1:"mmap(anonymous RW)",0x1B4:"read(fd0,EOF probe)",
    0x1EA:"fstat(fd0)",0x236:"fcntl(fd0,F_GET_SEALS)",0x250:"lseek(fd0,CUR)",
    0x266:"close(fd0)",0x2AB:"write(fd1)",0x2FA:"read(fd0,window)",0x383:"exit",
}
CALLS = {0x120:0x2EB,0x162:0x2EB,0x16B:0x328,0x191:0x2EB,0x19A:0x328,
         0x27E:0x328,0x340:0x400}


def sha(raw):
    return sha256(raw).hexdigest()


def static_transport(directory,image,text):
    adapter=directory/"carrier.raw"
    adapter.write_bytes(image[HEADER:PREFIX])
    rows=disassemble(adapter)
    where={i for i,_,_ in rows}
    actual={i for i,op,_ in rows if op=="syscall"}
    blocked={i for i,op,_ in rows if op in {"sysenter","int","int3"}}
    calls={i:int(dst,16) for i,op,dst in rows if op=="call"}
    branches={i:int(dst,16) for i,op,dst in rows if op.startswith("j")}
    if (actual!=set(SYSCALLS) or blocked or calls!=CALLS or not set(branches.values())<=where
            or not 0x1B4<0x266<0x27E<0x2AB):
        raise ValueError("Static syscall/branch/stock call roster differs")
    stock=directory/"stock.raw"
    stock.write_bytes(text)
    objdump=subprocess.run(["objdump","-w","-D","-b","binary","-m","i386:x86-64",stock],
                           check=True,capture_output=True,timeout=10).stdout
    if any(row.split(b"\t")[-1].strip().split(b" ",1)[0] in (b"syscall",b"sysenter",b"int")
           for row in objdump.splitlines() if b"\t" in row):
        raise ValueError("Stock text has a system call")
    (directory/"carrier-disassembly.json").write_text(json.dumps(rows)+"\n")
    return {"sites":SYSCALLS,"calls":CALLS,"stock_has_no_syscall":True}


def build(output):
    if (platform.system(),platform.machine())!=("Linux","x86_64"):
        raise ValueError("Use the fixed pinned Linux x86-64 fixture")
    bounded(output.parent)
    out=fresh_directory(output)
    pin=json.loads((HIA_ROOT/"qualification/compiler-binding.json").read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256")!=pin:
        raise ValueError("Exact stock Selfhost compiler pin required")
    fixed={p:data for part in (EMITTER,KERNEL) for p,data in checked_source(part)[-1]}
    object_=out/"stock.o"
    receipt,_=build_native(KERNEL,object_,kind="object",backend="selfhost",byte_exports=("f0",),
                           compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=pin)
    raw=object_.read_bytes()
    text=exact_native_text(raw)
    if (sha(raw),sha(text),receipt["compiler_wire_sha256"],
        receipt["chain_migration"]["composed_source_sha256"])!=STOCK or receipt["claims"]["fallback_used"]:
        raise ValueError("Wrong exact paired stock continuation")
    with NativeModule(EMITTER,backend="selfhost",byte_exports=("f0",)) as packer:
        for bad,cap in ((text[:-1],OUT),(text+b"x",OUT),(text,OUT-1)):
            args=[bad,b"Q"*cap,b"W"]
            got=packer.call("f0",args).require_returned()
            if (got.abi_status,got.value,got.arguments)!=(0,4294967294,args):
                raise ValueError("Packer changed output on geometry refusal")
        got=packer.call("f0",[text,b"Q"*(OUT+11),b"W"]).require_returned()
        image=got.arguments[1][:OUT]
        if (got.abi_status,got.value,got.arguments[0],got.arguments[1][OUT:],got.arguments[2])!=(
                0,OUT,text,b"Q"*11,b"W"):
            raise ValueError("Unexpected stock emitter result or canaries")
        packer_sha=packer.artifact_sha256
    elf=inspect_executable(image)
    if (sha(image[HEADER:PREFIX])!=CARRIER or image[PREFIX:]!=text
            or any(p.read_bytes()!=data for p,data in fixed.items())):
        raise ValueError("Exact carrier, stock execute text or captured sources changed")
    roster=static_transport(out,image,text)
    (out/"fixture.elf").write_bytes(image)
    report={"status":"PASS","elf":{**elf,"sha256":sha(image),"bytes":len(image)},
            "kernel":receipt,"carrier_sha256":CARRIER,"carrier_roster":roster,
            "packer_sha256":packer_sha,"packer_geometry_controls":3,
            "source_sha256":{str(p.relative_to(HIA_ROOT)):sha(data) for p,data in sorted(fixed.items())},
            "physical_cap":4259840,"row_cap":4194304,"window_cap":65536,
            "production_dispatch":False,"explicit_descriptor_fixture":True}
    (out/"build.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return image,report
