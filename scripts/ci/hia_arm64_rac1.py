#!/usr/bin/env python3
"""Finite LLVM ARM64 RAC1 diagnostic. No production or foreign buffer ABI."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

import hia_arm64_rac1_carrier as carrier
import hia_arm64_rac1_data as q

PIN="f33d8da316de8fdf27b504371f1a5310997ff548"
TARGET="aarch64-unknown-linux-gnu"
RUST="59807616e1fa2540724bfbac14d7976d7e4a3860"
CORE="ebe4e1c14ee3eaa213344a129548d5b956cb489a93d434a41ac34ebd4a1b82ea"
IR="b8701f5019d0bd013a22406c173d384343a7eb65118c937d3e98d41e1b46244f"
SOURCE="hia/src/release_bundle/artifact_header.hepta"
ORIGINAL="ff855d3c2a7dc18c2a386231747641c8f4b3dc2789eb677d159f03323357b881"
EXTRACTED="77226a9f3627ac01540c4495a9d0705e4f1239fbc5622b41639e1eb70f033e1c"
FILES={"original.stdout":32768,"native.request":65536,"native.stdout":120000,
       "native.o":32768,"reference.rs":8192,"driver.rs":8192}
SCHEMA="trnm-hia-arm64-rac1-diagnostic-v1"

def need(ok,why):
    if not ok: raise ValueError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def stable_json(raw):
    def unique(pairs):
        result={}
        for k,v in pairs:
            need(k not in result,"duplicate evidence key")
            result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique)

def run(argv,*,data=None,timeout=20):
    p=subprocess.run(argv,input=data,capture_output=True,check=False,timeout=timeout)
    need(p.returncode==0 and not p.stderr and len(p.stdout)<=262144,
         f"command failed: {argv[0]} rc={p.returncode} stderr={p.stderr[:1024]!r}")
    return p.stdout

def git(root,*args):
    return run(["git","-C",root,*args]).decode("ascii").strip()

def host():
    here=list(os.uname())
    need(platform.system()=="Linux" and here[0]=="Linux" and here[-1]=="aarch64"
         and platform.machine()=="aarch64" and sys.byteorder=="little"
         and ctypes.sizeof(ctypes.c_void_p)==8 and os.environ.get("RUNNER_ARCH")=="ARM64"
         and os.environ.get("RUNNER_OS")=="Linux","actual hosted AArch64 Linux LP64 required")
    return here

def binding(root,hepta,head):
    need(re.fullmatch("[a-f0-9]{40}",head) and git(root,"rev-parse","HEAD")==head,
         "candidate head mismatch")
    need(git(hepta,"rev-parse","HEAD")==PIN,"Hepta pin mismatch")
    for place in (root,hepta):
        need(not git(place,"status","--porcelain","--untracked-files=no"),"tracked source drift")
    q.source_bound(root)
    p=root/SOURCE
    need(p.is_file() and not p.is_symlink() and sha(p.read_bytes())==carrier.PIN,"RAC1 source drift")
    return git(root,"rev-parse","HEAD^{tree}")

def read(out,name,maxbytes):
    p=out/name
    need(p.is_file() and not p.is_symlink() and 0<p.stat().st_size<=maxbytes,f"bad evidence file: {name}")
    raw=p.read_bytes()
    need(0<len(raw)<=maxbytes,f"bad evidence length: {name}")
    return raw

def elf(raw,kinds):
    need(len(raw)>=64 and raw[:7]==b"\x7fELF\x02\x01\x01","not little-endian ELF64")
    typ,arch,vers=struct.unpack_from("<HHI",raw,16)
    need(typ in kinds and arch==183 and vers==1,"wrong ELF type or machine")
    return {"machine":arch,"type":typ,"bytes":len(raw),"sha256":sha(raw)}

def summarize(original):
    need(sha(original)==ORIGINAL,"genuine original stdout differs from frozen cross-check")
    inputs=q.typed_corpus()
    rows=q.oracle_parse(original,len(inputs))
    need(len(rows)==528 and sum(x is not None for x in rows)==198
         and max(len(x) for x in rows if x is not None)==208,"wrong actual original result distribution")
    cases=q.cases(inputs,rows)
    need(len(cases)==541,"bad diagnostic case count")
    return q.native_request(cases),q.native_expected(cases)

def verify(out,*,head,tree,run_id,attempt):
    p=stable_json(read(out,"report.json",16384))
    need((p["schema"],p["result"],p["head"],p["tree"],p["run"],p["attempt"])
         ==(SCHEMA,"PASS_DIAGNOSTIC_ONLY",head,tree,run_id,attempt),"wrong source/run/attempt binding")
    need(p["target"]==TARGET and p["host"][0]=="Linux" and p["host"][-1]=="aarch64"
         and p["runner_arch"]=="ARM64" and p["hepta"]==PIN and p["source"]=={**q.RUST_INPUT_DIGESTS,SOURCE:carrier.PIN}
         and p["core"]==CORE and p["ir"]==IR,"target or source mismatch")
    need(p["original_rows"]==528 and p["original_accepted"]==198 and p["original_refused"]==330
         and p["capacity_controls"]==9 and p["private_raw_controls"]==4 and p["actual_literal_rows"]==541,
         "incomplete raw control/row coverage")
    for k in ("foreign_buffer_abi","pinned_direct_or_selfhost","whole_chain_gate","production"):
        need(p[k] is False,"unexpected broader qualification")
    raw={name:read(out,name,b) for name,b in FILES.items()}
    need(p["files"]=={n:{"bytes":len(v),"sha256":sha(v)} for n,v in raw.items()},"artifact digest mismatch")
    need(elf(raw["native.o"],{1})==p["elf"]["native.o"],"object binding mismatch")
    for n in ("reference","driver"):
        need(p["elf"][n]["machine"]==183 and p["elf"][n]["type"] in {2,3},"wrong runtime ELF machine/type")
    need(raw["driver.rs"]==q.driver_source().encode() and sha(raw["reference.rs"])==EXTRACTED, "driver or extracted Rust source drift")
    need(p["compiler"]["target"]==TARGET and p["compiler"]["cross_target_compilation"] is False
         and p["compiler"]["core_sha256"]==CORE and p["compiler"]["llvm_ir_sha256"]==IR
         and p["compiler"]["artifact_sha256"]==p["elf"]["native.o"]["sha256"],"compiler receipt mismatch")
    request,expected=summarize(raw["original.stdout"])
    need(raw["native.request"]==request and raw["native.stdout"]==expected,
         "wrong original-derived request or nonidentical literal results")
    return p


def verify_archive(path,*,digest,head,tree,run_id,attempt):
    need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=262144,"invalid ZIP size")
    outer=path.read_bytes()
    need(re.fullmatch("[a-f0-9]{64}",digest) and sha(outer)==digest,"Actions ZIP SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(outer)) as zipped:
        entries=zipped.infolist()
        need(len(entries)==1 and entries[0].filename=="hia-arm64-rac1.tar"
             and 0<entries[0].file_size<=262144 and zipped.testzip() is None,"unexpected ZIP members, size or CRC")
        raw=zipped.read(entries[0])
    need(0<len(raw)<=262144,"oversized TAR")
    bounds={**FILES,"report.json":16384}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:") as ar, tempfile.TemporaryDirectory() as temp:
        members=ar.getmembers()
        need(len(members)==len(bounds) and {m.name for m in members}==set(bounds),"wrong or duplicated TAR members")
        for member in members:
            need(member.name in bounds and member.isreg() and not member.pax_headers
                 and 0<member.size<=bounds[member.name],"unsafe TAR member or size")
            f=ar.extractfile(member)
            payload=f.read(bounds[member.name]+1)
            need(len(payload)==member.size,"truncated TAR member")
            (Path(temp)/member.name).write_bytes(payload)
        return verify(Path(temp),head=head,tree=tree,run_id=run_id,attempt=attempt)

def qualify(root,hepta,out,head):
    initial_host=host()
    tree=binding(root,hepta,head)
    for env in ("CC","CFLAGS","RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","LD_PRELOAD","LD_LIBRARY_PATH"):
        need(not os.environ.get(env),f"unsupported tool override: {env}")
    real_rust=shutil.which("rustc")
    need(real_rust is not None,"missing actual pinned rustc")
    rust=Path(real_rust).resolve(strict=True)
    clang=Path("/usr/bin/clang-20").resolve(strict=True)
    cc=Path("/usr/bin/gcc").resolve(strict=True)
    ld=Path("/usr/bin/ld").resolve(strict=True)
    tools={str(v):sha(v.read_bytes()) for v in (rust,clang,cc,ld)}
    versions={str(v):run([v,"-vV" if v==rust else "--version"]).decode() for v in (rust,clang,cc,ld)}
    need(f"host: {TARGET}\n" in versions[str(rust)] and f"commit-hash: {RUST}\n" in versions[str(rust)]
         and "release: 1.95.0\n" in versions[str(rust)],"wrong rust version or host")
    sys.path[:0]=[str(hepta),str(root)]
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_llvm import emit_program_llvm,compile_program_llvm
    from hepta.object_symbols import inspect_object_symbols
    need(Path(sys.modules["hepta"].__file__).resolve().parent==hepta/"hepta","wrong Hepta module")
    oracle=importlib.import_module("hia.tests.test_release_artifact_header")
    need(Path(oracle.__file__).resolve()==root/"hia/tests/test_release_artifact_header.py","wrong original oracle")
    core=assemble_program(carrier.compose((root/SOURCE).read_bytes()))
    ir=emit_program_llvm(core,target=TARGET)
    need(core.sha256==CORE and ir.sha256==IR and ir.exports==(carrier.ENTRY,),"stock verified program drift")
    obj=out/"native.o"
    report=compile_program_llvm(ir,program=core,output=obj,kind="object",clang=str(clang))
    objraw=read(out,"native.o",FILES["native.o"])
    syms=inspect_object_symbols(objraw,"ELF64",183)
    need(syms["defined"]=={carrier.ENTRY} and syms["undefined"]<={"abort","calloc","free","memset","memcpy","memmove"},
         "unexpected scalar entry or runtime undefined symbol")
    reference=oracle.build_reference(out)
    driver_rs=out/"driver.rs"
    driver_rs.write_bytes(q.driver_source().encode())
    driver=out/"driver"
    compile_driver=[str(rust),"--edition=2021","-C","strip=symbols","-C",f"linker={cc}",
                    "-C",f"link-arg={obj}",str(driver_rs),"-o",str(driver)]
    run(compile_driver,timeout=30)
    images={f.name:elf(f.read_bytes(),{1} if f==obj else {2,3}) for f in (obj,reference,driver)}
    original=run([reference],data=q.oracle_request(q.typed_corpus()))
    request,expected=summarize(original)
    actual=run([driver],data=request)
    need(actual==expected,"actual ARM64 RAC1 bytes or atomic controls mismatch")
    need(host()==initial_host and binding(root,hepta,head)==tree,"run host/source changed")
    need(all(sha(Path(p).read_bytes())==h for p,h in tools.items()) and
         all(sha((out/p).read_bytes())==b["sha256"] for p,b in images.items()),"tool or executable drift")
    for p,v in {"original.stdout":original,"native.request":request,"native.stdout":actual}.items():
        (out/p).write_bytes(v)
    p={"schema":SCHEMA,"result":"PASS_DIAGNOSTIC_ONLY","head":head,"tree":tree,"run":os.environ["GITHUB_RUN_ID"],
       "attempt":os.environ["GITHUB_RUN_ATTEMPT"],"host":initial_host,"runner_arch":"ARM64","target":TARGET,
       "hepta":PIN,"source":{**q.RUST_INPUT_DIGESTS,SOURCE:carrier.PIN},"core":CORE,"ir":IR,"tools":tools,
       "versions":versions,"elf":images,"compiler":report,"driver_compile":compile_driver,
       "actual_native_call":[str(driver)],"actual_original_call":[str(reference)],
       "original_rows":528,"original_accepted":198,"original_refused":330,
       "capacity_controls":9,"private_raw_controls":4,"actual_literal_rows":541,
       "foreign_buffer_abi":False,"pinned_direct_or_selfhost":False,"whole_chain_gate":False,"production":False,
       "files":{n:{"bytes":len(v),"sha256":sha(v)} for n,b in FILES.items() for v in (read(out,n,b),)}}
    (out/"report.json").write_text(json.dumps(p,sort_keys=True,indent=2)+"\n")
    verify(out,head=head,tree=tree,run_id=p["run"],attempt=p["attempt"])

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="mode",required=True)
    p=sub.add_parser("collect")
    for name in ("root","hepta","out"):p.add_argument(name,type=Path)
    p.add_argument("head")
    v=sub.add_parser("verify")
    v.add_argument("out",type=Path)
    for name in ("head","tree","run_id","attempt"):v.add_argument(name)
    z=sub.add_parser("verify-archive")
    z.add_argument("zip",type=Path)
    for name in ("digest","head","tree","run_id","attempt"):z.add_argument(name)
    a=parser.parse_args()
    if a.mode=="verify-archive":
        verify_archive(a.zip, digest=a.digest, head=a.head, tree=a.tree, run_id=a.run_id, attempt=a.attempt)
        print("PASS original ZIP/TAR and retained RAC1 diagnostic readback")
    elif a.mode=="verify":
        verify(a.out.resolve(strict=True),head=a.head,tree=a.tree,run_id=a.run_id,attempt=a.attempt)
        print("PASS retained RAC1 diagnostic readback")
    else:
        out=a.out.resolve(strict=True)
        need(out.is_dir() and not any(out.iterdir()),"empty private output directory required")
        qualify(a.root.resolve(strict=True),a.hepta.resolve(strict=True),out,a.head)
