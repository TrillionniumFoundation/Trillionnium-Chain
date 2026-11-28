"""Pack the strict named handoff behind the unchanged private sealed fd0 adapter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

from hia.platform.build import inspect_executable, sha256
from hia.platform.integer_model_handoff import build as handoff
from hia.platform.worker_audit_sealed_query import build as prior
from hia.platform.worker_audit_sealed_query_lines.build import bounded, single
from hia.platform.worker_audit.build import fresh_directory
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

EMITTER = Path(__file__).with_name("emitter.hepta")
ELF = "sealed-integer-model-handoff.elf"
ADAPTER = prior.ADAPTER_END
PREFIX = ADAPTER + 96
TEXT_N = handoff.THUNK + sum(row[2] for row in handoff.PROGRAMS)
IMAGE_N = PREFIX + TEXT_N
STOCK_SHA = "71d44e6c5f6363c52e14e252be934aa1c777ed7b582a52eefdc7a3f67048e701"
STOCK_SO = "bca0d0f3e64ff96b5416b3cba36cbb020a50ed6d6d798f9242fa6a87e28da9d8"


def thunk():
    # SysV entry from the fixed descriptor adapter. Save output pointer in
    # callee-saved rbx and keep call stack aligned. Do not change input or
    # scratch pointers. Pass exact existing fixed model output/scratch sizes.
    code=bytearray.fromhex("53 48 89 d3")
    code+=b"\xb9"+struct.pack("<I",handoff.BODY)
    code+=b"\x41\xb9"+struct.pack("<I",handoff.WORK)
    code+=b"\xe8"+struct.pack("<i",PREFIX-(ADAPTER+len(code)+5))
    code+=bytes.fromhex("48 85 c0")  # Test the complete packed u64 status.
    rejects=[]
    alternatives=[]
    def jcc(op,target):
        code.append(op); target.append(len(code)); code.append(0)
    jcc(0x75,rejects)
    # Six success bytes are already checked by im_decode_at. Read only the
    # admitted output prefix, never input metadata or unconstrained extents.
    code+=bytes.fromhex("81 7b 20")+b"ILM2"
    jcc(0x75,alternatives)
    code+=bytes.fromhex("66 83 7b 24 02")
    jcc(0x75,rejects)
    code+=b"\xb8"+struct.pack("<I",handoff.BODY-2)+b"\x5b\xc3"
    modern=len(code)
    code+=bytes.fromhex("81 7b 20")+b"ILM3"
    jcc(0x75,rejects)
    code+=bytes.fromhex("66 83 7b 24 03")
    jcc(0x75,rejects)
    code+=b"\xb8"+struct.pack("<I",handoff.BODY)+b"\x5b\xc3"
    refuse=len(code)
    code+=bytes.fromhex("31 c0 5b c3")
    for at,destination in [(i,modern) for i in alternatives]+[(i,refuse) for i in rejects]:
        struct.pack_into("<b",code,at,destination-at-1)
    if len(code)>PREFIX-ADAPTER:
        raise ValueError("Changed fixed adapter thunk extent")
    return bytes(code).ljust(PREFIX-ADAPTER,b"\x90")


def projection():
    src=prior.EMITTER.read_text()
    def fn(name):
        [part]=re.findall(r"^fn "+name+r"\(.*?^end\n",src,re.M|re.S)
        return part
    f0=fn("f0")
    for key,old,new in (
        ("pinned_n:usize",prior.IMAGE_N-prior.THUNK_END,TEXT_N),
        ("required:usize",prior.IMAGE_N,IMAGE_N),("image_n:u32",prior.IMAGE_N,IMAGE_N),
        ("stop:usize",prior.THUNK_END,PREFIX),("to_prefix:usize",prior.THUNK_END,PREFIX),
    ):
        f0=single(f0,f'{key} = const() {{"value":{old}}}',f'{key} = const() {{"value":{new}}}')
    old_ctors="".join(f'  _thunk_{i}:u64 = call(out) {{"function":"query_thunk_{i}"}}\n' for i in range(4))
    f0=single(f0,old_ctors,'  _model:u64 = call(out) {"function":"model_thunk"}\n')
    header=fn("elf_header")
    for pos in (96,104):
        header=single(header,f'word_{pos}:u64 = const() {{"value":{prior.IMAGE_N}}}',
                      f'word_{pos}:u64 = const() {{"value":{IMAGE_N}}}')
    lines=['fn model_thunk(out:mutbuf) -> (u64) effects(read,write,trap) entry(entry)','block entry(out:mutbuf)']
    payload=thunk()
    for i in range(0,len(payload),8):
        pos=ADAPTER+i
        word=int.from_bytes(payload[i:i+8],"little")
        lines+= [f'  at_{pos}:u64 = const() {{"value":{pos}}}',
                 f'  word_{pos}:u64 = const() {{"value":{word}}}',
                 f'  _store_{pos}:u64 = call(out,at_{pos},word_{pos}) {{"function":"put_le64"}}']
    lines+=['  zero:u64 = const() {"value":0}','  ret(zero)','end','']
    return ("hia-asm.v1 hepta.hia.program.v8 trnm_integer_model_sealed_descriptor_v1\n"
            +f0+"\n"+header+"\n"+"\n".join(lines)).encode()


def build(output):
    bounded(output.parent)
    out=fresh_directory(output)
    if EMITTER.read_bytes()!=projection():
        raise ValueError("Changed exact HIA descriptor emitter")
    tested=checked_source(EMITTER)[-1]
    shared,old=handoff.build(out/"original-named")
    raw=(shared.parent/"linked.raw").read_bytes()
    if (old["artifact_sha256"],old["linked_machine_text_sha256"],len(raw),sha256(raw))!=(
            STOCK_SO,STOCK_SHA,TEXT_N,STOCK_SHA):
        raise ValueError("Changed exact original handoff text or ABI")
    bounded(out)
    target=out/"emitter.so"
    compiler=os.environ["HIA_NATIVE_COMPILER_SHA256"]
    if compiler!=old["stock_object_receipts"]["imp1"]["compiler_sha256"]:
        raise ValueError("Compiler identity differs from native linked text")
    receipt,_=build_native(EMITTER,target,backend="selfhost",kind="shared",byte_exports=("f0",),
                compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=compiler)
    if receipt["claims"].get("fallback_used") or sha256(target.read_bytes())!=receipt["artifact_sha256"]:
        raise ValueError("Unqualified HIA emitter")
    py=single(prior._EMIT,"buffer.read(293544)",f"buffer.read({TEXT_N+1})")
    def emit(payload,cap):
        return subprocess.run([sys.executable,"-B","-c",py,str(target),str(cap)],
                              input=payload,capture_output=True,env={"PATH":""},timeout=20)
    for payload,cap in ((raw[:-1],IMAGE_N),(raw+b"x",IMAGE_N),(raw,IMAGE_N-1)):
        r=emit(payload,cap)
        if (r.returncode,r.stdout,r.stderr)!=(21,b"",b""):
            raise ValueError("Bad image geometry modified the output")
    result=emit(raw,IMAGE_N)
    image=result.stdout
    if (result.returncode or result.stderr or len(image)!=IMAGE_N
            or sha256(image[176:ADAPTER])!=prior.ADAPTER_SHA256
            or image[ADAPTER:PREFIX]!=thunk() or image[PREFIX:]!=raw
            or any(p.read_bytes()!=data for p,data in tested)):
        raise ValueError("Changed exact read adapter, model thunk, handoff or source")
    elf=inspect_executable(image)
    (out/ELF).write_bytes(image)
    proof={"status":"PASS","elf":{**elf,"sha256":sha256(image),"size":len(image)},
           "backend":"selfhost-only","stock_named_sha256":STOCK_SO,"stock_handoff_text_sha256":STOCK_SHA,
           "stock_handoff_text_bytes":TEXT_N,"stock_native_receipt":old,"emit_receipt":receipt,
           "thunk_sha256":sha256(thunk()),"existing_adapter_sha256":prior.ADAPTER_SHA256,
           "physical_max":prior.RAW_MAX,"scratch_bytes":handoff.WORK,"memory_abi_changed":False,
           "production_dispatch":False,"direct_named_qualified":False,"emitter_refusals":3}
    (out/"build.json").write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    return image,proof
