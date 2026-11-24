"""Build a separate private sealed WER2 query fixture, preserving the WQS1 wire."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

from hia.platform.bench.main_build import exact_native_text
from hia.platform.build import inspect_executable, sha256
from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_audit_sealed_query import build as prior
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

HERE = Path(__file__).resolve().parent
EMITTER = HERE/"emitter.hepta"
WER2 = HIA_ROOT/"src/worker_agent/audit_export_row_lines_v2.hepta"
ELF_NAME = "sealed-worker-task-query-lines.elf"
RAW_MAX = prior.RAW_MAX
ROW_TEXT = 84748
ROW_SHA = "99a2e83ac61ccc91202947488baeb7223adf5944bbed5b327a1d192d52beddfb"
OLD_ELF_SHA = "86fe45bdb66593c4a1587e2accd66e53a35d8bfeb4658d0ed70dd841d8ed3989"
DELTA = ROW_TEXT-prior.PROGRAMS["wer"][1]
IMAGE_N = prior.IMAGE_N+DELTA
BASE = 0x400000
# These are offsets of the disassembled WID/WTQ call instructions, not
# searched byte patterns. The WER call stays at 0x461 -> 0x518.
CALLS = (("wid", "query_thunk_1", 0x410, 1040), ("wtq", "query_thunk_3", 0x4fb, 1272))
ELF_SLOTS = (96,104)  # RX PT_LOAD filesz, memsz; runtime anonymous map is unchanged.


def bounded(path):
    prior.guard_space(path)
    stat = os.statvfs("/tmp")
    if stat.f_bavail * stat.f_frsize < 25*1024*1024:
        raise RuntimeError("Stop before the 25 MiB /tmp floor")


def single(text, old, new):
    if text.count(old)!=1:
        raise ValueError("Changed exact WQS1 projector anchor: "+old)
    return text.replace(old,new)


def projection():
    """Exact four-function projection of the tracked WQS1 HIA emitter."""
    source = prior.EMITTER.read_text()

    def fn(name):
        selected = re.findall(r"^fn "+name+r"\(.*?^end\n",source,re.MULTILINE|re.DOTALL)
        if len(selected)!=1:
            raise ValueError("Missing exact earlier emitter function: "+name)
        return selected[0]

    entry = single(fn("f0"),f'pinned_n:usize = const() {{"value":{prior.IMAGE_N-prior.THUNK_END}}}',
                   f'pinned_n:usize = const() {{"value":{IMAGE_N-prior.THUNK_END}}}')
    for token in ("required:usize","image_n:u32"):
        entry = single(entry,f'{token} = const() {{"value":{prior.IMAGE_N}}}',
                       f'{token} = const() {{"value":{IMAGE_N}}}')
    header = fn("elf_header")
    for slot in ELF_SLOTS:
        header = single(header,f'word_{slot}:u64 = const() {{"value":{prior.IMAGE_N}}}',
                        f'word_{slot}:u64 = const() {{"value":{IMAGE_N}}}')
    older = prior.THUNK_END + prior.PROGRAMS["wer"][1]
    old_targets = {"wid":older,"wtq":older+prior.PROGRAMS["wid"][1]}
    edited = []
    for role,name,call,word_at in CALLS:
        block = fn(name)
        [line] = re.findall(r'^  bytes_'+str(word_at)+r':u64 = const\(\) \{"value":(\d+)\}$',block,re.MULTILINE)
        old_value = int(line)
        encoded = bytearray(old_value.to_bytes(8,"little"))
        offset = call-word_at
        if encoded[offset] != 0xE8 or call+5+struct.unpack_from("<i",encoded,offset+1)[0] != old_targets[role]:
            raise ValueError("Earlier thunk constant does not resolve to the strict old entry")
        struct.pack_into("<i",encoded,offset+1,old_targets[role]+DELTA-(call+5))
        edited.append(single(block,f'bytes_{word_at}:u64 = const() {{"value":{old_value}}}',
                            f'bytes_{word_at}:u64 = const() {{"value":{int.from_bytes(encoded,"little")}}}'))
    return ("hia-asm.v1 hepta.hia.program.v8 trnm_worker_sealed_task_query_lines_v2\n"
            +"\n".join((entry,header,*edited))).encode()


def expected_prefix(old_image, layout):
    """Independent byte-level readback of the exact legal changes to WQS1."""
    if len(old_image)!=prior.IMAGE_N or sha256(old_image)!=OLD_ELF_SHA:
        raise ValueError("Earlier static image changed")
    expected=bytearray(old_image[:prior.THUNK_END])
    for slot in ELF_SLOTS:
        if struct.unpack_from("<Q",expected,slot)[0]!=prior.IMAGE_N:
            raise ValueError("Earlier ELF image extent changed")
        struct.pack_into("<Q",expected,slot,IMAGE_N)
    for role,_,site,_ in CALLS:
        if expected[site]!=0xE8 or struct.unpack_from("<i",expected,site+1)[0]+site+5!=layout[role]["at"]-DELTA:
            raise ValueError("Earlier call target changed")
        struct.pack_into("<i",expected,site+1,layout[role]["at"]-site-5)
    if prior.THUNK_END != layout["wer"]["at"] or expected[0x461]!=0xE8 or (
            struct.unpack_from("<i",expected,0x462)[0]+0x466!=layout["wer"]["at"]):
        raise ValueError("Earlier row-call address changed")
    return bytes(expected)


def build(output):
    bounded(output.parent)
    output=fresh_directory(output)
    captured = {Path(__file__).resolve():sha256(Path(__file__).read_bytes()),
                prior.EMITTER:sha256(prior.EMITTER.read_bytes()),Path(prior.__file__):sha256(Path(prior.__file__).read_bytes())}
    if EMITTER.read_bytes()!=projection():
        raise ValueError("Tracked HIA projection changed outside seven static constants")
    for path in (WER2,EMITTER):
        captured.update((p,sha256(b)) for p,b in checked_source(path)[-1])
    old_image,old=prior.build(output/"old-wqs1")
    compiler=old["compiler_sha256"]

    def compile(path,file,kind):
        from hepta.hia_agent_assembly import render_assembly

        bounded(output)
        dest=output/file
        r, d=build_native(path,dest,kind=kind,backend="selfhost",byte_exports=("f0",),
                          compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=compiler)
        binary=dest.read_bytes()
        wire=render_assembly({**d,"module":"selfhost_elf"}).encode()
        if (r["claims"].get("fallback_used") or r["compiler_wire_sha256"]!=sha256(wire)
                or r["artifact_sha256"]!=sha256(binary)):
            raise ValueError("Expected exact pinned compiler wire and native binary")
        dest.with_suffix(".compiler-input.hepta").write_bytes(wire)
        return binary,r

    raw,wer2=compile(WER2,"wer2.o","object")
    row=exact_native_text(raw)
    if (len(row),sha256(row))!=(ROW_TEXT,ROW_SHA):
        raise ValueError("WER2 strict .text is not the approved image")
    bodies={"wer":row}
    for name in ("wid","wtq"):
        body=exact_native_text((output/"old-wqs1"/(name+".o")).read_bytes())
        if (len(body),sha256(body))!=(old["kernel_text"][name]["bytes"],old["kernel_text"][name]["sha256"]):
            raise ValueError("Old checked kernel text changed")
        bodies[name]=body
    layout={}
    cursor=prior.THUNK_END
    for name,body in bodies.items():
        layout[name]={"at":cursor,"bytes":len(body),"sha256":sha256(body),"imports":[],"relocations":False}
        cursor+=len(body)
    if cursor!=IMAGE_N:
        raise ValueError("Changed resolved image extent")
    prefix=expected_prefix(old_image,layout)
    _,emitter=compile(EMITTER,"emitter.so","shared")
    payload=b"".join(bodies.values())
    emit_adapter=single(prior._EMIT,"buffer.read(293544)",f"buffer.read({len(payload)+1})")

    def emit(src,cap):
        return subprocess.run([sys.executable,"-B","-c",emit_adapter,str(output/"emitter.so"),str(cap)],
                              input=src,capture_output=True,env={"PATH":""},timeout=20)

    for src,cap in ((payload[:-1],IMAGE_N),(payload+b"x",IMAGE_N),(payload,IMAGE_N-1)):
        got=emit(src,cap)
        if (got.returncode,got.stdout,got.stderr)!=(21,b"",b""):
            raise ValueError("Projected HIA emitter does not refuse wrong geometry atomically")
    result=emit(payload,IMAGE_N)
    image=result.stdout
    if (result.returncode or result.stderr or len(image)!=IMAGE_N or image[:prior.THUNK_END]!=prefix
            or image[prior.THUNK_END:]!=payload or any(sha256(p.read_bytes())!=v for p,v in captured.items())):
        raise ValueError("Changed fixed HIA image layout, retained machine instructions or source")
    elf=inspect_executable(image)
    (output/ELF_NAME).write_bytes(image)
    receipt={"schema":"trnm.hia.worker-sealed-task-query-lines.fixture.v1","backend":"selfhost",
             "direct_named_qualified":False,"compiler_sha256":compiler,
             "elf":{**elf,"sha256":sha256(image),"bytes":IMAGE_N},"old_elf_sha256":OLD_ELF_SHA,
             "earlier_fd_adapter":old["earlier_fd_adapter"],"caps":old["caps"],"input_magic":"WQS1",
             "kernel_text":layout,"raw_wer2":wer2,"emitter":emitter,
             "elf_size_fields":list(ELF_SLOTS),"rel32_call_fields":[site+1 for _,_,site,_ in CALLS],
             "emitter_refusal_controls":3,"production_dispatch":False,
             "pins":{str(p.relative_to(HIA_ROOT)):v for p,v in sorted(captured.items())}}
    (output/"build.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    return image,receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    _,r=build(args.output.absolute())
    print(json.dumps({"artifact":ELF_NAME,"elf":r["elf"],"backend":r["backend"],
                      "installed":False},sort_keys=True))


if __name__ == "__main__":
    main()
