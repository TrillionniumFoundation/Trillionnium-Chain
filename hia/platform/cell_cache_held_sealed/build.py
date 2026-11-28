"""Pack the exact held cache reader behind the unchanged private sealed adapter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

from hia.platform.bench.main_build import exact_native_text
from hia.platform.build import inspect_executable, sha256
from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_audit_sealed_query import build as prior
from hia.platform.worker_audit_sealed_query_lines.build import bounded, single
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

EMITTER = Path(__file__).with_name("emitter.hepta")
KERNEL = HIA_ROOT / "src/data_availability/cell_cache_payload_held_read.hepta"
ELF = "sealed-held-cache-read.elf"
ADAPTER = prior.ADAPTER_END
PREFIX = ADAPTER + 64
KERNEL_BYTES = 102947
KERNEL_SHA = "3ddb35f1d0049581d47c92cc0acb231c096db138fae148b1dfc40113ee0709f8"
COMPOSED_SHA = "38d630cd593544f8faa04825005f3dd5a15a8f2bdc231a88df75118c1b218eb7"
WIRE_SHA = "d49433d091122d8d803ad95b7db57518399c6d9649e19c2b33b2d9928f714c9a"
ADAPTER_SOURCE_SHA = "9d16c98723e2dcbdded173a5b387dada6d24496df0b916638f3e6530eb1d4d7b"
IMAGE_N = PREFIX + KERNEL_BYTES
RAW_MAX = prior.RAW_MAX
OUT_MAX = RAW_MAX + 16
SCRATCH = 1232
FIXED = (Path(__file__).resolve(), prior.EMITTER, HIA_ROOT / "platform/build.py",
         HIA_ROOT / "platform/bench/main_build.py", HIA_ROOT / "tools/toolchain.py",
         HIA_ROOT / "toolchain.lock.json", HIA_ROOT / "qualification/compiler-binding.json")


def thunk():
    # SysV: preserve the output pointer across the native call; input extent
    # and both pointers remain unchanged. The push aligns the call stack.
    code = bytearray.fromhex("53 48 89 d3")
    code += b"\xb9" + struct.pack("<I", OUT_MAX)
    code += b"\x41\xb9" + struct.pack("<I", SCRATCH)
    code += b"\xe8" + struct.pack("<i", PREFIX-(ADAPTER+len(code)+5))
    code += bytes.fromhex("48 85 c0 75 00")  # test whole returned status
    fail_status = len(code)-1
    code += bytes.fromhex("48 8b 43 08 48 3d") + struct.pack("<I", RAW_MAX)
    code += bytes.fromhex("77 00")  # bound the successful count before adding 16
    fail_bound = len(code)-1
    code += bytes.fromhex("48 83 c0 10 5b c3")
    refusal = len(code)
    code += bytes.fromhex("31 c0 5b c3")
    for at in (fail_status, fail_bound):
        struct.pack_into("<b", code, at, refusal-at-1)
    if len(code) > PREFIX-ADAPTER:
        raise ValueError("Thunk exceeds bounded size")
    return bytes(code).ljust(PREFIX-ADAPTER, b"\x90")


def projection():
    raw = prior.EMITTER.read_bytes()
    if sha256(raw) != ADAPTER_SOURCE_SHA:
        raise ValueError("Changed prior sealed adapter source")
    src = raw.decode("ascii")
    def one_fn(name):
        [part] = re.findall(r"^fn "+name+r"\(.*?^end\n", src, re.M|re.S)
        return part
    f0 = one_fn("f0")
    for field, old, new in (
        ("pinned_n:usize", prior.IMAGE_N-prior.THUNK_END, KERNEL_BYTES),
        ("required:usize", prior.IMAGE_N, IMAGE_N), ("image_n:u32", prior.IMAGE_N, IMAGE_N),
        ("stop:usize", prior.THUNK_END, PREFIX), ("to_prefix:usize", prior.THUNK_END, PREFIX),
    ):
        f0 = single(f0, f'{field} = const() {{"value":{old}}}',
                   f'{field} = const() {{"value":{new}}}')
    old_parts = "".join(f'  _thunk_{i}:u64 = call(out) {{"function":"query_thunk_{i}"}}\n'
                        for i in range(4))
    f0 = single(f0, old_parts, '  _held:u64 = call(out) {"function":"held_thunk"}\n')
    header = one_fn("elf_header")
    for pos in (96,104):
        header = single(header, f'word_{pos}:u64 = const() {{"value":{prior.IMAGE_N}}}',
                        f'word_{pos}:u64 = const() {{"value":{IMAGE_N}}}')
    body = ["fn held_thunk(out:mutbuf) -> (u64) effects(read,write,trap) entry(entry)",
            "block entry(out:mutbuf)"]
    payload = thunk()
    for i in range(0,len(payload),8):
        pos = ADAPTER+i
        word = int.from_bytes(payload[i:i+8],"little")
        body.extend((f'  at_{pos}:u64 = const() {{"value":{pos}}}',
                     f'  word_{pos}:u64 = const() {{"value":{word}}}',
                     f'  store_{pos}:u64 = call(out,at_{pos},word_{pos}) {{"function":"put_le64"}}'))
    body.extend(('  zero:u64 = const() {"value":0}', '  ret(zero)', 'end', ''))
    return ("hia-asm.v1 hepta.hia.program.v8 trnm_cell_cache_held_sealed\n"
            +f0+"\n"+header+"\n"+"\n".join(body)).encode()


def build(output):
    if (platform.system(),platform.machine()) != ("Linux","x86_64"):
        raise ValueError("This pinned fixture only targets Linux x86-64")
    bounded(output.parent)
    out = fresh_directory(output)
    bound = json.loads(FIXED[-1].read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256") != bound:
        raise ValueError("Use the existing qualified native compiler")
    if EMITTER.read_bytes() != projection():
        raise ValueError("Tracked HIA packer differs from exact projection")
    before = {p: p.read_bytes() for p in FIXED}
    for p in (EMITTER,KERNEL):
        before.update(checked_source(p)[-1])
    options = dict(backend="selfhost", byte_exports=("f0",),
                   compiler=os.environ["HIA_NATIVE_COMPILER"], compiler_sha256=bound)
    object_path = out/"held.o"
    kernel, _ = build_native(KERNEL,object_path,kind="object",**options)
    obj = object_path.read_bytes()
    body = exact_native_text(obj)
    if (len(body), sha256(body), kernel["compiler_wire_sha256"],
            kernel["chain_migration"]["composed_source_sha256"], sha256(obj)) != (
                KERNEL_BYTES, KERNEL_SHA, WIRE_SHA, COMPOSED_SHA, kernel["artifact_sha256"]):
        raise ValueError("Stock held reader text/closure differs")
    path = out/"emitter.so"
    emitter,_ = build_native(EMITTER,path,kind="shared",**options)
    script = single(prior._EMIT,"buffer.read(293544)",f"buffer.read({KERNEL_BYTES+1})")
    def emit(data,cap):
        return subprocess.run([sys.executable,"-B","-c",script,str(path),str(cap)],
                              input=data,capture_output=True,env={"PATH":""},timeout=20)
    for request, cap in ((body[:-1],IMAGE_N),(body+b"x",IMAGE_N),(body,IMAGE_N-1)):
        refused = emit(request,cap)
        if (refused.returncode,refused.stdout,refused.stderr) != (21,b"",b""):
            raise ValueError("Emitter extent refusal changed")
    result = emit(body,IMAGE_N)
    image = result.stdout
    elf = inspect_executable(image)
    if (result.returncode or result.stderr or len(image)!=IMAGE_N
            or sha256(image[176:ADAPTER])!=prior.ADAPTER_SHA256
            or image[ADAPTER:PREFIX]!=thunk() or image[PREFIX:]!=body
            or any(p.read_bytes()!=raw for p,raw in before.items())
            or sha256(path.read_bytes()) != emitter["artifact_sha256"]
            or any(r["claims"]["fallback_used"] for r in (kernel,emitter))):
        raise ValueError("Wrong exact sealed adapter/thunk/stock reader projection")
    (out/ELF).write_bytes(image)
    proof = {"status":"PASS","elf":{**elf,"sha256":sha256(image),"bytes":len(image)},
             "source_sha256":{str(p.relative_to(HIA_ROOT)):sha256(data)
                                for p,data in sorted(before.items())},
             "adapter_sha256":prior.ADAPTER_SHA256,"thunk_sha256":sha256(thunk()),
             "kernel_text_sha256":KERNEL_SHA,"kernel":kernel,"emitter":emitter,
             "physical_read_max":RAW_MAX,"returned_max":OUT_MAX,"scratch":SCRATCH,
             "emitter_refusals":3,"production_dispatch":False}
    (out/"build.json").write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    return image,proof
