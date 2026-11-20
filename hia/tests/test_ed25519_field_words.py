"""Narrow field reads preserve the original checked memory semantics.

The optimized function retains the exact original fallback. Its pinned digest
provides an independently compiled baseline without storing a second runtime
implementation. Each call runs in a bounded child over shared guarded memory,
so even writes before an arithmetic or bounds trap remain observable. Returned
canonical cases also use Python big integers as an independent arithmetic oracle.

After the read-only guard, i and j stay in 0..15, every address stays inside
its checked 128-byte input, and a coefficient has at most 16 products of
65535**2. The folded accumulator is bounded by 39*16*65535**2 < 2**42.
Consequently the narrow loop's wrapping arithmetic has the same values as
the original checked operations; the unchanged normalization and copy still
determine all later traps and partial writes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.platform.pq_auth.qualification import supervision
from hia.tests.native_support import NativeModule
from hia.tests.test_sha256_words import progress

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/crypto/ed25519_group.hepta"
ORIGINAL_MUL_SHA256 = "57baac5862f3c27402d01059f3dec4e8866fcc3e014f1f2d8e2aa05283f5508a"
P = (1 << 255) - 19
ENTRY = """hia-asm.v1 hepta.hia.program.v8 field_word_boundary
fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(b0)
block b0(s:readbuf,o:mutbuf,w:mutbuf)
  zero:usize = const() {"value":0}
  eight:usize = const() {"value":8}
  sixteen:usize = const() {"value":16}
  out:u64 = call(o,zero) {"function":"ed_load64"}
  x:u64 = call(o,eight) {"function":"ed_load64"}
  y:u64 = call(o,sixteen) {"function":"ed_load64"}
  outp:usize = int.cast(out) {"mode":"wrap"}
  xp:usize = int.cast(x) {"mode":"wrap"}
  yp:usize = int.cast(y) {"mode":"wrap"}
  code:u32 = call(w,outp,xp,yp) {"function":"ed_fe_mul"}
  ret(code)
end
"""
FUNCTIONS = ["ed_fe_mul", "ed_zero", "ed_load64", "ed_store64",
             "ed_normalize", "ed_copy", "ed_compare"]

WORKER = r'''
import ctypes,fcntl,hashlib,json,mmap,os,resource,signal,struct,sys,time
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
def emit(row):print(json.dumps(row,sort_keys=True),flush=True)
def put(memory,offset,value):
 if offset<=len(memory) and 8<=len(memory)-offset:
  memory[offset:offset+8]=struct.pack('<Q',value)
def initial(row):
 memory=bytearray(b'\xa5'*row['extent'])
 p=(1<<255)-19
 for i in range(16):put(memory,133760+8*i,(p>>(16*i))&65535)
 for axis in ('x','y'):
  for i,value in enumerate(row[axis+'limbs']):put(memory,row[axis]+8*i,value)
 for offset,value in row.get('extra',[]):put(memory,offset,value)
 return bytes(memory)
raw=open(request['library'],'rb').read()
assert hashlib.sha256(raw).hexdigest()==request['sha256']
fd=os.memfd_create('trnm-field-words',os.MFD_ALLOW_SEALING)
position=0
while position<len(raw):
 count=os.write(fd,raw[position:]);assert count>0;position+=count
fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
library=ctypes.CDLL('/proc/self/fd/'+str(fd))
fn=library.f0;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint32
emit({'event':'ready','artifact_sha256':request['sha256'],'cases':len(request['cases']),
      'dumpable':libc.prctl(3,0,0,0,0),'child_cpu_limit_seconds':1,'child_wall_limit_seconds':2})
completed=0
try:
 for index,row in enumerate(request['cases']):
  payloads=[b'',struct.pack('<3Q',row['out'],row['x'],row['y']),initial(row)]
  mappings=[];views=[];args=[];before=[]
  for payload in payloads:
   memory=mmap.mmap(-1,len(payload)+16);memory[:]=b'\x5c'*8+payload+b'\xc5'*8
   view=(ctypes.c_uint8*len(memory)).from_buffer(memory)
   mappings.append(memory);views.append(view);before.append(bytes(memory))
   args.extend([ctypes.c_void_p(ctypes.addressof(view)+8),len(payload)])
  pid=os.fork()
  if pid==0:
   try:
    for stream in (0,1,2):os.close(stream)
    resource.setrlimit(resource.RLIMIT_CPU,(1,1))
    result=fn(*args)
    os._exit(0 if result==0 else 81)
   except BaseException:os._exit(82)
  started=time.monotonic();deadline=started+2;status=None
  emit({'event':'started','index':index,'pid':pid,'started_monotonic':started,'deadline_monotonic':deadline})
  while status is None:
   if time.monotonic()>=deadline:
    emit({'event':'child-timeout','index':index,'pid':pid,'seconds':time.monotonic()-started})
    raise TimeoutError('native field multiplication exceeded 2 seconds')
   got,value=os.waitpid(pid,os.WNOHANG)
   if got:status=value;break
   time.sleep(min(0.001,max(0,deadline-time.monotonic())))
  after=[bytes(memory) for memory in mappings];work=after[2][8:-8]
  outcome=({'status':'trapped','signal':os.WTERMSIG(status)} if os.WIFSIGNALED(status)
           else {'status':'returned','exit_code':os.WEXITSTATUS(status)})
  answer={**row,**outcome,'input_unchanged':after[:2]==before[:2],
    'guards_unchanged':all(a[:8]==b[:8] and a[-8:]==b[-8:] for a,b in zip(after,before)),
    'work_before_sha256':hashlib.sha256(payloads[2]).hexdigest(),
    'work_after_sha256':hashlib.sha256(work).hexdigest(),
    'output_hex':work[row['out']:row['out']+128].hex()}
  emit({'event':'completed','index':index,'pid':pid,'seconds':time.monotonic()-started,'answer':answer})
  completed+=1
  del view;views.clear()
  for memory in mappings:memory.close()
finally:os.close(fd)
emit({'event':'finished','artifact_sha256':request['sha256'],'completed':completed,
      'host_compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]})
'''


def cases():
    rows = []
    def add(label, *, x=128, y=384, out=640, extent=140800,
            xlimbs=None, ylimbs=None, oracle=False, extra=()):
        row = {"label": label, "x": x, "y": y, "out": out, "extent": extent,
               "xlimbs": [1] * 16 if xlimbs is None else xlimbs,
               "ylimbs": [2] * 16 if ylimbs is None else ylimbs,
               "oracle": oracle, "extra": [list(pair) for pair in extra]}
        rows.append(row)
    rng = random.Random(25519016)
    for x in (0, 1, 65535):
        for y in (0, 1, 65535):
            add(f"constant-{x}-{y}", xlimbs=[x]*16, ylimbs=[y]*16, oracle=True)
    for i in range(64):
        add(f"random-{i}", xlimbs=[rng.randrange(65536) for _ in range(16)],
            ylimbs=[rng.randrange(65536) for _ in range(16)], oracle=True)
    for out in (128, 384, 129, 383, 133760, 139640, 139648, 139649, 139768):
        add(f"output-alias-{out}", out=out)
    for offset in (139520, 139521, 139640, 139647, 139648, 139649, 139656, 139775, 139776):
        add(f"x-accumulator-{offset}", x=offset)
        add(f"y-accumulator-{offset}", y=offset)
    for x, y in ((128,128),(128,129),(129,128),(133760,384),(128,133760)):
        add(f"input-alias-{x}-{y}", x=x, y=y)
    for axis in ("x", "y"):
        for i in (0, 7, 15):
            for value in (65536, (1 << 32), (1 << 63), (1 << 64) - 1):
                limbs = [1] * 16
                limbs[i] = value
                add(f"wide-{axis}-{i}-{value}", **{axis + "limbs": limbs})
    for extent in (0, 1, 139647, 139648, 139649, 139655, 139775, 139776):
        add(f"short-accumulator-{extent}", extent=extent)
    for axis in ("x", "y", "out"):
        for offset in (140672, 140673, 140799, 140800, 140801, (1 << 64)-127, (1 << 64)-1):
            add(f"late-bounds-{axis}-{offset}", **{axis: offset})
    add("normalization-trap", extra=((133760, (1 << 64)-1), (133880, (1 << 64)-1)))
    return rows


class Ed25519FieldWordTests(unittest.TestCase):
    def test_narrow_reads_preserve_full_memory_and_late_traps(self):
        from hia.tools import toolchain

        current = SOURCE.read_bytes()
        match = re.search(rb"(?ms)^fn ed_fe_mul\([^\n]*\n.*?^end\n", current)
        self.assertIsNotNone(match)
        body = match.group()
        fallback = (b"fn ed_fe_mul(a:mutbuf,out:usize,x:usize,y:usize) -> (u32) effects(read,write,trap) entry(entry)\n"
                    + body[body.index(b"block entry("):])
        self.assertEqual(hashlib.sha256(fallback).hexdigest(), ORIGINAL_MUL_SHA256)
        baseline = current[:match.start()] + fallback + current[match.end():]
        rows = cases()
        observations = []
        artifacts = os.environ.get("TRNM_HIA_FIELD_WORDS_ARTIFACT_DIR")
        with tempfile.TemporaryDirectory(prefix="trnm-field-words-") as temporary:
            for label, source in (("baseline", baseline), ("narrow", current)):
                root = Path(temporary) / label
                dependency_name = "src/crypto/ed25519_group.hepta"
                entry = root / "src/field.hepta"
                entry.parent.mkdir(parents=True)
                if label == "baseline":
                    # The historical comparator is one explicitly owned test
                    # entry, never a changed copy of a production dependency.
                    owned = {m[1].decode(): m[0] for m in re.finditer(
                        rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end\n", source)}
                    entry.write_bytes(ENTRY.encode() + b"".join(owned[name] for name in FUNCTIONS))
                    includes = {}
                else:
                    dependency = root / dependency_name
                    dependency.parent.mkdir(parents=True, exist_ok=True)
                    dependency.write_bytes(source)
                    entry.write_text(ENTRY)
                    includes = {"src/field.hepta": [{"source": dependency_name,
                                                      "functions": FUNCTIONS}]}
                (root / "components.json").write_text(json.dumps({
                    "schema": "trnm.hia.component-includes.v1", "includes": includes}))
                with patch.object(toolchain, "HIA_ROOT", root):
                    native = NativeModule(entry, byte_exports=("f0",), fixture_owner=Path(__file__))
                with native:
                    from hia.tools.qualify import build_provenance
                    provenance = build_provenance(native, {
                        "hia/tests/test_ed25519_field_words.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "hia/src/crypto/ed25519_group.hepta": hashlib.sha256(current).hexdigest()})
                    request = {"library": str(native.library), "sha256": native.artifact_sha256, "cases": rows}
                    completed = supervision.run([sys.executable, "-I", "-S", "-B", "-c", WORKER],
                        cwd=root, data=json.dumps(request).encode(), execution_seconds=60)
                    observed = progress(completed["stdout"], rows)
                    receipt = completed["receipt"]
                    if artifacts:
                        destination = Path(artifacts).absolute() / label
                        if ROOT == destination or ROOT in destination.parents:
                            raise ValueError("Field boundary evidence must be outside the checkout")
                        destination.mkdir(parents=True)
                        files = {"production.hepta": source, "fixture.hepta": entry.read_bytes(),
                                 "components.json": (root / "components.json").read_bytes(),
                                 "provenance.json": json.dumps(provenance, indent=2).encode(),
                                 "module.so": native.library.read_bytes(), "worker.py": WORKER.encode(),
                                 "test.py": Path(__file__).read_bytes(), "stdout.raw": completed["stdout"],
                                 "stderr.raw": completed["stderr"],
                                 "request.json": json.dumps(request, indent=2).encode(),
                                 "build.json": json.dumps(native.receipt, indent=2).encode(),
                                 "supervision.json": json.dumps(receipt, indent=2).encode()}
                        for name, data in files.items():
                            (destination / name).write_bytes(data)
                        (destination / "manifest.json").write_text(json.dumps({name: {
                            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                            for name, data in files.items()}, indent=2) + "\n")
                    self.assertEqual(receipt["outcome"], "success", completed["stderr"].decode(errors="replace"))
                    self.assertEqual(receipt["exit_code"], 0)
                    self.assertEqual(completed["stderr"], b"")
                    self.assertTrue(receipt["cleanup_complete"])
                    self.assertEqual(receipt["killpg_attempts"], [])
                    self.assertEqual(observed["parse_errors"], [])
                    self.assertEqual(observed["ready"]["artifact_sha256"], native.artifact_sha256)
                    self.assertEqual(observed["finished"]["artifact_sha256"], native.artifact_sha256)
                    self.assertEqual(observed["finished"]["completed"], len(rows))
                    self.assertEqual(observed["finished"]["host_compiler_modules_loaded"], [])
                    self.assertEqual(len(observed["cases"]), len(rows))
                    observations.append(observed["cases"])
        self.assertEqual(SOURCE.read_bytes(), current)
        for sent, baseline, narrow in zip(rows, *observations):
            with self.subTest(label=sent["label"]):
                self.assertEqual({key: narrow[key] for key in sent}, sent)
                self.assertTrue(narrow["input_unchanged"])
                self.assertTrue(narrow["guards_unchanged"])
                self.assertEqual(baseline, narrow)
                if narrow["status"] == "trapped":
                    self.assertEqual(narrow["signal"], 4)
                else:
                    self.assertEqual(narrow["exit_code"], 0)
                if sent["oracle"]:
                    self.assertEqual(narrow["status"], "returned")
                    x = sum(value << (16*i) for i, value in enumerate(sent["xlimbs"]))
                    y = sum(value << (16*i) for i, value in enumerate(sent["ylimbs"]))
                    product = x*y % P
                    expected = b"".join(((product >> (16*i)) & 65535).to_bytes(8, "little") for i in range(16))
                    self.assertEqual(bytes.fromhex(narrow["output_hex"]), expected)
        print(json.dumps({"schema": "trnm.hia.field-word-boundary.v1",
                          "cases": len(rows), "native_calls": 2*len(rows),
                          "baseline_function_sha256": ORIGINAL_MUL_SHA256,
                          "production_sha256": hashlib.sha256(current).hexdigest()}, sort_keys=True), flush=True)
