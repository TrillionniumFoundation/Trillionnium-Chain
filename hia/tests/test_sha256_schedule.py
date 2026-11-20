"""Compare bounded u32 SHA compression with the exact prior native compressor.

The fast path requires a complete 1168-byte context and eight incoming state
words within u32. Every W slot is still written as the same eight bytes with
zero upper halves. Arbitrary u64 K words contribute through addition modulo
2**32, so their high halves cannot affect a result. Short contexts and wider
incoming states execute the unchanged original blocks, including partial
writes and traps. The baseline is a test entry assembled from those blocks;
its whole function digest must match the original production source exactly.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import random
import re
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.platform.pq_auth.qualification import supervision
from hia.tests.native_support import NativeModule
from hia.tests.test_sha256_words import progress

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/crypto/sha256_stream.hepta"
ORIGINAL_COMPRESS_SHA256 = "2a5e99e2bd678db29b5879826fa20ee0214e7a3a48c0f40c7185f8ddff45eeed"
ENTRY = """hia-asm.v1 hepta.hia.program.v8 sha_schedule_boundary
fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(b0)
block b0(s:readbuf,o:mutbuf,w:mutbuf)
  zero:usize = const() {"value":0}
  mode:u8 = buffer.load(s,zero)
  no:u8 = const() {"value":0}
  initialize:bool = compare.ne(mode,no)
  branch initialize init(w) compress(w)
block init(iw:mutbuf)
  initialized:u64 = call(iw) {"function":"tr_sha_init"}
  jump compress(iw)
block compress(cw:mutbuf)
  result:u64 = call(cw) {"function":"tr_sha_compress"}
  code:u32 = int.cast(result) {"mode":"wrap"}
  ret(code)
end
"""

WORKER = r'''
import base64,ctypes,fcntl,hashlib,json,mmap,os,resource,signal,struct,sys,time
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
def emit(row):print(json.dumps(row,sort_keys=True),flush=True)
raw=open(request['library'],'rb').read()
assert hashlib.sha256(raw).hexdigest()==request['sha256']
fd=os.memfd_create('trnm-sha-schedule',os.MFD_ALLOW_SEALING)
p=0
while p<len(raw):
 n=os.write(fd,raw[p:]);assert n>0;p+=n
fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
library=ctypes.CDLL('/proc/self/fd/'+str(fd))
fn=library.f0;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint32
emit({'event':'ready','artifact_sha256':request['sha256'],'cases':len(request['cases']),
      'dumpable':libc.prctl(3,0,0,0,0),'child_cpu_limit_seconds':1,'child_wall_limit_seconds':2})
completed=0
try:
 for index,row in enumerate(request['cases']):
  payload=base64.b64decode(row['backing'],validate=True)
  memory=mmap.mmap(-1,len(payload)+64);memory[:]=b'\x5c'*32+payload+b'\xc5'*32
  view=(ctypes.c_uint8*len(memory)).from_buffer(memory);args=[]
  for offset,length in row['views']:
   assert 0<=offset<=len(payload) and 0<=length<=len(payload)-offset
   args.extend([ctypes.c_void_p(ctypes.addressof(view)+32+offset),length])
  result=mmap.mmap(-1,8);result[:]=b'\xff'*8
  pid=os.fork()
  if pid==0:
   try:
    for stream in (0,1,2):os.close(stream)
    resource.setrlimit(resource.RLIMIT_CPU,(1,1))
    code=fn(*args);result[:]=struct.pack('<Q',code);os._exit(0)
   except BaseException:os._exit(82)
  started=time.monotonic();deadline=started+2;status=None
  emit({'event':'started','index':index,'pid':pid,'started_monotonic':started,'deadline_monotonic':deadline})
  while status is None:
   if time.monotonic()>=deadline:
    emit({'event':'child-timeout','index':index,'pid':pid,'seconds':time.monotonic()-started})
    raise TimeoutError('native SHA case exceeded 2 seconds')
   got,value=os.waitpid(pid,os.WNOHANG)
   if got:status=value;break
   time.sleep(min(0.001,max(0,deadline-time.monotonic())))
  after=bytes(memory);body=after[32:-32];wo,wl=row['views'][2];oo,ol=row['views'][1]
  outcome=({'status':'trapped','signal':os.WTERMSIG(status)} if os.WIFSIGNALED(status)
           else {'status':'returned','exit_code':os.WEXITSTATUS(status),'code':struct.unpack('<Q',result[:])[0]})
  answer={**row,**outcome,'guards_unchanged':after[:32]==b'\x5c'*32 and after[-32:]==b'\xc5'*32,
    'before_sha256':hashlib.sha256(payload).hexdigest(),'after_sha256':hashlib.sha256(body).hexdigest(),
    'state_hex':body[wo+1024:wo+1088].hex() if wl>=1088 else '',
    'output_hex':body[oo:oo+ol].hex()}
  emit({'event':'completed','index':index,'pid':pid,'seconds':time.monotonic()-started,'answer':answer})
  completed+=1
  del view;memory.close();result.close()
finally:os.close(fd)
emit({'event':'finished','artifact_sha256':request['sha256'],'completed':completed,
      'host_compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]})
'''


def original_source(current):
    match = re.search(rb"(?ms)^fn tr_sha_compress\([^\n]*\n.*?^end\n", current)
    if match is None:
        raise AssertionError("compressor source is missing")
    body = match.group()
    raw = (b"fn tr_sha_compress(v0:mutbuf) -> (u64) effects(read,write,trap) entry(b0)\n"
           + body[body.index(b"block b0("):])
    if hashlib.sha256(raw).hexdigest() != ORIGINAL_COMPRESS_SHA256:
        raise AssertionError("reconstructed compressor is not the exact original function")
    return current[:match.start()] + raw + current[match.end():]


def compression_cases():
    rows = []
    rng = random.Random(25632064)
    for length in (0, 511, 512, 519, 1023, 1024, 1087, 1103, *range(1104, 1169), 1207, 1208, 1280):
        work = bytes(rng.randrange(256) for _ in range(length))
        backing = work + bytes(128)
        rows.append({"label": f"extent-{length}", "views": [[length+32,1],[length+64,0],[0,length]],
                     "backing": base64.b64encode(backing).decode(), "digest": None})
    for seed in range(64):
        work = bytes(rng.randrange(256) for _ in range(1208))
        # K and all incoming state halves are unconstrained, not truncated by the oracle.
        rows.append({"label": f"arbitrary-state-k-{seed}", "views": [[1240,1],[1272,0],[0,1208]],
                     "backing": base64.b64encode(work + bytes(128)).decode(), "digest": None})
    for seed in range(24):
        work = bytearray(rng.randrange(256) for _ in range(1208))
        for i in range(8):
            value = rng.randrange(1 << 32)
            if seed >= 16 and i == seed - 16:
                value |= 1 << 32
            struct.pack_into("<Q", work, 1024 + 8*i, value)
        label = f"wide-k-u32-state-{seed}" if seed < 16 else f"wide-state-word-{seed-16}"
        rows.append({"label": label, "views": [[1240,1],[1272,0],[0,1208]],
                     "backing": base64.b64encode(work + bytes(128)).decode(), "digest": None})
    for message in (b"", b"a", b"abc", b"x"*55):
        block = message + b"\x80" + bytes(55-len(message)) + (8*len(message)).to_bytes(8,"big")
        backing = bytearray(b"\xa5"*1336)
        backing[1104:1168] = block
        backing[1240] = 1
        rows.append({"label": f"hashlib-{len(message)}", "views": [[1240,1],[1272,0],[0,1208]],
                     "backing": base64.b64encode(backing).decode(), "digest": hashlib.sha256(message).hexdigest()})
    return rows


def streaming_alias_cases():
    rows = []
    message = bytes((i*73+19)&255 for i in range(73))
    layouts = [(1408,2304,0), (1104,2304,0), (0,2304,0), (1408,1024,0),
               (1408,1168,0), (1408,1104,0), (0,0,1408), (1184,2304,0)]
    for chunk in (1, 16, 64, 97):
        for number, (source, output, work) in enumerate(layouts):
            backing = bytearray(b"\xa5"*4096)
            payload = struct.pack("<Q",chunk)+message
            backing[source:source+len(payload)] = payload
            rows.append({"label": f"chunk-{chunk}-alias-{number}",
                         "views": [[source,len(payload)],[output,64],[work,1208]],
                         "backing": base64.b64encode(backing).decode(),
                         "digest": hashlib.sha256(message).hexdigest() if number in (0,3,4,5,6) else None})
    return rows


class Sha256ScheduleNativeTests(unittest.TestCase):
    def observe(self, *, label, rows, compression):
        from hia.tools import toolchain

        current = SOURCE.read_bytes()
        baseline = original_source(current)
        results = []
        with tempfile.TemporaryDirectory(prefix="trnm-sha-schedule-") as temporary:
            for variant, source in (("baseline", baseline), ("narrow", current)):
                root = Path(temporary) / variant
                dependency = root / "src/crypto/sha256_stream.hepta"
                dependency.parent.mkdir(parents=True)
                if compression:
                    entry = root / "src/compression.hepta"
                    functions = ["tr_sha_init", "tr_sha_compress", "tr_get", "tr_put"]
                    if variant == "baseline":
                        owned = {m[1].decode(): m[0] for m in re.finditer(
                            rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end\n", source)}
                        entry.write_bytes(ENTRY.encode() + b"".join(owned[name] for name in functions))
                        includes = {}
                    else:
                        dependency.write_bytes(source)
                        entry.write_text(ENTRY)
                        includes = {"src/compression.hepta": [{"source": "src/crypto/sha256_stream.hepta",
                                                                 "functions": functions}]}
                else:
                    entry, includes = root / "src/sha_stream_fixture.hepta", {}
                    entry.write_bytes(source)
                (root / "components.json").write_text(json.dumps({
                    "schema": "trnm.hia.component-includes.v1", "includes": includes}))
                with patch.object(toolchain, "HIA_ROOT", root):
                    native = NativeModule(entry, byte_exports=("f0",), fixture_owner=Path(__file__))
                with native:
                    from hia.tools.qualify import build_provenance
                    provenance = build_provenance(native, {
                        "hia/tests/test_sha256_schedule.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "hia/src/crypto/sha256_stream.hepta": hashlib.sha256(current).hexdigest()})
                    request = {"library": str(native.library), "sha256": native.artifact_sha256, "cases": rows}
                    completed = supervision.run([sys.executable, "-I", "-S", "-B", "-c", WORKER],
                        cwd=root, data=json.dumps(request).encode(), execution_seconds=60)
                    observed = progress(completed["stdout"], rows)
                    receipt = completed["receipt"]
                    artifacts = os.environ.get("TRNM_HIA_SHA256_SCHEDULE_ARTIFACT_DIR")
                    if artifacts:
                        destination = Path(artifacts).absolute() / label / variant
                        if ROOT == destination or ROOT in destination.parents:
                            raise ValueError("SHA boundary evidence must be outside the checkout")
                        destination.mkdir(parents=True)
                        files = {"production.hepta": source, "entry.hepta": entry.read_bytes(),
                            "components.json": (root/"components.json").read_bytes(),
                            "provenance.json": json.dumps(provenance, indent=2).encode(),
                            "module.so": native.library.read_bytes(), "test.py": Path(__file__).read_bytes(),
                            "worker.py": WORKER.encode(), "stdout.raw": completed["stdout"],
                            "stderr.raw": completed["stderr"], "request.json": json.dumps(request).encode(),
                            "build.json": json.dumps(native.receipt).encode(),
                            "supervision.json": json.dumps(receipt).encode()}
                        for name, raw in files.items():
                            (destination/name).write_bytes(raw)
                        (destination/"manifest.json").write_text(json.dumps({name: {
                            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                            for name, raw in files.items()}, indent=2)+"\n")
                    self.assertEqual(receipt["outcome"], "success", completed["stderr"].decode(errors="replace"))
                    self.assertEqual(receipt["exit_code"], 0)
                    self.assertEqual(completed["stderr"], b"")
                    self.assertTrue(receipt["cleanup_complete"])
                    self.assertEqual(receipt["killpg_attempts"], [])
                    self.assertEqual(observed["parse_errors"], [])
                    self.assertEqual(observed["ready"]["artifact_sha256"], native.artifact_sha256)
                    self.assertEqual(observed["finished"]["artifact_sha256"], native.artifact_sha256)
                    self.assertEqual(observed["finished"]["host_compiler_modules_loaded"], [])
                    self.assertEqual(observed["finished"]["completed"], len(rows))
                    self.assertEqual(len(observed["cases"]), len(rows))
                    results.append(observed["cases"])
        self.assertEqual(SOURCE.read_bytes(), current)
        for sent, baseline, narrow in zip(rows, *results):
            with self.subTest(label=sent["label"]):
                self.assertEqual({key: narrow[key] for key in sent}, sent)
                self.assertEqual(baseline, narrow)
                self.assertTrue(narrow["guards_unchanged"])
                self.assertEqual(narrow["before_sha256"], hashlib.sha256(base64.b64decode(sent["backing"])).hexdigest())
                if narrow["status"] == "trapped":
                    self.assertEqual(narrow["signal"], 4)
                else:
                    self.assertEqual(narrow["exit_code"], 0)
                if sent["digest"] is not None:
                    self.assertEqual(narrow["status"], "returned")
                    self.assertEqual(narrow["code"], 0)
                    if compression:
                        words = struct.unpack("<8Q", bytes.fromhex(narrow["state_hex"]))
                        got = b"".join(word.to_bytes(4,"big") for word in words).hex()
                    else:
                        got = narrow["output_hex"][:64]
                    self.assertEqual(got, sent["digest"])
        print(json.dumps({"schema": "trnm.hia.sha256-schedule-boundary.v1", "label": label,
            "cases": len(rows), "native_calls": 2*len(rows),
            "baseline_compress_sha256": ORIGINAL_COMPRESS_SHA256,
            "production_sha256": hashlib.sha256(current).hexdigest()}, sort_keys=True), flush=True)

    def test_schedule_full_memory_short_buffers_and_arbitrary_state_k(self):
        self.observe(label="compress", rows=compression_cases(), compression=True)

    def test_stream_input_output_and_workspace_aliases_match_original(self):
        self.observe(label="alias", rows=streaming_alias_cases(), compression=False)
