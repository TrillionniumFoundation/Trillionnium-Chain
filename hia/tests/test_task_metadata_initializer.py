"""Compare every metadata write boundary with the original native initializer.

The historical comparator is only the fixed original function and its unchanged
eight-byte writer, extracted from Git and compiled as an explicitly owned test
fixture. The candidate selects the current production functions verbatim. A
shared mapping makes partial writes before an actual native bounds trap visible;
the independent expected image comes from the pinned original table constants.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.platform.pq_auth.qualification import supervision
from hia.tests.native_support import NativeModule
from hia.tests.test_sha256_words import progress

ROOT = Path(__file__).resolve().parents[2]
CODEC = ROOT / "hia/src/task_kernel/codec.hepta"
CORE = ROOT / "hia/src/control_plane/core.hepta"
ORIGINAL_COMMIT = "267989537b255f168ac132edfbe317aba6c0e34a"
ORIGINAL_METADATA_SHA256 = "dc23f7c96f60248e04616823f53a6e36713584a30de0e1c4c628b996b2895094"
EXTENT = 16416
ENTRY = b'''hia-asm.v1 hepta.hia.program.v8 task_metadata_boundary
fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(b0)
block b0(s:readbuf,o:mutbuf,w:mutbuf)
  value:u64 = call(w) {"function":"tk_metadata"}
  code:u32 = int.cast(value) {"mode":"wrap"}
  ret(code)
end
'''

WORKER = r'''
import ctypes,fcntl,hashlib,json,mmap,os,resource,signal,sys,time
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
fd=os.memfd_create('trnm-task-metadata',os.MFD_ALLOW_SEALING)
position=0
while position<len(raw):
 count=os.write(fd,raw[position:]);assert count>0;position+=count
fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
library=ctypes.CDLL('/proc/self/fd/'+str(fd))
fn=library.f0;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint32
initial=bytes((i*73+19)&255 for i in range(request['extent']))
emit({'event':'ready','artifact_sha256':request['sha256'],'cases':len(request['cases']),
      'dumpable':libc.prctl(3,0,0,0,0),'child_cpu_limit_seconds':1,'child_wall_limit_seconds':2})
completed=0
try:
 for index,row in enumerate(request['cases']):
  assert 0<=row['offset']<=request['extent'] and 0<=row['length']<=request['extent']-row['offset']
  memory=mmap.mmap(-1,len(initial)+16);memory[:]=b'\x5c'*8+initial+b'\xc5'*8
  view=(ctypes.c_uint8*len(memory)).from_buffer(memory)
  pointer=ctypes.c_void_p(ctypes.addressof(view)+8+row['offset'])
  pid=os.fork()
  if pid==0:
   try:
    for stream in (0,1,2):os.close(stream)
    resource.setrlimit(resource.RLIMIT_CPU,(1,1))
    value=fn(pointer,0,pointer,0,pointer,row['length'])
    os._exit(0 if value==0 else 81)
   except BaseException:os._exit(82)
  started=time.monotonic();deadline=started+2;status=None
  emit({'event':'started','index':index,'pid':pid,'started_monotonic':started,'deadline_monotonic':deadline})
  while status is None:
   if time.monotonic()>=deadline:
    emit({'event':'child-timeout','index':index,'pid':pid,'seconds':time.monotonic()-started})
    raise TimeoutError('native metadata initializer exceeded 2 seconds')
   got,value=os.waitpid(pid,os.WNOHANG)
   if got:status=value;break
   time.sleep(min(0.001,max(0,deadline-time.monotonic())))
  after=bytes(memory)
  outcome=({'status':'trapped','signal':os.WTERMSIG(status)} if os.WIFSIGNALED(status)
           else {'status':'returned','exit_code':os.WEXITSTATUS(status)})
  emit({'event':'completed','index':index,'pid':pid,'seconds':time.monotonic()-started,
        'answer':{**row,**outcome,'guards_unchanged':after[:8]==b'\x5c'*8 and after[-8:]==b'\xc5'*8,
                  'backing_sha256':hashlib.sha256(after[8:-8]).hexdigest()}})
  completed+=1
  del view
  memory.close()
finally:os.close(fd)
emit({'event':'finished','artifact_sha256':request['sha256'],'completed':completed,
      'host_compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]})
'''


def function(raw, name):
    matches = list(re.finditer(rb"(?ms)^fn " + name.encode() + rb"\([^\n]*\n.*?^end\n", raw))
    if len(matches) != 1:
        raise ValueError("Expected one exact function: " + name)
    return matches[0][0]


def original(path):
    return subprocess.run(["git", "-C", str(ROOT), "show",
                           ORIGINAL_COMMIT + ":" + path.relative_to(ROOT).as_posix()],
                          check=True, capture_output=True, timeout=10).stdout


def original_writes(raw):
    constants, rows = {}, []
    for line in raw.decode().splitlines():
        constant = re.fullmatch(r'  (\w+):u64 = const\(\) \{"value":([0-9]+)\}', line)
        call = re.fullmatch(r'  (\w+):u64 = call\(v0,(\w+),(\w+)\) \{"function":"cp_put"\}', line)
        if constant:
            constants[constant[1]] = int(constant[2])
        if call:
            rows.append((constants[call[2]], constants[call[3]]))
    if len(rows) != 648 or [p for p, _ in rows] != [*range(8192, 9744, 8), *range(12288, 15920, 8)]:
        raise ValueError("Historical metadata table differs")
    return rows


def cases():
    lengths = sorted({0, 1, 8191, 9744, 9745, 12287, 15920, 15921, 16384,
                      *range(8192, 9744), *range(12288, 15920)})
    rows = [{"label": "byte-" + str(n), "length": n, "offset": 0} for n in lengths]
    for offset in (1, 7, 31):
        for length in (0, 8192, 8193, 9744, 12288, 12289, 15919, 15920, 16384):
            rows.append({"label": f"unaligned-{offset}-{length}", "length": length, "offset": offset})
    return rows


class TaskMetadataInitializerTests(unittest.TestCase):
    def test_every_written_byte_preserves_original_partial_traps_and_full_memory(self):
        from hia.tools import toolchain
        from hia.tools.qualify import build_provenance

        codec, core = CODEC.read_bytes(), CORE.read_bytes()
        before_codec, before_core = original(CODEC), original(CORE)
        baseline = function(before_codec, "tk_metadata")
        self.assertEqual(hashlib.sha256(baseline).hexdigest(), ORIGINAL_METADATA_SHA256)
        self.assertEqual(function(core, "cp_put"), function(before_core, "cp_put"))
        self.assertEqual(function(codec, "tk_write"), function(before_codec, "tk_write"))
        table = original_writes(baseline)
        initialized = bytearray(16384)
        for position, value in table:
            initialized[position:position+8] = value.to_bytes(8, "little")
        rows, observations = cases(), []
        self.assertEqual(len(rows), 5220)
        artifacts = os.environ.get("TRNM_HIA_TASK_METADATA_ARTIFACT_DIR")
        with tempfile.TemporaryDirectory(prefix="trnm-task-metadata-") as temporary:
            for label, selected in (
                    ("baseline", baseline + function(before_core, "cp_put")),
                    ("current", function(codec, "tk_metadata") + function(codec, "tk_write"))):
                root = Path(temporary) / label
                entry = root / "src/metadata.hepta"
                entry.parent.mkdir(parents=True)
                entry.write_bytes(ENTRY + selected)
                (root / "components.json").write_text(json.dumps({
                    "schema": "trnm.hia.component-includes.v1", "includes": {}}))
                with patch.object(toolchain, "HIA_ROOT", root):
                    native = NativeModule(entry, byte_exports=("f0",), fixture_owner=Path(__file__))
                with native:
                    provenance = build_provenance(native, {
                        "hia/tests/test_task_metadata_initializer.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "hia/src/task_kernel/codec.hepta": hashlib.sha256(codec).hexdigest(),
                        "hia/src/control_plane/core.hepta": hashlib.sha256(core).hexdigest()})
                    request = {"library": str(native.library), "sha256": native.artifact_sha256,
                               "cases": rows, "extent": EXTENT}
                    completed = supervision.run([sys.executable, "-I", "-S", "-B", "-c", WORKER],
                        cwd=root, data=json.dumps(request).encode(), execution_seconds=60)
                    observed = progress(completed["stdout"], rows)
                    receipt = completed["receipt"]
                    if artifacts:
                        destination = Path(artifacts).absolute() / label
                        if ROOT == destination or ROOT in destination.parents:
                            raise ValueError("Metadata boundary evidence must be outside the checkout")
                        destination.mkdir(parents=True)
                        files = {"fixture.hepta": entry.read_bytes(),
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
        self.assertEqual(CODEC.read_bytes(), codec)
        self.assertEqual(CORE.read_bytes(), core)
        initial = bytes((i*73+19) & 255 for i in range(EXTENT))
        for sent, old, new in zip(rows, *observations):
            with self.subTest(label=sent["label"]):
                self.assertEqual({key: new[key] for key in sent}, sent)
                self.assertEqual(old, new)
                self.assertTrue(new["guards_unchanged"])
                expected = bytearray(initial)
                for start, end in ((8192, 9744), (12288, 15920)):
                    end = min(end, sent["length"])
                    if start < end:
                        expected[sent["offset"]+start:sent["offset"]+end] = initialized[start:end]
                self.assertEqual(new["backing_sha256"], hashlib.sha256(expected).hexdigest())
                if sent["length"] < 15920:
                    self.assertEqual(new["status"], "trapped")
                    self.assertEqual(new["signal"], 4)
                else:
                    self.assertEqual(new["status"], "returned")
                    self.assertEqual(new["exit_code"], 0)
        print(json.dumps({"schema": "trnm.hia.task-metadata-initializer-boundary.v1",
                          "cases": len(rows), "native_calls": 2*len(rows),
                          "baseline_function_sha256": ORIGINAL_METADATA_SHA256,
                          "production_sha256": hashlib.sha256(codec).hexdigest()}, sort_keys=True), flush=True)
