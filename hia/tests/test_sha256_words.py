"""Native SHA word access, including observable writes before a late trap.

The fixture selects current production helpers without reimplementing them.
The observer forks only to keep a trapping call from terminating the test;
shared guarded mappings expose every byte written before that trap.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.tests.native_support import NativeModule
from hia.platform.pq_auth.qualification import supervision

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/crypto/sha256_stream.hepta"
ENTRY = """hia-asm.v1 hepta.hia.program.v8 sha_word_boundary
fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(b0)
block b0(s:readbuf,o:mutbuf,w:mutbuf)
  zero:u64 = const() {"value":0}
  eight:u64 = const() {"value":8}
  mode:u64 = call(s,zero) {"function":"tr_read"}
  offset:u64 = call(s,eight) {"function":"tr_read"}
  read:bool = compare.eq(mode,zero)
  branch read get(s,o,w,offset) put(s,o,w,offset)
block get(sg:readbuf,og:mutbuf,wg:mutbuf,pg:u64)
  valueg:u64 = call(wg,pg) {"function":"tr_get"}
  jump done(og,valueg)
block put(sp:readbuf,op:mutbuf,wp:mutbuf,pp:u64)
  sixteen:u64 = const() {"value":16}
  valuep:u64 = call(sp,sixteen) {"function":"tr_read"}
  resultp:u64 = call(wp,pp,valuep) {"function":"tr_put"}
  jump done(op,resultp)
block done(od:mutbuf,result:u64)
  at:u64 = const() {"value":0}
  ignored:u64 = call(od,at,result) {"function":"tr_put"}
  code:u32 = const() {"value":0}
  ret(code)
end
"""

WORKER = r'''
import ctypes,fcntl,hashlib,json,mmap,os,resource,signal,struct,sys,time
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
# RLIMIT_CORE alone does not suppress a piped kernel core handler. The
# canonical native observer already uses this inherited Linux process flag.
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
libc.prctl.restype=ctypes.c_int
if libc.prctl(4,0,0,0,0)!=0 or libc.prctl(3,0,0,0,0)!=0:
 raise OSError(ctypes.get_errno(),'could not disable dumpability')
def emit(row):
 print(json.dumps(row,sort_keys=True),flush=True)
fault=request.get('fault')
if fault is not None:
 assert fault['mode'] in ('child-pause','observer-and-child-pause')
 assert type(fault['index']) is int and 0<=fault['index']<len(request['cases'])
raw=open(request['library'],'rb').read()
assert hashlib.sha256(raw).hexdigest()==request['sha256']
fd=os.memfd_create('trnm-sha-words',os.MFD_ALLOW_SEALING)
position=0
while position<len(raw):
 count=os.write(fd,raw[position:]);assert count>0;position+=count
fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
library=ctypes.CDLL('/proc/self/fd/'+str(fd))
fn=library.f0;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint64
emit({'event':'ready','artifact_sha256':request['sha256'],'cases':len(request['cases']),
      'dumpable':libc.prctl(3,0,0,0,0),'child_cpu_limit_seconds':1,'child_wall_limit_seconds':2})
completed=0
try:
 for index,row in enumerate(request['cases']):
  payloads=[struct.pack('<3Q',row['mode'],row['offset'],row['value']),b'\xa5'*8,bytes((i*73+19)&255 for i in range(row['extent']))]
  mappings=[];views=[];args=[];before=[]
  for payload in payloads:
   initial=b'\x5c'*8+payload+b'\xc5'*8
   memory=mmap.mmap(-1,len(initial));memory[:]=initial
   view=(ctypes.c_uint8*len(initial)).from_buffer(memory)
   mappings.append(memory);views.append(view);before.append(initial)
   args.extend([ctypes.c_void_p(ctypes.addressof(view)+8),len(payload)])
  pid=os.fork()
  if pid==0:
   try:
    # No native helper writes these streams. Closing the inherited observer
    # pipes lets its leader report a child deadline immediately; the single
    # outer cleanup owns killing and reaping any still-live native child.
    for stream in (0,1,2):os.close(stream)
    resource.setrlimit(resource.RLIMIT_CPU,(1,1))
    if libc.prctl(3,0,0,0,0)!=0:os._exit(83)
    if fault is not None and index==fault['index']:
     while True:signal.pause()
    result=fn(*args)
    os._exit(0 if result==0 else 81)
   except BaseException:os._exit(82)
  started=time.monotonic();deadline=started+2;status=None
  emit({'event':'started','index':index,'pid':pid,'started_monotonic':started,'deadline_monotonic':deadline})
  if fault is not None and index==fault['index'] and fault['mode']=='observer-and-child-pause':
   while True:signal.pause()
  while status is None:
   if time.monotonic()>=deadline:
    emit({'event':'child-timeout','index':index,'pid':pid,'seconds':time.monotonic()-started})
    raise TimeoutError('native fixed-width helper exceeded 2 seconds')
   got,value=os.waitpid(pid,os.WNOHANG)
   if got:status=value;break
   time.sleep(min(0.001,max(0,deadline-time.monotonic())))
  after=[bytes(memory) for memory in mappings]
  if os.WIFSIGNALED(status):outcome={'status':'trapped','signal':os.WTERMSIG(status)}
  else:outcome={'status':'returned','exit_code':os.WEXITSTATUS(status)}
  answer={**row,**outcome,'input_unchanged':after[0]==before[0],
    'guards_unchanged':all(a[:8]==b[:8] and a[-8:]==b[-8:] for a,b in zip(after,before)),
    'output_hex':after[1][8:-8].hex(),'work_before_hex':payloads[2].hex(),'work_after_hex':after[2][8:-8].hex()}
  emit({'event':'completed','index':index,'pid':pid,'seconds':time.monotonic()-started,'answer':answer})
  completed+=1
  del view;views.clear()
  for memory in mappings:memory.close()
finally:os.close(fd)
emit({'event':'finished','artifact_sha256':request['sha256'],'completed':completed,
      'host_compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]})
'''


def native_cases():
    cases = []
    for extent in (*range(10), 15, 16, 17, 31, 64):
        offsets = sorted({0, 1, max(0, extent - 8), max(0, extent - 7),
                          max(0, extent - 1), extent, extent + 1,
                          (1 << 64) - 8, (1 << 64) - 1})
        for offset in offsets:
            for mode, value in ((0, 0), (1, 0), (1, 0xFEDCBA9876543210),
                                (1, (1 << 64) - 1)):
                cases.append({"extent": extent, "offset": offset,
                              "mode": mode, "value": value})
    return cases


def progress(raw, cases):
    """Keep every requested case visible, including an interrupted JSON line."""
    states = [{"index": index, "case": row, "state": "not-started"}
              for index, row in enumerate(cases)]
    observed = {"ready": None, "finished": None, "states": states,
                "cases": [], "parse_errors": []}
    for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
        try:
            if not line.endswith(b"\n"):
                raise ValueError("incomplete event line")
            event = json.loads(line)
            kind = event["event"]
            if kind == "ready":
                if observed["ready"] is not None or any(row["state"] != "not-started" for row in states):
                    raise ValueError("duplicate or late ready event")
                observed["ready"] = event
            elif kind == "finished":
                if observed["finished"] is not None or any(row["state"] != "completed" for row in states):
                    raise ValueError("duplicate or early finished event")
                observed["finished"] = event
            else:
                index = event["index"]
                if type(index) is not int or not 0 <= index < len(states):
                    raise ValueError("invalid event case index")
                row = states[index]
                if observed["ready"] is None or observed["finished"] is not None:
                    raise ValueError("case event outside ready/finished interval")
                if kind == "started":
                    if row["state"] != "not-started" or index != len(observed["cases"]):
                        raise ValueError("duplicate or out of order start")
                    row.update(state="started-unfinished", started=event)
                elif kind in ("completed", "child-timeout"):
                    if row["state"] != "started-unfinished" or event["pid"] != row["started"]["pid"]:
                        raise ValueError("unmatched completion or deadline event")
                    if kind == "completed":
                        row.update(state="completed", completed=event)
                        observed["cases"].append(event["answer"])
                    else:
                        row.update(state="child-timeout", timeout=event)
                else:
                    raise ValueError("unknown event")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as error:
            observed["parse_errors"].append({"line": line_number, "error": str(error),
                                             "raw_hex": line.hex()})
    return observed


class Sha256WordNativeTests(unittest.TestCase):
    def observe(self, *, label, fault=None, execution_seconds=30):
        from hia.tools import toolchain

        original = SOURCE.read_bytes()
        cases = native_cases()
        self.assertEqual(len(cases), 440)
        with tempfile.TemporaryDirectory(prefix="trnm-sha-word-boundary-") as temporary:
            root = Path(temporary)
            dependency = root / "src/crypto/sha256_stream.hepta"
            dependency.parent.mkdir(parents=True)
            dependency.write_bytes(original)
            entry = root / "src/words.hepta"
            entry.write_text(ENTRY)
            (root / "components.json").write_text(json.dumps({
                "schema": "trnm.hia.component-includes.v1", "includes": {
                    "src/words.hepta": [{"source": "src/crypto/sha256_stream.hepta",
                                          "functions": ["tr_read", "tr_get", "tr_put"]}]}}))
            with patch.object(toolchain, "HIA_ROOT", root):
                native = NativeModule(entry, byte_exports=("f0",),
                                      fixture_owner=Path(__file__))
            with native:
                request = {"library": str(native.library),
                           "sha256": native.artifact_sha256, "cases": cases}
                if fault is not None:
                    request["fault"] = fault
                completed = supervision.run([sys.executable, "-I", "-S", "-B", "-c", WORKER],
                                            cwd=root, data=json.dumps(request).encode(),
                                            execution_seconds=execution_seconds)
                observed = progress(completed["stdout"], cases)
                report = {"schema": "trnm.hia.sha256-word-boundary-observations.v2",
                          "label": label, "production_sha256": hashlib.sha256(original).hexdigest(),
                          "artifact_sha256": native.artifact_sha256, "requested_cases": len(cases),
                          "completed_cases": len(observed["cases"]), "fault": fault,
                          "supervisor": completed["receipt"], **observed}
                # Emit before any assertion/capture failure, so the enclosing
                # qualification raw log preserves unfinished cases as well.
                print(json.dumps(report, sort_keys=True), flush=True)
                if completed["receipt"]["outcome"] != "success":
                    print(json.dumps({"label": label, "stdout_raw_hex": completed["stdout"].hex(),
                                      "stderr_raw_hex": completed["stderr"].hex()}, sort_keys=True), flush=True)
                artifact_directory = os.environ.get("TRNM_HIA_SHA256_WORDS_ARTIFACT_DIR")
                if artifact_directory:
                    target = Path(artifact_directory).absolute() / label
                    if ROOT in target.parents:
                        raise ValueError("Word boundary evidence must be outside the checkout")
                    target.mkdir(parents=True)
                    files = {
                        "fixture.hepta": ENTRY.encode(), "production.hepta": original,
                        "module.so": native.library.read_bytes(), "worker.py": WORKER.encode(),
                        "test.py": Path(__file__).read_bytes(),
                        "native_support.py": (ROOT / "hia/tests/native_support.py").read_bytes(),
                        "supervision.py": Path(supervision.__file__).read_bytes(),
                        "toolchain.py": (ROOT / "hia/tools/toolchain.py").read_bytes(),
                        "toolchain.lock.json": (ROOT / "hia/toolchain.lock.json").read_bytes(),
                        "native-compiler": Path(os.environ["HIA_NATIVE_COMPILER"]).read_bytes(),
                        "request.json": (json.dumps(request, indent=2) + "\n").encode(),
                        "receipt.json": (json.dumps(native.receipt, indent=2) + "\n").encode(),
                        "stdout.raw": completed["stdout"], "stderr.raw": completed["stderr"],
                        "supervision.json": (json.dumps(completed["receipt"], indent=2) + "\n").encode(),
                        "observations.json": (json.dumps(report, indent=2) + "\n").encode(),
                    }
                    from hepta.hia_agent_assembly import render_assembly
                    compiler_document = dict(native.document)
                    compiler_document["module"] = "selfhost_elf"
                    files["compiler-input.hepta"] = render_assembly(compiler_document).encode()
                    self.assertEqual(hashlib.sha256(files["compiler-input.hepta"]).hexdigest(),
                                     native.receipt["compiler_wire_sha256"])
                    for name, content in files.items():
                        (target / name).write_bytes(content)
                    (target / "manifest.json").write_text(json.dumps({
                        "schema": "trnm.hia.sha256-word-boundary-capture.v2",
                        "exit_code": completed["receipt"]["exit_code"],
                        "cases": len(cases), "source_unchanged": SOURCE.read_bytes() == original,
                        "files": {name: {"bytes": len(content),
                                         "sha256": hashlib.sha256(content).hexdigest()}
                                  for name, content in files.items()}}, indent=2, sort_keys=True) + "\n")
        self.assertEqual(SOURCE.read_bytes(), original)
        return request, completed, observed

    def test_native_words_preserve_every_partial_store_and_bounds_trap(self):
        request, completed, observed = self.observe(label="complete-440")
        receipt = completed["receipt"]
        self.assertEqual(receipt["outcome"], "success", completed["stderr"].decode(errors="replace"))
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(completed["stderr"], b"")
        self.assertEqual(receipt["execution_limit_seconds"], 30)
        self.assertEqual(receipt["cleanup_limit_seconds"], 3)
        self.assertLessEqual(receipt["execution_seconds"], 30)
        self.assertLessEqual(receipt["cleanup_seconds"], 3)
        self.assertTrue(receipt["cleanup_complete"])
        self.assertEqual(receipt["killpg_attempts"], [])
        self.assertEqual(observed["parse_errors"], [])
        self.assertEqual(observed["ready"]["artifact_sha256"], request["sha256"])
        self.assertEqual(observed["ready"]["cases"], 440)
        self.assertEqual(observed["ready"]["dumpable"], 0)
        self.assertEqual(observed["ready"]["child_cpu_limit_seconds"], 1)
        self.assertEqual(observed["ready"]["child_wall_limit_seconds"], 2)
        self.assertEqual(observed["finished"]["artifact_sha256"], request["sha256"])
        self.assertEqual(observed["finished"]["host_compiler_modules_loaded"], [])
        self.assertEqual(observed["finished"]["completed"], 440)
        self.assertEqual(len(observed["cases"]), 440)
        for state, sent, got in zip(observed["states"], request["cases"], observed["cases"]):
            with self.subTest(**sent):
                self.assertEqual(state["state"], "completed")
                self.assertLess(state["completed"]["seconds"], 2)
                self.assertEqual({key: got[key] for key in sent}, sent)
                self.assertTrue(got["input_unchanged"])
                self.assertTrue(got["guards_unchanged"])
                before = bytes((i * 73 + 19) & 255 for i in range(sent["extent"]))
                self.assertEqual(bytes.fromhex(got["work_before_hex"]), before)
                after = bytearray(before)
                fits = sent["offset"] <= len(before) and 8 <= len(before) - sent["offset"]
                result = b"\xa5" * 8
                if sent["mode"] == 1 and sent["offset"] < len(before):
                    count = min(8, len(before) - sent["offset"])
                    after[sent["offset"]:sent["offset"] + count] = sent["value"].to_bytes(8, "little")[:count]
                if fits:
                    self.assertEqual(got["status"], "returned")
                    self.assertEqual(got["exit_code"], 0)
                    result = bytes(8) if sent["mode"] else before[sent["offset"]:sent["offset"] + 8]
                else:
                    self.assertEqual(got["status"], "trapped")
                    self.assertEqual(got["signal"], 4)
                self.assertEqual(bytes.fromhex(got["work_after_hex"]), bytes(after))
                self.assertEqual(bytes.fromhex(got["output_hex"]), result)

    def assert_incomplete_group_cleaned(self, completed, observed, *, expected_state):
        receipt = completed["receipt"]
        self.assertNotEqual(receipt["outcome"], "success")
        self.assertTrue(receipt["cleanup_complete"])
        self.assertTrue(receipt["streams_complete"])
        self.assertTrue(receipt["direct_child_reaped"])
        self.assertTrue(receipt["group_absent"])
        self.assertLessEqual(receipt["cleanup_seconds"], 3)
        self.assertEqual(receipt["cleanup_limit_seconds"], 3)
        self.assertEqual(len(receipt["killpg_attempts"]), 1)
        self.assertEqual(receipt["killpg_attempts"][0]["errno"], 0)
        self.assertEqual(observed["parse_errors"], [])
        self.assertIsNone(observed["finished"])
        self.assertEqual(len(observed["states"]), 440)
        self.assertEqual(len(observed["cases"]), 7)
        self.assertEqual([row["state"] for row in observed["states"]],
                         ["completed"] * 7 + [expected_state] + ["not-started"] * 432)
        child = observed["states"][7]["started"]["pid"]
        self.assertIn(child, [row["pid"] for row in receipt["adopted_reaped"]])
        self.assertFalse(supervision.group_exists(receipt["pgid"]))
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_child_deadline_keeps_all_cases_and_reaps_native_orphan(self):
        _, completed, observed = self.observe(
            label="child-deadline-control", fault={"mode": "child-pause", "index": 7})
        self.assert_incomplete_group_cleaned(completed, observed, expected_state="child-timeout")
        self.assertFalse(completed["receipt"]["timed_out"])
        self.assertEqual(completed["receipt"]["execution_limit_seconds"], 30)
        self.assertTrue(completed["receipt"]["descendants_outlived_leader"])
        self.assertGreaterEqual(observed["states"][7]["timeout"]["seconds"], 2)
        self.assertIn(b"exceeded 2 seconds", completed["stderr"])

    def test_observer_deadline_keeps_progress_and_cleans_whole_group_once(self):
        # A short real deadline exercises the same supervisor. Production
        # complete-440 and the child-deadline control still require exactly 30.
        _, completed, observed = self.observe(
            label="observer-deadline-control",
            fault={"mode": "observer-and-child-pause", "index": 7}, execution_seconds=1)
        self.assert_incomplete_group_cleaned(completed, observed, expected_state="started-unfinished")
        self.assertTrue(completed["receipt"]["timed_out"])
        self.assertEqual(completed["receipt"]["outcome"], "timeout")
        self.assertEqual(completed["receipt"]["execution_limit_seconds"], 1)
        self.assertEqual(completed["stderr"], b"")


if __name__ == "__main__":
    unittest.main()
