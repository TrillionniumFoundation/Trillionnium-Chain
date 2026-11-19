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
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.tests.native_support import NativeModule

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
raw=open(request['library'],'rb').read()
assert hashlib.sha256(raw).hexdigest()==request['sha256']
fd=os.memfd_create('trnm-sha-words',os.MFD_ALLOW_SEALING)
position=0
while position<len(raw):
 count=os.write(fd,raw[position:]);assert count>0;position+=count
fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
library=ctypes.CDLL('/proc/self/fd/'+str(fd))
fn=library.f0;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint64
answers=[]
try:
 for row in request['cases']:
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
    resource.setrlimit(resource.RLIMIT_CPU,(1,1));result=fn(*args)
    os._exit(0 if result==0 else 81)
   except BaseException:os._exit(82)
  started=time.monotonic();status=None
  while status is None:
   got,value=os.waitpid(pid,os.WNOHANG)
   if got:status=value;break
   if time.monotonic()-started>2:
    os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);raise TimeoutError('native fixed-width helper exceeded 2 seconds')
   time.sleep(0.001)
  after=[bytes(memory) for memory in mappings]
  if os.WIFSIGNALED(status):outcome={'status':'trapped','signal':os.WTERMSIG(status)}
  else:outcome={'status':'returned','exit_code':os.WEXITSTATUS(status)}
  answers.append({**row,**outcome,'input_unchanged':after[0]==before[0],
    'guards_unchanged':all(a[:8]==b[:8] and a[-8:]==b[-8:] for a,b in zip(after,before)),
    'output_hex':after[1][8:-8].hex(),'work_before_hex':payloads[2].hex(),'work_after_hex':after[2][8:-8].hex()})
  del view;views.clear()
  for memory in mappings:memory.close()
finally:os.close(fd)
print(json.dumps({'artifact_sha256':request['sha256'],'cases':answers,'host_compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]}))
'''


class Sha256WordNativeTests(unittest.TestCase):
    def test_native_words_preserve_every_partial_store_and_bounds_trap(self):
        from hia.tools import toolchain

        original = SOURCE.read_bytes()
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
                completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", WORKER],
                                           input=json.dumps(request), text=True,
                                           capture_output=True, timeout=30, check=False)
                artifact_directory = os.environ.get("TRNM_HIA_SHA256_WORDS_ARTIFACT_DIR")
                if artifact_directory:
                    target = Path(artifact_directory).absolute()
                    if ROOT in target.parents:
                        raise ValueError("Word boundary evidence must be outside the checkout")
                    target.mkdir(parents=True)
                    files = {
                        "fixture.hepta": ENTRY.encode(), "production.hepta": original,
                        "module.so": native.library.read_bytes(), "worker.py": WORKER.encode(),
                        "test.py": Path(__file__).read_bytes(),
                        "native_support.py": (ROOT / "hia/tests/native_support.py").read_bytes(),
                        "toolchain.py": (ROOT / "hia/tools/toolchain.py").read_bytes(),
                        "toolchain.lock.json": (ROOT / "hia/toolchain.lock.json").read_bytes(),
                        "native-compiler": Path(os.environ["HIA_NATIVE_COMPILER"]).read_bytes(),
                        "request.json": (json.dumps(request, indent=2) + "\n").encode(),
                        "receipt.json": (json.dumps(native.receipt, indent=2) + "\n").encode(),
                        "stdout.raw": completed.stdout.encode(), "stderr.raw": completed.stderr.encode(),
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
                        "schema": "trnm.hia.sha256-word-boundary-capture.v1",
                        "exit_code": completed.returncode,
                        "cases": len(cases), "source_unchanged": SOURCE.read_bytes() == original,
                        "files": {name: {"bytes": len(content),
                                         "sha256": hashlib.sha256(content).hexdigest()}
                                  for name, content in files.items()}}, indent=2, sort_keys=True) + "\n")
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                observed = json.loads(completed.stdout)
                self.assertEqual(observed["artifact_sha256"], native.artifact_sha256)
                self.assertEqual(observed["host_compiler_modules_loaded"], [])
                self.assertEqual(len(observed["cases"]), len(cases))
                for sent, got in zip(cases, observed["cases"]):
                    with self.subTest(**sent):
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
                print(json.dumps({"schema": "trnm.hia.sha256-word-boundary-observations.v1",
                                  "status": "PASS", "production_sha256": hashlib.sha256(original).hexdigest(),
                                  "native_calls": len(cases), **observed}), flush=True)
        self.assertEqual(SOURCE.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
