"""Original TransferTx methods executed as self-hosted HIA machine code.

The original crate is linked unchanged. Python supplies independently framed
inputs, decimal/hash expectations and adversarial controls; it never implements
the native signing or verification path.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/types/transfer.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-types/src/transfer.rs"
ADAPTER = ROOT / "hia/tests/rust_transfer_reference.rs"
U64 = (1 << 64) - 1
U128 = (1 << 128) - 1
MAGIC = b"TRNMTX1\0"
MESSAGE_BASE = 143360
CANARY = b"\xa5" * 17
WHITESPACE = [9, 10, 11, 12, 13, 32, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
              0x2028, 0x2029, 0x202F, 0x205F, 0x3000]


def request(op, sender="", recipient="", *, amount=1, fee=0, nonce=0,
            signature="", private_key=""):
    values = [value.encode() if isinstance(value, str) else bytes(value)
              for value in (sender, recipient, signature, private_key)]
    if op == 1:
        amount = fee = nonce = 0
    return (struct.pack("<8s5Q", MAGIC, op, *(len(value) for value in values))
            + amount.to_bytes(16, "little") + fee.to_bytes(16, "little")
            + nonce.to_bytes(8, "little") + b"".join(values))


def scratch_extent(raw):
    if len(raw) < 88:
        return 143504
    a, b = struct.unpack_from("<QQ", raw, 16)
    if a > len(raw) or b > len(raw):
        return 143504
    return 143504 + a + b


def original_message(sender, recipient, amount, fee, nonce):
    return (f"trnm-transfer-v1|from={sender}|to={recipient}|amount={amount}"
            f"|fee={fee}|nonce={nonce}").encode()


LARGE_WORKER = r'''
import ctypes,fcntl,hashlib,json,os,resource,sys,time
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
resource.setrlimit(resource.RLIMIT_CPU,(60,60))
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(4,0,0,0,0):raise OSError(ctypes.get_errno(),'disable core dumps')
with open(request['library'],'rb') as stream:binary=stream.read()
if hashlib.sha256(binary).hexdigest()!=request['sha256']:raise ValueError('changed native artifact')
fd=os.memfd_create('trnm-hia-transfer-large',os.MFD_ALLOW_SEALING)
try:
 at=0
 while at<len(binary):
  count=os.write(fd,binary[at:])
  if count<=0:raise OSError('short native artifact capture')
  at+=count
 fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
 library=ctypes.CDLL('/proc/self/fd/'+str(fd))
finally:os.close(fd)
raw=bytes.fromhex(request['input'])
if not len(raw)<=8<<20:raise ValueError('large qualification input exceeds explicit cap')
payloads=[raw,b'\xa5'*request['output_bytes'],b'\x6d'*request['scratch_bytes']]
if any(len(payload)>8<<20 for payload in payloads):raise ValueError('large qualification extent')
copies=[];arguments=[];residues=[]
for payload,residue in zip(payloads,request['residues']):
 storage=ctypes.create_string_buffer(b'\x69'*(len(payload)+32))
 begin=8+((residue-ctypes.addressof(storage))%8)
 address=ctypes.addressof(storage)+begin
 ctypes.memmove(address,payload,len(payload))
 copies.append((storage,begin,len(payload)))
 arguments.extend((ctypes.c_void_p(address),len(payload)));residues.append(address%8)
entry=library.f0
entry.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3
entry.restype=ctypes.c_uint64
start=time.monotonic_ns();result=entry(*arguments);elapsed=time.monotonic_ns()-start
after=[storage.raw[begin:begin+size] for storage,begin,size in copies]
guards=all(storage.raw[:begin]==b'\x69'*begin and
 storage.raw[begin+size:-1]==b'\x69'*(len(storage.raw)-1-begin-size) and
 storage.raw[-1:]==b'\0' for storage,begin,size in copies)
print(json.dumps({'artifact_sha256':request['sha256'],'input_sha256':hashlib.sha256(raw).hexdigest(),
 'input_bytes':len(raw),'value':result&0xffffffff,'abi_status':result>>32,
 'residues':residues,'guards':guards,'input_unchanged':after[0]==raw,
 'output':after[1].hex(),'scratch_sha256':hashlib.sha256(after[2]).hexdigest(),
 'scratch_unchanged':after[2]==payloads[2],'elapsed_ns':elapsed,
 'compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]}))
'''


# This test-only entry dispatches to unchanged production SHA-256 functions.
# It admits bounded, manufactured counters so the actual upper length guard and
# final length encoding can be executed without claiming an exabyte message.
SHA256_BOUNDARY_ENTRY = '''hia-asm.v1 hepta.hia.program.v8 trnm_sha256_boundary_fixture
fn f0(input:readbuf,output:mutbuf,work:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(input:readbuf,output:mutbuf,work:mutbuf)
  extent:usize = buffer.len(input)
  extent64:u64 = int.cast(extent) {"mode":"wrap"}
  header:u64 = const() {"value":32}
  short:bool = compare.lt(extent64,header)
  branch short invalid() read(input,work)
block invalid()
  invalid_code:u32 = const() {"value":199}
  ret(invalid_code)
block read(i:readbuf,w:mutbuf)
  p0:u64 = const() {"value":0}
  p8:u64 = const() {"value":8}
  p16:u64 = const() {"value":16}
  p24:u64 = const() {"value":24}
  op:u64 = call(i,p0) {"function":"tr_read"}
  offset:u64 = call(i,p8) {"function":"tr_read"}
  count:u64 = call(i,p16) {"function":"tr_read"}
  limit:u64 = call(i,p24) {"function":"tr_read"}
  is_init:bool = compare.eq(op,p0)
  branch is_init initialize(w) choose1(i,w,op,offset,count,limit)
block initialize(w0:mutbuf)
  initialized:u64 = call(w0) {"function":"tr_sha_init"}
  jump done(initialized)
block choose1(i1:readbuf,w1:mutbuf,op1:u64,o1:u64,n1:u64,l1:u64)
  one:u64 = const() {"value":1}
  update:bool = compare.eq(op1,one)
  branch update read_full(i1,w1,o1,n1) choose2(i1,w1,op1,o1,n1,l1)
block read_full(ir:readbuf,wr:mutbuf,orr:u64,nr:u64)
  read_result:u64 = call(ir,orr,nr,wr) {"function":"tr_sha_update_full"}
  jump done(read_result)
block choose2(i2:readbuf,w2:mutbuf,op2:u64,o2:u64,n2:u64,l2:u64)
  two:u64 = const() {"value":2}
  update_work:bool = compare.eq(op2,two)
  branch update_work work_full(w2,o2,n2) choose3(i2,w2,op2,o2,n2,l2)
block work_full(ww:mutbuf,ow:u64,nw:u64)
  work_result:u64 = call(ww,ow,nw) {"function":"tr_sha_update_work_full"}
  jump done(work_result)
block choose3(i3:readbuf,w3:mutbuf,op3:u64,o3:u64,n3:u64,l3:u64)
  three:u64 = const() {"value":3}
  final:bool = compare.eq(op3,three)
  branch final final_full(w3) choose4(i3,w3,op3,o3,n3,l3)
block final_full(wf:mutbuf)
  final_result:u64 = call(wf) {"function":"tr_sha_final_full"}
  jump done(final_result)
block choose4(i4:readbuf,w4:mutbuf,op4:u64,o4:u64,n4:u64,l4:u64)
  four:u64 = const() {"value":4}
  limited_read:bool = compare.eq(op4,four)
  branch limited_read read_limit(i4,w4,o4,n4,l4) choose5(i4,w4,op4,o4,n4,l4)
block read_limit(irl:readbuf,wrl:mutbuf,orl:u64,nrl:u64,lrl:u64)
  read_limit_result:u64 = call(irl,orl,nrl,wrl,lrl) {"function":"tr_sha_update_limit"}
  jump done(read_limit_result)
block choose5(i5:readbuf,w5:mutbuf,op5:u64,o5:u64,n5:u64,l5:u64)
  five:u64 = const() {"value":5}
  limited_work:bool = compare.eq(op5,five)
  branch limited_work work_limit(w5,o5,n5,l5) choose6(w5,op5,o5,l5)
block work_limit(wwl:mutbuf,owl:u64,nwl:u64,lwl:u64)
  work_limit_result:u64 = call(wwl,owl,nwl,lwl) {"function":"tr_sha_update_work_limit"}
  jump done(work_limit_result)
block choose6(w6:mutbuf,op6:u64,o6:u64,l6:u64)
  six:u64 = const() {"value":6}
  limited_final:bool = compare.eq(op6,six)
  branch limited_final final_limit(w6,l6) choose7(w6,op6,o6,l6)
block final_limit(wfl:mutbuf,lfl:u64)
  final_limit_result:u64 = call(wfl,lfl) {"function":"tr_sha_final_limit"}
  jump done(final_limit_result)
block choose7(w7:mutbuf,op7:u64,o7:u64,l7:u64)
  seven:u64 = const() {"value":7}
  limited_feed:bool = compare.eq(op7,seven)
  branch limited_feed feed_limit(w7,o7,l7) invalid()
block feed_limit(wb:mutbuf,byte:u64,lb:u64)
  feed_result:u64 = call(wb,byte,lb) {"function":"tr_sha_feed_limit"}
  jump done(feed_result)
block done(status:u64)
  result:u32 = int.cast(status) {"mode":"wrap"}
  ret(result)
end
'''


class TransferNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["bash", "scripts/project-preflight.sh", "--audit"],
                       cwd=ROOT, check=True, capture_output=True, text=True)
        cls.original_sha256 = hashlib.sha256(ORIGINAL.read_bytes()).hexdigest()
        cls._temporary = tempfile.TemporaryDirectory(prefix="trnm-hia-transfer-original-")
        cls.original = Path(cls._temporary.name) / "original-transfer"
        library_name = os.environ.get("TRNM_HIA_RUST_TYPES_RLIB")
        if not library_name:
            cls._temporary.cleanup()
            raise RuntimeError("TRNM_HIA_RUST_TYPES_RLIB must identify the unchanged original crate")
        library = Path(library_name).resolve(strict=True)
        deps = library.parent / "deps"
        if not deps.is_dir():
            cls._temporary.cleanup()
            raise RuntimeError("Original trnm-types dependency directory is missing")
        cls.library_sha256 = hashlib.sha256(library.read_bytes()).hexdigest()
        cls.rustc_version = subprocess.run(["rustc", "--version"], check=True,
                                          capture_output=True, text=True).stdout.strip()
        result = subprocess.run(["rustc", "--edition=2021", "-O", str(ADAPTER),
                                 "--extern", "trnm_types=" + str(library),
                                 "-L", "dependency=" + str(deps), "-o", str(cls.original)],
                                cwd=ROOT, capture_output=True, text=True, check=False)
        if result.returncode:
            cls._temporary.cleanup()
            raise RuntimeError("Actual original TransferTx adapter failed: " + result.stderr)
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))
        cls.native_calls = 0
        cls.large_pointer_calls = 0
        cls.large_observations = []
        cls.legacy_sha256_artifact = None
        cls.legacy_sha256_receipt = None
        cls.sha256_boundary_artifact = None
        cls.sha256_boundary_receipt = None
        cls.sha256_boundary_source = None
        cls.sha256_boundary_observations = []
        cls.original_calls = 0
        cls.observations = []
        cls.reference_observations = []
        cls.seed = "11" * 32
        first = cls.reference([request(2, "temporary", "recipient", private_key=cls.seed)])[0]
        assert first[0] == 0
        public_key = bytes.fromhex(first[1].decode().split(":")[1])
        cls.sender = "trnm1" + hashlib.sha256(public_key).digest()[:20].hex()
        cls.recipient = "trnm1" + "bb" * 20
        cls.signature = cls.reference([request(2, cls.sender, cls.recipient, amount=10,
                                               fee=1, nonce=1, private_key=cls.seed)])[0][1].decode()

    @classmethod
    def tearDownClass(cls):
        try:
            if hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() != cls.original_sha256:
                raise AssertionError("Original TransferTx source changed during qualification")
            output = os.environ.get("TRNM_HIA_TRANSFER_REPORT_DIR")
            if output:
                destination = Path(output).resolve()
                destination.mkdir(parents=True, exist_ok=False)
                shutil.copyfile(cls.native.library, destination / "transfer.so")
                shutil.copyfile(cls.original, destination / "original-transfer")
                shutil.copyfile(ADAPTER, destination / ADAPTER.name)
                shutil.copyfile(ORIGINAL, destination / "original-transfer.rs")
                if cls.legacy_sha256_artifact is not None:
                    (destination / "legacy-sha256-stream.so").write_bytes(cls.legacy_sha256_artifact)
                if cls.sha256_boundary_artifact is not None:
                    (destination / "sha256-boundary.so").write_bytes(cls.sha256_boundary_artifact)
                    (destination / "sha256-boundary.hepta").write_text(SHA256_BOUNDARY_ENTRY)
                    (destination / "sha256-stream-tested.hepta").write_bytes(cls.sha256_boundary_source)
                report = {"schema": "trnm.hia.transfer-development.v1",
                          "native_calls": cls.native_calls, "original_calls": cls.original_calls,
                          "large_pointer_calls": cls.large_pointer_calls,
                          "large_observations": cls.large_observations,
                          "legacy_sha256_build_receipt": cls.legacy_sha256_receipt,
                          "sha256_boundary_build_receipt": cls.sha256_boundary_receipt,
                          "sha256_boundary_observations": cls.sha256_boundary_observations,
                          "sha256_boundary_manufactured_contexts": True,
                          "sha256_exabyte_message_executed": False,
                          "original_source_sha256": cls.original_sha256,
                          "original_rlib_sha256": cls.library_sha256,
                          "original_adapter_sha256": hashlib.sha256(ADAPTER.read_bytes()).hexdigest(),
                          "original_binary_sha256": hashlib.sha256(cls.original.read_bytes()).hexdigest(),
                          "rustc_version": cls.rustc_version,
                          "build_receipt": cls.native.receipt,
                          "native_observations": cls.observations,
                          "original_observations": cls.reference_observations,
                          "whole_chain_native": False, "retirement_accepted": False}
                (destination / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        finally:
            cls.native.close()
            cls._temporary.cleanup()

    @classmethod
    def reference(cls, requests):
        result = subprocess.run([str(cls.original)], input="".join(raw.hex() + "\n" for raw in requests),
                                capture_output=True, text=True, check=True, timeout=60)
        lines = result.stdout.splitlines()
        if len(lines) != len(requests) or result.stderr:
            raise AssertionError("Incomplete original method observations")
        answers = []
        for raw, line in zip(requests, lines):
            code, payload = line.split(":", 1)
            answer = (int(code), bytes.fromhex(payload))
            cls.reference_observations.append({"request_sha256": hashlib.sha256(raw).hexdigest(),
                                              "status": answer[0], "output": answer[1].hex()})
            answers.append(answer)
        cls.original_calls += len(requests)
        return answers

    def check(self, raw, expected=None, *, capacity=None, scratch=None, wipe=False):
        if expected is None:
            expected = self.reference([raw])[0]
        status, payload = expected
        op = int.from_bytes(raw[8:16], "little") if len(raw) >= 16 else -1
        published = struct.pack("<Q", len(payload)) + payload if status == 0 and op != 3 else b""
        if capacity is None:
            capacity = len(published) + len(CANARY)
        if scratch is None:
            scratch = b"\x6d" * scratch_extent(raw)
        observed = self.native.call("f0", [raw, b"\xa5" * capacity, scratch], timeout=60).require_returned()
        self.assertEqual(observed.value, status, raw[:100].hex())
        self.assertEqual(observed.arguments[0], raw)
        self.assertEqual(observed.arguments[1], published + b"\xa5" * (capacity - len(published)))
        self.assertEqual(len(observed.arguments[2]), len(scratch))
        if wipe:
            self.assertEqual(observed.arguments[2][:141568], bytes(141568))
        type(self).native_calls += 1
        type(self).observations.append({"request_sha256": hashlib.sha256(raw).hexdigest(),
                                       "request_bytes": len(raw), "operation": op,
                                       "status": observed.value, "output": published.hex(),
                                       "output_capacity": capacity, "scratch_bytes": len(scratch),
                                       "scratch_sha256": hashlib.sha256(observed.arguments[2]).hexdigest(),
                                       "private_work_wiped": bool(wipe)})
        return payload

    def large_call(self, module, raw, *, output_bytes, scratch_bytes, expected, residues=(1, 3, 5)):
        sent = {"library": str(module.library), "sha256": module.artifact_sha256,
                "input": raw.hex(), "output_bytes": output_bytes, "scratch_bytes": scratch_bytes,
                "residues": list(residues)}
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", LARGE_WORKER],
                                input=json.dumps(sent), capture_output=True, text=True,
                                timeout=60, check=True)
        self.assertEqual(result.stderr, "")
        observed = json.loads(result.stdout)
        self.assertEqual(observed["artifact_sha256"], module.artifact_sha256)
        self.assertEqual(observed["input_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(observed["input_bytes"], len(raw))
        self.assertEqual(observed["abi_status"], 0)
        self.assertEqual(observed["value"], expected[0])
        self.assertEqual(observed["output"], expected[1].hex())
        self.assertTrue(observed["guards"])
        self.assertTrue(observed["input_unchanged"])
        self.assertEqual(observed["residues"], list(residues))
        self.assertEqual(observed["compiler_modules_loaded"], [])
        type(self).large_pointer_calls += 1
        type(self).large_observations.append(observed)
        return observed

    def test_sha256_full_domain_counter_bounds_and_prewrite_refusal(self):
        from hia.tools import toolchain

        production = ROOT / "hia/src/crypto/sha256_stream.hepta"
        original_source = production.read_bytes()
        maximum = (1 << 61) - 1
        output = b"\xa5" * 71

        def words(op, offset=0, count=0, limit=maximum):
            return struct.pack("<4Q", op, offset, count, limit)

        # Only the fixture entry is new. Every hashing function is selected
        # verbatim from a captured production source, checked independently by
        # Core, and emitted by the same pinned native compiler as TransferTx.
        with tempfile.TemporaryDirectory(prefix="trnm-sha256-boundary-") as temporary:
            root = Path(temporary)
            dependency = root / "src/crypto/sha256_stream.hepta"
            dependency.parent.mkdir(parents=True)
            dependency.write_bytes(original_source)
            entry = root / "src/boundary.hepta"
            entry.write_text(SHA256_BOUNDARY_ENTRY)
            manifest = {"schema": "trnm.hia.component-includes.v1", "includes": {
                "src/boundary.hepta": [{"source": "src/crypto/sha256_stream.hepta", "functions": [
                    "tr_sha_init", "tr_sha_update_full", "tr_sha_update_work_full", "tr_sha_final_full",
                    "tr_sha_update_limit", "tr_sha_update_work_limit", "tr_sha_feed_limit",
                    "tr_sha_final_limit", "tr_sha_compress", "tr_sha_rotr", "tr_read", "tr_get", "tr_put",
                ]}]}}
            (root / "components.json").write_text(json.dumps(manifest))
            with patch.object(toolchain, "HIA_ROOT", root):
                native = NativeModule(entry, byte_exports=("f0",), backend="selfhost",
                                      fixture_owner=Path(__file__))
            with native:
                type(self).sha256_boundary_artifact = native.library.read_bytes()
                type(self).sha256_boundary_receipt = native.receipt
                type(self).sha256_boundary_source = original_source

                def call(label, raw, arena, status=0, unchanged=False):
                    seen = native.call("f0", [raw, output, arena]).require_returned()
                    self.assertEqual(seen.value, status, label)
                    self.assertEqual(seen.arguments[0], raw, label)
                    self.assertEqual(seen.arguments[1], output, label)
                    self.assertEqual(seen.arguments[2][1208:], arena[1208:], label)
                    if status or unchanged:
                        self.assertEqual(seen.arguments[2], arena, label)
                    type(self).sha256_boundary_observations.append({
                        "case": label, "input_sha256": hashlib.sha256(raw).hexdigest(),
                        "scratch_bytes": len(arena), "status": seen.value,
                        "before_sha256": hashlib.sha256(arena).hexdigest(),
                        "after_sha256": hashlib.sha256(seen.arguments[2]).hexdigest(),
                        "scratch_unchanged": seen.arguments[2] == arena,
                    })
                    return seen.arguments[2]

                initialized = call("initialize real native context", words(0), b"\x6d" * 1280)

                def state(count, pending, finalized=0):
                    arena = bytearray(initialized)
                    struct.pack_into("<QQ", arena, 1088, count, pending)
                    struct.pack_into("<Q", arena, 1200, finalized)
                    arena[1208] = ord("x")
                    return bytes(arena)

                # Sanity-check both borrowed-input routes before manufacturing
                # counts. The bytes of these small messages really are hashed.
                for op, offset, expected in ((1, 32, b"abc"), (2, 1208, b"x")):
                    before = state(0, 0)
                    updated = call(f"ordinary update route {op}", words(op, offset, len(expected)) + b"abc", before)
                    finished = call(f"ordinary final route {op}", words(3), updated)
                    self.assertEqual(finished[1168:1200], hashlib.sha256(expected).digest())
                    call(f"reject update after final route {op}", words(op, offset, 0), finished, 102)
                    call(f"reject second final route {op}", words(3), finished, 102)

                almost = state(maximum - 1, 62)
                at_maximum = state(maximum, 63)
                for op, offset in ((1, 32), (2, 1208)):
                    last = call(f"last legal byte route {op}", words(op, offset, 1) + b"x", almost)
                    self.assertEqual(struct.unpack_from("<QQ", last, 1088), (maximum, 63))
                    self.assertEqual(last[1166], ord("x"))
                    call(f"count overflow after last byte route {op}", words(op, offset, 1) + b"x", last, 102)
                    call(f"two-byte overflow is atomic route {op}", words(op, offset, 2) + b"xy", almost, 102)
                    call(f"zero update at maximum route {op}", words(op, offset, 0), at_maximum, unchanged=True)

                # The initialized compression state represents no exabyte
                # prefix: this asserts counter guards and encoded bit length,
                # deliberately making no expected-digest claim for this state.
                finished = call("maximum count final length", words(3), at_maximum)
                self.assertEqual(finished[1160:1168], bytes.fromhex("fffffffffffffff8"))
                self.assertEqual(struct.unpack_from("<QQ", finished, 1088), (maximum, 0))
                self.assertEqual(struct.unpack_from("<Q", finished, 1200)[0], 1)
                call("feed refuses exhausted maximum", words(7, ord("x")), at_maximum, 102)

                for bad_count, pending in ((maximum + 1, 0), (U64, 63)):
                    bad = state(bad_count, pending)
                    for op, offset in ((1, 32), (2, 1208), (3, 0)):
                        call(f"invalid count {bad_count} route {op}", words(op, offset, 0), bad, 102)
                for pending, flag in ((64, 0), (U64, 0), (0, 1), (0, U64)):
                    bad = state(0, pending, flag)
                    for op, offset in ((1, 32), (2, 1208), (3, 0)):
                        call(f"invalid metadata {pending}:{flag} route {op}", words(op, offset, 0), bad, 102)

                # The generic limit guard precedes buffer access. A lower
                # valid limit retains distinct single-update and accumulated
                # count refusals, and rejects before touching the context.
                for limit in (maximum + 1, U64):
                    for op in (4, 5, 6, 7):
                        call(f"invalid limit {limit} route {op}", words(op, U64, U64, limit), b"", 102)
                call("single update exceeds chosen limit", words(4, 32, 8, 7) + b"abcdefgh", initialized, 101)
                call("same-arena update exceeds chosen limit", words(5, 1208, 8, 7), initialized, 101)
                call("accumulated count exceeds chosen limit", words(4, 32, 1, 7) + b"x", state(7, 7), 102)
                call("zero-sized limit empty update", words(4, 32, 0, 0), initialized, unchanged=True)
                zero_finished = call("zero-sized limit empty final", words(6, limit=0), initialized)
                self.assertEqual(zero_finished[1168:1200], hashlib.sha256(b"").digest())
                call("zero-sized limit feed refusal", words(7, ord("x"), limit=0), initialized, 102)

                for op in (1, 2, 3):
                    call(f"short context route {op}", words(op, 32 if op == 1 else 1208), initialized[:1207], 100)
                for offset in (0, 1207, len(initialized) + 1, U64):
                    call(f"work overlap or range {offset}", words(2, offset, 0), initialized, 100)
                call("work exact context end", words(2, 1208, 0), initialized, unchanged=True)
                call("work exact arena end", words(2, len(initialized), 0), initialized, unchanged=True)
                call("work beyond arena end", words(2, len(initialized), 1), initialized, 101)
                call("read offset before metadata checks", words(1, U64, 0), state(U64, 63), 100)
                call("read extent before metadata checks", words(1, 32, U64), state(U64, 63), 101)
                call("work extent before metadata checks", words(2, 1208, U64), state(U64, 63), 101)
        self.assertEqual(production.read_bytes(), original_source, "Production SHA-256 changed during boundary execution")

    def test_address_inputs_above_transport_cap_have_original_hashes(self):
        for size in [2098177, 4194561]:
            key = bytes((index * 131 + 17) & 255 for index in range(size))
            raw = request(1, key)
            expected = self.reference([raw])[0]
            digest_address = ("trnm1" + hashlib.sha256(key).digest()[:20].hex()).encode()
            self.assertEqual(expected, (0, digest_address))
            output = struct.pack("<Q", 45) + digest_address + CANARY
            self.large_call(self.native, raw, output_bytes=len(output), scratch_bytes=143504,
                            expected=(0, output))

    def test_original_transport_sha256_cap_and_error_order_are_unchanged(self):
        with NativeModule(ROOT / "hia/src/crypto/sha256_stream.hepta", byte_exports=("f0",)) as module:
            type(self).legacy_sha256_artifact = module.library.read_bytes()
            type(self).legacy_sha256_receipt = module.receipt
            limit = 2098176
            payload = bytes((index * 131 + 17) & 255 for index in range(limit))
            expected = hashlib.sha256(payload).digest() + struct.pack("<QQ", limit, 1) + b"\xa5" * 32
            self.large_call(module, struct.pack("<Q", limit) + payload,
                            output_bytes=80, scratch_bytes=1208, expected=(0, expected))
            cases = [(struct.pack("<Q", 65536) + payload + b"x", 103),
                     (struct.pack("<Q", limit + 1), 102), (bytes(8), 102), (bytes(7), 101)]
            for raw, code in cases:
                seen = self.large_call(module, raw, output_bytes=80, scratch_bytes=1208,
                                       expected=(code, b"\xa5" * 80))
                self.assertTrue(seen["scratch_unchanged"])

    def test_signing_message_exact_strings_and_full_width_numbers(self):
        values = [0, 1, 9, 10, (1 << 32) - 1, 1 << 64, (1 << 127), U128]
        texts = ["", "alice", "a|to=b", "\0", "链/é/😀", "\u2003x\u00a0"]
        rng = random.Random(0x54584631)
        cases = [(a, b, n, values[-j - 1], U64 if j % 2 else 0)
                 for j, n in enumerate(values) for a, b in zip(texts, reversed(texts))]
        cases += [(texts[rng.randrange(len(texts))], texts[rng.randrange(len(texts))],
                   rng.getrandbits(128), rng.getrandbits(128), rng.getrandbits(64)) for _ in range(24)]
        requests = [request(0, a, b, amount=n, fee=f, nonce=k) for a, b, n, f, k in cases]
        originals = self.reference(requests)
        for raw, expected, args in zip(requests, originals, cases):
            self.assertEqual(expected, (0, original_message(*args)))
            self.check(raw, expected)

    def test_address_hashes_exact_arbitrary_public_key_bytes(self):
        cases = [b"", bytes(32), bytes(range(32)), bytes(range(256)), b"x" * 131073,
                 b"\x80" * 262145, bytes(range(17))]
        requests = [request(1, raw) for raw in cases]
        originals = self.reference(requests)
        for raw, key, expected in zip(requests, cases, originals):
            self.assertEqual(expected, (0, ("trnm1" + hashlib.sha256(key).digest()[:20].hex()).encode()))
            self.check(raw, expected)

    def test_signatures_match_actual_original_for_distinct_seeds(self):
        for n, seed in enumerate([bytes(32), bytes([17]) * 32, bytes(range(32)), bytes([255]) * 32]):
            raw = request(2, self.sender, "链|recipient\0", amount=U128 - n,
                          fee=1 << (64 + n), nonce=U64 - n, private_key=seed.hex().upper())
            self.check(raw, wipe=True)

    def test_native_sign_then_strict_verify_and_original_readback(self):
        raw = request(2, self.sender, self.recipient, amount=10, fee=1, nonce=1,
                      private_key=self.seed)
        signature = self.check(raw, wipe=True).decode()
        self.assertEqual(signature, self.signature)
        self.check(request(3, self.sender, self.recipient, amount=10, fee=1, nonce=1,
                           signature=signature))
        algo, key, signed = signature.split(":")
        self.check(request(3, self.sender, self.recipient, amount=10, fee=1, nonce=1,
                           signature=":".join([algo, key.upper(), signed.upper()])))
        for key, value in [("amount", 11), ("fee", 2), ("nonce", 2)]:
            fields = {"amount": 10, "fee": 1, "nonce": 1}
            fields[key] = value
            self.check(request(3, self.sender, self.recipient, signature=signature, **fields))

    def test_unicode_whitespace_and_original_error_precedence(self):
        for value in WHITESPACE:
            text = chr(value)
            self.check(request(3, text, "", amount=0), (1, b""))
            self.check(request(3, "from", text, amount=0), (2, b""))
            self.check(request(3, "from", "to", signature=text), (5, b""))
        requests = [request(3, "same", "same", amount=0),
                    request(3, "from", "to", amount=0),
                    request(3, "\u200b", "to", signature="x"),
                    request(3, "\ufeff", "to", signature="x"),
                    request(3, self.sender + " ", self.recipient, amount=10, fee=1, nonce=1,
                            signature=self.signature)]
        for raw in requests:
            self.check(raw)
        # The whitespace table is also compared to the unchanged Rust method.
        refs = self.reference([request(3, chr(value), "x") for value in WHITESPACE])
        self.assertEqual(refs, [(1, b"")] * len(WHITESPACE))

    def test_signature_text_and_private_key_refusals(self):
        base = dict(amount=10, fee=1, nonce=1)
        invalid = ["x", self.signature + ":", self.signature[:-1], "ED25519" + self.signature[7:],
                   self.signature.replace(":", "/", 1), " " + self.signature,
                   self.signature[:72] + "/" + self.signature[73:]]
        for p in [8, 40, 71, 73, 105, 200]:
            for bad in ["g", "\x00", ":", " ", "é"]:
                invalid.append(self.signature[:p] + bad + self.signature[p + 1:])
        for value in invalid:
            self.check(request(3, self.sender, self.recipient, signature=value, **base))
        for value in ["", "00" * 31, "00" * 33, "g" * 64, ":" * 64, "é" * 32,
                      " " * 64, "\x00" * 64, "0" * 63 + "G"]:
            self.check(request(2, "", "", amount=0, private_key=value))

    def test_all_ascii_nonhex_bytes_are_errors_without_native_traps(self):
        valid = set(b"0123456789abcdefABCDEF")
        rows = []
        for value in range(128):
            if value in valid:
                continue
            bad = chr(value)
            rows.append(request(2, self.sender, self.recipient, private_key=bad + self.seed[1:]))
            for at in [8, 73]:
                signature = self.signature[:at] + bad + self.signature[at + 1:]
                rows.append(request(3, self.sender, self.recipient, amount=10, fee=1, nonce=1,
                                    signature=signature))
        originals = self.reference(rows)
        self.assertEqual(originals, [(6, b"")] * len(rows))
        for raw, expected in zip(rows, originals):
            self.check(raw, expected)

    def test_strict_ed25519_weak_keys_and_scalar_canonicality(self):
        algo, public, signature = self.signature.split(":")
        original_sig = bytes.fromhex(signature)
        order = (1 << 252) + 27742317777372353535851937790883648493
        for scalar in [order, order + 1, (1 << 256) - 1]:
            signed = original_sig[:32] + scalar.to_bytes(32, "little")
            self.check(request(3, self.sender, self.recipient, amount=10, fee=1, nonce=1,
                               signature=f"{algo}:{public}:{signed.hex()}"))
        weak = [bytes(32), b"\x01" + bytes(31), ((1 << 255) - 19).to_bytes(32, "little"),
                ((1 << 255) - 20).to_bytes(32, "little"), b"\xff" * 32]
        for key in weak:
            sender = "trnm1" + hashlib.sha256(key).digest()[:20].hex()
            self.check(request(3, sender, self.recipient, amount=1,
                               signature=f"ed25519:{key.hex()}:{bytes(64).hex()}"))
        for point in weak:
            signed = point + original_sig[32:]
            self.check(request(3, self.sender, self.recipient, amount=10, fee=1, nonce=1,
                               signature=f"{algo}:{public}:{signed.hex()}"))

    def test_long_messages_use_continuous_sha512(self):
        for size in [131009, 262177]:
            recipient = "x" * size
            signed = self.check(request(2, self.sender, recipient, amount=U128, fee=U128,
                                        nonce=U64, private_key=self.seed), wipe=True).decode()
            self.check(request(3, self.sender, recipient, amount=U128, fee=U128,
                               nonce=U64, signature=signed))
            self.check(request(3, self.sender, recipient[:-1] + "y", amount=U128, fee=U128,
                               nonce=U64, signature=signed))

    def test_full_width_message_uses_exact_scratch_boundary(self):
        fields = {"amount": U128, "fee": U128, "nonce": U64}
        message = request(0, self.sender, self.recipient, **fields)
        expected = original_message(self.sender, self.recipient, U128, U128, U64)
        self.assertEqual(len(expected), 144 + len(self.sender) + len(self.recipient))
        self.check(message, (0, expected))
        self.check(message, (102, b""), scratch=bytes(scratch_extent(message) - 1))
        sign = request(2, self.sender, self.recipient, private_key=self.seed, **fields)
        signature = self.check(sign, wipe=True).decode()
        self.check(sign, (102, b""), scratch=bytes(scratch_extent(sign) - 1))
        verify = request(3, self.sender, self.recipient, signature=signature, **fields)
        self.check(verify)
        self.check(verify, (102, b""), scratch=bytes(scratch_extent(verify) - 1))

    def test_frame_utf8_and_capacity_refuse_without_publication(self):
        good = request(0, "from", "to", amount=U128)
        for length in [0, 1, 7, 8, 15, 16, 31, 47, 63, 79, 87]:
            self.check(good[:length], (100, b""))
        for offset in [0, 8, 16, 24, 32, 40]:
            bad = bytearray(good)
            bad[offset:offset + 8] = bytes([255]) * 8
            self.check(bytes(bad), (100, b""))
        self.check(good + b"extra", (100, b""))
        for invalid in [b"\xff", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xc2"]:
            self.check(request(0, invalid, "to"), (101, b""))
        self.check(good, (102, b""), capacity=0)
        self.check(good, (102, b""), scratch=bytes(143503))
        self.check(good, (102, b""), scratch=bytes(scratch_extent(good) - 1))
        self.check(request(1, b"raw", recipient="unexpected"), (100, b""))
        self.check(request(2, self.sender, self.recipient, private_key=self.seed),
                   (102, b""), capacity=208)
        self.check(request(1, b"raw"), (102, b""), capacity=52)


if __name__ == "__main__":
    unittest.main()
