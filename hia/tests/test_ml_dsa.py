"""Actual HIA ML-DSA-65/87, official vectors and mandatory unchanged Rust.

Python frames bytes and controls tests. It never signs, verifies, samples a
production polynomial, or supplies a fallback result. Expanded-key operations
are explicitly diagnostic; the Candidate interface uses a private owned arena.
The exact scope and lifetime requirements are in crypto/ML_DSA.md.
"""
from __future__ import annotations

import base64
from collections import Counter
from contextlib import ExitStack
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.tests.native_support import NativeModule, unlinked_path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "hia/tests/vectors/ml_dsa_acvp_975de31.json.xz"
VECTOR_XZ_SHA = "d83ddcc98649e99c270f6d5791d074f80437aa63cd0d92e7663822ead5f9f8df"
VECTOR_SHA = "7bbcb89c57a046985587d7f66e5e013e597679fe24794c2ccd928b681aab1232"
PIN = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCES = {name: ROOT / ("hia/src/crypto/ml_dsa" + suffix + ".hepta") for name, suffix in
           (("verify", ""), ("keygen", "_keygen"), ("sign", "_sign"), ("owner", "_owner"))}
PARAMETERS = {65: (1952, 3309, 4032, 6, 5, 55, 196, 48),
              87: (2592, 4627, 4896, 8, 7, 75, 120, 64)}
WORK = {"verify": 32768, "keygen": 65536, "sign": 131072, "owner": 131072}
REFUSED = 0xfffffffd
U64 = (1 << 64) - 1
TAIL = b"\xa5" * 17


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reply(code=0, expected=0, actual=0):
    return struct.pack("<QQQ", code, expected, actual)


def change(raw, at, value):
    return raw[:at] + value + raw[at + len(value):]


def flip(raw, at, bit=0):
    return change(raw, at, bytes((raw[at] ^ (1 << bit),)))


def verify_request(parameter, public_key, signature, message=b"", context=b"", profile=0):
    return (b"TRNMDSA1" + bytes((0, parameter, profile)) + bytes(5)
            + struct.pack("<6Q", len(public_key), len(signature), len(message), len(context), 0, 0)
            + public_key + signature + context + message)


def keygen_request(parameter, seed):
    return b"TRNMDKG1" + bytes((parameter,)) + bytes(7) + seed


def sign_request(parameter, secret_key, message=b"", context=b"", randomizer=bytes(32), profile=1):
    return (b"TRNMDSG1" + bytes((parameter, profile)) + bytes(6)
            + struct.pack("<6Q", len(secret_key), len(message), len(context), len(randomizer), 0, 0)
            + secret_key + context + message + randomizer)


def owner_request(operation, parameter=0, *, message=b"", signature=b"", public_key=b"", expected=0, actual=0):
    return (b"TRNMDSO1" + bytes((operation, parameter)) + bytes(6)
            + struct.pack("<6Q", len(message), len(signature), len(public_key), expected, actual, 0)
            + public_key + message + signature)


def put_coefficient(signature, challenge_bytes, index, value):
    """Mutate one encoded 20-bit test coefficient, independently of HIA packing."""
    raw = bytearray(signature)
    first_bit = challenge_bytes * 8 + index * 20
    for bit in range(20):
        at, shift = divmod(first_bit + bit, 8)
        raw[at] = (raw[at] & ~(1 << shift)) | (((value >> bit) & 1) << shift)
    return bytes(raw)


def candidate_inputs():
    return [{"op": "sign", "parameter": parameter, "seed": seed.hex(), "message": message.hex()}
            for parameter in PARAMETERS
            for seed in (bytes(32), bytes(range(32)), b"\xff" * 32)
            for message in (b"", bytes(range(256)), bytes(range(256)) * 256)]


# This test entry exposes the unchanged sampler at its last legal two-byte
# nonce. It does not claim to execute 9363 actual rejection attempts or to turn
# the original crate's unreachable/panic path into an ordinary Rust Result.
NONCE_ENTRY = '''hia-asm.v1 hepta.hia.program.v8 trnm_ml_dsa_nonce_fixture
fn f0(input:readbuf,output:mutbuf,work:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(input:readbuf,output:mutbuf,work:mutbuf)
  size:usize = buffer.len(input)
  size64:u64 = int.cast(size) {"mode":"wrap"}
  sixteen:u64 = const() {"value":16}
  wrong:bool = compare.ne(size64,sixteen)
  branch wrong invalid() capacity(input,work)
block capacity(i:readbuf,w:mutbuf)
  extent:usize = buffer.len(w)
  extent64:u64 = int.cast(extent) {"mode":"wrap"}
  minimum:u64 = const() {"value":65536}
  short:bool = compare.lt(extent64,minimum)
  branch short invalid() decode(i,w)
block decode(ii:readbuf,ww:mutbuf)
  zero:u64 = const() {"value":0}
  eight:u64 = const() {"value":8}
  nonce:u64 = call(ii,zero) {"function":"md_read64"}
  count:u64 = call(ii,eight) {"function":"md_read64"}
  maximum:u64 = const() {"value":65536}
  beyond:bool = compare.gt(nonce,maximum)
  branch beyond invalid() select(ww,nonce,count)
block select(w0:mutbuf,n0:u64,c0:u64)
  five:u64 = const() {"value":5}
  seven:u64 = const() {"value":7}
  is5:bool = compare.eq(c0,five)
  is7:bool = compare.eq(c0,seven)
  valid:bool = bool.or(is5,is7)
  branch valid sample(w0,n0,c0) invalid()
block sample(w1:mutbuf,n1:u64,c1:u64)
  result64:u64 = call(w1,n1,c1) {"function":"ms_sample_mask"}
  result:u32 = int.cast(result64) {"mode":"wrap"}
  ret(result)
block invalid()
  refused:u32 = const() {"value":4294967293}
  ret(refused)
end
'''


# A bounded test process holds actual private allocations across calls. No
# compiler module, Rust library, signing oracle or cryptographic Python path is
# loaded in this process. All native images are captured into sealed memfds.
POINTER_WORKER = r'''
import base64,ctypes,fcntl,hashlib,json,os,resource,sys
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(384<<20,384<<20))
resource.setrlimit(resource.RLIMIT_CPU,(60,60))
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(4,0,0,0,0):raise OSError(ctypes.get_errno(),'disable core dumps')
libraries={};entries={};descriptors=[]
for name,item in request['images'].items():
 with open(item['path'],'rb') as stream:raw=stream.read()
 if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('changed native image')
 fd=os.memfd_create('trnm-ml-dsa-'+name,os.MFD_ALLOW_SEALING);descriptors.append(fd)
 at=0
 while at<len(raw):
  count=os.write(fd,raw[at:])
  if count<=0:raise OSError('short image capture')
  at+=count
 fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
 libraries[name]=ctypes.CDLL('/proc/self/fd/'+str(fd))
 entry=libraries[name].f0;entry.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;entry.restype=ctypes.c_uint64;entries[name]=entry
# Keep each descriptor open until every dlopen completed. Reusing fd 3 early
# would reuse the same loader pathname and can silently select the first image.
if len({ctypes.cast(entry,ctypes.c_void_p).value for entry in entries.values()})!=len(entries):raise ValueError('native image loader selected a duplicate entry')
for fd in descriptors:os.close(fd)
def allocate(data,residue,extra=0):
 storage=ctypes.create_string_buffer(b'\x69'*(len(data)+64+extra))
 begin=16+((residue-ctypes.addressof(storage))%8);address=ctypes.addressof(storage)+begin
 ctypes.memmove(address,data,len(data));return storage,begin,len(data),address
def content(x):return x[0].raw[x[1]:x[1]+x[2]]
def guarded(x):
 storage,begin,size,_=x
 return storage.raw[:begin]==b'\x69'*begin and storage.raw[begin+size:-1]==b'\x69'*(len(storage.raw)-1-begin-size) and storage.raw[-1:]==b'\0'
histories=[]
for case in request.get('histories',[]):
 owner=allocate(bytes.fromhex(case['owner']),case['residues'][1]);work=allocate(b'\x6d'*131072+b'\xa5'*17,case['residues'][2]);rows=[]
 for encoded in case['requests']:
  packet=base64.b64decode(encoded,validate=True);incoming=allocate(packet,case['residues'][0]);before=content(work)
  result=entries['owner'](incoming[3],incoming[2],owner[3],owner[2],work[3],work[2]);after=content(work)
  rows.append(dict(value=result&0xffffffff,abi_status=result>>32,owner=content(owner).hex(),
   input_unchanged=content(incoming)==packet,guards=all(guarded(x) for x in (incoming,owner,work)),
   residues=[x[3]%8 for x in (incoming,owner,work)],work_unchanged=before==after,
   work_cleared=after[:131072]==bytes(131072),work_tail=after[131072:].hex(),
   work_sha256=hashlib.sha256(after).hexdigest()))
 histories.append(rows)
guards=[]
for case in request.get('guards',[]):
 data=[base64.b64decode(case['packet'],validate=True),b'\xa5'*case['output'],b'\x6d'*case['work']]
 if 'oversize' in case:data[case['oversize']]+=bytes((1<<20)+1-len(data[case['oversize']]))
 allocated=[allocate(raw,index+1,extra=(1<<20)) for index,raw in enumerate(data)]
 args=[]
 for item in allocated:args.extend((item[3],item[2]))
 if 'overlap' in case:
  left,right=case['overlap'];args[right*2]=args[left*2]+1
 before=[item[0].raw for item in allocated]
 result=entries[case['image']](*args)
 guards.append(dict(value=result&0xffffffff,abi_status=result>>32,unchanged=all(item[0].raw==raw for item,raw in zip(allocated,before))))
print(json.dumps(dict(images={key:value['sha256'] for key,value in request['images'].items()},histories=histories,guards=guards,
 compiler_modules_loaded=[x for x in sys.modules if x.startswith('hepta')]),separators=(',',':')))
'''


class MlDsaNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        cls.counts = Counter()
        cls.out = None
        location = os.environ.get("TRNM_HIA_ML_DSA_OBSERVATIONS")
        if location:
            cls.out = Path(location)
            cls.out.mkdir()
            stream = cls.stack.enter_context((cls.out / "native-calls.jsonl.gz").open("xb"))
            cls.raw_native = cls.stack.enter_context(gzip.GzipFile(fileobj=stream, mode="wb", compresslevel=1, mtime=0))
        compressed = VECTORS.read_bytes()
        if sha(compressed) != VECTOR_XZ_SHA:
            raise ValueError("Changed pinned NIST fixture archive")
        decoder = lzma.LZMADecompressor()
        raw = decoder.decompress(compressed, max_length=8 << 20)
        if not decoder.eof or decoder.unused_data or sha(raw) != VECTOR_SHA:
            raise ValueError("Incomplete or changed pinned NIST fixture")
        cls.vectors = json.loads(raw)
        if (cls.vectors["commit"] != PIN or len(cls.vectors["verify"]) != 90
                or len(cls.vectors["keygen"]) != 50 or len(cls.vectors["sign"]) != 180):
            raise ValueError("Changed official group selection")
        path = os.environ.get("TRNM_HIA_RUST_ML_DSA_REFERENCE")
        expected = os.environ.get("TRNM_HIA_RUST_ML_DSA_REFERENCE_SHA256")
        if not path or not expected:
            raise RuntimeError("The exact unchanged Rust ML-DSA oracle and its SHA256 are mandatory")
        cls.reference = unlinked_path(path)
        cls.reference_sha = sha(cls.reference.read_bytes())
        if cls.reference_sha != expected:
            raise ValueError("Original ML-DSA oracle executable differs from its receipt")
        cls.source_before = {str(path): sha(path.read_bytes()) for path in
                             (*SOURCES.values(), VECTORS, Path(__file__), ROOT / "hia/tests/rust_ml_dsa_reference.rs")}
        cls.modules = {name: cls.stack.enter_context(NativeModule(path, byte_exports=("f0",)))
                       for name, path in SOURCES.items()}
        if cls.out:
            for name, module in cls.modules.items():
                (cls.out / (name + ".so")).write_bytes(module.library.read_bytes())
                (cls.out / (name + "-build.json")).write_text(json.dumps(module.receipt, sort_keys=True, indent=2) + "\n")
        requests = candidate_inputs()
        answers = cls.original(requests, "setup-candidates")
        cls.candidates = []
        for request, answer in zip(requests, answers):
            if answer["code"] != 0:
                raise AssertionError(answer)
            cls.candidates.append(dict(request, **answer))

    @classmethod
    def tearDownClass(cls):
        if cls.out:
            cls.raw_native.flush()
            document = {"counts": dict(cls.counts), "original_artifact_sha256": cls.reference_sha,
                        "source_inputs": cls.source_before,
                        "native_artifacts": {key: value.artifact_sha256 for key, value in cls.modules.items()}}
            (cls.out / "observations.json").write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
        for name, expected in cls.source_before.items():
            if sha(Path(name).read_bytes()) != expected:
                raise AssertionError("ML-DSA qualification source changed during execution: " + name)

    @classmethod
    def original(cls, requests, label):
        if sha(cls.reference.read_bytes()) != cls.reference_sha:
            raise ValueError("Changed original ML-DSA oracle")
        raw = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                       for row in requests)
        process = subprocess.run([str(cls.reference)], input=raw, capture_output=True, timeout=120, check=False)
        sequence = cls.counts["original_batches"]
        cls.counts["original_batches"] += 1
        if cls.out:
            stem = f"original-{sequence:03d}"
            for name, data in (("requests.jsonl", raw), ("stdout.raw", process.stdout), ("stderr.raw", process.stderr)):
                (cls.out / (stem + "." + name)).write_bytes(data)
            receipt = {"label": label, "argv": [str(cls.reference)], "wall_limit_seconds": 120,
                       "executable_sha256": cls.reference_sha, "exit_code": process.returncode,
                       "requests": len(requests), "input_sha256": sha(raw),
                       "stdout_sha256": sha(process.stdout), "stderr_sha256": sha(process.stderr)}
            (cls.out / (stem + ".receipt.json")).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        if process.returncode != 0:
            raise AssertionError((label, process.returncode, process.stderr.decode(errors="replace")))
        answers = [json.loads(line) for line in process.stdout.splitlines()]
        if len(answers) != len(requests):
            raise AssertionError("Incomplete original ML-DSA observations")
        cls.counts["original_calls"] += len(answers)
        return answers

    def execute(self, name, cases):
        answers = []
        for first in range(0, len(cases), 8):
            batch = cases[first:first + 8]
            actual = self.modules[name].call_many([("f0", arguments) for _, arguments in batch], timeout=60)
            for (label, arguments), result in zip(batch, actual):
                self.counts["native_" + name] += 1
                if self.out:
                    row = {"test": self.id(), "label": label, "module": name,
                           "artifact_sha256": self.modules[name].artifact_sha256,
                           "before": [base64.b64encode(bytes(x)).decode() for x in arguments],
                           "status": result.status, "returncode": result.returncode,
                           "abi_status": result.abi_status, "value": result.value, "stderr": result.stderr,
                           "after": None if result.arguments is None else
                           [base64.b64encode(bytes(x)).decode() for x in result.arguments]}
                    self.raw_native.write((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())
                result.require_returned()
                answers.append(result)
        return answers

    def one(self, name, packet, output, work=None, label="case"):
        if work is None:
            work = b"\x6d" * WORK[name] + TAIL
        return self.execute(name, [(label, [packet, bytes(output), bytes(work)])])[0]

    def check_math(self, name, result, expected, *, cleared=True):
        self.assertEqual(result.value, len(expected))
        self.assertEqual(result.arguments[1], expected + TAIL)
        work = WORK[name]
        self.assertEqual(result.arguments[2], (bytes(work) if cleared else b"\x6d" * work) + TAIL)

    def owner(self, packet, state, expected, *, cleared=True, label="owner"):
        result = self.one("owner", packet, state, label=label)
        self.assertEqual(result.value, len(expected))
        self.assertEqual(result.arguments[1][8192:8192 + len(expected)], expected)
        self.assertEqual(result.arguments[1][8192 + len(expected):16384], bytes(8192 - len(expected)))
        self.assertEqual(result.arguments[1][16384:], bytes(state[16384:]))
        self.assertEqual(result.arguments[2], (bytes(131072) if cleared else b"\x6d" * 131072) + TAIL)
        return result.arguments[1]

    def init_owner(self, row):
        state = bytearray(16384) + bytearray(TAIL)
        state[3008:3040] = bytes.fromhex(row["seed"])
        pk = bytes.fromhex(row["pk"])
        return self.owner(owner_request(1, row["parameter"]), state, reply(0, len(pk)) + pk, label="init-signing-owner")

    def test_01_complete_selected_official_verification_and_original(self):
        rows = self.vectors["verify"] + [dict(row, expected=True) for row in self.vectors["sign"]]
        original = self.original([dict(row, op="verify_math") for row in rows], self.id())
        cases = []
        for row in rows:
            pk, signature, message, context = [bytes.fromhex(row[key]) for key in ("pk", "signature", "message", "context")]
            packet = verify_request(row["parameter"], pk, signature, message, context, row["profile"])
            cases.append((f"tg{row['tgId']}-tc{row['tcId']}", [packet, b"\x5a" * 24 + TAIL, b"\x6d" * 32768 + TAIL]))
        for row, oracle, result in zip(rows, original, self.execute("verify", cases)):
            with self.subTest(group=row["tgId"], case=row["tcId"]):
                self.assertEqual(oracle["code"] == 0, row["expected"])
                self.assertIn(oracle["code"], (0, 6, 7))
                self.check_math("verify", result, reply(oracle["code"], oracle["expected"], oracle["actual"]))

    def test_02_complete_selected_official_key_generation_and_original(self):
        rows = self.vectors["keygen"]
        original = self.original([dict(row, op="keygen_math") for row in rows], self.id())
        cases, expected = [], []
        for row, oracle in zip(rows, original):
            self.assertEqual((oracle["code"], oracle["pk"], oracle["sk"]), (0, row["pk"], row["sk"]))
            pk, sk = bytes.fromhex(row["pk"]), bytes.fromhex(row["sk"])
            response = reply(0, len(pk), len(sk)) + pk + sk
            expected.append(response)
            cases.append((f"tc{row['tcId']}", [keygen_request(row["parameter"], bytes.fromhex(row["seed"])),
                                               b"\x5a" * len(response) + TAIL, b"\x6d" * 65536 + TAIL]))
        for result, wanted in zip(self.execute("keygen", cases), expected):
            self.check_math("keygen", result, wanted)

    def test_03_complete_selected_official_signatures_and_original_public_surface(self):
        rows = self.vectors["sign"]
        exposed = [row for row in rows if row["profile"] != 3 or row["deterministic"]]
        self.assertEqual(len(exposed), 150)
        original = self.original([dict(row, op="sign_math") for row in exposed], self.id())
        for row, oracle in zip(exposed, original):
            self.assertEqual((oracle["code"], oracle["signature"]), (0, row["signature"]))
        cases, expected = [], []
        for row in rows:
            sk, message, context, rnd, signature = [bytes.fromhex(row[key]) for key in ("sk", "message", "context", "rnd", "signature")]
            response = reply(0, len(signature)) + signature
            expected.append(response)
            packet = sign_request(row["parameter"], sk, message, context, rnd, row["profile"])
            cases.append((f"tg{row['tgId']}-tc{row['tcId']}", [packet, b"\x5a" * len(response) + TAIL, b"\x6d" * 131072 + TAIL]))
        for result, wanted in zip(self.execute("sign", cases), expected):
            self.check_math("sign", result, wanted)

    def test_04_candidate_complete_lifecycle_matches_original(self):
        for row in self.candidates:
            param = row["parameter"]
            pk, signature, message = [bytes.fromhex(row[key]) for key in ("pk", "signature", "message")]
            state = self.init_owner(row)
            self.assertEqual(state[3008:3040], bytes(32))
            self.assertEqual(state[:10], b"TRNMDSK1" + bytes((2, param)))
            private = state[:8192]
            state = self.owner(owner_request(4), state, reply(0, len(pk)) + pk, cleared=False, label="public-key")
            self.assertEqual(state[:8192], private)
            info = struct.pack("<4Q", len(pk), len(signature), 3 if param == 65 else 5, param) + row["name"].encode()
            state = self.owner(owner_request(9), state, reply(0, len(info)) + info, cleared=False, label="owned-algorithm")
            self.assertEqual(state[:8192], private)
            state = self.owner(owner_request(3, message=message), state, reply(0, len(signature)) + signature, label="deterministic-sign-selfverify")
            self.assertEqual(state[:8192], private)
            state = self.owner(owner_request(2, message=message, signature=signature), state, reply(), label="verify")
            self.assertEqual(state[:8192], private)
            state = self.owner(owner_request(6), state, reply(), label="destroy-signing-owner")
            self.assertEqual(state[:16384], bytes(16384))
            verifier = self.owner(owner_request(0, param, public_key=pk), bytes(16384) + TAIL,
                                  reply(0, len(pk)) + pk, cleared=False, label="pin-verifying-owner")
            self.assertEqual(verifier[3072:8192], bytes(5120))
            verifier = self.owner(owner_request(2, message=message, signature=signature), verifier, reply(), label="pinned-verify")
            verifier = self.owner(owner_request(6), verifier, reply(), label="destroy-verifying-owner")
            self.assertEqual(verifier[:16384], bytes(16384))

    def candidate_verify_cases(self, rows):
        requests = [{"op": "verify", "parameter": p, "pk": pk.hex(), "signature": sig.hex(), "message": message.hex()}
                    for _, p, pk, sig, message, _ in rows]
        answers = self.original(requests, self.id())
        calls = [(label, [verify_request(p, pk, sig, message), b"\x5a" * 24 + TAIL, b"\x6d" * 32768 + TAIL])
                 for label, p, pk, sig, message, _ in rows]
        results = self.execute("verify", calls)
        for row, answer, result in zip(rows, answers, results):
            label, _, _, _, _, known = row
            with self.subTest(label=label):
                if known is not None:
                    self.assertEqual(answer["code"], known)
                response = reply(answer["code"], answer["expected"], answer["actual"])
                self.check_math("verify", result, response, cleared=answer["code"] not in (3, 4, 5))

    def test_05_candidate_mixed_error_priority_and_content_mutations(self):
        cases = []
        for param in PARAMETERS:
            row = next(row for row in self.candidates if row["parameter"] == param and len(row["message"]) == 512)
            pk, sig, msg = [bytes.fromhex(row[key]) for key in ("pk", "signature", "message")]
            for length in (0, len(pk) - 1, len(pk) + 1):
                cases.append((f"{param}-pk-{length}", param, (pk + b"\0")[:length], b"", b"\0" * 65537, 3))
            for length in (0, len(sig) - 1, len(sig) + 1):
                cases.append((f"{param}-sig-{length}", param, pk, (sig + b"\0")[:length], msg, 5))
            cases += [(f"{param}-message-before-sig-length", param, pk, b"", b"\0" * 65537, 4),
                      (f"{param}-message-before-sig-encoding", param, pk, bytes(len(sig)), b"\0" * 65537, 4),
                      (f"{param}-all-zero-signature", param, pk, bytes(len(sig)), msg, 6),
                      (f"{param}-changed-message", param, pk, sig, msg + b"\0", 7)]
            for at in (0, 31, 32, len(pk) - 1):
                cases.append((f"{param}-pk-bit-{at}", param, flip(pk, at), sig, msg, 7))
            challenge = PARAMETERS[param][-1]
            for at in (0, challenge - 1, challenge, challenge + 1, len(sig) - 1):
                for bit in (0, 7):
                    cases.append((f"{param}-sig-bit-{at}-{bit}", param, pk, flip(sig, at, bit), msg, None))
        self.candidate_verify_cases(cases)

    def test_06_signature_z_norm_exact_boundaries(self):
        cases = []
        for param, (_, _, _, _, ell, _, beta, challenge) in PARAMETERS.items():
            row = next(row for row in self.candidates if row["parameter"] == param and not row["message"])
            pk, sig = bytes.fromhex(row["pk"]), bytes.fromhex(row["signature"])
            values = (0, beta, beta + 1, 524287, 524288, 524289, 1048575 - beta, 1048576 - beta, 1048575)
            for index in (0, 255, 256, ell * 256 - 1):
                for value in values:
                    malformed = value <= beta or value >= 1048576 - beta
                    cases.append((f"{param}-z-{index}-{value}", param, pk,
                                  put_coefficient(sig, challenge, index, value), b"", 6 if malformed else 7))
        self.candidate_verify_cases(cases)

    def test_07_hint_canonical_encoding_and_error_precedence(self):
        cases = []
        for param, (_, _, _, k, ell, omega, _, challenge) in PARAMETERS.items():
            row = next(row for row in self.candidates if row["parameter"] == param and not row["message"])
            pk, sig = bytes.fromhex(row["pk"]), bytes.fromhex(row["signature"])
            at = challenge + ell * 640
            variants = [
                ("empty", bytes(omega + k), 7),
                ("active-zero", bytes(omega) + bytes([1] * k), 7),
                ("active-255", bytes([255]) + bytes(omega - 1) + bytes([1] * k), 7),
                ("same-index-different-polys", bytes(omega) + bytes(range(1, k + 1)), 7),
                ("repeated-empty-cut", bytes(omega) + bytes([0, 0] + [1] * (k - 2)), 7),
                ("full-omega", bytes(range(omega)) + bytes([omega] * k), 7),
                ("cut-too-large", bytes(omega) + bytes([omega + 1] * k), 6),
                ("decreasing-cut", bytes([1, 2]) + bytes(omega - 2) + bytes([2, 1] + [2] * (k - 2)), 6),
                ("duplicate-index", bytes([1, 1]) + bytes(omega - 2) + bytes([2] * k), 6),
                ("descending-index", bytes([255, 0]) + bytes(omega - 2) + bytes([2] * k), 6),
                ("nonzero-unused-padding", bytes(omega - 1) + b"\x01" + bytes(k), 6),
            ]
            for name, hints, known in variants:
                cases.append((f"{param}-hints-{name}", param, pk, change(sig, at, hints), b"", known))
            invalid_both = put_coefficient(change(sig, at, variants[-1][1]), challenge, 0, 0)
            cases.append((f"{param}-bad-hints-and-z", param, pk, invalid_both, b"", 6))
        self.candidate_verify_cases(cases)

    def test_08_candidate_algorithm_and_every_error_display(self):
        original = self.original([{"op": "info", "parameter": p} for p in PARAMETERS], self.id())
        state = bytes(16384) + TAIL
        for param, oracle in zip(PARAMETERS, original):
            info = struct.pack("<4Q", oracle["public_key_bytes"], oracle["signature_bytes"], oracle["nist_category"], param) + oracle["name"].encode()
            self.owner(owner_request(5, param), state, reply(0, len(info)) + info, cleared=False)
            self.assertEqual(oracle["all"], ["ML-DSA-65", "ML-DSA-87"])
        self.owner(owner_request(8), state, reply(0, 2) + bytes((65, 87)), cleared=False)
        requests = [{"op": "error_display", "code": code, "expected": expected, "actual": actual}
                    for code in range(2, 9) for expected, actual in ((0, 0), (1, 9999999999), (U64, U64))]
        for request, oracle in zip(requests, self.original(requests, self.id())):
            text = oracle["display"].encode()
            self.owner(owner_request(7, request["code"], expected=request["expected"], actual=request["actual"]),
                       state, reply(0, len(text)) + text, cleared=False)

    def test_09_owned_key_error_priority_and_reinitialization_refusal(self):
        for param in PARAMETERS:
            row = next(row for row in self.candidates if row["parameter"] == param)
            state = self.init_owner(row)
            pk = bytes.fromhex(row["pk"])
            original = state[:8192]
            for request in (owner_request(0, param, public_key=pk), owner_request(1, param)):
                state = self.owner(request, state, reply(9), cleared=False, label="live-owner-reinitialization")
                self.assertEqual(state[:8192], original)
            for operation in (2, 3):
                state = self.owner(owner_request(operation, message=b"\0" * 65537), state,
                                   reply(4, 65536, 65537), cleared=False, label="owned-message-limit")
                self.assertEqual(state[:8192], original)
            state = self.owner(owner_request(2), state, reply(5, PARAMETERS[param][1], 0), cleared=False)
            self.assertEqual(state[:8192], original)
            verifier = self.owner(owner_request(0, param, public_key=pk), bytes(16384) + TAIL,
                                  reply(0, len(pk)) + pk, cleared=False)
            verifier = self.owner(owner_request(3), verifier, reply(9), cleared=False, label="verifier-cannot-sign")
            self.assertEqual(verifier[3072:8192], bytes(5120))
            dead = self.owner(owner_request(6), state, reply())
            dead = self.owner(owner_request(6), dead, reply(), label="idempotent-destroy")
            self.assertEqual(dead[:16384], bytes(16384))
            self.owner(owner_request(4), dead, reply(9), label="use-after-destroy")

    def test_10_selfverification_and_secret_failure_cleanup(self):
        for param in PARAMETERS:
            row = next(row for row in self.candidates if row["parameter"] == param)
            state = self.init_owner(row)
            # Fault injection into private storage is not a public key import API.
            # A mismatched pinned public key must prevent signature publication.
            corrupt = flip(state, 64)
            failed = self.owner(owner_request(3), corrupt, reply(7), label="self-verification-rejects-pinned-key-mismatch")
            self.assertEqual(failed[:8192], corrupt[:8192])
            # Invalid eta encoding fails before rejection sampling, without a signature.
            corrupt = change(state, 3072 + 128, b"\xff")
            failed = self.owner(owner_request(3), corrupt, reply(8), label="invalid-private-eta-clears-work")
            self.assertEqual(failed[:8192], corrupt[:8192])
            for at in (0, 8, 9, 10, 16, 24, 32, 63):
                invalid = flip(state, at)
                failed = self.owner(owner_request(4), invalid, reply(9), label=f"invalid-owner-header-{at}")
                self.assertEqual(failed[:8192], bytes(8192))

    def test_11_all_public_envelopes_refuse_before_caller_writes(self):
        good = {}
        row = self.vectors["keygen"][0]
        sign = self.vectors["sign"][0]
        good["keygen"] = keygen_request(65, bytes.fromhex(row["seed"]))
        good["verify"] = verify_request(65, bytes.fromhex(sign["pk"]), bytes.fromhex(sign["signature"]),
                                         bytes.fromhex(sign["message"]), bytes.fromhex(sign["context"]), sign["profile"])
        good["sign"] = sign_request(65, bytes.fromhex(sign["sk"]), bytes.fromhex(sign["message"]),
                                     bytes.fromhex(sign["context"]), bytes.fromhex(sign["rnd"]), sign["profile"])
        good["owner"] = owner_request(1, 65)
        output_lengths = {"verify": 24, "keygen": 6008, "sign": 3333, "owner": 16384}
        for name, raw in good.items():
            header = 48 if name == "keygen" else 64
            malformed = [(f"short-{size}", raw[:size]) for size in range(header)]
            malformed += [("bad-magic", flip(raw, 0)), ("trailing", raw + b"\0")]
            parameter_at = 8 if name in ("keygen", "sign") else 9
            malformed += [(f"algorithm-{value}", change(raw, parameter_at, bytes((value,)))) for value in (0, 44, 255)]
            reserved = range(9, 16) if name == "keygen" else range(11 if name == "verify" else 10, 16)
            malformed += [(f"reserved-{at}", change(raw, at, b"\x01")) for at in reserved]
            if name != "keygen":
                malformed += [(f"length-overflow-{at}", change(raw, at, struct.pack("<Q", U64))) for at in (16, 24, 32, 40, 48, 56)]
            before_output = b"\x5a" * output_lengths[name] + TAIL
            before_work = b"\x6d" * WORK[name] + TAIL
            calls = [(label, [packet, before_output, before_work]) for label, packet in malformed]
            for (label, arguments), result in zip(calls, self.execute(name, calls)):
                with self.subTest(module=name, label=label):
                    self.assertEqual(result.value, REFUSED)
                    self.assertEqual(result.arguments, arguments)
            cases = [("short-output", [raw, b"\x5a" * (output_lengths[name] - 1), before_work]),
                     ("short-work", [raw, before_output, b"\x6d" * (WORK[name] - 1)])]
            for (_, arguments), result in zip(cases, self.execute(name, cases)):
                self.assertEqual(result.value, REFUSED)
                self.assertEqual(result.arguments, arguments)

    def test_12_diagnostic_secret_encoding_failure_clears_work(self):
        for param in PARAMETERS:
            row = next(row for row in self.vectors["sign"] if row["parameter"] == param)
            sk = change(bytes.fromhex(row["sk"]), 128, b"\xff")
            packet = sign_request(param, sk)
            result = self.one("sign", packet, b"\x5a" * (24 + PARAMETERS[param][1]) + TAIL)
            self.assertEqual(result.value, 24)
            self.assertEqual(result.arguments[1][:24], reply(8, 6))
            self.assertEqual(result.arguments[1][24:], b"\x5a" * PARAMETERS[param][1] + TAIL)
            self.assertEqual(result.arguments[2], bytes(131072) + TAIL)

    def test_13_pure_internal_mu_and_context_separation(self):
        requests, expected = [], []
        for param in PARAMETERS:
            row = next(row for row in self.candidates if row["parameter"] == param and not row["message"])
            pk, sig = bytes.fromhex(row["pk"]), bytes.fromhex(row["signature"])
            tr = hashlib.shake_256(pk).digest(64)
            mu = hashlib.shake_256(tr + b"\0\0").digest(64)
            for profile, message, context, code in ((1, b"", b"", 0), (2, b"", b"", 7),
                                                     (3, mu, b"", 0), (3, flip(mu, 0), b"", 7),
                                                     (1, b"", b"\0", 7), (1, b"", bytes(255), 7),
                                                     (1, b"", bytes(256), 7)):
                requests.append({"op": "verify_math", "parameter": param, "pk": pk.hex(), "signature": sig.hex(),
                                 "message": message.hex(), "context": context.hex(), "profile": profile})
                expected.append(code)
        original = self.original(requests, self.id())
        for request, code, oracle in zip(requests, expected, original):
            self.assertEqual(oracle["code"], code)
            packet = verify_request(request["parameter"], bytes.fromhex(request["pk"]), bytes.fromhex(request["signature"]),
                                    bytes.fromhex(request["message"]), bytes.fromhex(request["context"]), request["profile"])
            result = self.one("verify", packet, b"\x5a" * 24 + TAIL)
            self.check_math("verify", result, reply(code), cleared=len(request["context"]) <= 510)

    def test_14_minimum_capacity_and_full_borrow_tail_preservation(self):
        for param in PARAMETERS:
            row = next(row for row in self.candidates if row["parameter"] == param)
            pk, sig = bytes.fromhex(row["pk"]), bytes.fromhex(row["signature"])
            packet = verify_request(param, pk, sig)
            result = self.one("verify", packet, bytes(24), bytes(32768), label="exact-minimum-verify")
            self.assertEqual(result.value, 24)
            self.assertEqual(result.arguments[1], reply())
            self.assertEqual(result.arguments[2], bytes(32768))
            result = self.one("verify", packet, b"\x5a" * (1 << 20), b"\x6d" * (1 << 20), label="full-borrow-tails")
            self.assertEqual(result.value, 24)
            self.assertEqual(result.arguments[1], reply() + b"\x5a" * ((1 << 20) - 24))
            self.assertEqual(result.arguments[2], bytes(32768) + b"\x6d" * ((1 << 20) - 32768))
            state = bytearray(16384)
            state[3008:3040] = bytes.fromhex(row["seed"])
            result = self.one("owner", owner_request(1, param), state, bytes(131072), label="exact-minimum-owned-key")
            self.assertEqual(result.value, 24 + len(pk))
            self.assertEqual(result.arguments[1][8192:8216 + len(pk)], reply(0, len(pk)) + pk)
            self.assertEqual(result.arguments[2], bytes(131072))
            self.assertEqual(result.arguments[1][3008:3040], bytes(32))

    def test_15_actual_last_nonce_and_explicit_overflow_refusal(self):
        from hia.tools import toolchain
        manifest = json.loads((ROOT / "hia/components.json").read_text())
        entry_name = "src/crypto/ml_dsa_nonce_fixture.hepta"
        selected = {}

        def dependencies(name):
            if name in selected:
                return
            selected[name] = manifest["includes"].get(name, [])
            for row in selected[name]:
                dependencies(row["source"])

        dependencies("src/crypto/ml_dsa_sign.hepta")
        selected[entry_name] = [{"source": "src/crypto/ml_dsa_sign.hepta", "functions": ["ms_sample_mask", "ms_bits"]}]
        selected[entry_name] += manifest["includes"]["src/crypto/ml_dsa_sign.hepta"]
        with tempfile.TemporaryDirectory(prefix="trnm-ml-dsa-nonce-") as directory:
            root = Path(directory)
            for name in selected:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name != entry_name:
                    path.write_bytes((ROOT / "hia" / name).read_bytes())
            entry = root / entry_name
            entry.write_text(NONCE_ENTRY)
            (root / "components.json").write_text(json.dumps({"schema": manifest["schema"], "includes": selected}, sort_keys=True))
            with patch.object(toolchain, "HIA_ROOT", root):
                native = NativeModule(entry, byte_exports=("f0",), fixture_owner=Path(__file__))
            with native:
                self.modules["nonce"] = native
                if self.out:
                    (self.out / "nonce.so").write_bytes(native.library.read_bytes())
                    (self.out / "nonce-build.json").write_text(json.dumps(native.receipt, sort_keys=True, indent=2) + "\n")
                    (self.out / "nonce-entry.hepta").write_text(NONCE_ENTRY)
                    (self.out / "nonce-components.json").write_bytes((root / "components.json").read_bytes())
                seed = bytes(range(64))
                for nonce, count in ((0, 5), (65530, 5), (65531, 5), (65527, 7), (65534, 7), (65535, 5), (65536, 7)):
                    work = bytearray(b"\x6d" * 65536 + TAIL)
                    work[704:768] = seed
                    completed = min(count, max(0, 65536 - nonce))
                    status = 0 if completed == count else 9
                    result = self.execute("nonce", [(f"nonce-{nonce}-l{count}", [struct.pack("<QQ", nonce, count), b"\x5a" * 24, work])])[0]
                    self.assertEqual(result.value, status)
                    self.assertEqual(result.arguments[1], b"\x5a" * 24)
                    self.assertEqual(result.arguments[2][704:768], seed)
                    self.assertEqual(result.arguments[2][65536:], TAIL)
                    for index in range(completed):
                        stream = hashlib.shake_256(seed + (nonce + index).to_bytes(2, "little")).digest(640)
                        packed = int.from_bytes(stream, "little")
                        coefficients = [(524288 - ((packed >> (20 * j)) & 1048575)) % 8380417 for j in range(256)]
                        expected = struct.pack("<256I", *coefficients)
                        start = 28672 + index * 1024
                        self.assertEqual(result.arguments[2][start:start + 1024], expected)
                    for start in (28672, 36864):
                        begin, end = start + completed * 1024, start + count * 1024
                        self.assertEqual(result.arguments[2][begin:end], bytes(work[begin:end]))
                    if completed == 0:
                        self.assertEqual(result.arguments[2], bytes(work))

    def test_16_real_private_allocations_unaligned_lifetimes_and_capacity_refusals(self):
        histories, expected = [], []
        for param in PARAMETERS:
            row = next(row for row in self.candidates if row["parameter"] == param and len(row["message"]) == 512)
            pk, signature, message = [bytes.fromhex(row[key]) for key in ("pk", "signature", "message")]
            state = bytearray(16384) + bytearray(TAIL)
            state[3008:3040] = bytes.fromhex(row["seed"])
            requests = [owner_request(1, param), owner_request(4), owner_request(3, message=message),
                        owner_request(2, message=message, signature=signature), owner_request(6), owner_request(4)]
            responses = [reply(0, len(pk)) + pk, reply(0, len(pk)) + pk,
                         reply(0, len(signature)) + signature, reply(), reply(), reply(9)]
            for shift in range(8):
                histories.append({"owner": state.hex(), "residues": [shift, (shift + 1) % 8, (shift + 4) % 8],
                                  "requests": [base64.b64encode(x).decode() for x in requests]})
                expected.append(responses)
        sample = self.candidates[0]
        packets = {"verify": verify_request(65, bytes.fromhex(sample["pk"]), bytes.fromhex(sample["signature"])),
                   "keygen": keygen_request(65, bytes(32)), "sign": sign_request(65, bytes(4032)),
                   "owner": owner_request(1, 65)}
        guards = []
        for name, packet in packets.items():
            output = {"verify": 24, "keygen": 6008, "sign": 3333, "owner": 16384}[name]
            common = {"image": name, "packet": base64.b64encode(packet).decode(), "output": output, "work": WORK[name]}
            guards += [dict(common, oversize=index) for index in range(3)]
        images = {name: {"path": str(module.library), "sha256": module.artifact_sha256}
                  for name, module in self.modules.items() if name != "nonce"}
        request = json.dumps({"images": images, "histories": histories, "guards": guards}, sort_keys=True).encode()
        process = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", POINTER_WORKER],
                                 input=request, capture_output=True, timeout=90, check=False)
        if self.out:
            (self.out / "pointer.requests.json").write_bytes(request)
            (self.out / "pointer.stdout.raw").write_bytes(process.stdout)
            (self.out / "pointer.stderr.raw").write_bytes(process.stderr)
            (self.out / "pointer.receipt.json").write_text(json.dumps({"exit_code": process.returncode,
                "wall_limit_seconds": 90, "input_sha256": sha(request), "stdout_sha256": sha(process.stdout),
                "stderr_sha256": sha(process.stderr), "worker_sha256": sha(POINTER_WORKER.encode())}, sort_keys=True) + "\n")
        self.assertEqual(process.returncode, 0, process.stderr)
        observed = json.loads(process.stdout)
        self.assertEqual(observed["images"], {name: value["sha256"] for name, value in images.items()})
        self.assertEqual(observed["compiler_modules_loaded"], [])
        self.assertEqual(len(observed["histories"]), len(histories))
        for case, wanted, rows in zip(histories, expected, observed["histories"]):
            self.assertEqual(len(rows), len(wanted))
            private = None
            for index, (row, response) in enumerate(zip(rows, wanted)):
                self.assertEqual((row["abi_status"], row["value"]), (0, len(response)))
                self.assertTrue(row["guards"] and row["input_unchanged"])
                self.assertEqual(row["residues"], case["residues"])
                state = bytes.fromhex(row["owner"])
                self.assertEqual(state[8192:8192 + len(response)], response)
                self.assertEqual(state[8192 + len(response):16384], bytes(8192 - len(response)))
                self.assertEqual(state[16384:], TAIL)
                self.assertTrue(row["work_cleared"])
                self.assertEqual(row["work_tail"], TAIL.hex())
                if index == 0:
                    private = state[:8192]
                    self.assertEqual(state[3008:3040], bytes(32))
                elif index < 4:
                    self.assertEqual(state[:8192], private)
                else:
                    self.assertEqual(state[:8192], bytes(8192))
                self.counts["raw_owned_calls"] += 1
        self.assertEqual(len(observed["guards"]), len(guards))
        for sent, row in zip(guards, observed["guards"]):
            # The pinned selfhost entry is legacy-f0-private-buffers: it has
            # no foreign-pointer admission gate. These are valid, disjoint
            # allocations whose explicit Core extent guards must refuse them.
            self.assertEqual(row["abi_status"], 0)
            self.assertEqual(row["value"], REFUSED)
            self.assertTrue(row["unchanged"])
            self.counts["raw_capacity_refusals"] += 1


if __name__ == "__main__":
    unittest.main()
