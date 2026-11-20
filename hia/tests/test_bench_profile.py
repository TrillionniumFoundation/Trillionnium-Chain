"""Real native logarithm, derived profile and complete four-place float fields.

The Rust adapter includes the entire unchanged executor. MPFR is a separate
qualification oracle, never a production fallback. Every observed Rust/native
logarithm or entropy bit difference is retained with both final report strings.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_bench_native import (
    build_original, clean_environment, run_original_command, txs_from_frame,
)
from hia.tests.test_executor_schedule import decoded_output, graph_violations, sizes
from hia.tools.qualify import native_build_record, sources

ROOT = Path(__file__).resolve().parents[2]
EXECUTOR = ROOT / "trillionnium/crates/trnm-executor/src/lib.rs"
REFERENCE = ROOT / "hia/tests/rust_bench_profile_reference.rs"
U64 = (1 << 64) - 1
ONE = 0x3FF0000000000000
INTEGER_FIELDS = frozenset((8, 16, 35, 38, 39, 42, 45))
STAGES = ("none", "ww", "wr", "rw", "mixed")
METHODS = (
    "conflict_checks_per_tx", "conflict_hits_per_tx", "candidate_groups_per_tx",
    "retry_fallback_new_group_share", "retry_fallback_share_of_new_groups",
    "retry_fallback_share_of_retry_hits", "retry_fallback_scan_share", "retry_pressure",
    "reused_group_placements", "reused_group_share", "new_group_share",
    "candidate_groups_per_retry_hit", "candidate_groups_per_reused_placement",
    "retry_scan_reuse_rate", "retry_reuse_salvage_rate", "retry_scan_hit_rate",
    "retry_scan_misses", "retry_scan_miss_rate", "retry_scan_misses_per_tx",
    "retry_scan_misses_per_group", "retry_scan_overhang_per_hit",
    "retry_scan_overhang_per_reused_placement", "retry_fallback_share_of_retry_misses",
    "ww_retry_hit_rate", "wr_retry_hit_rate", "rw_retry_hit_rate", "ww_retry_hits_per_tx",
    "wr_retry_hits_per_tx", "rw_retry_hits_per_tx", "ww_retry_share", "wr_retry_share",
    "rw_retry_share", "dominant_retry_stage", "dominant_retry_share",
    "dominant_attributed_retry_share", "dominant_retry_lead_hits", "dominant_retry_lead_share",
    "dominant_attributed_retry_lead_share", "attributed_retry_hits", "unattributed_retry_hits",
    "unattributed_retry_share", "retry_attribution_coverage", "retry_stage_overlap_hits",
    "retry_stage_overlap_share", "retry_stage_overlap_share_of_attributed",
    "singly_attributed_retry_hits", "singly_attributed_retry_share",
    "singly_attributed_retry_share_of_attributed", "retry_stage_concentration",
    "retry_stage_mix_entropy", "conflict_hit_rate",
)
# Lefevre/Muller, TMDworstcases.pdf, Table 5, printed page 15.
HARD_CASES = (
    ("1110101001110001110110000101110011101110000000100000", -509),
    ("1001010001110110111000110000010011001101011111000111", -384),
    ("0010011011101001110001001101001100100111100101100000", -232),
    ("0110000100111001010101011101110010000000001011111000", -35),
    ("0110001010101000100001100001001101100010100110110110", 678),
)

# A signal ends the ordinary NativeModule worker before it can return buffers.
# This extra observer uses shared mappings to retain their actual post-trap
# bytes. It does not replace the formal recorded NativeModule invocations.
OVERFLOW_WORKER = r'''
import base64,ctypes,fcntl,hashlib,json,mmap,os,resource,signal,sys
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
binary=open(request['library'],'rb').read()
assert hashlib.sha256(binary).hexdigest()==request['sha256']
fd=os.memfd_create('bench-profile-overflow',os.MFD_ALLOW_SEALING)
position=0
while position<len(binary):
 count=os.write(fd,binary[position:]);assert count>0;position+=count
fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
library=ctypes.CDLL('/proc/self/fd/'+str(fd))
function=library.f0;function.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;function.restype=ctypes.c_uint64
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
libc.prctl.restype=ctypes.c_int
answers=[]
for raw in request['inputs']:
 data=[base64.b64decode(raw,validate=True),b'\xa5'*416,b'\xc3'*2048]
 mappings=[];views=[];pointers=[];before=[]
 for value,offset in zip(data,(17,19,21)):
  memory=mmap.mmap(-1,len(value)+64);memory[:]=b'\x69'*len(memory)
  memory[offset:offset+len(value)]=value
  view=(ctypes.c_uint8*len(memory)).from_buffer(memory)
  mappings.append(memory);views.append(view);pointers.append(ctypes.addressof(view)+offset);before.append(bytes(memory))
 parent=os.getpid();pid=os.fork()
 if pid==0:
  assert libc.prctl(1,signal.SIGKILL,0,0,0)==0
  if os.getppid()!=parent:os._exit(84)
  resource.setrlimit(resource.RLIMIT_CPU,(1,1))
  for stream in (0,1,2):os.close(stream)
  value=function(pointers[0],len(data[0]),pointers[1],len(data[1]),pointers[2],len(data[2]))
  os._exit(0 if value==0 else 85)
 waited,status=os.waitpid(pid,0);assert waited==pid
 after=[bytes(memory) for memory in mappings]
 answers.append({'signal':os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
  'exit_code':os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
  'pointer_residues':[p%8 for p in pointers],
  'before':[base64.b64encode(v).decode() for v in before],
  'after':[base64.b64encode(v).decode() for v in after]})
 del view;views.clear()
 for memory in mappings:memory.close()
os.close(fd)
print(json.dumps({'artifact_sha256':request['sha256'],'answers':answers,
 'host_compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]}))
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def number(value):
    return struct.unpack("<d", struct.pack("<Q", value))[0]


def source_inputs():
    result = sources()
    for name in ("LOGARITHM.md", "PROFILE.md", "FORMATTING.md", "README.md"):
        path = ROOT / "hia/src/bench" / name
        if path.is_symlink():
            raise AssertionError("linked profile contract source")
        result[path.relative_to(ROOT).as_posix()] = digest(path.read_bytes())
    return dict(sorted(result.items()))


class MPFRValue(ctypes.Structure):
    _fields_ = [("precision", ctypes.c_long), ("sign", ctypes.c_int),
                ("exponent", ctypes.c_long), ("limbs", ctypes.POINTER(ctypes.c_ulong))]


class MPFRReference:
    """Independent RN binary64 result and directed 400-bit interval enclosure."""

    def __init__(self):
        name = ctypes.util.find_library("mpfr")
        if not name:
            raise RuntimeError("MPFR is required for independent logarithm qualification")
        self.library = ctypes.CDLL(name)
        pointer = ctypes.POINTER(MPFRValue)
        signatures = (
            ("mpfr_init2", [pointer, ctypes.c_long], None),
            ("mpfr_clear", [pointer], None),
            ("mpfr_set_d", [pointer, ctypes.c_double, ctypes.c_int], ctypes.c_int),
            ("mpfr_set_str", [pointer, ctypes.c_char_p, ctypes.c_int, ctypes.c_int], ctypes.c_int),
            ("mpfr_log", [pointer, pointer, ctypes.c_int], ctypes.c_int),
            ("mpfr_abs", [pointer, pointer, ctypes.c_int], ctypes.c_int),
            ("mpfr_mul_2si", [pointer, pointer, ctypes.c_long, ctypes.c_int], ctypes.c_int),
            ("mpfr_get_d", [pointer, ctypes.c_int], ctypes.c_double),
            ("mpfr_cmp", [pointer, pointer], ctypes.c_int),
            ("mpfr_get_version", [], ctypes.c_char_p),
        )
        for symbol, arguments, result in signatures:
            function = getattr(self.library, symbol)
            function.argtypes, function.restype = arguments, result
        self.values = [MPFRValue() for _ in range(6)]
        for value, precision in zip(self.values, (53, 53, 400, 400, 400, 400)):
            self.library.mpfr_init2(ctypes.byref(value), precision)
        paths = sorted({Path(line.split()[-1]) for line in Path("/proc/self/maps").read_text().splitlines()
                        if "libmpfr.so" in line and line.split()[-1].startswith("/")})
        if len(paths) != 1:
            self.close()
            raise AssertionError("ambiguous actual MPFR library")
        self.identity = {"version": self.library.mpfr_get_version().decode(),
            "path": str(paths[0]), "sha256": digest(paths[0].read_bytes()),
            "production_dependency": False, "result_precision": 53, "interval_precision": 400}

    def close(self):
        for value in self.values:
            self.library.mpfr_clear(ctypes.byref(value))
        self.values = []

    def ln(self, raw):
        x, result = map(ctypes.byref, self.values[:2])
        self.library.mpfr_set_d(x, number(raw), 0)
        self.library.mpfr_log(result, x, 0)
        return bits(self.library.mpfr_get_d(result, 0))

    def encloses(self, raw, precision, lower, upper):
        x = ctypes.byref(self.values[0])
        down, up, a, b = map(ctypes.byref, self.values[2:])
        self.library.mpfr_set_d(x, number(raw), 0)
        self.library.mpfr_log(down, x, 3)  # MPFR_RNDD
        self.library.mpfr_log(up, x, 2)    # MPFR_RNDU
        self.library.mpfr_abs(down, down, 0)
        self.library.mpfr_abs(up, up, 0)
        if raw < ONE:
            down, up = up, down
        for value, integer in ((a, lower), (b, upper)):
            if self.library.mpfr_set_str(value, str(integer).encode(), 10, 0):
                raise AssertionError("invalid exact endpoint integer")
            self.library.mpfr_mul_2si(value, value, -precision, 0)
        return self.library.mpfr_cmp(a, down) <= 0 and self.library.mpfr_cmp(b, up) >= 0


def logarithm_inputs():
    result = {1, (1 << 52) - 1, ONE, 0x7FEFFFFFFFFFFFFF}
    # Every finite exponent field, edge mantissas, and all subnormal binades.
    for exponent in range(1, 2047):
        for mantissa in (0, 1, (1 << 52) - 1):
            result.add((exponent << 52) | mantissa)
    for bit in range(52):
        for delta in (-1, 0, 1):
            if (1 << bit) + delta > 0:
                result.add((1 << bit) + delta)
    result.update(ONE + delta for delta in range(-32, 33))
    for fraction, exponent in HARD_CASES:
        value = ((1023 + exponent) << 52) | int(fraction, 2)
        result.update((value - 1, value, value + 1))
    rng = random.Random(0x424C4F4741524954)
    result.update(rng.randrange(1, 0x7FF0000000000000) for _ in range(192))
    return sorted(result)


def profile_inputs():
    values = [0, 1, 2, 3, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, U64 // 3]
    result = [[value] * 17 for value in values]
    # Every dominant stage/tie, missing attribution, overlap, saturating misses,
    # and independently zero denominators; raw avg/hot bits are unused here.
    for weights in ((0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 0),
                    (1, 0, 1), (0, 1, 1), (1, 1, 1), (5, 3, 1), (U64, 0, 0),
                    (U64 - 2, 1, 1), ((1 << 53) + 1, (1 << 53) - 1, 7)):
        for denominator in (0, 1, 3, U64):
            row = [denominator] * 17
            row[10] = 0
            row[12], row[14], row[16] = weights
            result.append(row)
    for index in range(17):
        row = [3] * 17
        row[index] = 0
        result.append(row)
    rng = random.Random(0x4250524F46494C45)
    for _ in range(160):
        limit = rng.choice((7, 127, 65535, 1 << 53, U64 // 4))
        row = [rng.randrange(limit + 1) for _ in range(17)]
        result.append(row)
    # The actual Rust debug additions must remain in range for successful rows.
    assert all(sum(row[index] for index in (12, 14, 16)) <= U64
               and max(0, row[0] - row[1]) + row[10] <= U64 for row in result)
    return result


class BenchProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        configured = os.environ.get("HIA_BENCH_PROFILE_OBSERVATIONS")
        cls.temporary = None if configured else tempfile.TemporaryDirectory(prefix="trnm-bench-profile-")
        if cls.temporary:
            cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(configured or cls.temporary.name).absolute()
        if configured:
            cls.directory.mkdir(parents=True, exist_ok=False)
        if ROOT == cls.directory or ROOT in cls.directory.parents:
            raise AssertionError("Bench evidence must be outside the checkout")
        cls.before = source_inputs()
        (cls.directory / "source-before.json").write_text(json.dumps(cls.before, indent=2) + "\n")
        run_original_command(cls.directory, "preflight", ["bash", "scripts/project-preflight.sh", "--audit"],
                             clean_environment(), 30)
        cls.modules, cls.builds = {}, {}
        for name, source in (("ln", "bench/logarithm.hepta"), ("profile", "bench/profile.hepta"),
                             ("format", "bench/format_value.hepta"), ("schedule", "executor/schedule.hepta")):
            module = NativeModule(ROOT / "hia/src" / source, byte_exports=("f0",))
            cls.modules[name] = module
            cls.addClassCleanup(module.close)
            cls.builds[name] = {"receipt": module.receipt, "actual_build": native_build_record(module, cls.before)}
            (cls.directory / (name + ".so")).write_bytes(module.library.read_bytes())
        (cls.directory / "native-builds.json").write_text(json.dumps(cls.builds, indent=2) + "\n")
        cls.bench_original, cls.bench_identity = build_original(cls.directory)
        cls.original = cls.directory / "profile-original"
        types = Path(cls.bench_identity["dependencies"]["trnm_types"]["path"])
        if digest(types.read_bytes()) != cls.bench_identity["dependencies"]["trnm_types"]["sha256"]:
            raise AssertionError("Actual original type library changed")
        env = clean_environment()
        env["TRNM_EXECUTOR_SOURCE"] = str(EXECUTOR)
        command = ["rustc", "--edition=2021", "--deny=warnings", str(REFERENCE), "-o", str(cls.original),
                   "--extern", "trnm_types=" + str(types), "-L", "dependency=" + str(types.parent)]
        run_original_command(cls.directory, "profile-rustc", command, env, 90)
        cls.original_identity = {"source_sha256": digest(EXECUTOR.read_bytes()),
            "adapter_source_sha256": digest(REFERENCE.read_bytes()), "binary_sha256": digest(cls.original.read_bytes()),
            "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
            "type_library": cls.bench_identity["dependencies"]["trnm_types"], "original_source_transformed": False}
        cls.mpfr = MPFRReference()
        cls.addClassCleanup(cls.mpfr.close)
        cls.raw_path = cls.directory / "native-calls.jsonl.gz"
        cls.raw_file = cls.raw_path.open("wb")
        cls.raw = gzip.GzipFile(filename="", mode="wb", fileobj=cls.raw_file, mtime=0)
        cls.addClassCleanup(cls.raw_file.close)
        cls.addClassCleanup(cls.raw.close)
        cls.events, cls.differences, cls.counts, cls.formatted = [], [], {}, {}

    @classmethod
    def tearDownClass(cls):
        cls.raw.close()
        cls.raw_file.close()
        stable = source_inputs() == cls.before
        report = {"schema": "trnm.hia.bench-profile.observations.v1", "observations_only": True,
            "source_inputs": cls.before, "source_unchanged": stable, "original": cls.original_identity,
            "original_bench": cls.bench_identity, "mpfr": cls.mpfr.identity, "builds": cls.builds,
            "counts": cls.counts, "native_invocations": cls.events, "raw_platform_differences": cls.differences,
            "complete_raw_native_calls": {"path": str(cls.raw_path), "bytes": cls.raw_path.stat().st_size,
                                           "sha256": digest(cls.raw_path.read_bytes())},
            "whole_bench_native_qualified": False, "complete_report_renderer_qualified": False,
            "native_os_owner_qualified": False, "wall_seconds": time.monotonic() - cls.started}
        (cls.directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"bench_profile_observations": str(cls.directory / "report.json"),
                          "counts": cls.counts, "raw_platform_differences": len(cls.differences)}))
        if not stable:
            raise AssertionError("Bench profile source changed during qualification")

    def calls(self, component, cases):
        results = self.modules[component].call_many(cases, timeout=60)
        self.counts[component] = self.counts.get(component, 0) + len(results)
        for sent, got in zip(cases, results):
            event = {"component": component, "artifact_sha256": self.modules[component].artifact_sha256,
                "input_sha256": digest(sent[1][0]), "argument_sha256": [digest(arg) for arg in sent[1]],
                "argument_bytes": [len(arg) for arg in sent[1]], "status": got.status,
                "returncode": got.returncode, "value": got.value, "abi_status": got.abi_status,
                "output_sha256": None if got.arguments is None else digest(got.arguments[1])}
            self.events.append(event)
            raw = {**event, "sent": [base64.b64encode(arg).decode() for arg in sent[1]],
                   "returned": None if got.arguments is None else [base64.b64encode(arg).decode() for arg in got.arguments],
                   "stderr": got.stderr}
            self.raw.write((json.dumps(raw, separators=(",", ":")) + "\n").encode())
        self.raw.flush()
        return results

    def original_rows(self, commands, label, executable=None):
        data = "".join(commands).encode()
        (self.directory / (label + ".input.raw")).write_bytes(data)
        actual = subprocess.run([str(executable or self.original)], input=data, env=clean_environment(),
                                capture_output=True, timeout=60)
        (self.directory / (label + ".stdout.raw")).write_bytes(actual.stdout)
        (self.directory / (label + ".stderr.raw")).write_bytes(actual.stderr)
        self.assertEqual(actual.returncode, 0, actual.stderr.decode(errors="backslashreplace"))
        lines = actual.stdout.decode().splitlines()
        self.assertEqual(len(lines), len(commands))
        return lines

    def float_texts(self, values):
        missing = sorted(set(values) - self.formatted.keys())
        for begin in range(0, len(missing), 64):
            batch = missing[begin:begin + 64]
            cases = [("f0", [b"BFLD0001" + struct.pack("<Q", value), b"\xa5" * 340, b"\xc3" * 4625])
                     for value in batch]
            for value, sent, got in zip(batch, cases, self.calls("format", cases)):
                got.require_returned()
                self.assertEqual(got.value, 0)
                length, = struct.unpack_from("<Q", got.arguments[1])
                self.assertLessEqual(length, 315)
                self.formatted[value] = got.arguments[1][8:8 + length].decode("ascii")
                self.assertEqual(got.arguments[1][8 + length:], b"\xa5" * (332 - length))
                for a, b in ((0, 1024), (2048, 4096), (4608, 4625)):
                    self.assertEqual(got.arguments[2][a:b], sent[1][2][a:b])
        return {value: self.formatted[value] for value in values}

    def test_logarithm_all_exponents_intervals_and_actual_rust_text(self):
        values = logarithm_inputs()
        refs = self.original_rows([f"L {value:016x}\n" for value in values], "logarithm-original")
        observed, stages = [], {128: 0, 256: 0, 0: 0}
        for begin in range(0, len(values), 64):
            batch = values[begin:begin + 64]
            cases = [("f0", [b"BLOG0001" + struct.pack("<Q", value), b"\xa5" * 33, b"\xc3" * 1041])
                     for value in batch]
            for value, got in zip(batch, self.calls("ln", cases)):
                got.require_returned()
                self.assertEqual(got.value, 0, hex(value))
                actual, precision = struct.unpack_from("<QQ", got.arguments[1])
                self.assertEqual(actual, self.mpfr.ln(value), hex(value))
                self.assertEqual(got.arguments[1][16:], b"\xa5" * 17)
                self.assertEqual(got.arguments[2][1024:], b"\xc3" * 17)
                stages[precision] += 1
                if value != ONE:
                    self.assertIn(precision, (128, 256))
                    limbs = precision // 32 + 1
                    span = 8 * limbs
                    endpoints = []
                    for slot in (11, 12):
                        digits = struct.unpack_from("<" + "Q" * limbs, got.arguments[2], slot * span)
                        self.assertTrue(all(digit < 1 << 32 for digit in digits))
                        endpoints.append(sum(digit << (32 * n) for n, digit in enumerate(digits)))
                    self.assertEqual(endpoints[1] - endpoints[0], 1 << 21)
                    self.assertTrue(self.mpfr.encloses(value, precision, *endpoints), hex(value))
                else:
                    self.assertEqual(precision, 0)
                observed.append((value, actual, precision))
        texts = self.float_texts([row[1] for row in observed])
        rows = []
        for row, reference in zip(observed, refs):
            value, actual, precision = row
            self.assertTrue(reference.startswith("ok "))
            original, text = reference[3:].split("|", 1)
            record = {"input": f"{value:016x}", "native": f"{actual:016x}", "rust": original,
                      "precision": precision, "native_text": texts[actual], "rust_text": text}
            rows.append(record)
            if int(original, 16) != actual:
                self.differences.append({"kind": "logarithm-platform-precision", **record})
            self.assertEqual(texts[actual], text, record)
        (self.directory / "logarithm-pairs.json").write_text(json.dumps(rows, indent=2) + "\n")
        self.assertGreater(stages[128], 0)
        self.assertGreater(stages[256], 0)
        self.assertEqual(next(p for v, _, p in observed if v == 0x3DC613955DC802F8), 256)
        self.counts.update(logarithm_mpfr_pairs=len(values), logarithm_interval_enclosures=len(values) - 1,
                           logarithm_precision_stages=stages, logarithm_final_text_pairs=len(values))

    def test_logarithm_special_values_and_nan_payloads(self):
        values = [0, 1 << 63, 0x7FF0000000000000, 0xFFF0000000000000,
                  0x8000000000000001, 0xBFF0000000000000, 0xFFEFFFFFFFFFFFFF]
        for sign in (0, 1 << 63):
            values += [sign | 0x7FF0000000000000 | payload
                       for payload in (1, 0x123, 1 << 51, (1 << 51) + 0x456, (1 << 52) - 1)]
        refs = self.original_rows([f"L {value:016x}\n" for value in values], "logarithm-special-original")
        cases = [("f0", [b"BLOG0001" + struct.pack("<Q", value), b"\xa5" * 33, b"\xc3" * 1041])
                 for value in values]
        actuals = []
        for value, got in zip(values, self.calls("ln", cases)):
            got.require_returned()
            self.assertEqual(got.value, 0)
            actual, precision = struct.unpack_from("<QQ", got.arguments[1])
            self.assertEqual(precision, 0)
            self.assertEqual(got.arguments[1][16:], b"\xa5" * 17)
            self.assertEqual(got.arguments[2], b"\xc3" * 1008 + bytes(8) + b"\xc3" * 25)
            actuals.append(actual)
        texts = self.float_texts(actuals)
        for value, actual, reference in zip(values, actuals, refs):
            self.assertTrue(reference.startswith("ok "))
            original, text = reference[3:].split("|", 1)
            self.assertEqual(actual, int(original, 16), hex(value))
            self.assertEqual(texts[actual], text, hex(value))
        self.counts["logarithm_special_actual_rust_pairs"] = len(values)

    def test_complete_four_place_float_fields_match_actual_rust(self):
        values = {0, 1, (1 << 52) - 1, 1 << 52, 0x7FEFFFFFFFFFFFFF,
                  0x7FF0000000000000, 0x7FF0000000000001, 0x7FF8000000000000,
                  0x7FFFFFFFFFFFFFFF}
        for exponent in range(0, 2047, 29):
            values.update((exponent << 52) | mantissa for mantissa in (0, 1, (1 << 52) - 1))
        for value in (.00005, .00015, .03125, .09375, .99995, 9.99995, 1.23445, float(U64)):
            values.update((bits(value) - 1, bits(value), bits(value) + 1))
        values |= {value | (1 << 63) for value in values}
        rng = random.Random(0x4250524F464D5434)
        values.update(rng.randrange(1 << 64) for _ in range(128))
        values = sorted(values)
        refs = self.original_rows([f"F {value:016x}\n" for value in values], "full-float-original")
        texts = self.float_texts(values)
        for value, reference in zip(values, refs):
            self.assertEqual(reference, f"ok {value:016x}|" + texts[value])
        self.counts["full_float_actual_rust_pairs"] = len(values)

    def check_profiles(self, rows, label):
        refs = self.original_rows(["P " + " ".join(f"{v:016x}" for v in row) + "\n" for row in rows], label)
        observations = []
        for begin in range(0, len(rows), 32):
            batch = rows[begin:begin + 32]
            cases = [("f0", [b"BPRO0001" + struct.pack("<17Q", *row), b"\xa5" * 433, b"\xc3" * 2065])
                     for row in batch]
            for sent, got in zip(cases, self.calls("profile", cases)):
                got.require_returned()
                self.assertEqual(got.value, 0)
                self.assertEqual(got.arguments[1][:8], b"BPROOUT1")
                self.assertEqual(got.arguments[1][416:], b"\xa5" * 17)
                self.assertEqual(got.arguments[2][1160:], b"\xc3" * (2065 - 1160))
                self.assertEqual(got.arguments[2][1024:1160], sent[1][0][8:])
                observations.append(struct.unpack_from("<51Q", got.arguments[1], 8))
        texts = self.float_texts([value for row in observations for i, value in enumerate(row)
                                 if i not in INTEGER_FIELDS and i != 32])
        differences = 0
        pairs = []
        for index, (row, actual, reference) in enumerate(zip(rows, observations, refs)):
            self.assertTrue(reference.startswith("ok "), (index, reference))
            fields = reference[3:].split()
            self.assertEqual(len(fields), len(METHODS))
            attributed = row[12] + row[14] + row[16]
            entropy = -0.0
            if attributed:
                for weight in (row[12], row[14], row[16]):
                    if weight:
                        share = float(weight) / float(attributed)
                        entropy += -share * number(self.mpfr.ln(bits(share)))
                entropy /= number(self.mpfr.ln(bits(3.0)))
            else:
                entropy = 0.0
            self.assertEqual(actual[49], bits(entropy), (index, "independent entropy"))
            for field, (value, original) in enumerate(zip(actual, fields)):
                original_bits, original_text = original.split("|", 1)
                native_text = (str(value) if field in INTEGER_FIELDS else
                               STAGES[value] if field == 32 else texts[value])
                entry = {"case": index, "method": METHODS[field], "native": f"{value:016x}",
                         "rust": original_bits, "native_text": native_text, "rust_text": original_text}
                if value != int(original_bits, 16):
                    self.assertEqual(field, 49, entry)
                    differences += 1
                    self.differences.append({"kind": "profile-entropy-platform-precision", "corpus": label,
                                             "profile": [f"{v:016x}" for v in row], **entry})
                self.assertEqual(native_text, original_text, entry)
                pairs.append(entry)
        (self.directory / (label + ".pairs.json")).write_text(json.dumps(pairs, indent=2) + "\n")
        self.counts[label + "_profiles"] = len(rows)
        self.counts[label + "_field_pairs"] = len(rows) * len(METHODS)
        self.counts[label + "_entropy_bit_differences"] = differences

    def test_derived_profile_methods_and_final_fields(self):
        self.check_profiles(profile_inputs(), "profile-synthetic-original")

    def test_profiles_from_actual_three_workloads_and_seven_strategies(self):
        inputs = [(workload, n, 17 if workload != 2 else 3, 2, 3, strategy)
                  for n in (65, 513) for workload in range(3) for strategy in range(7)]
        answers = self.original_rows([" ".join(map(str, row)) + "\n" for row in inputs],
                                     "workload-schedule-original", self.bench_original)
        rows, cases, originals = [], [], []
        for source in answers:
            raw, _, _, output = map(bytes.fromhex, source.split("\t"))
            txs = txs_from_frame(raw)
            count, work = sizes(txs)
            old, _ = decoded_output(output, len(txs), 0)
            rows.append(old["profile"])
            originals.append((txs, old))
            cases.append(("f0", [raw, b"\xa5" * (count + 17), b"\xc3" * (work + 13)]))
        repaired = []
        for row, (txs, old), sent, actual in zip(inputs, originals, cases, self.calls("schedule", cases)):
            actual.require_returned()
            self.assertEqual(actual.value, 0)
            new, used = decoded_output(actual.arguments[1], len(txs), 0)
            self.assertEqual(graph_violations(txs, new["groups"]), [])
            self.assertEqual(actual.arguments[1][used:], b"\xa5" * (len(sent[1][1]) - used))
            self.assertEqual(actual.arguments[2][-13:], b"\xc3" * 13)
            rows.append(new["profile"])
            if old != new:
                repaired.append({"input": list(row), "original_profile": old["profile"],
                                 "native_profile": new["profile"],
                                 "original_graph_violations": graph_violations(txs, old["groups"]),
                                 "native_graph_violations": []})
        (self.directory / "existing-high-water-differences.json").write_text(json.dumps(repaired, indent=2) + "\n")
        self.check_profiles(rows, "profile-actual-schedulers-original")
        self.counts["actual_scheduler_profiles"] = len(inputs)
        self.counts["existing_high_water_differences"] = len(repaired)

    def test_frame_and_capacity_refusals_are_atomic(self):
        for component, magic, words, output, work in (
                ("ln", b"BLOG0001", [ONE], 16, 1024),
                ("profile", b"BPRO0001", [0] * 17, 416, 2048),
                ("format", b"BFLD0001", [0x7FF8000000000000], 323, 4608)):
            base = magic + struct.pack("<" + "Q" * len(words), *words)
            variants = [(base[:n], output, work, 1) for n in range(len(base))]
            variants += [(base + b"x", output, work, 1), (b"X" + base[1:], output, work, 2)]
            variants += [(base, n, work, 100) for n in (0, 1, 7, output - 1)]
            variants += [(base, output, n, 100) for n in (0, 1, 127, work - 1)]
            cases = [("f0", [raw, b"\xa5" * a, b"\xc3" * b]) for raw, a, b, _ in variants]
            for sent, variant, actual in zip(cases, variants, self.calls(component, cases)):
                actual.require_returned()
                self.assertEqual(actual.value, variant[3])
                self.assertEqual(actual.arguments, sent[1])
            self.counts[component + "_atomic_refusals"] = len(cases)

    def test_profile_checked_additions_preserve_actual_original_panics(self):
        rows = []
        for field in (14, 16):
            row = [0] * 17
            row[12], row[field] = U64, 1
            rows.append(row)
        row = [0] * 17
        row[0], row[10] = U64, 1
        rows.append(row)
        refs = self.original_rows(["P " + " ".join(f"{v:016x}" for v in row) + "\n" for row in rows],
                                  "profile-checked-overflow-original")
        self.assertEqual(refs, ["panic"] * len(rows))
        for row in rows:
            case = ("f0", [b"BPRO0001" + struct.pack("<17Q", *row), b"\xa5" * 416, b"\xc3" * 2048])
            actual = self.calls("profile", [case])[0]
            self.assertEqual((actual.status, actual.returncode), ("trapped", -4))
        self.counts["actual_original_panic_and_native_trap_pairs"] = len(rows)
        native = self.modules["profile"]
        inputs = [b"BPRO0001" + struct.pack("<17Q", *row) for row in rows]
        request = {"library": str(native.library), "sha256": native.artifact_sha256,
                   "inputs": [base64.b64encode(raw).decode() for raw in inputs]}
        encoded = json.dumps(request).encode()
        (self.directory / "overflow-native.request.json").write_bytes(encoded)
        observed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", OVERFLOW_WORKER],
                                  input=encoded, capture_output=True, timeout=15)
        (self.directory / "overflow-native.stdout.raw").write_bytes(observed.stdout)
        (self.directory / "overflow-native.stderr.raw").write_bytes(observed.stderr)
        self.assertEqual(observed.returncode, 0, observed.stderr.decode(errors="backslashreplace"))
        result = json.loads(observed.stdout)
        self.assertEqual(result["artifact_sha256"], native.artifact_sha256)
        self.assertEqual(result["host_compiler_modules_loaded"], [])
        self.assertEqual(len(result["answers"]), len(rows))
        for sent, row in zip(inputs, result["answers"]):
            self.assertEqual((row["signal"], row["exit_code"]), (4, None))
            self.assertEqual(row["pointer_residues"], [1, 3, 5])
            before, after = ([base64.b64decode(v, validate=True) for v in row[key]]
                             for key in ("before", "after"))
            self.assertEqual(after[:2], before[:2])
            expected_work = bytearray(before[2])
            expected_work[21 + 1024:21 + 1160] = sent[8:]
            self.assertEqual(after[2], expected_work)
        self.counts["raw_shared_mapping_overflow_invocations"] = len(rows)


if __name__ == "__main__":
    unittest.main()
