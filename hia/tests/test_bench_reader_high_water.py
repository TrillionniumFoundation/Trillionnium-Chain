"""Test-only reader-high-water-v1 qualification; never edits the Rust checkout."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
import tomllib
import unittest

from hia.platform.bench.main_build import build
from hia.platform.build import new_output, sealed_executable
from hia.tests.native_support import NativeModule
from hia.tests.test_bench_main import replay_fixture, stdout_observation
from hia.tests.test_bench_native import REFERENCE, request, run_original_command, txs_from_frame
from hia.tests.test_bench_report import report_case, report_frame
from hia.tests.test_executor_schedule import decoded_output, sizes, tx

ROOT = Path(__file__).resolve().parents[2]
LIB = Path("crates/trnm-executor/src/lib.rs")
MAIN = Path("crates/trnm-bench/src/main.rs")
LOCK = Path("Cargo.lock")
SOURCE_SHA = "d5cf48dfe4daa00bd739b39bd3dbbc2148f6bddf171eb0e356b0f1df434db5f4"
SEMANTICS = "reader-high-water-v1"
MODE = "--reader-high-water-v1"
STAMP = b"schedule_semantics=reader-high-water-v1\n"
CORRECTED_BASENAME = "executor-profile-summary-reader-high-water-v1-"
LIMIT = 16 << 20
WORKLOADS = {0: "classic", 1: "mixed", 2: "hot-streak"}
STRATEGIES = {0: "original", 2: "write-first", 4: "hot-bucket-interleave"}
OUTSIDE = b"Bench native candidate: invocation outside admitted Bench scope\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def corrected_executor(raw):
    if sha(raw) != SOURCE_SHA:
        raise ValueError("Unreviewed active executor Rust source")
    for key, group, count in ((b"key", b"required_group", 1), (b"key", b"min_group", 1),
                              (b"*key", b"idx", 2)):
        old = b"latest_reader_group.insert(" + key + b", " + group + b");"
        new = (b"latest_reader_group.entry(" + key + b")"
               b".and_modify(|slot| *slot = (*slot).max(" + group + b"))"
               b".or_insert(" + group + b");")
        if raw.count(old) != count:
            raise ValueError("Exact reader-only owner sites changed")
        raw = raw.replace(old, new)
    if raw.count(b"latest_reader_group.entry(") != 4:
        raise ValueError("Missing one fast/ordinary/aggressive reader update")
    return raw


def identity_tree(path):
    return {p.relative_to(path).as_posix(): sha(p.read_bytes())
            for p in path.rglob("*") if p.is_file() and not p.is_symlink()}


def cargo_oracle(directory, private, target):
    anchor = private / "trillionnium"
    exact = ["git", "archive", "--format=tar", "HEAD", "trillionnium"]
    tracked = subprocess.check_output(exact, cwd=ROOT, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(tracked), mode="r:") as archive:
        if any(not (row.isdir() or row.isfile()) for row in archive):
            raise ValueError("Linked or special file in isolated Cargo source")
        archive.extractall(private, filter="data")
    before = identity_tree(anchor)
    real = ROOT / "trillionnium"
    originals = {str(p): sha((real / p).read_bytes()) for p in (LIB, MAIN, LOCK)}
    if any(before[k] != v for k, v in originals.items()):
        raise ValueError("Isolated original source or lock differs")
    local_lib = anchor / LIB
    corrected = corrected_executor(local_lib.read_bytes())
    local_lib.write_bytes(corrected)
    expected = dict(before, **{str(LIB): sha(corrected)})
    if identity_tree(anchor) != expected:
        raise ValueError("Unexpected isolated oracle change")
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME",
           "RUSTUP_TOOLCHAIN", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTC") if key in os.environ}
    for tool in ("cargo", "rustc"):
        version = subprocess.check_output([tool, "--version"], env=env, text=True, timeout=10)
        if version.split()[:2] != [tool, pin]:
            raise ValueError(f"Expected pinned {tool} {pin}")
    command = ["cargo", "build", "--locked", "--offline", "--manifest-path", str(anchor / "Cargo.toml"),
               "--target-dir", str(target), "-p", "trnm-bench", "--message-format=json"]
    result = run_original_command(directory, "corrected-oracle-cargo", command, env, 240)
    cli = []
    deps = {}
    wanted = {"sha2", "clap", "trnm_executor", "trnm_types"}
    for line in result.stdout.splitlines():
        entry = json.loads(line)
        if entry.get("reason") != "compiler-artifact":
            continue
        name = entry["target"]["name"]
        if name == "trnm-bench" and "bin" in entry["target"]["kind"] and entry.get("executable"):
            cli.append(Path(entry["executable"]))
        if name not in wanted or (name == "sha2" and "0.10." not in entry["package_id"]):
            continue
        libs = [Path(x) for x in entry["filenames"] if x.endswith(".rlib")]
        if len(libs) != 1 or not libs[0].is_relative_to(target) or (name in deps and deps[name] != libs[0]):
            raise ValueError("Ambiguous or unowned corrected-oracle dependency")
        deps[name] = libs[0]
    if len(cli) != 1 or not cli[0].is_relative_to(target) or set(deps) != wanted:
        raise ValueError("Expected actual locked corrected Cargo artifacts")
    adapter = private / "corrected-adapter"
    command = ["rustc", "--edition=2021", "--deny=warnings", str(REFERENCE), "-o", str(adapter)]
    for name, path in sorted(deps.items()):
        command += ["--extern", name + "=" + str(path)]
    for path in sorted({lib.parent for lib in deps.values()}):
        command += ["-L", "dependency=" + str(path)]
    env.update(TRNM_BENCH_SOURCE=str(anchor / MAIN), CARGO_MANIFEST_DIR=str((anchor / MAIN).parents[1]))
    run_original_command(directory, "corrected-oracle-adapter", command, env, 90)
    if identity_tree(anchor) != expected or {str(p): sha((real / p).read_bytes()) for p in (LIB, MAIN, LOCK)} != originals:
        raise ValueError("Tracked Rust source/lock or private oracle changed during build")
    receipt = {"semantics": SEMANTICS, "test_only": True, "tracked_original_untouched": True,
               "snapshot_sha256": sha(tracked), "source_git_head": subprocess.check_output(
                   ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip(),
               "original_sources": originals, "corrected_executor_sha256": sha(corrected),
               "reader_map_updates": 4, "rustc_and_cargo_pin": pin, "cli_sha256": sha(cli[0].read_bytes()),
               "adapter_sha256": sha(adapter.read_bytes()),
               "dependency_sha256": {name: sha(file.read_bytes()) for name, file in deps.items()}}
    (directory / "oracle-identity.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return anchor, cli[0], adapter


LARGE_CALL = r"""
import ctypes, fcntl, hashlib, os, resource, struct, sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
resource.setrlimit(resource.RLIMIT_CPU,(20,20))
raw=sys.stdin.buffer.read((16<<20)+1)
out_n,scratch_n=map(int,sys.argv[3:])
if any(not 0 <= n <= 16<<20 for n in (len(raw),out_n,scratch_n)):
    raise ValueError("outside private test transport cap")
image=open(sys.argv[1],"rb").read()
if hashlib.sha256(image).hexdigest()!=sys.argv[2]:
    raise ValueError("native artifact changed")
fd=os.memfd_create("bench-reader-high-water",os.MFD_ALLOW_SEALING)
with os.fdopen(os.dup(fd),"wb") as f:
    if f.write(image)!=len(image):
        raise ValueError("short artifact copy")
fcntl.fcntl(fd,getattr(fcntl,"F_ADD_SEALS",1033),15)
if fcntl.fcntl(fd,getattr(fcntl,"F_GET_SEALS",1034))!=15:
    raise ValueError("unsealed artifact")
lib=ctypes.CDLL("/proc/self/fd/"+str(fd))
os.close(fd)
entry=lib.f0
entry.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3
entry.restype=ctypes.c_uint64
def arena(n, fill, residue):
    obj=ctypes.create_string_buffer(n+64)
    address=ctypes.addressof(obj)
    at=16+(residue-address)%8
    ctypes.memset(address,fill,n+64)
    return obj,at,address+at,n
i,o,s=arena(len(raw),0xC1,1),arena(out_n,0xA5,3),arena(scratch_n,0xD3,5)
ctypes.memmove(i[2],raw,len(raw))
def guard(a):
    obj,at,_,n=a
    return obj.raw[:at],obj.raw[at+n:]
old=[guard(a) for a in (i,o,s)]
code=entry(i[2],i[3],o[2],o[3],s[2],s[3])
if old!=[guard(a) for a in (i,o,s)] or ctypes.string_at(i[2],i[3])!=raw:
    raise ValueError("native wrote outside borrowed mutable extents")
sys.stdout.buffer.write(struct.pack("<Q",code)+ctypes.string_at(o[2],o[3]))
"""


def independent_access_graph(txs, groups):
    """Each group's original access edges are checked without scheduler maps."""
    by_id = {tx.identity: tx for tx in txs}
    if len(by_id) != len(txs):
        raise ValueError("Bench fixture identity isn't unique")
    seen = set()
    edges = 0
    for group in groups:
        reads, writes = set(), set()
        for member in group:
            if member not in by_id or member in seen:
                raise ValueError("Wrong or repeated transaction membership")
            seen.add(member)
            tx = by_id[member]
            r, w = ({key for key, _ in refs} for refs in (tx.reads, tx.writes))
            if r & writes or w & (reads | writes):
                raise ValueError("Within-group WW/WR/RW conflict")
            edges += len(r) + len(w)
            reads.update(r)
            writes.update(w)
    if seen != by_id.keys():
        raise ValueError("Dropped transaction")
    return edges


class IndependentAccessGraphTests(unittest.TestCase):
    def test_membership_and_conflict_controls(self):
        frame = [tx(12, reads=[1]), tx(29, reads=[1]), tx(31, writes=[1])]
        self.assertEqual(independent_access_graph(frame, [[12, 29], [31]]), 3)
        for groups in ([[12, 29, 31]], [[12, 29], [31, 31]], [[12], [31]], [[12, 29], [55]]):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                independent_access_graph(frame, groups)


class BenchReaderHighWater(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("HIA_BENCH_READER_HIGH_WATER_OBSERVATIONS")
        cls.persist_native_requests = bool(configured)
        cls.root = (new_output(Path(configured)) if configured else Path(cls.enterClassContext(
            tempfile.TemporaryDirectory(prefix="trnm-bench-reader-high-water-"))))
        private = cls.root / "isolated-source"
        private.mkdir(mode=0o700)
        cls.addClassCleanup(shutil.rmtree, private)
        target = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-corrected-cargo-")))
        cls.anchor, cls.cli, cls.adapter = cargo_oracle(cls.root, private, target)
        cls.native = {name: cls.enterClassContext(NativeModule(ROOT / f"hia/src/{source}.hepta",
                                     byte_exports=("f0",))) for name, source in (
            ("workload", "bench/workload"), ("schedule", "executor/schedule"),
            ("repeat", "bench/repeat"), ("digests", "bench/digests"),
            ("profile", "bench/profile"), ("report", "bench/report"))}
        cls.image, cls.image_receipt = build(cls.root / "corrected-bound", bind_profile_output=True)
        cls.events = []
        cls.results = []
        cls.standalone = []

    @classmethod
    def tearDownClass(cls):
        record = {"semantics": SEMANTICS, "test_only": True, "actual_native_calls": cls.events,
                  "cohorts": cls.results, "legacy_vulnerable_runtime_replayed": False,
                  "explicit_corrected_elf": cls.standalone,
                  "unmarked_elf_default_admission_expanded": False, "production_activation": False,
                  "native_machine": {name: m.receipt for name, m in cls.native.items()}}
        (cls.root / "observations.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

    def actual(self, case, command, data=b""):
        result = subprocess.run(command, input=data, env={}, cwd=self.root, timeout=45, capture_output=True)
        for name, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            (self.root / f"{case}.{name}.raw").write_bytes(raw)
        self.assertEqual((result.returncode, result.stderr), (0, b""), case)
        return result.stdout

    def native_call(self, case, name, data, output, scratch):
        module = self.native[name]
        if max(len(data), output, scratch) > LIMIT:
            raise ValueError("Outside test-only private transport")
        sent = [sys.executable, "-I", "-S", "-B", "-c", LARGE_CALL, str(module.library),
                module.artifact_sha256, str(output), str(scratch)]
        if self.persist_native_requests:
            (self.root / f"{case}.stdin.raw").write_bytes(data)
        response = self.actual(case, sent, data)
        status, = struct.unpack_from("<Q", response)
        self.assertEqual((status, len(response)), (0, 8 + output), case)
        self.events.append({"label": case, "source": name, "request_sha256": sha(data),
                            "request_bytes": len(data), "output_sha256": sha(response[8:]),
                            "output_bytes": output, "scratch_bytes": scratch, "status": status,
                            "unaligned_pointer_residues": [1, 3, 5]})
        return response[8:]

    def test_native_defaults_match_corrected_rust_graph_profile_and_replay(self):
        rows = ((0, 32, 7, 3, 1, 0), (1, 20000, 2000, 3, 1, 0),
                (2, 20000, 2000, 3, 1, 0), (2, 20000, 2000, 3, 1, 4),
                (1, 20000, 1, 8, 1, 0),
                (1, 20000, 2000, 3, 1, 2), (2, 20000, 2000, 3, 1, 2))
        for row_index, row in enumerate(rows):
            with self.subTest(row=row):
                self.compare_cohort(row_index, row)

    def compare_cohort(self, row_index, row):
        w, n, k, fan, stride, strategy = row
        label = f"cohort-{row_index}"
        # The unchanged adapter wraps the actual corrected Cargo dependencies,
        # calls the unmodified Bench workload, and emits raw profile and groups.
        rust = self.actual(label + "-corrected-observer", [str(self.adapter)],
                           (" ".join(map(str,row)) + "\n").encode())
        ref_hex, input_hex, groups_hex, order_hex = rust.split()
        raw, reference = bytes.fromhex(ref_hex.decode()), bytes.fromhex(order_hex.decode())
        refs = txs_from_frame(raw)
        out_n, scratch_n = sizes(refs)
        workload = self.native_call(label+"-workload", "workload", request(row), len(raw)+8+19, 0)
        self.assertEqual(workload, struct.pack("<Q",len(raw)) + raw + b"\xA5"*19)
        native = self.native_call(label+"-schedule", "schedule", raw, out_n+19, scratch_n)
        result, used = decoded_output(native, n, 0)
        oracle_groups, oracle_length = decoded_output(reference, n, 0)
        edges = independent_access_graph(refs, result["groups"])
        self.assertEqual(edges, independent_access_graph(refs, oracle_groups["groups"]))
        self.assertEqual(native, reference + b"\xA5" * (len(native) - len(reference)))
        self.assertEqual(used, oracle_length)
        self.assertEqual(used, len(reference))
        repeats = 2
        repeat_frame = bytearray(raw)
        repeat_frame[:8] = b"BNCHREP1"
        struct.pack_into("<Q",repeat_frame,112,repeats)
        repeated = self.native_call(label+"-replay","repeat",bytes(repeat_frame),2*out_n+112+19,scratch_n)
        self.assertEqual(repeated[:used],reference)
        self.assertEqual(repeated[used:out_n],b"\xA5"*(out_n-used))
        self.assertEqual(struct.unpack_from("<8s5Q",repeated,out_n),
                         (b"BNCHRES1",repeats,1,repeats+1,used,result["group_count"]))
        hashes=bytes.fromhex((input_hex+groups_hex).decode())
        self.assertEqual(repeated[out_n+48:out_n+112],hashes)
        self.assertEqual(repeated[out_n+112:],reference + b"\xA5"*(out_n+19-used))
        for idx, data in enumerate((raw, reference)):
            digest=self.native_call(f"{label}-digest-{idx}","digests",data,32+19,1208)
            self.assertEqual(digest,hashes[idx*32:idx*32+32]+b"\xA5"*19)
        p=self.native_call(label+"-profile","profile",
             b"BPRO0001"+struct.pack("<17Q",*result["profile"]),416+19,2048)
        self.assertEqual((p[:8],p[416:]),(b"BPROOUT1",b"\xA5"*19))
        derived=list(struct.unpack_from("<51Q",p,8))
        command=[str(self.cli),"--workload",WORKLOADS[w],
                 "--strategy",STRATEGIES[strategy],"--determinism-repeats",str(repeats),"--profile"]
        if (n, k, fan, stride) != (20000, 2000, 3, 1):
            command += ["--txs", str(n), "--keys", str(k), "--read-fanout", str(fan), "--write-every", str(stride)]
        stdout=self.actual(label+"-corrected-cli",command)
        fields=dict(line.split(b"=",1) for line in stdout.splitlines()[1:])
        self.assertEqual(fields[b"determinism.input_sha256"],input_hex)
        self.assertEqual(fields[b"determinism.groups_sha256"],groups_hex)
        self.assertEqual(fields[b"determinism.replay_match"],b"true")
        profile=Path(os.fsdecode(fields[b"profile.report.path"]))
        self.assertEqual(profile.parent,self.anchor/"run/bench")
        persisted=profile.read_bytes()
        (self.root / (label + "-corrected-profile.raw")).write_bytes(persisted)
        elapsed=int(fields[b"elapsed_ms"])
        epoch=int(fields[b"profile.report.capture_started_at_epoch"])
        context=[w,strategy,n,k,fan,stride,1,1,repeats,1,epoch,elapsed,0,
                 result["group_count"],n]
        sent=report_case(report_frame(context,result["profile"],derived,result["decision"],
                         hashes,2,os.fsencode(profile),fields[b"profile.report.artifact_basename"]))
        rendered=self.native_call(label+"-report","report",sent[1][0],len(sent[1][1]),len(sent[1][2]))
        tag,code,a,b,c=struct.unpack_from("<8s4Q",rendered)
        self.assertEqual((tag,code,b),(b"BRPTOUT1",0,0))
        self.assertEqual(rendered[40:40+a],stdout)
        self.assertEqual(rendered[40+a:40+a+c],persisted)
        self.assertEqual(rendered[40+a+c:],b"\xA5"*(len(rendered)-40-a-c))
        if w:
            self.compare_standalone(label, command[1:], stdout, profile, persisted, len(raw), scratch_n)
        self.results.append({"label":label,"input":row,"group_count":result["group_count"],
                             "independent_accesses":edges,"conflicts":0,"members":n,
                             "input_sha256":input_hex.decode(),"group_sha256":groups_hex.decode(),
                             "profile_sha256":sha(persisted),"native_schedule_invocations_in_replay":3})

    def standalone_process(self, label, args, *, image=None, env=None):
        fd = sealed_executable(self.image if image is None else image, label)
        try:
            before = time.time_ns()
            monotonic = time.monotonic_ns()
            result = subprocess.run(["trnm-bench", *args], executable=f"/proc/self/fd/{fd}",
                        pass_fds=(fd,), env={} if env is None else env, cwd=self.root,
                        stdin=subprocess.DEVNULL, capture_output=True, timeout=25)
            elapsed = time.monotonic_ns() - monotonic
            after = time.time_ns()
        finally:
            os.close(fd)
        for k, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            (self.root / f"{label}.{k}.raw").write_bytes(raw)
        return result, elapsed, before, after

    def compare_standalone(self, label, args, rust_stdout, rust_path, rust_file, work_bytes, scratch_bytes):
        # Both binaries take their own clocks. Only exact clock/path-dependent
        # fields and the new explicit semantics metadata are normalized.
        native, wall, before, after = self.standalone_process(label+"-native-profile", [MODE, *args])
        self.assertEqual((native.returncode, native.stderr), (0, b""))
        measured, _ = stdout_observation(native.stdout, wall)
        self.assertGreater(measured, 0)
        keys = dict(line.split(b"=", 1) for line in native.stdout.splitlines()[1:])
        epoch = int(keys[b"profile.report.capture_started_at_epoch"])
        self.assertLessEqual(before//1_000_000_000, epoch)
        self.assertLessEqual(epoch, after//1_000_000_000)
        iso = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ").encode()
        self.assertEqual(keys[b"profile.report.capture_started_at_iso"], iso)
        self.assertEqual(keys[b"profile.report.elapsed_ms"], str(measured).encode())
        for key in (b"capture_stamp", b"capture_stamp_epoch"):
            self.assertEqual(keys[b"profile.report."+key], str(epoch).encode())
        candidate = self.anchor/"run/bench"/f"{CORRECTED_BASENAME}{epoch}.txt"
        self.assertEqual(keys[b"profile.report.path"], os.fsencode(candidate))
        self.assertEqual(keys[b"profile.report.artifact_basename"], os.fsencode(candidate.name))
        self.assertNotEqual(candidate, rust_path)
        self.assertEqual(rust_path.read_bytes(), rust_file)
        persisted = candidate.read_bytes()
        (self.root / (label + "-native-profile.file.raw")).write_bytes(persisted)
        for file, stdout in ((persisted, native.stdout), (rust_file, rust_stdout)):
            footer = (f"profile.report.output_line_count={file.count(bytes([10]))}\n"
                      f"profile.report.output_bytes={len(file)}\n").encode()
            self.assertEqual(file, stdout + footer)
        self.assertEqual(native.stdout.count(STAMP), 1)
        self.assertNotIn(STAMP, rust_stdout)
        permitted = {b"elapsed_ms"} | {b"profile.report." + k for k in (
            b"capture_started_at_epoch", b"capture_started_at_iso", b"capture_stamp",
            b"capture_stamp_epoch", b"elapsed_ms", b"path", b"artifact_basename")}
        def normalized(stdout):
            return [line for line in stdout.splitlines()
                    if line.partition(b"=")[0] not in permitted and line != STAMP.rstrip(b"\n")]
        self.assertEqual(normalized(native.stdout), normalized(rust_stdout))
        candidate.unlink()
        rust_path.unlink()
        self.standalone.append({"label": label, "profile_and_replay": True, "native_wall_ns": wall,
                                "native_elapsed_ms": measured, "native_realtime_epoch": epoch,
                                "native_profile_sha256": sha(persisted), "original_profile_sha256": sha(rust_file),
                                "native_profile_basename": candidate.name, "workload_frame_bytes": work_bytes,
                                "scheduler_scratch_required": scratch_bytes, "separate_profile_namespace": True})

    def test_corrected_mode_scope_and_native_replay_clock_bound(self):
        args = [MODE, "--workload=mixed", "--txs", "3", "--keys", "1"]
        cases = ([MODE, "--workload=classic"], [MODE, "--workload=mixed", "--keys=1999"],
                 [MODE, "--workload=hot-streak", "--txs=19999"],
                 [MODE, "--workload=mixed", "--strategy=write-last"],
                 [MODE, "--workload=mixed", "--strategy=write-first", "--keys=1999"],
                 [MODE, "--workload=hot-streak", "--read-fanout=9"],
                 [MODE, "--workload=hot-streak", "--txs=20001"],
                 [MODE, MODE, "--workload=hot-streak"],
                 [MODE+"=true", "--workload=hot-streak"])
        for k, flags in enumerate(cases):
            result, *_ = self.standalone_process(f"corrected-refused-{k}", flags)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b"",OUTSIDE))
        result, *_ = self.standalone_process("corrected-nonempty-env", [MODE, "--workload=hot-streak",
             "--strategy=hot-bucket-interleave"], env={b"TRNM_HOT_BUCKETS":b"8"})
        self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b"",OUTSIDE))
        image = replay_fixture(self.image, self.image_receipt, self.root, "corrected-mode-count", 0)
        for count in (0, 2, 1000):
            result, wall, *_ = self.standalone_process(f"corrected-count-{count}",
                    [*args, f"--determinism-repeats={count}"], image=image)
            self.assertEqual((result.returncode, result.stderr), (0, b"S"*(1+count)))
            self.assertIn(STAMP,result.stdout)
            _, comparable = stdout_observation(result.stdout, wall)
            self.assertIn(b"determinism.replay_match="+(b"true" if count else b"not-requested"), comparable)
        result, *_ = self.standalone_process("corrected-count-over", [MODE, "--workload=mixed",
                 "--determinism-repeats=1001"], image=image)
        self.assertEqual((result.returncode,result.stdout,result.stderr),
                         (2,b"",b"--determinism-repeats exceeds bounded maximum 1000\n"))
        delayed = replay_fixture(self.image, self.image_receipt, self.root, "corrected-mode-delay", 3)
        result, wall, *_ = self.standalone_process("corrected-delay", [*args,"--determinism-repeats=4"], image=delayed)
        self.assertEqual((result.returncode,result.stderr),(0,b"SSSSS"))
        elapsed, _ = stdout_observation(result.stdout, wall)
        self.assertGreaterEqual(wall - elapsed*1_000_000, 190_000_000)
        self.standalone.append({"count_exact": [1, 3, 1001], "over_bound_started_calls": 0,
                               "delayed_replay_wall_ns": wall, "timed_first_schedule_ms": elapsed})
        directory = self.anchor / "run/bench"
        self.assertFalse(directory.exists() and any(directory.iterdir()))

    def test_existing_elf_default_multiwriter_admission_remains_closed(self):
        image,receipt=build(self.root/"existing-unbound")
        for w in ("mixed","hot-streak"):
            fd=sealed_executable(image,w)
            try:
                result=subprocess.run(["trnm-bench","--workload",w],executable=f"/proc/self/fd/{fd}",
                               pass_fds=(fd,),env={},cwd=self.root,stdin=subprocess.DEVNULL,
                               capture_output=True,timeout=15)
            finally:
                os.close(fd)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b"",OUTSIDE))
            (self.root/f"existing-{w}.stderr.raw").write_bytes(result.stderr)
        self.assertEqual(receipt["native_elf"]["sha256"], sha(image))
        # In the same unbound image, the explicit corrected choice owns
        # no-profile reporting but still cannot acquire a file authority.
        for workload in ("mixed", "hot-streak"):
            result, wall, *_ = self.standalone_process("unbound-corrected-" + workload,
                                      [MODE, "--workload", workload], image=image)
            self.assertEqual((result.returncode, result.stderr), (0, b""))
            self.assertIn(STAMP, stdout_observation(result.stdout, wall)[1])
            denied, *_ = self.standalone_process("unbound-profile-refused-" + workload,
                        [MODE, "--workload", workload, "--profile"], image=image)
            self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        self.assertFalse((self.anchor / "run").exists())
