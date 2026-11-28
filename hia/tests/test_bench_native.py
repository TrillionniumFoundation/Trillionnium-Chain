"""Actual HIA Bench primitives against an include! of the unchanged Rust crate.

The scheduler's recorded reader-high-water repair remains explicit. Tests do
not label an unsafe original grouping as an equivalence requirement.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from hia.platform.bench.build import BenchBuild, COMPONENTS
from hia.tests.native_support import NativeModule
from hia.tests.test_executor_schedule import (
    Config, Tx, RAW_WORKER, decoded_output, graph_violations, schedule_reference, sizes,
)

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = ROOT / "trillionnium/crates/trnm-bench/src/main.rs"
REFERENCE = ROOT / "hia/tests/rust_bench_reference.rs"
MAX = (1 << 64) - 1


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def clean_environment():
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("TRNM_AGGR_", "TRNM_AUTO_", "TRNM_HOT_"))}


def request(row):
    return b"BNCHGEN1" + struct.pack("<7Q", *row, 0)


def txs_from_frame(raw):
    count, = struct.unpack_from("<Q", raw, 24)
    position, txs = 128, []
    for _ in range(count):
        identity, r, w, n = struct.unpack_from("<4Q", raw, position)
        position += 32
        refs = []
        for _ in range(r + w):
            refs.append(struct.unpack_from("<QQ", raw, position))
            position += 16
        payload = raw[position:position+n]
        position += n
        txs.append(Tx(identity, tuple(refs[:r]), tuple(refs[r:]), payload))
    if position != len(raw):
        raise AssertionError("oracle frame has trailing bytes")
    return txs


def group_digest(groups):
    data = bytearray(b"TRNM-BENCH-GROUPS-V1\0" + struct.pack("<Q", len(groups)))
    for index, group in enumerate(groups):
        data.extend(struct.pack("<QQ", index, len(group)))
        for identity in group:
            data.extend(struct.pack("<Q", identity))
    return hashlib.sha256(data).digest()


class BuiltModule(NativeModule):
    def __init__(self, build, name):
        # Use the same actual canonical build and provenance constructor as
        # every other component. qualify.py records this real init and its
        # call_many invocations; BenchBuild's direct builds are also recorded.
        super().__init__(ROOT / COMPONENTS[name][0], byte_exports=("f0",))
        try:
            expected = json.loads((build / "build.json").read_text())["canonical_receipts"][name]["shared"]
            for field in ("chain_migration", "compiler_sha256", "compiler_wire_sha256",
                          "object_sha256", "artifact_sha256", "artifact_bytes", "exports", "claims"):
                if self.receipt[field] != expected[field]:
                    raise AssertionError("Repeated canonical Bench build differs: " + field)
            if self.library.read_bytes() != (build / (name + ".so")).read_bytes():
                raise AssertionError("Observed Bench library differs from the retained build")
        except BaseException:
            self.close()
            raise


def run_original_command(directory, prefix, command, env, timeout):
    """Keep the actual streams even when setup fails before any test starts."""
    started = time.monotonic()
    error = None
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=timeout)
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as caught:
        error = caught
        stdout, stderr, returncode = caught.stdout or b"", caught.stderr or b"", None
    except OSError as caught:
        error = caught
        stdout, stderr, returncode = b"", b"", None
    streams = {}
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        path = directory / (prefix + "." + name + ".raw")
        path.write_bytes(raw)
        streams[name] = {"path": str(path), "bytes": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest()}
    record = {"argv": command, "cwd": str(ROOT), "timeout_seconds": timeout,
              "seconds": time.monotonic() - started, "exit_code": returncode,
              "timed_out": isinstance(error, subprocess.TimeoutExpired),
              "launch_error": str(error) if isinstance(error, OSError) else None,
              "streams_complete": error is None, **streams}
    (directory / (prefix + ".process.json")).write_text(json.dumps(record, indent=2) + "\n")
    if error is not None or returncode:
        # CalledProcessError's default message omits these captured streams.
        # Include every captured byte in the CI traceback, as well as retaining
        # the exact raw files and their process receipt for the always artifact.
        detail = ("Original process failed: " + json.dumps(record, sort_keys=True)
                  + "\nstdout:\n" + stdout.decode("utf-8", errors="backslashreplace")
                  + "\nstderr:\n" + stderr.decode("utf-8", errors="backslashreplace"))
        raise RuntimeError(detail) from error
    return result


def build_original(directory):
    before = ORIGINAL.read_bytes()
    env = clean_environment()
    manifest = ROOT / "trillionnium/Cargo.toml"
    target = directory / "original-target"
    command = ["cargo", "build", "--manifest-path", str(manifest), "--target-dir", str(target),
               "--locked", "--offline", "-p", "trnm-bench", "--message-format=json"]
    result = run_original_command(directory, "original-build", command, env, 240)
    dependencies = {}
    executables = []
    wanted = {"sha2", "clap", "trnm_executor", "trnm_types"}
    for line in result.stdout.splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact":
            continue
        if (row["target"]["name"] == "trnm-bench" and "bin" in row["target"]["kind"]
                and row.get("executable")):
            executables.append(Path(row["executable"]))
        if row["target"]["name"] not in wanted:
            continue
        name = row["target"]["name"]
        if name == "sha2" and "0.10." not in row["package_id"]:
            continue
        paths = [Path(p) for p in row["filenames"] if p.endswith(".rlib")]
        if len(paths) != 1 or name in dependencies and dependencies[name] != paths[0]:
            raise AssertionError("ambiguous actual original dependency")
        dependencies[name] = paths[0]
    if set(dependencies) != wanted:
        raise AssertionError("missing original bench dependency")
    if len(executables) != 1:
        raise AssertionError("ambiguous actual original Bench CLI artifact")
    output = directory / "bench-original"
    command = ["rustc", "--edition=2021", "--deny=warnings", str(REFERENCE), "-o", str(output)]
    for name, path in sorted(dependencies.items()):
        command.extend(["--extern", name + "=" + str(path)])
    for path in sorted({p.parent for p in dependencies.values()}):
        command.extend(["-L", "dependency=" + str(path)])
    env.update(TRNM_BENCH_SOURCE=str(ORIGINAL), CARGO_MANIFEST_DIR=str(ORIGINAL.parent.parent))
    run_original_command(directory, "original-adapter", command, env, 90)
    if before != ORIGINAL.read_bytes():
        raise AssertionError("original Bench source changed during include! build")
    return output, {"source_sha256": hashlib.sha256(before).hexdigest(),
                    "adapter_source_sha256": digest(REFERENCE), "binary_sha256": digest(output),
                    "dependencies": {name: {"path": str(path), "sha256": digest(path)}
                                     for name, path in dependencies.items()},
                    "cli": {"path": str(executables[0]), "sha256": digest(executables[0]),
                            "selected_from_actual_cargo_artifact": True},
                    "original_source_transformed": False}


COMPARE_ENTRY = """hia-asm.v1 hepta.hia.program.v8 selfhost_elf
fn f0(i:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(i:readbuf,o:mutbuf,w:mutbuf)
  zero:u64 = const() {"value":0}
  eight:u64 = const() {"value":8}
  sixteen:u64 = const() {"value":16}
  old:u64 = call(i,zero) {"function":"bench_read"}
  hash:u64 = call(i,eight) {"function":"bench_read"}
  count:u64 = call(i,sixteen) {"function":"bench_read"}
  equal_hash:u64 = call(o,hash,w) {"function":"bench_digest_equal"}
  equal_groups:u64 = call(o,old,count) {"function":"bench_same_membership"}
  two:u64 = const() {"value":2}
  flag:u64 = int.mul.wrap(equal_hash,two)
  combined:u64 = int.add.wrap(flag,equal_groups)
  answer:u32 = int.cast(combined) {"mode":"wrap"}
  ret(answer)
end
"""


class BenchNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        configured = os.environ.get("HIA_BENCH_OBSERVATIONS")
        cls.temporary = None if configured else tempfile.TemporaryDirectory(prefix="trnm-bench-native-")
        cls.directory = Path(configured or cls.temporary.name).absolute()
        if configured:
            cls.directory.mkdir(parents=True, exist_ok=False)
        cls.build = cls.directory / "build"
        cls.builder = BenchBuild(cls.build)
        cls.build_report = cls.builder.run()
        cls.native = {}
        for name in COMPONENTS:
            cls.native[name] = BuiltModule(cls.build, name)
            cls.addClassCleanup(cls.native[name].close)
        cls.oracle, cls.original_identity = build_original(cls.directory)
        cls.counts = {"native_invocations": 0, "original_workload_cases": 0,
                      "exact_original_groups": 0, "intentional_high_water_differences": 0}
        cls.differences = []
        cls.native_events = []
        cls.cli_events = []

    @classmethod
    def tearDownClass(cls):
        cls.builder.fence()
        if len(cls.native_events) != cls.counts["native_invocations"]:
            raise AssertionError("Incomplete native invocation transcript")
        record = {"schema": "trnm.hia.bench-primitives.observations.v1",
                  "counts": cls.counts, "original": cls.original_identity,
                  "native_invocations": cls.native_events,
                  "actual_original_cli": cls.cli_events,
                  "artifact_sha256": {k: m.artifact_sha256 for k, m in cls.native.items()},
                  "intentional_high_water_differences": cls.differences,
                  "whole_bench_native_qualified": False,
                  "open_contracts": ["CLI", "environment text", "derived profile and ln entropy",
                                     "decimal formatting", "clock and persistence", "native CLI integration of the repeat owner"],
                  "wall_seconds": time.monotonic() - cls.started}
        (cls.directory / "report.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"bench_observations": str(cls.directory / "report.json"), "counts": cls.counts}))
        if cls.temporary:
            cls.temporary.cleanup()

    def calls(self, component, calls):
        results = self.native[component].call_many(calls, timeout=60)
        self.counts["native_invocations"] += len(results)
        for call, result in zip(calls, results):
            self.native_events.append({"component": component,
                "input_sha256": hashlib.sha256(call[1][0]).hexdigest(),
                "argument_sha256": [hashlib.sha256(arg).hexdigest() for arg in call[1]],
                "argument_bytes": [len(arg) for arg in call[1]],
                "status": result.status, "returncode": result.returncode,
                "value": result.value, "abi_status": result.abi_status,
                "output_sha256": (hashlib.sha256(result.arguments[1]).hexdigest()
                                   if result.arguments else None)})
        return results

    def oracle_rows(self, rows):
        result = subprocess.run([str(self.oracle)],
            input="".join(" ".join(map(str, row)) + "\n" for row in rows), text=True,
            capture_output=True, env=clean_environment(), check=True, timeout=60)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(rows))
        self.counts["original_workload_cases"] += len(rows)
        return [(bytes.fromhex(a), bytes.fromhex(b), bytes.fromhex(c), bytes.fromhex(d))
                for a, b, c, d in (line.split("\t") for line in lines)]

    def test_workloads_and_all_seven_strategies_against_actual_original(self):
        rng = random.Random(0x42454E43)
        rows = []
        for workload in range(3):
            for strategy in range(7):
                for n in (0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127):
                    keys = rng.choice((0, 1, 2, 3, 7, 97, MAX))
                    fan = rng.choice((0, 1, 2, 3, 4, 7))
                    every = rng.choice((0, 1, 2, 3, 17, MAX))
                    rows.append((workload, n, keys, fan, every, strategy))
        rows += [(2, n, k, f, e, 5) for n, k, f, e in
                 ((512, 1, 1, 1), (513, 7, 3, 2), (2049, 97, 3, 5))]
        for start in range(0, len(rows), 32):
            batch = rows[start:start + 32]
            references = self.oracle_rows(batch)
            generated = self.calls("workload", [("f0", [request(row), b"\xa5" * (len(ref[0])+27), b"unchanged"])
                                                for row, ref in zip(batch, references)])
            schedules = []
            for row, ref, actual in zip(batch, references, generated):
                raw = ref[0]
                actual.require_returned()
                self.assertEqual(actual.value, 0, row)
                expected = struct.pack("<Q", len(raw)) + raw
                self.assertEqual(actual.arguments[1], expected + b"\xa5" * 19, row)
                self.assertEqual(actual.arguments[2], b"unchanged")
                txs = txs_from_frame(raw)
                o, s = sizes(txs)
                schedules.append(("f0", [raw, b"\xa7" * (o+19), b"\xc4" * (s+23)]))
            scheduled = self.calls("schedule", schedules)
            hashes, expected_hashes = [], []
            for row, ref, actual in zip(batch, references, scheduled):
                actual.require_returned()
                self.assertEqual(actual.value, 0, row)
                txs = txs_from_frame(ref[0])
                original, _ = decoded_output(ref[3], len(txs), 0)
                repaired = schedule_reference(txs, row[5], Config(), True)
                self.assertEqual(original, schedule_reference(txs, row[5], Config(), False), row)
                native, used = decoded_output(actual.arguments[1], len(txs), 0)
                self.assertEqual(native, repaired, row)
                self.assertEqual(graph_violations(txs, native["groups"]), [], row)
                if original != native:
                    self.counts["intentional_high_water_differences"] += 1
                    self.differences.append({"input": list(row),
                        "original_group_sha256": ref[2].hex(),
                        "repaired_group_sha256": group_digest(native["groups"]).hex(),
                        "original_pairwise_violations": graph_violations(txs, original["groups"]),
                        "native_pairwise_violations": []})
                else:
                    self.counts["exact_original_groups"] += 1
                self.assertEqual(group_digest(original["groups"]), ref[2])
                output = actual.arguments[1][:used]
                for raw, expected in ((ref[0], ref[1]), (ref[3], ref[2]),
                                      (output, group_digest(native["groups"]))):
                    hashes.append(("f0", [raw, b"\xa7" * 51, b"\xc4" * 1231]))
                    expected_hashes.append(expected)
            for expected, actual in zip(expected_hashes, self.calls("digests", hashes)):
                actual.require_returned()
                self.assertEqual(actual.value, 0)
                self.assertEqual(actual.arguments[1], expected + b"\xa7" * 19)
                self.assertEqual(actual.arguments[2][1208:], b"\xc4" * 23)

    def test_workload_error_precedence_and_capacity_are_atomic(self):
        base = (2, 17, 3, 7, 2, 0)
        raw, _, _, _ = self.oracle_rows([base])[0]
        need = 8 + len(raw)
        cases = [(request(base), need-1, 100)]
        cases += [(request(base)[:n], need, 1) for n in range(64)]
        cases += [(b"badmagic" + request(base)[8:], need, 2),
                  (request((3, *base[1:])), need, 3),
                  (request((*base[:5], 7)), need, 3),
                  (request(base)[:-8] + struct.pack("<Q", 1), need, 3),
                  (request((0, MAX, 1, 1, 1, 0)), need, 100),
                  (request((1, 2, 1, MAX, 1, 0)), need, 100),
                  (request((2, MAX//64, 1, 3, 1, 0)), need, 100)]
        for (raw, n, code), actual in zip(cases, self.calls("workload", [
                ("f0", [raw, b"\xa7" * n, b"unaltered"]) for raw, n, _ in cases])):
            actual.require_returned()
            self.assertEqual(actual.value, code)
            self.assertEqual(actual.arguments, [raw, b"\xa7" * n, b"unaltered"])
        actual = self.calls("workload", [("f0", [request(base), bytes(need), b""])])[0]
        actual.require_returned()
        self.assertEqual(actual.value, 0)
        self.assertEqual(actual.arguments[1],
                         struct.pack("<Q", need-8) + self.oracle_rows([base])[0][0])

    def test_hash_frame_and_capacity_refusals_leave_buffers_unchanged(self):
        raw, ih, gh, grouped = self.oracle_rows([(1, 9, 7, 3, 2, 0)])[0]
        rows = [(raw[:n], 32, 1208, 1) for n in (0, 1, 127, 128, len(raw)-1)]
        rows += [(raw + b"X", 32, 1208, 1), (b"badmagic" + raw[8:], 32, 1208, 1),
                 (grouped[:-1], 32, 1208, 1), (grouped + b"X", 32, 1208, 1),
                 (raw, 31, 1208, 100), (raw, 32, 1207, 100)]
        for offset, value in ((16, MAX), (24, MAX), (256, 1), (264, MAX)):
            bad = bytearray(grouped)
            struct.pack_into("<Q", bad, offset, value)
            rows.append((bytes(bad), 32, 1208, 1))
        for (sent, o, s, code), actual in zip(rows, self.calls("digests", [
                ("f0", [raw, b"\xa7" * o, b"\xc4" * s]) for raw, o, s, _ in rows])):
            actual.require_returned()
            self.assertEqual(actual.value, code)
            self.assertEqual(actual.arguments, [sent, b"\xa7" * o, b"\xc4" * s])
        for sent, expected in ((raw, ih), (grouped, gh)):
            actual = self.calls("digests", [("f0", [sent, bytes(32), bytes(1208)])])[0]
            actual.require_returned()
            self.assertEqual(actual.value, 0)
            self.assertEqual(actual.arguments[1], expected)

    def test_native_repeat_owner_runs_exact_bounded_replays(self):
        workloads = ("classic", "mixed", "hot-streak")
        strategies = ("original", "footprint-desc", "write-first", "write-last",
                      "hot-bucket-interleave", "auto-adaptive", "aggressive-greedy")
        rows = [(w, 17, 5, 3, 2, strategy) for w in range(3) for strategy in range(7)]
        references = self.oracle_rows(rows)
        cases, expected = [], []
        for row, reference in zip(rows, references):
            raw = reference[0]
            txs = txs_from_frame(raw)
            base, scratch = sizes(txs)
            repaired = schedule_reference(txs, row[5], Config(), True)
            for repeats in (0, 1, 3):
                sent = bytearray(raw)
                sent[:8] = b"BNCHREP1"
                struct.pack_into("<Q", sent, 112, repeats)
                cases.append(("f0", [bytes(sent), b"\xa7" * (2*base+112+19), b"\xc4" * (scratch+23)]))
                expected.append((row, reference, txs, repaired, repeats, base, scratch))
        small = (2, 2, 1, 3, 1, 6)
        reference = self.oracle_rows([small])[0]
        txs = txs_from_frame(reference[0])
        base, scratch = sizes(txs)
        sent = bytearray(reference[0]); sent[:8] = b"BNCHREP1"
        struct.pack_into("<Q", sent, 112, 1000)
        cases.append(("f0", [bytes(sent), b"\xa7" * (2*base+112+19), b"\xc4" * (scratch+23)]))
        expected.append((small, reference, txs, schedule_reference(txs, 6), 1000, base, scratch))
        for exp, actual in zip(expected, self.calls("repeat", cases)):
            row, reference, txs, repaired, repeats, base, scratch = exp
            actual.require_returned()
            self.assertEqual(actual.value, 0, (row, repeats))
            out = actual.arguments[1]
            got, used = decoded_output(out, len(txs), 0)
            self.assertEqual(got, repaired)
            magic, requested, matched, executions, first_len, first_groups = struct.unpack_from("<6Q", out, base)
            self.assertEqual(magic, int.from_bytes(b"BNCHRES1", "little"))
            self.assertEqual((requested, matched, executions, first_len, first_groups),
                             (repeats, int(repeats > 0), repeats+1, used, repaired["group_count"]))
            self.assertEqual(out[base+48:base+80], reference[1])
            self.assertEqual(out[base+80:base+112], group_digest(repaired["groups"]))
            self.assertEqual(out[base+112:base+112+used], out[:used])
            self.assertEqual(out[used:base], b"\xa7" * (base-used))
            self.assertEqual(out[base+112+used:], b"\xa7" * (base-used+19))
            self.assertEqual(actual.arguments[2][scratch:], b"\xc4" * 23)
            # Execute the exact retained main(), including its in-process loop.
            command = [self.original_identity["cli"]["path"],
                "--workload", workloads[row[0]], "--txs", str(row[1]), "--keys", str(row[2]),
                "--read-fanout", str(row[3]), "--write-every", str(row[4]),
                "--strategy", strategies[row[5]], "--determinism-repeats", str(repeats)]
            self.assertEqual(digest(command[0]), self.original_identity["cli"]["sha256"])
            original = subprocess.run(command, cwd=self.directory, env=clean_environment(),
                                      capture_output=True, check=True, text=True, timeout=30)
            self.assertEqual(digest(command[0]), self.original_identity["cli"]["sha256"])
            directory = self.directory / "original-cli"
            directory.mkdir(exist_ok=True)
            index = len(self.cli_events)
            stdout = directory / f"{index:03}.stdout.raw"
            stderr = directory / f"{index:03}.stderr.raw"
            stdout.write_bytes(original.stdout.encode())
            stderr.write_bytes(original.stderr.encode())
            self.cli_events.append({"argv": command, "cwd": str(self.directory),
                "all_scheduler_environment_variables_unset": True,
                "executable_sha256": self.original_identity["cli"]["sha256"],
                "exit_code": original.returncode, "stdout": str(stdout),
                "stdout_sha256": digest(stdout), "stderr": str(stderr),
                "stderr_sha256": digest(stderr)})
            lines = dict(line.split("=", 1) for line in original.stdout.splitlines() if "=" in line)
            self.assertEqual(lines["determinism.input_sha256"], reference[1].hex())
            self.assertEqual(lines["determinism.groups_sha256"], reference[2].hex())
            self.assertEqual(lines["determinism.repeats"], str(repeats))
            self.assertEqual(lines["determinism.replay_match"], "true" if repeats else "not-requested")
        self.counts["actual_original_cli_repeat_cases"] = len(expected)
        self.counts["native_schedule_executions_in_repeat_owner"] = sum(e[4]+1 for e in expected)

    def test_repeat_refusals_preserve_output_before_initialization(self):
        raw = self.oracle_rows([(2, 3, 5, 3, 2, 0)])[0][0]
        txs = txs_from_frame(raw)
        base, scratch = sizes(txs)
        output = 2*base+112
        sent = bytearray(raw); sent[:8] = b"BNCHREP1"
        cases = [(bytes(sent), output-1, scratch, 100), (bytes(sent), output, scratch-1, 100),
                 (bytes(sent[:127]), output, scratch, 1), (bytes(sent)+b"X", output, scratch, 1)]
        for offset, value in ((8, 1), (16, 7), (32, 8), (40, 3), (40, 65), (48, 63),
                              (56, 2049), (64, 4097), (80, 0x7ff8000000000000),
                              (88, 0xbff0000000000000), (112, 1001), (120, 1)):
            bad = bytearray(sent); struct.pack_into("<Q", bad, offset, value)
            cases.append((bytes(bad), output, scratch, 3))
        for (raw, o, s, code), actual in zip(cases, self.calls("repeat", [
                ("f0", [raw, b"\xa7" * o, b"\xc4" * s]) for raw, o, s, _ in cases])):
            actual.require_returned()
            self.assertEqual(actual.value, code)
            self.assertEqual(actual.arguments, [raw, b"\xa7" * o, b"\xc4" * s])

    def test_default_size_and_over_two_mib_use_real_unaligned_buffers(self):
        # No convenience runner extent is treated as a product count limit.
        rows = [(0, 20000, 2000, 3, 1, 0), (1, 20000, 2000, 3, 1, 0),
                (2, 20000, 2000, 3, 1, 0), (1, 20000, 2000, 7, 2, 0)]
        references = self.oracle_rows(rows)
        observed = []
        for component in ("workload", "digests"):
            module = self.native[component]
            calls = []
            for row, reference in zip(rows, references):
                raw = request(row) if component == "workload" else reference[0]
                calls.append({"raw": base64.b64encode(raw).decode(),
                    "output": len(reference[0])+8 if component == "workload" else 32,
                    "scratch": 0 if component == "workload" else 1208,
                    "used": 0 if component == "workload" else 1208})
            sent = {"path": str(module.library), "sha256": module.artifact_sha256,
                    "sequences": [{"residues": [1, 3, 5], "rows": calls}]}
            result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", RAW_WORKER],
                input=json.dumps(sent), text=True, capture_output=True, check=True, timeout=40)
            answers = json.loads(result.stdout)
            self.assertEqual(answers["sha256"], module.artifact_sha256)
            self.assertEqual(answers["compiler_modules_loaded"], [])
            self.assertEqual(len(answers["answers"]), len(rows))
            for row, ref, answer in zip(rows, references, answers["answers"]):
                self.assertEqual((answer["value"], answer["abi_status"]), (0, 0))
                for key in ("input_unchanged", "output_outside_borrow_unchanged",
                            "scratch_outside_used_unchanged", "scratch_outside_borrow_unchanged",
                            "guards_unchanged"):
                    self.assertTrue(answer[key], (component, row, key))
                self.assertEqual(answer["residues"], [1, 3, 5])
                expected = struct.pack("<Q", len(ref[0])) + ref[0] if component == "workload" else ref[1]
                self.assertEqual(bytes.fromhex(answer["output"]), expected)
                self.native_events.append({"component": component, "scope": "large-unaligned",
                    "input_sha256": hashlib.sha256(request(row) if component == "workload" else ref[0]).hexdigest(),
                    "output_sha256": hashlib.sha256(expected).hexdigest(),
                    "status": "returned", "returncode": 0, "value": answer["value"],
                    "abi_status": answer["abi_status"]})
                observed.append({"component": component, "parameters": list(row),
                    "input_bytes": len(ref[0]), "output_bytes": len(expected),
                    "output_sha256": hashlib.sha256(expected).hexdigest(),
                    "elapsed_ns": answer["elapsed_ns"], "residues": answer["residues"],
                    "all_buffer_and_guard_assertions_passed": True})
        self.counts["native_invocations"] += len(observed)
        self.counts["large_unaligned_invocations"] = len(observed)
        self.assertGreater(max(row["input_bytes"] for row in observed), 2098176)
        (self.directory / "large-unaligned.json").write_text(json.dumps(observed, indent=2) + "\n")

    def test_repeat_comparators_detect_membership_and_digest_changes(self):
        from hia.tools import toolchain
        from hia.tools.qualify import native_build_record, sources
        probe = self.directory / "repeat-comparator-probe"
        probe.mkdir()
        fixture = probe / "hia"
        manifest = json.loads((ROOT / "hia/components.json").read_text())
        includes = {}
        production = self.build_report["canonical_receipts"]["repeat"]["shared"]
        for row in production["chain_migration"]["inputs"]:
            relative = row["path"]
            if not relative.endswith(".hepta"):
                continue
            canonical = ROOT / "hia" / relative
            self.assertEqual(digest(canonical), row["sha256"])
            copied = fixture / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(canonical.read_bytes())
            includes[relative] = manifest["includes"].get(relative, [])
        entry_relative = "src/bench_repeat_compare_fixture.hepta"
        entry = fixture / entry_relative
        entry.write_text(COMPARE_ENTRY)
        includes[entry_relative] = [
            {"source": "src/bench/repeat.hepta",
             "functions": ["bench_digest_equal", "bench_same_membership"]},
            {"source": "src/bench/workload.hepta", "functions": ["bench_get", "bench_read"]},
        ]
        (fixture / "components.json").write_text(json.dumps({"schema": manifest["schema"],
                                                              "includes": includes}, indent=2) + "\n")
        with patch.object(toolchain, "HIA_ROOT", fixture):
            module = NativeModule(entry, byte_exports=("f0",), fixture_owner=Path(__file__))
        self.addCleanup(module.close)
        actual_build = native_build_record(module, sources())
        self.assertIsNone(actual_build["source"])
        self.assertEqual(actual_build["generated_fixture"]["owner"],
                         "hia/tests/test_bench_native.py")
        (probe / "repeat.so").write_bytes(module.library.read_bytes())
        raw, _, _, grouped = self.oracle_rows([(1, 8, 3, 2, 2, 6)])[0]
        n = len(txs_from_frame(raw)); base = 264+16*n
        expected_hash = group_digest(decoded_output(grouped, n, 0)[0]["groups"])
        backing = bytearray(b"\xa7" * (2*base+32))
        backing[:len(grouped)] = grouped
        backing[base:base+len(grouped)] = grouped
        backing[2*base:] = expected_hash
        scratch = bytearray(1208); scratch[1168:1200] = expected_hash
        header = struct.pack("<3Q", base, 2*base, n)
        cases = [(bytes(backing), bytes(scratch), 3, "exact")]
        for offset, expected, label in ((2*base, 1, "digest"), (24, 2, "group-count"),
                (264, 2, "ordered-boundary"), (len(grouped)-8, 2, "member-id"),
                (40, 3, "profile-is-excluded"), (176, 3, "adaptive-is-excluded")):
            changed = bytearray(backing); changed[offset] ^= 1
            cases.append((bytes(changed), bytes(scratch), expected, label))
        both = bytearray(backing); both[2*base] ^= 1; both[len(grouped)-8] ^= 1
        cases.append((bytes(both), bytes(scratch), 0, "both"))
        observations = module.call_many([("f0", [header, o, work]) for o, work, _, _ in cases])
        for (o, work, expected, label), actual in zip(cases, observations):
            actual.require_returned()
            self.assertEqual(actual.value, expected, label)
            self.assertEqual(actual.arguments, [header, o, work], label)
            self.native_events.append({"component": "qualification-repeat-comparator",
                "label": label, "artifact_sha256": module.artifact_sha256,
                "argument_sha256": [hashlib.sha256(arg).hexdigest() for arg in (header, o, work)],
                "output_sha256": hashlib.sha256(actual.arguments[1]).hexdigest(),
                "status": actual.status, "returncode": actual.returncode,
                "value": actual.value, "abi_status": actual.abi_status})
        self.assertEqual(actual_build, native_build_record(module, sources()))
        report = {"status": "PASS", "finalized": True,
            "scope": "qualification-only direct calls to the unchanged native repeat comparators",
            "not_a_production_entry": True,
            "cases": [{"label": r[3], "expected_flags": r[2]} for r in cases],
            "receipt": module.receipt, "actual_build": actual_build}
        (probe / "build.json").write_text(json.dumps(report, indent=2) + "\n")
        self.counts["native_invocations"] += len(cases)
        self.counts["native_comparator_controls"] = len(cases)

    def test_retained_original_tests(self):
        # The shared general-shard recorder and its independent reader must
        # bind the Rust include! body and every local dependency source, not
        # only this suite's own report of their identities.
        from hia.tools.qualify import sources
        bound = sources()
        required = [ROOT / "trillionnium/Cargo.toml", ROOT / "trillionnium/Cargo.lock",
                    ROOT / "hia/src/bench/README.md"]
        for package in ("trnm-bench", "trnm-executor", "trnm-types"):
            crate = ROOT / "trillionnium/crates" / package
            required.extend(crate.rglob("*.rs"))
            required.append(crate / "Cargo.toml")
        for path in required:
            self.assertEqual(bound.get(path.relative_to(ROOT).as_posix()), digest(path), str(path))
        result = run_original_command(self.directory, "retained-original",
            ["cargo", "test", "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"),
            "--target-dir", str(self.directory / "original-target"), "--locked", "--offline",
            "-p", "trnm-bench", "--all-targets", "--all-features"], clean_environment(), 240)
        self.assertIn(b"11 passed; 0 failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
