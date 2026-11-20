"""Actual HIA report bytes against the whole unchanged original Bench main.

All observed clocks and OS persistence results belong to the original process;
the new component renders supplied native values. A native CLI/clock/file owner
is not certified by this suite. Synthetic arithmetic and reader-style ABI
controls are reported separately from real original command executions.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import time
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_bench_native import build_original, clean_environment, run_original_command
from hia.tools.qualify import native_build_record, sources

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "hia/tests/rust_bench_report_reference.rs"
PROFILE_REFERENCE = ROOT / "hia/tests/rust_bench_profile_reference.rs"
ORIGINAL = ROOT / "trillionnium/crates/trnm-bench/src/main.rs"
EXECUTOR = ROOT / "trillionnium/crates/trnm-executor/src/lib.rs"
U64 = (1 << 64) - 1


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_inputs():
    result = sources()
    for name in ("TEXT.md", "REPORT.md", "PROFILE.md", "FORMATTING.md", "LOGARITHM.md"):
        path = ROOT / "hia/src/bench" / name
        if path.is_symlink():
            raise AssertionError("linked Bench contract source")
        result[path.relative_to(ROOT).as_posix()] = digest(path.read_bytes())
    return dict(sorted(result.items()))


def report_frame(context=None, raw=None, derived=None, adaptive=None, hashes=None,
                 state=0, path=b"", basename=b"", error=b""):
    context = context or [0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1]
    raw = [0] * 17 if raw is None else raw
    derived = [0] * 51 if derived is None else derived
    adaptive = [0] * 10 if adaptive is None else adaptive
    hashes = bytes(64) if hashes is None else hashes
    assert (len(context), len(raw), len(derived), len(adaptive), len(hashes)) == (15, 17, 51, 10, 64)
    return (b"BRPT0001" + struct.pack("<15Q", *context) + struct.pack("<17Q", *raw)
            + struct.pack("<51Q", *derived) + struct.pack("<10Q", *adaptive) + hashes
            + struct.pack("<4Q", state, len(path), len(basename), len(error)) + path + basename + error)


def report_case(value):
    bound = 32768 + len(value) - 848
    return "f0", [value, bytes([0xA5]) * (40 + 2 * bound + 13),
                  bytes([0xD3]) * (8192 + len(value) + 2 * bound + 17)]


class BenchReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        configured = os.environ.get("HIA_BENCH_REPORT_OBSERVATIONS")
        cls.temporary = None if configured else tempfile.TemporaryDirectory(prefix="trnm-bench-report-")
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
        for name in ("text", "report", "profile"):
            module = NativeModule(ROOT / "hia/src/bench" / (name + ".hepta"), byte_exports=("f0",))
            cls.modules[name] = module
            cls.addClassCleanup(module.close)
            cls.builds[name] = {"receipt": module.receipt, "actual_build": native_build_record(module, cls.before)}
            (cls.directory / (name + ".so")).write_bytes(module.library.read_bytes())
        (cls.directory / "native-builds.json").write_text(json.dumps(cls.builds, indent=2) + "\n")
        cls.bench_original, cls.bench_identity = build_original(cls.directory)
        cls.original = cls.directory / "report-original"
        cls.manifest_dir = cls.directory / "actual-cli-root/crates/trnm-bench"
        cls.manifest_dir.mkdir(parents=True)
        env = clean_environment()
        env.update(TRNM_BENCH_SOURCE=str(ORIGINAL), CARGO_MANIFEST_DIR=str(cls.manifest_dir))
        command = ["rustc", "--edition=2021", "--deny=warnings", str(REFERENCE), "-o", str(cls.original)]
        for name, record in sorted(cls.bench_identity["dependencies"].items()):
            if digest(Path(record["path"]).read_bytes()) != record["sha256"]:
                raise AssertionError("Actual original dependency changed")
            command += ["--extern", name + "=" + record["path"]]
        for directory in sorted({str(Path(v["path"]).parent) for v in cls.bench_identity["dependencies"].values()}):
            command += ["-L", "dependency=" + directory]
        run_original_command(cls.directory, "report-rustc", command, env, 90)
        cls.profile_original = cls.directory / "profile-original"
        types = Path(cls.bench_identity["dependencies"]["trnm_types"]["path"])
        env = clean_environment()
        env["TRNM_EXECUTOR_SOURCE"] = str(EXECUTOR)
        command = ["rustc", "--edition=2021", "--deny=warnings", str(PROFILE_REFERENCE), "-o", str(cls.profile_original),
                   "--extern", "trnm_types=" + str(types), "-L", "dependency=" + str(types.parent)]
        run_original_command(cls.directory, "profile-rustc", command, env, 90)
        cls.original_identity = {"source_sha256": digest(ORIGINAL.read_bytes()),
            "adapter_source_sha256": digest(REFERENCE.read_bytes()), "binary_sha256": digest(cls.original.read_bytes()),
            "compile_environment": {"TRNM_BENCH_SOURCE": str(ORIGINAL), "CARGO_MANIFEST_DIR": str(cls.manifest_dir)},
            "profile_adapter_source_sha256": digest(PROFILE_REFERENCE.read_bytes()),
            "profile_source_sha256": digest(EXECUTOR.read_bytes()),
            "profile_binary_sha256": digest(cls.profile_original.read_bytes()),
            "original_source_transformed": False, "real_main_called": True,
            "rustc": subprocess.check_output(["rustc", "-Vv"], text=True)}
        cls.raw_path = cls.directory / "native-calls.jsonl.gz"
        cls.raw_file = cls.raw_path.open("wb")
        cls.raw = gzip.GzipFile(filename="", mode="wb", fileobj=cls.raw_file, mtime=0)
        cls.addClassCleanup(cls.raw_file.close)
        cls.addClassCleanup(cls.raw.close)
        cls.events, cls.counts, cls.differences, cls.completed = [], {}, [], []

    @classmethod
    def tearDownClass(cls):
        cls.raw.close()
        cls.raw_file.close()
        stable = source_inputs() == cls.before
        report = {"schema": "trnm.hia.bench-report.observations.v1", "observations_only": True,
            "source_inputs": cls.before, "source_unchanged": stable, "original": cls.original_identity,
            "original_cargo_bench": cls.bench_identity, "builds": cls.builds, "counts": cls.counts,
            "native_invocations": cls.events, "raw_profile_bit_differences": cls.differences,
            "completed_test_methods": cls.completed,
            "complete_raw_native_calls": {"path": str(cls.raw_path), "bytes": cls.raw_path.stat().st_size,
                                           "sha256": digest(cls.raw_path.read_bytes())},
            "whole_bench_native_qualified": False, "native_cli_clock_filesystem_owner_qualified": False,
            "wall_seconds": time.monotonic() - cls.started}
        (cls.directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"bench_report_observations": str(cls.directory / "report.json"),
                          "counts": cls.counts, "raw_profile_bit_differences": len(cls.differences)}))
        if not stable:
            raise AssertionError("Bench report source changed during qualification")

    def calls(self, component, cases):
        answers = []
        for offset in range(0, len(cases), 16):
            chunk = cases[offset:offset + 16]
            results = self.modules[component].call_many(chunk, timeout=60)
            for sent, got in zip(chunk, results):
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
            answers.extend(results)
        self.raw.flush()
        self.counts[component] = self.counts.get(component, 0) + len(answers)
        return answers

    def process(self, command, data, label, expected=0):
        (self.directory / (label + ".stdin.raw")).write_bytes(data)
        started = time.monotonic()
        error = None
        try:
            result = subprocess.run(list(map(str, command)), input=data, cwd=self.directory,
                                    env=clean_environment(), capture_output=True, timeout=60)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as caught:
            stdout, stderr, code, error = caught.stdout or b"", caught.stderr or b"", None, caught
        (self.directory / (label + ".stdout.raw")).write_bytes(stdout)
        (self.directory / (label + ".stderr.raw")).write_bytes(stderr)
        (self.directory / (label + ".process.json")).write_text(json.dumps({"argv": list(map(str, command)),
            "cwd": str(self.directory), "exit_code": code, "timed_out": error is not None,
            "timeout_seconds": 60, "seconds": time.monotonic() - started,
            "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}, indent=2) + "\n")
        self.assertEqual(code, expected, stderr.decode(errors="backslashreplace"))
        return stdout, stderr

    def rendered(self, sent, answer):
        answer.require_returned()
        self.assertEqual(answer.value, 0)
        output = answer.arguments[1]
        tag, code, stdout_n, stderr_n, file_n = struct.unpack_from("<8s4Q", output)
        self.assertEqual(tag, b"BRPTOUT1")
        used = 40 + stdout_n + stderr_n + file_n
        self.assertLessEqual(used, len(output))
        self.assertEqual(output[used:], sent[1][1][used:])
        self.assertEqual(answer.arguments[2][-17:], bytes([0xD3]) * 17)
        self.assertEqual(answer.arguments[2][4931:6000], bytes([0xD3]) * (6000 - 4931))
        self.assertEqual(answer.arguments[2][6224:8192], bytes([0xD3]) * (8192 - 6224))
        self.assertEqual(answer.arguments[2][8192:8192 + len(sent[1][0])], sent[1][0])
        stdout = output[40:40 + stdout_n]
        stderr = output[40 + stdout_n:40 + stdout_n + stderr_n]
        file = output[40 + stdout_n + stderr_n:used]
        if file:
            self.assertTrue(file.endswith(("profile.report.output_bytes=" + str(len(file)) + "\n").encode()))
            self.assertIn(("profile.report.output_line_count=" + str(file.count(b"\n")) + "\n").encode(), file)
        return code, stdout, stderr, file

    def test_decimal_integer_width_and_full_u128(self):
        rng = random.Random(0x42545854)
        values = {0, 1, 9, 10, 99, 100, (1 << 63) - 1, 1 << 63, U64}
        for exponent in range(1, 20):
            values.update((10 ** exponent - 1, 10 ** exponent, 10 ** exponent + 1))
        values.update(rng.getrandbits(64) for _ in range(100))
        rows = [(mode, value, 0, width) for mode in (0, 1) for value in sorted(values) for width in (0, 4, 20, 40)]
        wide = {0, 1, (1 << 64) - 1, 1 << 64, (1 << 127), (1 << 128) - 1}
        for exponent in range(1, 39):
            wide.update((10 ** exponent - 1, 10 ** exponent, 10 ** exponent + 1))
        wide.update(rng.getrandbits(128) for _ in range(80))
        rows += [(2, value & U64, value >> 64, width) for value in sorted(wide) for width in (0, 39, 40)]
        data = "".join(" ".join(map(str, row)) + "\n" for row in rows).encode()
        output, _ = self.process([self.original, "--reference-text"], data, "text-integers")
        expected = output.splitlines()
        self.assertEqual(len(expected), len(rows))
        cases = [("f0", [b"BTXT0001" + struct.pack("<4Q", *row), bytes([0xA5]) * 61, bytes([0xD3]) * 29]) for row in rows]
        for case, answer, reference in zip(cases, self.calls("text", cases), expected):
            answer.require_returned()
            self.assertEqual(answer.value, 0)
            length = struct.unpack_from("<Q", answer.arguments[1])[0]
            self.assertEqual(answer.arguments[1][8:8 + length], reference)
            self.assertEqual(answer.arguments[1][8 + length:], case[1][1][8 + length:])
            self.assertEqual(answer.arguments[2], case[1][2])
        self.counts["original_integer_pairs"] = len(rows)
        self.completed.append(self._testMethodName)

    def test_calendar_against_original_system_time_formatter(self):
        values = {0, 1, 59, 60, 3599, 3600, 86399, 86400, 951782399, 951782400,
                  1709164800, 1709251199, 1709251200, 2147483647, 2147483648,
                  4107542399, 4107542400, (1 << 63) - 1}
        for day in (365, 366, 1460, 1461, 36524, 36525, 146096, 146097, 146098):
            values.update(day * 86400 + delta for delta in (-1, 0, 1))
        rng = random.Random(0x49534F)
        values.update(rng.randrange(1 << 63) for _ in range(320))
        rows = [(3, value, 0, 0) for value in sorted(values)]
        data = "".join(" ".join(map(str, row)) + "\n" for row in rows).encode()
        output, _ = self.process([self.original, "--reference-text"], data, "text-calendar")
        expected = output.splitlines()
        self.assertEqual(len(expected), len(rows))
        cases = [("f0", [b"BTXT0001" + struct.pack("<4Q", *row), bytes([0xA5]) * 61, b""]) for row in rows]
        for case, answer, reference in zip(cases, self.calls("text", cases), expected):
            answer.require_returned()
            self.assertEqual(answer.value, 0)
            length = struct.unpack_from("<Q", answer.arguments[1])[0]
            self.assertEqual(answer.arguments[1][8:8 + length], reference)
            self.assertEqual(answer.arguments[1][8 + length:], case[1][1][8 + length:])
        self.counts["original_calendar_pairs"] = len(rows)
        self.completed.append(self._testMethodName)

    def test_complete_actual_main_reports_and_native_profile_chain(self):
        workload_names = ("classic", "mixed", "hot-streak")
        strategy_names = ("original", "footprint-desc", "write-first", "write-last", "hot-bucket-interleave", "auto-adaptive", "aggressive-greedy")
        rows = [(workload, 65, 9, 4, 3, strategy) for workload in range(3) for strategy in range(7)]
        data = "".join(" ".join(map(str, row)) + "\n" for row in rows).encode()
        output, _ = self.process([self.bench_original], data, "original-raw-schedules")
        actual = [line.split("\t") for line in output.decode().splitlines()]
        self.assertEqual(len(actual), len(rows))
        native_profiles = []
        raw_values = []
        adaptive_values = []
        for observation in actual:
            scheduler = bytes.fromhex(observation[3])
            self.assertEqual(scheduler[:8], b"EXSCOUT1")
            raw = list(struct.unpack_from("<17Q", scheduler, 40))
            adaptive = list(struct.unpack_from("<10Q", scheduler, 176))
            raw_values.append(raw)
            adaptive_values.append(adaptive)
        requests = [("f0", [b"BPRO0001" + struct.pack("<17Q", *raw), bytes([0xA5]) * 429, bytes([0xD3]) * 2065]) for raw in raw_values]
        for answer in self.calls("profile", requests):
            answer.require_returned()
            self.assertEqual(answer.value, 0)
            self.assertEqual(answer.arguments[1][:8], b"BPROOUT1")
            native_profiles.append(list(struct.unpack_from("<51Q", answer.arguments[1], 8)))
        data = "".join("P " + " ".join(f"{value:016x}" for value in raw) + "\n" for raw in raw_values).encode()
        output, _ = self.process([self.profile_original], data, "original-derived-profiles")
        original_profiles = [[int(field.split("|")[0], 16) for field in line.split()[1:]] for line in output.decode().splitlines()]
        self.assertEqual(len(original_profiles), len(rows))
        for index, (native, original) in enumerate(zip(native_profiles, original_profiles)):
            self.assertEqual(len(original), 51)
            for field, (left, right) in enumerate(zip(native, original)):
                if left != right:
                    self.differences.append({"row": index, "field": field, "native": left, "original": right})
        cases, expected = [], []
        for index, (row, observation, raw, derived, adaptive) in enumerate(zip(rows, actual, raw_values, native_profiles, adaptive_values)):
            workload, n, keys, fan, every, strategy = row
            for profile in (0, 1):
                repeats = index % 3
                command = [self.original, "--workload", workload_names[workload], "--strategy", strategy_names[strategy],
                           "--txs", str(n), "--keys", str(keys), "--read-fanout", str(fan), "--write-every", str(every),
                           "--determinism-repeats", str(repeats)]
                if profile:
                    command.append("--profile")
                stdout, stderr = self.process(command, b"", f"actual-main-{index:02}-{profile}")
                self.assertEqual(stderr, b"")
                fields = dict(line.split(b"=", 1) for line in stdout.splitlines()[1:])
                epoch = int(fields[b"profile.report.capture_started_at_epoch"]) if profile else 0
                elapsed = int(fields[b"elapsed_ms"])
                context = [workload, strategy, n, keys, fan, every, profile, 1, repeats, int(repeats > 0),
                           epoch, elapsed & U64, elapsed >> 64, int(fields[b"groups"]), int(fields[b"grouped"])]
                path = fields.get(b"profile.report.path", b"")
                basename = fields.get(b"profile.report.artifact_basename", b"")
                persisted = Path(os.fsdecode(path)).read_bytes() if profile else b""
                (self.directory / f"actual-main-{index:02}-{profile}.persisted.raw").write_bytes(persisted)
                hashes = bytes.fromhex(observation[1] + observation[2])
                self.assertEqual(fields[b"determinism.input_sha256"], observation[1].encode())
                self.assertEqual(fields[b"determinism.groups_sha256"], observation[2].encode())
                cases.append(report_case(report_frame(context, raw, derived, adaptive, hashes,
                                                     2 if profile else 0, path, basename)))
                expected.append((0, stdout, b"", persisted))
        for case, answer, original in zip(cases, self.calls("report", cases), expected):
            self.assertEqual(self.rendered(case, answer), original)
        self.counts["actual_original_main_runs"] = len(cases)
        self.counts["native_profile_to_report_chains"] = len(rows)
        self.completed.append(self._testMethodName)

    def test_binary64_metric_order_and_u128_elapsed(self):
        rng = random.Random(0x5245504F5254)
        values = [(1, 1, 0, 0), (0, 0, 0, 0), (1, U64, U64, U64), (U64, 1, U64, U64),
                  (1, 1 << 54, 1 << 63, 1 << 63), (1, (1 << 54) - 1, U64, U64),
                  ((1 << 53) - 1, 1 << 53, 1, 1), ((1 << 53) + 1, (1 << 53) + 2, 2, 1)]
        values += [tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(96)]
        for exponent in range(1, 64):
            values.append((1, (1 << exponent) + 1, exponent, exponent - 1))
        data = "".join(" ".join(map(str, row)) + "\n" for row in values).encode()
        output, _ = self.process([self.original, "--reference-metrics"], data, "synthetic-rust-metrics")
        reference = [line.split(b"\t") for line in output.splitlines()]
        self.assertEqual(len(reference), len(values))
        cases, elapsed_values = [], []
        for j, (keys, n, groups, grouped) in enumerate(values):
            elapsed = (1 << 128) - 1 if j == 0 else rng.getrandbits(128)
            context = [1, 0, n, keys, U64, U64, 1, 0, 0, 0, 0, elapsed & U64, elapsed >> 64, groups, grouped]
            cases.append(report_case(report_frame(context)))
            elapsed_values.append(elapsed)
        for case, answer, expected, elapsed in zip(cases, self.calls("report", cases), reference, elapsed_values):
            code, stdout, stderr, file = self.rendered(case, answer)
            self.assertEqual((code, stderr, file), (0, b"", b""))
            fields = dict(line.split(b"=", 1) for line in stdout.splitlines()[1:])
            for key, value in zip((b"estimated_conflict_rate", b"profile.report.coverage_ratio", b"profile.report.groups_per_1k_txs", b"profile.report.grouping_efficiency"), expected):
                self.assertEqual(fields[key], value)
            self.assertEqual(fields[b"elapsed_ms"], str(elapsed).encode())
            self.assertEqual(fields[b"profile.report.elapsed_ms"], str(elapsed).encode())
        self.counts["synthetic_rust_metric_pairs"] = len(values)
        self.completed.append(self._testMethodName)

    def test_original_persistence_newlines_errors_and_overwrite(self):
        epoch = 1709251199
        context = [2, 5, 65, 9, 4, 3, 1, 1, 0, 0, epoch, 0, 0, 4, 65]
        first = report_case(report_frame(context))
        _, base, _, _ = self.rendered(first, self.calls("report", [first])[0])
        root = os.fsencode(self.directory / "persistence-cases")
        os.makedirs(root)
        paths = [root + b"/plain", root + b"/line\nfeed", root + b"/carriage\r\nline", root + b"/invalid-\xff-utf8",
                 root + b"/create-error", root + b"/write-error", root + b"/plain"]
        Path(os.fsdecode(paths[4])).write_bytes(b"existing file prevents directory creation")
        os.makedirs(paths[5] + b"/executor-profile-summary-1709251199.txt")
        cases, expected = [], []
        for index, path in enumerate(paths):
            current = list(context)
            if index == len(paths) - 1:
                current[11] = U64
            plain_case = report_case(report_frame(current))
            _, plain, _, _ = self.rendered(plain_case, self.calls("report", [plain_case])[0])
            data = path.hex().encode() + b"\t" + str(epoch).encode() + b"\t" + plain.hex().encode() + b"\n"
            output, _ = self.process([self.original, "--reference-persist"], data, f"original-persist-{index}")
            fields = output.rstrip(b"\n").split(b"\t")
            self.assertEqual(len(fields), 6)
            ok = fields[0] == b"1"
            stdout, persisted, displayed, basename, error = [bytes.fromhex(value.decode()) for value in fields[1:]]
            state = 2 if ok else 3 if displayed else 1
            cases.append(report_case(report_frame(current, state=state, path=displayed, basename=basename, error=error)))
            expected.append((stdout, persisted, ok, state))
            if ok:
                actual = Path(os.fsdecode(path + b"/executor-profile-summary-1709251199.txt")).read_bytes()
                self.assertEqual(actual, persisted)
                (self.directory / f"original-persist-{index}.file.raw").write_bytes(actual)
        for case, answer, (stdout, persisted, ok, state) in zip(cases, self.calls("report", cases), expected):
            code, got, error, candidate = self.rendered(case, answer)
            self.assertEqual((code, got, error), (0, stdout, b""))
            if ok:
                self.assertEqual(candidate, persisted)
            elif state == 1:
                self.assertEqual(candidate, b"")
            else:
                self.assertNotIn(b"profile.report.persist_error=", candidate)
        self.assertNotEqual(expected[0][1], expected[-1][1])
        self.counts["actual_original_persistence_pairs"] = len(paths)
        self.completed.append(self._testMethodName)

    def test_replay_error_order_and_bounded_maximum(self):
        cases, expected = [], []
        for repeats in (0, 1, 1000, 1001, U64):
            for match in (0, 1):
                context = [1, 6, 1, 1, 1, 1, 1, 1, repeats, match, 0, 0, 0, 1, 1]
                case = report_case(report_frame(context, hashes=bytes(range(64))))
                cases.append(case)
                if repeats > 1000:
                    expected.append(b"--determinism-repeats exceeds bounded maximum 1000\n")
                elif repeats and not match:
                    expected.append(b"determinism replay mismatch for input " + bytes(range(32)).hex().encode()
                                    + b" and strategy AggressiveGreedy\n")
                else:
                    expected.append(None)
        for case, answer, error in zip(cases, self.calls("report", cases), expected):
            code, stdout, stderr, file = self.rendered(case, answer)
            if error is not None:
                self.assertEqual((code, stdout, stderr, file), (2, b"", error, b""))
            else:
                self.assertEqual((code, stderr, file), (0, b"", b""))
                self.assertTrue(stdout.startswith(b"bench_parallel_grouping\n"))
        stdout, stderr = self.process([self.original, "--determinism-repeats", "1001"], b"", "original-repeat-limit", expected=2)
        self.assertEqual((stdout, stderr), (b"", b"--determinism-repeats exceeds bounded maximum 1000\n"))
        self.counts["replay_outcome_controls"] = len(cases)
        self.completed.append(self._testMethodName)

    def test_atomic_frame_utf8_and_capacity_refusals(self):
        good = report_frame()
        normal = report_case(good)
        cases, expected = [], []
        def add(value, code, output=None, work=None):
            cases.append(("f0", [value, normal[1][1] if output is None else output, normal[1][2] if work is None else work]))
            expected.append(code)
        for length in (0, 1, 7, 8, 127, 263, 671, 751, 815, 847):
            add(good[:length], 1)
        add(b"X" + good[1:], 2)
        add(good + b"x", 1)
        for offset, value in ((8, 3), (16, 7), (56, 2), (64, 2), (80, 2), (520, 5), (672, 2), (680, 7), (816, 4)):
            changed = bytearray(good)
            struct.pack_into("<Q", changed, offset, value)
            add(bytes(changed), 3)
        for offset in (824, 832, 840):
            changed = bytearray(good)
            struct.pack_into("<Q", changed, offset, U64)
            add(bytes(changed), 1)
        active = [0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1]
        for invalid in (b"\x80", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"):
            value = report_frame(active, state=2, path=invalid)
            add(value, 4)
            add(value, 4, b"", b"")
        for capacity in (0, 39, 40, len(normal[1][1]) - 14):
            add(good, 100, bytes([0xA5]) * capacity)
        for capacity in (0, 8191, len(normal[1][2]) - 18):
            add(good, 100, work=bytes([0xD3]) * capacity)
        for case, answer, code in zip(cases, self.calls("report", cases), expected):
            answer.require_returned()
            self.assertEqual(answer.value, code)
            self.assertEqual(answer.arguments, case[1])
        text = b"BTXT0001" + struct.pack("<4Q", 0, 0, 0, 0)
        text_cases, text_expected = [], []
        for value, code in [(text[:n], 1) for n in (0, 7, 8, 39)] + [(text + b"x", 1), (b"X" + text[1:], 2)]:
            text_cases.append(("f0", [value, bytes([0xA5]) * 61, bytes([0xD3]) * 29]));text_expected.append(code)
        for words in ((4, 0, 0, 0), (0, 0, 1, 0), (1, 0, 1, 0), (2, 0, 0, 41), (3, 0, 0, 1)):
            text_cases.append(("f0", [b"BTXT0001" + struct.pack("<4Q", *words), bytes([0xA5]) * 61, b""]));text_expected.append(3)
        for size in (0, 7, 8, 47):
            text_cases.append(("f0", [text, bytes([0xA5]) * size, b""]));text_expected.append(100)
        for case, answer, code in zip(text_cases, self.calls("text", text_cases), text_expected):
            answer.require_returned()
            self.assertEqual(answer.value, code)
            self.assertEqual(answer.arguments, case[1])
        self.counts["report_atomic_refusals"] = len(cases)
        self.counts["text_atomic_refusals"] = len(text_cases)
        self.completed.append(self._testMethodName)


if __name__ == "__main__":
    unittest.main()
