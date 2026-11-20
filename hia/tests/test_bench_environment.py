"""Native decimal/environment parsing and its actual seven-strategy effects.

The original executor is included unchanged to observe its private environment
getters. The existing Bench adapter supplies actual workloads and public Rust
scheduler/profile observations. Python only constructs test cases and transports
bytes; production numeric conversion and configuration selection are native HIA.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import time
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_bench_native import (
    build_original, clean_environment, group_digest, request, txs_from_frame,
)
from hia.tests.test_executor_schedule import (
    Config, decoded_output, graph_violations, schedule_reference, sizes,
)
from hia.tools.qualify import native_build_record, sources

ROOT = Path(__file__).resolve().parents[2]
EXECUTOR = ROOT / "trillionnium/crates/trnm-executor/src/lib.rs"
REFERENCE = ROOT / "hia/tests/rust_bench_environment_reference.rs"
U64 = (1 << 64) - 1
NAMES = (
    "TRNM_AGGR_DEEP_SCAN", "TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS",
    "TRNM_AGGR_SCAN_ROUND_ROBIN", "TRNM_AGGR_SCAN_WINDOW",
    "TRNM_AGGR_SCAN_RR_SEED", "TRNM_HOT_BUCKETS",
    "TRNM_AUTO_MIN_BATCH_LEN", "TRNM_AUTO_SAMPLE_LEN",
    "TRNM_AUTO_HOT_STREAK_RATIO", "TRNM_AUTO_REORDER_MIN_MARGIN",
    "TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE",
)
WHITE = tuple(chr(n) for n in (
    *range(9, 14), 32, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_inputs():
    result = sources()
    extras = [ROOT / "hia/src/bench/ENVIRONMENT.md", ROOT / "hia/src/bench/FORMATTING.md",
              ROOT / "hia/src/bench/README.md"]
    for name in ("trnm-bench", "trnm-executor", "trnm-types"):
        extras += [p for p in (ROOT / "trillionnium/crates" / name).rglob("*") if p.is_file()]
    for path in extras:
        if path.is_symlink():
            raise AssertionError("linked observation source")
        result[path.relative_to(ROOT).as_posix()] = digest(path.read_bytes())
    return dict(sorted(result.items()))


def frame(values):
    assert len(values) == 12
    return (b"BENV0001" + b"".join(struct.pack("<Q", U64 if value is None else len(value))
                                  for value in values)
            + b"".join(value or b"" for value in values))


def encoded(value):
    return "-" if value is None else value.hex() or "="


def decimal_cases():
    cases = [b"", b"+", b"-", b".", b".e1", b"1e", b"1e+", b"1e-", b"1.e2",
             b".1", b"1.", b"+0", b"-0", b"-0.000e+99999999999999999999999",
             b"0e999999999999999999999999999999", b"1e-999999999999999999999999999999",
             b"1e999999999999999999999999999999", b"1_000", b"1,000", b"1%", b" 1", b"1 ",
             b"++1", b"--1", b"+-1", b"1e++2", b"0x1p0", b"0b1", b"NaN", b"nan",
             b"inf", b"infinity", b"-Infinity", b"+INF", b"\xff", b"1\x00", "１".encode()]
    boundaries = (0, 1, 2, 0x000FFFFFFFFFFFFE, 0x000FFFFFFFFFFFFF,
                  0x0010000000000000, 0x3FEFFFFFFFFFFFFF, 0x3FF0000000000000,
                  0x3FF0000000000001, 0x7FEFFFFFFFFFFFFE, 0x7FEFFFFFFFFFFFFF)
    for bits in boundaries:
        a = Fraction.from_float(struct.unpack("<d", struct.pack("<Q", bits))[0])
        b = (Fraction(1 << 1024) if bits == 0x7FEFFFFFFFFFFFFF else
             Fraction.from_float(struct.unpack("<d", struct.pack("<Q", bits + 1))[0]))
        midpoint = (a + b) / 2
        exponent = midpoint.denominator.bit_length() - 1
        coefficient = midpoint.numerator * 5 ** exponent
        for tail in (0, 900):
            for delta in (-1, 0, 1):
                text = f"{coefficient * 10 ** tail + delta}e-{exponent + tail}".encode()
                cases.extend((text, b"-" + text))
    rng = random.Random(0x42454E56444543)
    for _ in range(96):
        bits = rng.randrange(1 << 64)
        value = struct.unpack("<d", struct.pack("<Q", bits))[0]
        if math.isfinite(value):
            cases.extend((repr(value).encode(), format(value, ".25e").encode()))
    for _ in range(96):
        length = rng.choice((1, 2, 17, 64, 799, 800, 801, 1001))
        digits = "".join(str(rng.randrange(10)) for _ in range(length))
        where = rng.randrange(length + 1)
        value = rng.choice(("", "+", "-")) + digits[:where] + "." + digits[where:]
        value += "e" + str(rng.randrange(-1300, 1301))
        cases.append(value.encode())
    return cases


def environment_cases():
    values = [None, b"", b" ", b"''", b'""', b"'", b'"', b"' ' ", b"'0\"", b"'\"0\"'",
        b"0", b"1", b"2", b"FALSE", b"Off", b"nO", b"true", b"yes", b"on", b"disabled",
        b"_", b",", b"_,_,", b"__false", b"0_", b"0,", b"\t' no '\r\n",
        b"+0", b"++0", b"++1", b"+++1", b"-0", b"-1", b"64", b"4096", b"4097",
        b"1_024", b"1,024", b"+1,024", b"++1,024", b"1,2,3", b",123", b"123,",
        b"1234,567", b"0,000", b"0,001", b"00,125", b"1,001", b"1,12", b"1,2e3",
        b"1e,3", b",1e3", b"1,,.0", b"1,000,000", b"1,00,000", b"+-,123", b"--0,123",
        b"+1", b"++64", str(U64).encode(), str(U64 + 1).encode(), b"9" * 80,
        b".22", b"+.22", b"-.22", b"22%", b"  '2_2%' ", b",125", b"+,125", b"-,125",
        b",5%", b"+0,125%", b"0.0075", b"-0%", b"-5e-324%", b"5e-324", b"1e-99999",
        b"1.7976931348623157e308", b"1.7976931348623159e308", b"0e999999999999999999999999",
        b"NaN", b"inf", b"-infinity", b"%", b"1%%", b"1e+2", b"1.e-2", b"0.0,001",
        b"\x80", b"\xc0\x80", b"\xe0\x80\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
        b"\xf0\x80\x80\x80", b"\xc2", b"\xe2\x80", b"\xf0\x90\x80", "零".encode()]
    for whitespace in WHITE:
        values.append((whitespace + "'" + whitespace + "0" + whitespace + "'" + whitespace).encode())
        values.append((whitespace + '"' + whitespace + "0,125%" + whitespace + '"' + whitespace).encode())
    for nonwhite in ("\u180e", "\u200b", "\ufeff", "\x1c", "\x1f"):
        values.extend(((nonwhite + "0").encode(), ("0" + nonwhite).encode()))
    result = [[value] * 12 for value in values]
    for index in range(12):
        for value in (None, b"", b"false", b"++1", b"++1,024", b"1,2e3", b"-5e-324%", b"\xff",
                      b"1,000", b"0,001", str(U64).encode(), str(U64 + 1).encode()):
            row = [None] * 12
            row[index] = value
            result.append(row)
    rng = random.Random(0x42454E56434647)
    result += [[rng.choice(values) for _ in range(12)] for _ in range(96)]
    return result


class BenchEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        configured = os.environ.get("HIA_BENCH_ENV_OBSERVATIONS")
        cls.temporary = None if configured else tempfile.TemporaryDirectory(prefix="trnm-bench-env-")
        if cls.temporary:
            cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(configured or cls.temporary.name).absolute()
        if configured:
            cls.directory.mkdir(parents=True, exist_ok=False)
        if ROOT == cls.directory or ROOT in cls.directory.parents:
            raise AssertionError("Bench evidence must be outside the checkout")
        cls.before = source_inputs()
        (cls.directory / "source-before.json").write_text(json.dumps(cls.before, indent=2) + "\n")
        result = subprocess.run(["bash", "scripts/project-preflight.sh", "--audit"], cwd=ROOT,
                                capture_output=True, timeout=30)
        (cls.directory / "preflight.stdout.raw").write_bytes(result.stdout)
        (cls.directory / "preflight.stderr.raw").write_bytes(result.stderr)
        result.check_returncode()
        cls.modules, cls.builds = {}, {}
        for name, source in (("decimal", "bench/decimal.hepta"), ("environment", "bench/environment.hepta"),
                             ("format", "bench/format_fixed.hepta"),
                             ("workload", "bench/workload.hepta"), ("schedule", "executor/schedule.hepta"),
                             ("repeat", "bench/repeat.hepta")):
            module = NativeModule(ROOT / "hia/src" / source, byte_exports=("f0",))
            cls.modules[name] = module
            cls.addClassCleanup(module.close)
            cls.builds[name] = {"receipt": module.receipt, "actual_build": native_build_record(module, cls.before)}
            (cls.directory / (name + ".so")).write_bytes(module.library.read_bytes())
        (cls.directory / "native-builds.json").write_text(json.dumps(cls.builds, indent=2) + "\n")
        cls.bench_original, cls.bench_identity = build_original(cls.directory)
        cls.original = cls.directory / "environment-original"
        dependencies = cls.bench_identity["dependencies"]
        types = Path(dependencies["trnm_types"]["path"])
        if digest(types.read_bytes()) != dependencies["trnm_types"]["sha256"]:
            raise AssertionError("Actual original type library changed")
        env = clean_environment()
        env["TRNM_EXECUTOR_SOURCE"] = str(EXECUTOR)
        command = ["rustc", "--edition=2021", "--deny=warnings", str(REFERENCE), "-o", str(cls.original),
                   "--extern", "trnm_types=" + str(types), "-L", "dependency=" + str(types.parent)]
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=90)
        (cls.directory / "environment-rustc.stdout.raw").write_bytes(result.stdout)
        (cls.directory / "environment-rustc.stderr.raw").write_bytes(result.stderr)
        result.check_returncode()
        cls.original_identity = {"source_sha256": digest(EXECUTOR.read_bytes()),
            "adapter_source_sha256": digest(REFERENCE.read_bytes()), "binary_sha256": digest(cls.original.read_bytes()),
            "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
            "type_library": dependencies["trnm_types"], "original_source_transformed": False}
        cls.events, cls.differences, cls.counts = [], [], {}

    @classmethod
    def tearDownClass(cls):
        after = source_inputs()
        stable = after == cls.before
        record = {"schema": "trnm.hia.bench-environment.observations.v1", "observations_only": True,
            "source_inputs": cls.before, "source_unchanged": stable, "original": cls.original_identity,
            "original_bench": cls.bench_identity, "builds": cls.builds, "counts": cls.counts,
            "native_invocations": cls.events, "intentional_high_water_differences": cls.differences,
            "whole_bench_native_qualified": False, "native_os_environment_owner_qualified": False,
            "wall_seconds": time.monotonic() - cls.started}
        (cls.directory / "report.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"bench_environment_observations": str(cls.directory / "report.json"),
                          "counts": cls.counts, "native_calls": len(cls.events)}))
        if not stable:
            raise AssertionError("Bench environment source changed during qualification")

    def calls(self, component, cases):
        results = self.modules[component].call_many(cases, timeout=60)
        self.counts[component] = self.counts.get(component, 0) + len(results)
        for sent, got in zip(cases, results):
            self.events.append({"component": component, "input_sha256": digest(sent[1][0]),
                "argument_sha256": [digest(arg) for arg in sent[1]], "argument_bytes": [len(arg) for arg in sent[1]],
                "status": got.status, "returncode": got.returncode, "value": got.value,
                "abi_status": got.abi_status,
                "output_sha256": None if got.arguments is None else digest(got.arguments[1])})
        return results

    def original_rows(self, commands, label):
        actual = subprocess.run([str(self.original)], input="".join(commands), text=True,
                                capture_output=True, check=True, timeout=60)
        (self.directory / (label + ".input.raw")).write_text("".join(commands))
        (self.directory / (label + ".stdout.raw")).write_text(actual.stdout)
        (self.directory / (label + ".stderr.raw")).write_text(actual.stderr)
        lines = actual.stdout.splitlines()
        self.assertEqual(len(lines), len(commands))
        return lines

    def test_decimal_exact_rounding_grammar_and_long_tails(self):
        values = decimal_cases()
        refs = self.original_rows(["D " + encoded(v) + "\n" for v in values], "decimal-original")
        for start in range(0, len(values), 24):
            batch = values[start:start + 24]
            cases = [("f0", [value, b"\xa5" * 25, b"\xc3" * (8192 + len(value) + 13)]) for value in batch]
            results = self.calls("decimal", cases)
            for offset, (case, actual) in enumerate(zip(cases, results), start):
                actual.require_returned()
                original = refs[offset]
                expected = b"\xa5" * 25 if original == "invalid" else struct.pack("<Q", int(original[3:], 16)) + b"\xa5" * 17
                self.assertEqual(actual.value, 1 if original == "invalid" else 0, offset)
                self.assertEqual(actual.arguments[1], expected, offset)
                self.assertEqual(actual.arguments[2][4096:8192], case[1][2][4096:8192], offset)
                self.assertEqual(actual.arguments[2][8192 + len(case[1][0]):], b"\xc3" * 13, offset)
        self.counts["decimal_actual_rust_pairs"] = len(values)

    def test_decimal_capacity_refusals_are_atomic(self):
        cases = []
        for value in (b"1", b"invalid", b"-5e-324"):
            required = 8192 + len(value)
            for output in range(8):
                cases.append(("f0", [value, b"\xa5" * output, b"\xc3" * required]))
            for scratch in (0, 127, 1023, 2047, 3071, 4095, 8191, required - 1):
                cases.append(("f0", [value, b"\xa5" * 23, b"\xc3" * scratch]))
        for case, actual in zip(cases, self.calls("decimal", cases)):
            actual.require_returned()
            self.assertEqual(actual.value, 100)
            self.assertEqual(actual.arguments, case[1])
        self.counts["decimal_atomic_refusals"] = len(cases)

    def test_twelve_environment_fields_against_actual_original(self):
        values = environment_cases()
        commands = ["E " + " ".join(encoded(v) for v in row) + "\n" for row in values]
        refs = self.original_rows(commands, "environment-original")
        for start in range(0, len(values), 24):
            batch = values[start:start + 24]
            payloads = [frame(row) for row in batch]
            cases = [("f0", [payload, b"\xa5" * 99, b"\xc3" * (8194 + len(payload) + 17)]) for payload in payloads]
            for offset, (case, actual) in enumerate(zip(cases, self.calls("environment", cases)), start):
                actual.require_returned()
                self.assertEqual(actual.value, 0, offset)
                self.assertEqual(actual.arguments[1], bytes.fromhex(refs[offset]) + b"\xa5" * 19, offset)
                self.assertEqual(actual.arguments[2][8194 + len(case[1][0]):], b"\xc3" * 17, offset)
        self.counts["environment_actual_rust_pairs"] = len(values)

    def test_environment_frame_and_capacity_refusals_are_atomic(self):
        base = frame([None] * 12)
        vectors = [(base[:n], 1) for n in range(104)]
        vectors += [(b"X" + base[1:], 2), (base + b"x", 1), (frame([b"\x00"] + [None] * 11), 1)]
        for length in (1, U64 - 1, 1 << 63):
            value = bytearray(base)
            struct.pack_into("<Q", value, 8, length)
            vectors.append((bytes(value), 1))
        cases = [("f0", [raw, b"\xa5" * 99, b"\xc3" * (8194 + len(raw))]) for raw, _ in vectors]
        expected = [code for _, code in vectors]
        for output in (0, 1, 7, 8, 79):
            cases.append(("f0", [base, b"\xa5" * output, b"\xc3" * (8194 + len(base))])); expected.append(100)
        for scratch in (0, 79, 4095, 8191, 8194 + len(base) - 1):
            cases.append(("f0", [base, b"\xa5" * 99, b"\xc3" * scratch])); expected.append(100)
        for case, code, actual in zip(cases, expected, self.calls("environment", cases)):
            actual.require_returned()
            self.assertEqual(actual.value, code)
            self.assertEqual(actual.arguments, case[1])
        self.counts["environment_atomic_refusals"] = len(cases)

    def test_fixed_four_format_matches_actual_rust_rounding(self):
        values = {0, 1, 2, 0x000FFFFFFFFFFFFF, 0x0010000000000000, 0x7FEFFFFFFFFFFFFF}
        for exponent in (*range(0, 2047, 31), 1007, 1008, 1009, 1074, 1075, 1076, 2046):
            for mantissa in (0, 1, (1 << 51) - 1, (1 << 52) - 1):
                values.add((exponent << 52) | mantissa)
        for number in (.00005, .00015, .00025, .03125, .09375, .99995, 9.99995, 99.99995,
                       1.23445, float(U64)):
            bits, = struct.unpack("<Q", struct.pack("<d", number))
            values.update((bits - 1, bits, bits + 1))
        values |= {value | (1 << 63) for value in values}
        rng = random.Random(0x42454E56464D54)
        for _ in range(96):
            bits = rng.randrange(1 << 64)
            if bits >> 52 & 2047 != 2047:
                values.add(bits)
        values = sorted(values)
        refs = self.original_rows([f"F {bits:016x}\n" for bits in values], "fixed-four-original")
        for start in range(0, len(values), 24):
            batch = values[start:start + 24]
            cases = [("f0", [b"BFXD0001" + struct.pack("<Q", bits), b"\xa5" * 340, b"\xc3" * 4625])
                     for bits in batch]
            for offset, (case, actual) in enumerate(zip(cases, self.calls("format", cases)), start):
                actual.require_returned()
                self.assertEqual(actual.value, 0)
                text = refs[offset].encode()
                expected = struct.pack("<Q", len(text)) + text
                self.assertEqual(actual.arguments[1], expected + b"\xa5" * (340 - len(expected)), offset)
                for begin, end in ((0, 1024), (2048, 4096), (4608, 4625)):
                    self.assertEqual(actual.arguments[2][begin:end], case[1][2][begin:end], offset)
        self.counts["fixed_four_actual_rust_pairs"] = len(values)

    def test_fixed_four_refusals_preserve_both_buffers(self):
        base = b"BFXD0001" + struct.pack("<d", -1.25)
        variants = [(base[:n], 323, 4608, 1) for n in range(16)]
        variants += [(base + b"x", 323, 4608, 1), (b"X" + base[1:], 323, 4608, 2)]
        for bits in (0x7FF0000000000000, 0xFFF0000000000000, 0x7FF0000000000001,
                     0xFFF8000000000000):
            variants.append((base[:8] + struct.pack("<Q", bits), 323, 4608, 3))
        variants += [(base, n, 4608, 100) for n in (0, 1, 8, 322)]
        variants += [(base, 323, n, 100) for n in (0, 1023, 2047, 4095, 4607)]
        cases = [("f0", [raw, b"\xa5" * out, b"\xc3" * work]) for raw, out, work, _ in variants]
        for case, (_, _, _, code), actual in zip(cases, variants, self.calls("format", cases)):
            actual.require_returned()
            self.assertEqual(actual.value, code)
            self.assertEqual(actual.arguments, case[1])
        self.counts["fixed_four_atomic_refusals"] = len(cases)

    def test_effective_config_drives_seven_strategies_profiles_and_repeats(self):
        configs = [
            [None] * 12,
            [b"true", b"false", b"false", b"1", b"0", b"4", b"64", b"64", b"0", b"-0", b"0", b"0"],
            [b"yes", b"on", b"on", b"2", str(U64).encode(), b"+1_6", b"64", b"128", b"22%", b"4%", b",75%", b"1%"],
            [b"false", b"0", b"no", b"4,096", b"++64", b"64", b"64", b"64", b"100%", b"100%", b"100%", b"100%"],
            [b"  ' true ' ", b"_,", b"false", b"++3", b"+1,024", b"++8", b"64", b"2_048", b"-5e-324%", b"0,001", b"1,2e-3", b"NaN"],
            [b"\xff", b"\xff", b"\xff", b"1,2,3", b"++1,024", b"-0", b"++64", b"++64", b"\xff", b"inf", b"-0%", b"0"],
        ]
        refs = self.original_rows(["E " + " ".join(encoded(v) for v in row) + "\n" for row in configs], "effective-config-original")
        payloads = [frame(row) for row in configs]
        parsed = self.calls("environment", [("f0", [raw, bytes(80), bytes(8194 + len(raw))]) for raw in payloads])
        exact, repaired_count, scheduled_count, replay_count = 0, 0, 0, 0
        for config_index, (values, actual, expected) in enumerate(zip(configs, parsed, refs)):
            actual.require_returned()
            self.assertEqual(actual.value, 0)
            raw_config = actual.arguments[1]
            self.assertEqual(raw_config.hex(), expected)
            config = Config(*struct.unpack("<10Q", raw_config))
            environment = clean_environment()
            environment.update({name: value for name, value in zip(NAMES, values) if value is not None})
            rows = [(workload, 65 if workload != 2 else 127, 3 if workload == 2 else 17, 2, 3, strategy)
                    for workload in range(3) for strategy in range(7)]
            original = subprocess.run([str(self.bench_original)],
                input="".join(" ".join(map(str, row)) + "\n" for row in rows), text=True,
                env=environment, capture_output=True, check=True, timeout=60)
            (self.directory / ("profile-original-" + str(config_index) + ".stdout.raw")).write_text(original.stdout)
            answers = [(bytes.fromhex(a), bytes.fromhex(b), bytes.fromhex(c), bytes.fromhex(d))
                       for a, b, c, d in (line.split("\t") for line in original.stdout.splitlines())]
            self.assertEqual(len(answers), len(rows))
            generated = self.calls("workload", [("f0", [request(row), bytes(len(ref[0]) + 8), b"unchanged"])
                                                 for row, ref in zip(rows, answers)])
            jobs, inputs = [], []
            for row, reference, got in zip(rows, answers, generated):
                got.require_returned(); self.assertEqual(got.value, 0)
                self.assertEqual(got.arguments[1], struct.pack("<Q", len(reference[0])) + reference[0])
                self.assertEqual(got.arguments[2], b"unchanged")
                effective = bytearray(got.arguments[1][8:]); effective[32:112] = raw_config
                txs = txs_from_frame(effective); out, work = sizes(txs)
                inputs.append((bytes(effective), txs, out, work))
                jobs.append(("f0", [bytes(effective), b"\xa5" * (out + 17), b"\xc3" * (work + 13)]))
            schedules = self.calls("schedule", jobs)
            repeat_cases, repeat_expected = [], []
            for row, reference, native, (effective, txs, out, work) in zip(rows, answers, schedules, inputs):
                native.require_returned(); self.assertEqual(native.value, 0)
                original, _ = decoded_output(reference[3], len(txs), 0)
                got, used = decoded_output(native.arguments[1], len(txs), 0)
                self.assertEqual(original, schedule_reference(txs, row[5], config, False), row)
                self.assertEqual(got, schedule_reference(txs, row[5], config, True), row)
                self.assertEqual(graph_violations(txs, got["groups"]), [], row)
                self.assertEqual(native.arguments[1][used:], b"\xa5" * (out + 17 - used))
                self.assertEqual(native.arguments[2][work:], b"\xc3" * 13)
                if original == got:
                    exact += 1
                else:
                    repaired_count += 1
                    self.differences.append({"config_index": config_index, "input": list(row),
                        "original_group_sha256": reference[2].hex(),
                        "native_group_sha256": group_digest(got["groups"]).hex(),
                        "original_pairwise_violations": graph_violations(txs, original["groups"]),
                        "native_pairwise_violations": []})
                scheduled_count += 1
                if row[5] in (4, 5, 6):
                    replay = bytearray(effective); replay[:8] = b"BNCHREP1"
                    struct.pack_into("<Q", replay, 112, 1)
                    repeat_cases.append(("f0", [bytes(replay), b"\xa5" * (2 * out + 112), bytes(work)]))
                    repeat_expected.append((out, native.arguments[1][:used], reference[1], group_digest(got["groups"])))
            for sent, expected, replay in zip(repeat_cases, repeat_expected, self.calls("repeat", repeat_cases)):
                replay.require_returned(); self.assertEqual(replay.value, 0)
                base, first, input_hash, groups_hash = expected
                output = replay.arguments[1]
                self.assertEqual(output[:len(first)], first)
                self.assertEqual(struct.unpack_from("<5Q", output, base + 8), (1, 1, 2, len(first), struct.unpack_from("<Q", first, 24)[0]))
                self.assertEqual(output[base + 48:base + 80], input_hash)
                self.assertEqual(output[base + 80:base + 112], groups_hash)
                self.assertEqual(output[base + 112:base + 112 + len(first)], first)
                replay_count += 1
        self.counts.update(effective_scheduler_cases=scheduled_count, exact_original_profiles=exact,
                           intentional_high_water_differences=repaired_count, effective_repeat_cases=replay_count)


if __name__ == "__main__":
    unittest.main()
