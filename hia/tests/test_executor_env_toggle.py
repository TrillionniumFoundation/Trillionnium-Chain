"""Exact active/retained Rust environment versus self-hosted HIA toggle."""
from __future__ import annotations

import hashlib
import itertools
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/executor/env_toggle.hepta"
RUST = ROOT / "trillionnium/crates/trnm-executor/src"
ADAPTER = ROOT / "hia/tests/rust_executor_env_toggle_reference.rs"
FUNCTIONS = ("env_toggle_enabled", "aggr_skip_empty_stage_checks", "aggr_deep_scan_enabled",
             "aggr_scan_round_robin_enabled")
PIN = {
    "lib.rs": "34da3fcf14cd41afd04de7e0037982631b8542fcc9271b457f961e112c91d1ac",
    "env_config.rs": "cdf0785931f0cf5a7f282742cb379a1465e6c29c347423674205c7650801f874",
}
WHITESPACE = (*range(9, 14), 0x20, 0x85, 0xa0, 0x1680, *range(0x2000, 0x200b),
              0x2028, 0x2029, 0x202f, 0x205f, 0x3000)
MAX_FRAME = 1 << 20
OUTPUT = b"\xa5" * 17
SCRATCH = b"\x66" * 19


def extract_original(path):
    source = path.read_bytes()
    result = []
    for name in FUNCTIONS:
        pattern = rb"(?ms)^(?:pub\(crate\) )?fn " + name.encode() + rb"\([^\n]*\n.*?^}"
        matches = re.findall(pattern, source)
        if len(matches) != 1:
            raise AssertionError(f"missing/ambiguous original {name} in {path.name}")
        result.append(matches[0])
    joined = b"\n\n".join(result)
    if hashlib.sha256(joined).hexdigest() != PIN[path.name]:
        raise AssertionError(f"original toggle or callers changed in {path.name}")
    return joined


def frame(value, default):
    if value is None:
        return bytes([0, default])
    return bytes([1, default]) + value


def expected(value, default):
    if value is None:
        return default
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return default
    space = "".join(map(chr, WHITESPACE))
    text = text.strip(space)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip(space)
    if not text or all(ch in "_," for ch in text):
        return default
    folded = text.encode().lower()
    return folded not in (b"0", b"false", b"off", b"no")


def values():
    result = [None, b"", b".", b"0", b"false", b"off", b"no", b"1", b"on", b"true",
              b"0_", b",false", b"of f", b"''", b"\"\"", b"'", b"\"", b"'false\"",
              b'"false\'', b'"\"false\""', b'"\'false\'"', b"false\rtrue", b"__,,",
              b"__ ,", b"'__,_'", b' "\t,_,_ " ', b"\xff", b"\x80\x80", b"\xc0\x80",
              b"\xef\xbb\xbf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xf0\x9f\x98",
              "ＮＯ".encode(), "Falſe".encode(), "✘".encode()]
    for token in ("false", "off", "no"):
        result.extend("".join(word).encode() for word in
                      itertools.product(*[(ch, ch.upper()) for ch in token]))
    for cp in (*WHITESPACE, 0x1c, 0x1d, 0x1e, 0x1f, 0x180e, 0x200b, 0x2060, 0xfeff):
        ch = chr(cp)
        for token in ("", "0", "No", "_,", "True", "N o"):
            result.extend((ch + token + ch, ch + "'" + ch + token + ch + "'" + ch,
                           '"' + ch + token + ch + '"'))
    rng = random.Random(0x45544F47)
    alphabet = "0faLSeON_,.'\" \t\n\r" + "".join(map(chr, WHITESPACE)) + "é😀中"
    result.extend("".join(rng.choices(alphabet, k=rng.randrange(25))) for _ in range(181))
    result.extend(bytes([n]) for n in range(1, 256))
    return list(dict.fromkeys(v.encode() if isinstance(v, str) else v for v in result))


class ExecutorEnvToggle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_native(self, cases):
        for start in range(0, len(cases), 48):
            batch = cases[start:start + 48]
            got = self.native.call_many([("f0", [raw, OUTPUT, SCRATCH]) for raw, _ in batch])
            for answer, (raw, result) in zip(got, batch, strict=True):
                answer.require_returned()
                self.assertEqual(answer.value, result, raw[:40].hex())
                self.assertEqual(answer.arguments, [raw, OUTPUT, SCRATCH])

    def test_exact_active_and_retained_environment_and_all_three_callers(self):
        original = {name: extract_original(RUST / name) for name in PIN}
        specimens = [(raw, default) for raw in values() for default in (False, True)]
        requests = [frame(raw, default) for raw, default in specimens]
        framed = b"".join(struct.pack("<I", len(raw)) + raw for raw in requests)
        with tempfile.TemporaryDirectory(prefix="trnm-executor-toggle-rust-") as tmp:
            tmpdir = Path(tmp)
            active = tmpdir / "toggle_active.rs"
            active.write_bytes(original["lib.rs"] + b"\n")
            executable = tmpdir / "toggle_original"
            rustc = os.environ.get("RUSTC", "rustc")
            toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
            version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                                     text=True, timeout=15).stdout.split()
            self.assertEqual(version[:2], ["rustc", toolchain])
            env = {**os.environ, "TRNM_EXECUTOR_ACTIVE_TOGGLE_SOURCE": str(active),
                   "TRNM_EXECUTOR_RETAINED_CONFIGURATION_SOURCE": str(RUST / "env_config.rs")}
            compile_run = subprocess.run(
                [rustc, "--edition=2021", "-Dwarnings", str(ADAPTER), "-o", str(executable)],
                check=True, capture_output=True, env=env, timeout=30)
            self.assertEqual(compile_run.stderr, b"")
            observed = subprocess.run([str(executable)], input=framed, check=True,
                                      capture_output=True, env={}, timeout=30)
        self.assertEqual(observed.stderr, b"")
        self.assertEqual({name: extract_original(RUST / name) for name in PIN}, original)
        expected_wires = []
        cases = []
        for raw, default in specimens:
            decision = expected(raw, default)
            row = bytes([decision, expected(raw, True), expected(raw, False), expected(raw, True)])
            expected_wires.append(row * 2)
            cases.append((frame(raw, default), decision))
        self.assertEqual(observed.stdout, b"".join(expected_wires))
        self.check_native(cases)

    def test_malformed_frame_is_not_a_decision(self):
        malformed = [b"", b"\0", b"\1", b"\0\0extra", b"\0\1extra"]
        malformed.extend(bytes([tag, default]) for tag in range(2, 256) for default in (0, 1))
        malformed.extend(bytes([tag, default]) for default in range(2, 256) for tag in (0, 1))
        self.check_native([(raw, 100) for raw in malformed])

    def test_bounded_long_separator_and_nonfalse_paths(self):
        body = b",_" * ((MAX_FRAME - 2) // 2)
        self.assertEqual(len(body) + 2, MAX_FRAME)
        self.check_native([(frame(body, False), False),
                           (frame(body, True), True),
                           (frame(body[:-1] + b"X", False), True)])

    def test_length_is_bound_to_exact_false_token(self):
        # These bytes cannot come from an OS environment variable, but the
        # private ABI must not accept a false-token prefix followed by NUL.
        self.check_native([(frame(token + b"\0", False), True)
                           for token in (b"0", b"no", b"off", b"false")])


if __name__ == "__main__":
    unittest.main()
