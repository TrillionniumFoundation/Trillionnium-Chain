"""Native RequestStatus operations versus the unchanged original Rust crate.

The local binary envelope carries values only. It supplies no queue, durable
owner, authorization or Node capability. The tested state machine executes
the pinned HIA compiler's emitted machine code in bounded child processes.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/types/request_status.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-types/src/request_status"
ADAPTER = ROOT / "hia/tests/rust_request_status_reference.rs"
NAMES = ("OPEN", "ASSIGNED", "COMMIT_QUEUED", "REVEAL_SUBMITTED", "REJECTED",
         "FAILED_ADAPTER", "FAILED_SUBMISSION")
EDGES = {(0, 1), (1, 2), (1, 4), (1, 5), (2, 3), (2, 4), (2, 6)}
WHITESPACE = "".join(chr(c) for c in (*range(9, 14), 32, 0x85, 0xa0, 0x1680,
                                      *range(0x2000, 0x200b), 0x2028, 0x2029,
                                      0x202f, 0x205f, 0x3000))
SCRATCH = b"\x6d" * 19


def request(op=0, body=b"", source=0, target=0):
    return struct.pack("<4sBBBBQ", b"RQS1", op, source, target, 0, len(body)) + body


def record(kind, source, target, flags, display, detail="", code=""):
    strings = [value.encode() for value in (display, detail, code)]
    return (struct.pack("<8s7Q", b"RQSR0001", kind, source, target, flags,
                        *(len(value) for value in strings)) + b"".join(strings))


def expected_transition(source, target):
    allowed = source == target or (source, target) in EDGES
    flags = int(source >= 3) | int(allowed) << 1 | int(target >= 3) << 2
    if allowed:
        return record(0, source, target, flags, NAMES[target])
    code = "RequestStateInvalidTransition"
    display = f"illegal request status transition: {NAMES[source]} -> {NAMES[target]} (code={code})"
    return record(2, source, target, flags, display, code=code)


def expected_parse(text):
    normalized = text.strip(WHITESPACE)
    # str.upper() also changes non-ASCII code points; the original only folds
    # ASCII case. This independent model preserves every other input byte.
    token = "".join("_" if c in " -" else chr(ord(c) - 32) if "a" <= c <= "z" else c
                    for c in normalized)
    if token in NAMES:
        state = NAMES.index(token)
        return expected_transition(state, state)
    return record(1, 255, 255, 0, "unknown request state: " + normalized,
                  normalized, "RequestStateUnknown")


def public_cases():
    rows = [(request(1, source=state), expected_transition(state, state)) for state in range(7)]
    rows += [(request(2, source=left, target=right), expected_transition(left, right))
             for left, right in itertools.product(range(7), repeat=2)]
    for name in NAMES:
        forms = [name, name.lower(), "".join(c.lower() if i % 2 else c for i, c in enumerate(name)),
                 name.lower().replace("_", "-"), name.lower().replace("_", " ")]
        for text in forms:
            rows.append((request(body=text.encode()), expected_parse(text)))
            for whitespace in WHITESPACE:
                text_wrapped = whitespace + text + whitespace
                rows.append((request(body=text_wrapped.encode()), expected_parse(text_wrapped)))
    unknown = ("", "not-a-state", "\x1cOPEN\x1f", "\0OPEN", "OPEN\0", "O\tPEN",
               "commit\tqueued", "commit  queued", "commit--queued", "REJECTE\u212a",
               "a\u017f\u017figned", "\ufeffOPEN", "\u180eOPEN", "OPEN\u200b", "\u2060OPEN",
               "\u00a0  unknown-state \u2007", "链/交易", "é", "e\u0301", "\U0010ffff")
    rows += [(request(body=text.encode()), expected_parse(text)) for text in unknown]
    rng = random.Random(0x527175657374)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_- \t\0链é\u00a0\u202f"
    for _ in range(256):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(40)))
        rows.append((request(body=text.encode()), expected_parse(text)))
    return rows


class RequestStatusNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))
        cls.native_calls = 0

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_cases(self, rows):
        rows = list(rows)
        for offset in range(0, len(rows), 48):
            batch = rows[offset:offset + 48]
            got = self.native.call_many([("f0", [raw, b"\xa5" * capacity, SCRATCH])
                                         for raw, status, expected, capacity in batch])
            for (raw, status, expected, capacity), result in zip(batch, got):
                result.require_returned()
                self.assertEqual(result.value, status, raw[:100].hex())
                output = expected + b"\xa5" * (capacity - len(expected)) if status == 0 else b"\xa5" * capacity
                self.assertEqual(result.arguments, [raw, output, SCRATCH])
                type(self).native_calls += 1

    def test_all_public_methods_and_full_transition_matrix(self):
        self.check_cases((raw, 0, expected, len(expected) + 13) for raw, expected in public_cases())

    def test_no_non_ascii_case_folding_or_additional_separators(self):
        rows = []
        for state in NAMES:
            for position in range(len(state)):
                for char in ("\0", "\t", "\n", "\r", "/", ".", "\u017f", "\u212a", "\u200b", "\u00a0"):
                    text = state[:position] + char + state[position + 1:]
                    expected = expected_parse(text)
                    rows.append((request(body=text.encode()), 0, expected, len(expected) + 13))
        self.check_cases(rows)

    def test_unicode_trim_and_unknown_payload_are_exact(self):
        rows = []
        for left, right in itertools.product(WHITESPACE, repeat=2):
            for text in (left + "failed-submission" + right, left + "MiXeD-Unknown\0链" + right):
                expected = expected_parse(text)
                rows.append((request(body=text.encode()), 0, expected, len(expected)))
        # Python's default whitespace additionally includes these C0 controls;
        # the original Rust Unicode White_Space property does not.
        for codepoint in (0x1c, 0x1d, 0x1e, 0x1f, 0x180e, 0x200b, 0xfeff):
            text = chr(codepoint) + "OPEN" + chr(codepoint)
            expected = expected_parse(text)
            rows.append((request(body=text.encode()), 0, expected, len(expected)))
        self.check_cases(rows)

    def test_invalid_utf8_never_enters_string_methods(self):
        invalid = [bytes([byte]) for byte in range(128, 256)]
        invalid += [b"\xc0\x80", b"\xc1\xbf", b"\xe0\x80\x80", b"\xed\xa0\x80",
                    b"\xf0\x80\x80\x80", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80",
                    b"\xc2", b"\xe0\xa0", b"\xf0\x90\x80"]
        rows = [(request(body=raw), 101, b"", 256) for raw in invalid]
        rows += [(request(body=b"OPEN" + raw), 101, b"", 0) for raw in invalid]
        self.check_cases(rows)

    def test_canonical_envelope_and_invalid_states_refuse_without_mutation(self):
        base = request(body=b"OPEN")
        rows = [(base[:size], 100, b"", 256) for size in range(len(base))]
        rows += [(base + b"x", 100, b"", 256), (request(3), 100, b"", 256),
                 (request(255), 100, b"", 256), (request(1, b"x"), 100, b"", 256),
                 (request(2, b"x"), 100, b"", 256), (request(0, b"OPEN", 1), 100, b"", 256),
                 (request(0, b"OPEN", 0, 1), 100, b"", 256),
                 (request(1, source=0, target=1), 100, b"", 256)]
        for offset in (*range(4), 7):
            raw = bytearray(base)
            raw[offset] ^= 128
            rows.append((bytes(raw), 100, b"", 256))
        for size in (0, 1, 3, 5, (1 << 63), (1 << 64) - 1):
            raw = bytearray(base)
            struct.pack_into("<Q", raw, 8, size)
            rows.append((bytes(raw), 100, b"", 0))
        for state in range(7, 256):
            rows += [(request(1, source=state), 100, b"", 256),
                     (request(2, source=state), 100, b"", 256),
                     (request(2, target=state), 100, b"", 256)]
        self.check_cases(rows)

    def test_every_short_output_and_exact_output_boundary(self):
        rows = []
        samples = [(request(body=b"OPEN"), expected_parse("OPEN")),
                   (request(body=b"  unknown  "), expected_parse("  unknown  ")),
                   (request(2, source=6, target=3), expected_transition(6, 3))]
        for raw, expected in samples:
            rows.extend((raw, 102, b"", capacity) for capacity in range(len(expected)))
            rows += [(raw, 0, expected, len(expected)), (raw, 0, expected, len(expected) + 13)]
        self.check_cases(rows)

    def test_large_strings_have_no_new_semantic_length_limit(self):
        rows = []
        for text in ("\u2007" * 50000 + "open" + "\u3000" * 50000,
                     "\u00a0" * 2048 + "链\0" * 50000 + "\u2028" * 2048):
            expected = expected_parse(text)
            rows.append((request(body=text.encode()), 0, expected, len(expected) + 13))
            rows.append((request(body=text.encode()), 102, b"", max(0, len(expected) - 1)))
        self.check_cases(rows)

    def test_native_result_drives_the_next_transition(self):
        current = 0
        for target in (1, 1, 2, 0, 3, 3, 1):
            raw = request(2, source=current, target=target)
            expected = expected_transition(current, target)
            result = self.native.call("f0", [raw, b"\xa5" * len(expected), SCRATCH]).require_returned()
            self.assertEqual(result.value, 0)
            self.assertEqual(result.arguments, [raw, expected, SCRATCH])
            fields = struct.unpack("<8s7Q", result.arguments[1][:64])
            if fields[1] == 0:
                current = fields[3]
            type(self).native_calls += 1
        self.assertEqual(current, 3)

    def test_actual_unchanged_original_crate_and_all_request_status_tests(self):
        rows = public_cases()
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in sorted(ORIGINAL.glob("*.rs"))}
        with tempfile.TemporaryDirectory(prefix="trnm-hia-request-status-original-") as directory:
            directory = Path(directory)
            target, binary = directory / "target", directory / "reference"
            common = ["--locked", "--offline", "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"),
                      "-p", "trnm-types", "--target-dir", str(target)]
            configured = os.environ.get("TRNM_HIA_RUST_TYPES_RLIB")
            if configured:
                rlib = Path(configured).resolve(strict=True)
                self.assertEqual(rlib.suffix, ".rlib")
                dependencies = rlib.parent if rlib.parent.name == "deps" else rlib.parent / "deps"
                self.assertTrue(dependencies.is_dir())
            else:
                build = subprocess.run(["cargo", "build", *common, "--message-format=json"],
                                       capture_output=True, text=True, timeout=180, check=False)
                self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
                events = [json.loads(line) for line in build.stdout.splitlines() if line]
                libraries = [event for event in events if event.get("reason") == "compiler-artifact"
                             and event["target"]["name"] == "trnm_types"]
                self.assertEqual(len(libraries), 1)
                rlibs = [name for name in libraries[0]["filenames"] if name.endswith(".rlib")]
                self.assertEqual(len(rlibs), 1)
                rlib, dependencies = Path(rlibs[0]), target / "debug/deps"
            commands = [["rustc", "--edition=2021", "-O", str(ADAPTER), "--extern",
                         "trnm_types=" + str(rlib), "-L", "dependency=" + str(dependencies),
                         "-o", str(binary)],
                        ["cargo", "test", *common, "--lib", "request_status::tests::", "--", "--test-threads=1"]]
            observations = []
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                observations.append(result.stdout)
            self.assertIn("7 passed; 0 failed", observations[-1])
            result = subprocess.run([str(binary)], input="".join(raw.hex() + "\n" for raw, _ in rows),
                                    capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            original = [bytes.fromhex(line) for line in result.stdout.splitlines()]
        self.assertEqual(original, [expected for _, expected in rows])
        self.check_cases((raw, 0, expected, len(expected) + 13)
                         for (raw, _), expected in zip(rows, original))
        after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(ORIGINAL.glob("*.rs"))}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
