"""M11 native score closure against independent String/set/map observations."""
from __future__ import annotations
import itertools
import base64
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule

SOURCE = Path(__file__).resolve().parents[1] / "src/verification/closed_round.hepta"
MAX_U64 = (1 << 64) - 1
CANARY = bytes.fromhex("a55aa55aa55aa55a") * 2
SCRATCH = b"scratch remains unchanged"


def raw_wire(roster, votes, maximum=MAX_U64):
    """Test-only byte encoder; does not perform admission or score decisions."""
    data = b"CRD1" + struct.pack("<QII", maximum, len(roster), len(votes))
    for name in roster:
        data += struct.pack("<I", len(name)) + name
    for name, score in votes:
        data += struct.pack("<I", len(name)) + name + struct.pack("<Q", score)
    return data


def wire(eligible, votes, maximum=MAX_U64):
    return raw_wire(sorted(name.encode("utf-8") for name in eligible),
                    sorted((name.encode("utf-8"), score) for name, score in votes.items()), maximum)


def oracle(eligible, votes, maximum):
    """Independent policy on decoded Python containers, with Rust's ordering."""
    if len(eligible) not in (2, 3):
        return 2, None
    if not set(votes).issubset(eligible):
        return 3, None
    if any(score > maximum for score in votes.values()):
        return 4, None
    if len(votes) < len(eligible):
        return 1, None
    return 0, min(votes.values())


class ClosedRoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def observe(self, encoded, *, output=CANARY):
        result = self.native.call("f0", [encoded, output, SCRATCH]).require_returned()
        self.assertEqual(result.arguments[0], encoded)
        self.assertEqual(result.arguments[2], SCRATCH)
        return result

    def assert_policy(self, eligible, votes, maximum=MAX_U64):
        expected, score = oracle(eligible, votes, maximum)
        result = self.observe(wire(eligible, votes, maximum))
        self.assertEqual(result.value, expected)
        self.assertEqual(result.arguments[1], CANARY if score is None else struct.pack("<Q", score) + CANARY[8:])

    def test_original_every_arrival_order(self):
        eligible = {"a", "b", "c"}
        for order in itertools.permutations(("a", "b", "c")):
            votes = {}
            self.assert_policy(eligible, votes, 1000)
            for name in order:
                votes[name] = 10 if name == "a" else 100
                self.assert_policy(eligible, votes, 1000)

    def test_missing_is_pending_and_zero_is_complete(self):
        self.assert_policy({"a", "b", "c"}, {"b": 100, "c": 100}, 1000)
        self.assert_policy({"a", "b", "c"}, {"a": 0, "b": 100, "c": 100}, 1000)
        self.assert_policy({"a", "b"}, {"a": 0, "b": 0}, 0)
        pending = self.observe(wire({"a", "b"}, {"a": 0}), output=b"")
        self.assertEqual((pending.value, pending.arguments[1]), (1, b""))

    def test_roster_authority_evidence_pending_precedence(self):
        for eligible in (set(), {"a"}, {"a", "b", "c", "d"}):
            self.assert_policy(eligible, {"unknown": MAX_U64}, 0)
        self.assert_policy({"a", "b"}, {"unknown": MAX_U64}, 0)
        self.assert_policy({"a", "b"}, {"a": 1}, 0)
        self.assert_policy({"a", "b"}, {"a": 0}, 0)
        self.assert_policy({"a", "b"}, {"a": 0, "b": 0}, 0)

    def test_author_excluded_two_evaluator_roster(self):
        self.assert_policy({"a", "b"}, {"a": 10, "b": 100}, 1000)
        self.assert_policy({"a", "b"}, {"a": 10, "b": 100, "author": 1}, 1000)

    def test_full_u64_domain_endpoints(self):
        for maximum in (0, 1, 255, 65535, 1 << 32, 1 << 63, MAX_U64):
            self.assert_policy({"a", "b"}, {"a": maximum, "b": maximum}, maximum)
            self.assert_policy({"a", "b"}, {"a": 0, "b": maximum}, maximum)
            if maximum != MAX_U64:
                self.assert_policy({"a", "b"}, {"a": maximum + 1, "b": 0}, maximum)

    def test_exact_unicode_and_empty_string_identities(self):
        names = ["", "\x00", "a", "é", "e\u0301", "中", "\ud7ff", "\ue000", "\uffff", "\U00010000", "\U0010ffff"]
        for left, right in itertools.combinations(names, 2):
            self.assert_policy({left, right}, {left: 17, right: 23})
        self.assert_policy({"é", "a"}, {"e\u0301": 17, "a": 23})

    def test_container_truncation_trailing_and_header_failures(self):
        encoded = wire({"a", "b", "c"}, {"a": 7, "b": 8, "c": 9})
        vectors = [encoded[:i] for i in range(len(encoded))]
        vectors += [encoded + b"\x00", b"BAD1" + encoded[4:], encoded[:12] + b"\xff" * 4 + encoded[16:]]
        results = self.native.call_many([("f0", [data, CANARY, SCRATCH]) for data in vectors])
        for result in results:
            result.require_returned()
            self.assertEqual(result.value, 100)
            self.assertEqual(result.arguments[1:], [CANARY, SCRATCH])

    def test_unsorted_or_duplicate_roster_and_votes_are_not_maps(self):
        vectors = [raw_wire([b"b", b"a"], []), raw_wire([b"a", b"a"], []),
                   raw_wire([b"a", b"b"], [(b"b", 1), (b"a", 2)]),
                   raw_wire([b"a", b"b"], [(b"a", 1), (b"a", 2)]),
                   raw_wire([b"", b""], []), raw_wire([b"a", b"b"], [(b"", 1), (b"", 1)])]
        for encoded in vectors:
            result = self.observe(encoded)
            self.assertEqual((result.value, result.arguments[1]), (102, CANARY))

    def test_invalid_utf8_is_rejected_before_policy(self):
        invalid = [b"\x80", b"\xbf", b"\xc0\x80", b"\xc1\xbf", b"\xc2", b"\xe0\x9f\x80",
                   b"\xed\xa0\x80", b"\xf0\x8f\xbf\xbf", b"\xf4\x90\x80\x80",
                   b"\xf5\x80\x80\x80", b"\xff", b"\xfe", b"\xe2A\x80", b"\xf0\x90\x80"]
        for name in invalid:
            for encoded in (raw_wire([name], []), raw_wire([b"a", b"b"], [(name, MAX_U64)], 0)):
                result = self.observe(encoded)
                self.assertEqual((result.value, result.arguments[1]), (101, CANARY))

    def test_utf8_decoder_against_independent_codec(self):
        rng = random.Random(61115)
        names = [bytes([byte]) for byte in range(256)]
        names += [rng.randbytes(rng.randrange(0, 9)) for _ in range(512)]
        expected = []
        for name in names:
            try:
                name.decode("utf-8", errors="strict")
                expected.append(2)  # valid one-element roster, then original roster refusal
            except UnicodeDecodeError:
                expected.append(101)
        results = self.native.call_many([("f0", [raw_wire([name], []), CANARY, SCRATCH]) for name in names])
        for result, code in zip(results, expected):
            result.require_returned()
            self.assertEqual(result.value, code)
            self.assertEqual(result.arguments[1:], [CANARY, SCRATCH])

    def test_output_is_written_only_for_complete(self):
        complete = wire({"a", "b"}, {"a": 5, "b": 7})
        for size in range(8):
            initial = b"\xa5" * size
            result = self.observe(complete, output=initial)
            self.assertEqual((result.value, result.arguments[1]), (104, initial))
        self.assert_policy({"a", "b"}, {"a": 5, "b": 7})

    def test_long_names_with_exact_original_identity(self):
        first, second = "a" * 131072, "a" * 131071 + "b"
        self.assert_policy({first, second}, {first: 3, second: 7})

    def test_exact_capacity_and_actual_native_oversize_refusal(self):
        # 52 fixed bytes plus each name twice is exactly the public 1 MiB bound.
        first, second = "a" * 262131, "b" * 262131
        encoded = wire({first, second}, {first: 5, second: 7})
        self.assertEqual(len(encoded), 1 << 20)
        result = self.observe(encoded)
        self.assertEqual(result.value, 0)
        self.assertEqual(result.arguments[1], struct.pack("<Q", 5) + CANARY[8:])
        # The normal caller rejects oversize before execution. This explicit
        # negative probe uses its same isolated test worker and exact artifact
        # to exercise the HIA capacity branch, with actual private allocations.
        request = {"library": str(self.native.library), "sha256": self.native.artifact_sha256,
                   "cpu_seconds": 5, "cases": [{"function": "f0", "returns": ["u32"],
                   "byte_abi": True, "arguments": [
                       {"type": typ, "bytes": base64.b64encode(data).decode()}
                       for typ, data in (("readbuf", encoded + b"!"), ("mutbuf", CANARY),
                                         ("mutbuf", SCRATCH))]}]}
        child = subprocess.run([sys.executable, "-I", "-S", "-B",
                                str(Path(__file__).with_name("native_support.py")), "--worker"],
                               input=json.dumps(request), capture_output=True, text=True,
                               timeout=10, check=True)
        observed = json.loads(child.stdout)
        self.assertEqual(observed["artifact_sha256"], self.native.artifact_sha256)
        self.assertEqual(observed["host_compiler_modules_loaded"], [])
        case = observed["cases"][0]
        self.assertEqual((case["abi_status"], case["value"]), (0, 103))
        self.assertEqual(base64.b64decode(case["arguments"][1]["bytes"]), CANARY)
        self.assertEqual(base64.b64decode(case["arguments"][2]["bytes"]), SCRATCH)

    def test_independent_container_oracle_and_second_native_backend(self):
        rng = random.Random(150011)
        names = ["", "a", "ab", "b", "é", "中", "\U00010000"]
        vectors, expectations = [], []
        for _ in range(384):
            eligible = set(rng.sample(names, rng.randrange(6)))
            votes = {name: rng.choice((0, 1, 17, 1 << 63, MAX_U64))
                     for name in rng.sample(names, rng.randrange(6))}
            maximum = rng.choice((0, 1, 17, 1 << 63, MAX_U64))
            vectors.append(("f0", [wire(eligible, votes, maximum), CANARY, SCRATCH]))
            expectations.append(oracle(eligible, votes, maximum))
        native = self.native.call_many(vectors)
        with NativeModule(SOURCE, byte_exports=("f0",), backend="direct") as reference_backend:
            other = reference_backend.call_many(vectors)
        for left, right, (status, score) in zip(native, other, expectations):
            left.require_returned(); right.require_returned()
            self.assertEqual((left.value, left.arguments), (right.value, right.arguments))
            self.assertEqual(left.value, status)
            expected = CANARY if score is None else struct.pack("<Q", score) + CANARY[8:]
            self.assertEqual(left.arguments[1:], [expected, SCRATCH])


if __name__ == "__main__":
    unittest.main()
