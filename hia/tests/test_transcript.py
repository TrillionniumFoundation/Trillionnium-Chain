"""Actual self-hosted HIA transcript methods versus the unchanged Rust crate.

The Python process supplies typed values, framing, hashlib controls and test
observations. Only the emitted HIA machine code performs the native methods.
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

from hia.tests.native_support import NativeModule
from hia.tests.test_transfer import LARGE_WORKER

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/types/transcript.hepta"
ADAPTER = ROOT / "hia/tests/rust_transcript_reference.rs"
ORIGINAL = ROOT / "trillionnium/crates/trnm-types/src/transcript"
MAGIC = b"TRNMTP1\0"
U64 = (1 << 64) - 1
U128 = (1 << 128) - 1
CANARY = b"\xa5" * 19
FIELDS = ("chain_id", "msg_type", "version", "task_id", "session_id", "from", "to",
          "nonce", "payload_hash", "sig")


def sample(seq=1, **changes):
    value = dict(chain_id="trnm-mainnet", msg_type="INPUT_CHUNK", version="p2p-v0.2",
                 task_id="task-1", session_id="session-1", seq=seq,
                 timestamp_ms=1730000000000 + seq, nonce=f"nonce-{seq}",
                 payload=b"\x00\xffsample", payload_hash="hash-text", sig="signature-text")
    value.update({"from": "from-address", "to": "to-address"})
    value.update(changes)
    return value


def envelope(value):
    strings = [value[name].encode() if isinstance(value[name], str) else bytes(value[name])
               for name in FIELDS]
    payload = bytes(value["payload"])
    body = b"".join(strings) + payload
    return (struct.pack("<15Q", 120 + len(body), value["seq"], value["timestamp_ms"] & U64,
                        value["timestamp_ms"] >> 64, *(len(text) for text in strings), len(payload))
            + body)


def request(op, values=(), *, start=0, end=0, target=0, targets=()):
    return (struct.pack("<8s9Q", MAGIC, op, start, end, target, len(values), len(targets), 0, 0, 0)
            + b"".join(envelope(value) for value in values)
            + b"".join(struct.pack("<Q", value) for value in targets))


def verify_request(root, leaf, path=(), directions=()):
    return (struct.pack("<8s9Q", MAGIC, 5, 0, 0, 0, 0, 0, len(path), len(directions), 0)
            + bytes(root) + bytes(leaf) + b"".join(path) + bytes(directions))


def record(tag=0, x=0, y=0, z=0, payload=b""):
    return struct.pack("<8s5Q", b"TRNMTR1\0", tag, x, y, z, len(payload)) + payload


def hash_control(value):
    fields = ["TRNM_P2P_V1", value["chain_id"], value["msg_type"], value["version"],
              value["task_id"], value["session_id"], str(value["seq"]), str(value["timestamp_ms"]),
              value["from"], value["to"], value["nonce"], value["payload_hash"], value["sig"]]
    return hashlib.sha256("|".join(fields).encode()).digest()


def tree_extent(count):
    total = 0
    while count:
        total += count
        if count == 1:
            break
        count = count // 2 + count % 2
    return 4096 + total * 32


def scratch_extent(raw):
    if len(raw) < 80:
        return 4096
    op = struct.unpack_from("<Q", raw, 8)[0]
    if op == 0:
        return 2600
    if op == 5:
        return 1312
    count = struct.unpack_from("<Q", raw, 40)[0]
    return tree_extent(count) if count <= len(raw) // 120 else 4096


def decode_proof(raw, at=0):
    leaf = raw[at:at + 32]
    paths, directions = struct.unpack_from("<QQ", raw, at + 32)
    cursor = at + 48
    path = [raw[cursor + index * 32:cursor + (index + 1) * 32] for index in range(paths)]
    cursor += paths * 32
    return leaf, path, list(raw[cursor:cursor + directions]), cursor + directions


class TranscriptNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["bash", "scripts/project-preflight.sh", "--audit"], cwd=ROOT,
                       capture_output=True, text=True, check=True)
        cls.original_sources = {path: path.read_bytes() for path in (
            *sorted(ORIGINAL.glob("*.rs")), ORIGINAL.parent / "lib.rs", ORIGINAL.parent / "relay.rs",
            ORIGINAL.parent.parent / "Cargo.toml", ROOT / "trillionnium/Cargo.lock")}
        cls.own_sources = {path: path.read_bytes() for path in (SOURCE, ADAPTER, Path(__file__))}
        cls._temporary = tempfile.TemporaryDirectory(prefix="trnm-hia-transcript-original-")
        cls.original = Path(cls._temporary.name) / "original-transcript"
        library_name = os.environ.get("TRNM_HIA_RUST_TYPES_RLIB")
        if not library_name:
            cls._temporary.cleanup()
            raise RuntimeError("TRNM_HIA_RUST_TYPES_RLIB must identify the unchanged original crate")
        cls.library = Path(library_name).resolve(strict=True)
        cls.library_sha256 = hashlib.sha256(cls.library.read_bytes()).hexdigest()
        cls.rustc_version = subprocess.run(["rustc", "--version"], capture_output=True,
                                          text=True, check=True).stdout.strip()
        if not cls.rustc_version.startswith("rustc 1.95.0 "):
            cls._temporary.cleanup()
            raise RuntimeError("Transcript differential requires the repository's pinned Rust 1.95.0")
        built = subprocess.run(["rustc", "--edition=2021", "-O", str(ADAPTER),
                                "--extern", "trnm_types=" + str(cls.library),
                                "-L", "dependency=" + str(cls.library.parent / "deps"),
                                "-o", str(cls.original)], capture_output=True, text=True, check=False)
        if built.returncode:
            cls._temporary.cleanup()
            raise RuntimeError("Actual original transcript adapter failed: " + built.stderr)
        cls.native = NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost")
        cls.native_calls = cls.original_calls = cls.large_calls = 0
        cls.observations = []
        cls.original_observations = []
        cls.large_observations = []
        cls.original_test_stdout = cls.original_test_stderr = ""
        cls.original_tests_passed = 0

    @classmethod
    def tearDownClass(cls):
        try:
            for path, raw in {**cls.original_sources, **cls.own_sources}.items():
                if path.read_bytes() != raw:
                    raise AssertionError("Transcript qualification source changed: " + str(path))
            if hashlib.sha256(cls.library.read_bytes()).hexdigest() != cls.library_sha256:
                raise AssertionError("Original compiled trnm-types changed during qualification")
            report = {"schema": "trnm.hia.transcript-development.v1", "backend": "selfhost",
                      "native_calls": cls.native_calls, "original_calls": cls.original_calls,
                      "large_pointer_calls": cls.large_calls,
                      "original_module_tests_passed": cls.original_tests_passed,
                      "rustc_version": cls.rustc_version,
                      "original_rlib_sha256": cls.library_sha256,
                      "original_binary_sha256": hashlib.sha256(cls.original.read_bytes()).hexdigest(),
                      "sources_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(raw).hexdigest()
                                         for path, raw in {**cls.original_sources, **cls.own_sources}.items()},
                      "build_receipt": cls.native.receipt, "native_observations": cls.observations,
                      "original_observations": cls.original_observations,
                      "large_observations": cls.large_observations,
                      "whole_crate_native": False, "whole_chain_native": False,
                      "retirement_accepted": False}
            output = os.environ.get("TRNM_HIA_TRANSCRIPT_REPORT_DIR")
            if output:
                destination = Path(output).resolve()
                destination.mkdir(parents=True, exist_ok=False)
                shutil.copyfile(cls.native.library, destination / "transcript.so")
                shutil.copyfile(cls.original, destination / "original-transcript")
                shutil.copyfile(SOURCE, destination / "transcript.hepta")
                shutil.copyfile(ADAPTER, destination / ADAPTER.name)
                (destination / "original-tests.stdout").write_text(cls.original_test_stdout)
                (destination / "original-tests.stderr").write_text(cls.original_test_stderr)
                (destination / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            print(json.dumps({key: report[key] for key in (
                "schema", "backend", "native_calls", "original_calls", "large_pointer_calls",
                "original_module_tests_passed", "whole_crate_native", "whole_chain_native")}, sort_keys=True))
        finally:
            cls.native.close()
            cls._temporary.cleanup()

    @classmethod
    def reference(cls, requests):
        result = subprocess.run([str(cls.original)], input="".join(raw.hex() + "\n" for raw in requests),
                                capture_output=True, text=True, timeout=60, check=True)
        if result.stderr or len(result.stdout.splitlines()) != len(requests):
            raise AssertionError("Incomplete original transcript observations")
        answers = [bytes.fromhex(line) for line in result.stdout.splitlines()]
        cls.original_calls += len(requests)
        cls.original_observations.extend({"request_sha256": hashlib.sha256(raw).hexdigest(),
                                          "result": answer.hex()}
                                         for raw, answer in zip(requests, answers))
        return answers

    def checks(self, requests, expected=None):
        requests = list(requests)
        expected = self.reference(requests) if expected is None else expected
        for start in range(0, len(requests), 32):
            batch = list(zip(requests[start:start + 32], expected[start:start + 32]))
            calls = [("f0", [raw, b"\xa5" * (len(answer) + len(CANARY)),
                               b"\x6d" * (scratch_extent(raw) + 19)]) for raw, answer in batch]
            results = self.native.call_many(calls, timeout=60)
            for (raw, answer), (_, before), observed in zip(batch, calls, results):
                observed.require_returned()
                self.assertEqual(observed.value, 0, raw[:80].hex())
                self.assertEqual(observed.arguments[0], raw)
                self.assertEqual(observed.arguments[1], answer + CANARY, raw[:80].hex())
                self.assertEqual(observed.arguments[2][scratch_extent(raw):], before[2][scratch_extent(raw):])
                if struct.unpack_from("<Q", answer, 8)[0]:
                    self.assertEqual(observed.arguments[2], before[2])
                type(self).native_calls += 1
                type(self).observations.append({"request_sha256": hashlib.sha256(raw).hexdigest(),
                    "operation": struct.unpack_from("<Q", raw, 8)[0], "status": observed.value,
                    "result": answer.hex(), "scratch_bytes": len(before[2]),
                    "scratch_sha256": hashlib.sha256(observed.arguments[2]).hexdigest()})
        return expected

    def exact(self, raw, answer, *, capacity, scratch, code=0):
        before = [raw, b"\xa5" * capacity, b"\x6d" * scratch]
        seen = self.native.call("f0", before, timeout=60).require_returned()
        self.assertEqual(seen.value, code, raw[:80].hex())
        self.assertEqual(seen.arguments[0], raw)
        wanted = answer + b"\xa5" * (capacity - len(answer)) if code == 0 else before[1]
        self.assertEqual(seen.arguments[1], wanted)
        if code or (answer and struct.unpack_from("<Q", answer, 8)[0]):
            self.assertEqual(seen.arguments[2], before[2])
        type(self).native_calls += 1
        type(self).observations.append({"request_sha256": hashlib.sha256(raw).hexdigest(),
            "status": seen.value, "result": answer.hex() if code == 0 else "",
            "output_capacity": capacity, "scratch_bytes": scratch,
            "scratch_unchanged": seen.arguments[2] == before[2]})

    def test_hash_exact_field_order_unsigned_decimal_and_typed_strings(self):
        cases = [sample(0, timestamp_ms=0), sample(U64, timestamp_ms=U128)]
        numbers = [0, 1, 9, 10, 99, 100, (1 << 32) - 1, 1 << 32,
                   (1 << 63) - 1, 1 << 63, U64]
        cases += [sample(seq, timestamp_ms=time) for seq in numbers
                  for time in (0, 9, 10, U64, U64 + 1, 1 << 127, U128)]
        for field in FIELDS:
            for text in ("", "|", "a|b", "\x00\n\t", "链ée\u0301\U0010ffff", " x ", "x" * 513):
                cases.append(sample(**{field: text}))
        cases += [sample(payload=b""), sample(payload=bytes(range(256)) * 7)]
        expected = [record(payload=hash_control(value)) for value in cases]
        raw = [request(0, [value]) for value in cases]
        self.assertEqual(self.reference(raw), expected)
        self.checks(raw, expected)
        self.assertEqual(expected[-1], expected[-2], "payload bytes are excluded by the original hash")

    def test_all_tree_methods_and_odd_leaf_proofs(self):
        requests = []
        for count in [1, 2, 3, 4, 5, 7, 8, 9, 17, 31, 32, 33, 65]:
            values = [sample(index + 11) for index in range(count)]
            for op in (1, 4, 6, 7):
                requests.append(request(op, values, start=11, end=count + 10))
            for index in range(count):
                requests.append(request(2, values, start=11, end=count + 10, target=index + 11))
                requests.append(request(8, values, start=11, end=count + 10, target=index))
            requests.append(request(8, values, start=11, end=count + 10, target=count))
            requests.append(request(8, values, start=11, end=count + 10, target=U64))
            requests.append(request(3, values, start=11, end=count + 10,
                                    targets=[count + 10, 11, count + 10, 11]))
        self.checks(requests)
        values = [sample(1), sample(2), sample(3)]
        answer = self.checks([request(2, values, start=1, end=3, target=3)])[0]
        leaf, path, directions, _ = decode_proof(answer, 80)
        self.assertEqual(path[0], leaf)
        self.assertEqual(directions, [1, 0])
        left = hashlib.sha256(hash_control(values[0]) + hash_control(values[1])).digest()
        right = hashlib.sha256(hash_control(values[2]) * 2).digest()
        self.assertEqual(answer[48:80], hashlib.sha256(left + right).digest())

    def test_sequence_errors_priorities_and_full_u64_endpoints(self):
        cases = [([], 1, 3), ([0], 1, 3), ([2, 3], 1, 3), ([1], 1, 3),
                 ([1, 3], 1, 3), ([1, 1, 2, 3], 1, 3), ([1, 4, 2, 3], 1, 3),
                 ([4, 1, 2, 3], 1, 3), ([1, 0, 2, 3], 1, 3),
                 ([0, 1, 2, 3, 4], 1, 3), ([], 3, 1), ([1, 2, 3], 3, 1),
                 ([U64], U64, U64), ([U64 - 1, U64], U64 - 1, U64),
                 ([U64 - 1], U64 - 1, U64 - 1), ([0], 0, 0)]
        rows = []
        for seqs, start, end in cases:
            values = [sample(seq, timestamp_ms=U128) for seq in seqs]
            for op in (1, 2, 3, 4, 6, 7, 8):
                rows.append(request(op, values, start=start, end=end,
                                    target=start if op == 2 else U64 if op == 8 else 0,
                                    targets=[start, end] if op == 3 else []))
            rows.append(request(3, values, start=start, end=end, targets=[]))
        answers = self.checks(rows)
        self.assertTrue(any(answer == record(4, U64) for answer in answers))
        values = [sample(1), sample(2), sample(3)]
        rows = [request(2, values, start=1, end=3, target=t) for t in (0, 4, U64)]
        rows += [request(3, values, start=1, end=3, targets=targets)
                 for targets in ([0, 4], [4, 0], [1, 4, 0], [3, 1, 3, 2])]
        self.checks(rows)
        self.checks([request(3, [], start=3, end=1)], [record(2)])

    def test_proof_verification_and_tampering_against_original(self):
        rows = []
        for count in (1, 3, 5, 9):
            values = [sample(index + 1) for index in range(count)]
            requests = [request(2, values, start=1, end=count, target=index + 1)
                        for index in range(count)]
            for answer in self.reference(requests):
                root = answer[48:80]
                leaf, path, directions, _ = decode_proof(answer, 80)
                rows.append(verify_request(root, leaf, path, directions))
                rows.append(verify_request(bytes([root[0] ^ 1]) + root[1:], leaf, path, directions))
                rows.append(verify_request(root, bytes([leaf[0] ^ 1]) + leaf[1:], path, directions))
                rows.append(verify_request(root, leaf, path, directions + [0]))
                if path:
                    rows.append(verify_request(root, leaf, path, directions[:-1]))
                for index in range(len(path)):
                    changed = list(path)
                    changed[index] = changed[index][:-1] + bytes([changed[index][-1] ^ 1])
                    rows.append(verify_request(root, leaf, changed, directions))
                    flipped = list(directions)
                    flipped[index] ^= 1
                    rows.append(verify_request(root, leaf, path, flipped))
        self.checks(rows)
        for depth in (0, 1, 63, 64, 65, 129, 1025):
            leaf = bytes(range(32))
            path = [hashlib.sha256(struct.pack("<Q", index)).digest() for index in range(depth)]
            directions = [index & 1 for index in range(depth)]
            acc = leaf
            for sibling, direction in zip(path, directions):
                acc = hashlib.sha256(sibling + acc if direction == 0 else acc + sibling).digest()
            raw = verify_request(acc, leaf, path, directions)
            self.assertEqual(self.reference([raw]), [record(x=1)])
            self.checks([raw], [record(x=1)])

    def test_deterministic_randomized_original_method_differential(self):
        rng = random.Random(0x54524E4D5452)
        rows = []
        alphabet = "abAB|\x00\n链é\u00a0"
        for _ in range(256):
            count = rng.randrange(0, 13)
            values = [sample(index + 1, timestamp_ms=rng.getrandbits(128),
                             nonce="".join(rng.choice(alphabet) for _ in range(rng.randrange(30))))
                      for index in range(count)]
            if values and rng.randrange(3) == 0:
                values[rng.randrange(count)]["seq"] = rng.choice([0, 1, count, U64])
            start, end = rng.randrange(count + 3), rng.randrange(count + 3)
            op = rng.choice([1, 2, 3, 4, 6, 7, 8])
            targets = [rng.randrange(count + 4) for _ in range(rng.randrange(5))] if op == 3 else []
            target = rng.randrange(count + 4) if op in (2, 8) else 0
            rows.append(request(op, values, start=start, end=end, target=target, targets=targets))
        self.checks(rows)

    def test_exact_output_scratch_and_failure_atomicity(self):
        values = [sample(index + 1) for index in range(5)]
        rows = [request(0, [sample()])]
        rows += [request(op, values, start=1, end=5, target=3 if op == 2 else 2 if op == 8 else 0,
                         targets=[5, 1, 5] if op == 3 else []) for op in (1, 2, 3, 4, 6, 7, 8)]
        proof = self.reference([rows[2]])[0]
        leaf, path, directions, _ = decode_proof(proof, 80)
        rows.append(verify_request(proof[48:80], leaf, path, directions))
        for raw, answer in zip(rows, self.reference(rows)):
            scratch = scratch_extent(raw)
            self.exact(raw, answer, capacity=len(answer), scratch=scratch)
            self.exact(raw, answer, capacity=len(answer) - 1, scratch=scratch, code=102)
            self.exact(raw, answer, capacity=len(answer), scratch=scratch - 1, code=102)
        for raw, answer in zip((request(1, []), request(3, [], start=3, end=1)),
                               (record(1), record(2))):
            self.exact(raw, answer, capacity=48, scratch=0)
            self.exact(raw, answer, capacity=47, scratch=0, code=102)
        self.exact(verify_request(bytes(32), bytes(32)), record(x=1), capacity=48, scratch=0)
        self.exact(verify_request(bytes(32), bytes(32), directions=[0]), record(x=0), capacity=48, scratch=0)

    def test_malformed_framing_and_utf8_preserve_all_buffers(self):
        good = request(0, [sample()])
        rows = [(good[:length], 100) for length in range(80)]
        rows += [(good[:-cut], 100) for cut in (1, 2, 7, 8, 31, 64, 120)]
        for offset in (0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 112, 192):
            for value in (U64, U64 - 1, 1 << 63):
                changed = bytearray(good)
                struct.pack_into("<Q", changed, offset, value)
                rows.append((bytes(changed), 100))
        rows += [(good + b"x", 100), (request(0, []), 100), (request(0, [sample(), sample()]), 100)]
        for bad in (b"\xff", b"\x80", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"):
            for field in FIELDS:
                rows.append((request(0, [sample(**{field: bad})]), 101))
        proof = verify_request(bytes(32), bytes(32), [bytes(32)], [0])
        rows += [(proof[:-1] + b"\x02", 100), (proof[:-1] + b"\xff", 100), (proof + b"x", 100)]
        for offset in (16, 24, 32, 40, 48, 56, 64, 72):
            changed = bytearray(proof)
            struct.pack_into("<Q", changed, offset, U64)
            rows.append((bytes(changed), 100))
        for raw, code in rows:
            self.exact(raw, b"", capacity=127, scratch=4217, code=code)

    def test_large_unaligned_fields_and_ignored_payload(self):
        cases = [sample(chain_id="x" * 2098177), sample(sig="链" * 700000),
                 sample(payload=bytes(range(256)) * 8193)]
        for value in cases:
            raw = request(0, [value])
            answer = self.reference([raw])[0]
            self.assertEqual(answer, record(payload=hash_control(value)))
            sent = {"library": str(self.native.library), "sha256": self.native.artifact_sha256,
                    "input": raw.hex(), "output_bytes": len(answer) + len(CANARY),
                    "scratch_bytes": 2619, "residues": [1, 3, 5]}
            ran = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", LARGE_WORKER],
                                 input=json.dumps(sent), capture_output=True, text=True,
                                 timeout=60, check=True)
            self.assertEqual(ran.stderr, "")
            observed = json.loads(ran.stdout)
            self.assertEqual(observed["artifact_sha256"], self.native.artifact_sha256)
            self.assertEqual(observed["input_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(observed["value"], 0)
            self.assertEqual(observed["abi_status"], 0)
            self.assertEqual(observed["output"], (answer + CANARY).hex())
            self.assertTrue(observed["guards"])
            self.assertTrue(observed["input_unchanged"])
            self.assertEqual(observed["residues"], [1, 3, 5])
            self.assertEqual(observed["compiler_modules_loaded"], [])
            type(self).large_calls += 1
            type(self).large_observations.append(observed)

    def test_original_module_retained_tests(self):
        result = subprocess.run(["cargo", "test", "--locked", "--offline", "-p", "trnm-types",
                                 "--target-dir", str(Path(self._temporary.name) / "cargo"),
                                 "--lib", "transcript::tests::", "--", "--test-threads=1"],
                                cwd=ROOT / "trillionnium", capture_output=True, text=True,
                                timeout=180, check=False)
        type(self).original_test_stdout = result.stdout
        type(self).original_test_stderr = result.stderr
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("8 passed; 0 failed; 0 ignored", result.stdout)
        type(self).original_tests_passed = 8


if __name__ == "__main__":
    unittest.main()
