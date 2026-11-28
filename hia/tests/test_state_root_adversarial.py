"""Independent bottom-up sparse-tree and raw native memory controls.

The oracle combines least-significant path bits level by level. It does not
import the product generator, use its sorted top-down DFS, or call the Rust
implementation. The worker runs only the pinned selfhost-generated machine
artifact, from sealed bytes, with actual unaligned pointer residues and repeated
calls sharing one physical arena. Live foreign allocations remain exclusive;
cross-call reuse does not permit simultaneous mutable aliases.

The complete 65,536-row case has an explicit 570-second child CPU budget and a
600-second wall deadline. These development budgets do not change or certify
the original four-second service budget, throughput or whole-chain acceptance.
"""
from __future__ import annotations

import base64
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time
import unittest

from hia.tests.native_support import NativeModule


ROOT = Path(__file__).resolve().parents[1]
BASE_SCRATCH = 157024
ROW_SCRATCH = 64
MAX_ROWS = 65536
OUTPUT_BYTES = 47


def domain_hash(name, *fields):
    encoded = b"TRNM-PON1\0" + len(name).to_bytes(2, "little") + name
    encoded += b"".join(len(field).to_bytes(4, "little") + field for field in fields)
    return hashlib.sha256(encoded).digest()


@lru_cache(maxsize=1)
def empty_by_height():
    empty = [domain_hash(b"state-empty")]
    for _ in range(256):
        empty.append(domain_hash(b"state-node", empty[-1], empty[-1]))
    return tuple(empty)


def bottom_up_root(entries):
    """A map of integer path positions, reduced from leaves up to the root."""
    nodes = {}
    for key, value in entries:
        position = int.from_bytes(domain_hash(b"state-key", key), "big")
        if position in nodes:
            raise ValueError("duplicate hash path")
        nodes[position] = domain_hash(b"state-leaf", key, value)
    if not nodes:
        return empty_by_height()[256]
    for height in range(256):
        empty = empty_by_height()[height]
        parents = {position >> 1 for position in nodes}
        nodes = {parent: domain_hash(b"state-node", nodes.get(parent << 1, empty),
                                     nodes.get((parent << 1) | 1, empty))
                 for parent in parents}
    if set(nodes) != {0}:
        raise AssertionError("oracle did not reach one root")
    return nodes[0]


def frame(entries):
    return b"SRV1" + len(entries).to_bytes(4, "little") + b"".join(
        len(key).to_bytes(4, "little") + len(value).to_bytes(4, "little") + key + value
        for key, value in entries)


def step(entries=(), *, raw=None, code=0, scratch_len=None, output_len=OUTPUT_BYTES,
         before_writes=False):
    raw = frame(entries) if raw is None else raw
    count = int.from_bytes(raw[4:8], "little") if len(raw) >= 8 else 0
    used = BASE_SCRATCH + ROW_SCRATCH * min(count, MAX_ROWS)
    return {"raw": raw, "code": code, "entries": entries,
            "scratch_len": used + 37 if scratch_len is None else scratch_len,
            "output_len": output_len, "used": used, "before_writes": before_writes}


RAW_WORKER = r"""
import base64, ctypes, fcntl, hashlib, json, os, resource, sys, time
request = json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (request['cpu_seconds'], request['cpu_seconds']))
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(4, 0, 0, 0, 0):
    raise OSError(ctypes.get_errno(), 'disable core dumps')
with open(request['artifact']['path'], 'rb') as source:
    binary = source.read()
actual_sha = hashlib.sha256(binary).hexdigest()
if actual_sha != request['artifact']['sha256']:
    raise ValueError('native artifact identity changed')
fd = os.memfd_create('trnm-state-root-adversarial', os.MFD_ALLOW_SEALING)
try:
    position = 0
    while position < len(binary):
        written = os.write(fd, binary[position:])
        if written <= 0:
            raise OSError('short native artifact capture')
        position += written
    fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
    if fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034)) != 15:
        raise ValueError('native artifact is not sealed')
    library = ctypes.CDLL('/proc/self/fd/' + str(fd))
finally:
    os.close(fd)
function = library.f0
function.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
function.restype = ctypes.c_uint64

def allocate(payload, residue):
    storage = ctypes.create_string_buffer(len(payload) + 64)
    ctypes.memset(ctypes.addressof(storage), 0x69, ctypes.sizeof(storage))
    begin = 16 + ((residue - ctypes.addressof(storage)) % 8)
    address = ctypes.addressof(storage) + begin
    ctypes.memmove(address, payload, len(payload))
    return (storage, begin, len(payload), address, storage.raw)

def contents(buffer):
    storage, begin, size, address, initial = buffer
    return storage.raw[begin:begin + size]

def guards(buffer):
    storage, begin, size, address, initial = buffer
    return (storage.raw[:begin] == initial[:begin]
            and storage.raw[begin + size:] == initial[begin + size:])

answers = []
for sequence in request['sequences']:
    steps = sequence['steps']
    rows = [base64.b64decode(case['input'], validate=True) for case in steps]
    source = allocate(b'\x5a' * max(map(len, rows)), sequence['residues'][0])
    output = allocate(b'\xa5' * 47, sequence['residues'][1])
    size = max(case['scratch_len'] for case in steps) + 37
    if not 0 <= size <= 8 << 20:
        raise ValueError('test arena bound')
    pattern = bytes((index * 73 + sequence['seed']) & 255 for index in range(256))
    arena = allocate((pattern * ((size + 255) // 256))[:size], sequence['residues'][2])
    ranges = [(buffer[3], buffer[3] + buffer[2]) for buffer in (source, output, arena)]
    for i, (left, end) in enumerate(ranges):
        for right, right_end in ranges[i + 1:]:
            if max(left, right) < min(end, right_end):
                raise ValueError('foreign allocations must be exclusive')
    sequence_answers = []
    for raw, case in zip(rows, steps):
        if not 0 <= case['scratch_len'] <= arena[2] or not 0 <= case['output_len'] <= 47:
            raise ValueError('test buffer extent')
        ctypes.memmove(source[3], raw, len(raw))
        ctypes.memset(output[3], 0xa5, 47)
        input_before, before = contents(source), contents(arena)
        started, cpu_started = time.monotonic_ns(), time.process_time_ns()
        result = function(source[3], len(raw), output[3], case['output_len'],
                          arena[3], case['scratch_len'])
        elapsed, cpu = time.monotonic_ns() - started, time.process_time_ns() - cpu_started
        after, out = contents(arena), contents(output)
        sequence_answers.append({
            'value': result & 0xffffffff, 'abi_status': result >> 32,
            'elapsed_ns': elapsed, 'cpu_ns': cpu,
            'pointer_residues': [buffer[3] % 8 for buffer in (source, output, arena)],
            'arena_address': arena[3], 'scratch_extent': case['scratch_len'],
            'input_sha256': hashlib.sha256(raw).hexdigest(),
            'input_unchanged': contents(source) == input_before,
            'output': out.hex(), 'output_tail_unchanged': out[32:] == b'\xa5' * 15,
            'scratch_unchanged': before == after,
            'scratch_outside_work_unchanged': before[case['used']:] == after[case['used']:],
            'scratch_outside_borrow_unchanged': before[case['scratch_len']:] == after[case['scratch_len']:],
            'guards_unchanged': all(guards(buffer) for buffer in (source, output, arena)),
        })
    answers.append(sequence_answers)
print(json.dumps({'artifact_sha256': actual_sha, 'sequences': answers,
                  'compiler_modules_loaded': [name for name in sys.modules if name.startswith('hepta')]}))
"""


class StateRootAdversarialNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = ROOT / "src/protocol/state_root.hepta"
        cls.test_source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        cls.sources = {path: path.read_bytes() for path in
                       (cls.source, ROOT / "src/crypto/sha256_arena.hepta")}
        cls.module = NativeModule(cls.source, byte_exports=("f0",), backend="selfhost")
        cls.observations = []
        cls.native_calls = 0

    @classmethod
    def tearDownClass(cls):
        try:
            print(json.dumps({
                "schema": "trnm.hia.state-root-adversarial-observation.v1",
                "backend": "selfhost", "native_calls": cls.native_calls,
                "source_sha256": {path.name: hashlib.sha256(raw).hexdigest()
                                  for path, raw in cls.sources.items()},
                "sources_unchanged": all(path.read_bytes() == raw for path, raw in cls.sources.items()),
                "test_source_sha256": cls.test_source_sha256,
                "artifact_sha256": cls.module.artifact_sha256,
                "build_receipt": cls.module.receipt,
                "observations": cls.observations,
                "maximum_state_count_executed": any(row.get("rows") == MAX_ROWS and row.get("result") == 0
                                                     for row in cls.observations),
                "oracle": "bottom-up integer-path levels with hashlib",
                "service_budget_qualified": False, "whole_chain_native": False,
                "production_activation": False,
            }, sort_keys=True), flush=True)
        finally:
            cls.module.close()

    def run_sequences(self, sequences, *, cpu_seconds=55, wall_seconds=60):
        encoded = []
        for sequence in sequences:
            steps = [{"input": base64.b64encode(item["raw"]).decode(),
                      "scratch_len": item["scratch_len"], "output_len": item["output_len"],
                      "used": item["used"]} for item in sequence["steps"]]
            encoded.append({"residues": sequence["residues"], "seed": sequence["seed"], "steps": steps})
        request = {"artifact": {"path": str(self.module.library), "sha256": self.module.artifact_sha256},
                   "cpu_seconds": cpu_seconds, "sequences": encoded}
        started = time.monotonic()
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", RAW_WORKER],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            process.stdin.write(json.dumps(request)); process.stdin.close(); process.stdin = None
            # Compute the independent expectation while the native worker runs;
            # no oracle code or expected digest is sent to that worker.
            expected = [[bottom_up_root(item["entries"]) if item["code"] == 0 else None
                         for item in sequence["steps"]] for sequence in sequences]
            remaining = wall_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, wall_seconds)
            stdout, stderr = process.communicate(timeout=remaining)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            type(self).observations.append({"worker_completed": False,
                                           "elapsed_seconds": time.monotonic() - started,
                                           "cpu_budget_seconds": cpu_seconds,
                                           "wall_budget_seconds": wall_seconds})
            raise
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stderr, "")
        observed = json.loads(stdout)
        self.assertEqual(observed["artifact_sha256"], self.module.artifact_sha256)
        self.assertEqual(observed["compiler_modules_loaded"], [])
        self.assertEqual(len(observed["sequences"]), len(sequences))
        for sequence, outputs, roots in zip(sequences, observed["sequences"], expected):
            self.assertEqual(len(outputs), len(sequence["steps"]))
            self.assertEqual(len({row["arena_address"] for row in outputs}), 1)
            for item, got, root in zip(sequence["steps"], outputs, roots):
                with self.subTest(input_sha256=hashlib.sha256(item["raw"]).hexdigest(), code=item["code"]):
                    self.assertEqual(got["value"], item["code"])
                    self.assertEqual(got["abi_status"], 0)
                    self.assertEqual(got["pointer_residues"], sequence["residues"])
                    self.assertEqual(got["input_sha256"], hashlib.sha256(item["raw"]).hexdigest())
                    for key in ("input_unchanged", "output_tail_unchanged", "scratch_outside_work_unchanged",
                                "scratch_outside_borrow_unchanged", "guards_unchanged"):
                        self.assertTrue(got[key], key)
                    if item["before_writes"]:
                        self.assertTrue(got["scratch_unchanged"])
                    output = bytes.fromhex(got["output"])
                    self.assertEqual(output, root + b"\xa5" * 15 if root is not None else b"\xa5" * 47)
                    type(self).native_calls += 1
                    if len(item["entries"]) == MAX_ROWS:
                        type(self).observations.append({
                            "rows": MAX_ROWS, "input_bytes": len(item["raw"]),
                            "input_sha256": got["input_sha256"], "result": got["value"],
                            "abi_status": got["abi_status"], "scratch_extent": item["scratch_len"],
                            "native_elapsed_seconds": got["elapsed_ns"] / 1e9,
                            "native_cpu_seconds": got["cpu_ns"] / 1e9,
                            "root": root.hex() if root is not None else None,
                            "same_physical_arena_sequence": True, "canaries_preserved": True,
                            "cpu_budget_seconds": cpu_seconds, "wall_budget_seconds": wall_seconds,
                            "service_budget_qualified": False,
                        })
        return observed

    def test_00_full_65536_rows_and_one_byte_short_reuse(self):
        rows = [(index.to_bytes(4, "little"), b"x") for index in range(MAX_ROWS)]
        minimum = BASE_SCRATCH + ROW_SCRATCH * MAX_ROWS
        duplicate = [(b"duplicate", b"first"), (b"other", b""), (b"duplicate", b"second")]
        small = [(b"after-maximum", b""), (b"\x00", b"replacement")]
        self.run_sequences([{"residues": [7, 3, 5], "seed": 219, "steps": [
            step(rows, code=100, scratch_len=minimum - 1, before_writes=True),
            step(rows, scratch_len=minimum),
            step(small), step([]), step(duplicate, code=5),
            step(raw=b"SRV1\x01\0\0\0", code=1, before_writes=True), step(small),
        ]}], cpu_seconds=570, wall_seconds=600)

    def test_actual_unaligned_residues_and_absent_is_not_empty(self):
        cases = [[], [(b"", b"")], [(b"present", b"")], [(b"present", b"\0")]]
        self.assertEqual(len({bottom_up_root(rows) for rows in cases}), len(cases))
        sequences = [{"residues": [residue, (residue + 3) % 8, (residue + 5) % 8],
                      "seed": residue * 13 + 1, "steps": [step(rows) for rows in cases]}
                     for residue in range(8)]
        self.run_sequences(sequences)

    def test_insertion_orders_heap_boundaries_and_stale_arena(self):
        randomizer = random.Random(0x53525631)
        small = [(index.to_bytes(2, "big"), bytes([index & 255]) * (index % 71)) for index in range(33)]
        large = [(index.to_bytes(4, "little"), randomizer.randbytes(index % 97)) for index in range(257)]
        shuffled = large.copy(); randomizer.shuffle(shuffled)
        rows = [small, list(reversed(large)), shuffled, [], list(reversed(small)), large[:1]]
        self.assertEqual(bottom_up_root(large), bottom_up_root(shuffled))
        self.run_sequences([{"residues": [1, 7, 3], "seed": 151,
                             "steps": [step(value) for value in rows]}])

    def test_transcript_padding_maximum_key_and_value_are_real_bytes(self):
        cases = []
        for key_length in (0, 30, 31, 38, 39, 40, 94, 95, 102, 103, 104, 159, 160):
            key = bytes((index * 83 + key_length) & 255 for index in range(key_length))
            cases.append([(key, bytes(range(256)) * 16)])
        for length in (0, 25, 26, 33, 34, 35, 89, 90, 4095, 4096):
            cases.append([(b"", bytes((index * 47 + 11) & 255 for index in range(length)))])
        self.run_sequences([{"residues": [3, 5, 7], "seed": 17,
                             "steps": [step(rows) for rows in cases]}])

    def test_full_grammar_pass_limits_and_error_precedence_before_writes(self):
        valid = [(b"prefix", b"v"), (b"tail", b"more")]
        good = frame(valid)
        cases = [step(raw=good[:7], code=1, scratch_len=0, output_len=0, before_writes=True),
                 step(raw=b"BAD!" + (65537).to_bytes(4, "little"), code=2,
                      scratch_len=0, output_len=0, before_writes=True),
                 step(raw=b"SRV1" + (65537).to_bytes(4, "little"), code=4,
                      scratch_len=0, output_len=0, before_writes=True),
                 step(valid, code=100, output_len=31, before_writes=True),
                 step(valid, code=100, scratch_len=BASE_SCRATCH + 127, before_writes=True),
                 step(raw=good[:-1], code=1, before_writes=True),
                 step(raw=good + b"trailing", code=1, before_writes=True),
                 step(raw=b"SRV1\x01\0\0\0" + (0xffffffff).to_bytes(4, "little") + bytes(4),
                      code=4, before_writes=True),
                 step([(b"a" * 161, b"")], code=4, before_writes=True),
                 step([(b"", b"v" * 4097)], code=4, before_writes=True),
                 step([(b"same", b"1"), (b"same", b"2"), (b"late" * 41, b"")],
                      code=4, before_writes=True),
                 step(raw=frame([(b"same", b"1"), (b"same", b"2"), (b"late", b"3")])[:-1],
                      code=1, before_writes=True), step(valid, output_len=32)]
        self.run_sequences([{"residues": [5, 1, 7], "seed": 93, "steps": cases}])

    def test_repeated_key_hash_collisions_never_publish_a_partial_root(self):
        rows = [(index.to_bytes(2, "little"), bytes([index])) for index in range(17)]
        controls = [rows + [rows[0]], rows + [(rows[-1][0], b"different")],
                    [(b"", b""), (b"", b"other")]]
        for entries in controls:
            with self.assertRaisesRegex(ValueError, "duplicate hash path"):
                bottom_up_root(entries)
        self.run_sequences([{"residues": [7, 5, 1], "seed": 201,
                             "steps": [step(rows), *[step(value, code=5) for value in controls], step(rows)]}])

    def test_exact_native_source_and_backend(self):
        self.assertEqual(hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), self.test_source_sha256)
        for path, before in self.sources.items():
            self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.module.receipt["chain_migration"]["backend"], "selfhost")
        self.assertFalse(self.module.receipt["claims"]["python_emitter_used"])
        self.assertFalse(self.module.receipt["claims"]["fallback_used"])


if __name__ == "__main__":
    unittest.main()
