"""Stateful native M05 queue owner with mandatory original Rust comparison.

One isolated process retains every physical context allocation throughout an
entire operation sequence. Python supplies commands and observes bytes; it does
not restore a context between calls or perform a native-path queue operation.
The independent deque model and original Rust adapter are reference paths only.
"""
from __future__ import annotations

from collections import deque
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/mempool/lane_owner.hepta"
POLICY = ROOT / "hia/src/mempool/lane_quota.hepta"
RUST_LIB = ROOT / "trillionnium/crates/trnm-mempool/src/lib.rs"
RUST_REFERENCE = ROOT / "hia/tests/rust_mempool_owner_reference.rs"
U64 = (1 << 64) - 1
MAGIC = b"NLOV0001"
REPLY = b"NLOR0001"
HEADER = b"NLOC0001"
TAIL = b"\x69" * 19
OUT_TAIL = b"\xa5" * 17


def wire(op, a=0, b=0, reserved=0):
    return struct.pack("<8s4Q", MAGIC, op, a, b, reserved)


def context(capacity):
    return bytes(128 + 8 * capacity) + TAIL


def command(op, a=0, b=0, **options):
    return {"input": wire(op, a, b).hex(), "output_size": 113, **options}


class Model:
    """Independent mathematical queue definition; never used by the worker."""

    def __init__(self):
        self.live = False
        self.normal = deque()
        self.critical = deque()
        self.total = self.reserve = self.normal_capacity = self.streak = 0

    def allowed(self):
        free = self.reserve - len(self.critical)
        normal_free = len(self.normal) < self.normal_capacity
        borrow = free > 0 and (self.normal_capacity == 0 or free > 1
                              or len(self.critical) == 0)
        room = len(self.normal) + len(self.critical) < self.total
        return (room and (normal_free or borrow), room and (free > 0 or normal_free))

    def apply(self, op, a=0, b=0):
        outcome = id_ = 0
        if op == 0:
            assert not self.live
            self.live = True
            self.total, self.reserve = a, min(a, b)
            self.normal_capacity = a - self.reserve
            self.burst = max(1, min(U64, 2 * self.reserve))
            self.normal.clear()
            self.critical.clear()
            self.streak = 0
        elif op == 7:
            assert self.live
            self.live = False
            self.normal.clear()
            self.critical.clear()
            self.streak = 0
            return struct.pack("<8s11Q", REPLY, op, *([0] * 10))
        else:
            assert self.live
            if op in (1, 2):
                id_ = a
                if a in self.normal or a in self.critical:
                    outcome = 1
                elif not self.allowed()[op - 1]:
                    outcome = 2
                else:
                    empty_normal = not self.normal
                    if op == 1:
                        target = self.normal if len(self.normal) < self.normal_capacity else self.critical
                    else:
                        target = self.critical if len(self.critical) < self.reserve else self.normal
                    target.append(a)
                    if self.normal_capacity and empty_normal and self.normal and self.critical:
                        self.streak = self.burst
            elif op == 3:
                if self.normal or self.critical:
                    prefer_normal = self.normal_capacity > 0 and self.streak >= self.burst and self.normal
                    critical = bool(self.critical and not prefer_normal)
                    id_ = (self.critical if critical else self.normal).popleft()
                    outcome = 1
                    if critical and self.normal_capacity:
                        self.streak = min(self.streak + 1, self.burst)
                    elif self.normal_capacity and self.normal and self.critical:
                        self.streak = max(0, self.burst - 1)
                    else:
                        self.streak = 0
                if not self.normal and not self.critical:
                    self.streak = 0
            elif op == 6:
                self.normal.clear()
                self.critical.clear()
                self.streak = 0
            else:
                assert op in (4, 5)
        n, c = len(self.normal), len(self.critical)
        an, ac = self.allowed()
        return struct.pack("<8s11Q", REPLY, op, outcome, id_, n, c, n + c,
                           self.normal_capacity - n, self.reserve - c,
                           self.total - n - c, an, ac)


def public_scenarios():
    """Deterministic operation histories, including real reuse after CLOSE."""
    rng = random.Random(0x4D303520261116)
    rows = []
    for total in range(9):
        for reserve in [*range(11), U64]:
            ops = [(0, total, reserve), (3, 0, 0), (4, 0, 0), (5, 0, 0)]
            # Saturation, global cross-class duplicates, ID zero/MAX and drain.
            for class_ in (1, 2):
                for id_ in [0, U64, *range(1, total + 4), 0, U64]:
                    ops.append((class_, id_, 0))
            ops.extend((3, 0, 0) for _ in range(total + 3))
            for _ in range(192):
                op = rng.choices((1, 2, 3, 4, 5, 6), (31, 31, 27, 4, 4, 3))[0]
                id_ = rng.choice([0, U64, rng.randrange(1, 2 * total + 11)]) if op in (1, 2) else 0
                ops.append((op, id_, 0))
            ops.extend((3, 0, 0) for _ in range(total + 3))
            # Clear a nonempty owner, release it, reuse exactly the same bytes.
            ops.extend([(1, 0, 0), (2, U64, 0), (6, 0, 0), (5, 0, 0),
                        (1, U64, 0), (7, 0, 0), (0, total, 0),
                        (2, 0, 0), (2, U64, 0), (3, 0, 0), (7, 0, 0)])
            rows.append((total, ops))
    # Repeated wraparound without emptying either physical ring.
    for total, reserve in ((7, 3), (9, 2), (11, 0), (11, 11)):
        ops = [(0, total, reserve)]
        ops.extend((1 if i % 2 else 2, i, 0) for i in range(total))
        for i in range(512):
            ops.extend([(3, 0, 0), (1 if i % 3 else 2, 1000 + i, 0)])
            if i % 13 == 0:
                ops.extend([(4, 0, 0), (5, 0, 0)])
        ops.extend((3, 0, 0) for _ in range(total + 1))
        ops.append((7, 0, 0))
        rows.append((total, ops))
    return rows


def short_scenarios():
    alphabet = [(1, 0, 0), (1, U64, 0), (2, 0, 0), (2, U64, 0), (3, 0, 0)]
    return [(total, [(0, total, reserve), *history, (3, 0, 0), (7, 0, 0)])
            for total in range(4) for reserve in range(total + 2)
            for history in itertools.product(alphabet, repeat=3)]


def native_scenarios(native, scenarios, *, fault_library=None, timeout=60):
    request = {"library": str(native.library), "sha256": native.artifact_sha256,
               "scenarios": scenarios, "fault_library": str(fault_library) if fault_library else None}
    environment = dict(os.environ)
    if fault_library:
        environment["LD_PRELOAD"] = str(fault_library)
    observed = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                               "--owner-worker"], input=json.dumps(request),
                              capture_output=True, text=True, timeout=timeout,
                              env=environment, check=False)
    if observed.returncode:
        raise AssertionError(("native owner worker failed", observed.returncode, observed.stderr))
    result = json.loads(observed.stdout)
    if (result["artifact_sha256"] != native.artifact_sha256
            or result["host_compiler_modules_loaded"] != []
            or not result["persistent_context_addresses"]
            or len(result["scenarios"]) != len(scenarios)):
        raise AssertionError("Native artifact, persistent owner, or result identity differs")
    for scenario, records in zip(scenarios, result["scenarios"]):
        if len(scenario["commands"]) != len(records):
            raise AssertionError("Incomplete native operation sequence")
        for sent, record in zip(scenario["commands"], records):
            if record["input"] != sent["input"] or record["abi_status"] != 0:
                raise AssertionError("Native call altered input or violated borrowed ABI")
    return result


# Test-only Linux/glibc fault injector. The wrapper alters only whether calloc
# succeeds during a call to the unchanged native f0. It implements no queue,
# policy, ID membership, admission, output, context mutation or success path.
FAULT_SOURCE = r'''
#include <stddef.h>
#include <stdint.h>
extern void *__libc_calloc(size_t, size_t);
static _Thread_local int deny_alloc;
static _Thread_local uint64_t denied;
void *calloc(size_t n, size_t size) {
    if (deny_alloc) { denied++; return NULL; }
    return __libc_calloc(n, size);
}
typedef uint64_t (*entry)(const void *, uint64_t, void *, uint64_t, void *, uint64_t);
uint64_t hia_fault_invoke(entry f, const void *in, uint64_t ni, void *out,
                        uint64_t no, void *ctx, uint64_t nc) {
    denied = 0;
    deny_alloc = 1;
    uint64_t result = f(in, ni, out, no, ctx, nc);
    deny_alloc = 0;
    return result;
}
uint64_t hia_fault_denied(void) { return denied; }
'''


class MempoolOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hia.tests.native_support import NativeModule
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))
        cls.native_invocations = 0

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def run_scenarios(self, scenarios, **options):
        result = native_scenarios(self.native, scenarios, **options)
        type(self).native_invocations += sum(len(row["commands"]) for row in scenarios)
        return result["scenarios"]

    def assert_context(self, raw, model, original, *, op):
        extent = 128 + 8 * model.total
        self.assertEqual(raw[extent:], original[extent:])
        if not model.live:
            self.assertEqual(raw[:extent], bytes(extent), "CLOSE must erase the whole owner")
            return
        values = struct.unpack("<8s15Q", raw[:128])
        magic, live, owned, total, reserve, ncap, nh, nn, ch, cn, streak, burst, *reserved = values
        self.assertEqual((magic, live, owned, total, reserve, ncap, nn, cn, streak, burst),
                         (HEADER, 1, extent, model.total, model.reserve, model.normal_capacity,
                          len(model.normal), len(model.critical), model.streak, model.burst))
        self.assertEqual(reserved, [0] * 4)
        for base, capacity, head, count, queue in (
                (128, ncap, nh, nn, model.normal),
                (128 + 8 * ncap, reserve, ch, cn, model.critical)):
            self.assertTrue(0 <= head < capacity if capacity else head == 0)
            self.assertTrue(0 <= count <= capacity)
            if not count:
                self.assertEqual(head, 0)
            data = list(struct.unpack(f"<{capacity}Q", raw[base:base + 8 * capacity]))
            live_indices = [(head + i) % capacity for i in range(count)]
            self.assertEqual([data[i] for i in live_indices], list(queue))
            self.assertTrue(all(value == 0 for i, value in enumerate(data) if i not in live_indices))
        if op == 6:
            self.assertEqual(raw[128:extent], bytes(extent - 128), "CLEAR must erase every queued ID")

    def check_public(self, scenarios, *, rust=None, require_wrap=False):
        observations = []
        wrapped = [False, False]
        for start in range(0, len(scenarios), 64):
            batch = scenarios[start:start + 64]
            sent = [{"initial": context(capacity).hex(),
                     "commands": [command(*op) for op in ops]}
                    for capacity, ops in batch]
            actual = self.run_scenarios(sent)
            for scene, (_, ops), records in zip(sent, batch, actual):
                model = Model()
                original = bytes.fromhex(scene["initial"])
                before = original
                for op, record in zip(ops, records):
                    expected = model.apply(*op)
                    self.assertEqual(record["status"], 0, (op, record))
                    self.assertEqual(bytes.fromhex(record["output"]), expected + OUT_TAIL, op)
                    after = bytes.fromhex(record["context"])
                    self.assert_context(after, model, original, op=op[0])
                    if op[0] == 3:
                        for lane, head_at, count_at in ((0, 48, 56), (1, 64, 72)):
                            before_head = struct.unpack_from("<Q", before, head_at)[0]
                            after_head = struct.unpack_from("<Q", after, head_at)[0]
                            after_count = struct.unpack_from("<Q", after, count_at)[0]
                            wrapped[lane] |= bool(after_count and after_head < before_head)
                    # Read-only queries and duplicate/backpressure are byte-idempotent.
                    outcome = struct.unpack_from("<Q", expected, 16)[0]
                    if op[0] in (4, 5) or op[0] in (1, 2) and outcome in (1, 2):
                        self.assertEqual(after, before, op)
                    observations.append(expected)
                    before = after
        if rust is not None:
            self.assertEqual(observations, rust, "Actual original Rust/public owner histories diverged")
        if require_wrap:
            self.assertEqual(wrapped, [True, True], "Both physical rings must wrap while still nonempty")
        return observations

    def test_stateful_public_sequences_and_wraparound(self):
        scenarios = public_scenarios()
        self.check_public(scenarios, require_wrap=True)

    def test_exhaustive_short_histories_zero_and_max_ids(self):
        self.check_public(short_scenarios())

    def test_invalid_requests_do_not_publish_or_mutate_owner(self):
        total = 5
        prefix = [command(0, total, 2), command(1, 0), command(2, U64)]
        invalid = [(wire(4)[:i], 1, 113, None) for i in range(40)]
        invalid += [(wire(4) + b"x", 1, 113, None), (b"X" + wire(4)[1:], 1, 113, None)]
        invalid += [(wire(op), 1, 113, None) for op in (8, 255, U64)]
        invalid += [(wire(4, 1), 1, 113, None), (wire(1, 0, 1), 1, 113, None),
                    (wire(0, total, 2, 1), 1, 113, None),
                    (wire(4), 2, 95, None), (wire(4), 2, 0, None),
                    (wire(4), 3, 113, 127), (wire(4), 3, 113, 0),
                    (wire(4), 4, 113, 128), (wire(0, 1, 0), 4, 113, None)]
        commands = prefix + [{"input": frame.hex(), "output_size": output,
                              **({"context_size": extent} if extent is not None else {})}
                             for frame, _, output, extent in invalid]
        commands += [command(5), command(7), command(5), command(7)]
        records, = self.run_scenarios([{"initial": context(total).hex(), "commands": commands}])
        stable = records[len(prefix) - 1]["context"]
        for case, record in zip(invalid, records[len(prefix):len(prefix) + len(invalid)]):
            _, status, output_size, _ = case
            self.assertEqual(record["status"], status)
            self.assertEqual(record["context"], stable)
            self.assertEqual(bytes.fromhex(record["output"]), b"\xa5" * output_size)
        self.assertEqual(records[-4]["context"], stable)
        self.assertEqual(records[-3]["status"], 0)
        for record in records[-2:]:
            self.assertEqual(record["status"], 4)
            self.assertEqual(record["context"], records[-3]["context"])
            self.assertEqual(bytes.fromhex(record["output"]), b"\xa5" * 113)
        fresh = [{"initial": context(0).hex(), "commands": [command(0, U64, 0)]},
                 {"initial": context(0).hex(), "commands": [command(4)]}]
        for records, status in zip(self.run_scenarios(fresh), (3, 4)):
            self.assertEqual(records[0]["status"], status)
            self.assertEqual(records[0]["context"], context(0).hex())
            self.assertEqual(bytes.fromhex(records[0]["output"]), b"\xa5" * 113)

    def test_malformed_private_shape_is_refused_without_repair(self):
        observed, = self.run_scenarios([{"initial": context(4).hex(),
                                        "commands": [command(0, 4, 2)]}])
        good = bytes.fromhex(observed[0]["context"])
        damaged = []
        for offset, value in ((0, 0), (8, 0), (8, 2), (16, 0), (16, 161),
                              (24, U64), (32, 5), (40, 3), (48, 2),
                              (48, 1), (56, 3), (64, 2), (64, 1), (72, 3),
                              (80, 5), (88, 0), (88, 5), (96, 1), (120, 1)):
            changed = bytearray(good)
            struct.pack_into("<Q", changed, offset, value)
            damaged.append(bytes(changed))
        scenes = [{"initial": raw.hex(), "commands": [command(5), command(7)]} for raw in damaged]
        for raw, records in zip(damaged, self.run_scenarios(scenes)):
            for record in records:
                self.assertEqual(record["status"], 4)
                self.assertEqual(record["context"], raw.hex())
                self.assertEqual(bytes.fromhex(record["output"]), b"\xa5" * 113)

    def test_real_allocator_failure_is_atomic_and_close_does_not_allocate(self):
        with tempfile.TemporaryDirectory(prefix="trnm-hia-owner-fault-") as tmp:
            c_path, so_path = Path(tmp) / "fault.c", Path(tmp) / "fault.so"
            c_path.write_text(FAULT_SOURCE)
            built = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    "-O2", "-fPIC", "-shared", str(c_path), "-o", str(so_path)],
                                   capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            cmds = [command(0, 5, 2, deny_alloc=True), command(0, 5, 2),
                    command(1, 0), command(2, U64)]
            cmds += [command(op, 1 if op in (1, 2) else 0, deny_alloc=True) for op in range(1, 7)]
            cmds += [command(5, deny_alloc=True, output_size=95),
                     command(7, deny_alloc=True), command(0, 5, 2, deny_alloc=True),
                     command(0, 5, 2), command(7)]
            records, = self.run_scenarios([{"initial": context(5).hex(), "commands": cmds}],
                                          fault_library=so_path)
        before = context(5).hex()
        for index, (sent, record) in enumerate(zip(cmds, records)):
            denial = sent.get("deny_alloc") and index not in (10, 11)
            if denial:
                self.assertEqual(record["status"], 5, (index, record))
                self.assertEqual(record["allocations_denied"], 1, index)
                self.assertEqual(record["context"], before, index)
                self.assertEqual(bytes.fromhex(record["output"]), b"\xa5" * sent["output_size"])
            elif index == 10:
                self.assertEqual(record["status"], 2)
                self.assertEqual(record["allocations_denied"], 0)
                self.assertEqual(record["context"], before)
            else:
                self.assertEqual(record["status"], 0, index)
                self.assertEqual(record["allocations_denied"], 0)
            if index == 11:
                self.assertEqual(bytes.fromhex(record["context"]), bytes(168) + TAIL)
            before = record["context"]

    def test_actual_complete_original_rust_gate_for_every_public_sequence(self):
        scenarios = public_scenarios() + short_scenarios()
        with tempfile.TemporaryDirectory(prefix="trnm-hia-owner-rust-") as tmp:
            library = Path(tmp) / "libtrnm_mempool.rlib"
            executable = Path(tmp) / "original-owner"
            for args in (
                    ["rustc", "--edition=2021", "--crate-type=rlib", "--crate-name", "trnm_mempool",
                     "-O", str(RUST_LIB), "-o", str(library)],
                    ["rustc", "--edition=2021", "-O", str(RUST_REFERENCE), "--extern",
                     "trnm_mempool=" + str(library), "-o", str(executable)]):
                compiled = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                                          timeout=120, check=False)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
            request = "".join(" ".join(str(word) for op in ops for word in op) + "\n"
                              for _, ops in scenarios)
            original = subprocess.run([str(executable)], input=request, capture_output=True,
                                      text=True, timeout=60, check=False)
            self.assertEqual(original.returncode, 0, original.stderr)
            rust = [bytes.fromhex(line) for line in original.stdout.splitlines()]
        self.assertEqual(len(rust), sum(len(ops) for _, ops in scenarios))
        self.assertTrue(all(len(row) == 96 for row in rust))
        self.check_public(scenarios, rust=rust)


def _owner_worker():
    """Allocation, direct ABI calls and observations only; no queue emulation."""
    import ctypes
    import fcntl
    import resource
    request = json.load(sys.stdin)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (55, 55))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "disable core dumps")
    raw = Path(request["library"]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != request["sha256"]:
        raise ValueError("Native owner artifact changed")
    fd = os.memfd_create("trnm-hia-mempool-owner", os.MFD_ALLOW_SEALING)
    try:
        position = 0
        while position < len(raw):
            written = os.write(fd, raw[position:])
            if written <= 0:
                raise OSError("short native artifact capture")
            position += written
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        library = ctypes.CDLL("/proc/self/fd/" + str(fd))
    finally:
        os.close(fd)
    fn = library.f0
    signature = [ctypes.c_void_p, ctypes.c_uint64] * 3
    fn.argtypes, fn.restype = signature, ctypes.c_uint64
    if request["fault_library"]:
        fault = libc.hia_fault_invoke
        fault.argtypes = [ctypes.c_void_p, *signature]
        fault.restype = ctypes.c_uint64
        denied = libc.hia_fault_denied
        denied.argtypes, denied.restype = [], ctypes.c_uint64
    contexts = []
    for scenario in request["scenarios"]:
        initial = bytes.fromhex(scenario["initial"])
        if len(initial) > 1 << 20:
            raise ValueError("Test context exceeds extent bound")
        allocation = ctypes.create_string_buffer(initial, max(1, len(initial)))
        contexts.append((allocation, len(initial), ctypes.addressof(allocation)))
    results = [[] for _ in contexts]
    stable_addresses = True
    # Round-robin deliberately interleaves independent owners. Each allocation
    # is created once and is never rewritten or replaced by host test code.
    longest = max(len(s["commands"]) for s in request["scenarios"])
    for index in range(longest):
        for scenario, (allocation, size, address), records in zip(request["scenarios"], contexts, results):
            if index >= len(scenario["commands"]):
                continue
            sent = scenario["commands"][index]
            inp = bytes.fromhex(sent["input"])
            out_size = sent["output_size"]
            ctx_size = sent.get("context_size", size)
            if not (0 <= out_size <= 1 << 20 and 0 <= ctx_size <= size and len(inp) <= 1 << 20):
                raise ValueError("Test argument extent invalid")
            input_buffer = ctypes.create_string_buffer(inp, max(1, len(inp)))
            output_buffer = ctypes.create_string_buffer(b"\xa5" * out_size, max(1, out_size))
            args = (input_buffer, len(inp), output_buffer, out_size, allocation, ctx_size)
            allocation_denials = 0
            if sent.get("deny_alloc"):
                if not request["fault_library"]:
                    raise ValueError("Fault injection requested without a loaded injector")
                value = fault(ctypes.cast(fn, ctypes.c_void_p), *args)
                allocation_denials = denied()
            else:
                value = fn(*args)
            stable_addresses &= ctypes.addressof(allocation) == address
            records.append({"status": value & 0xffffffff, "abi_status": value >> 32,
                            "input": input_buffer.raw[:len(inp)].hex(),
                            "output": output_buffer.raw[:out_size].hex(),
                            "context": allocation.raw[:size].hex(),
                            "allocations_denied": allocation_denials})
    print(json.dumps({"artifact_sha256": digest, "persistent_context_addresses": stable_addresses,
                      "host_compiler_modules_loaded": [name for name in sys.modules if name.startswith("hepta")],
                      "scenarios": results}, separators=(",", ":")))


if __name__ == "__main__":
    if sys.argv[1:] == ["--owner-worker"]:
        _owner_worker()
    else:
        unittest.main()
