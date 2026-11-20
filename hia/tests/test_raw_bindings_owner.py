"""Persistent native exact digest/body binding owner used by Node M05 preview.

The original remove-before-body-mismatch behavior is intentional. It is checked
against the exact original Rust method bodies, not replaced with an atomic-error
model. Private ABI/capacity refusals remain separate and never mutate state.
"""
from __future__ import annotations

import hashlib
import itertools
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_mempool_owner import native_scenarios

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/mempool/raw_bindings_owner.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-pon-node/src/store/mempool.rs"
NODE_LIB = ROOT / "trillionnium/crates/trnm-pon-node/src/lib.rs"
REFERENCE = ROOT / "hia/tests/rust_raw_bindings_reference.rs"
U64 = (1 << 64) - 1
ZERO = bytes(32)
MAX_DIGEST = b"\xff" * 32
TAIL = b"\x69" * 19
OUT_SIZE = 57


def wire(op, a=0, b=0, digest=ZERO, body=b""):
    assert len(digest) == 32
    return struct.pack("<8s3Q32s", b"NBRV0001", op, a, b, digest) + body


def new(capacity, maximum):
    return (0, capacity, maximum, ZERO, b"")


def insert(digest, body):
    return (1, len(body), 0, digest, body)


def consume(digest, body):
    return (2, len(body), 0, digest, body)


def control(op):
    return (op, 0, 0, ZERO, b"")


def extent(capacity, maximum):
    return 128 + capacity * (48 + maximum)


def context(capacity, maximum):
    return bytes(extent(capacity, maximum)) + TAIL


class Model:
    def __init__(self):
        self.live = False
        self.bindings = {}

    def apply(self, op, a, b, digest, body):
        outcome = 0
        if op == 0:
            assert not self.live
            self.live = True
            self.capacity, self.maximum = a, b
            self.bindings.clear()
        elif op == 5:
            assert self.live
            self.live = False
            self.bindings.clear()
        else:
            assert self.live
            if op == 1:
                if digest in self.bindings:
                    outcome = 1
                elif len(self.bindings) >= self.capacity:
                    outcome = 2
                elif len(body) > self.maximum:
                    return 5, b"\xa5" * OUT_SIZE
                else:
                    self.bindings[digest] = body
            elif op == 2:
                if digest not in self.bindings:
                    outcome = 3
                else:
                    previous = self.bindings.pop(digest)
                    outcome = 0 if previous == body else 3
            elif op == 4:
                self.bindings.clear()
            else:
                assert op == 3
        count = len(self.bindings)
        return 0, struct.pack("<8s4Q", b"NBRR0001", op, outcome, count, count == 0) + b"\xa5" * 17


def public_scenarios():
    rng = random.Random(0x52415720261116)
    scenes = []
    configs = [(capacity, maximum) for capacity in range(8)
               for maximum in (0, 1, 7, 31, 32, 33, 127, 2048)]
    for capacity, maximum in configs:
        body_a = bytes([0, 255, 128, 1])[:maximum]
        body_b = b"z" * min(maximum, 11)
        ops = [new(capacity, maximum), control(3), insert(ZERO, body_a),
               insert(ZERO, body_b), insert(MAX_DIGEST, body_b),
               consume(ZERO, body_a + b"x"), control(3), consume(ZERO, body_a),
               insert(ZERO, body_b), consume(MAX_DIGEST, body_b)]
        candidates = [ZERO, MAX_DIGEST] + [hashlib.sha256(bytes([i])).digest() for i in range(7)]
        for _ in range(96):
            op = rng.choices((1, 2, 3, 4), (48, 42, 7, 3))[0]
            key = rng.choice(candidates)
            if op in (1, 2):
                size = rng.choice((0, min(maximum, 1), min(maximum, 11), maximum))
                body = bytes(rng.randrange(256) for _ in range(size))
                ops.append(insert(key, body) if op == 1 else consume(key, body))
            else:
                ops.append(control(op))
        ops += [control(4), insert(ZERO, body_a), consume(ZERO, body_a), control(3),
                control(5), new(capacity, maximum), insert(MAX_DIGEST, body_b), control(5)]
        scenes.append((capacity, maximum, ops))
    # Every physical slot is used and freed in a different order; zero digest
    # and zero length do not act as an empty-slot sentinel.
    for capacity, maximum in ((9, 33), (32, 7), (256, 1)):
        keys = [i.to_bytes(32, "little") for i in range(capacity)]
        bodies = [bytes([i % 256]) * maximum for i in range(capacity)]
        ops = [new(capacity, maximum)] + [insert(k, v) for k, v in zip(keys, bodies)]
        ops += [insert(MAX_DIGEST, b"over capacity"), insert(keys[-1], b"different")]
        ops += [consume(keys[i], bodies[i]) for i in range(capacity - 1, -1, -1)]
        ops += [insert(k, v) for k, v in zip(keys, bodies)]
        ops += [consume(keys[i], bodies[i] + b"x") for i in range(capacity)]
        ops += [control(3), control(5)]
        scenes.append((capacity, maximum, ops))
    # Full Node configured record/body arena bound, with observed physical wipe.
    scenes.append((256, 2048, [new(256, 2048), insert(MAX_DIGEST, bytes(range(256)) * 8),
                                consume(MAX_DIGEST, bytes(range(256)) * 8), control(5)]))
    return scenes


def short_scenarios():
    alphabet = [insert(ZERO, b"a"), insert(MAX_DIGEST, b"b"),
                consume(ZERO, b"a"), consume(ZERO, b"bad"), consume(MAX_DIGEST, b"b"), control(3)]
    return [(capacity, 3, [new(capacity, 3), *history, control(3), control(5)])
            for capacity in range(4) for history in itertools.product(alphabet, repeat=3)]


def byte_scenarios():
    original = bytes(range(256))
    scenes = []
    for position in range(256):
        changed = bytearray(original)
        changed[position] ^= 0xff
        ops = [new(2, 256), insert(ZERO, original), insert(MAX_DIGEST, b"survivor"),
               consume(ZERO, bytes(changed)), consume(ZERO, original), control(3),
               consume(MAX_DIGEST, b"survivor"), insert(ZERO, original),
               consume(ZERO, original), control(5)]
        scenes.append((2, 256, ops))
    for position in range(32):
        key = bytearray(ZERO)
        key[position] = 1
        ops = [new(2, 0), insert(ZERO, b""), insert(bytes(key), b""), consume(ZERO, b""),
               control(3), consume(bytes(key), b""), control(5)]
        scenes.append((2, 0, ops))
    return scenes


def original_source():
    raw = ORIGINAL.read_bytes()
    start = raw.index(b"struct RawBindings<'a> {")
    end = raw.index(b"/// Real M05 metadata and strict M06", start)
    body = raw[start:end]
    node = NODE_LIB.read_bytes()
    ensure_start = node.index(b"pub(crate) fn ensure(ok: bool, message: &str) -> Result<()> {")
    ensure_end = node.index(b"\npub fn digest", ensure_start)
    ensure = node[ensure_start:ensure_end]
    adapter = REFERENCE.read_bytes()
    for marker, original in ((b"// __ORIGINAL_ENSURE__", ensure),
                             (b"// __ORIGINAL_RAW_BINDINGS__", body)):
        if adapter.count(marker) != 1:
            raise AssertionError("Original source insertion marker differs")
        adapter = adapter.replace(marker, original)
    return adapter, body, ensure


class RawBindingsOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))
        cls.native_invocations = 0

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def run_scenarios(self, scenes):
        result = native_scenarios(self.native, scenes)
        type(self).native_invocations += sum(len(s["commands"]) for s in scenes)
        return result["scenarios"]

    def assert_context(self, raw, model, before):
        owned = extent(model.capacity, model.maximum)
        self.assertEqual(raw[owned:], before[owned:])
        if not model.live:
            self.assertEqual(raw[:owned], bytes(owned))
            return
        values = struct.unpack("<8s15Q", raw[:128])
        magic, live, size, capacity, maximum, stride, count, *reserved = values
        self.assertEqual((magic, live, size, capacity, maximum, stride, count),
                         (b"NBRC0001", 1, owned, model.capacity, model.maximum,
                          model.maximum + 48, len(model.bindings)))
        self.assertEqual(reserved, [0] * 9)
        records = {}
        for index in range(capacity):
            slot = raw[128 + index * stride:128 + (index + 1) * stride]
            occupied, size = struct.unpack_from("<2Q", slot)
            if occupied:
                self.assertEqual(occupied, 1)
                self.assertLessEqual(size, maximum)
                digest = slot[16:48]
                self.assertNotIn(digest, records)
                records[digest] = slot[48:48 + size]
                self.assertEqual(slot[48 + size:], bytes(maximum - size))
            else:
                self.assertEqual(slot, bytes(stride))
        self.assertEqual(records, model.bindings)

    def check_public(self, scenes, *, rust=None):
        outputs = []
        # Exact full context observations are deliberately bounded per child.
        for start in range(0, len(scenes), 8):
            batch = scenes[start:start + 8]
            sent = [{"initial": context(capacity, maximum).hex(),
                     "commands": [{"input": wire(*op).hex(), "output_size": OUT_SIZE} for op in ops]}
                    for capacity, maximum, ops in batch]
            for scene, (_, _, ops), records in zip(sent, batch, self.run_scenarios(sent)):
                model = Model()
                before = bytes.fromhex(scene["initial"])
                for op, record in zip(ops, records):
                    prior = dict(model.bindings)
                    status, expected = model.apply(*op)
                    self.assertEqual(record["status"], status, op[:3])
                    self.assertEqual(bytes.fromhex(record["output"]), expected, op[:3])
                    after = bytes.fromhex(record["context"])
                    self.assert_context(after, model, before)
                    if status or op[0] == 3 or op[0] in (1, 2) and prior == model.bindings:
                        self.assertEqual(after, before, op[:3])
                    if status == 0:
                        outputs.append(expected[:40])
                    before = after
        if rust is not None:
            self.assertEqual(outputs, rust, "Original RawBindings/native owner behavior differs")
        return outputs

    def test_complete_binding_histories_exact_bytes_and_capacity(self):
        self.check_public(public_scenarios())

    def test_exhaustive_short_histories_including_consumed_mismatch(self):
        self.check_public(short_scenarios())

    def test_every_digest_and_body_byte_affects_exact_binding(self):
        self.check_public(byte_scenarios())

    def test_private_body_bound_preserves_original_duplicate_and_full_priority(self):
        # Oversize fresh storage is a private capacity refusal. It does not
        # mask original duplicate/full outcomes and never alters a known body.
        ops = [new(2, 3), insert(ZERO, b"original too large"), insert(ZERO, b"old"),
               insert(ZERO, b"replacement too large"), insert(MAX_DIGEST, b"two"),
               insert(b"z" * 32, b"fresh over limit"),
               consume(ZERO, b"mismatch larger than storage limit"),
               insert(b"z" * 32, b"fresh over limit"), consume(MAX_DIGEST, b"two"), control(5)]
        self.check_public([(2, 3, ops)])

    def test_dirty_initial_arena_and_zero_capacity_maximum_stride(self):
        initial = bytes(128) + b"\x7d" * (3 * 55) + TAIL
        ops = [new(3, 7), insert(ZERO, b"bytes"), control(4), control(5)]
        scenes = [{"initial": initial.hex(), "commands": [
            {"input": wire(*op).hex(), "output_size": OUT_SIZE} for op in ops]}]
        records, = self.run_scenarios(scenes)
        model = Model()
        before = initial
        for op, record in zip(ops, records):
            status, output = model.apply(*op)
            self.assertEqual(record["status"], status)
            self.assertEqual(bytes.fromhex(record["output"]), output)
            after = bytes.fromhex(record["context"])
            self.assert_context(after, model, before)
            before = after
        self.check_public([(0, U64 - 48, [new(0, U64 - 48), insert(ZERO, b""),
                                          consume(ZERO, b"unknown"), control(3), control(5)])])

    def test_frame_capacity_lifetime_refusals_are_unchanged(self):
        initial = context(3, 7)
        prefix = [new(3, 7), insert(ZERO, b"keep"), insert(MAX_DIGEST, b"same")]
        malformed = [(wire(*control(3))[:i], 1, OUT_SIZE, None) for i in range(64)]
        malformed += [(wire(*control(3)) + b"x", 1, OUT_SIZE, None),
                      (b"X" + wire(*control(3))[1:], 1, OUT_SIZE, None),
                      (wire(6), 1, OUT_SIZE, None), (wire(U64), 1, OUT_SIZE, None),
                      (wire(3, 1), 1, OUT_SIZE, None), (wire(3, 0, 1), 1, OUT_SIZE, None),
                      (wire(3, digest=MAX_DIGEST), 1, OUT_SIZE, None),
                      (wire(1, 9, 0, ZERO, b"short"), 1, OUT_SIZE, None),
                      (wire(2, 4, 1, ZERO, b"keep"), 1, OUT_SIZE, None),
                      (wire(*control(3)), 2, 39, None), (wire(*control(3)), 2, 0, None),
                      (wire(*control(3)), 3, OUT_SIZE, 127),
                      (wire(*control(3)), 4, OUT_SIZE, 128),
                      (wire(*new(3, 7)), 4, OUT_SIZE, None)]
        commands = [{"input": wire(*op).hex(), "output_size": OUT_SIZE} for op in prefix]
        commands += [{"input": frame.hex(), "output_size": output,
                      **({"context_size": n} if n is not None else {})}
                     for frame, _, output, n in malformed]
        commands += [{"input": wire(*control(op)).hex(), "output_size": OUT_SIZE} for op in (5, 3, 5)]
        records, = self.run_scenarios([{"initial": initial.hex(), "commands": commands}])
        stable = records[len(prefix) - 1]["context"]
        for (_, status, output, _), record in zip(malformed, records[len(prefix):]):
            self.assertEqual(record["status"], status)
            self.assertEqual(record["context"], stable)
            self.assertEqual(bytes.fromhex(record["output"]), b"\xa5" * output)
        self.assertEqual(bytes.fromhex(records[-3]["context"]), bytes(len(initial) - len(TAIL)) + TAIL)
        for record in records[-2:]:
            self.assertEqual(record["status"], 4)
            self.assertEqual(record["context"], records[-3]["context"])
            self.assertEqual(bytes.fromhex(record["output"]), b"\xa5" * OUT_SIZE)
        # Multiplication/stride overflow is refused before arithmetic or memory writes.
        scenes = [{"initial": context(0, 0).hex(), "commands": [
            {"input": wire(*new(cap, maximum)).hex(), "output_size": OUT_SIZE}]}
                  for cap, maximum in ((U64, 0), (1, U64), (0, U64), (2, U64 - 48))]
        for records in self.run_scenarios(scenes):
            self.assertEqual(records[0]["status"], 3)
            self.assertEqual(records[0]["context"], context(0, 0).hex())
            self.assertEqual(bytes.fromhex(records[0]["output"]), b"\xa5" * OUT_SIZE)

    def test_invalid_private_shape_refuses_without_mutation(self):
        commands = [{"input": wire(*op).hex(), "output_size": OUT_SIZE}
                    for op in (new(2, 3), insert(ZERO, b"old"), insert(MAX_DIGEST, b"two"))]
        records, = self.run_scenarios([{"initial": context(2, 3).hex(), "commands": commands}])
        good = bytes.fromhex(records[-1]["context"])
        mutations = [(0, 0), (8, 0), (8, 2), (16, 0), (24, U64), (32, U64),
                     (40, U64), (48, 3), (48, 1), (56, 1), (120, 1),
                     (128, 2), (128, U64), (128 + 8, 4),
                     (128 + 51, U64), (128 + 51, 0)]
        scenes = []
        for offset, value in mutations:
            changed = bytearray(good)
            struct.pack_into("<Q", changed, offset, value)
            scenes.append({"initial": changed.hex(), "commands": [
                {"input": wire(*control(3)).hex(), "output_size": OUT_SIZE}]})
        for sent, records in zip(scenes, self.run_scenarios(scenes)):
            self.assertEqual(records[0]["status"], 4)
            self.assertEqual(records[0]["context"], sent["initial"])
            self.assertEqual(bytes.fromhex(records[0]["output"]), b"\xa5" * OUT_SIZE)

    def test_actual_original_rust_raw_bindings_entire_method_bodies(self):
        scenes = public_scenarios() + short_scenarios() + byte_scenarios()
        source, body, ensure = original_source()
        self.assertIn(body, source)
        self.assertIn(ensure, source)
        with tempfile.TemporaryDirectory(prefix="trnm-hia-raw-bindings-rust-") as tmp:
            source_file = Path(tmp) / "original.rs"
            executable = Path(tmp) / "original-bindings"
            source_file.write_bytes(source)
            compiled = subprocess.run(["rustc", "--edition=2021", "-O", str(source_file), "-o", str(executable)],
                                      capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            request = "".join(" ".join(wire(*op).hex() for op in ops) + "\n" for _, _, ops in scenes)
            original = subprocess.run([str(executable)], input=request, capture_output=True,
                                      text=True, timeout=60, check=False)
            self.assertEqual(original.returncode, 0, original.stderr)
            observed = [bytes.fromhex(line) for line in original.stdout.splitlines()]
        self.assertEqual(len(observed), sum(len(ops) for _, _, ops in scenes))
        self.assertTrue(all(len(row) == 40 for row in observed))
        self.check_public(scenes, rust=observed)
