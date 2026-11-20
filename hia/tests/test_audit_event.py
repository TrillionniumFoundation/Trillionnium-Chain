"""Actual HIA AuditEvent value operations and the unchanged original crate.

The Python value model and Rust adapter are independent references. Native
results come only from the pinned compiler's emitted artifact. No event carries
signature, ledger, persistence or publication authority.
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

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/audit/event.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-audit-events/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_audit_event_reference.rs"
U128 = (1 << 128) - 1
REQUEST = b"NAEB0001"
RECORD = b"NAER0001"
NAMES = ("source", "event_type", "actor", "object_id", "related_id", "reason", "note")
BITS = {"actor": 0, "object_id": 1, "related_id": 2, "amount": 3, "reason": 4, "note": 5}
CANARY = b"\xa5" * 13
SCRATCH = b"\x6d" * 29


def empty(source="", event_type=""):
    return {name: (source if name == "source" else event_type if name == "event_type" else None)
            for name in (*NAMES, "amount")}


def record(event):
    fields = [(event[name] or "").encode() for name in NAMES]
    mask = sum(1 << bit for name, bit in BITS.items() if event[name] is not None)
    amount = event["amount"] or 0
    total = 96 + sum(map(len, fields))
    return struct.pack("<8s11Q", RECORD, total, mask, amount & ((1 << 64) - 1), amount >> 64,
                       *(len(field) for field in fields)) + b"".join(fields)


def request(op, left, right=b""):
    return struct.pack("<8s3Q", REQUEST, op, len(left), len(right)) + left + right


def public_cases():
    texts = ["", "a", "\0", "\t\r\n", "链/交易", "é", "e\u0301", "\U0010ffff",
             "\u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000", "\u202equoted\"\\"]
    amounts = [0, 1, (1 << 64) - 1, 1 << 64, 1 << 127, U128]
    rows = []
    for source, event_type in itertools.product(texts[:5], repeat=2):
        event = empty(source, event_type)
        rows.append((request(0, source.encode(), event_type.encode()), record(event)))
    for mask in range(64):
        event = empty(texts[mask % len(texts)], texts[(mask + 2) % len(texts)])
        for name, bit in BITS.items():
            if mask & (1 << bit):
                event[name] = amounts[mask % len(amounts)] if name == "amount" else texts[(mask + bit) % len(texts)]
        original = record(event)
        rows += [(request(7, original), original), (request(8, original, original), b"\1")]
        for op, name in enumerate(("actor", "object_id", "related_id", "amount", "reason", "note"), 1):
            for value in ([0, U128] if name == "amount" else ["", texts[(mask + op + 1) % len(texts)]]):
                updated = dict(event, **{name: value})
                payload = value.to_bytes(16, "little") if name == "amount" else value.encode()
                rows.append((request(op, original, payload), record(updated)))
                rows.append((request(8, original, record(updated)), bytes([event == updated])))
        changed = dict(event, source=event["source"] + "!")
        rows.append((request(8, original, record(changed)), b"\0"))
    rng = random.Random(0xA17D17)
    for _ in range(96):
        def random_text():
            return "".join(rng.choice(texts) for _ in range(rng.randrange(8)))
        event = empty(random_text(), random_text())
        for name in BITS:
            if rng.randrange(2):
                event[name] = rng.getrandbits(128) if name == "amount" else random_text()
        old = record(event)
        op = rng.randrange(1, 7)
        name = ("actor", "object_id", "related_id", "amount", "reason", "note")[op - 1]
        value = rng.getrandbits(128) if name == "amount" else random_text()
        arg = value.to_bytes(16, "little") if name == "amount" else value.encode()
        rows.append((request(op, old, arg), record(dict(event, **{name: value}))))
    return rows


class AuditEventNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))
        cls.native_calls = 0

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_cases(self, rows):
        # Rows are (request, result status, published bytes, supplied capacity).
        rows = list(rows)
        for start in range(0, len(rows), 24):
            batch = rows[start:start + 24]
            seen = self.native.call_many([("f0", [raw, b"\xa5" * capacity, SCRATCH])
                                          for raw, _, _, capacity in batch])
            for (raw, status, expected, capacity), observed in zip(batch, seen):
                observed.require_returned()
                self.assertEqual(observed.value, status, raw[:120].hex())
                want = expected + b"\xa5" * (capacity - len(expected)) if status == 0 else b"\xa5" * capacity
                self.assertEqual(observed.arguments, [raw, want, SCRATCH])
                type(self).native_calls += 1

    def test_complete_constructor_builders_clone_and_equality(self):
        self.check_cases((raw, 0, expected, len(expected) + len(CANARY)) for raw, expected in public_cases())

    def test_native_output_is_the_next_value_and_input_is_unchanged(self):
        event = empty("settlement-vault", "vault.locked")
        frame = request(0, event["source"].encode(), event["event_type"].encode())
        previous = None
        for op, name, value in [(0, None, None), (1, "actor", "operator"),
                                (2, "object_id", "req-7"), (3, "related_id", "alice"),
                                (4, "amount", 42), (5, "reason", "manual_review"),
                                (6, "note", "eta=123"), (1, "actor", ""),
                                (4, "amount", U128), (7, None, None)]:
            if op:
                payload = b"" if op == 7 else value.to_bytes(16, "little") if op == 4 else value.encode()
                frame = request(op, previous, payload)
                if name:
                    event[name] = value
            expected = record(event)
            got = self.native.call("f0", [frame, b"\xa5" * (len(expected) + 13), SCRATCH]).require_returned()
            self.assertEqual(got.value, 0)
            self.assertEqual(got.arguments, [frame, expected + CANARY, SCRATCH])
            previous = got.arguments[1][:-13]
            type(self).native_calls += 1

    def test_none_is_distinct_from_empty_and_amount_zero(self):
        absent = empty("source", "event")
        rows = []
        for name in BITS:
            present = dict(absent, **{name: 0 if name == "amount" else ""})
            rows.append((request(8, record(absent), record(present)), 0, b"\0", 14))
            rows.append((request(8, record(present), record(absent)), 0, b"\0", 14))
        self.check_cases(rows)

    def test_extent_and_utf8_refusals_never_publish(self):
        base = record(empty("s", "t"))
        good = request(7, base)
        rows = [(good[:i], 1, b"", 128) for i in range(len(good)) if i < 32]
        rows += [(request(9, base), 1, b"", 128), (good + b"x", 1, b"", 128),
                 (request(4, base, bytes(15)), 1, b"", 128),
                 (request(7, base, b"x"), 1, b"", 128)]
        for position in (0, 8, 16):
            bad = bytearray(base)
            bad[position] ^= 128
            rows.append((request(7, bad), 2, b"", 256))
        for position in (24, 32, 56, 64, 72, 80, 88):
            bad = bytearray(base)
            bad[position] = 1
            rows.append((request(7, bad), 2, b"", 256))
        for length in (0, 1, 95, len(base) - 1):
            rows.append((request(7, base[:length]), 2, b"", 256))
        for position in (40, 48, 56, 64, 72, 80, 88):
            bad = bytearray(base)
            struct.pack_into("<Q", bad, position, (1 << 64) - 1)
            rows.append((request(7, bad), 2, b"", 256))
        for byte in range(128, 256):
            rows.append((request(0, bytes([byte]), b"t"), 3, b"", 256))
            rows.append((request(1, base, bytes([byte])), 3, b"", 256))
        invalid = [b"\xc0\x80", b"\xc1\xbf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
                   b"\xf5\x80\x80\x80", b"\xe0\x80\x80", b"\xf0\x80\x80\x80",
                   b"\xc2", b"\xe0\xa0", b"\xf0\x90\x80"]
        for raw in invalid:
            rows.append((request(0, b"s", raw), 3, b"", 256))
            bad = bytearray(record(empty("x" * len(raw), "")))
            bad[96:] = raw
            rows.append((request(7, bad), 3, b"", 256))
        for raw, expected in public_cases()[::137]:
            rows.append((raw, 4, b"", max(0, len(expected) - 1)))
        self.check_cases(rows)

    def test_no_artificial_string_limit_and_all_u128_bits(self):
        event = empty("s" * 131073, "链" * 21846)
        expected = record(event)
        updated = dict(event, note="\0" * 131071, amount=U128)
        amount_only = record(dict(event, amount=U128))
        self.check_cases([(request(0, event["source"].encode(), event["event_type"].encode()), 0,
                           expected, len(expected) + 13),
                          (request(4, expected, U128.to_bytes(16, "little")), 0,
                           amount_only, len(amount_only) + 13),
                          (request(6, amount_only, updated["note"].encode()), 0,
                           record(updated), len(record(updated)) + 13)])
        rows = []
        small = record(empty())
        for bit in range(128):
            value = 1 << bit
            want = record(dict(empty(), amount=value))
            rows.append((request(4, small, value.to_bytes(16, "little")), 0, want, len(want) + 13))
        self.check_cases(rows)

    def test_utf8_sequences_cannot_cross_declared_field_boundaries(self):
        # The concatenated payload is valid UTF-8, but each declared String
        # must independently be valid. No string can borrow the next one's
        # continuation bytes, including the two constructor arguments.
        points = (0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff)
        splits = [(encoded[:cut], encoded[cut:]) for point in points
                  for encoded in (chr(point).encode(),) for cut in range(1, len(encoded))]
        self.assertEqual(len(splits), 16)
        rows = []
        for left, right in splits:
            rows.append((request(0, left, right), 3, b"", 160))
            for boundary in range(len(NAMES) - 1):
                event = empty()
                for name in BITS:
                    if name != "amount":
                        event[name] = ""
                event[NAMES[boundary]] = "x" * len(left)
                event[NAMES[boundary + 1]] = "y" * len(right)
                raw = bytearray(record(event))
                raw[96:] = left + right
                self.assertEqual(raw[96:].decode(), (left + right).decode())
                rows.append((request(7, raw), 3, b"", len(raw) + 13))
        self.assertEqual(len(rows), 112)
        self.check_cases(rows)

    def test_equality_validates_both_records_before_an_unequal_result(self):
        left = record(empty("left", "kind"))
        different = empty("a much longer right source", "different type")
        base = record(different)
        bad_records = []
        for offset, value in ((0, 0), (8, 0), (8, len(base) + 1), (16, 64),
                              (24, 1), (32, 1)):
            bad = bytearray(base)
            struct.pack_into("<Q", bad, offset, value)
            bad_records.append((bytes(bad), 2))
        for offset in (40, 48, 56, 64, 72, 80, 88):
            bad = bytearray(base)
            struct.pack_into("<Q", bad, offset, (1 << 64) - 1)
            bad_records.append((bytes(bad), 2))
        bad_records.append((base[:95], 2))
        for name, bit in BITS.items():
            if name == "amount":
                continue
            bad = bytearray(record(dict(different, **{name: "x"})))
            mask = struct.unpack_from("<Q", bad, 16)[0]
            struct.pack_into("<Q", bad, 16, mask & ~(1 << bit))
            bad_records.append((bytes(bad), 2))
        bad = bytearray(record(empty("x", "different right type")))
        bad[96] = 0xff
        bad_records.append((bytes(bad), 3))
        self.assertEqual(len(bad_records), 20)
        rows = []
        for malformed, status in bad_records:
            self.assertNotEqual(len(left), len(malformed))
            rows += [(request(8, left, malformed), status, b"", 14),
                     (request(8, malformed, left), status, b"", 14)]
        self.check_cases(rows)

    def test_outer_u64_fields_refuse_without_overflow_or_publication(self):
        base = request(7, record(empty("source", "type")))
        large = ((1 << 64) - 1, (1 << 64) - 32, 1 << 63)
        rows = []
        for offset in (8, 16, 24):
            for value in large:
                bad = bytearray(base)
                struct.pack_into("<Q", bad, offset, value)
                rows.append((bytes(bad), 1, b"", 160))
        for left, right in itertools.product(large, repeat=2):
            bad = bytearray(base)
            struct.pack_into("<2Q", bad, 16, left, right)
            rows.append((bytes(bad), 1, b"", 160))
        self.assertEqual(len(rows), 18)
        self.check_cases(rows)

    def test_equality_observes_each_amount_bit_in_both_directions(self):
        event = dict(empty("source", "amount event"), actor="actor", amount=0,
                     object_id="object", related_id="related", reason="reason", note="note")
        zero = record(event)
        rows = []
        for bit in range(128):
            changed = record(dict(event, amount=1 << bit))
            rows += [(request(8, zero, changed), 0, b"\0", 14),
                     (request(8, changed, zero), 0, b"\0", 14)]
        self.assertEqual(len(rows), 256)
        self.check_cases(rows)

    def test_builder_growth_and_empty_values_preserve_all_following_fields(self):
        event = dict(empty("source \u94fe", "builder event"), actor="actor before",
                     object_id="object before", related_id="related before",
                     amount=U128 // 3, reason="reason before", note="tail\0must survive")
        original = record(event)
        strings = ("", "x", "\u94fe\0", "\U0010ffff", "z" * 4097, "\u00e9" * 33)
        amounts = (0, 1, (1 << 64) - 1, 1 << 64, 1 << 127, U128)
        rows = []
        for op, name in enumerate(("actor", "object_id", "related_id", "amount", "reason", "note"), 1):
            for value in (amounts if name == "amount" else strings):
                payload = value.to_bytes(16, "little") if name == "amount" else value.encode()
                expected = record(dict(event, **{name: value}))
                for capacity in (len(expected), len(expected) + 13):
                    rows.append((request(op, original, payload), 0, expected, capacity))
        self.assertEqual(len(rows), 72)
        self.check_cases(rows)

    def test_actual_unchanged_original_crate_and_all_original_unit_tests(self):
        rows = public_cases()
        with tempfile.TemporaryDirectory(prefix="trnm-hia-audit-original-") as directory:
            directory = Path(directory)
            rlib, original, tests = (directory / name for name in ("libtrnm_audit_events.rlib", "original", "tests"))
            commands = [["rustc", "--edition=2021", "--crate-type=rlib", "--crate-name", "trnm_audit_events",
                         "-O", str(ORIGINAL), "-o", str(rlib)],
                        ["rustc", "--edition=2021", "-O", str(ADAPTER), "--extern",
                         "trnm_audit_events=" + str(rlib), "-o", str(original)],
                        ["rustc", "--edition=2021", "--test", str(ORIGINAL), "-o", str(tests)],
                        [str(tests), "--test-threads=1"]]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            wire = "".join(raw.hex() + "\n" for raw, _ in rows)
            result = subprocess.run([str(original)], input=wire, capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            rust = [bytes.fromhex(line) for line in result.stdout.splitlines()]
        self.assertEqual(rust, [expected for _, expected in rows])
        self.check_cases((raw, 0, expected, len(expected) + 13) for (raw, _), expected in zip(rows, rust))


if __name__ == "__main__":
    unittest.main()
