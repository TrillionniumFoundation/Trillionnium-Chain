"""Native checkpoint V2 values; no durable CAS, freshness or store authority.

The original value wire is exactly 672 bytes, with every u64 in big endian.
Its checksum is SHA256(b"trnm.domain.hash.v1" + BE64(38) +
b"trnm.external-node-checkpoint.value.v2" + BE64(640) + prefix640).
This is a different domain/framing from the PoN hash.

The test/native ABI uses CPV2, version 1, operation u8, two zero bytes:
0: decode exact record672 -> record672;
1: construct from fields624 (record offsets16..640) -> record672;
2: predecessor672 + target672 -> target672 if validate_successor_of succeeds;
3: watermark104 -> watermark104 (scope32,journal32,BE64 sequence,checksum32).
Output capacity must cover the result; all later bytes stay unchanged. Only
hashing operations need scratch>=132256. Scratch writes are restricted to
[0,713) and [131136,132256); no failing operation writes output.

Codes1..28 preserve every original error/field identity; ABI-only codes100..103
mean short envelope, bad envelope, insufficient output, insufficient scratch.
The checkpoint-store trait, CAS durability, independent retained frontier and
the consuming host's actual root reconciliation remain separate obligations.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule


SOURCE = Path(__file__).resolve().parents[1] / "src/checkpoint/value_v2.hepta"
MAX_U64 = (1 << 64) - 1
RECORD_SIZE = 672
PREFIX_SIZE = 640
MAGIC = b"TRNMCP02"
SCHEMA = 2
DOMAIN = b"trnm.external-node-checkpoint.value.v2"
FRAME_PREFIX = b"trnm.domain.hash.v1" + struct.pack(">Q", len(DOMAIN)) + DOMAIN + struct.pack(">Q", PREFIX_SIZE)
SCRATCH_MIN = 132256
SCRATCH = b"\xc7" * (SCRATCH_MIN + 31)
OUTPUT = b"\xa5" * (RECORD_SIZE + 19)

# Canonical record layout, independently represented as named fields.
LAYOUT = {
    "scope": (16, 32), "generation": (48, 8), "predecessor": (56, 32),
    "authority_journal": (88, 32), "authority_profile": (120, 32),
    "authority_revision": (152, 8), "authority_state": (160, 32),
    "authority_chain": (192, 32), "host_config": (224, 32),
    "projection_profile": (256, 32), "binding_manifest": (288, 32),
    "committed_head": (320, 32), "recovery_closure": (352, 32),
    "block_id": (384, 32), "height": (416, 8), "state_root": (424, 32),
    "application_generation": (456, 8), "timestamp_ms": (464, 8),
    "effect_journal": (472, 32), "effect_profile": (504, 32),
    "watermark_scope": (536, 32), "watermark_journal": (568, 32),
    "watermark_sequence": (600, 8), "watermark_checksum": (608, 32),
}
ERRORS = {
    1: "WrongLength", 2: "WrongMagic", 3: "UnsupportedSchema",
    4: "effect watermark", 5: "signer watermark", 6: "scope",
    7: "safety journal id", 8: "safety verifier profile",
    9: "safety state record checksum", 10: "safety record chain checksum",
    11: "application host config", 12: "application projection profile",
    13: "application safety binding manifest checksum",
    14: "application committed head row checksum", 15: "application recovery closure checksum",
    16: "signer journal id", 17: "signer profile checksum", 18: "application block id",
    19: "application state root", 20: "generation-zero predecessor",
    21: "successor predecessor", 22: "signer watermark scope",
    23: "signer watermark journal id", 24: "ChecksumMismatch",
    25: "successor scope", 26: "successor generation overflow",
    27: "successor generation", 28: "successor checkpoint checksum",
    100: "EnvelopeLength", 101: "EnvelopeHeader", 102: "OutputCapacity", 103: "ScratchCapacity",
}
REQUIRED = (
    ("scope", 6), ("authority_journal", 7), ("authority_profile", 8),
    ("authority_state", 9), ("authority_chain", 10), ("host_config", 11),
    ("projection_profile", 12), ("binding_manifest", 13), ("committed_head", 14),
    ("recovery_closure", 15), ("effect_journal", 16), ("effect_profile", 17),
    ("block_id", 18), ("state_root", 19),
)


def request(operation, body):
    return b"CPV2\x01" + bytes([operation]) + b"\x00\x00" + body


def digest(prefix):
    assert len(prefix) == PREFIX_SIZE
    return hashlib.sha256(FRAME_PREFIX + prefix).digest()


def set_field(record, name, value, *, rehash=True):
    offset, size = LAYOUT[name]
    data = bytearray(record)
    data[offset:offset + size] = struct.pack(">Q", value) if size == 8 else value
    if rehash:
        data[640:672] = digest(data[:640])
    return bytes(data)


def record(generation=0, predecessor=None, **overrides):
    """Encode named fields without applying any admission or successor policy."""
    values = {
        "scope": b"\x01" * 32, "generation": generation,
        "predecessor": bytes(32) if generation == 0 else b"\x21" * 32,
        "authority_journal": b"\x02" * 32, "authority_profile": b"\x03" * 32,
        "authority_revision": 1, "authority_state": b"\x04" * 32,
        "authority_chain": b"\x05" * 32, "host_config": b"\x06" * 32,
        "projection_profile": b"\x07" * 32, "binding_manifest": b"\x08" * 32,
        "committed_head": b"\x09" * 32, "recovery_closure": b"\x0a" * 32,
        "block_id": b"\x0b" * 32, "height": 1, "state_root": b"\x0c" * 32,
        "application_generation": 1, "timestamp_ms": 100,
        "effect_journal": b"\x0d" * 32, "effect_profile": b"\x0e" * 32,
        "watermark_scope": b"\x01" * 32, "watermark_journal": b"\x0d" * 32,
        "watermark_sequence": 0, "watermark_checksum": b"\x0f" * 32,
    }
    if predecessor is not None:
        values["predecessor"] = predecessor
    values.update(overrides)
    prefix = bytearray(MAGIC + struct.pack(">Q", SCHEMA) + bytes(624))
    for name, value in values.items():
        offset, size = LAYOUT[name]
        encoded = struct.pack(">Q", value) if size == 8 else value
        assert len(encoded) == size
        prefix[offset:offset + size] = encoded
    return bytes(prefix) + digest(prefix)


def decoded(prefix):
    return {name: int.from_bytes(prefix[offset:offset + size], "big") if size == 8
            else prefix[offset:offset + size] for name, (offset, size) in LAYOUT.items()}


def field_error(values):
    for name, code in REQUIRED:
        if values[name] == bytes(32):
            return code
    if values["generation"] == 0 and values["predecessor"] != bytes(32):
        return 20
    if values["generation"] != 0 and values["predecessor"] == bytes(32):
        return 21
    if values["watermark_scope"] != values["scope"]:
        return 22
    if values["watermark_journal"] != values["effect_journal"]:
        return 23
    return 0


def watermark_error(values, code):
    return code if any(values[name] == bytes(32) for name in (
        "watermark_scope", "watermark_journal", "watermark_checksum")) else 0


def decode_error(raw):
    if len(raw) != RECORD_SIZE:
        return 1
    if raw[:8] != MAGIC:
        return 2
    if int.from_bytes(raw[8:16], "big") != SCHEMA:
        return 3
    values = decoded(raw)
    return watermark_error(values, 5) or field_error(values) or (24 if digest(raw[:640]) != raw[640:] else 0)


def reference(raw, output, scratch):
    """Structured Python/stdlib oracle, independent of HIA implementation."""
    if len(raw) < 8:
        return 100, output
    if raw[:5] != b"CPV2\x01" or raw[5] > 3 or raw[6:8] != bytes(2):
        return 101, output
    operation, body = raw[5], raw[8:]
    if len(body) != (672, 624, 1344, 104)[operation]:
        return 1, output
    size = 104 if operation == 3 else 672
    if len(output) < size:
        return 102, output
    if operation != 3 and len(scratch) < SCRATCH_MIN:
        return 103, output
    result = body
    if operation == 3:
        error = 4 if any(body[offset:offset + 32] == bytes(32) for offset in (0, 32, 72)) else 0
    elif operation == 1:
        prefix = MAGIC + struct.pack(">Q", SCHEMA) + body
        values = decoded(prefix)
        error = watermark_error(values, 4) or field_error(values)
        result = prefix + digest(prefix)
    elif operation == 0:
        error = decode_error(body)
    else:
        predecessor, target = body[:672], body[672:]
        error = decode_error(predecessor) or decode_error(target)
        if not error:
            before, after = decoded(predecessor), decoded(target)
            if after["scope"] != before["scope"]:
                error = 25
            elif before["generation"] == MAX_U64:
                error = 26
            elif after["generation"] != before["generation"] + 1:
                error = 27
            elif after["predecessor"] != predecessor[640:672]:
                error = 28
        result = target
    return (error, output) if error else (0, result + output[size:])


def boundary_records():
    values = [record(), record(1), record(MAX_U64)]
    for name, (_, width) in LAYOUT.items():
        if width == 8 and name != "generation":
            values.extend(set_field(record(), name, n) for n in (
                0, 1, 255, 1 << 32, (1 << 63) - 1, 1 << 63, MAX_U64))
    return values


class CheckpointValueNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost")
        cls.addClassCleanup(cls.native.close)

    def compare(self, cases, *, module=None):
        """Cases are (raw, initial output, initial scratch, optional fixed code)."""
        module = self.native if module is None else module
        observations = []
        for start in range(0, len(cases), 24):
            batch = cases[start:start + 24]
            results = module.call_many([("f0", [raw, out, scratch])
                                        for raw, out, scratch, _ in batch], timeout=30)
            self.assertEqual(len(results), len(batch))
            for index, (observed, (raw, out, scratch, fixed)) in enumerate(zip(results, batch), start):
                with self.subTest(case=index, input_sha256=hashlib.sha256(raw).hexdigest()):
                    code, expected_output = reference(raw, out, scratch)
                    if fixed is not None:
                        self.assertEqual(code, fixed, "the independent oracle disagrees with this explicit boundary")
                    observed.require_returned()
                    self.assertEqual(observed.abi_status, 0)
                    self.assertEqual(observed.value, code, ERRORS.get(code, "success"))
                    self.assertEqual(observed.arguments[0], raw)
                    self.assertEqual(observed.arguments[1], expected_output)
                    after_scratch = observed.arguments[2]
                    self.assertEqual(len(after_scratch), len(scratch))
                    self.assertEqual(after_scratch[713:131136], scratch[713:131136])
                    self.assertEqual(after_scratch[132256:], scratch[132256:])
                    if len(raw) >= 8 and raw[5] == 3:
                        self.assertEqual(after_scratch, scratch)
                observations.append(observed)
        return observations

    def requests(self, raws, *, expected=None, output=OUTPUT, scratch=SCRATCH):
        return self.compare([(raw, output, scratch, expected) for raw in raws])

    def test_complete_canonical_value_round_trip_and_all_u64_endpoints(self):
        values = boundary_records()
        self.requests([request(op, value if op == 0 else value[16:640])
                       for value in values for op in (0, 1)], expected=0)
        # A constructor's native output is decoded again in another native process.
        built = self.requests([request(1, record()[16:640])], expected=0)[0].arguments[1][:672]
        self.assertEqual(built, record())
        self.requests([request(0, built)], expected=0)

    def test_original_big_endian_hash_domain_and_complete_checksum(self):
        base = record(0x0102030405060708, timestamp_ms=0x8877665544332211)
        self.assertEqual(base[48:56], bytes.fromhex("0102030405060708"))
        self.assertEqual(base[464:472], bytes.fromhex("8877665544332211"))
        result = self.requests([request(1, base[16:640])], expected=0)[0]
        self.assertEqual(result.arguments[1][:672], base)
        wrong_hashes = (
            hashlib.sha256(base[:640]).digest(),
            hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(DOMAIN)) + DOMAIN
                           + struct.pack("<I", 640) + base[:640]).digest(),
            hashlib.sha256(b"trnm.domain.hash.v1" + struct.pack("<Q", len(DOMAIN)) + DOMAIN
                           + struct.pack("<Q", 640) + base[:640]).digest(),
        )
        self.requests([request(0, base[:640] + bad) for bad in wrong_hashes], expected=24)
        wrong_schema = base[:8] + struct.pack("<Q", 2) + base[16:]
        self.requests([request(0, wrong_schema)], expected=3)

    def test_every_required_field_and_exact_original_field_priority(self):
        base = record()
        cases = []
        for name, code in REQUIRED:
            invalid = set_field(base, name, bytes(32), rehash=False)
            cases.extend([(request(0, invalid), OUTPUT, SCRATCH, code),
                          (request(1, invalid[16:640]), OUTPUT, SCRATCH, code)])
        for index, (left, left_code) in enumerate(REQUIRED):
            for right, _ in REQUIRED[index + 1:]:
                invalid = set_field(set_field(base, left, bytes(32)), right, bytes(32))
                cases.append((request(0, invalid), OUTPUT, SCRATCH, left_code))
        for name in ("watermark_scope", "watermark_journal", "watermark_checksum"):
            invalid = set_field(set_field(base, "scope", bytes(32)), name, bytes(32))
            cases.extend([(request(0, invalid), OUTPUT, SCRATCH, 5),
                          (request(1, invalid[16:640]), OUTPUT, SCRATCH, 4)])
        self.compare(cases)

    def test_generation_watermark_joins_and_decoder_error_order(self):
        base = record()
        values = [
            (set_field(base, "predecessor", b"\x80" * 32), 20),
            (set_field(record(1), "predecessor", bytes(32)), 21),
            (set_field(base, "watermark_scope", b"\x91" * 32), 22),
            (set_field(base, "watermark_journal", b"\x91" * 32), 23),
        ]
        cases = [(request(op, value if op == 0 else value[16:640]), OUTPUT, SCRATCH, code)
                 for value, code in values for op in (0, 1)]
        for value, code in values[:2]:
            value = set_field(value, "watermark_scope", b"\x91" * 32)
            cases.append((request(0, value), OUTPUT, SCRATCH, code))
        invalid = set_field(set_field(base, "watermark_scope", b"\x91" * 32),
                            "watermark_journal", b"\x91" * 32)
        cases.append((request(0, invalid), OUTPUT, SCRATCH, 22))
        bad_watermark = set_field(base, "watermark_checksum", bytes(32), rehash=False)
        cases.extend([
            (request(0, b"BADMAGIC" + bad_watermark[8:]), OUTPUT, SCRATCH, 2),
            (request(0, bad_watermark[:8] + bytes(8) + bad_watermark[16:]), OUTPUT, SCRATCH, 3),
            (request(0, bad_watermark), OUTPUT, SCRATCH, 5),
            (request(0, base[:640] + bytes(32)), OUTPUT, SCRATCH, 24),
        ])
        self.compare(cases)

    def test_watermark_constructor_full_sequence_range_and_no_hash_workspace(self):
        values = [record(watermark_sequence=sequence)[536:640]
                  for sequence in (0, 1, 1 << 32, 1 << 63, MAX_U64)]
        self.requests([request(3, value) for value in values], expected=0,
                      output=b"\xa5" * 119, scratch=b"")
        cases = []
        for offset in (0, 32, 72):
            invalid = bytearray(values[0])
            invalid[offset:offset + 32] = bytes(32)
            cases.append((request(3, invalid), b"\xa5" * 104, b"untouched", 4))
        cases.append((request(3, bytes(104)), b"\xa5" * 104, b"untouched", 4))
        self.compare(cases)

    def test_all_truncations_and_noncanonical_envelope_lengths(self):
        base = record()
        bodies = (base, base[16:640], base + record(1, base[640:]), base[536:640])
        cases = []
        for operation, body in enumerate(bodies):
            cases.extend((request(operation, body[:size]), OUTPUT, b"", 1)
                         for size in range(len(body)))
            cases.extend((request(operation, body + suffix), OUTPUT, b"", 1)
                         for suffix in (b"\0", bytes(32)))
        cases.extend((b"CPV2\x01\0\0\0"[:size], b"", b"", 100) for size in range(8))
        original = request(0, base)
        for offset in range(8):
            invalid = bytearray(original)
            invalid[offset] = 4 if offset == 5 else 255
            cases.append((bytes(invalid), OUTPUT, b"", 101))
        self.compare(cases)

    def test_output_and_scratch_capacity_and_no_failure_output_writes(self):
        base = record()
        cases = []
        for operation, body in ((0, base), (1, base[16:640]), (2, base + record(1, base[640:]))):
            for size in (0, 1, 31, 104, 671):
                cases.append((request(operation, body), b"\xa5" * size, SCRATCH, 102))
            for size in (0, 1, 1088, 132255):
                cases.append((request(operation, body), OUTPUT, b"\xc7" * size, 103))
            cases.append((request(operation, body), b"\xa5" * 672, bytes(SCRATCH_MIN), 0))
        for size in (0, 1, 103):
            cases.append((request(3, base[536:640]), b"\xa5" * size, b"", 102))
        cases.append((request(3, base[536:640]), b"\xa5" * 104, b"", 0))
        self.compare(cases)

    def test_every_record_byte_and_every_checksum_bit(self):
        base = record()
        raws = []
        for index in range(672):
            changed = bytearray(base)
            changed[index] ^= 1
            raws.append(request(0, changed))
        for index in range(640, 672):
            for bit in range(1, 8):
                changed = bytearray(base)
                changed[index] ^= 1 << bit
                raws.append(request(0, changed))
        observations = self.requests(raws)
        self.assertTrue(all(item.value for item in observations))

    def test_successor_exact_generation_scope_checksum_and_unconstrained_other_fields(self):
        first = record()
        second = record(1, first[640:])
        final_predecessor = record(MAX_U64 - 1)
        final_target = record(MAX_U64, final_predecessor[640:])
        pairs = [(first, second, 0), (final_predecessor, final_target, 0)]
        # These values are commitments, not an independent check of local root
        # freshness: this method intentionally does not compare other counters.
        predecessor = record(9, authority_revision=MAX_U64, height=MAX_U64,
                             application_generation=MAX_U64, timestamp_ms=MAX_U64,
                             watermark_sequence=MAX_U64)
        target = record(10, predecessor[640:], authority_revision=0, height=0,
                        application_generation=0, timestamp_ms=0, watermark_sequence=0)
        pairs.append((predecessor, target, 0))
        wrong_scope = record(1, first[640:], scope=b"\x88" * 32, watermark_scope=b"\x88" * 32)
        pairs.extend([
            (first, wrong_scope, 25),
            (record(MAX_U64), first, 26),
            (record(MAX_U64), wrong_scope, 25),
            (first, record(2), 27),
            (first, record(1), 28),
            (first, first, 27),
            (second, first, 27),
        ])
        self.compare([(request(2, before + after), OUTPUT, SCRATCH, code)
                      for before, after, code in pairs])
        bad_first = first[:640] + bytes(32)
        bad_target = b"BADMAGIC" + second[8:]
        self.requests([request(2, bad_first + bad_target)], expected=24)
        self.requests([request(2, first + bad_target)], expected=2)

    def test_deterministic_full_width_fields_and_second_native_compiler(self):
        rng = random.Random(0x43505632)
        cases = []
        for index in range(96):
            values = {name: rng.getrandbits(64) if width == 8 else rng.randbytes(32)
                      for name, (_, width) in LAYOUT.items()}
            generation = (0, 1, 1 << 63, MAX_U64, rng.getrandbits(64))[index % 5]
            values.update(generation=generation,
                          predecessor=bytes(32) if generation == 0 else rng.randbytes(32),
                          watermark_scope=values["scope"], watermark_journal=values["effect_journal"])
            value = record(**values)
            cases.extend([(request(0, value), OUTPUT, SCRATCH, 0),
                          (request(1, value[16:640]), OUTPUT, SCRATCH, 0)])
            if generation < MAX_U64:
                target = record(generation + 1, value[640:], scope=values["scope"],
                                watermark_scope=values["scope"])
                cases.append((request(2, value + target), OUTPUT, SCRATCH, 0))
        self.compare(cases)
        with NativeModule(SOURCE, byte_exports=("f0",), backend="direct") as direct:
            self.compare(cases[:32], module=direct)

    def test_original_rust_crate_differential_if_configured(self):
        configured = os.environ.get("TRNM_HIA_RUST_CHECKPOINT_REFERENCE")
        if not configured:
            self.skipTest("NOT_RUN: TRNM_HIA_RUST_CHECKPOINT_REFERENCE is not configured; "
                          "the original Rust checkpoint value differential has not executed")
        executable = Path(configured).expanduser().resolve(strict=True)
        fingerprint = hashlib.sha256(executable.read_bytes()).hexdigest()
        described = subprocess.run([str(executable), "--describe"], check=True, text=True,
                                   capture_output=True, timeout=10)
        self.assertEqual(described.stdout.strip(), "TRNM-HIA-RUST-CHECKPOINT/1 original-crate value-only")
        self.assertEqual(described.stderr, "")
        values = boundary_records()
        raws = [request(op, value if op == 0 else value[16:640]) for value in values for op in (0, 1)]
        first = record()
        for name, _ in REQUIRED:
            bad = set_field(first, name, bytes(32))
            raws.extend((request(0, bad), request(1, bad[16:640])))
        for name in ("watermark_scope", "watermark_journal", "watermark_checksum"):
            bad = set_field(first, name, bytes(32))
            raws.extend((request(0, bad), request(1, bad[16:640]), request(3, bad[536:640])))
        for before, after in ((first, record(1, first[640:])), (record(MAX_U64), first),
                              (first, record(1)), (first, record(2)), (first, first)):
            raws.append(request(2, before + after))
        for value in values:
            raws.append(request(3, value[536:640]))
        result = subprocess.run([str(executable)], input="".join(
            f"{raw.hex()} {OUTPUT.hex()}\n" for raw in raws), capture_output=True,
            text=True, timeout=30, check=True)
        self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(raws))
        observations = self.requests(raws)
        for line, observed in zip(lines, observations):
            status, encoded = line.split()
            self.assertEqual(observed.value, int(status))
            self.assertEqual(observed.arguments[1], bytes.fromhex(encoded))
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), fingerprint)


if __name__ == "__main__":
    unittest.main()
