#!/usr/bin/env python3
"""Independent public-byte controls and an explicitly hypothetical cost screen.

No STARK verification, guest execution, proving or quantum attack takes place.
Synthetic second leaves below exercise parsing/order ONLY and have no receipt.
Passing this file is not evidence that the Rust code compiles or that composition
works. It cannot close a proof-benefit, consensus, quantum or WAN gate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence/pon-w1-complete-succinct-20261028/full-proof"
IMAGE = (4203990569, 1706128024, 889896351, 2751765305,
         3434005897, 1411617246, 870515685, 3215144349)
LEAF_DOMAIN = b"TRNM-W1-ZK-JOURNAL1\0"
INPUT_DOMAIN = b"TRNM-W1-BATCH-INPUT1\0"
BATCH_DOMAIN = b"TRNM-W1-BATCH-JOURNAL1\0"
HEADER_BYTES, JOURNAL_BYTES, MAX_LEAVES = 318, 16818, 64
ENTRY_BYTES = HEADER_BYTES + JOURNAL_BYTES
INPUT_PREFIX = len(INPUT_DOMAIN) + 4
BATCH_PREFIX = len(BATCH_DOMAIN) + 32 + 4


def require(value: bool, label: str) -> None:
    if not value:
        raise ValueError(label)


def pon_hash(tag: bytes, *parts: bytes) -> bytes:
    value = b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
    value += b"".join(struct.pack("<I", len(part)) + part for part in parts)
    return hashlib.sha256(value).digest()


def identity(header: bytes, journal: bytes) -> bytes:
    require(len(header) == HEADER_BYTES and header[:6] == b"PNH1\1\0", "header")
    require(len(journal) == JOURNAL_BYTES and journal.startswith(LEAF_DOMAIN), "leaf")
    offset = len(LEAF_DOMAIN) + HEADER_BYTES
    require(journal[len(LEAF_DOMAIN):offset] == header, "expected header")
    trace, ticket, carried = (journal[offset + n:offset + n + 32] for n in (0, 32, 64))
    target = header[118:150]
    require(target != bytes(32) and ticket <= target, "target")
    require(ticket == pon_hash(b"ticket", pon_hash(b"challenge", header), trace), "ticket")
    calculated = pon_hash(b"block", header, trace)
    require(carried == calculated, "original work ID")
    require(all(value[0] < 4294967291 for value in struct.iter_unpack("<I", journal[offset + 96:])), "range")
    return calculated


def checked(leaves: list[tuple[bytes, bytes]]) -> list[bytes]:
    require(1 <= len(leaves) <= MAX_LEAVES, "count")
    ids = [identity(header, journal) for header, journal in leaves]
    require(len(ids) == len(set(ids)), "duplicate original work")
    return ids


def encode_input(leaves: list[tuple[bytes, bytes]]) -> bytes:
    checked(leaves)
    return INPUT_DOMAIN + struct.pack("<I", len(leaves)) + b"".join(h + j for h, j in leaves)


def decode_input(value: bytes) -> list[tuple[bytes, bytes]]:
    require(INPUT_PREFIX <= len(value) <= INPUT_PREFIX + MAX_LEAVES * ENTRY_BYTES, "input length")
    require(value.startswith(INPUT_DOMAIN), "input domain")
    count, = struct.unpack_from("<I", value, len(INPUT_DOMAIN))
    require(1 <= count <= MAX_LEAVES, "input count")
    require(len(value) == INPUT_PREFIX + count * ENTRY_BYTES, "exact input")
    leaves = [(value[start:start + HEADER_BYTES], value[start + HEADER_BYTES:start + ENTRY_BYTES])
              for start in range(INPUT_PREFIX, len(value), ENTRY_BYTES)]
    checked(leaves)
    return leaves


def batch(leaves: list[tuple[bytes, bytes]]) -> bytes:
    checked(leaves)
    return (BATCH_DOMAIN + struct.pack("<8I", *IMAGE) + struct.pack("<I", len(leaves))
            + b"".join(journal for _, journal in leaves))


def decode_batch(headers: list[bytes], value: bytes) -> list[bytes]:
    require(BATCH_PREFIX <= len(value) <= BATCH_PREFIX + MAX_LEAVES * JOURNAL_BYTES, "batch length")
    require(value.startswith(BATCH_DOMAIN), "batch domain")
    require(value[len(BATCH_DOMAIN):len(BATCH_DOMAIN) + 32] == struct.pack("<8I", *IMAGE), "leaf image")
    count, = struct.unpack_from("<I", value, BATCH_PREFIX - 4)
    require(1 <= count <= MAX_LEAVES and len(headers) == count, "batch count")
    require(len(value) == BATCH_PREFIX + count * JOURNAL_BYTES, "exact batch")
    leaves = list(zip(headers, [value[start:start + JOURNAL_BYTES]
                              for start in range(BATCH_PREFIX, len(value), JOURNAL_BYTES)]))
    return checked(leaves)


def synthetic_public_leaf(header: bytes, journal: bytes, nonce: int) -> tuple[bytes, bytes]:
    """Public parser fixture ONLY. Its apparent identity has NO W1 receipt."""
    header = header[:310] + struct.pack("<Q", nonce)
    offset = len(LEAF_DOMAIN) + HEADER_BYTES
    trace = journal[offset:offset + 32]
    ticket = pon_hash(b"ticket", pon_hash(b"challenge", header), trace)
    return header, (LEAF_DOMAIN + header + trace + ticket + pon_hash(b"block", header, trace)
                    + journal[offset + 96:])


class ContractControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (EVIDENCE / "header.bin").read_bytes()
        cls.journal = (EVIDENCE / "expected-journal.bin").read_bytes()
        cls.leaf = (cls.header, cls.journal)

    def test_original_identity_is_fixed(self) -> None:
        self.assertEqual(identity(*self.leaf).hex(), "ccf544056c6df13a5ab4e6c021e587ff0008d92388270e64f72a6e2168a326cd")

    def test_exact_full_public_bytes_roundtrip(self) -> None:
        self.assertEqual(decode_input(encode_input([self.leaf])), [self.leaf])
        value = batch([self.leaf])
        self.assertEqual(value[BATCH_PREFIX:], self.journal)
        self.assertEqual(decode_batch([self.header], value), [identity(*self.leaf)])

    def test_same_receipt_cannot_supply_multiple_work(self) -> None:
        for n in (2, 8, 32, 64):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                batch([self.leaf] * n)

    def test_changed_product_does_not_create_a_new_ticket(self) -> None:
        changed = bytearray(self.journal)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "duplicate"):
            batch([self.leaf, (self.header, bytes(changed))])

    def test_oversized_zero_and_omitted_count(self) -> None:
        for n in (0, 2, 65, 2**32 - 1):
            original = encode_input([self.leaf])
            value = original[:len(INPUT_DOMAIN)] + struct.pack("<I", n) + original[INPUT_PREFIX:]
            with self.assertRaises(ValueError):
                decode_input(value)
        for leaves in ([], [self.leaf] * 65):
            with self.assertRaises(ValueError):
                batch(leaves)

    def test_exact_input_length_and_domain(self) -> None:
        value = encode_input([self.leaf])
        for bad in (b"", value[:-1], value + b"\0", b"X" + value[1:]):
            with self.assertRaises(ValueError):
                decode_input(bad)

    def test_full_leaf_bindings(self) -> None:
        offset = len(LEAF_DOMAIN) + HEADER_BYTES
        for index in (0, len(LEAF_DOMAIN), offset, offset + 32, offset + 64):
            bad = bytearray(self.journal)
            bad[index] ^= 1
            with self.assertRaises(ValueError):
                identity(self.header, bytes(bad))

    def test_zero_target_and_noncanonical_product(self) -> None:
        offset = len(LEAF_DOMAIN) + HEADER_BYTES
        bad = bytearray(self.journal)
        bad[offset + 96:offset + 100] = struct.pack("<I", 4294967291)
        with self.assertRaisesRegex(ValueError, "range"):
            identity(self.header, bytes(bad))
        header = self.header[:118] + bytes(32) + self.header[150:]
        bad = LEAF_DOMAIN + header + self.journal[offset:]
        with self.assertRaisesRegex(ValueError, "target"):
            identity(header, bad)

    def test_batch_domain_image_count_and_trailing_bytes(self) -> None:
        value = batch([self.leaf])
        for index in (0, len(BATCH_DOMAIN), BATCH_PREFIX - 4):
            bad = bytearray(value)
            bad[index] ^= 1
            with self.assertRaises(ValueError):
                decode_batch([self.header], bytes(bad))
        with self.assertRaises(ValueError):
            decode_batch([self.header], value + b"\0")

    def test_ordered_public_headers_using_unproven_control(self) -> None:
        other = synthetic_public_leaf(*self.leaf, nonce=10001)
        value = batch([self.leaf, other])
        self.assertEqual(len(decode_batch([self.header, other[0]], value)), 2)
        with self.assertRaisesRegex(ValueError, "expected header"):
            decode_batch([other[0], self.header], value)
        # This is an order/parser positive, explicitly NOT two proven works.

    def test_full_cap_using_unproven_public_controls(self) -> None:
        leaves = [synthetic_public_leaf(*self.leaf, nonce=20000 + n) for n in range(MAX_LEAVES)]
        self.assertEqual(len(decode_input(encode_input(leaves))), MAX_LEAVES)
        self.assertEqual(len(decode_batch([leaf[0] for leaf in leaves], batch(leaves))), MAX_LEAVES)

    def test_source_pins_and_no_claim_only_api(self) -> None:
        source = (HERE / "statement/src/lib.rs").read_text()
        match = re.search(r"FROZEN_LEAF_IMAGE_ID: \[u32; 8\] = \[([^]]+)\]", source)
        self.assertIsNotNone(match)
        self.assertEqual(tuple(map(int, re.findall(r"\d+", match.group(1)))), IMAGE)
        guest = (HERE / "methods/guest/src/main.rs").read_text()
        self.assertIn("env::verify(FROZEN_LEAF_IMAGE_ID, leaf.journal)", guest)
        self.assertIn("input.read(&mut trailing)", guest)
        self.assertIn("builder.finish()", guest)
        host = (HERE / "host/src/main.rs").read_text()
        self.assertIn("builder.add_assumption(leaf.receipt.clone())", host)
        self.assertRegex(host, r"receipt\s*\.verify\(FROZEN_LEAF_IMAGE_ID\)")
        self.assertRegex(host, r"receipt\s*\.verify\(TRNM_W1_BATCH_GUEST_ID\)")
        for forbidden in ("ReceiptClaim::", "default_prover(", "new_sub_process_compat(", "version_override:"):
            self.assertNotIn(forbidden, host)
        self.assertLess(host.index('"succinct wire tag required"'), host.index(".deserialize(bytes)"))
        for relative in ("host/Cargo.toml", "methods/guest/Cargo.toml"):
            dependency = tomllib.loads((HERE / relative).read_text())["dependencies"]["risc0-zkvm"]
            self.assertEqual(dependency["version"], "=3.0.6")
            self.assertIn("disable-dev-mode", dependency["features"])


def arithmetic_screen() -> dict:
    # THESE ARE HISTORICAL ONE-LEAF COSTS, NOT MEASURED AGGREGATION COSTS.
    native_ns = 554392.5
    old_final_ns = 16660953
    old_receipt_bytes = 256886
    fixed_bytes = old_receipt_bytes - JOURNAL_BYTES
    rows = [{
        "distinct_work_hypothesis": n,
        "historical_native_sum_ns": n * native_ns,
        "assumed_final_decode_verify_ns": old_final_ns,
        "assumed_batch_receipt_bytes": fixed_bytes + BATCH_PREFIX + n * JOURNAL_BYTES,
        "original_witness_bytes": n * 49188,
        "cpu_screen_only": old_final_ns < n * native_ns,
        "bytes_screen_only": fixed_bytes + BATCH_PREFIX + n * JOURNAL_BYTES < n * 49188,
    } for n in range(1, MAX_LEAVES + 1)]
    return {
        "schema": "TRNM-W1-BATCH-ARITHMETIC-SCREEN1",
        "measured_unique_complete_leaf_receipts_available": 1,
        "aggregation_proved": False,
        "aggregation_cost_measured": False,
        "constant_final_cost_assumed_not_established": True,
        "first_cpu_screen_count": next(row["distinct_work_hypothesis"] for row in rows if row["cpu_screen_only"]),
        "first_bytes_screen_count": next(row["distinct_work_hypothesis"] for row in rows if row["bytes_screen_only"]),
        "selected_rows": [row for row in rows if row["distinct_work_hypothesis"] in (1, 8, 31, 32, 64)],
        "native_extra_parent_task_window_m06_authorization_cost_removed": False,
        "benefit_gate": "OPEN_FAIL_CURRENT_SINGLE_PROOF",
        "production_activation": False,
    }


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractControls))
    report = {"schema": "TRNM-W1-BATCH-PUBLIC-CONTROLS1", "tests": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "rust_compiled": False, "guest_executed": False,
              "receipt_verification_executed": False, "prover_executed": False,
              "synthetic_public_leaves_have_no_proof": True,
              "screen": arithmetic_screen()}
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
