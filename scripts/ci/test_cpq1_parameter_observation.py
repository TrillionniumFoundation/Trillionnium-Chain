#!/usr/bin/env python3
"""Adversarial reader tests using synthetic observations, never native evidence.

Only descriptor bytes come from the pre-existing independent Python oracle.
Public keys/signatures/timings below are deliberately synthetic. A successful
reader verdict proves schema/byte/counter consistency, NOT ML-DSA execution.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import runpy
import struct
import sys
import tempfile
import unittest
from unittest import mock

import check_cpq1_parameter_observation as reader


SCHEMA = "trnm.cpq1-parameter-observation.v1"
OPS = (
    "cpq1_encode_with_existing_signatures", "cpq1_sign_self_verify_and_encode",
    "cpq1_cold_pin_and_verify", "cpq1_hot_verify", "cpq1_late_invalid_last_signature",
    "cpq1_wrong_profile", "cpq1_wrong_purpose", "cpq1_short_wire",
    "cpq1_trailing_byte", "cpq1_message_length_mismatch", "cpq1_shared_budget_exhaustion",
)
COUNTERS = (
    "encoded_frames", "sign_and_self_verify_calls", "verification_api_calls",
    "accepted_authentications", "returned_verified_signatures", "policy_encoding_rejections",
    "policy_size_rejections", "policy_budget_rejections", "signature_arithmetic_rejections",
    "reserved_verification_attempts", "reserved_wire_bytes", "sticky_budget_checks", "input_wire_bytes",
)


def digest(data):
    return hashlib.sha512(data).hexdigest()


def configurations():
    root = Path(__file__).resolve().parents[2]
    oracle = root / "evidence/crypto-profile-20261104/recompute_profile_ids.py"
    original = sys.argv
    try:
        sys.argv = [str(oracle), str(root)]
        with contextlib.redirect_stdout(io.StringIO()):
            reference = runpy.run_path(str(oracle))
    finally:
        sys.argv = original
    return [reference["configuration"](n) for n in (2, 3)], reference["work_digest"]


def foreign_id(configuration):
    at = len(b"TRNM/CryptoProfile/Configuration/v1\0") + 1
    for _ in range(4):
        n, = struct.unpack(">I", configuration[at:at + 4])
        at += 4 + n
    at += 8
    assert configuration[at:at + 32] == b"\1" * 32
    return digest(configuration[:at] + b"\4" * 32 + configuration[at + 32:])


def outcomes(stage, signers, wire):
    out = dict.fromkeys(COUNTERS, 0)
    if stage in (0, 1):
        out["encoded_frames"] = 1
        if stage == 1:
            out["sign_and_self_verify_calls"] = signers
        return out
    out.update(verification_api_calls=1, input_wire_bytes=wire,
               reserved_verification_attempts=signers, reserved_wire_bytes=wire)
    if stage in (2, 3):
        out.update(accepted_authentications=1, returned_verified_signatures=signers)
    elif stage == 4:
        out["signature_arithmetic_rejections"] = 1
    elif stage in (5, 6, 8):
        out["policy_encoding_rejections"] = 1
        if stage == 8:
            out["reserved_wire_bytes"] = out["input_wire_bytes"] = wire + 1
    elif stage in (7, 9):
        out["policy_size_rejections"] = 1
        if stage == 7:
            out["reserved_wire_bytes"] = out["input_wire_bytes"] = 7
    elif stage == 10:
        batches = 64 // signers
        out.update(verification_api_calls=batches + 2,
                   accepted_authentications=1, returned_verified_signatures=signers,
                   policy_encoding_rejections=batches - 1, policy_budget_rejections=2,
                   reserved_verification_attempts=64 + signers,
                   reserved_wire_bytes=(batches + 1) * wire, sticky_budget_checks=1,
                   input_wire_bytes=(batches + 1) * wire + 7)
    return out


def fixture():
    """Independent byte/counter fixture; all signatures and timings are synthetic."""
    descriptors, work_digest = configurations()
    parameters = (("ML-DSA-65", 1952, 3309, 3), ("ML-DSA-87", 2592, 4627, 5))
    profiles = [{"algorithm": algorithm, "crypto_profile_id": digest(raw),
                 "canonical_configuration_bytes": len(raw), "canonical_configuration_hex": raw.hex(),
                 "wrong_network_profile_id": foreign_id(raw)}
                for (algorithm, *_), raw in zip(parameters, descriptors)]
    header = {
        "schema": SCHEMA, "kind": "run", "wire_format": "CPQ1",
        "scope": "actual CPQ1 candidate APIs; local repeated public fixtures only",
        "algorithms": [row[0] for row in parameters], "signer_counts": [1, 2, 4, 8],
        "payload_labels": ["empty", "176", "4096", "maximum"],
        "samples_per_operation_case": 64, "operations": list(OPS),
        "warmup_groups_per_operation_case": 1, "fixture_repeated_each_sample": True,
        "signature_mode": "FIPS204-Pure", "fips_context_hex": "", "signing_variant": "deterministic",
        "seed_fixture": "32 bytes 0x42; last eight bytes replaced by signer index as u64be",
        "payload_fixture": "byte[i] = (i * 29 + 17) mod 256",
        "binding": {"network_hex": "01" * 32, "parameters_hex": "02" * 32,
                    "genesis_hex": "03" * 32, "scope": "WholeSystemCandidate",
                    "protocol_version": 1, "activation_height": 10, "retirement_height_exclusive": 100},
        "envelope": {"purpose": "FinalUse", "purpose_code": 9, "owner_generation": 7,
                     "key_epoch": 3, "sequence": 11, "valid_from_height": 10,
                     "valid_until_height_inclusive": 99},
        "work_configuration_digest": work_digest.hex(), "profiles": profiles,
        "limits": {"signed_message_bytes": 65536, "wire_bytes": 131072, "signers": 8,
                   "reserved_verification_attempts": 64, "reserved_wire_bytes": 8388608,
                   "signed_header_bytes": 207},
        "clock": "std::time::Instant", "quantiles": "nearest-rank; integer mean; raw samples retained",
        "tail_note": "64-sample p99 is the observed maximum, not a production population tail",
        "timing_scope": "inclusive operation, outcome checks and owned temporary drops; fixture key generation and initial signatures outside samples; output IO outside samples",
        "budget_scope": "each independent timing sample and warmup creates a new budget; shared_budget_exhaustion never resets its one budget within a sample",
        "hardware_scope": "single process on caller-recorded host; wall time includes scheduling; CPU, RSS, WAL, WAN and business confirmation are not measured",
        "execution_context": {"arch": "synthetic", "os": "synthetic", "debug_assertions": True, "crate_version": "0.1.0"},
        "caller_run_context_required": True,
        "caller_run_context": "record exact source and diff, binary hash, locked graph, rustc -Vv, cargo -V, target, flags, CPU, memory, kernel, load, command and terminal exit beside this output",
        "frame_is_PNQ_or_NPQ": False, "network_or_business_confirmation_measured": False,
        "production_tail_established": False, "activation_performed": False,
    }
    rows, global_totals = [header], dict.fromkeys(COUNTERS, 0)
    for signers in (1, 2, 4, 8):
        maximum = {1: 65265, 2: 65201, 4: 65073, 8: 64817}[signers]
        for label, payload_bytes in (("empty", 0), ("176", 176), ("4096", 4096), ("maximum", maximum)):
            for (algorithm, pk_bytes, sig_bytes, category), description in zip(parameters, profiles):
                profile_id = bytes.fromhex(description["crypto_profile_id"])
                ordered = []
                for index in range(signers):
                    # Syntactically sized only: this is not an ML-DSA public key derivation.
                    key = bytes([index + 41]) * pk_bytes
                    key_id = hashlib.sha512(b"TRNM/CryptoProfile/Commitment/v1\0" + profile_id
                                            + b"\1" + struct.pack(">Q", len(key)) + key).digest()
                    ordered.append((key_id, index, key))
                ordered.sort()
                body = bytes((i * 29 + 17) % 256 for i in range(payload_bytes))
                message = b"TRNM/CryptoProfile/Envelope/v1\0" + profile_id + work_digest
                message += struct.pack(">HQQQQQH", 9, 7, 3, 11, 10, 99, signers)
                message += b"".join(key_id for key_id, _, _ in ordered) + struct.pack(">I", len(body)) + body
                wire = b"CPQ1" + struct.pack(">I", len(message)) + message
                for _, index, key in ordered:
                    signature = bytes([index + 71]) * sig_bytes
                    wire += struct.pack(">I", pk_bytes) + key + struct.pack(">I", sig_bytes) + signature
                case_id = f"{algorithm}/{signers}/{label}"
                setup = outcomes(3, signers, len(wire))
                setup.update(encoded_frames=1, sign_and_self_verify_calls=signers)
                rows.append({
                    "schema": SCHEMA, "kind": "case", "case_id": case_id,
                    "algorithm": algorithm, "nist_category": category, "signer_count": signers,
                    "payload_label": label, "payload_bytes": payload_bytes, "maximum_legal_payload_bytes": maximum,
                    "crypto_profile_id": profile_id.hex(), "wrong_profile_id": description["wrong_network_profile_id"],
                    "signer_ids": [key_id.hex() for key_id, _, _ in ordered],
                    "signer_seed_indices_in_wire_order": [index for _, index, _ in ordered],
                    "signed_message_bytes": len(message), "cpq1_wire_bytes": len(wire),
                    "signed_metadata_bytes": 207 + 64 * signers, "outer_framing_bytes": 8 + 8 * signers,
                    "public_key_bytes_each": pk_bytes, "signature_bytes_each": sig_bytes,
                    "signed_message_hex": message.hex(), "cpq1_wire_hex": wire.hex(),
                    "signed_message_sha512": digest(message), "cpq1_wire_sha512": digest(wire),
                    "late_invalid_byte_offset": len(wire) - sig_bytes, "late_invalid_xor": 1,
                    "setup_wall_ns": 1234, "setup_outcomes": setup, "current_authorization_refused": True,
                })
                for stage, operation in enumerate(OPS):
                    raw = [(i * 37) % 193 + 25 for i in range(64)]
                    ordered_ns = sorted(raw)
                    expected = outcomes(stage, signers, len(wire))
                    totals = {field: count * 64 for field, count in expected.items()}
                    for field, count in totals.items():
                        global_totals[field] += count
                    rows.append({
                        "schema": SCHEMA, "kind": "measurement", "case_id": case_id,
                        "operation": operation, "samples": 64, "checked_samples": 64, "warmup_groups": 1,
                        "latency_unit": "ns_per_independent_operation_group", "sample_ns": raw,
                        "min_ns": min(raw), "max_ns": max(raw), "mean_ns": sum(raw) // 64,
                        "p50_ns": ordered_ns[31], "p95_ns": ordered_ns[60], "p99_ns": ordered_ns[63],
                        "total_ns": sum(raw), "outcomes_per_sample": expected,
                        "warmup_outcomes": dict(expected), "measured_outcome_totals": totals,
                        "production_p99_ns": None, "performance_acceptance_gate": False,
                    })
    rows.append({"schema": SCHEMA, "kind": "complete", "cases": 32, "measurement_rows": 352,
                 "samples_per_operation_case": 64, "raw_sample_values": 22528,
                 "warmup_groups": 352, "all_expected_outcomes_checked": True,
                 "measured_outcome_totals": global_totals, "production_qualified": False,
                 "activation_performed": False})
    return rows


class Cpq1ObservationReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = fixture()

    def data(self):
        return copy.deepcopy(self.template)

    def refuse(self, records, pattern=None):
        with self.assertRaisesRegex(ValueError, pattern or "."):
            reader.validate(records)

    def test_synthetic_consistency_is_never_native_or_signature_acceptance(self):
        result = reader.validate(self.data())
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["cases"], 32)
        self.assertEqual(result["raw_sample_values_recomputed"], 22528)
        self.assertFalse(result["native_execution_attested"])
        self.assertFalse(result["signature_math_independently_verified"])
        self.assertFalse(result["production_or_activation_claim"])

    def test_independent_maximum_payload_and_full_wire_boundaries(self):
        rows = [row for row in self.template if row["kind"] == "case" and row["payload_label"] == "maximum"]
        self.assertEqual({row["signer_count"]: row["payload_bytes"] for row in rows},
                         {1: 65265, 2: 65201, 4: 65073, 8: 64817})
        self.assertEqual({row["algorithm"]: row["cpq1_wire_bytes"] for row in rows if row["signer_count"] == 8},
                         {"ML-DSA-65": 107696, "ML-DSA-87": 123360})

    def test_missing_completion_or_missing_measurement_refuses(self):
        self.refuse(self.data()[:-1], "completion")
        rows = self.data()
        rows.pop(6)
        self.refuse(rows, "completion")

    def test_duplicate_case_cannot_replace_missing_coverage(self):
        rows = self.data()
        rows[13:25] = copy.deepcopy(rows[1:13])
        self.refuse(rows, "duplicate case")

    def test_wrong_case_stage_or_stage_order_refuses(self):
        for field, value in (("case_id", "ML-DSA-87/8/maximum"), ("operation", OPS[2])):
            rows = self.data()
            rows[2][field] = value
            self.refuse(rows, field)

    def test_raw_population_and_each_recomputed_statistic_refuse_corruption(self):
        rows = self.data()
        rows[2]["sample_ns"].pop()
        self.refuse(rows, "population")
        for field in ("min_ns", "mean_ns", "p50_ns", "p95_ns", "p99_ns", "max_ns", "total_ns"):
            rows = self.data()
            rows[2][field] += 1
            self.refuse(rows, field)

    def test_bad_sample_number_types_and_integer_overflow_refuse(self):
        for value in (True, -1, 1.5, 1 << 64):
            rows = self.data()
            rows[2]["sample_ns"][0] = value
            self.refuse(rows, "unsigned integer")
        rows = self.data()
        rows[2]["sample_ns"] = [(1 << 64) - 1] * 64
        self.refuse(rows, "duration sum")

    def test_boolean_cannot_impersonate_one_checked_sample_or_signer(self):
        for index, field in ((1, "signer_count"), (2, "warmup_groups")):
            rows = self.data()
            rows[index][field] = True
            self.refuse(rows)

    def test_wrong_profile_descriptor_or_id_refuses(self):
        for field in ("crypto_profile_id", "wrong_network_profile_id"):
            rows = self.data()
            rows[0]["profiles"][0][field] = "00" * 64
            self.refuse(rows, "profile")
        rows = self.data()
        text = rows[0]["profiles"][0]["canonical_configuration_hex"]
        rows[0]["profiles"][0]["canonical_configuration_hex"] = "00" + text[2:]
        self.refuse(rows, "configuration digest")

    def test_mutated_signature_wire_without_matching_digest_refuses(self):
        rows = self.data()
        wire = bytearray.fromhex(rows[1]["cpq1_wire_hex"])
        wire[-1] ^= 1
        rows[1]["cpq1_wire_hex"] = wire.hex()
        self.refuse(rows, "wire digest")

    def test_wrong_magic_and_extra_wire_tail_refuse_even_with_recomputed_digest(self):
        for mutate in (lambda wire: b"NPQ6" + wire[4:], lambda wire: wire + b"\0"):
            rows = self.data()
            wire = mutate(bytes.fromhex(rows[1]["cpq1_wire_hex"]))
            rows[1]["cpq1_wire_hex"] = wire.hex()
            rows[1]["cpq1_wire_sha512"] = digest(wire)
            self.refuse(rows)

    def test_corrupted_complete_message_refuses_even_with_recomputed_hashes(self):
        rows = self.data()
        message = bytearray.fromhex(rows[1]["signed_message_hex"])
        message[len(b"TRNM/CryptoProfile/Envelope/v1\0") + 128 + 1] ^= 1
        wire = bytearray.fromhex(rows[1]["cpq1_wire_hex"])
        wire[8:8 + len(message)] = message
        rows[1].update(signed_message_hex=message.hex(), signed_message_sha512=digest(message),
                       cpq1_wire_hex=wire.hex(), cpq1_wire_sha512=digest(wire))
        self.refuse(rows, "complete fixed context")

    def test_metadata_size_or_late_mutation_location_refuses(self):
        for field in ("payload_bytes", "signed_message_bytes", "cpq1_wire_bytes",
                      "signed_metadata_bytes", "outer_framing_bytes", "late_invalid_byte_offset"):
            rows = self.data()
            rows[1][field] += 1
            self.refuse(rows, field)

    def test_noncanonical_hex_signer_ids_and_seed_indices_refuse(self):
        rows = self.data()
        rows[1]["signed_message_hex"] = rows[1]["signed_message_hex"].upper()
        self.refuse(rows, "hex")
        rows = self.data()
        rows[1]["signer_ids"][0] = "00" * 64
        self.refuse(rows, "signer IDs")
        rows = self.data()
        rows[1]["signer_seed_indices_in_wire_order"] = [True]
        self.refuse(rows, "seed-index permutation")

    def test_signature_rejection_cannot_be_relabelled_policy_rejection(self):
        rows = self.data()
        rows[6]["outcomes_per_sample"]["signature_arithmetic_rejections"] = 0
        rows[6]["outcomes_per_sample"]["policy_encoding_rejections"] = 1
        self.refuse(rows, "checked outcomes")

    def test_cold_or_hot_verified_signature_count_cannot_be_omitted(self):
        for row_index in (4, 5):
            rows = self.data()
            rows[row_index]["outcomes_per_sample"]["returned_verified_signatures"] = 0
            self.refuse(rows, "returned_verified_signatures")

    def test_full_signing_cannot_claim_precomputed_signature_cost(self):
        rows = self.data()
        rows[3]["outcomes_per_sample"]["sign_and_self_verify_calls"] = 0
        self.refuse(rows, "sign_and_self_verify_calls")

    def test_budget_reset_refund_or_missing_sticky_refusal_refuses(self):
        for field, value in (("reserved_verification_attempts", 1), ("reserved_wire_bytes", 0),
                             ("policy_budget_rejections", 1), ("sticky_budget_checks", 0),
                             ("policy_encoding_rejections", 0)):
            rows = self.data()
            rows[12]["outcomes_per_sample"][field] = value
            self.refuse(rows, field)

    def test_over_budget_reservation_is_not_miscounted_as_signature_observation(self):
        rows = self.data()
        rows[12]["outcomes_per_sample"]["returned_verified_signatures"] = 65
        self.refuse(rows, "returned_verified_signatures")

    def test_warmup_and_measured_total_are_independently_checked(self):
        for field in ("warmup_outcomes", "measured_outcome_totals"):
            rows = self.data()
            rows[5][field]["accepted_authentications"] += 1
            self.refuse(rows, "outcomes|totals")

    def test_incomplete_global_accounting_refuses(self):
        for field in ("cases", "measurement_rows", "raw_sample_values", "warmup_groups"):
            rows = self.data()
            rows[-1][field] -= 1
            self.refuse(rows, field)
        rows = self.data()
        rows[-1]["measured_outcome_totals"]["policy_budget_rejections"] -= 1
        self.refuse(rows, "policy_budget_rejections")

    def test_production_or_activation_claims_and_extra_fields_refuse(self):
        for index, field, value in ((0, "frame_is_PNQ_or_NPQ", True),
                                    (0, "production_tail_established", True),
                                    (0, "activation_performed", True),
                                    (-1, "production_qualified", True),
                                    (2, "performance_acceptance_gate", True),
                                    (2, "production_p99_ns", 1),
                                    (1, "current_authorization_refused", False)):
            rows = self.data()
            rows[index][field] = value
            self.refuse(rows, field)
        rows = self.data()
        rows[2]["all_native_security_gates_passed"] = True
        self.refuse(rows, "fields")

    def test_bounded_file_roundtrip_retains_no_execution_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic.jsonl"
            raw = "".join(json.dumps(row) + "\n" for row in self.template).encode()
            path.write_bytes(raw)
            result = reader.check(path)
            self.assertEqual(result["observation_file"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertFalse(result["native_execution_attested"])

    def test_duplicate_json_keys_nonfinite_and_floating_numbers_refuse(self):
        for raw in (b'{"schema":"a","schema":"b"}\n', b'{"x":NaN}\n',
                    b'{"x":Infinity}\n', b'{"x":-Infinity}\n', b'{"x":1.0}\n', b'{"x":1e999}\n'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "bad.jsonl"
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    reader.read_records(path)

    def test_partial_file_blank_record_oversize_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.jsonl"
            for raw in (b'{}', b'{}\n\n'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    reader.read_records(path)
            path.write_bytes(b'{"x":0}\n')
            with mock.patch.object(reader, "MAX_FILE_BYTES", 4), self.assertRaises(ValueError):
                reader.read_records(path)
            link = path.with_name("linked.jsonl")
            link.symlink_to(path)
            with self.assertRaises(OSError):
                reader.read_records(link)


if __name__ == "__main__":
    unittest.main()
