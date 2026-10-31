#!/usr/bin/env python3
"""Adversarial metadata controls; synthetic records below are never proof evidence."""
import copy
import json
import struct
import unittest

import check_audit_one as reader


def synthetic_receipt(journal):
    """Supported wire layout only: arbitrary seal words are NOT a valid proof."""
    raw = bytearray(struct.pack("<IQ", 0, 3))
    positions = {"seal_starts": [], "seal_ends": [], "parameters": [],
                 "seal_lengths": [], "indices": [], "hash_lengths": []}
    for index, (word_count, po2) in enumerate(((102, 13), (103, 14), (104, 15))):
        positions["seal_lengths"].append(len(raw))
        raw += struct.pack("<Q", word_count)
        positions["seal_starts"].append(len(raw))
        words = [0x5A5A5A5A] * word_count
        words[0], words[91] = 2, po2
        raw += struct.pack("<" + "I" * word_count, *words)
        positions["seal_ends"].append(len(raw))
        positions["indices"].append(len(raw))
        raw += struct.pack("<I", index)
        positions["hash_lengths"].append(len(raw))
        raw += struct.pack("<Q", 9) + b"poseidon2"
        positions["parameters"].append(len(raw))
        raw += b"\xa5\0" * 16
        raw += (struct.pack("<I", 1) + bytes(32)) * 2  # Pruned states.
        raw += struct.pack("<II", 0, 0)  # Halted(0).
        raw += struct.pack("<I", 0) + b"\0"  # Value(None) input.
        raw += struct.pack("<I", 1) + bytes(32)  # Pruned output.
    positions["nested_assumptions"] = len(raw)
    raw += struct.pack("<Q", 0) + bytes(32)
    positions["journal_length"] = len(raw)
    raw += struct.pack("<Q", len(journal))
    positions["journal"] = len(raw)
    raw += journal
    positions["metadata"] = len(raw)
    raw += b"\x33" * 32
    return bytes(raw), {"segments": 3, "maximum_po2": 15,
                        "padded_cycles": 8192 + 16384 + 32768}, positions


def synthetic_metadata():
    witness = b"PNW1" + bytes(49184)
    header = bytearray(318)
    header[:6] = b"PNH1\x01\0"
    header[118:150] = b"\xff" * 32
    header[278:310] = b"\x09" * 32
    statement = (b"PWG1\x01\0" + reader.domain(b"w1-complete-profile-v1", b"pon-complete-w1-relation-v1")
                 + header + b"\x09" * 32 + b"\xff" * 32
                 + reader.domain(b"w1-complete-witness-v1", witness))
    input_bytes = statement + witness
    statement_id, journal = reader.claimed_journal(input_bytes)
    receipt_bytes, shape, _ = synthetic_receipt(journal)
    manifest = reader.decode_json((reader.ROOT / (reader.PREFIX + "guests/w1-risc0/backend-manifest.json")).read_bytes())
    inputs = []
    for path in sorted(reader.SOURCE_PATHS):
        raw = (reader.ROOT / path).read_bytes()
        inputs.append({"path":path, "bytes":len(raw), "sha256":reader.sha(raw)})
    record = {
        "schema":"pon-w1-receiver-case-v1", "operation":"audit-one", "case":"valid",
        "real_proof_positive_control":True, "positive_prerequisite_warms_verifier":True,
        "positive_prerequisite_wall_ns":100, "case_construction_wall_ns":10,
        "receiver":{"accepted":True, "outcome":"verified", "reason":None,
                    "last_stage":"strict_verify", "bounded_preflight_and_sdk_decode_wall_ns":10,
                    "strict_verify_wall_ns":70, "decoded_receipt_drop_wall_ns":10,
                    "receiver_total_wall_ns":100},
        "receiver_scope":"bounded-preflight/sdk-decode/strict-verify/decoded-drop",
        "excluded_from_receiver_timing":reader.EXCLUDED.copy(),
        "original_input":{"bytes":len(input_bytes), "sha256":reader.sha(input_bytes)},
        "original_receipt":{"bytes":len(receipt_bytes), "sha256":reader.sha(receipt_bytes)},
        "case_input":{"bytes":len(input_bytes), "sha256":reader.sha(input_bytes)},
        "case_receipt":{"bytes":len(receipt_bytes), "sha256":reader.sha(receipt_bytes)},
        "input_mutation":{"before_bytes":len(input_bytes), "after_bytes":len(input_bytes), "byte_changes":[]},
        "receipt_mutation":{"before_bytes":len(receipt_bytes), "after_bytes":len(receipt_bytes), "byte_changes":[]},
        "original_shape":shape,
        "original_statement_id":statement_id, "case_expected_journal_sha256":reader.sha(journal),
        "image_id":manifest["guest_image_id"], "source_inputs":inputs,
        "resource_caps":reader.CAPS.copy(), **{key:False for key in reader.FALSE_FLAGS},
    }
    return record, input_bytes, receipt_bytes


class ReaderControls(unittest.TestCase):
    def setUp(self):
        self.record, self.input, self.receipt = synthetic_metadata()
        _, _, self.positions = synthetic_receipt(reader.claimed_journal(self.input)[1])

    def check(self, record=None, input_bytes=None, receipt_bytes=None):
        return reader.validate(record if record is not None else self.record,
                               input_bytes if input_bytes is not None else self.input,
                               receipt_bytes if receipt_bytes is not None else self.receipt)

    def refuse(self, change):
        record = copy.deepcopy(self.record)
        change(record)
        with self.assertRaises(ValueError):
            self.check(record)

    def test_synthetic_metadata_pass_does_not_gain_proof_authority(self):
        result = self.check()
        self.assertTrue(result["metadata_and_byte_bindings_pass"])
        self.assertEqual(result["schema"], "pon-w1-receiver-case-binding-v2")
        self.assertTrue(result["receipt_layout_independently_reconstructed"])
        self.assertTrue(result["mutation_offsets_independently_reconstructed"])
        self.assertTrue(result["original_receipt_journal_bound_to_claimed_input"])
        for key in ["proof_reverified_by_reader", "proof_shape_independently_reconstructed",
                    "sdk_mutation_dispatch_independently_reexecuted", "timings_independently_remeasured",
                    "consensus_authority"]:
            self.assertIs(result[key], False)

    def test_duplicate_json_key_is_rejected(self):
        with self.assertRaises(ValueError):
            reader.decode_json('{"case":"valid","case":"last_seal_tamper"}')

    def test_all_qualification_promotions_are_rejected(self):
        for key in reader.FALSE_FLAGS:
            self.refuse(lambda row, key=key: row.update({key:True}))

    def test_caps_cannot_change_or_gain_float_aliases(self):
        for key in reader.CAPS:
            self.refuse(lambda row, key=key: row["resource_caps"].update({key:reader.CAPS[key] + 1}))
            self.refuse(lambda row, key=key: row["resource_caps"].update({key:float(reader.CAPS[key])}))
        self.refuse(lambda row: row["resource_caps"].pop("receipt_bytes"))

    def test_source_omission_duplicate_and_changed_hash_are_rejected(self):
        self.refuse(lambda row: row["source_inputs"].pop())
        self.refuse(lambda row: row["source_inputs"].__setitem__(1, copy.deepcopy(row["source_inputs"][0])))
        self.refuse(lambda row: row["source_inputs"][0].update({"sha256":"0" * 64}))
        self.refuse(lambda row: row["source_inputs"][0].update({"path":"../outside"}))

    def test_actual_byte_rebinding_is_rejected(self):
        with self.assertRaises(ValueError):
            self.check(receipt_bytes=self.receipt[:-1] + b"X")
        with self.assertRaises(ValueError):
            self.check(input_bytes=self.input[:-1] + b"X")

    def test_coordinated_input_hash_change_cannot_hide_bad_header_context(self):
        changed = bytearray(self.input)
        changed[38 + 278] ^= 1
        self.record["original_input"]["sha256"] = reader.sha(changed)
        with self.assertRaises(ValueError):
            self.check(input_bytes=bytes(changed))

    def test_matching_zero_targets_are_rejected(self):
        changed = bytearray(self.input)
        changed[38 + 118:38 + 150] = bytes(32)
        changed[388:420] = bytes(32)
        self.record["original_input"]["sha256"] = reader.sha(changed)
        with self.assertRaises(ValueError):
            self.check(input_bytes=bytes(changed))

    def test_statement_id_and_claimed_journal_are_independently_bound(self):
        self.refuse(lambda row: row.update({"original_statement_id":"0" * 64}))
        self.refuse(lambda row: row.update({"case_expected_journal_sha256":"0" * 64}))

    def test_receipt_outcome_cannot_be_relabelled(self):
        self.refuse(lambda row: row["receiver"].update({"accepted":False}))
        self.refuse(lambda row: row["receiver"].update({"outcome":"verification_failed"}))
        self.refuse(lambda row: row["receiver"].update({"last_stage":"bounded_preflight_or_sdk_decode"}))
        self.refuse(lambda row: row.update({"case":"unknown"}))

    def test_timings_reject_boolean_float_negative_and_missing_stages(self):
        for value in [True, 1.0, -1, None]:
            self.refuse(lambda row, value=value: row["receiver"].update({"strict_verify_wall_ns":value}))
        self.refuse(lambda row: row["receiver"].update({"receiver_total_wall_ns":1}))
        self.refuse(lambda row: row.update({"positive_prerequisite_wall_ns":False}))

    def test_timing_scope_cannot_include_unrelated_costs(self):
        self.refuse(lambda row: row.update({"receiver_scope":"whole-process"}))
        self.refuse(lambda row: row["excluded_from_receiver_timing"].remove("positive-prerequisite"))
        self.refuse(lambda row: row.update({"positive_prerequisite_warms_verifier":False}))

    def test_wrong_record_kind_is_not_a_sample(self):
        with self.assertRaises(ValueError):
            self.check({"schema":"pon-w1-actual-process-v1", "returncode":0})

    def test_image_pin_and_shape_caps_remain_exact(self):
        self.refuse(lambda row: row.update({"image_id":"0" * 64}))
        self.refuse(lambda row: row["original_shape"].update({"maximum_po2":21}))
        self.refuse(lambda row: row["original_shape"].update({"segments":False}))

    def test_mutation_metadata_cannot_silently_change_valid_case(self):
        self.refuse(lambda row: row["receipt_mutation"]["byte_changes"].append(
            {"offset":0,"before":self.receipt[0],"after":self.receipt[0] ^ 1}))
        self.refuse(lambda row: row["receipt_mutation"].update({"after_bytes":len(self.receipt) - 1}))

    def mutation_record(self, case, offsets, zero=False):
        record = copy.deepcopy(self.record)
        changed = bytearray(self.receipt)
        for offset in offsets:
            changed[offset] = 0 if zero else changed[offset] ^ 1
        record["case"] = case
        record["receiver"].update(accepted=False, outcome="verification_failed",
                                   reason="synthetic negative metadata; no proof execution")
        record["case_receipt"] = {"bytes": len(changed), "sha256": reader.sha(changed)}
        record["receipt_mutation"]["byte_changes"] = [
            {"offset": offset, "before": old, "after": new}
            for offset, (old, new) in enumerate(zip(self.receipt, changed)) if old != new]
        return record

    def rebind_original_receipt(self, changed):
        self.receipt = bytes(changed)
        binding = {"bytes": len(changed), "sha256": reader.sha(changed)}
        self.record["original_receipt"] = binding.copy()
        self.record["case_receipt"] = binding.copy()
        self.record["receipt_mutation"].update(before_bytes=len(changed), after_bytes=len(changed))

    def test_middle_seal_cannot_be_labelled_last(self):
        record = self.mutation_record("last_seal_tamper", [self.positions["seal_ends"][1] - 4])
        with self.assertRaises(ValueError):
            self.check(record)

    def test_other_last_seal_word_cannot_be_labelled_last(self):
        record = self.mutation_record("last_seal_tamper", [self.positions["seal_ends"][-1] - 8])
        with self.assertRaises(ValueError):
            self.check(record)

    def test_nonparameter_digest_cannot_be_labelled_verifier_parameters(self):
        start = self.positions["metadata"]
        record = self.mutation_record("wrong_verifier_parameters", range(start, start + 32), zero=True)
        with self.assertRaises(ValueError):
            self.check(record)

    def test_partial_parameter_zeroing_cannot_be_labelled_whole_digest(self):
        record = self.mutation_record("wrong_verifier_parameters", [self.positions["parameters"][0]], zero=True)
        with self.assertRaises(ValueError):
            self.check(record)

    def test_declared_shape_must_match_actual_receipt(self):
        self.record["original_shape"] = {"segments": 1, "maximum_po2": 13, "padded_cycles": 8192}
        with self.assertRaises(ValueError):
            self.check()

    def test_malformed_original_receipt_cannot_gain_bound_layout(self):
        changed = bytearray(self.receipt)
        changed[0] = 1
        self.rebind_original_receipt(changed)
        with self.assertRaises(ValueError):
            self.check()

    def test_receipt_journal_must_match_input(self):
        changed = bytearray(self.receipt)
        changed[self.positions["journal"] + 4] ^= 1
        self.rebind_original_receipt(changed)
        with self.assertRaises(ValueError):
            self.check()

    def test_exact_first_last_and_parameter_mutations_are_accepted(self):
        start = self.positions["parameters"][0]
        cases = (("first_seal_tamper", [self.positions["seal_starts"][0] + 400], False),
                 ("last_seal_tamper", [self.positions["seal_ends"][-1] - 4], False),
                 ("wrong_verifier_parameters", range(start, start + 32), True))
        for case, offsets, zero in cases:
            with self.subTest(case=case):
                self.assertTrue(self.check(self.mutation_record(case, offsets, zero))["metadata_and_byte_bindings_pass"])

    def test_receipt_length_and_variant_bombs_are_refused_before_rebinding(self):
        seal = self.positions["seal_starts"][0]
        cases = ((4, "<Q", 0), (4, "<Q", 2049),
                 (self.positions["seal_lengths"][0], "<Q", (1 << 64) - 1),
                 (self.positions["seal_lengths"][0], "<Q", 91),
                 (seal, "<I", 3), (seal + 91 * 4, "<I", 12), (seal + 91 * 4, "<I", 21),
                 (self.positions["indices"][1], "<I", 0),
                 (self.positions["hash_lengths"][0], "<Q", (1 << 64) - 1),
                 (self.positions["nested_assumptions"], "<Q", 1),
                 (self.positions["journal_length"], "<Q", 227),
                 (self.positions["journal_length"], "<Q", (1 << 64) - 1))
        for offset, encoding, value in cases:
            with self.subTest(offset=offset, value=value):
                changed = bytearray(self.receipt)
                struct.pack_into(encoding, changed, offset, value)
                with self.assertRaises(ValueError):
                    reader.parse_receipt_layout(changed, reader.CAPS)

    def test_layout_rejects_every_truncated_prefix_and_trailing_byte(self):
        for length in range(len(self.receipt)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                reader.parse_receipt_layout(self.receipt[:length], reader.CAPS)
        with self.assertRaises(ValueError):
            reader.parse_receipt_layout(self.receipt + b"\0", reader.CAPS)

    def test_layout_checks_aggregate_cycle_cap_not_only_each_segment(self):
        # Keep the original cap; 257 individually allowed po2=20 segments exceed it.
        segment_start = self.positions["seal_lengths"][0]
        segment_end = self.positions["seal_lengths"][1]
        template = bytearray(self.receipt[segment_start:segment_end])
        index_offset = self.positions["indices"][0] - segment_start
        struct.pack_into("<I", template, 8 + 91 * 4, 20)
        changed = bytearray(struct.pack("<IQ", 0, 257))
        for index in range(257):
            struct.pack_into("<I", template, index_offset, index)
            changed += template
        changed += self.receipt[self.positions["nested_assumptions"]:]
        with self.assertRaisesRegex(ValueError, "total padded proof-cycle budget"):
            reader.parse_receipt_layout(changed, reader.CAPS)


if __name__ == "__main__":
    unittest.main()
