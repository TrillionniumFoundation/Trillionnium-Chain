#!/usr/bin/env python3
"""Adversarial metadata controls; synthetic records below are never proof evidence."""
import copy
import json
import unittest

import check_audit_one as reader


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
    receipt_bytes = b"synthetic-not-a-proof" * 60
    statement_id, journal = reader.claimed_journal(input_bytes)
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
        "original_shape":{"segments":1, "maximum_po2":13, "padded_cycles":8192},
        "original_statement_id":statement_id, "case_expected_journal_sha256":reader.sha(journal),
        "image_id":manifest["guest_image_id"], "source_inputs":inputs,
        "resource_caps":reader.CAPS.copy(), **{key:False for key in reader.FALSE_FLAGS},
    }
    return record, input_bytes, receipt_bytes


class ReaderControls(unittest.TestCase):
    def setUp(self):
        self.record, self.input, self.receipt = synthetic_metadata()

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


if __name__ == "__main__":
    unittest.main()
