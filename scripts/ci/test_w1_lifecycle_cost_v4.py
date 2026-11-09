#!/usr/bin/env python3
"""Negative readback controls; synthetic prefixes never claim native success."""
from __future__ import annotations
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "pon_w1_lifecycle_cost_v4.py"
SPEC = importlib.util.spec_from_file_location("lifecycle_v4", PATH)
v4 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v4)


def start():
    return dict(
        kind="start", selector=v4.SELECTOR, samples=v4.SAMPLES,
        searches_per_setup=v4.SEARCHES, attempt_budget=v4.LIMIT, seed=0,
        target=v4.TARGET, arms=list(v4.ARMS),
        clock="thread-cpu-and-monotonic-wall-ns",
        setup_reuse="one-actual-preparation-four-distinct-domain-searches",
        attempt_timing_scope="proof-generation-and-trial-digest-before-finish-observation",
        search_timing_scope="native-search-with-v4-streaming-observation",
        verifier_timing_scope="complete-native-verification-call",
        missing_finish="INCOMPLETE_COST_UNKNOWN_NEVER_ZERO",
        sink_guarantee="line-write-and-flush-not-power-loss-durability",
        raw_process_and_source_receipts_required=True,
        hardness_accepted=False, work_profile_qualified=False,
        public_service_measured=False, production_activation=False,
        consensus_credit_added=0,
    )


def encoded(rows):
    return b"".join(json.dumps(dict(row, schema=v4.SCHEMA, sequence=index)).encode() + b"\n"
                    for index, row in enumerate(rows))


def prefix():
    zero = bytes(v4.CELLS * 4)
    task = v4.digest(b"task", zero, zero).hex()
    key = dict(
        **{"class": "zero"}, sample=0, arm=v4.ARMS[0],
        invocation_order=0, task=task, target=v4.TARGET,
    )
    search = dict(key, search_index=0)
    return [
        start(),
        dict(kind="material-setup-start"),
        dict(kind="material-setup-finish", classes=list(v4.CLASSES),
             timing=dict(cpu_ns=None, wall_ns=1)),
        dict(kind="material", **{"class": "zero"}, source="synthetic-fixture",
             task=task, a_hex=zero.hex(), b_hex=zero.hex()),
        dict(key, kind="cohort-start"),
        dict(key, kind="prepare-start"),
        dict(key, kind="prepare-finish", timing=dict(cpu_ns=1, wall_ns=1),
             setup_calls=1, status="supported"),
        dict(search, kind="search-start"),
        dict(search, kind="attempt-start", nonce=0,
             challenge=v4.challenge(task, 0, 0, 0)),
    ]


class Readback(unittest.TestCase):
    def test_every_complete_line_prefix_remains_incomplete_and_unknown(self):
        rows = prefix()
        for count in range(len(rows) + 1):
            result = v4.read_stream(io.BytesIO(encoded(rows[:count])), process_exit_code=0)
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertIsNone(result["unfinished_resource_cost"])
            self.assertFalse(result["all_legal_work_cost_lower_bound_proved"])
            self.assertEqual(result["consensus_credit_added"], 0)

    def test_half_written_attempt_is_retained_as_partial_not_zero_cost(self):
        raw = encoded(prefix())
        result = v4.read_stream(io.BytesIO(raw[:-17]), process_exit_code=-15)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["native_process_exit_code"], -15)
        self.assertGreater(result["trailing_partial_bytes"], 0)
        self.assertIsNone(result["unfinished_resource_cost"])

    def test_missing_start_deletion_and_duplicate_sequence_are_refused(self):
        raw = encoded(prefix()).splitlines(keepends=True)
        for changed in (raw[1:], raw[:7] + raw[8:], raw[:8] + [raw[7]] + raw[8:]):
            with self.assertRaises(ValueError):
                v4.read_stream(io.BytesIO(b"".join(changed)))

    def test_wrong_challenge_or_extra_credit_authority_is_refused(self):
        for field, value in (("challenge", "00" * 32), ("native_credit_qualified", True)):
            rows = prefix()
            rows[-1][field] = value
            with self.assertRaises(ValueError):
                v4.read_stream(io.BytesIO(encoded(rows)))

    def test_attempt_error_preserves_unknown_and_unfinished_search(self):
        rows = prefix()
        fields = {key: rows[-1][key] for key in v4.KEYS | {"search_index"}}
        rows.append(dict(fields, kind="attempt-error", nonce=0, reason="GENERATION:NoiseBudget",
                         timing=dict(cpu_ns=None, wall_ns=4), accepted_work=False))
        rows.append(dict(kind="failure", reason="GENERATION:NoiseBudget", complete=False,
                         unfinished_cost=None, consensus_credit_added=0,
                         production_qualified=False))
        result = v4.read_stream(io.BytesIO(encoded(rows)), process_exit_code=1)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["generation_records_with_unknown_cpu"], 1)
        self.assertEqual(result["failure"], "GENERATION:NoiseBudget")
        self.assertIsNotNone(result["unfinished_search"])
        self.assertIsNone(result["unfinished_resource_cost"])

    def test_injected_end_cannot_close_unfinished_native_work(self):
        rows = prefix()
        rows.append(dict(kind="end", material_count=9, cohort_count=1, search_count=0,
                         attempt_count=0, candidate_count=0, verifier_count=0,
                         fully_verified_search_count=0,
                         total_before_terminal_record=dict(cpu_ns=1, wall_ns=1),
                         complete=True, consensus_credit_added=0,
                         work_cost_lower_bound_proved=False, production_qualified=False))
        with self.assertRaisesRegex(ValueError, "END_WITH_OPEN_WORK"):
            v4.read_stream(io.BytesIO(encoded(rows)), process_exit_code=0)

    def test_duplicate_json_key_and_boolean_sequence_are_rejected(self):
        row = encoded([start()])
        altered = row.replace(b'"sequence": 0', b'"sequence": 0, "sequence": 0')
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            v4.read_stream(io.BytesIO(altered))
        altered = row.replace(b'"sequence": 0', b'"sequence": false')
        with self.assertRaisesRegex(ValueError, "SEQUENCE"):
            v4.read_stream(io.BytesIO(altered))

    def test_measured_scope_text_cannot_be_relabelled(self):
        for field in ("clock", "setup_reuse", "attempt_timing_scope", "search_timing_scope",
                      "verifier_timing_scope", "sink_guarantee"):
            row = start()
            row[field] = "changed-scope"
            with self.assertRaisesRegex(ValueError, "START_CONTRACT:" + field):
                v4.read_stream(io.BytesIO(encoded([row])))

    def test_material_provenance_label_is_frozen(self):
        rows = prefix()
        rows[3]["source"] = "paid-independent-native-task"
        with self.assertRaisesRegex(ValueError, "MATERIAL_SOURCE"):
            v4.read_stream(io.BytesIO(encoded(rows)))

    def test_equal_winner_cannot_hide_a_changed_losing_trial(self):
        reader = v4.Reader()
        rows = prefix()
        for index, row in enumerate(rows):
            reader.consume(dict(row, schema=v4.SCHEMA, sequence=index))
        key = {key: rows[-1][key] for key in v4.KEYS | {"search_index"}}

        def feed(row):
            reader.consume(dict(row, schema=v4.SCHEMA, sequence=reader.sequence))

        def trial(nonce, hit, proof):
            context = v4.challenge(key["task"], 0, 0, nonce)
            for counter in range(10000):
                trace = hashlib.sha256(str(counter).encode()).digest()
                ticket = v4.digest(b"ticket", bytes.fromhex(context), trace).hex()
                if (ticket <= v4.TARGET) == hit:
                    return dict(nonce=nonce, challenge=context, trace=trace.hex(),
                                ticket=ticket, proof_sha256=proof, target_hit=hit)
            self.fail("failed to construct bounded hash-only parser control")

        losing = trial(0, False, "11" * 32)
        winning = trial(1, True, "22" * 32)
        feed(dict(key, kind="attempt-finish", trial=losing,
                  timing=dict(cpu_ns=1, wall_ns=1), accepted_work=False))
        feed(dict(key, kind="attempt-start", nonce=1, challenge=winning["challenge"]))
        feed(dict(key, kind="attempt-finish", trial=winning,
                  timing=dict(cpu_ns=1, wall_ns=1), accepted_work=False))
        # An independent expected prior stream differs only in the losing
        # proof digest. The same declared winner cannot conceal that change.
        prior_losing = dict(losing, proof_sha256="33" * 32)
        def stream_sha(trials):
            hasher = hashlib.sha256()
            for item in trials:
                hasher.update(json.dumps(item, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=True).encode("ascii") + b"\n")
            return hasher.hexdigest()

        self.assertEqual(stream_sha((losing, winning)),
                         reader.search["trial_stream_sha256"])
        changed = stream_sha((prior_losing, winning))
        self.assertNotEqual(changed, reader.search["trial_stream_sha256"])
        canon = ("zero", 0, 0)
        reader.canonical_streams[canon] = (2, changed)
        reader.canonical[canon] = tuple(winning[field] for field in
                                       ("nonce", "challenge", "trace", "ticket", "proof_sha256"))
        with self.assertRaisesRegex(ValueError, "PRODUCER_TRIAL_STREAM_DISAGREEMENT"):
            feed(dict(key, kind="search-finish", attempt_count=2,
                      timing=dict(cpu_ns=2, wall_ns=2), status="target-hit-unverified"))

    def test_no_more_records_can_follow_failure(self):
        rows = prefix()
        rows.append(dict(kind="failure", reason="operator cancel", complete=False,
                         unfinished_cost=None, consensus_credit_added=0,
                         production_qualified=False))
        rows.append(start())
        with self.assertRaisesRegex(ValueError, "RECORD_AFTER_TERMINAL"):
            v4.read_stream(io.BytesIO(encoded(rows)), process_exit_code=1)


if __name__ == "__main__":
    unittest.main()
