#!/usr/bin/env python3
"""Synthetic reader-boundary tests, never native W1 or cost observations.

These records deliberately use invented transcripts and recorded verdicts.
They test strict retention/coverage/identity checks, not the W1 relation.
"""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_reused_cost_reader_v3 as reader

common = reader.common


def stamp(number):
    return {"cpu_ns": number, "wall_ns": number}


def row(kind, **fields):
    return {"schema": reader.SCHEMA, "kind": kind, **fields}


def fixture():
    records = [row("campaign", selector=reader.SELECTOR, samples=8, searches_per_setup=4,
        attempt_budget=4096, seed=0, target=reader.TARGET, arms=list(reader.ARMS),
        classes=list(reader.CLASSES), clock="thread-cpu-and-monotonic-wall-ns",
        material_setup=stamp(1000), setup_reuse="one-actual-preparation-four-independent-searches",
        producer_timing_scope="actual-setup-and-complete-search-retention-excludes-json-comparison-verification",
        verifier_timing_scope="native-full-verification-call-only-no-fact-cache", **reader.FALSE_FLAGS)]
    counts = dict.fromkeys(("material", "cohort", "search", "candidate", "verifier"), 0)

    def add(kind, **fields):
        counts[kind] += 1
        records.append(row(kind, **fields))

    for name in reader.CLASSES:
        a, b, task, prefix = common.material(name)
        add("material", **{"class": name}, source="hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture",
            task=task.hex(), a_hex=a.hex(), b_hex=b.hex())
        for sample in range(reader.SAMPLES):
            cases = []
            for search in range(reader.SEARCHES):
                trials = []
                for nonce in range(reader.ATTEMPT_BUDGET):
                    context = reader.challenge(task, sample, search, nonce)
                    trace = common.pon_hash(b"synthetic-reader-v3-not-a-w1-proof", context)
                    proof = prefix + trace
                    ticket = common.pon_hash(b"ticket", context, trace)
                    hit = ticket <= bytes.fromhex(reader.TARGET)
                    trials.append({"nonce": nonce, "challenge": context.hex(), "trace": trace.hex(),
                        "ticket": ticket.hex(), "proof_sha256": common.sha(proof), "target_hit": hit})
                    if hit:
                        break
                else:
                    raise AssertionError("bounded synthetic reader fixture exhausted")
                cases.append((trials, proof, context))
            context_fields = {"class": name, "sample": sample, "task": task.hex(), "target": reader.TARGET}
            for order in range(len(reader.ARMS)):
                arm = reader.ARMS[(sample + order) % len(reader.ARMS)]
                supported = common.supported(arm, name)
                add("cohort", **context_fields, arm=arm, invocation_order=order,
                    status="supported" if supported else "unsupported", setup_calls=1,
                    searches=reader.SEARCHES if supported else 0, setup=stamp(100),
                    total=stamp(1500 if supported else 110))
                if not supported:
                    continue
                for search, (trials, proof, context) in enumerate(cases):
                    add("search", **context_fields, arm=arm, search_index=search, setup_calls=0,
                        timing=stamp(300), status="target-hit-unverified", attempts=copy.deepcopy(trials),
                        winner={"challenge": context.hex(), "proof_sha256": common.sha(proof)})
                    for verification_order in range(2):
                        path = "reference" if (sample + order + search + verification_order) % 2 else "production"
                        add("verifier", **context_fields, arm=arm, search_index=search, path=path,
                            invocation_order=verification_order, challenge=context.hex(),
                            proof_sha256=common.sha(proof), outcome="Accepted", timing=stamp(200))
            for search, (_, proof, context) in enumerate(cases):
                add("candidate", **context_fields, search_index=search, challenge=context.hex(),
                    proof_hex=proof.hex(), proof_sha256=common.sha(proof))
    records.append(row("end", **{kind + "_count": value for kind, value in counts.items()}, complete=True))
    return records


class ReusedReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="reused-v3-reader-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic.jsonl"

    def records(self):
        return copy.deepcopy(self.original)

    def analyze(self, records):
        with self.path.open("w") as output:
            for record in records:
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
        return reader.analyze(self.path)

    def first(self, records, kind, **fields):
        return next(record for record in records if record["kind"] == kind
                    and all(record.get(key) == value for key, value in fields.items()))

    def fails(self, records, message):
        with self.assertRaisesRegex(ValueError, message):
            self.analyze(records)

    def test_complete_actual_grid_does_not_claim_native_or_hardware_qualification(self):
        result = self.analyze(self.original)
        self.assertEqual(result["record_consistency"], "PASS")
        self.assertEqual(result["record_counts"]["cohort"], 936)
        self.assertEqual(result["record_counts"]["search"], 1888)
        self.assertEqual(result["record_counts"]["candidate"], 288)
        self.assertEqual(result["record_counts"]["verifier"], 3776)
        self.assertEqual(result["semantic_alerts"], [])
        self.assertFalse(result["modeled_setup_division_used"])
        self.assertFalse(result["w1_transcript_replayed"])
        self.assertFalse(result["source_applicability_verified"])
        for flag in reader.FALSE_FLAGS:
            self.assertIs(result[flag], False)
        for cohort in result["actual_reuse_cohorts"]:
            self.assertEqual(cohort["actual_setup_calls"], 8)
            self.assertEqual(cohort["actual_searches"], 32 if cohort["supported"] else 0)

    def test_zero_tests_and_empty_end_cannot_pass(self):
        self.fails([self.original[0], row("end", material_count=0, cohort_count=0,
            search_count=0, candidate_count=0, verifier_count=0, complete=True)], "grid incomplete")

    def test_missing_unsupported_arm_is_still_missing_coverage(self):
        records = self.records()
        records.remove(self.first(records, "cohort", status="unsupported"))
        records[-1]["cohort_count"] -= 1
        self.fails(records, "rotation changed")

    def test_modeled_division_cannot_replace_actual_reuse(self):
        records = self.records()
        records[0]["setup_reuse"] = "modeled-setup-divisor-not-observed-multiwinner"
        self.fails(records, "modeled amortization")

    def test_default_v2_schema_is_not_relabelled(self):
        records = self.records()
        records[0]["schema"] = common.SCHEMA
        self.fails(records, "explicit V3 schema")

    def test_rebuilding_inside_search_is_not_reuse(self):
        records = self.records()
        self.first(records, "search")["setup_calls"] = 1
        self.fails(records, "rebuilt preparation")

    def test_missing_actual_setup_is_rejected(self):
        records = self.records()
        self.first(records, "cohort")["setup_calls"] = 0
        self.fails(records, "actual constructor")

    def test_replayed_search_challenge_is_rejected(self):
        records = self.records()
        first = self.first(records, "search", search_index=0)
        second = self.first(records, "search", search_index=1)
        second["attempts"] = copy.deepcopy(first["attempts"])
        second["winner"] = copy.deepcopy(first["winner"])
        self.fails(records, "challenge recipe mismatch")

    def test_omitted_miss_cannot_look_like_a_complete_search(self):
        records = self.records()
        search = next(record for record in records if record["kind"] == "search" and len(record["attempts"]) > 1)
        search["attempts"].pop(0)
        self.fails(records, "nonconsecutive nonce")

    def test_full_exhaustion_retains_every_miss_and_cannot_be_shortened(self):
        name = "zero"
        _, _, task, prefix = common.material(name)
        trials = []
        for nonce in range(reader.ATTEMPT_BUDGET):
            context = reader.challenge(task, 0, 0, nonce)
            for salt in range(4096):
                trace = common.pon_hash(b"synthetic-exhausted-reader-v3", context, salt.to_bytes(8, "little"))
                ticket = common.pon_hash(b"ticket", context, trace)
                if ticket > bytes.fromhex(reader.TARGET):
                    break
            else:
                self.fail("bounded synthetic miss search exhausted")
            trials.append({"nonce": nonce, "challenge": context.hex(), "trace": trace.hex(),
                "ticket": ticket.hex(), "proof_sha256": common.sha(prefix + trace), "target_hit": False})
        item = {"kind": "search", "class": name, "sample": 0, "status": "exhausted", "attempts": trials}
        check = lambda: common._trials(item, task, 0, prefix,
            challenge_at=lambda nonce: reader.challenge(task, 0, 0, nonce))
        self.assertEqual(len(check()[0]), 4096)
        item["attempts"].pop()
        with self.assertRaisesRegex(ValueError, "exhaustion omitted attempts"):
            check()

    def test_unknown_or_zero_cpu_is_not_a_measurement(self):
        for value in (None, 0, False):
            with self.subTest(value=value):
                records = self.records()
                self.first(records, "search")["timing"]["cpu_ns"] = value
                self.fails(records, "observation required|bounded nonnegative integer")

    def test_actual_phases_cannot_exceed_cohort_total(self):
        records = self.records()
        self.first(records, "cohort")["total"] = stamp(100)
        self.fails(records, "phases exceed")

    def test_wrong_verifier_proof_identity_is_rejected(self):
        records = self.records()
        self.first(records, "verifier")["proof_sha256"] = "00" * 32
        self.fails(records, "exact actual winner")

    def test_native_disagreement_is_retained_without_qualification(self):
        records = self.records()
        self.first(records, "verifier")["outcome"] = "Product"
        result = self.analyze(records)
        self.assertEqual(len(result["semantic_alerts"]), 1)
        self.assertIs(result["hardness_accepted"], False)

    def test_missing_reference_verification_is_rejected(self):
        records = self.records()
        records.remove(self.first(records, "verifier", path="reference"))
        records[-1]["verifier_count"] -= 1
        self.fails(records, "verification incomplete|coverage incomplete")

    def test_changed_complete_winner_bytes_are_rejected(self):
        records = self.records()
        candidate = self.first(records, "candidate")
        candidate["proof_hex"] = "00" + candidate["proof_hex"][2:]
        self.fails(records, "complete bytes/challenge")

    def test_missing_full_candidate_cannot_pass_hash_only(self):
        records = self.records()
        records.remove(self.first(records, "candidate"))
        records[-1]["candidate_count"] -= 1
        self.fails(records, "winner byte coverage")

    def test_missing_end_and_duplicate_json_keys_are_rejected(self):
        self.fails(self.original[:-1], "missing complete end")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            common.decode('{"schema":"a","schema":"b"}')

    def test_authority_promotion_and_numeric_false_are_rejected(self):
        for value in (True, 0):
            with self.subTest(value=value):
                records = self.records()
                records[0]["hardness_accepted"] = value
                self.fails(records, "cannot grant authority")


if __name__ == "__main__":
    unittest.main(verbosity=2)
