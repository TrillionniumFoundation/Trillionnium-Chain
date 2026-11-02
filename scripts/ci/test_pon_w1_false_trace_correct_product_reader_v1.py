#!/usr/bin/env python3
"""Synthetic capture-boundary tests, never native W1 execution or CPU evidence.

False-trace hash recipes and complete attack bytes are real; timestamps and
claimed native verdicts here are invented solely to exercise the strict reader.
"""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_false_trace_correct_product_reader_v1 as reader

common = reader.common


def stamp(number):
    return {"cpu_ns": number, "wall_ns": number}


def row(kind, **fields):
    return {"schema": reader.SCHEMA, "kind": kind, **fields}


def fixture():
    paths, schema, selector = reader.PATHS, reader.SCHEMA, reader.SELECTOR
    def row(kind, **fields):
        return {"schema": schema, "kind": kind, **fields}
    records = [row("campaign", selector=selector, samples=reader.SAMPLES,
        searches_per_setup=reader.SEARCHES, attempt_budget=reader.ATTEMPT_BUDGET, seed=0,
        target=reader.TARGET, paths=list(paths), classes=list(reader.CLASSES),
        clock="thread-cpu-and-monotonic-wall-ns", material_setup=stamp(1000),
        setup_reuse=reader.SETUP_SCOPE, attacker_timing_scope=reader.ATTACK_SCOPE,
        verifier_timing_scope=reader.VERIFY_SCOPE, **reader.FALSE_FLAGS)]
    counts = dict.fromkeys(("material", "cohort", "search", "candidate", "verifier"), 0)

    def add(kind, **fields):
        counts[kind] += 1
        records.append(row(kind, **fields))

    for name in reader.CLASSES:
        a, b, task, prefix = common.material(name)
        add("material", **{"class": name}, source="hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture",
            task=task.hex(), a_hex=a.hex(), b_hex=b.hex())
        for sample in range(reader.SAMPLES):
            fields = {"class": name, "sample": sample, "task": task.hex(), "target": reader.TARGET}
            add("cohort", **fields, setup_calls=1, searches=reader.SEARCHES, setup=stamp(100), total=stamp(1500))
            for search in range(reader.SEARCHES):
                context = reader.challenge(task, sample, search)
                trials = []
                for nonce in range(reader.ATTEMPT_BUDGET):
                    trace = common.pon_hash(b"public-v3-from-zero-v1", context, nonce.to_bytes(8, "little"))
                    ticket = common.pon_hash(b"ticket", context, trace)
                    hit = ticket <= bytes.fromhex(reader.TARGET)
                    trials.append({"nonce": nonce, "challenge": context.hex(), "trace": trace.hex(),
                        "ticket": ticket.hex(), "proof_sha256": None, "target_hit": hit})
                    if hit:
                        break
                else:
                    raise AssertionError("fixed synthetic hash search unexpectedly exhausted")
                proof = prefix + trace
                add("search", **fields, search_index=search, setup_calls=0, timing=stamp(300),
                    status="target-hit-unverified", attempts=trials,
                    winner={"challenge": context.hex(), "proof_sha256": common.sha(proof)})
                add("candidate", **fields, search_index=search, challenge=context.hex(),
                    proof_hex=proof.hex(), proof_sha256=common.sha(proof))
                for order in range(len(paths)):
                    path = paths[(sample + search + order) % len(paths)]
                    add("verifier", **fields, search_index=search, path=path, invocation_order=order,
                        challenge=context.hex(), proof_sha256=common.sha(proof), outcome="Transcript", timing=stamp(200))
    records.append(row("end", **{kind + "_count": value for kind, value in counts.items()}, complete=True))
    return records


class CorrectProductFalseTraceReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="false-reuse-reader-")
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

    def test_complete_grid_retains_full_cost_and_never_grants_qualification(self):
        result = self.analyze(self.original)
        self.assertEqual(result["record_consistency"], "PASS")
        self.assertEqual(result["record_counts"], {"campaign": 1, "material": 9, "cohort": 72,
            "search": 288, "candidate": 288, "verifier": 288, "end": 1})
        self.assertEqual(result["semantic_alerts"], [])
        for flag in (*reader.FALSE_FLAGS, "fastest_adversary_lower_bound", "public_attack_amplification_measured",
                     "w1_transcript_replayed", "source_applicability_verified", "modeled_setup_division_used"):
            self.assertIs(result[flag], False)
        for item in result["actual_reuse_cohorts"]:
            self.assertEqual(item["actual_setup_calls"], 8)
            self.assertEqual(item["actual_searches"], 32)
            self.assertEqual(item["full_attacker_cohort_total"]["cpu_ns"], 12000)
            self.assertEqual(item["setup"]["cpu_ns"], 800)
            self.assertEqual(item["search"]["cpu_ns"], 9600)
            for path in reader.PATHS:
                self.assertEqual(item["verification"][path]["cpu_ns"], 6400)
                self.assertEqual(item["receiver_rejection_cpu_over_full_attacker_cpu"][path], 6400 / 12000)

    def test_empty_grid_and_deleted_cohort_do_not_reduce_denominators(self):
        self.fails([self.original[0], row("end", material_count=0, cohort_count=0, search_count=0,
            candidate_count=0, verifier_count=0, complete=True)], "grid incomplete")
        records = self.records()
        records.remove(self.first(records, "cohort"))
        self.fails(records, "current actual cohort")

    def test_setup_missing_repeated_or_modeled_cannot_pass(self):
        for kind, value, message in (("cohort", 0, "one actual"), ("search", 1, "rebuilt")):
            with self.subTest(kind=kind):
                records = self.records()
                self.first(records, kind)["setup_calls"] = value
                self.fails(records, message)
        records = self.records()
        records[0]["setup_reuse"] = "modeled-setup-divisor"
        self.fails(records, "one actual")

    def test_every_fixed_parameter_and_provenance_flag_is_enforced(self):
        for field in ("samples", "searches_per_setup", "attempt_budget", "seed"):
            with self.subTest(field=field):
                records = self.records()
                records[0][field] += 1
                self.fails(records, "fixed campaign")
        for flag in reader.FALSE_FLAGS:
            with self.subTest(flag=flag):
                records = self.records()
                records[0][flag] = True
                self.fails(records, "cannot acquire")

    def test_borrowed_or_replayed_challenge_cannot_replace_independent_search(self):
        records = self.records()
        first = self.first(records, "search", search_index=0)
        second = self.first(records, "search", search_index=1)
        second["attempts"] = copy.deepcopy(first["attempts"])
        second["winner"] = copy.deepcopy(first["winner"])
        self.fails(records, "challenge recipe")

    def test_omitted_hash_miss_and_forged_ticket_are_rejected(self):
        records = self.records()
        searched = next(record for record in records if record["kind"] == "search" and len(record["attempts"]) > 1)
        searched["attempts"].pop(0)
        self.fails(records, "nonconsecutive nonce")
        records = self.records()
        self.first(records, "search")["attempts"][0]["ticket"] = "00" * 32
        self.fails(records, "ticket hash")

    def test_wrong_product_cannot_replace_independently_reconstructed_AB(self):
        records = self.records()
        candidate = self.first(records, "candidate")
        proof = bytearray.fromhex(candidate["proof_hex"])
        proof[4 + 8 * common.CELLS] ^= 1
        candidate["proof_hex"], candidate["proof_sha256"] = proof.hex(), common.sha(proof)
        self.fails(records, "complete forged bytes")

    def test_full_candidate_and_every_verifier_are_required(self):
        for kind in ("candidate", "verifier"):
            with self.subTest(kind=kind):
                records = self.records()
                records.remove(self.first(records, kind))
                self.fails(records, "complete forged bytes|order/coverage|verifier coverage")

    def test_verifier_false_acceptance_is_retained_and_never_reported_as_rejection_ratio(self):
        records = self.records()
        self.first(records, "verifier", path="production")["outcome"] = "Accepted"
        report = self.analyze(records)
        self.assertEqual(len(report["semantic_alerts"]), 1)
        self.assertEqual(report["semantic_alerts"][0]["actual"], "Accepted")
        self.assertIsNone(report["actual_reuse_cohorts"][0]["receiver_rejection_cpu_over_full_attacker_cpu"]["production"])

    def test_native_noise_exhaustion_is_preserved_as_a_semantic_alert(self):
        records = self.records()
        self.first(records, "verifier", path="production")["outcome"] = "NoiseBudget"
        report = self.analyze(records)
        self.assertEqual(report["semantic_alerts"][0]["actual"], "NoiseBudget")
        self.assertIsNone(report["actual_reuse_cohorts"][0]["receiver_rejection_cpu_over_full_attacker_cpu"]["production"])

    def test_unknown_zero_and_boolean_cpu_cannot_become_measured_cost(self):
        for value in (None, 0, True):
            with self.subTest(value=value):
                records = self.records()
                self.first(records, "cohort")["total"]["cpu_ns"] = value
                self.fails(records, "positive actual|bounded nonnegative")

    def test_total_cannot_drop_setup_or_failed_search_cost(self):
        records = self.records()
        self.first(records, "cohort")["total"] = stamp(1200)
        self.fails(records, "phases exceed")

    def test_full_search_exhaustion_cannot_be_claimed_after_a_target_hit(self):
        records = self.records()
        self.first(records, "search")["status"] = "exhausted"
        self.first(records, "search")["winner"] = None
        self.fails(records, "search status mismatch")

    def test_relabelled_schema_added_fields_and_truncated_capture_are_rejected(self):
        records = self.records()
        records[0]["schema"] = common.SCHEMA
        self.fails(records, "explicit correct-product")
        records = self.records()
        records[0]["network_safe"] = True
        self.fails(records, "exact fields")
        self.analyze(self.original)
        raw = self.path.read_bytes()
        for changed in (raw[:-1], raw.replace(b'"kind":"campaign"', b'"kind":"campaign","kind":"campaign"', 1)):
            self.path.write_bytes(changed)
            with self.assertRaises(ValueError):
                reader.analyze(self.path)

    def test_same_class_sample_but_wrong_search_verifier_binding_is_rejected(self):
        records = self.records()
        first = self.first(records, "verifier")
        first["search_index"] = 1
        self.fails(records, "outside current search")

    def test_counts_cannot_hide_omitted_or_extra_native_work(self):
        records = self.records()
        records[-1]["verifier_count"] -= 1
        self.fails(records, "count mismatch")
        records = self.records()
        records.append(copy.deepcopy(records[-1]))
        self.fails(records, "after complete end|bounded complete")


    def test_rehashed_zero_product_substitution_cannot_evade_independent_product_check(self):
        records = self.records()
        search = self.first(records, "search")
        candidate = self.first(records, "candidate")
        verifier = self.first(records, "verifier")
        proof = bytearray.fromhex(candidate["proof_hex"])
        self.assertNotEqual(proof[4 + 8 * common.CELLS:-32], bytes(common.CELLS * 4))
        proof[4 + 8 * common.CELLS:-32] = bytes(common.CELLS * 4)
        digest = common.sha(proof)
        candidate["proof_hex"], candidate["proof_sha256"] = proof.hex(), digest
        search["winner"]["proof_sha256"] = digest
        verifier["proof_sha256"] = digest
        self.fails(records, "winner does not bind full forged bytes")

    def test_old_schema_and_challenge_domains_cannot_be_relabelled(self):
        records = self.records()
        records[0]["schema"] = reader.original.SCHEMA
        self.fails(records, "explicit correct-product")
        records = self.records()
        search = self.first(records, "search")
        task = bytes.fromhex(search["task"])
        old = reader.original.challenge(task, search["sample"], search["search_index"])
        search["attempts"][0]["challenge"] = old.hex()
        self.fails(records, "challenge recipe mismatch")

    def test_scalar_product_computation_covers_nonzero_dense_and_zero_classes(self):
        records = self.records()
        report = self.analyze(records)
        self.assertIs(report["canonical_product_independently_reconstructed"], True)
        for name in reader.CLASSES:
            a, b, _, prefix = common.material(name)
            import struct
            av, bv = struct.unpack("<4096I", a), struct.unpack("<4096I", b)
            words = struct.unpack("<4096I", prefix[4 + 8 * common.CELLS:])
            for i, j in ((0, 0), (31, 17), (63, 63)):
                scalar = sum(av[i * 64 + k] * bv[k * 64 + j] for k in range(64)) % common.Q
                self.assertEqual(words[i * 64 + j], scalar)


if __name__ == "__main__":
    unittest.main()
