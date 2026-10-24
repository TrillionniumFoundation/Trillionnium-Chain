#!/usr/bin/env python3
"""Reader boundaries using synthetic records, never native W1 cost evidence.

The fixture deliberately does not compute a W1 transcript: Accepted is a
synthetic recorded verdict. These tests exercise the evidence reader, not the
consensus relation, hardware costs, or independent qualification.
"""

import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout

READER = Path(__file__).resolve().parents[1] / "pon_w1_cost_matrix_reader.py"
SPEC = importlib.util.spec_from_file_location("cost_matrix_reader", READER)
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


def stamp(cpu, wall=None):
    return {"cpu_ns": cpu, "wall_ns": cpu if wall is None else wall}


def row(kind, **fields):
    return {"schema": reader.SCHEMA, "kind": kind, **fields}


def record_fixture():
    result = [row("campaign", samples=8, attempt_budget=4096, seed=0, target=reader.TARGET,
        arms=list(reader.ARMS), classes=list(reader.CLASSES),
        clock="thread-cpu-and-monotonic-wall-ns", material_setup=stamp(500_000),
        setup_amortization="modeled-setup-divisor-not-observed-multiwinner",
        public_listener_uses_work_facts=False, hardness_accepted=False, production_activation=False)]
    counts = {name: 0 for name in ("material", "producer", "candidate", "forgery", "verifier")}

    def add(kind, **fields):
        counts[kind] += 1
        result.append(row(kind, **fields))

    for name in reader.CLASSES:
        a, b, task, prefix = reader.material(name)
        add("material", **{"class": name}, source="hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture",
            task=task.hex(), a_hex=a.hex(), b_hex=b.hex())
        for sample in range(8):
            trials = []
            for nonce in range(4096):
                context = reader.challenge(task, sample, nonce)
                trace = reader.pon_hash(b"synthetic-reader-fixture-trace", context)
                proof = prefix + trace
                ticket = reader.pon_hash(b"ticket", context, trace)
                hit = ticket <= bytes.fromhex(reader.TARGET)
                trials.append({"nonce": nonce, "challenge": context.hex(), "trace": trace.hex(),
                    "ticket": ticket.hex(), "proof_sha256": reader.sha(proof), "target_hit": hit})
                if hit:
                    break
            else:
                raise AssertionError("synthetic fixture did not find a target hit")
            common = {"class": name, "sample": sample, "task": task.hex(), "target": reader.TARGET}
            for order in range(13):
                arm = reader.ARMS[(sample + order) % 13]
                supported = reader.supported(arm, name)
                add("producer", **common, arm=arm, invocation_order=order,
                    status="target-hit-unverified" if supported else "unsupported", setup_calls=1,
                    setup=stamp(100), search=stamp(300) if supported else None,
                    total=stamp(500) if supported else stamp(110),
                    attempts=copy.deepcopy(trials) if supported else [],
                    winner={"challenge": context.hex(), "proof_sha256": reader.sha(proof)} if supported else None)
            add("candidate", **common, challenge=context.hex(), proof_hex=proof.hex(), proof_sha256=reader.sha(proof))
            proofs = {"legal": proof}
            forged_trials = []
            for nonce in range(4096):
                forged_trace = reader.pon_hash(b"public-v3-from-zero-v1", context, nonce.to_bytes(8, "little"))
                ticket = reader.pon_hash(b"ticket", context, forged_trace)
                hit = ticket <= bytes.fromhex(reader.TARGET)
                forged_trials.append({"nonce": nonce, "challenge": context.hex(), "trace": forged_trace.hex(),
                    "ticket": ticket.hex(), "proof_sha256": None, "target_hit": hit})
                if hit:
                    break
            else:
                raise AssertionError("synthetic false-trace fixture did not find a hit")
            proofs["from-zero-transcript"] = b"PNW1" + a + b + bytes(4 * reader.CELLS) + forged_trace
            changed = bytearray(proof)
            offset = reader.PROOF_BYTES - 36
            struct.pack_into("<I", changed, offset, (struct.unpack_from("<I", changed, offset)[0] + 1) % reader.Q)
            proofs["product-last"] = bytes(changed)
            for variant in reader.VARIANTS:
                acquired = variant == "product-last"
                add("forgery", **common, variant=variant, challenge=context.hex(), status="target-hit-unverified",
                    setup=stamp(0 if acquired else 50), search=stamp(400), total=stamp(500),
                    attempts=[] if acquired else forged_trials,
                    winner={"trace": proofs[variant][-32:].hex(), "proof_sha256": reader.sha(proofs[variant])},
                    valid_proof_acquisition_used=acquired,
                    construction_scope="existing-valid-proof-clone-and-canonical-last-cell-increment" if acquired else "full-public-prefix-and-all-hash-trials")
            for case, tested in proofs.items():
                for path in reader.PATHS:
                    warm, facts = path == "facts-warm", path != "production"
                    hit = warm and case != "from-zero-transcript"
                    slot = lambda value: int.from_bytes(reader.pon_hash(b"w1-mathematical-fact-slot-v1", b"pon-matmul-transcript-64-v1", context, task, value[-32:])[:8], "little") % 256
                    eviction = int(warm and not hit and slot(proof) == slot(tested))
                    add("verifier", **common, case=case, path=path, challenge=context.hex(),
                        proof_sha256=reader.sha(tested), outcome=reader.EXPECTED_OUTCOME[case], timing=stamp(200 if case == "legal" else 250),
                        cache_capacity=256 if facts else None,
                        cache_before={"full_replays": int(warm), "hits": 0, "wait_polls": 0, "evictions": 0} if facts else None,
                        cache_after={"full_replays": int(warm) + int(not hit), "hits": int(hit), "wait_polls": 0, "evictions": eviction} if facts else None,
                        cache_setup=stamp(10) if facts else None,
                        warmup={"timing": stamp(200), "outcome": "Accepted", "proof_sha256": reader.sha(proof)} if warm else None)
    result.append(row("end", **{name + "_count": value for name, value in counts.items()}, complete=True))
    return result


class CostMatrixReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = record_fixture()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cost-matrix-reader-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic-records.jsonl"

    def records(self):
        return copy.deepcopy(self.fixture)

    def write(self, records):
        with self.path.open("w", encoding="utf-8", newline="\n") as target:
            for item in records:
                target.write(json.dumps(item, separators=(",", ":")) + "\n")
        return self.path

    def analyze(self, records):
        return reader.analyze(self.write(records))

    def first(self, records, kind, **fields):
        return next(item for item in records if item["kind"] == kind and all(item.get(key) == value for key, value in fields.items()))

    def fails(self, records, expression):
        with self.assertRaisesRegex(ValueError, expression):
            self.analyze(records)

    def test_complete_records_do_not_claim_service_or_authority(self):
        report = self.analyze(self.fixture)
        self.assertEqual(report["record_consistency"], "PASS")
        self.assertEqual(report["local_cost_gate"], "pass")
        self.assertEqual(report["local_observation_gate"], "not-accepted")
        self.assertEqual(report["service"]["status"], "unmeasured")
        self.assertEqual(report["semantic_alerts"], [])
        self.assertEqual(report["record_counts"]["producer"], 936)
        self.assertEqual(report["record_counts"]["verifier"], 648)
        self.assertEqual(len(report["costs"]), 27)
        self.assertEqual(report["profile_sha256"], reader.PROFILE_SHA256)
        self.assertTrue(report["matrix_product_reconstructed"])
        self.assertFalse(report["w1_transcript_replayed"])
        self.assertFalse(report["material_setup_charged_per_producer"])
        for flag in reader.FALSE_FLAGS:
            self.assertIs(report[flag], False)

    def test_shared_material_setup_is_not_duplicated_into_costs(self):
        rows = self.records()
        rows[0]["material_setup"] = stamp(2**63)
        report = self.analyze(rows)
        self.assertEqual(report["material_setup"]["cpu_ns"], 2**63)
        self.assertEqual(report["costs"][0]["cheapest_known_cohort_mean_cpu_ns"]["value"], 500.0)

    def test_fixed_arm_mean_selection_prevents_per_sample_fastest_mixing(self):
        rows = self.records()
        for item in rows:
            if item["kind"] != "producer" or item["class"] != "periodic-dense-fixture" or item["status"] == "unsupported":
                continue
            if item["arm"] == "scalar-original":
                total = 100 if item["sample"] % 2 == 0 else 900
            elif item["arm"] == "prepared-generic":
                total = 900 if item["sample"] % 2 == 0 else 100
            else:
                total = 1000
            item.update(setup=stamp(0), search=stamp(total - 1), total=stamp(total))
        report = self.analyze(rows)
        cost = report["costs"][0]
        self.assertEqual(cost["selected_fixed_cohort_algorithm"], "scalar-original")
        self.assertEqual(cost["cheapest_known_cohort_mean_cpu_ns"]["value"], 500.0)
        self.assertNotEqual(cost["cheapest_known_cohort_mean_cpu_ns"]["value"], 100.0)

    def test_setup_is_subtracted_once_and_horizon_is_explicitly_modeled(self):
        report = self.analyze(self.fixture)
        costs = report["costs"][:3]
        self.assertEqual([cost["setup_amortization_winners"] for cost in costs], [1, 8, 64])
        self.assertEqual([cost["cheapest_known_cohort_mean_cpu_ns"]["value"] for cost in costs], [500, 412.5, 401.5625])
        for cost in costs:
            self.assertTrue(cost["amortization_is_modeled"])
            self.assertEqual(cost["observed_winning_searches_per_supported_arm"], 8)

    def test_warm_cache_never_replaces_failed_raw_gate(self):
        rows = self.records()
        for item in rows:
            if item["kind"] == "verifier":
                item["timing"] = stamp(2000 if item["path"] == "production" else 1)
        report = self.analyze(rows)
        self.assertEqual(report["local_cost_gate"], "not-accepted")
        self.assertEqual(report["record_consistency"], "PASS")
        self.assertFalse(report["cache_paths_replace_default_gate"])
        for cost in report["costs"]:
            self.assertEqual(cost["default_cost_gate"], "not-accepted")
            self.assertEqual(cost["verification_paths"]["facts-warm"]["cost_gate"], "pass")
            self.assertEqual(cost["verification_paths"]["facts-warm"]["legal_cache_costs"]["warmup_cpu_mean_ns"]["value"], 200)
            for variant in reader.VARIANTS:
                self.assertEqual(cost["verification_paths"]["facts-warm"]["forgeries"][variant]["warmup_cpu_mean_ns"]["value"], 200)

    def test_marginal_mutation_does_not_recharge_genuine_proof_acquisition(self):
        rows = self.records()
        for item in rows:
            if item["kind"] == "forgery" and item["variant"] == "product-last":
                item.update(setup=stamp(0), search=stamp(1), total=stamp(2))
        report = self.analyze(rows)
        self.assertEqual(report["local_cost_gate"], "not-accepted")
        mutation = report["costs"][0]["verification_paths"]["production"]["forgeries"]["product-last"]
        self.assertEqual(mutation["measured_total_construction_cpu_mean_ns"]["value"], 2)
        self.assertEqual(mutation["marginal_rejection_amplification"]["ratio"]["value"], 125)
        self.assertIs(mutation["genuine_proof_acquisition_charged_again"], False)

    def test_unknown_supported_algorithm_cannot_silently_be_dropped_for_green(self):
        rows = self.records()
        self.first(rows, "producer", arm="scalar-original")["total"]["cpu_ns"] = None
        report = self.analyze(rows)
        self.assertEqual(report["local_cost_gate"], "unmeasured")
        self.assertIsNotNone(report["costs"][0]["selected_fixed_cohort_algorithm"])
        self.assertFalse(report["costs"][0]["all_supported_cohorts_measured"])
        self.assertEqual(report["costs"][0]["verification_paths"]["production"]["winner_to_verifier"]["gate"], "unmeasured")

    def test_missing_cpu_never_uses_known_wall_time(self):
        rows = self.records()
        for item in rows:
            if item["kind"] == "verifier" and item["path"] == "production":
                item["timing"]["cpu_ns"] = None
        report = self.analyze(rows)
        self.assertEqual(report["local_cost_gate"], "unmeasured")
        self.assertIsNone(report["costs"][0]["verification_paths"]["production"]["winner_to_verifier"]["ratio"])

    def test_zero_denominator_remains_unmeasured(self):
        rows = self.records()
        for item in rows:
            if item["kind"] == "forgery":
                item.update(setup=stamp(0), search=stamp(0), total=stamp(0))
        report = self.analyze(rows)
        self.assertEqual(report["local_cost_gate"], "unmeasured")
        self.assertIsNone(report["costs"][0]["verification_paths"]["production"]["forgeries"]["product-last"]["marginal_rejection_amplification"]["ratio"])

    def test_unexpected_native_verdict_is_retained_not_hidden_as_complete(self):
        rows = self.records()
        self.first(rows, "verifier", case="product-last", path="production")["outcome"] = "AcceptedWrongProduct"
        report = self.analyze(rows)
        self.assertEqual(report["record_consistency"], "PASS")
        self.assertEqual(report["semantic_alerts"][0]["actual"], "AcceptedWrongProduct")
        self.assertEqual(report["local_cost_gate"], "not-accepted")
        self.assertEqual(report["costs"][0]["verification_paths"]["production"]["cost_gate"], "not-accepted")

    def test_unavailable_fact_outcome_and_failed_warmup_block_acceptance(self):
        rows = self.records()
        item = self.first(rows, "verifier", path="facts-warm")
        item["outcome"] = "Unavailable"
        item["warmup"]["outcome"] = "Transcript"
        item["cache_after"] = {"full_replays": 2, "hits": 0, "wait_polls": 0, "evictions": 0}
        report = self.analyze(rows)
        self.assertEqual(len(report["semantic_alerts"]), 2)
        self.assertEqual(report["local_cost_gate"], "not-accepted")

    def test_unavailable_warmup_before_replay_remains_a_semantic_failure(self):
        rows = self.records()
        item = self.first(rows, "verifier", path="facts-warm")
        item["outcome"] = item["warmup"]["outcome"] = "Unavailable"
        item["cache_before"] = item["cache_after"] = {"full_replays": 0, "hits": 0, "wait_polls": 0, "evictions": 0}
        report = self.analyze(rows)
        self.assertEqual(report["record_consistency"], "PASS")
        self.assertEqual(len(report["semantic_alerts"]), 2)
        self.assertEqual(report["local_cost_gate"], "not-accepted")

    def test_cpu_and_wall_are_not_assumed_simultaneous(self):
        rows = self.records()
        self.first(rows, "producer")["setup"]["wall_ns"] = 99
        self.assertEqual(self.analyze(rows)["local_cost_gate"], "pass")

    def test_phase_nesting_checked_separately_for_each_clock(self):
        for axis in ("cpu_ns", "wall_ns"):
            with self.subTest(axis=axis):
                rows = self.records()
                self.first(rows, "producer")["search"][axis] = 401
                self.fails(rows, "disjoint phases exceed total")

    def test_policy_bytes_cannot_be_changed_to_weaken_gate(self):
        altered = Path(self.directory.name) / "altered-policy.json"
        altered.write_bytes(reader.PROFILE.read_bytes().replace(b'"minimum_winner_to_verifier_ratio": 1', b'"minimum_winner_to_verifier_ratio": 0'))
        with mock.patch.object(reader, "PROFILE", altered):
            self.fails(self.fixture, "original acceptance profile bytes changed")

    def test_campaign_exact_fixed_scope_and_unknown_fields(self):
        changes = {"samples": 7, "attempt_budget": 10, "seed": 1, "target": "ff" * 32,
            "arms": list(reversed(reader.ARMS)), "classes": list(reader.CLASSES[:-1]),
            "clock": "wall-only", "setup_amortization": "measured-64", "hardness_accepted": True}
        for key, value in changes.items():
            with self.subTest(field=key):
                rows = self.records()
                rows[0][key] = value
                self.fails(rows, "campaign|scope|authority")
        rows = self.records()
        rows[0]["work_profile"] = "pon-matmul-transcript-64-v1"
        self.fails(rows, "exact fields")

    def test_material_source_task_and_complete_bytes_are_exact(self):
        for key, value in (("a_hex", "00" * 16384), ("b_hex", "FF" * 16384), ("task", "00" * 32), ("source", "production-model")):
            with self.subTest(field=key):
                rows = self.records()
                self.first(rows, "material")[key] = value
                self.fails(rows, "material|canonical")
        rows = self.records()
        self.first(rows, "material")["timing"] = stamp(100)
        self.fails(rows, "exact fields")

    def test_rotation_duplicate_and_missing_arm_are_rejected(self):
        rows = self.records()
        self.first(rows, "producer")["invocation_order"] = 1
        self.fails(rows, "rotation")
        rows = self.records()
        index = next(i for i, item in enumerate(rows) if item["kind"] == "producer")
        rows.insert(index, copy.deepcopy(rows[index]))
        self.fails(rows, "rotation")
        rows = self.records()
        rows.pop(index)
        self.fails(rows, "rotation")

    def test_unsupported_is_not_zero_cost_or_silent_fallback(self):
        rows = self.records()
        item = self.first(rows, "producer", status="unsupported")
        item["status"] = "target-hit-unverified"
        self.fails(rows, "unsupported arm misreported")
        rows = self.records()
        item = self.first(rows, "producer", status="unsupported")
        item["search"] = stamp(0)
        self.fails(rows, "unsupported search must be null")

    def test_trial_nonce_challenge_ticket_hash_and_hit_are_bound(self):
        changes = (("nonce", 1), ("challenge", "00" * 32), ("ticket", "00" * 32),
                   ("proof_sha256", "00" * 32), ("target_hit", None))
        for key, value in changes:
            with self.subTest(field=key):
                rows = self.records()
                self.first(rows, "producer")["attempts"][0][key] = value
                self.fails(rows, "nonce|challenge|ticket|SHA|target-hit")

    def test_supported_streams_cannot_mix_different_legal_searches(self):
        rows = self.records()
        item = self.first(rows, "producer", arm="prepared-generic")
        task = bytes.fromhex(item["task"])
        prefix = reader.material(item["class"])[3]
        trials = []
        for nonce in range(4096):
            context = reader.challenge(task, item["sample"], nonce)
            trace = reader.pon_hash(b"different-synthetic-stream", context)
            ticket = reader.pon_hash(b"ticket", context, trace)
            hit = ticket <= bytes.fromhex(reader.TARGET)
            trials.append({"nonce": nonce, "challenge": context.hex(), "trace": trace.hex(), "ticket": ticket.hex(),
                "proof_sha256": reader.sha(prefix + trace), "target_hit": hit})
            if hit:
                break
        item["attempts"] = trials
        item["winner"] = {key: trials[-1][key] for key in ("challenge", "proof_sha256")}
        self.fails(rows, "supported legal streams disagree")

    def test_early_hit_and_fake_exhaustion_are_rejected(self):
        rows = self.records()
        item = self.first(rows, "producer")
        item["attempts"].append(copy.deepcopy(item["attempts"][-1]))
        self.fails(rows, "first target hit")
        rows = self.records()
        item = self.first(rows, "producer")
        item.update(status="exhausted", winner=None)
        self.fails(rows, "search status mismatch")

    def test_complete_exhausted_cohort_is_retained_without_cost_green(self):
        rows = self.records()
        name, sample = reader.CLASSES[0], 0
        _, _, task, prefix = reader.material(name)
        trials = []
        for nonce in range(reader.ATTEMPT_BUDGET):
            context = reader.challenge(task, sample, nonce)
            for salt in range(4096):
                trace = reader.pon_hash(b"synthetic-exhausted-reader-fixture", context, salt.to_bytes(8, "little"))
                ticket = reader.pon_hash(b"ticket", context, trace)
                if ticket > bytes.fromhex(reader.TARGET):
                    break
            else:
                raise AssertionError("bounded synthetic miss construction exhausted")
            trials.append({"nonce": nonce, "challenge": context.hex(), "trace": trace.hex(), "ticket": ticket.hex(),
                "proof_sha256": reader.sha(prefix + trace), "target_hit": False})
        kept = []
        for item in rows:
            if item.get("class") == name and item.get("sample") == sample:
                if item["kind"] in ("candidate", "forgery", "verifier"):
                    continue
                if item["kind"] == "producer" and item["status"] != "unsupported":
                    item.update(attempts=trials, status="exhausted", winner=None)
            kept.append(item)
        for kind in ("candidate", "forgery", "verifier"):
            kept[-1][kind + "_count"] = sum(item["kind"] == kind for item in kept)
        report = self.analyze(kept)
        self.assertEqual(report["record_consistency"], "PASS")
        self.assertEqual(report["local_cost_gate"], "unmeasured")
        self.assertIsNone(report["costs"][0]["selected_fixed_cohort_algorithm"])
        self.assertEqual(report["costs"][0]["observed_winning_searches_per_supported_arm"], 7)
        self.assertEqual(report["producer_cohorts"][0]["status_counts"], {"exhausted": 1, "target-hit-unverified": 7})

    def test_original_exact_one_ratio_thresholds_remain_inclusive(self):
        rows = self.records()
        for item in rows:
            if item["kind"] == "producer" and item["status"] != "unsupported":
                item.update(setup=stamp(0), search=stamp(199), total=stamp(200))
            if item["kind"] == "forgery":
                item.update(setup=stamp(0), search=stamp(249), total=stamp(250))
        report = self.analyze(rows)
        self.assertEqual(report["local_cost_gate"], "pass")
        cost = report["costs"][0]["verification_paths"]["production"]
        self.assertEqual(cost["winner_to_verifier"]["ratio"]["numerator"], 1)
        self.assertEqual(cost["winner_to_verifier"]["ratio"]["denominator"], 1)
        self.assertEqual(cost["forgeries"]["product-last"]["marginal_rejection_amplification"]["ratio"]["value"], 1)

    def test_candidates_bind_canonical_product_trace_and_complete_sha(self):
        for field, value in (("challenge", "00" * 32), ("proof_sha256", "00" * 32), ("proof_hex", "00" * reader.PROOF_BYTES)):
            with self.subTest(field=field):
                rows = self.records()
                self.first(rows, "candidate")[field] = value
                self.fails(rows, "candidate")
        rows = self.records()
        item = self.first(rows, "candidate")
        value = bytearray.fromhex(item["proof_hex"])
        struct.pack_into("<I", value, reader.PROOF_BYTES - 36, reader.Q)
        item["proof_hex"], item["proof_sha256"] = value.hex(), reader.sha(value)
        self.fails(rows, "canonical A/B/C/trace")

    def test_forgery_trial_hash_acquisition_scope_and_mutation_are_bound(self):
        for variant, field, value in (("from-zero-transcript", "valid_proof_acquisition_used", True),
                                     ("product-last", "valid_proof_acquisition_used", False),
                                     ("from-zero-transcript", "construction_scope", "borrowed-valid-proof")):
            with self.subTest(variant=variant, field=field):
                rows = self.records()
                self.first(rows, "forgery", variant=variant)[field] = value
                self.fails(rows, "scope mismatch")
        rows = self.records()
        self.first(rows, "forgery", variant="from-zero-transcript")["attempts"][0]["proof_sha256"] = "00" * 32
        self.fails(rows, "must not claim a constructed buffer")
        rows = self.records()
        self.first(rows, "forgery", variant="product-last")["winner"]["proof_sha256"] = "00" * 32
        self.fails(rows, "forgery full-byte SHA")

    def test_verifier_exact_proof_and_all_three_paths_required(self):
        rows = self.records()
        self.first(rows, "verifier")["proof_sha256"] = "00" * 32
        self.fails(rows, "exact available proof")
        rows = self.records()
        index = next(i for i, item in enumerate(rows) if item["kind"] == "verifier")
        rows.pop(index)
        rows[-1]["verifier_count"] -= 1
        self.fails(rows, "verifier coverage mismatch")

    def test_cache_warmup_counters_capacity_and_eviction_are_checked(self):
        for path, field, value in (("production", "cache_capacity", 256), ("facts-cold", "cache_capacity", 128),
                                  ("facts-warm", "warmup", None)):
            with self.subTest(path=path, field=field):
                rows = self.records()
                self.first(rows, "verifier", path=path)[field] = value
                self.fails(rows, "cache|warmup")
        rows = self.records()
        self.first(rows, "verifier", path="facts-warm")["warmup"]["proof_sha256"] = "00" * 32
        self.fails(rows, "genuine candidate")
        for path in ("facts-cold", "facts-warm"):
            with self.subTest(path=path):
                rows = self.records()
                self.first(rows, "verifier", path=path)["cache_after"]["hits"] += 1
                self.fails(rows, "replay/hit/eviction mismatch")
        rows = self.records()
        item = self.first(rows, "verifier", path="facts-warm", case="from-zero-transcript")
        item["cache_after"]["evictions"] = 1 - item["cache_after"]["evictions"]
        self.fails(rows, "replay/hit/eviction mismatch")

    def test_verifier_may_precede_associated_forgery_but_not_candidate(self):
        rows = self.records()
        index = next(i for i, item in enumerate(rows) if item["kind"] == "candidate")
        stop = next(i for i in range(index + 1, len(rows)) if rows[i]["kind"] == "producer")
        section = rows[index + 1:stop]
        rows[index + 1:stop] = sorted(section, key=lambda item: item["kind"] != "verifier")
        self.assertEqual(self.analyze(rows)["record_consistency"], "PASS")
        rows = self.records()
        verifier_index = next(i for i, item in enumerate(rows) if item["kind"] == "verifier")
        rows.insert(index, rows.pop(verifier_index))
        self.fails(rows, "before candidate")

    def test_end_and_full_grid_cannot_be_forged(self):
        rows = self.records()
        rows[-1]["complete"] = False
        self.fails(rows, "incomplete native campaign")
        rows = self.records()
        rows[-1]["producer_count"] -= 1
        self.fails(rows, "end count mismatch")
        rows = self.records()
        rows.append(copy.deepcopy(rows[-1]))
        self.fails(rows, "after end")
        self.fails(self.fixture[:-1], "missing complete end")

    def test_non_integer_overflow_duplicate_fields_and_truncation_rejected(self):
        for value in (True, -1, 2**64, 1.5):
            with self.subTest(value=value):
                rows = self.records()
                rows[0]["material_setup"]["cpu_ns"] = value
                self.fails(rows, "integer|number")
        raw = json.dumps(self.fixture[0]).replace('"samples": 8', '"samples": 8,"samples": 8') + "\n"
        self.path.write_text(raw)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            reader.analyze(self.path)
        self.path.write_text(json.dumps(self.fixture[0]))
        with self.assertRaisesRegex(ValueError, "truncated JSONL"):
            reader.analyze(self.path)
        self.path.write_bytes(b" " * (reader.MAX_LINE + 1))
        with self.assertRaisesRegex(ValueError, "oversized"):
            reader.analyze(self.path)

    def test_cli_distinguishes_record_validity_cost_gate_and_semantic_alert(self):
        rows = self.records()
        for item in rows:
            if item["kind"] == "verifier" and item["path"] == "production":
                item["timing"] = stamp(2000)
        self.write(rows)
        for arguments, expected in (([], 0), (["--require-cost-gates"], 2)):
            with self.subTest(arguments=arguments), mock.patch.object(sys, "argv", [str(READER), str(self.path), *arguments]), redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(reader.main(), expected)
                self.assertEqual(json.loads(captured.getvalue())["local_cost_gate"], "not-accepted")
        self.first(rows, "verifier")["outcome"] = "Product"
        self.write(rows)
        with mock.patch.object(sys, "argv", [str(READER), str(self.path)]), redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(reader.main(), 1)
            self.assertEqual(json.loads(captured.getvalue())["record_consistency"], "PASS")
        self.path.write_text("{}\n")
        with mock.patch.object(sys, "argv", [str(READER), str(self.path)]), redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(reader.main(), 2)
            self.assertEqual(json.loads(captured.getvalue())["record_consistency"], "FAIL")


if __name__ == "__main__":
    unittest.main()
