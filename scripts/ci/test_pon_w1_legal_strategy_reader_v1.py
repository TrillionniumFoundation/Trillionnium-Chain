#!/usr/bin/env python3
"""Synthetic reader controls; invented timings/verdicts are never native evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_legal_strategy_reader_v1 as reader

common = reader.common


def stamp(value):
    return dict(cpu_ns=value, wall_ns=value)


def row(kind, **fields):
    return dict(schema=reader.SCHEMA, kind=kind, **fields)


def fixture(name="zero", target_index=0, horizon=1, salt=0, exhausted=None, *, reader_api=reader):
    # Explicit fixture dependency; never switch a reader module's global profile.
    reader = reader_api

    def row(kind, **fields):
        return dict(schema=reader.SCHEMA, kind=kind, **fields)

    target = bytes.fromhex(reader.TARGETS[target_index])
    a, b, task, prefix = common.material(name)
    rows = [row("campaign", selector=reader.SELECTOR, **{"class": name}, target_index=target_index,
        target=target.hex(), reuse_winners=horizon, samples=reader.SAMPLES,
        attempt_budget=reader.ATTEMPT_BUDGET, seed=0, classes=list(reader.CLASSES),
        horizons=list(reader.HORIZONS), strategies=list(reader.STRATEGIES), paths=list(reader.PATHS),
        cases=list(reader.CASES), dispatch_arms=list(reader.DISPATCH_ARMS), material_setup=stamp(1000),
        clock="thread-cpu-and-monotonic-wall-ns", producer_timing_scope=reader.PRODUCER_SCOPE,
        verifier_timing_scope=reader.VERIFY_SCOPE, mutation_timing_scope=reader.MUTATION_SCOPE,
        cross_horizon_challenges="same-prefix-not-independent",
        **reader.FALSE_FLAGS), row("material", **{"class": name},
        source="hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture",
        task=task.hex(), a_hex=a.hex(), b_hex=b.hex())]
    counts = dict.fromkeys(("cohort", "search", "candidate", "product_mutation", "verifier"), 0)

    def add(kind, **fields):
        counts[kind] += 1
        rows.append(row(kind, **fields))

    for sample in range(reader.SAMPLES):
        searches = []
        for index in range(horizon):
            attempts = []
            for nonce in range(reader.ATTEMPT_BUDGET):
                context = reader.challenge(task, target, sample, index, nonce)
                perturbation = 0
                while True:
                    trace = common.pon_hash(b"synthetic-reader-not-W1", context,
                        salt.to_bytes(8, "little"), perturbation.to_bytes(8, "little"))
                    ticket = common.pon_hash(b"ticket", context, trace)
                    if (sample, index) != exhausted or ticket > target:
                        break
                    perturbation += 1
                hit = ticket <= target
                proof = prefix + trace
                attempts.append(dict(nonce=nonce, challenge=context.hex(), trace=trace.hex(),
                    ticket=ticket.hex(), proof_sha256=common.sha(proof), target_hit=hit))
                if hit:
                    break
            winner = dict(challenge=context.hex(), proof_sha256=common.sha(proof)) if hit else None
            searches.append(dict(attempts=attempts, winner=winner, proof=proof if hit else None,
                timing=stamp(len(attempts) * 10 + 10)))
        for order in range(len(reader.STRATEGIES)):
            strategy = reader.STRATEGIES[(sample + target_index + order) % len(reader.STRATEGIES)]
            probes = reader.dispatch_probes(name, strategy)
            add("cohort", sample=sample, strategy=strategy, invocation_order=order, setup_calls=1,
                searches=horizon, probes=probes, selected_arm=probes[-1], setup=stamp(100),
                total=stamp(101 + sum(s["timing"]["cpu_ns"] for s in searches)))
            for index, searched in enumerate(searches):
                add("search", sample=sample, strategy=strategy, search_index=index, setup_calls=0,
                    timing=searched["timing"].copy(), attempts=copy.deepcopy(searched["attempts"]),
                    status="target-hit-unverified" if searched["winner"] else "exhausted",
                    winner=copy.deepcopy(searched["winner"]))
                if searched["winner"] is None:
                    continue
                context = searched["winner"]["challenge"]
                if order == 0:
                    add("candidate", sample=sample, search_index=index, challenge=context,
                        proof_hex=searched["proof"].hex(), proof_sha256=common.sha(searched["proof"]))
                offset = common.PROOF_BYTES - 36
                before = int.from_bytes(searched["proof"][offset:offset + 4], "little")
                add("product_mutation", sample=sample, strategy=strategy, search_index=index,
                    source_proof_sha256=common.sha(searched["proof"]),
                    proof_sha256=common.sha(reader.product_last(searched["proof"])), offset=offset,
                    before=before, after=(before + 1) % common.Q, timing=stamp(20))
                for case in reader.CASES:
                    proof = searched["proof"] if case == "legal" else reader.product_last(searched["proof"])
                    for verify_order in range(len(reader.PATHS)):
                        path = reader.PATHS[(sample + order + index + verify_order) % len(reader.PATHS)]
                        add("verifier", sample=sample, strategy=strategy, search_index=index,
                            case=case, invocation_order=verify_order, path=path, challenge=context,
                            proof_sha256=common.sha(proof), outcome="Accepted" if case == "legal" else "Product",
                            timing=stamp(50))
    rows.append(row("end", **{kind + "_count": count for kind, count in counts.items()}, complete=True))
    return rows


class LegalStrategyReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="legal-strategy-reader-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def save(self, rows, name="synthetic.jsonl"):
        path = self.root / name
        with path.open("w") as output:
            for record in rows:
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
        return path

    def first(self, rows, kind, **fields):
        return next(r for r in rows if r["kind"] == kind and all(r.get(k) == v for k, v in fields.items()))

    def mutate_fails(self, kind, field, value, message, **fields):
        rows = copy.deepcopy(self.original)
        self.first(rows, kind, **fields)[field] = value
        with self.assertRaisesRegex(ValueError, message):
            reader.analyze_shard(self.save(rows))

    def test_frozen_contract_has_thirty_shards_and_original_reuse_horizons(self):
        self.assertEqual(len(reader.CLASSES) * len(reader.TARGETS) * len(reader.HORIZONS), 30)
        self.assertEqual(reader.HORIZONS, (1, 8, 64))
        self.assertEqual(reader.SAMPLES, 2)
        self.assertEqual(reader.ATTEMPT_BUDGET, 4096)

    def test_shard_preserves_costs_verifiers_and_nonqualification(self):
        result = reader.analyze_shard(self.save(self.original))
        self.assertEqual(result["record_consistency"], "PASS")
        self.assertEqual(result["selection"], {"class": "zero", "target_index": 0, "reuse_winners": 1})
        self.assertEqual(result["record_counts"]["verifier"], 32)
        self.assertEqual(result["semantic_alerts"], [])
        for key in (*reader.FALSE_FLAGS, "complete_fixed_grid", "w1_transcript_replayed", "native_execution_authenticated", "fastest_adversary_lower_bound"):
            self.assertIs(result[key], False)
        self.assertEqual(result["strategy_costs"][0]["actual_setup_calls"], 2)
        ratio = result["generic_over_frozen_dispatch_cpu"]
        self.assertEqual(ratio["numerator"], ratio["denominator"])

    def test_each_public_dispatch_branch_is_fixed_without_timing_oracle(self):
        expected = {"full-rank-field": 4, "zero": 2, "continuity-maintenance-v1": 1,
                    "one-zero-left-rank-one": 3, "one-zero-right-rank-one": 3}
        for name, count in expected.items():
            self.assertEqual(reader.dispatch_probes(name, reader.STRATEGIES[1]), list(reader.DISPATCH_ARMS[:count]))
        self.mutate_fails("cohort", "selected_arm", "paired-product", "dispatch mismatch", strategy=reader.STRATEGIES[1])

    def test_missing_misses_and_changed_losing_proof_digest_reject(self):
        rows = copy.deepcopy(self.original)
        searched = next(r for r in rows if r["kind"] == "search" and len(r["attempts"]) > 1)
        searched["attempts"].pop(0)
        with self.assertRaisesRegex(ValueError, "nonconsecutive"):
            reader.analyze_shard(self.save(rows))
        rows = copy.deepcopy(self.original)
        self.first(rows, "search")["attempts"][0]["proof_sha256"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "complete attempt proof"):
            reader.analyze_shard(self.save(rows))

    def test_full_exhaustion_retains_all_cost_and_no_imputed_winner(self):
        rows = fixture(exhausted=(0, 0))
        report = reader.analyze_shard(self.save(rows))
        for costs in report["strategy_costs"]:
            self.assertEqual(costs["exhausted_searches"], 1)
            self.assertEqual(costs["target_hits"], 1)
            self.assertGreaterEqual(costs["attempts"], reader.ATTEMPT_BUDGET + 1)
        searched = self.first(rows, "search", status="exhausted")
        searched["attempts"].pop()
        with self.assertRaisesRegex(ValueError, "exhaustion/misses incomplete"):
            reader.analyze_shard(self.save(rows))

    def test_all_actual_setups_and_nested_costs_are_required(self):
        self.mutate_fails("cohort", "setup_calls", 0, "one actual setup")
        self.mutate_fails("search", "setup_calls", 1, "hidden setup")
        self.mutate_fails("cohort", "total", stamp(1), "exceed inclusive total")
        for value in (None, 0, True):
            self.mutate_fails("cohort", "total", dict(cpu_ns=value, wall_ns=100), "positive measured|bounded nonnegative")

    def test_unexpected_legal_or_negative_verdict_stays_alert_and_null_ratio(self):
        for case, wrong in (("legal", "Transcript"), ("product-last", "Accepted")):
            rows = copy.deepcopy(self.original)
            self.first(rows, "verifier", case=case)["outcome"] = wrong
            report = reader.analyze_shard(self.save(rows))
            self.assertEqual(report["semantic_alerts"][0]["case"], case)
            self.assertIsNone(report["generic_over_frozen_dispatch_cpu"])
            self.assertTrue(any(r["cpu_per_observed_valid_winner"] is None for r in report["strategy_costs"]))

    def test_complete_candidate_and_every_negative_verifier_are_required(self):
        for kind in ("candidate", "verifier"):
            rows = copy.deepcopy(self.original)
            rows.remove(self.first(rows, kind))
            with self.assertRaisesRegex(ValueError, "requires.*candidate|coverage|identity/rotation"):
                reader.analyze_shard(self.save(rows))
        self.mutate_fails("verifier", "proof_sha256", "00" * 32, "identity/rotation", case="product-last")

    def test_product_mutation_is_measured_separately_and_binds_last_canonical_word(self):
        report = reader.analyze_shard(self.save(self.original))
        for costs in report["strategy_costs"]:
            self.assertEqual(costs["separate_product_mutation_total"], stamp(40))
        for field, value in (("offset", 4), ("before", 1), ("after", common.Q), ("source_proof_sha256", "00" * 32)):
            self.mutate_fails("product_mutation", field, value, "canonical final|bounded nonnegative")
        rows = copy.deepcopy(self.original)
        rows.remove(self.first(rows, "product_mutation"))
        with self.assertRaisesRegex(ValueError, "measured mutation"):
            reader.analyze_shard(self.save(rows))

    def test_fixed_scope_flags_and_grid_cannot_change(self):
        self.mutate_fails("campaign", "samples", 1, "fixed parameter")
        self.mutate_fails("campaign", "reuse_winners", 4, "fixed actual reuse")
        self.mutate_fails("campaign", "target", "ff" * 32, "fixed target")
        for flag in reader.FALSE_FLAGS:
            self.mutate_fails("campaign", flag, True, "qualification flag")

    def test_framing_duplicate_json_and_truncation_fail(self):
        path = self.save(self.original)
        raw = path.read_bytes()
        path.write_bytes(raw[:-1])
        with self.assertRaisesRegex(ValueError, "bounded complete"):
            reader.analyze_shard(path)
        path.write_bytes(raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1))
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            reader.analyze_shard(path)

    def test_complete_grid_counts_and_same_horizon_prefix_are_strict(self):
        # Reduce only the in-memory test contract. There is no shortened native
        # selector or reader CLI mode; these records are synthetic test fixtures.
        with patch.multiple(reader, CLASSES=("zero",), TARGETS=(reader.TARGETS[0],), HORIZONS=(1, 8)):
            paths = [self.save(fixture(horizon=h), f"h{h}.jsonl") for h in reader.HORIZONS]
            report = reader.analyze(paths)
            self.assertTrue(report["complete_fixed_grid"])
            self.assertFalse(report["policy_sample_count_satisfied"])
            self.assertFalse(report["work_profile_qualified"])
            self.assertEqual(report["unique_search_streams"], 16)
            with self.assertRaisesRegex(ValueError, "complete fixed shard grid"):
                reader.analyze(paths[:1])
            with self.assertRaisesRegex(ValueError, "duplicate/unknown shard"):
                reader.analyze([paths[0], paths[0]])
            changed = self.save(fixture(horizon=8, salt=1), "different-prefix.jsonl")
            with self.assertRaisesRegex(ValueError, "cross-horizon matched search prefix"):
                reader.analyze([paths[0], changed])


if __name__ == "__main__":
    unittest.main()
