#!/usr/bin/env python3
"""Parser attack controls. Generated rows below are NOT native W1 evidence.

The parser deliberately cannot authenticate a trace or a claimed verifier.
These synthetic records test exact binding, ledger completeness and accounting;
the separate native example tests and its raw integration run supply execution.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_rank_batch_reader_v5 as reader


def measured(n=1):
    return {"cpu_ns": n, "wall_ns": n}


def synthetic_parser_records(target_index=3):
    """Only a deterministic parser fixture, never written as an observation."""
    name = "zero"
    a, b, task, prefix, ranks, source = reader.material(name)
    target = bytes.fromhex(reader.TARGETS[target_index])
    records = []

    def emit(kind, **row):
        row.update(schema=reader.SCHEMA, kind=kind)
        records.append(row)

    emit("header", **reader.STATIC, **dict(class_=name))
    header = records[0]
    header["class"] = header.pop("class_")
    header.update(target_index=target_index, target=target.hex(), horizon=1,
        purpose=reader.PURPOSES[target_index], attempt_limit=3, task=task.hex(),
        a_hex=a.hex(), b_hex=b.hex(), c_hex=prefix[4 + 8 * reader.common.CELLS:].hex(),
        rank_a=ranks[0], rank_b=ranks[1], material_setup=measured(), reference_setup=measured(),
        material_source=source, ideal_uniform_ticket_probability_assumption=None)
    counts = dict.fromkeys(reader.COUNTERS, 0)
    for sample in range(reader.SAMPLES):
        for position in range(len(reader.STRATEGIES)):
            index = (sample + position) % len(reader.STRATEGIES)
            supported = reader.supported(index, name)
            emit("cohort", sample=sample, position=position, strategy_index=index,
                strategy=reader.STRATEGIES[index], setup_calls=1, supported=supported,
                setup=measured(), selection=reader.selection(index, ranks, supported), searches_planned=int(supported))
            counts["setup_calls"] += 1
            counts["unsupported_setups"] += not supported
            if supported:
                width = 4 if index == 3 else 1
                attempt_count = 3 if target_index == 2 or width == 4 else 1
                trials = []
                for nonce in range(attempt_count):
                    context = reader.challenge(task, target, sample, 0, nonce)
                    trace = hashlib.sha256(b"parser-fixture-not-native-W1" + context).digest()
                    ticket = reader.common.pon_hash(b"ticket", context, trace)
                    hit = ticket <= target
                    materialized = index >= 4 or hit
                    trials.append(dict(nonce=nonce, challenge=context.hex(), trace=trace.hex(), ticket=ticket.hex(),
                        target_hit=hit, proof_materialized=materialized, proof_sha256=reader.common.sha(prefix + trace),
                        after_first_hit=target_index == 3 and nonce > 0, complete=True))
                    counts["hit_count" if hit else "miss_count"] += 1
                first = 0 if target_index == 3 else None
                speculative = attempt_count - 1 if target_index == 3 else 0
                buffers = sum(t["proof_materialized"] for t in trials)
                emit("search", sample=sample, strategy_index=index, search_index=0, setup_calls=0,
                    batch_width=width, batches=(attempt_count + width - 1) // width, attempt_count=attempt_count,
                    complete=True, errors=0, first_hit_nonce=first, speculative_attempts=speculative,
                    proof_buffers=buffers, producer=measured(), observation=measured(), disposal=measured(), attempts=trials)
                counts["search_count"] += 1
                counts["attempt_count"] += attempt_count
                counts["exhausted_searches"] += first is None
                counts["speculative_attempts"] += speculative
                counts["proof_buffers"] += buffers
                checks = []
                if first is not None:
                    checks.extend((case, path, first) for case in ("winner", "product-last") for path in ("production", "reference"))
                    checks.extend(("post-winner-full-replay", path, nonce) for nonce in range(1, attempt_count) for path in ("production", "reference"))
                for case, path, nonce in checks:
                    proof = prefix + bytes.fromhex(trials[nonce]["trace"])
                    if case == "product-last":
                        proof = reader.product_last(proof)
                    emit("verifier", sample=sample, strategy_index=index, search_index=0, nonce=nonce,
                        path=path, case=case, target=reader.TARGETS[3] if case == "post-winner-full-replay" else target.hex(),
                        challenge=trials[nonce]["challenge"], proof_sha256=reader.common.sha(proof),
                        result="Product" if case == "product-last" else "ACCEPT", timing=measured())
                    counts["verifier_calls"] += 1
                emit("search-cleanup", sample=sample, strategy_index=index, search_index=0,
                    scope="winning-proof-buffer-only", timing=measured())
            emit("cohort-end", sample=sample, strategy_index=index, teardown=measured(int(supported)), total=measured(1000))
    emit("footer", **counts, all_declared_cohorts_completed=True, status="COMPONENT_OBSERVATION", activation=False)
    return records


def read(rows):
    records = reader.Records()
    for row in rows:
        records.add(row)
    return records.summary()


def find(rows, kind, **values):
    return next(row for row in rows if row["kind"] == kind and all(row.get(key) == value for key, value in values.items()))


class RankBatchReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.first_hit = synthetic_parser_records()
        cls.exhaustion = synthetic_parser_records(2)

    def rejected(self, mutate, rows=None):
        fixture = deepcopy(self.first_hit if rows is None else rows)
        mutate(fixture)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            read(fixture)

    def test_complete_partial_batch_and_paid_unsupported_setup_accounting(self):
        report = read(self.first_hit)
        self.assertEqual(report["counts"]["setup_calls"], 136)
        self.assertEqual(report["counts"]["unsupported_setups"], 40)
        self.assertEqual(report["counts"]["attempt_count"], 112)
        batch = report["arms"][3]
        self.assertEqual((batch["accepted_winners"], batch["physical_hits"], batch["physical_attempts"], batch["speculative_attempts"]), (8, 24, 24, 16))
        self.assertTrue(all(report[key] is False for key in reader.FALSE_FLAGS))
        self.assertGreater(report["arms"][12]["paid_setup"]["cpu_ns"], 0)

    def test_exhaustion_retains_all_misses_and_materialization_costs(self):
        report = read(self.exhaustion)
        self.assertEqual(report["counts"]["hit_count"], 0)
        self.assertEqual(report["counts"]["miss_count"], 288)
        self.assertEqual(report["counts"]["exhausted_searches"], 96)
        self.assertEqual(report["arms"][3]["accepted_winners"], 0)
        self.assertIsNone(report["arms"][3]["cpu_ns_per_accepted_winner"])

    def test_fixed_domain_and_safety_flags_reject_boolean_and_resource_overrides(self):
        for key, value in (("samples", 4), ("batch_workers", 8), ("rank_bound", 9),
                ("activation", True), ("complete_trace_tiles", 511), ("rank_a", False),
                ("horizons", [True, 8]), ("producer_clock_includes_threads", 1),
                ("ideal_uniform_ticket_probability_assumption", "1/2")):
            with self.subTest(key=key):
                self.rejected(lambda rows: rows[0].update({key: value}))

    def test_preprocessing_cannot_be_free_unsupported_omitted_or_fallback_relabelled(self):
        for key, value in (("setup_calls", 0), ("supported", False), ("searches_planned", 0),
                ("selection", {"preparation_used": "dense", "rank_bound": None})):
            self.rejected(lambda rows: find(rows, "cohort", strategy_index=2).update({key: value}))
        self.rejected(lambda rows: rows.remove(find(rows, "cohort", strategy_index=12)))
        self.rejected(lambda rows: find(rows, "cohort", strategy_index=2)["selection"].update(rank=False))
        self.rejected(lambda rows: find(rows, "cohort", strategy_index=12).update(setup=measured(0)))
        self.rejected(lambda rows: find(rows, "search", strategy_index=3).update(producer=measured(0)))

    def test_every_speculative_attempt_and_complete_nonce_order_required(self):
        self.rejected(lambda rows: find(rows, "search", strategy_index=3)["attempts"].pop())
        for key, value in (("batch_width", 1), ("first_hit_nonce", 2), ("speculative_attempts", 0),
                ("attempt_count", 1), ("proof_buffers", 1), ("batches", 2), ("complete", False), ("errors", 1)):
            self.rejected(lambda rows: find(rows, "search", strategy_index=3).update({key: value}))
        for key, value in (("nonce", 4), ("challenge", "00" * 32), ("trace", "00" * 32), ("ticket", "00" * 32),
                ("proof_sha256", "00" * 32), ("proof_materialized", False), ("after_first_hit", False), ("complete", False)):
            self.rejected(lambda rows: find(rows, "search", strategy_index=3)["attempts"][1].update({key: value}))

    def test_omitted_misses_and_early_exhaustion_are_rejected(self):
        self.rejected(lambda rows: find(rows, "search", strategy_index=0)["attempts"].pop(), self.exhaustion)
        self.rejected(lambda rows: find(rows, "search", strategy_index=4)["attempts"][0].update(proof_materialized=False), self.exhaustion)

    def test_both_verifiers_mutants_and_post_winner_replays_bound_to_actual_proof(self):
        for case in ("winner", "product-last", "post-winner-full-replay"):
            self.rejected(lambda rows: rows.remove(find(rows, "verifier", case=case, path="reference")))
        for key, value in (("result", "Product"), ("challenge", "00" * 32), ("proof_sha256", "00" * 32),
                ("target", reader.TARGETS[0]), ("nonce", 0)):
            self.rejected(lambda rows: find(rows, "verifier", case="post-winner-full-replay").update({key: value}))

    def test_cleanup_and_inclusive_totals_are_required_and_no_double_counting(self):
        self.rejected(lambda rows: rows.remove(find(rows, "search-cleanup")))
        self.rejected(lambda rows: find(rows, "cohort-end").update(total=measured(1)))
        report = read(self.first_hit)
        self.assertEqual(report["arms"][0]["producer_total"]["cpu_ns"], 40)
        self.assertEqual(report["arms"][0]["inclusive_cohort"]["cpu_ns"], 8000)

    def test_unknown_cpu_stays_unknown_and_invalid_clocks_rejected(self):
        rows = deepcopy(self.first_hit)
        find(rows, "search", strategy_index=0)["producer"]["cpu_ns"] = None
        report = read(rows)
        self.assertIsNone(report["arms"][0]["producer_total"]["cpu_ns"])
        self.assertIsNone(report["arms"][0]["cpu_ns_per_accepted_winner"])
        for axis, value in (("cpu_ns", -1), ("cpu_ns", True), ("wall_ns", None)):
            self.rejected(lambda rows: find(rows, "cohort")["setup"].update({axis: value}))

    def test_truncation_duplicate_unknown_records_and_footer_laundering_rejected(self):
        self.rejected(lambda rows: rows.pop())
        self.rejected(lambda rows: rows.append(deepcopy(rows[-1])))
        self.rejected(lambda rows: rows[-1].update(hit_count=48))
        self.rejected(lambda rows: rows[-1].update(activation=True))
        self.rejected(lambda rows: rows[0].update(unknown=True))

    def test_json_parser_rejects_duplicates_numbers_and_missing_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.jsonl"
            valid = b"".join(json.dumps(row).encode() + b"\n" for row in self.first_hit)
            path.write_bytes(valid)
            self.assertEqual(reader.analyze(path)["status"], "COMPLETE_COMPONENT_OBSERVATION")
            for bad in (valid[:-1], b'{"schema":"a","schema":"b"}\n', b'{"x":NaN}\n', b'{"x":1.2}\n'):
                path.write_bytes(bad)
                with self.assertRaises(ValueError):
                    reader.analyze(path)

    def test_complete_grid_requires_all_controls_and_same_horizon_prefix(self):
        # Grid-join test objects are not native observations or reader fixtures.
        reports = [dict(zip(("class", "target_index", "horizon"), key), counts={}, logical_prefix_sha256={"0:0:0": "fixed"}) for key in reader.grid()]
        self.assertEqual(reader.campaign(reports)["shard_count"], 66)
        for bad in (reports[:-1], reports + [reports[0]], reports[:-1] + [reports[0]]):
            with self.assertRaises(ValueError):
                reader.campaign(bad)
        bad = deepcopy(reports)
        bad[1]["logical_prefix_sha256"]["0:0:0"] = "different"
        with self.assertRaises(ValueError):
            reader.campaign(bad)


if __name__ == "__main__":
    unittest.main()
