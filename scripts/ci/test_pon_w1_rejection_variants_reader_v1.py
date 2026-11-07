#!/usr/bin/env python3
"""Reader controls with Python relation witnesses and INVENTED timings/stages.

These fixtures are not native observations, performance results or qualifications.
"""
import copy
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_rejection_variants_reader_v1 as reader


def stamp(value):
    return dict(wall_ns=value, thread_cpu_ns=value)


def observed(outcome, tiles, points, value, product=None):
    return dict(outcome=outcome, timing=stamp(value), progress_points=points,
                transcript_tiles=tiles, accepted_product=None if product is None else list(product))


def fixture():
    result = dict(schema=reader.SCHEMA, samples=reader.SAMPLES, variants_per_claim=reader.VARIANTS,
        timing_scope=reader.TIMING_SCOPE, control_scope=reader.CONTROL_SCOPE, material_scope=reader.MATERIAL_SCOPE,
        cpu_unknown_is_null=True, **dict.fromkeys(reader.UNKNOWN_FIELDS), **dict.fromkeys(reader.FALSE_FLAGS, False),
        materials=[], rows=[])
    for name in reader.CLASSES:
        a, b, task, prefix = reader.material(name)
        result["materials"].append(dict(**{"class":name}, setup=stamp(100), task=task.hex(),
            a=a.copy(), b=b.copy(), setup_charged_once_per_class=True))
        for target_hex in reader.TARGETS:
            target = bytes.fromhex(target_hex)
            for sample in range(reader.SAMPLES):
                context = reader.challenge(name, target, sample)
                attempts, selected = [], None
                for nonce in range(reader.SEARCH_LIMIT):
                    trace = reader.H(b"false-trace-c-variants-v1", context, nonce.to_bytes(8, "little"))
                    ticket = reader.H(b"ticket", context, trace)
                    hit = ticket <= target
                    attempts.append(dict(nonce=nonce, trace=trace.hex(), ticket=ticket.hex(), meets_target=hit))
                    if hit:
                        selected = trace
                        break
                product, honest_trace = reader.positive_relation(name, context)
                honest_target = reader.H(b"ticket", context, honest_trace)
                variants = []
                for variant in range(reader.VARIANTS if selected is not None else 0):
                    proof = bytearray(prefix)
                    proof[-32:] = selected
                    word = (0, reader.CELLS//2, reader.CELLS-1)[variant % 3]
                    offset = 4 + 2 * reader.CELLS * 4 + word * 4
                    proof[offset:offset+4] = (variant+1).to_bytes(4, "little")
                    variants.append(dict(variant=variant, cached_first=(sample+variant)%2==0,
                        proof_commitment=reader.H(b"measured-proof", proof).hex(), construction=stamp(3),
                        native_no_cache=observed("Transcript", 512, 897, 100),
                        configured_cache=observed("Transcript", 512 if variant==0 else 0,
                            897 if variant==0 else 1, 110 if variant==0 else 2)))
                result["rows"].append(dict(**{"class":name}, sample=sample, challenge=context.hex(), target=target.hex(),
                    search=stamp(len(attempts)*10+5), attempt_limit=reader.SEARCH_LIMIT,
                    attempts=attempts, exhausted=selected is None, variants=variants,
                    cache_setup=stamp(10), cache_destruction=stamp(5), positive_setup=stamp(180),
                    positive_target=honest_target.hex(), positive_trace=honest_trace.hex(),
                    positive_control_scope=reader.POSITIVE_SCOPE,
                    positive_same_attack_target=observed("Accepted", 512, 1099, 300, product) if honest_target<=target else None,
                    positive=observed("Accepted", 512, 1099, 300, product)))
    return result


class RejectionVariantsReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def reject(self, value):
        with self.assertRaises(ValueError):
            reader.summarize(value)

    def test_complete_grid_binds_all_claims_variants_and_positive_relations(self):
        report = reader.summarize(copy.deepcopy(self.original))
        self.assertEqual(report["qualification_status"], "HOLD")
        self.assertEqual(report["independent_positive_relation_replays"], 64)
        counts = report["totals"]["counts"]
        self.assertEqual(counts["claim_cohorts"], 64)
        self.assertEqual(counts["submitted_variants"], 2048)
        self.assertEqual(counts["cached_complete_replays"], 64)
        self.assertEqual(counts["cached_fact_refusals"], 1984)
        self.assertTrue(report["scope"]["fresh_claims_still_need_complete_replay"])
        self.assertFalse(report["scope"]["minimum_work_cost_proved"])

    def test_paid_denominators_include_material_search_construction_and_cache_lifecycle(self):
        report = reader.summarize(copy.deepcopy(self.original))
        total = report["totals"]
        attack = 4*100+sum(row["search"]["thread_cpu_ns"] for row in self.original["rows"])+2048*3
        self.assertEqual(total["attacker_including_paid_material"]["thread_cpu_ns"], attack)
        self.assertEqual(total["receiver_native_no_cache"]["thread_cpu_ns"], 2048*100)
        self.assertEqual(total["receiver_configured_cache_including_lifecycle"]["thread_cpu_ns"], 64*(10+110+31*2+5))
        self.assertEqual(total["configured_receiver_over_attacker"]["thread_cpu_ns"]["denominator"], attack)
        changed = copy.deepcopy(self.original)
        changed["rows"][0]["positive_setup"] = stamp(10**9)
        changed["rows"][0]["positive"]["timing"] = stamp(10**9)
        self.assertEqual(reader.summarize(changed)["totals"]["attacker_including_paid_material"], total["attacker_including_paid_material"])
        self.assertEqual(reader.summarize(changed)["totals"]["receiver_configured_cache_including_lifecycle"], total["receiver_configured_cache_including_lifecycle"])

    def test_missing_duplicate_or_reordered_claims_cannot_shrink_cost(self):
        for mutation in (lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])), lambda rows: rows.reverse()):
            value = copy.deepcopy(self.original)
            mutation(value["rows"])
            self.reject(value)

    def test_missing_or_changed_material_setup_is_rejected(self):
        for change in (lambda rows: rows.pop(), lambda rows: rows[0].__setitem__("setup_charged_once_per_class", False)):
            value = copy.deepcopy(self.original)
            change(value["materials"])
            self.reject(value)

    def test_periodic_material_must_not_be_relabelled_full_rank(self):
        value = copy.deepcopy(self.original)
        value["materials"][1]["class"] = "full-rank-field"
        self.reject(value)
        value = copy.deepcopy(self.original)
        value["material_scope"] = "full-rank material"
        self.reject(value)

    def test_changed_input_word_or_task_is_rejected(self):
        for field in ("a", "b", "task"):
            value = copy.deepcopy(self.original)
            if field == "task":
                value["materials"][0][field] = "00"*32
            else:
                value["materials"][0][field][-1] = 1
            self.reject(value)

    def test_removed_misses_and_fabricated_early_exhaustion_are_rejected(self):
        value = copy.deepcopy(self.original)
        row = next(row for row in value["rows"] if len(row["attempts"])>1)
        row["attempts"].pop(0)
        self.reject(value)
        value = copy.deepcopy(self.original)
        row = next(row for row in value["rows"] if len(row["attempts"])>1)
        row["attempts"].pop()
        row["exhausted"], row["variants"] = True, []
        self.reject(value)

    def test_false_ticket_trace_and_target_must_match_exact_nonce(self):
        for field in ("trace", "ticket"):
            value = copy.deepcopy(self.original)
            value["rows"][0]["attempts"][0][field] = "00"*32
            self.reject(value)
        value = copy.deepcopy(self.original)
        value["rows"][0]["target"] = "ff"*32
        self.reject(value)

    def test_all_product_variants_and_commitments_are_required(self):
        value = copy.deepcopy(self.original)
        value["rows"][0]["variants"].pop()
        self.reject(value)
        value = copy.deepcopy(self.original)
        value["rows"][0]["variants"][1]["proof_commitment"] = value["rows"][0]["variants"][0]["proof_commitment"]
        self.reject(value)

    def test_native_full_replay_cannot_be_replaced_by_cheap_target_refusal(self):
        for change in ({"outcome":"Target"}, {"transcript_tiles":0}, {"progress_points":1}):
            value = copy.deepcopy(self.original)
            value["rows"][0]["variants"][0]["native_no_cache"].update(change)
            self.reject(value)

    def test_first_cached_claim_must_replay_and_later_variants_must_use_fact(self):
        for index, tiles, points in ((0, 0, 1), (1, 512, 897)):
            value = copy.deepcopy(self.original)
            value["rows"][0]["variants"][index]["configured_cache"].update(transcript_tiles=tiles, progress_points=points)
            self.reject(value)

    def test_both_paths_must_reject_without_verified_product(self):
        for path in ("native_no_cache", "configured_cache"):
            value = copy.deepcopy(self.original)
            value["rows"][0]["variants"][0][path]["accepted_product"] = [0]*reader.CELLS
            self.reject(value)

    def test_actual_paired_invocation_order_cannot_be_changed(self):
        value = copy.deepcopy(self.original)
        value["rows"][0]["variants"][0]["cached_first"] = False
        self.reject(value)

    def test_always_reject_verifier_fails_positive_control(self):
        value = copy.deepcopy(self.original)
        value["rows"][0]["positive"] = observed("Transcript", 512, 897, 100)
        self.reject(value)

    def test_positive_target_trace_and_product_are_independently_replayed(self):
        for field in ("positive_target", "positive_trace"):
            value = copy.deepcopy(self.original)
            value["rows"][0][field] = "ff"*32
            self.reject(value)
        value = copy.deepcopy(self.original)
        value["rows"][0]["positive"]["accepted_product"][-1] = 1
        self.reject(value)

    def test_own_ticket_control_cannot_claim_fixed_target_mining(self):
        value = copy.deepcopy(self.original)
        value["rows"][0]["positive_control_scope"] = "accepted work produced at fixed attack target"
        self.reject(value)
        self.assertNotEqual(self.original["rows"][0]["positive_target"], self.original["rows"][0]["target"])

    def test_conditional_same_target_control_cannot_be_invented_or_dropped(self):
        value = copy.deepcopy(self.original)
        eligible = next(row for row in value["rows"] if row["positive_same_attack_target"] is not None)
        eligible["positive_same_attack_target"] = None
        self.reject(value)
        value = copy.deepcopy(self.original)
        ineligible = next(row for row in value["rows"] if row["positive_same_attack_target"] is None)
        ineligible["positive_same_attack_target"] = copy.deepcopy(ineligible["positive"])
        self.reject(value)

    def test_unknown_cpu_propagates_to_totals_and_ratios(self):
        value = copy.deepcopy(self.original)
        value["rows"][0]["cache_setup"]["thread_cpu_ns"] = None
        report = reader.summarize(value)
        self.assertIsNone(report["totals"]["receiver_configured_cache_including_lifecycle"]["thread_cpu_ns"])
        self.assertIsNone(report["totals"]["configured_receiver_over_attacker"]["thread_cpu_ns"])
        self.assertIsNotNone(report["totals"]["configured_receiver_over_attacker"]["wall_ns"])
        value["materials"][0]["setup"]["thread_cpu_ns"] = None
        self.assertIsNone(reader.summarize(value)["totals"]["native_receiver_over_attacker"]["thread_cpu_ns"])

    def test_zero_denominator_is_not_infinity_or_fictitious_success(self):
        value = copy.deepcopy(self.original)
        for material in value["materials"]: material["setup"] = stamp(0)
        for row in value["rows"]:
            row["search"] = stamp(0)
            for variant in row["variants"]: variant["construction"] = stamp(0)
        report = reader.summarize(value)
        self.assertIsNone(report["totals"]["native_receiver_over_attacker"]["thread_cpu_ns"])

    def test_unknown_external_costs_are_not_zero_and_booleans_are_not_clocks(self):
        for key in reader.UNKNOWN_FIELDS:
            value = copy.deepcopy(self.original)
            value[key] = 0
            self.reject(value)
        value = copy.deepcopy(self.original)
        value["rows"][0]["search"]["thread_cpu_ns"] = True
        self.reject(value)

    def test_duplicate_keys_and_oversized_gzip_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"duplicate.json"
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaises(ValueError): reader.analyze(path)
            zipped = Path(directory)/"oversized.json.gz"
            zipped.write_bytes(gzip.compress(b" "*100))
            with patch.object(reader, "MAX_RAW", 50), self.assertRaises(ValueError):
                reader.analyze(zipped)


if __name__ == "__main__":
    unittest.main()
