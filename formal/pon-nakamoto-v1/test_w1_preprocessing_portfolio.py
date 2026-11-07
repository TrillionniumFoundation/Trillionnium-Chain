"""Complete proof equivalence, exact rank decisions and paid censoring controls."""
from collections import Counter
from copy import deepcopy
import hashlib
import unittest
from unittest.mock import patch

from test_w1_quantum_oracle import fixture
from w1_preprocessing_cache import CACHE_COUNTERS, PayloadLRU, _field, produce
from w1_preprocessing_portfolio import (
    CLAIMS, STRATEGIES, WORK_COUNTERS, _ab_key, _dense_product, _rank_product,
    _sparse_product, execute_portfolio, run_cell, verify_attempt, verify_cell, verify_portfolio,
)
from w1_quantum_oracle import FixedTemplate, Shape, canonical, h_bytes


def changed(template, a=None, b=None, parent=False, target=None, shape=None):
    a = template.a if a is None else tuple(a)
    b = template.b if b is None else tuple(b)
    header = bytearray(template.header)
    base = 4 if template.profile == "PGH2" else 0
    if parent:
        header[base + 70] ^= 1
    if target is not None:
        header[base + 118:base + 150] = target.to_bytes(32, "big")
    header[base + 278:base + 310] = hashlib.sha256(h_bytes(b"task", _field(a), _field(b))).digest()
    return FixedTemplate.from_header(bytes(header), a, b, template.nonce_bits, shape or template.shape)


def rehash(value):
    value["record_sha256"] = hashlib.sha256(canonical({k: v for k, v in value.items()
                                                     if k != "record_sha256"})).hexdigest()
    return value


class AlgebraTests(unittest.TestCase):
    def test_rank_and_sparse_products_equal_independent_dense_for_structured_and_dense_inputs(self):
        n, q = 3, 11
        cases = [
            ((0,) * 9, tuple(range(9))),
            ((1, 2, 3, 2, 4, 6, 3, 6, 9), tuple(range(9))),
            (tuple(range(9)), (1, 2, 3, 2, 4, 6, 3, 6, 9)),
            ((1, 0, 0, 0, 2, 0, 0, 0, 3), (0, 2, 0, 3, 0, 0, 0, 0, 4)),
            ((2, 1, 7, 5, 3, 1, 4, 2, 9), (8, 3, 4, 7, 9, 2, 3, 6, 5)),
        ]
        for a, b in cases:
            expected = _dense_product(a, b, n, q, Counter())
            rank_work, sparse_work = Counter(), Counter()
            rank, path = _rank_product(a, b, n, q, rank_work)
            sparse = _sparse_product(a, b, n, q, sparse_work)
            self.assertEqual(rank, expected)
            self.assertEqual(sparse, expected)
            self.assertEqual(sparse_work["ab_sparse_zero_products_skipped"]
                             + sparse_work["ab_sparse_field_multiply_add_pairs"], n**3)
            self.assertTrue(path)

    def test_noninvertible_reduced_pivot_has_an_explicit_charged_dense_fallback(self):
        a, b = (3, 0, 0, 3), (3, 1, 1, 3)
        work = Counter()
        out, path = _rank_product(a, b, 2, 27, work)
        self.assertEqual(out, _dense_product(a, b, 2, 27, Counter()))
        self.assertEqual(work["ab_rank_inverse_calls"], 2)
        self.assertEqual(work["ab_rank_inverse_failures"], 2)
        self.assertEqual(work["ab_rank_dense_fallback_products"], 1)
        self.assertEqual(work["ab_field_multiply_add_pairs"], 8)
        self.assertIn("charged-dense-product", path)

    def test_almost_rank_one_is_not_misclassified_by_partial_or_probabilistic_checks(self):
        a = (1, 2, 3, 2, 4, 6, 3, 6, 10)
        b = (1, 0, 0, 0, 1, 0, 0, 0, 1)
        work = Counter()
        out, path = _rank_product(a, b, 3, 11, work)
        self.assertEqual(out, list(a))
        self.assertEqual(work["ab_rank_equality_checks"], 14)
        self.assertIn("A:refused-not-rank-one", path)
        self.assertIn("charged-dense-product", path)

    def test_rank_factor_work_and_output_multiplications_are_not_omitted(self):
        work = Counter()
        _, path = _rank_product((1, 2, 2, 4), (2, 1, 7, 3), 2, 11, work)
        self.assertIn("rank-one-left-product", path)
        self.assertEqual(work["ab_rank_equality_checks"], 4)
        self.assertEqual(work["ab_rank_factor_field_multiplications"], 6)
        self.assertEqual(work["ab_rank_product_field_multiply_add_pairs"], 4)
        self.assertEqual(work["ab_rank_outer_field_multiplications"], 4)


class PortfolioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = fixture(Shape(2, 1, 8, 2), nonce_bits=3)

    def test_all_algorithms_and_capacities_generate_identical_complete_proofs(self):
        p = self.template
        contexts = (p, changed(p, parent=True), changed(p, target=1),
                    changed(p, a=(0, 0, 0, 0)), changed(p, a=(1, 2, 2, 4)))
        report = execute_portfolio(contexts, tuple((i, 0) for i in range(5)), (0, 4096))
        self.assertEqual(len(report["cells"]), 8)
        for cell in report["cells"]:
            self.assertEqual(cell["attempts_verified"], 5)
            self.assertEqual(cell["verified_target_misses"], 1)
            self.assertEqual(cell["work_units_total"]["trace_field_multiply_add_pairs"], 5 * 2**3)
            self.assertEqual(cell["work_units_total"]["independent_direct_product_field_multiply_add_pairs"], 5 * 2**3)
        self.assertEqual(verify_portfolio(report), report)

    def test_native_trace_correction_saves_only_ab_macs_and_retains_all_trace_words(self):
        p = fixture(Shape(), nonce_bits=1)
        direct = run_cell((p,), ((0, 0),), "direct-ab", 0)
        correction = run_cell((p,), ((0, 0),), "trace-correction-ab", 0)
        self.assertEqual(direct["attempts"][0]["proof_sha256"], correction["attempts"][0]["proof_sha256"])
        self.assertEqual(direct["work_units_total"]["ab_field_multiply_add_pairs"], 64**3)
        self.assertEqual(correction["work_units_total"]["ab_correction_field_multiply_add_pairs"], 4 * 64**2 * 8)
        for cell in (direct, correction):
            self.assertEqual(cell["status"], "COMPLETE")
            self.assertEqual(cell["work_units_total"]["trace_field_multiply_add_pairs"], 64**3)
            self.assertEqual(cell["work_units_total"]["trace_prefix_words"], 64**3 // 8)
            self.assertEqual(cell["work_units_total"]["proof_bytes_materialized"], 4 + 12 * 64**2 + 32)
            self.assertFalse(cell["claims"]["native_block_admission_executed"])

    def test_noise_exhaustion_retains_failed_attempt_costs_without_inventing_a_proof(self):
        p = fixture(Shape(2, 2, 4, 1), nonce_bits=7)
        nonce = next(i for i in range(128) if produce(p, i, PayloadLRU(0))[0]["outcome"] == "NOISE_EXHAUSTED")
        for strategy in STRATEGIES:
            cell = run_cell((p,), ((0, nonce),), strategy, 4096)
            self.assertEqual(cell["status"], "COMPLETE")
            self.assertEqual(cell["verified_noise_exhaustions"], 1)
            self.assertGreater(cell["work_units_total"]["noise_hashes"], 0)
            self.assertEqual(cell["work_units_total"]["proof_bytes_materialized"], 0)
            self.assertEqual(cell["work_units_total"]["ab_products_computed"], 0)
            self.assertEqual(cell["work_units_total"]["independent_direct_product_field_multiply_add_pairs"], 0)

    def test_growth_header_profile_has_the_same_complete_proof_equivalence(self):
        p = fixture(Shape(2, 1, 8, 2), profile="PGH2", nonce_bits=3)
        report = execute_portfolio((p, changed(p, parent=True)), ((0, 0), (1, 0)), (4096,))
        self.assertTrue(report["same_verified_complete_results_across_algorithms"])
        self.assertEqual(len({cell["attempts"][0]["proof_sha256"] for cell in report["cells"]}), 1)

    def test_cache_keys_invalidate_task_and_field_but_reuse_across_parent_target_and_rank(self):
        p = self.template
        contexts = (p, changed(p, parent=True), changed(p, target=1),
                    changed(p, a=(3, 5, 7, 9)), changed(p, shape=Shape(2, 2, 8, 2)))
        self.assertEqual(_ab_key(p), _ab_key(contexts[1]))
        self.assertEqual(_ab_key(p), _ab_key(contexts[2]))
        self.assertEqual(_ab_key(p), _ab_key(contexts[4]))
        self.assertNotEqual(_ab_key(p), _ab_key(contexts[3]))
        other_field = fixture(Shape(2, 1, 9, 2), nonce_bits=3)
        self.assertNotEqual(_ab_key(p), _ab_key(other_field))
        for strategy in STRATEGIES:
            cell = run_cell(contexts, ((0, 0), (1, 0), (2, 0), (3, 0), (0, 1), (4, 1)), strategy, 4096)
            self.assertEqual(cell["work_units_total"]["ab_products_computed"], 2)
            self.assertEqual(cell["work_units_total"]["ab_products_reused"], 4)

    def test_low_capacity_evictions_and_rejections_do_not_change_verified_proofs(self):
        report = execute_portfolio((self.template, changed(self.template, parent=True)),
                                   ((0, 0), (1, 0), (0, 1)), (0, 200, 4096), ("sparse-ab",))
        small = report["cells"][1]["cache"]
        self.assertGreater(small["counters"]["evictions"], 0)
        self.assertGreater(small["counters"]["insertion_refusals"], 0)
        self.assertLessEqual(small["peak_resident_payload_bytes"], 200)

    def test_every_stage_prefix_retains_exact_costs_partial_attempt_and_full_denominator(self):
        schedule = ((0, 0), (0, 1))
        for limit in range(18):
            cell = run_cell((self.template,), schedule, "rank-aware-ab", 4096, max_stages=limit)
            self.assertEqual(len(cell["attempts"]), 2)
            self.assertEqual(cell["attempts_verified"] + cell["attempts_partial"] + cell["attempts_not_started"], 2)
            self.assertEqual(verify_cell(cell, (self.template,), schedule), cell)
            for key in WORK_COUNTERS:
                self.assertEqual(cell["work_units_total"][key], sum(row["work_units"][key] for row in cell["attempts"]))
            if cell["cache"] is not None:
                for key in CACHE_COUNTERS:
                    self.assertEqual(cell["cache"]["counters"][key], sum(row["cache_counter_delta"][key] for row in cell["attempts"]))

    def test_full_trace_before_censoring_is_charged_without_a_fictitious_delivered_proof(self):
        cell = run_cell((self.template,), ((0, 0), (0, 1)), "trace-correction-ab", 4096, max_stages=6)
        self.assertEqual(cell["stopped_before"], [0, "proof_product"])
        self.assertEqual(cell["attempts_partial"], 1)
        self.assertEqual(cell["attempts_not_started"], 1)
        self.assertEqual(cell["work_units_total"]["trace_field_multiply_add_pairs"], 8)
        self.assertGreater(cell["work_units_total"]["noise_hashes"], 0)
        self.assertEqual(cell["work_units_total"]["proof_bytes_materialized"], 0)
        self.assertIsNone(cell["attempts"][0]["verification"])

    def test_materialized_but_unverified_proof_is_not_a_verified_attempt(self):
        cell = run_cell((self.template,), ((0, 0),), "direct-ab", 4096, max_stages=8)
        self.assertEqual(cell["stopped_before"], [0, "independent_full_relation_check"])
        self.assertGreater(cell["attempts"][0]["proof_bytes"], 0)
        self.assertEqual(cell["attempts_verified"], 0)

    def test_observer_exception_retains_paid_work_failure_and_not_started_tail(self):
        def observe(identity, call):
            value = call()
            if identity == (0, "noise"):
                raise RuntimeError("CONTROL_FAILED_AFTER_NOISE_WORK")
            return value
        cell = run_cell((self.template,), ((0, 0), (0, 1)), "direct-ab", 4096, observer=observe)
        self.assertEqual(cell["status"], "FAILED")
        self.assertGreater(cell["work_units_total"]["noise_hashes"], 0)
        self.assertEqual(cell["failure"]["stage"], [0, "noise"])
        self.assertEqual(cell["attempts_not_started"], 1)
        self.assertTrue(all(value is False for value in cell["claims"].values()))
        with self.assertRaisesRegex(ValueError, "CELL_RECORD"):
            verify_cell(cell, (self.template,), ((0, 0), (0, 1)))

    def test_cache_poisoning_cannot_pass_the_independent_complete_relation(self):
        original = PayloadLRU.get
        def corrupted(cache, key):
            value = original(cache, key)
            if value is not None and key.startswith(b"TRNM-W1-PORTFOLIO-AB1\0"):
                return bytes([value[0] ^ 1]) + value[1:]
            return value
        with patch.object(PayloadLRU, "get", corrupted):
            cell = run_cell((self.template,), ((0, 0), (0, 1)), "trace-correction-ab", 4096)
        self.assertEqual(cell["status"], "FAILED")
        self.assertEqual(cell["attempts_verified"], 1)
        self.assertIn("COMPLETE_PROOF_MISMATCH", cell["failure"]["message"])

    def test_direct_scalar_verifier_is_separate_from_trace_correction_identity(self):
        row, proof = produce(self.template, 0, PayloadLRU(0))
        start = 4 + 8 * self.template.shape.n**2
        broken = proof[:start] + bytes([proof[start] ^ 1]) + proof[start + 1:]
        with patch("w1_preprocessing_portfolio.verify_complete_attempt", return_value={"full_relation_checked": True}):
            with self.assertRaisesRegex(ValueError, "INDEPENDENT_DIRECT_AB"):
                verify_attempt(self.template, 0, row, broken)

    def test_censoring_omissions_rehashed_counter_forgery_and_claim_promotion_are_refused(self):
        cell = run_cell((self.template,), ((0, 0), (0, 1)), "direct-ab", 4096, max_stages=6)
        for kind in ("partial_work", "tail", "cache", "claim", "prefix"):
            changed_cell = deepcopy(cell)
            if kind == "partial_work":
                changed_cell["work_units_total"]["trace_field_multiply_add_pairs"] = 0
            elif kind == "tail":
                changed_cell["attempts"].pop()
            elif kind == "cache":
                changed_cell["cache"]["counters"]["key_bytes_compared"] += 1
            elif kind == "claim":
                changed_cell["claims"]["global_minimum_attacker_cost_proved"] = True
            else:
                changed_cell["completed_stage_count"] -= 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verify_cell(rehash(changed_cell), (self.template,), ((0, 0), (0, 1)))

    def test_invalid_budget_strategy_and_nonce_rejected_before_execution(self):
        with patch("w1_preprocessing_portfolio.PayloadLRU", side_effect=AssertionError("cache ran")):
            for limit in (True, -1, 1.5, 10):
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    run_cell((self.template,), ((0, 0),), "direct-ab", 0, max_stages=limit)
            with self.assertRaises(ValueError):
                run_cell((self.template,), ((0, 8),), "direct-ab", 0)
            with self.assertRaises(ValueError):
                run_cell((self.template,), ((0, 0),), "fast-unimplemented", 0)


if __name__ == "__main__":
    unittest.main()
