"""Complete proof identity, bounded exact-key cache and failed-attempt controls."""
from copy import deepcopy
import hashlib
import unittest
from unittest.mock import patch

from test_w1_preprocessing_reuse import changed_header, changed_task
from test_w1_quantum_oracle import fixture
from w1_preprocessing_cache import (CACHE_COUNTERS, MAX_CACHE_BYTES, PayloadLRU, WORK_COUNTERS,
    execute_cache_comparison, produce, verify_cache_comparison, verify_complete_attempt)
from w1_quantum_oracle import FixedTemplate, Shape, canonical


class BoundedLRUTests(unittest.TestCase):
    def test_payload_cap_counts_keys_values_hits_and_lru_evictions(self):
        cache = PayloadLRU(8)
        self.assertIsNone(cache.get(b"a"))
        cache.put_new(b"a", b"123")
        cache.put_new(b"b", b"456")
        self.assertEqual(cache.get(b"a"), b"123")
        cache.put_new(b"c", b"789")
        self.assertEqual(cache.entries, [(b"a", b"123"), (b"c", b"789")])
        self.assertIsNone(cache.get(b"b"))
        row = cache.record()
        self.assertEqual(row["resident_payload_bytes"], 8)
        self.assertEqual(row["peak_resident_payload_bytes"], 8)
        self.assertEqual(row["counters"]["evictions"], 1)
        self.assertEqual(row["counters"]["key_and_value_bytes_evicted"], 4)
        self.assertEqual(row["counters"]["key_and_value_bytes_written"], 12)
        self.assertEqual(row["counters"]["value_bytes_read"], 3)
        self.assertGreater(row["counters"]["key_bytes_compared"], 0)

    def test_oversized_entry_is_refused_without_discarding_previous_paid_cache(self):
        cache = PayloadLRU(4)
        cache.put_new(b"a", b"123")
        cache.put_new(b"too-large", b"entry")
        self.assertEqual(cache.entries, [(b"a", b"123")])
        self.assertEqual(cache.counters["insertion_refusals"], 1)
        self.assertEqual(cache.counters["evictions"], 0)
        cache0 = PayloadLRU(0)
        cache0.put_new(b"a", b"b")
        self.assertEqual(cache0.resident_bytes, 0)
        self.assertEqual(cache0.counters["insertion_refusals"], 1)

    def test_exact_key_identity_does_not_accept_hash_collisions_or_duplicate_insertions(self):
        cache = PayloadLRU(128)
        cache.put_new(b"prefix-a", b"123")
        self.assertIsNone(cache.get(b"prefix-b"))
        self.assertEqual(cache.get(b"prefix-a"), b"123")
        with self.assertRaisesRegex(ValueError, "DUPLICATE"):
            cache.put_new(b"prefix-a", b"456")
        for capacity in (True, -1, 1.0, MAX_CACHE_BYTES + 1):
            with self.assertRaises(ValueError):
                PayloadLRU(capacity)


class CompleteCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = fixture(nonce_bits=3)

    def test_same_task_across_parent_changes_reuses_ab_and_only_compatible_sha_prefix(self):
        p = self.template
        other = changed_header(p, 70)
        report = execute_cache_comparison((p, other), ((0, 0), (1, 0), (0, 1), (1, 1)), (0, 4096))
        cold, cached = report["cells"]
        self.assertEqual(cold["work_units_total"]["ab_products_computed"], 4)
        self.assertEqual(cached["work_units_total"]["ab_products_computed"], 1)
        self.assertEqual(cached["work_units_total"]["ab_products_reused"], 3)
        self.assertEqual(cold["work_units_total"]["challenge_sha_compressions"], 24)
        self.assertEqual(cached["work_units_total"]["challenge_sha_compressions"], 13)
        self.assertEqual(cached["work_units_total"]["cached_challenge_sha_compressions_reused"], 11)
        self.assertEqual([row["work_units"]["cached_challenge_sha_compressions_reused"] for row in cached["attempts"]], [0, 1, 5, 5])
        self.assertEqual(cold["work_units_total"]["proof_bytes_materialized"], cached["work_units_total"]["proof_bytes_materialized"])
        self.assertEqual(cold["work_units_total"]["trace_field_multiply_add_pairs"], cached["work_units_total"]["trace_field_multiply_add_pairs"])
        self.assertEqual(verify_cache_comparison(report), report)

    def test_target_misses_keep_complete_noise_trace_ticket_proof_and_verification_costs(self):
        p = self.template
        header = p.header[:118] + (1).to_bytes(32, "big") + p.header[150:]
        hard = FixedTemplate.from_header(header, p.a, p.b, p.nonce_bits, p.shape)
        report = execute_cache_comparison((hard,), ((0, 0), (0, 1)), (0, 4096))
        for cell in report["cells"]:
            self.assertEqual(cell["target_misses"], 2)
            self.assertEqual(cell["target_hits"], 0)
            self.assertEqual(cell["work_units_total"]["proof_bytes_materialized"], 96)
            self.assertEqual(cell["work_units_total"]["trace_prefix_words"], 2)
            self.assertTrue(all(row["verification"]["full_relation_checked"] for row in cell["attempts"]))

    def test_complete_new_task_changes_product_key_and_preserves_old_entry_when_capacity_allows(self):
        p, other = self.template, changed_task(self.template)
        report = execute_cache_comparison((p, other), ((0, 0), (1, 0), (0, 1)), (4096,))
        rows = report["cells"][0]["attempts"]
        self.assertEqual([row["work_units"]["ab_products_computed"] for row in rows], [1, 1, 0])
        self.assertNotEqual(rows[0]["proof_sha256"], rows[1]["proof_sha256"])

    def test_modulus_is_in_ab_key_while_rank_and_noise_cap_are_not(self):
        p = fixture(Shape(2, 1, 4, 2), nonce_bits=3)
        rank = FixedTemplate.from_header(p.header, p.a, p.b, p.nonce_bits, Shape(2, 2, 4, 2))
        field = FixedTemplate.from_header(p.header, p.a, p.b, p.nonce_bits, Shape(2, 1, 5, 2))
        report = execute_cache_comparison((p, rank, field), ((0, 0), (1, 0), (2, 0)), (4096,))
        rows = report["cells"][0]["attempts"]
        self.assertEqual([row["work_units"]["ab_products_computed"] for row in rows], [1, 0, 1])
        self.assertEqual(rows[1]["work_units"]["ab_products_reused"], 1)
        self.assertEqual(rows[2]["work_units"]["ab_products_reused"], 0)

    def test_profile_and_growth_suffix_reuse_only_exact_framed_checkpoint_bytes(self):
        plain, growth = self.template, fixture(profile="PGH2", nonce_bits=3)
        witness = changed_header(growth, 322)
        report = execute_cache_comparison((plain, growth, witness), ((0, 0), (1, 0), (2, 0)), (4096,))
        rows = report["cells"][0]["attempts"]
        self.assertEqual([row["work_units"]["cached_challenge_sha_compressions_reused"] for row in rows], [0, 0, 5])
        self.assertEqual([row["work_units"]["ab_products_computed"] for row in rows], [1, 0, 0])
        self.assertEqual(len({row["challenge"] for row in rows}), 3)

    def test_small_cache_evictions_and_refusals_are_retained_without_changing_outcomes(self):
        p = self.template
        report = execute_cache_comparison((p, changed_header(p, 70)), ((0, 0), (1, 0), (0, 1)), (0, 200, 4096))
        small = report["cells"][1]["cache"]
        self.assertLessEqual(small["peak_resident_payload_bytes"], 200)
        self.assertGreater(small["counters"]["evictions"], 0)
        self.assertGreater(small["counters"]["insertion_refusals"], 0)
        self.assertTrue(report["same_complete_proof_outcomes_across_capacities"])

    def test_every_cache_and_work_counter_equals_sum_over_all_attempts(self):
        report = execute_cache_comparison((self.template,), ((0, 0), (0, 1), (0, 2)), (0, 512, 4096))
        for cell in report["cells"]:
            for name in CACHE_COUNTERS:
                self.assertEqual(cell["cache"]["counters"][name], sum(row["cache_counter_delta"][name] for row in cell["attempts"]))
            for name in WORK_COUNTERS:
                self.assertEqual(cell["work_units_total"][name], sum(row["work_units"][name] for row in cell["attempts"]))
            self.assertEqual(cell["cache"]["counters"]["lookups"],
                             cell["cache"]["counters"]["hits"] + cell["cache"]["counters"]["misses"])

    def test_noise_exhaustion_is_a_retained_failed_attempt_with_no_fictitious_proof(self):
        p = fixture(Shape(2, 2, 4, 1), nonce_bits=7)
        nonce = next(n for n in range(128) if produce(p, n, PayloadLRU(0))[0]["outcome"] == "NOISE_EXHAUSTED")
        report = execute_cache_comparison((p,), ((0, nonce),), (0, 4096))
        for cell in report["cells"]:
            self.assertEqual(cell["noise_exhaustions"], 1)
            self.assertGreater(cell["work_units_total"]["noise_hashes"], 0)
            self.assertEqual(cell["work_units_total"]["proof_bytes_materialized"], 0)
            self.assertEqual(cell["work_units_total"]["ab_products_computed"], 0)
            self.assertFalse(cell["attempts"][0]["verification"]["complete_proof"])

    def test_corrupt_cached_product_is_rejected_by_independent_complete_relation(self):
        cache = PayloadLRU(4096)
        produce(self.template, 0, cache)
        for index, (key, value) in enumerate(cache.entries):
            if key.startswith(b"TRNM-W1-AB-CACHE1\0"):
                cache.entries[index] = key, bytes([value[0] ^ 1]) + value[1:]
        row, proof = produce(self.template, 1, cache)
        with self.assertRaisesRegex(ValueError, "COMPLETE_PROOF_MISMATCH"):
            verify_complete_attempt(self.template, 1, row, proof)

    def test_corrupt_sha_checkpoint_is_rejected_by_full_challenge_binding(self):
        cache = PayloadLRU(4096)
        produce(self.template, 0, cache)
        for index, (key, value) in enumerate(cache.entries):
            if key.startswith(b"TRNM-W1-SHA-CHECKPOINT1\0"):
                cache.entries[index] = key, bytes([value[0] ^ 1]) + value[1:]
        row, proof = produce(self.template, 1, cache)
        with self.assertRaisesRegex(ValueError, "INPUT_BINDING"):
            verify_complete_attempt(self.template, 1, row, proof)

    def test_rehashed_cost_savings_omissions_and_qualification_claims_cannot_pass_replay(self):
        record = execute_cache_comparison((self.template,), ((0, 0),), (0, 4096))
        for kind in ("work", "cache", "attempt", "claim", "source"):
            altered = deepcopy(record)
            if kind == "work":
                altered["cells"][0]["work_units_total"]["proof_bytes_materialized"] = 0
            elif kind == "cache":
                altered["cells"][1]["cache"]["counters"]["key_bytes_compared"] += 1
            elif kind == "attempt":
                altered["cells"][0]["attempts"] = []
            elif kind == "claim":
                altered["claims"]["same_total_economic_budget_proved"] = True
            else:
                altered["source_sha256"]["formal/pon-nakamoto-v1/w1_preprocessing_cache.py"] = "0" * 64
            altered["record_sha256"] = hashlib.sha256(canonical({k: v for k, v in altered.items() if k != "record_sha256"})).hexdigest()
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "REPLAY_MISMATCH"):
                verify_cache_comparison(altered)

    def test_invalid_plans_rejected_before_any_producer_or_cache_use(self):
        cases = (((), ((0, 0),), (0,)), ((self.template,), ((True, 0),), (0,)),
                 ((self.template,), ((0, True),), (0,)), ((self.template,), ((0, 8),), (0,)),
                 ((self.template,), ((0, 0),), (0, 0)), ((self.template,), ((0, 0),), (True,)))
        with patch("w1_preprocessing_cache.produce", side_effect=AssertionError("producer ran")):
            for templates, schedule, capacities in cases:
                with self.subTest(schedule=schedule, capacities=capacities), self.assertRaises(ValueError):
                    execute_cache_comparison(templates, schedule, capacities)

    def test_native_shape_complete_bytes_match_independent_correction_identity_and_native_verifier(self):
        import work_oracle
        p = fixture(Shape(), nonce_bits=1)
        cache = PayloadLRU(262144)
        row, proof = produce(p, 0, cache)
        reviewed = verify_complete_attempt(p, 0, row, proof)
        self.assertEqual(reviewed["relation"], "independent-native-work-oracle")
        self.assertEqual(row["proof_bytes"], work_oracle.PROOF_BYTES)
        self.assertEqual(row["work_units"]["trace_prefix_words"], 64**3 // 8)
        ticket, _ = work_oracle.verify(bytes.fromhex(row["challenge"]), p.header[278:310],
                                       p.target.to_bytes(32, "big"), proof)
        self.assertEqual(ticket.hex(), row["ticket"])
        self.assertFalse(reviewed["native_block_admitted"])


if __name__ == "__main__":
    unittest.main()
