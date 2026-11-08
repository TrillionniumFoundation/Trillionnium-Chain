"""Full native-shape relation controls; no native-node or lower-bound claim."""
from copy import deepcopy
from dataclasses import replace
import unittest

import legal_optimization_catalog_v1 as catalog
import work_oracle


class LegalOptimizationCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = catalog.build_report()
        cls.summary = catalog.replay_report(cls.report)
        cls.materials = catalog.materials()
        cls.identity = bytes.fromhex(catalog.digest(catalog.canonical(cls.report["source_before"]["files_sha256"])))

    def refusal(self, mutation, message):
        report = deepcopy(self.report)
        mutation(report)
        with self.assertRaisesRegex(ValueError, message):
            catalog.replay_report(report)

    def test_complete_predeclared_grid_replays_every_attempt(self):
        self.assertEqual(self.summary["cohorts"], 24)
        self.assertEqual(self.summary["complete_relation_replays"], 96)
        self.assertEqual(self.summary["controlled_cancellations"], 24)
        self.assertEqual(self.summary["original_target_accepted_candidates"]
                         + self.summary["original_target_refusals"], 96)
        self.assertEqual(self.summary["qualification"], "HOLD_NO_GO")
        self.assertEqual(self.summary["native_admitted_blocks"], 0)
        self.assertFalse(self.summary["minimum_legal_cost_proved"])

    def test_rank_paths_include_paid_failed_probes_and_zero(self):
        rows = {r["material"]: r for r in self.report["cohorts"]
                if r["profile"] == "PNH1" and r["strategy"] == "prepared-rank-8"}
        self.assertEqual(rows["dense"]["preparation"]["method"], "dense-after-two-failed-probes")
        self.assertEqual([p["minimum_rank"] for p in rows["dense"]["preparation"]["rank_probes"]], [9, 9])
        self.assertEqual(rows["left-rank-2"]["preparation"]["rank_probes"][0]["rank"], 2)
        self.assertEqual(rows["right-rank-4"]["preparation"]["method"], "right-low-rank")
        self.assertEqual([p["completed"] for p in rows["right-rank-4"]["preparation"]["rank_probes"]], [False, True])
        self.assertEqual(rows["right-rank-4"]["preparation"]["rank_probes"][1]["rank"], 4)
        self.assertEqual(rows["zero"]["preparation"]["rank_probes"][0]["rank"], 0)

    def test_misses_withheld_and_post_first_hit_work_are_retained(self):
        actual = {key: 0 for key in ("target-miss", "withheld-hit", "local-extraction", "cancelled")}
        for row in self.report["cohorts"]:
            hits = [a["nonce"] for a in row["attempts"] if a["target_hit"] is True]
            self.assertEqual(row["chosen_nonce"], hits[0] if hits else None)
            self.assertEqual([a["nonce"] for a in row["attempts"]], list(range(5)))
            for attempt in row["attempts"]:
                actual[attempt["disposition"]] += 1
        self.assertGreater(actual["target-miss"], 0)
        self.assertGreater(actual["withheld-hit"], 0)
        self.assertGreater(self.summary["post_first_hit_complete_attempts"], 0)
        self.assertEqual(actual["cancelled"], 24)
        self.assertEqual(actual["target-miss"], self.summary["original_target_refusals"])

    def test_bank_rejects_parent_target_time_witness_and_source_rebinding(self):
        for profile in ("PNH1", "PGH2"):
            template = catalog.fixture_template(self.materials["dense"], profile)
            proof = bytes.fromhex(next(r for r in self.report["cohorts"]
                                      if r["profile"] == profile)["proof_prefix_hex"])
            proof += bytes(32)
            bank = catalog.CandidateBank(template, self.identity)
            bank.store(template, self.identity, 0, proof)
            for offset in (template.base + 70, template.base + 110, template.base + 118):
                header = bytearray(template.header)
                header[offset] ^= 1
                changed = replace(template, header=bytes(header))
                with self.subTest(profile=profile, offset=offset), self.assertRaisesRegex(ValueError, "BANK_DOMAIN"):
                    bank.take(changed, self.identity, 0)
            if profile == "PGH2":
                changed = replace(template, header=template.header[:-1] + bytes([template.header[-1] ^ 1]))
                with self.assertRaisesRegex(ValueError, "BANK_DOMAIN"):
                    bank.take(changed, self.identity, 0)
            with self.assertRaisesRegex(ValueError, "BANK_DOMAIN"):
                bank.take(template, bytes(32), 0)
            self.assertEqual(bank.take(template, self.identity, 0), proof)

    def test_bank_cannot_refill_or_reextract_one_candidate(self):
        template = catalog.fixture_template(self.materials["zero"], "PNH1")
        bank = catalog.CandidateBank(template, self.identity)
        proof = bytes(catalog.PROOF_BYTES)
        bank.store(template, self.identity, 0, proof)
        with self.assertRaisesRegex(ValueError, "BANK_DUPLICATE"):
            bank.store(template, self.identity, 0, proof)
        bank.take(template, self.identity, 0)
        with self.assertRaisesRegex(ValueError, "BANK_NOT_AVAILABLE"):
            bank.take(template, self.identity, 0)
        with self.assertRaisesRegex(ValueError, "BANK_DUPLICATE"):
            bank.store(template, self.identity, 0, proof)

    def test_cached_bytes_never_confer_verification_authority(self):
        row = self.report["cohorts"][0]
        template = catalog.fixture_template(self.materials["dense"], "PNH1")
        proof = bytearray.fromhex(row["proof_prefix_hex"] + row["attempts"][0]["trace"])
        offset = catalog.PROOF_BYTES - 36
        value = (int.from_bytes(proof[offset:offset + 4], "little") + 1) % catalog.Q
        proof[offset:offset + 4] = value.to_bytes(4, "little")
        bank = catalog.CandidateBank(template, self.identity)
        bank.store(template, self.identity, 0, bytes(proof))
        output = bank.take(template, self.identity, 0)
        with self.assertRaisesRegex(ValueError, "PRODUCT"):
            work_oracle.verify(template.challenge(0), template.task, catalog.MAX_TARGET, output)

    def test_rank_validates_all_words_before_early_failure(self):
        values = list(self.materials["dense"][0])
        for invalid in (True, -1, catalog.Q):
            values[-1] = invalid
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "FIELD"):
                catalog.factor_rank_bounded(values)

    def test_boolean_and_noninteger_nonce_are_rejected(self):
        template = catalog.fixture_template(self.materials["zero"], "PNH1")
        for nonce in (True, -1, 0.0, 1 << 64):
            with self.subTest(nonce=nonce), self.assertRaisesRegex(ValueError, "NONCE"):
                template.header_for(nonce)
        self.refusal(lambda r: r["cohorts"][0]["attempts"][0].update(nonce=False), "NONCE_ORDER")

    def test_missing_miss_or_cancelled_record_refuses(self):
        self.refusal(lambda r: r["cohorts"][0]["attempts"].pop(0), "ATTEMPT_COVERAGE")
        self.refusal(lambda r: r["cohorts"][0]["attempts"].pop(), "ATTEMPT_COVERAGE")

    def test_missing_or_repeated_cohort_refuses(self):
        self.refusal(lambda r: r["cohorts"].pop(), "GRID_COVERAGE")
        self.refusal(lambda r: r["cohorts"].__setitem__(1, r["cohorts"][0]), "COHORT_IDENTITY")

    def test_rank_probe_erasure_refuses(self):
        self.refusal(lambda r: r["cohorts"][2]["preparation"].update(rank_probes=[]), "PREPARATION_PATH")

    def test_false_product_with_consistent_proof_hash_reaches_full_verifier(self):
        def change(report):
            row = report["cohorts"][0]
            prefix = bytearray.fromhex(row["proof_prefix_hex"])
            word = int.from_bytes(prefix[-4:], "little")
            prefix[-4:] = ((word + 1) % catalog.Q).to_bytes(4, "little")
            row["proof_prefix_hex"] = prefix.hex()
            for attempt in row["attempts"][:4]:
                attempt["proof_sha256"] = catalog.digest(prefix + bytes.fromhex(attempt["trace"]))
        self.refusal(change, "PRODUCT")

    def test_false_transcript_with_consistent_ticket_and_proof_hash_refuses(self):
        def change(report):
            row = report["cohorts"][0]
            a = row["attempts"][0]
            trace = bytes(32)
            ticket = catalog.framed_hash(b"ticket", bytes.fromhex(a["challenge"]), trace)
            template = catalog.fixture_template(self.materials["dense"], "PNH1")
            a.update(trace=trace.hex(), ticket=ticket.hex(), target_hit=ticket <= template.target,
                     proof_sha256=catalog.digest(bytes.fromhex(row["proof_prefix_hex"]) + trace))
        self.refusal(change, "TRANSCRIPT")

    def test_lottery_miss_cannot_be_promoted_to_original_target_acceptance(self):
        def change(report):
            row = report["cohorts"][0]
            attempt = next(a for a in row["attempts"][:4] if not a["target_hit"])
            attempt["target_hit"] = True
        self.refusal(change, "LOTTERY_RESULT")

    def test_cancelled_prefix_is_actually_replayed(self):
        self.refusal(lambda r: r["cohorts"][0]["attempts"][4].update(partial_trace_sha256="00" * 32),
                     "CANCELLED_PREFIX_REPLAY")

    def test_cancellation_cannot_claim_a_proof_or_ticket(self):
        self.refusal(lambda r: r["cohorts"][0]["attempts"][4].update(ticket="00" * 32), "ATTEMPT_FIELDS")

    def test_bank_inventory_and_extraction_cannot_be_rewritten(self):
        self.refusal(lambda r: r["cohorts"][0].update(bank_remaining_nonces=[]), "BANK_INVENTORY")
        self.refusal(lambda r: r["cohorts"][0].update(extracted_proof_sha256="00" * 32), "BANK_EXTRACTION_IDENTITY")

    def test_header_and_profile_cannot_be_rebound(self):
        self.refusal(lambda r: r["cohorts"][0].update(header_hex="00" * 318), "HEADER_BINDING")
        self.refusal(lambda r: r["cohorts"][0].update(profile="PGH2"), "COHORT_IDENTITY")

    def test_boolean_timing_or_negative_cost_refuses(self):
        self.refusal(lambda r: r["cohorts"][0]["setup_timing"].update(cpu_ns=True), "TIMING_INTEGER")
        self.refusal(lambda r: r["cohorts"][0]["attempts"][0]["timing"].update(cpu_ns=-1), "TIMING_INTEGER")

    def test_inclusive_timer_cannot_erase_nested_attempt_cpu(self):
        self.refusal(lambda r: r["cohorts"][0]["producer_inclusive_timing"].update(cpu_ns=0), "INCLUSIVE_CPU_WINDOW")

    def test_source_change_or_rebinding_refuses(self):
        self.refusal(lambda r: r["source_after"].update(git_head="0" * 40), "SOURCE_CHANGED_DURING_EXECUTION")
        def change(report):
            report["source_before"]["files_sha256"][catalog.CATALOG_PATH] = "0" * 64
            report["source_after"] = deepcopy(report["source_before"])
        self.refusal(change, "SOURCE_IDENTITY")

    def test_claims_and_unknown_physical_costs_cannot_be_promoted(self):
        self.refusal(lambda r: r["claims"].update(minimum_legal_cost_proved=True), "QUALIFICATION_CLAIMS")
        self.refusal(lambda r: r["cost_scope"].update(energy_joules=0), "COST_SCOPE")

    def test_fixed_grid_and_batch_policy_cannot_change(self):
        self.refusal(lambda r: r["catalog"].update(batch_width=True), "CATALOG_BINDING")
        self.refusal(lambda r: r["environment"].update(workers_per_batch=True), "ENVIRONMENT_VALUES")

    def test_common_template_preparation_costs_cannot_be_dropped(self):
        self.refusal(lambda r: r["shared_template_timings"].pop("PNH1:dense"), "TEMPLATE_COST_COVERAGE")

    def test_reader_rejects_duplicate_keys_floats_and_nonfinite(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                catalog.strict_json(raw)
        self.assertEqual(catalog.strict_json(b'{"a":1}'), {"a": 1})


if __name__ == "__main__":
    unittest.main()
