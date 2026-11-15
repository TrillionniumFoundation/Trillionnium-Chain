import copy
import unittest

from performance_economics import METERS, PEAKS, SCHEMA, summarize, unique


def fixture():
    rows = []
    for op, outcome, finish in (("a", "success", 10), ("b", "rejected", 20), ("c", "success", 90)):
        rows.append(dict(operation_id=op, outcome=outcome, started_ns=0,
                         finished_ns=finish, accepted_units=int(outcome == "success"),
                         cost_minor=7, lifecycle_terminal=True,
                         **{k: 3 for k in METERS}, **{k: 8 for k in PEAKS}))
    return dict(schema=SCHEMA, campaign_id="controlled-fixture", clock_scope="single-observer-monotonic",
                window_ns=100, money_unit="fixed-test-minor-unit",
                planned=[dict(operation_id=op, kind="work_verification", deadline_ns=50,
                              accepted_unit="verified_statements") for op in ("a", "b", "c")],
                observations=rows, settlements=[])


class AccountingTests(unittest.TestCase):
    def test_failure_and_late_success_stay_in_cost_and_denominator(self):
        out = summarize(fixture())
        m = out["metrics"]["work_verification"]
        self.assertEqual(m["planned"], 3)
        self.assertEqual(m["successful"], 2)
        self.assertEqual(m["on_time_successful"], 1)
        self.assertEqual(m["cost_minor_including_failures"], 21)
        self.assertEqual(m["all_outcome_resource_totals"]["cpu_ns"], 9)
        self.assertIsNone(m["successful_latency_p99_ns"])
        self.assertIsNone(m["successful_latency_p95_ns"])
        self.assertFalse(out["public_throughput_qualified"])

    def test_unknown_cost_never_becomes_zero(self):
        doc = fixture()
        doc["observations"][1]["cost_minor"] = None
        doc["observations"][1]["cpu_ns"] = None
        out = summarize(doc)
        self.assertIsNone(out["economics"]["declared_observed_to_date_cost_minor"])
        self.assertIsNone(out["economics"]["conditional_observed_to_date_external_net_minor_excluding_subsidy_and_internal_transfers"])
        self.assertIsNone(out["metrics"]["work_verification"]["all_outcome_resource_totals"]["cpu_ns"])

    def test_internal_transfers_and_subsidies_are_not_external_revenue(self):
        doc = fixture()
        for i, kind in enumerate(("protocol_subsidy", "internal_transfer", "external_customer_revenue", "refund")):
            doc["settlements"].append(dict(receipt_id=f"{i:064x}", operation_id="a", kind=kind,
                                           amount_minor=(10000, 10000, 30, 2)[i], money_unit=doc["money_unit"]))
        out = summarize(doc)["economics"]
        self.assertEqual(out["conditional_observed_to_date_external_net_minor_excluding_subsidy_and_internal_transfers"], 7)
        self.assertFalse(out["sustainable_rewards_qualified"])
        self.assertFalse(out["settlement_authenticity_verified"])

    def test_missing_operation_is_rejected(self):
        doc = fixture()
        doc["observations"].pop()
        with self.assertRaisesRegex(ValueError, "COMPLETE_DENOMINATOR"):
            summarize(doc)

    def test_duplicate_operation_cannot_replace_missing_one(self):
        doc = fixture()
        doc["observations"][2] = copy.deepcopy(doc["observations"][0])
        with self.assertRaisesRegex(ValueError, "OBSERVATION_ID"):
            summarize(doc)

    def test_failed_operation_cannot_mint_credit(self):
        doc = fixture()
        doc["observations"][1]["accepted_units"] = 1
        with self.assertRaisesRegex(ValueError, "FAILED_OPERATION_CREDIT"):
            summarize(doc)

    def test_boolean_negative_and_float_meters_are_rejected(self):
        for value in (True, -1, 1.0, float("inf"), 1 << 128):
            with self.subTest(value=value):
                doc = fixture()
                doc["observations"][0]["cpu_ns"] = value
                with self.assertRaises(ValueError):
                    summarize(doc)

    def test_unknown_started_attempt_preserves_cost(self):
        doc = fixture()
        row = doc["observations"][1]
        row.update(outcome="unknown", finished_ns=None, cost_minor=9, lifecycle_terminal=False)
        out = summarize(doc)
        self.assertEqual(out["economics"]["declared_observed_to_date_cost_minor"], 23)
        self.assertEqual(out["metrics"]["work_verification"]["outcomes"]["unknown"], 1)
        self.assertIsNone(out["economics"]["conditional_completed_declared_lifecycle_cost_minor"])
        self.assertIsNone(out["economics"]["conditional_completed_declared_lifecycle_external_net_minor"])

    def test_partial_lifecycle_cannot_claim_final_profit(self):
        doc = fixture()
        doc["observations"][1].update(outcome="timeout", lifecycle_terminal=False)
        doc["settlements"] = [dict(receipt_id="3" * 64, operation_id="a", kind="external_customer_revenue",
                                   amount_minor=100, money_unit=doc["money_unit"])]
        out = summarize(doc)["economics"]
        self.assertEqual(out["conditional_observed_to_date_external_net_minor_excluding_subsidy_and_internal_transfers"], 79)
        self.assertIsNone(out["conditional_completed_declared_lifecycle_external_net_minor"])
        self.assertFalse(out["all_declared_lifecycles_terminal"])

    def test_even_sample_p50_is_explicit_nearest_rank(self):
        out = summarize(fixture())["metrics"]["work_verification"]
        self.assertEqual(out["successful_latency_p50_nearest_rank_ns"], 10)
        self.assertNotIn("successful_latency_median_ns", out)

    def test_unobserved_finish_cannot_claim_closed_lifecycle(self):
        doc = fixture()
        doc["observations"][1].update(outcome="unknown", finished_ns=None)
        with self.assertRaisesRegex(ValueError, "LIFECYCLE_TERMINAL_WITHOUT_FINISH"):
            summarize(doc)

    def test_clock_reversal_and_incompatible_clock_refused(self):
        for change in ("reverse", "different_clock"):
            doc = fixture()
            if change == "reverse":
                doc["observations"][0].update(started_ns=20, finished_ns=10)
            else:
                doc["clock_scope"] = "cross-host-wall-clock"
            with self.assertRaises(ValueError):
                summarize(doc)

    def test_receipt_replay_and_mixed_money_units_refused(self):
        row = dict(receipt_id="1" * 64, operation_id="a", kind="external_customer_revenue",
                   amount_minor=10, money_unit="fixed-test-minor-unit")
        doc = fixture()
        doc["settlements"] = [row, copy.deepcopy(row)]
        with self.assertRaisesRegex(ValueError, "SETTLEMENT_REPLAY"):
            summarize(doc)
        doc["settlements"] = [dict(row, money_unit="unconverted-other-unit")]
        with self.assertRaisesRegex(ValueError, "MONEY_UNIT_MISMATCH"):
            summarize(doc)

    def test_unknown_refund_blocks_net(self):
        doc = fixture()
        doc["settlements"] = [dict(receipt_id="2" * 64, operation_id="a", kind="refund",
                                   amount_minor=None, money_unit=doc["money_unit"])]
        self.assertIsNone(summarize(doc)["economics"]["conditional_observed_to_date_external_net_minor_excluding_subsidy_and_internal_transfers"])

    def test_empty_kinds_have_unknown_cost_not_free_service(self):
        m = summarize(fixture())["metrics"]["device_load"]
        self.assertIsNone(m["cost_minor_including_failures"])
        self.assertIsNone(m["all_outcome_resource_totals"]["gpu_ns"])
        self.assertIsNone(m["deadline_success_fraction"])
        self.assertIsNone(m["on_time_units_per_second"])

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            unique([("cpu_ns", 3), ("cpu_ns", 0)])

    def test_mixed_goodput_units_are_refused(self):
        doc = fixture()
        for row in doc["planned"]:
            row.update(kind="cell_retrieval", accepted_unit="verified_payload_bytes")
        doc["planned"][1]["accepted_unit"] = "complete_cells"
        with self.assertRaisesRegex(ValueError, "ACCEPTED_UNIT"):
            summarize(doc)

    def test_goodput_reports_the_frozen_physical_unit(self):
        out = summarize(fixture())
        self.assertEqual(out["metrics"]["work_verification"]["accepted_unit"], "verified_statements")
        self.assertEqual(out["metrics"]["cell_retrieval"]["accepted_unit"], "verified_payload_bytes")


if __name__ == "__main__":
    unittest.main()
