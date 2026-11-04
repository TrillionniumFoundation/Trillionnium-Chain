"""Hand-checkable consensus/ledger controls for the explicitly scoped profile."""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from parallel_variable_ohie import (
    ASSUMPTIONS, Block, BudgetPhase, Limits, ModelLimit, Profile, Scenario, Simulation,
    State, Template, Transaction, block_from_dict, candidate, checked, heavier,
    next_rank, parent_commitment, run_scenario, sortition_counts, topological_blocks,
)


SMALL = Profile(chains=2, hash_bits=8, initial_target=128, epoch_blocks=2,
                target_block_rounds=2, confirmation_lag_rounds=2)


def fixture(template: Template, profile: Profile, chain: int, start: int = 0) -> Block:
    # Finite fixture construction with a real header hash, not forced successes.
    for nonce in range(start, start + 16384):
        block = candidate(template, nonce, profile)
        if block.chain == chain and block.ticket(profile.hash_bits) < block.target:
            return block
    raise AssertionError("FIXTURE_QUERY_BOUND")


def extend(state: State, chain: int, timestamp: int, *, pivot: str | None = None,
           parent: str | None = None, target: int | None = None,
           txs: tuple[Transaction, ...] = (), trailing: str | None = None,
           admit: bool = True, miner: str = "fixture", now: int = 1000) -> Block:
    parents = list(state.tips)
    if parent is not None:
        parents[chain] = parent
    if pivot is not None:
        parents[0] = pivot
    selected = tuple(parents)
    trail = trailing or max(selected, key=lambda block_id: state.records[block_id].next_rank)
    template = Template(state.identity, selected, trail, timestamp,
                        state.required_target(selected[0]) if target is None else target, miner, txs)
    block = fixture(template, state.profile, chain)
    if admit:
        result = state.receive(block, now)
        if result.status != "ACCEPTED":
            raise AssertionError((result, block))
    return block


class ArithmeticAndHashTests(unittest.TestCase):
    def test_profile_rejects_invalid_parameters_and_boolean_integers(self):
        cases = [replace(SMALL, chains=3), replace(SMALL, chains=True),
                 replace(SMALL, initial_target=257), replace(SMALL, epoch_blocks=0),
                 replace(SMALL, target_block_rounds=False), replace(SMALL, arithmetic_bits=8),
                 replace(SMALL, genesis_tokens=("gen:0", "gen:0"))]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                case.validate()

    def test_common_parent_commitment_and_post_hash_sortition(self):
        state = State(SMALL)
        template = state.template(1, "m0")
        block = fixture(template, SMALL, 1)
        self.assertEqual(block.commitment, parent_commitment(template.parents))
        self.assertNotEqual(block.commitment, parent_commitment(tuple(reversed(template.parents))))
        self.assertNotIn("chain", block.header())
        self.assertEqual(block.chain, block.ticket(SMALL.hash_bits) & 1)
        wrong = replace(block, chain=0)
        self.assertEqual(state.receive(wrong, 1).reason, "CHAIN_SORTITION")
        self.assertEqual(len(state.records), 2)

    def test_exclusive_target_and_sortition_are_not_independent(self):
        self.assertEqual(sortition_counts(1, 2), (1, 0))
        self.assertEqual(sortition_counts(5, 4), (2, 1, 1, 1))
        self.assertEqual(sortition_counts(8, 4), (2, 2, 2, 2))
        state = State(replace(SMALL, initial_target=1))
        template = state.template(1, "m0")
        zero = fixture(template, state.profile, 0)
        self.assertEqual(zero.ticket(state.profile.hash_bits), 0)
        self.assertEqual(state.receive(zero, 1).status, "ACCEPTED")
        # T=1 admits only ticket 0; chain 1 has zero marked tickets.
        for nonce in range(64):
            block = candidate(template, nonce, state.profile)
            if block.ticket(state.profile.hash_bits) >= 1:
                self.assertEqual(State(state.profile).receive(block, 1).reason, "POW_THRESHOLD")
                break
        else:
            self.fail("No failing finite ticket in deterministic control")

    def test_header_commitment_and_payload_are_bound(self):
        state = State(SMALL)
        block = fixture(state.template(1, "m0"), SMALL, 0)
        self.assertEqual(state.receive(replace(block, commitment="f" * 64), 1).reason, "PARENT_COMMITMENT")
        changed = replace(block, transactions=(Transaction("changed", "gen:0"),))
        self.assertEqual(state.receive(changed, 1).reason, "HEADER_HASH")
        self.assertEqual(state.receive(replace(block, nonce=block.nonce + 1), 1).reason, "HEADER_HASH")

    def test_rank_counterexample_uses_section_4_2(self):
        self.assertEqual(next_rank(Fraction(5), Fraction(3), Fraction(6)), Fraction(8))
        self.assertEqual(next_rank(Fraction(5), Fraction(3), Fraction(9)), Fraction(9))
        self.assertEqual(next_rank(Fraction(5, 3), Fraction(2, 3), Fraction(2)), Fraction(7, 3))
        with self.assertRaises(OverflowError):
            checked(Fraction(1 << 512), 512)

    def test_exact_rational_credit_and_bounds(self):
        state = State(replace(SMALL, initial_target=85))
        block = extend(state, 0, 1)
        self.assertEqual(state.records[block.block_id].credit, Fraction(256, 85))
        limited = State(replace(SMALL, initial_target=1, epoch_blocks=8, arithmetic_bits=9))
        first = extend(limited, 0, 1)
        second = extend(limited, 0, 2, admit=False)
        result = limited.receive(second, 1000)
        self.assertEqual(result.reason, "RATIONAL_ARITHMETIC_BOUND")
        self.assertEqual(limited.tips[0], first.block_id)
        self.assertEqual(limited.metrics["accepted"], 1)

    def test_retarget_branch_duration_and_ceiling_clamp(self):
        state = State(replace(SMALL, initial_target=101, target_block_rounds=100))
        extend(state, 0, 1)
        boundary = extend(state, 0, 2)
        self.assertEqual(state.required_target(boundary.block_id), 26)  # ceil(101/4)
        slow = State(replace(SMALL, initial_target=41, target_block_rounds=1))
        extend(slow, 0, 50)
        end = extend(slow, 0, 100)
        self.assertEqual(slow.required_target(end.block_id), 164)
        capped = State(replace(SMALL, initial_target=128, target_block_rounds=1))
        extend(capped, 0, 50)
        end = extend(capped, 0, 100)
        self.assertEqual(capped.required_target(end.block_id), 256)


class AdmissionTests(unittest.TestCase):
    def test_wrong_tree_reference_and_cross_profile_comparison(self):
        state = State(SMALL)
        template = replace(state.template(1, "m0"), parents=tuple(reversed(state.genesis)))
        wrong_tree = fixture(template, SMALL, 1)
        self.assertEqual(state.receive(wrong_tree, 1).reason, "PARENT_CHAIN")
        other = State(replace(SMALL, confirmation_lag_rounds=3))
        valid = fixture(other.template(1, "m0"), other.profile, 0)
        self.assertEqual(state.receive(valid, 1).reason, "PROFILE_MISMATCH")
        with self.assertRaisesRegex(ValueError, "INCOMPATIBLE"):
            heavier(state.records[state.genesis[0]], other.records[other.genesis[0]])

    def test_off_branch_target_is_checked_against_committed_pivot(self):
        state = State(SMALL)
        fast1 = extend(state, 0, 1)
        fast2 = extend(state, 0, 2)
        fast3 = extend(state, 0, 3)
        self.assertEqual(state.records[fast3.block_id].target, 64)
        slow1 = extend(state, 0, 2, parent=state.genesis[0], miner="slow")
        slow2 = extend(state, 0, 4, parent=slow1.block_id, miner="slow")
        self.assertEqual(state.tips[0], fast3.block_id)
        self.assertEqual(state.required_target(slow2.block_id), 128)
        wrong = extend(state, 1, 5, pivot=slow2.block_id, target=64, admit=False)
        self.assertEqual(state.receive(wrong, 1000).reason, "REQUIRED_TARGET")
        right = extend(state, 1, 5, pivot=slow2.block_id)
        self.assertEqual(state.records[right.block_id].pivot, slow2.block_id)
        self.assertNotEqual(state.records[right.block_id].pivot, state.tips[0])
        self.assertNotEqual(fast1.block_id, fast2.block_id)

    def test_m2_uses_cumulative_work_and_allows_a_heavier_pivot_fork(self):
        state = State(SMALL)
        extend(state, 0, 1)
        extend(state, 0, 2)
        hard = extend(state, 0, 3)
        old_voter = extend(state, 1, 4, pivot=hard.block_id)
        easy_parent = state.genesis[0]
        easy = []
        for timestamp in (8, 12, 16, 20, 24, 28, 32):
            block = extend(state, 0, timestamp, parent=easy_parent, miner="easy")
            easy_parent = block.block_id
            easy.append(block)
        lower = easy[3]
        self.assertGreater(state.records[lower.block_id].height, state.records[hard.block_id].height)
        self.assertLess(state.records[lower.block_id].chainwork, state.records[hard.block_id].chainwork)
        invalid = extend(state, 1, 33, pivot=lower.block_id, parent=old_voter.block_id, admit=False)
        self.assertEqual(state.receive(invalid, 1000).reason, "PIVOT_WORK_DECREASE")
        self.assertGreater(state.records[easy[-1].block_id].chainwork, state.records[hard.block_id].chainwork)
        valid = extend(state, 1, 34, pivot=easy[-1].block_id, parent=old_voter.block_id)
        self.assertEqual(state.records[valid.block_id].pivot, easy[-1].block_id)
        self.assertNotIn(hard.block_id, [entry.block_id for entry in state.path(easy[-1].block_id)])

    def test_equal_weight_keeps_first_admitted_tip(self):
        state = State(SMALL)
        template = state.template(1, "m0")
        first = fixture(template, SMALL, 0)
        second = fixture(template, SMALL, 0, first.nonce + 1)
        state.receive(first, 1)
        state.receive(second, 1)
        self.assertEqual(state.tips[0], first.block_id)
        reversed_view = State(SMALL)
        reversed_view.receive(second, 1)
        reversed_view.receive(first, 1)
        self.assertEqual(reversed_view.tips[0], second.block_id)

    def test_missing_dependencies_resolve_and_reverse_bundle_is_ordered(self):
        producer = State(SMALL)
        parent = extend(producer, 0, 1)
        child = extend(producer, 1, 2)
        receiver = State(SMALL)
        self.assertEqual(receiver.receive(child, 5).reason, "MISSING_DEPENDENCY")
        self.assertEqual(receiver.metrics["accepted"], 0)
        receiver.receive(parent, 5)
        self.assertIn(child.block_id, receiver.records)
        self.assertEqual(receiver.metrics["resolved_pending"], 1)
        self.assertEqual(receiver.pending, {})
        bundled = State(SMALL)
        results = bundled.receive_bundle((child, parent), 5)
        self.assertTrue(all(result.status == "ACCEPTED" for result in results))
        self.assertEqual(bundled.tips, receiver.tips)

    def test_future_bundle_waits_for_dependencies_and_time(self):
        producer = State(SMALL)
        parent = extend(producer, 0, 9)
        child = extend(producer, 1, 10)
        receiver = State(SMALL)
        receiver.receive_bundle((child, parent), 5)
        self.assertEqual(len(receiver.pending), 2)
        receiver.advance(9)
        self.assertIn(parent.block_id, receiver.records)
        self.assertNotIn(child.block_id, receiver.records)
        receiver.advance(10)
        self.assertIn(child.block_id, receiver.records)
        self.assertFalse(receiver.pending)
        with self.assertRaisesRegex(ValueError, "ROUND_REWIND"):
            receiver.advance(8)

    def test_timestamp_and_pending_invalid_parent_controls(self):
        producer = State(SMALL)
        parent = extend(producer, 0, 2)
        invalid = extend(producer, 1, 2, admit=False)
        receiver = State(SMALL)
        receiver.receive(invalid, 3)
        receiver.receive(parent, 3)
        self.assertNotIn(invalid.block_id, receiver.records)
        self.assertEqual(receiver.metrics["rejected_pending"], 1)
        self.assertEqual(receiver.metrics["deferred"], receiver.metrics["resolved_pending"]
                         + receiver.metrics["rejected_pending"] + len(receiver.pending))
        self.assertEqual(receiver.rejection_reasons, {"PARENT_TIMESTAMP": 1})

    def test_cycle_and_conflicting_envelopes_rejected_without_partial_import(self):
        state = State(SMALL)
        a = fixture(state.template(1, "a"), SMALL, 0)
        b = fixture(state.template(1, "b"), SMALL, 1)
        cycle_a = replace(a, trailing=b.block_id)
        cycle_b = replace(b, trailing=a.block_id)
        with self.assertRaisesRegex(ValueError, "CYCLIC_BUNDLE"):
            state.receive_bundle((cycle_a, cycle_b), 2)
        self.assertEqual(state.metrics["accepted"], 0)
        with self.assertRaisesRegex(ValueError, "CONFLICTING_BLOCK_ENVELOPE"):
            topological_blocks((a, replace(a, chain=1)))
        with self.assertRaises(ValueError):
            state.receive_bundle((a, replace(b, nonce=b.nonce + 1)), 2)
        self.assertEqual(state.metrics["accepted"], 0)
        with self.assertRaisesRegex(ValueError, "PARENT_VECTOR"):
            state.receive_bundle((replace(a, parents=state.genesis * 1000),), 2)

    def test_storage_pending_and_payload_bounds(self):
        limited = State(SMALL, Limits(max_blocks=3, max_pending_blocks=1))
        first = extend(limited, 0, 1)
        second = extend(limited, 0, 2, admit=False)
        with self.assertRaisesRegex(ModelLimit, "BLOCK_STORAGE_LIMIT"):
            limited.receive(second, 1000)
        self.assertIn(first.block_id, limited.records)
        producer = State(SMALL)
        extend(producer, 0, 1)
        child = extend(producer, 1, 2)
        second_child = extend(producer, 1, 3)
        waiting = State(SMALL, Limits(max_pending_blocks=1))
        waiting.receive(child, 5)
        with self.assertRaisesRegex(ModelLimit, "PENDING_BLOCK_LIMIT"):
            waiting.receive(second_child, 5)
        template = State(SMALL).template(1, "m0", (Transaction("x", "gen:0"),) * 17)
        oversized = fixture(template, SMALL, 0)
        self.assertEqual(State(SMALL).receive(oversized, 1).reason, "TRANSACTION_COUNT")

    def test_block_serialization_rejects_field_substitution(self):
        state = State(SMALL)
        block = fixture(state.template(1, "m0"), SMALL, 1)
        raw = json.loads(json.dumps(block.as_dict()))
        self.assertEqual(block_from_dict(raw), block)
        with self.assertRaisesRegex(ValueError, "BLOCK_FIELDS"):
            block_from_dict({**raw, "claimed_chainwork": 1000})


class LedgerTests(unittest.TestCase):
    def test_one_withheld_chain_blocks_global_confirmation(self):
        state = State(replace(SMALL, epoch_blocks=8))
        probe = Transaction("probe", "gen:0")
        for timestamp in range(1, 6):
            extend(state, 0, timestamp, txs=(probe,) if timestamp == 1 else ())
        before = state.ledger()
        self.assertEqual(before.confirmation_bar, Fraction(1))
        self.assertFalse(before.blocks)
        self.assertNotIn(probe.txid, before.transactions)
        extend(state, 1, 6)
        after = state.ledger()
        self.assertIn(probe.txid, after.transactions)
        self.assertEqual(after.blocks[0], state.path(state.tips[0])[1].block_id)

    def test_global_rank_order_deduplicates_and_resolves_double_spends(self):
        state = State(replace(SMALL, epoch_blocks=8))
        first = Transaction("first", "gen:0")
        conflict = Transaction("conflict", "gen:0")
        child = Transaction("child", first.txid)
        a = extend(state, 0, 1, txs=(first,), now=1)
        b = extend(state, 1, 2, txs=(conflict, first, child), now=2)
        state.advance(3)
        self.assertEqual(state.ledger().transactions, ())
        state.advance(4)
        ledger = state.ledger()
        self.assertEqual(ledger.blocks, (a.block_id, b.block_id))
        self.assertEqual(ledger.transactions, (first.txid, child.txid))
        self.assertEqual(ledger.labels, ("first", "child"))
        self.assertEqual(ledger.skipped, ((conflict.txid, "INPUT_NOT_UNSPENT"),
                                          (first.txid, "DUPLICATE_TRANSACTION")))
        self.assertEqual(set(ledger.unspent), {"gen:1", child.txid})


class SimulationTests(unittest.TestCase):
    def scenario(self, **updates) -> Scenario:
        return replace(Scenario("control", profile=replace(SMALL, epoch_blocks=8), rounds=60), **updates)

    def assert_accounting(self, summary: dict) -> None:
        counters = list(summary["miner_accounting"].values())
        self.assertEqual(sum(row["queries"] for row in counters), summary["queries_executed"])
        self.assertEqual(sum(row["accepted_blocks"] for row in counters), summary["created_blocks"])
        self.assertEqual(summary["queries_executed"] + summary["queries_not_executed"],
                         summary["queries_scheduled_over_horizon"])
        for row in counters:
            self.assertEqual(row["winning_candidates"], row["accepted_blocks"] + row["discarded_winners"]
                             + row["profile_rejected_winners"])
            self.assertLessEqual(row["winning_candidates"], row["queries"])
        for view in summary["views"].values():
            counts = view["admission"]
            self.assertEqual(counts["deferred"], counts["resolved_pending"] + counts["rejected_pending"]
                             + view["pending_dependency_or_future_blocks"])

    def test_seeded_honest_pipeline_and_delivery_clock(self):
        case = self.scenario(delay_rounds=2)
        summary, trace = run_scenario(case)
        self.assertEqual((summary, trace), run_scenario(case))
        self.assertEqual(summary["termination"], "horizon")
        self.assertTrue(summary["views"]["observer"]["probe_confirmed_at_end"])
        self.assertGreater(summary["views"]["observer"]["fully_confirmed_blocks"], 0)
        self.assert_accounting(summary)
        for row in trace:
            if row["kind"] == "delivery":
                self.assertEqual(row["round"], row["sent_round"] + case.delay_rounds)
        self.assertFalse(summary["security_theorem"])
        self.assertFalse(summary["fast_daa_2026_implemented"])

    def test_private_strategy_withholds_and_ignores_public_imports(self):
        case = self.scenario(queries_per_miner=(2, 2, 2), private_miner=2, private_release_round=25)
        summary, trace = run_scenario(case)
        self.assertGreater(summary["miner_accounting"]["m2"]["accepted_blocks"], 0)
        self.assertGreater(summary["miner_accounting"]["m2"]["ignored_public_deliveries"], 0)
        private_ids = {row["block"]["block_id"] for row in trace if row["kind"] == "query"
                       and row["miner"] == "m2" and row.get("disposition") == "private_withheld"}
        self.assertTrue(private_ids)
        for row in trace:
            if row["kind"] == "delivery" and row["round"] < 25 + case.delay_rounds:
                self.assertFalse(private_ids.intersection(row["roots"]))
        self.assertEqual(summary["private_blocks_still_withheld"], 0)
        self.assert_accounting(summary)

    def test_never_released_private_blocks_and_deliveries_are_censored(self):
        case = self.scenario(private_miner=1, private_release_round=None, delay_rounds=4)
        summary, _ = run_scenario(case)
        self.assertGreater(summary["private_blocks_still_withheld"], 0)
        self.assertGreater(summary["pending_deliveries_censored"], 0)
        self.assert_accounting(summary)

    def test_diagnostic_chain_withholding_is_not_reported_as_honest_liveness(self):
        summary, _ = run_scenario(self.scenario(diagnostic_discard_chain=1))
        self.assertTrue(summary["diagnostic_sortition_discard_enabled"])
        self.assertFalse(summary["views"]["observer"]["probe_confirmed_at_end"])
        self.assertEqual(summary["views"]["observer"]["heights"][1], 0)
        self.assertEqual(summary["views"]["observer"]["fully_confirmed_blocks"], 0)
        self.assertGreater(sum(row["discarded_winners"] for row in summary["miner_accounting"].values()), 0)
        self.assert_accounting(summary)

    def test_participation_phase_boundary_is_exact(self):
        case = self.scenario(rounds=20, budget_phases=(BudgetPhase(10, (0, 0)),))
        self.assertEqual(case.budgets(9), (2, 2))
        self.assertEqual(case.budgets(10), (0, 0))
        summary, trace = run_scenario(case)
        self.assertEqual(summary["queries_executed"], 36)
        self.assertFalse(any(row["kind"] == "query" and row["round"] >= 10 for row in trace))
        self.assert_accounting(summary)

    def test_all_budget_exits_keep_observed_state_and_accounting(self):
        cases = [("event_limit", {"max_events": 1}), ("query_limit", {"max_queries": 1}),
                 ("block_limit", {"max_blocks": 1}), ("trace_limit", {"max_trace_rows": 2}),
                 ("pending_delivery_limit", {"max_pending_deliveries": 1})]
        for termination, updates in cases:
            with self.subTest(termination=termination):
                summary, trace = run_scenario(self.scenario(**updates))
                self.assertEqual(summary["termination"], termination)
                self.assertFalse(summary["horizon_completed"])
                self.assertEqual(trace[-1]["kind"], "finish")
                self.assertLessEqual(len(trace), self.scenario(**updates).max_trace_rows)
                self.assert_accounting(summary)
                for view in summary["views"].values():
                    self.assertEqual(view["ledger"]["round"], summary["observed_round"])
        ticks = iter([0.0, 1.0])
        summary, trace = Simulation(self.scenario(cpu_limit_seconds=0.1), cpu_clock=lambda: next(ticks)).run()
        self.assertEqual(summary["termination"], "cpu_limit")
        self.assertEqual(summary["queries_executed"], 0)
        self.assertEqual(summary["observed_round"], 0)
        self.assertTrue(all(view["ledger"]["round"] == 0 for view in summary["views"].values()))
        self.assertEqual(trace[-1]["kind"], "finish")

    def test_invalid_scenarios_fail_closed(self):
        cases = [self.scenario(queries_per_miner=(True,)), self.scenario(delay_rounds=0),
                 self.scenario(private_release_round=4), self.scenario(diagnostic_discard_chain=2),
                 self.scenario(budget_phases=(BudgetPhase(2, (1,)),)),
                 self.scenario(cpu_limit_seconds=float("nan"))]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                run_scenario(case)


class CampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / "experiments" / "parallel_variable_ohie_campaign.py"
        spec = importlib.util.spec_from_file_location("ohie_campaign_test", path)
        cls.campaign = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.campaign)

    def test_campaign_replay_and_tampered_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "campaign"
            result = self.campaign.run_campaign(out, [], (7101,))
            self.assertEqual(result["runs"], 6)
            self.assertEqual(self.campaign.verify_campaign(out)["runs"], 6)
            report = json.loads((out / "report.json").read_text())
            report["source"]["all_source_files_committed_at_head"] = not report["source"]["all_source_files_committed_at_head"]
            (out / "report.json").write_bytes(self.campaign.canonical_line(report))
            manifest = json.loads((out / "manifest.json").read_text())
            manifest["files_sha256"]["report.json"] = self.campaign.digest(out / "report.json")
            (out / "manifest.json").write_bytes(self.campaign.canonical_line(manifest))
            with self.assertRaisesRegex(ValueError, "SOURCE_COMMITMENT_CLAIM"):
                self.campaign.verify_campaign(out)

    def test_duplicate_json_keys_and_false_block_record_fail(self):
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            self.campaign.strict_object([("x", 1), ("x", 2)])
        case = Scenario("reader", profile=SMALL, rounds=6)
        summary, trace = run_scenario(case)
        self.campaign.check_trace(trace, case)
        modified = json.loads(json.dumps(trace))
        row = next(row for row in modified if row["kind"] == "query" and row.get("disposition") == "published")
        row["block"]["chain"] ^= 1
        with self.assertRaises(ValueError):
            self.campaign.check_trace(modified, case)
        self.assertFalse(ASSUMPTIONS["security_theorem"])
        self.assertGreater(summary["created_blocks"], 0)


if __name__ == "__main__":
    unittest.main()
