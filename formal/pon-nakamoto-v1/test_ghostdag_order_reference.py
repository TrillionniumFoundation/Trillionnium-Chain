"""Independent set-based Algorithm 1 oracle and finite adversarial controls.

The oracle deliberately does not use the kernel's closure, traversal, bitsets,
cached counters, validation or selection helpers. Graph generators enumerate
single-genesis DAGs with edges to earlier vertices; ID and input permutations
separately exercise deterministic choices. These finite comparisons are not a
common-prefix, convergence, mining-security or native-integration proof.
"""
from __future__ import annotations

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import hashlib
import itertools
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from ghostdag_order_reference import (
    ASSUMPTIONS, PROFILE, Block, GraphError, Limits, ModelLimit,
    block_from_dict, canonical, order_dag,
)


def bid(index: int) -> str:
    return f"{index:064x}"


def graph_from_parents(parents: tuple[tuple[int, ...], ...],
                       labels: tuple[int, ...] | None = None) -> tuple[Block, ...]:
    labels = tuple(range(len(parents))) if labels is None else labels
    return tuple(Block(bid(labels[i]), tuple(bid(labels[p]) for p in predecessor))
                 for i, predecessor in enumerate(parents))


def ordered_dags(n: int):
    """All parent subsets into earlier vertices, with exactly one root (0)."""
    if type(n) is not int or not 1 <= n <= 6:
        raise ValueError("ENUMERATION_BOUND")
    for choices in itertools.product(*(range(1, 1 << i) for i in range(1, n))):
        parents = ((),) + tuple(tuple(j for j in range(i) if mask & (1 << j))
                                for i, mask in enumerate(choices, 1))
        yield graph_from_parents(parents)


def oracle_order(blocks: tuple[Block, ...], k: int, *, candidate_only: bool = False) -> dict:
    """Literal recursive set formulation, for small complete valid fixtures only.

    candidate_only intentionally enables the known incorrect admission rule so
    tests can exhibit a concrete counterexample rather than merely test a guard.
    """
    if not 1 <= len(blocks) <= 16:
        raise ValueError("ORACLE_GRAPH_BOUND")
    parents = {b.block_id: set(b.parents) for b in blocks}
    vertices = frozenset(parents)
    roots = [b for b in vertices if not parents[b]]
    if len(roots) != 1 or any(p not in vertices for ps in parents.values() for p in ps):
        raise ValueError("ORACLE_FIXTURE")
    genesis = roots[0]
    ancestors: dict[str, set[str]] = {}
    # Independent transitive closure by bounded repeated set union.
    for b in vertices:
        reached = set(parents[b])
        for _ in range(len(vertices)):
            expanded = reached | {p for a in reached for p in parents[a]}
            if expanded == reached:
                break
            reached = expanded
        if b in reached:
            raise ValueError("ORACLE_CYCLE")
        ancestors[b] = reached

    def unrelated(a: str, b: str) -> bool:
        return a != b and a not in ancestors[b] and b not in ancestors[a]

    def cluster(proposal: set[str]) -> bool:
        return all(sum(unrelated(a, b) for b in proposal) <= k for a in proposal)

    @lru_cache(maxsize=None)
    def solve(nodes: frozenset[str]) -> tuple[frozenset[str], tuple[str, ...], str]:
        if nodes == {genesis}:
            return frozenset({genesis}), (genesis,), genesis
        tips = nodes - {p for b in nodes for p in parents[b]}
        alternatives = {b: solve(frozenset(ancestors[b])) for b in tips}
        selected = min(tips, key=lambda b: (-len(alternatives[b][0]), b))
        blue = set(alternatives[selected][0]) | {selected}
        ordered = list(alternatives[selected][1]) + [selected]
        remaining = set(nodes) - ancestors[selected] - {selected}
        while remaining:
            # Different formulation from the kernel's indegree/child heap.
            ready = {b for b in remaining if parents[b] <= set(ordered)}
            if not ready:
                raise AssertionError("ORACLE_TOPOLOGY")
            b = min(ready)
            remaining.remove(b)
            acceptable = (sum(unrelated(b, a) for a in blue) <= k
                          if candidate_only else cluster(blue | {b}))
            if acceptable:
                blue.add(b)
            ordered.append(b)
        return frozenset(blue), tuple(ordered), selected

    blue, ordered, selected = solve(vertices)
    scores = []
    for b in sorted(vertices):
        if b == genesis:
            scores.append({"block_id": b, "blue_score": 0, "selected_parent": None})
        else:
            past_blue, _, parent = solve(frozenset(ancestors[b]))
            scores.append({"block_id": b, "blue_score": len(past_blue), "selected_parent": parent})
    return {"genesis": genesis, "selected_tip": selected, "blue": sorted(blue),
            "red": sorted(vertices - blue), "order": list(ordered), "scores": scores,
            "blue_anticone_sizes": [[b, sum(unrelated(b, a) for a in blue)] for b in sorted(blue)]}


def checked_case(blocks: tuple[Block, ...], k: int) -> tuple[dict, int]:
    result = order_dag(blocks, k)
    actual = json.loads(canonical(result.decision()))
    expected = oracle_order(blocks, k)
    for key, value in expected.items():
        if actual[key] != value:
            raise AssertionError({"kind": "ORACLE_DIFFERENCE", "k": k, "field": key,
                                  "blocks": [b.__dict__ for b in blocks],
                                  "expected": value, "actual": actual[key]})
    if sorted(result.order) != sorted(b.block_id for b in blocks):
        raise AssertionError("ORDER_NOT_PERMUTATION")
    positions = {b: i for i, b in enumerate(result.order)}
    if any(positions[p] >= positions[b.block_id] for b in blocks for p in b.parents):
        raise AssertionError("ORDER_NOT_TOPOLOGICAL")
    if any(count > k for _, count in result.blue_anticone_sizes):
        raise AssertionError("BLUE_NOT_K_CLUSTER")
    return actual, result.statistics.operations


def exhaustive_observation(max_blocks: int = 5) -> dict:
    """Deterministic finite comparison transcript; no timing/TPS extrapolation."""
    if type(max_blocks) is not int or not 1 <= max_blocks <= 6:
        raise ValueError("ENUMERATION_BOUND")
    transcript = hashlib.sha256(b"trnm-ghostdag-exhaustive-v1\0")
    groups = []
    max_operations = 0
    for n in range(1, max_blocks + 1):
        graphs = cases = 0
        for blocks in ordered_dags(n):
            graphs += 1
            for k in range(n + 1):
                decision, operations = checked_case(blocks, k)
                transcript.update(canonical({"n": n, "case": graphs, "decision": decision}) + b"\n")
                max_operations = max(max_operations, operations)
                cases += 1
        groups.append({"blocks": n, "graphs": graphs, "k_values": list(range(n + 1)),
                       "cases": cases})
    return {"schema": "trnm-ghostdag-exhaustive-observation-v1",
            "enumeration": "all nonempty parent subsets into earlier IDs; sole root 0; k from 0 through n",
            "max_blocks": max_blocks, "groups": groups,
            "graphs": sum(g["graphs"] for g in groups),
            "cases": sum(g["cases"] for g in groups),
            "oracle_differences": 0, "transcript_sha256": transcript.hexdigest(),
            "max_logical_operations": max_operations,
            "claim_scope": "finite ordering equivalence only; no protocol, security or performance qualification"}


# k=2: choose d (2), then visit a (3), then c (4). c's own blue anticone
# has size 2, but admitting c would raise a's blue anticone from 2 to 3.
SATURATED_BLUE = ((), (0,), (1,), (0,), (1,))


class PaperOrderingTests(unittest.TestCase):
    def test_exhaustive_ordered_dags_and_all_small_k(self):
        observation = exhaustive_observation(5)
        self.assertEqual(observation["graphs"], 341)
        self.assertEqual(observation["cases"], 2012)
        self.assertEqual(observation["oracle_differences"], 0)

    def test_all_small_id_rankings_independent_of_topological_labels(self):
        cases = 0
        for n in range(1, 5):
            for original in ordered_dags(n):
                parents = tuple(tuple(int(p, 16) for p in b.parents) for b in original)
                for labels in itertools.permutations(range(n)):
                    blocks = graph_from_parents(parents, labels)
                    for k in range(n + 1):
                        checked_case(blocks, k)
                        cases += 1
        self.assertEqual(cases, 2600)

    def test_existing_blue_guard_has_a_five_vertex_counterexample(self):
        blocks = graph_from_parents(SATURATED_BLUE)
        correct, _ = checked_case(blocks, 2)
        wrong = oracle_order(blocks, 2, candidate_only=True)
        self.assertEqual(correct["selected_tip"], bid(2))
        self.assertEqual(correct["order"], [bid(i) for i in (0, 1, 2, 3, 4)])
        self.assertEqual(correct["blue"], [bid(i) for i in (0, 1, 2, 3)])
        self.assertEqual(correct["red"], [bid(4)])
        self.assertIn(bid(4), wrong["blue"])
        self.assertIn([bid(3), 3], wrong["blue_anticone_sizes"])

    def test_all_id_permutations_of_saturated_blue_counterexample(self):
        for labels in itertools.permutations(range(5)):
            checked_case(graph_from_parents(SATURATED_BLUE, labels), 2)

    def test_score_is_blue_past_not_ancestor_count_or_direct_parent_count(self):
        # Wide x (5) has five ancestors but only two blue past vertices at k=0.
        # Thin y3 (8) has three blue ancestors, and wins before and after join (9).
        parents = ((), (0,), (0,), (0,), (0,), (1, 2, 3, 4), (0,), (6,), (7,))
        decision, _ = checked_case(graph_from_parents(parents), 0)
        self.assertEqual(decision["selected_tip"], bid(8))
        scores = {s["block_id"]: s for s in decision["scores"]}
        self.assertEqual(scores[bid(5)]["blue_score"], 2)
        self.assertEqual(scores[bid(8)]["blue_score"], 3)
        joined, _ = checked_case(graph_from_parents(parents + ((5, 8),)), 0)
        self.assertEqual(joined["scores"][-1]["selected_parent"], bid(8))

    def test_equal_score_tie_is_lowest_hash_not_arrival_position(self):
        blocks = graph_from_parents(((), (0,), (0,)), (100, 9, 2))
        expected, _ = checked_case(blocks, 0)
        self.assertEqual(expected["selected_tip"], bid(2))
        for arrival in itertools.permutations(blocks):
            self.assertEqual(json.loads(canonical(order_dag(arrival, 0).decision())), expected)

    def test_all_arrival_and_parent_permutations_of_complete_snapshot(self):
        original = graph_from_parents(((), (0,), (0,), (0,), (1, 2, 3)))
        expected = order_dag(original, 1).decision_sha256
        cases = 0
        for parents in itertools.permutations(original[4].parents):
            blocks = original[:4] + (replace(original[4], parents=parents),)
            for arrival in itertools.permutations(blocks):
                result = order_dag(arrival, 1)
                self.assertEqual(result.decision_sha256, expected)
                cases += 1
        self.assertEqual(cases, 720)

    def test_redundant_ancestor_edges_do_not_inflate_score(self):
        minimal = graph_from_parents(((), (0,), (1,), (2,)))
        redundant = graph_from_parents(((), (0,), (0, 1), (0, 1, 2)))
        a, _ = checked_case(minimal, 0)
        b, _ = checked_case(redundant, 0)
        for key in ("order", "blue", "red", "scores", "selected_tip"):
            self.assertEqual(a[key], b[key])
        self.assertNotEqual(a["graph_sha256"], b["graph_sha256"])

    def test_k_zero_chooses_a_longest_chain_and_retains_reds(self):
        blocks = graph_from_parents(((), (0,), (0,), (1,), (2,), (3,)))
        decision, _ = checked_case(blocks, 0)
        self.assertEqual(decision["blue"], [bid(i) for i in (0, 1, 3, 5)])
        self.assertEqual(decision["order"], [bid(i) for i in (0, 1, 3, 5, 2, 4)])
        self.assertEqual(decision["red"], [bid(2), bid(4)])

    def test_large_k_colors_entire_finite_graph(self):
        blocks = graph_from_parents(SATURATED_BLUE)
        decision, _ = checked_case(blocks, len(blocks))
        self.assertEqual(decision["red"], [])

    def test_genesis_is_counted_in_past_score_but_has_no_past_itself(self):
        decision, _ = checked_case(graph_from_parents(((), (0,))), 0)
        self.assertEqual(decision["scores"], [
            {"block_id": bid(0), "blue_score": 0, "selected_parent": None},
            {"block_id": bid(1), "blue_score": 1, "selected_parent": bid(0)},
        ])

    def test_deep_graph_uses_no_python_recursion_and_wide_graph_retains_reds(self):
        n = 1100
        deep = graph_from_parents(((),) + tuple((i - 1,) for i in range(1, n)))
        limits = Limits(max_blocks=n, max_parents=1, max_edges=n - 1,
                        max_cached_entries=2_000_000, max_operations=10_000_000)
        result = order_dag(deep, 0, limits=limits)
        self.assertEqual(result.statistics.depth, n - 1)
        self.assertEqual(result.order, tuple(b.block_id for b in deep))
        self.assertEqual(result.red, ())
        wide = graph_from_parents(((),) + ((0,),) * 129)
        result = order_dag(wide, 2)
        self.assertEqual(len(result.order), 130)
        self.assertEqual(len(result.blue), 4)
        self.assertEqual(len(result.red), 126)

    def test_finite_extension_may_reorder_and_is_not_finality(self):
        old = graph_from_parents(((), (0,), (0,)))
        extended = old + (Block(bid(3), (bid(2),)),)
        before, _ = checked_case(old, 0)
        after, _ = checked_case(extended, 0)
        self.assertEqual(before["order"], [bid(0), bid(1), bid(2)])
        self.assertEqual(after["order"], [bid(0), bid(2), bid(3), bid(1)])
        self.assertFalse(ASSUMPTIONS["confirmation_protocol_implemented"])
        self.assertFalse(ASSUMPTIONS["production_activation"])


class InputAndBudgetTests(unittest.TestCase):
    def setUp(self):
        self.blocks = graph_from_parents(SATURATED_BLUE)

    def test_empty_graph_missing_parent_multiple_genesis_cycles_and_duplicates(self):
        cases = [([], "EMPTY_GRAPH"),
                 ((Block(bid(1), (bid(0),)),), "MISSING_PARENT"),
                 ((Block(bid(0), ()), Block(bid(1), ())), "SINGLE_GENESIS_REQUIRED"),
                 ((Block(bid(0), ()), Block(bid(1), (bid(0), bid(2))),
                   Block(bid(2), (bid(1),))), "CYCLE"),
                 ((Block(bid(0), (bid(0),)),), "SELF_PARENT"),
                 ((Block(bid(0), ()), Block(bid(1), (bid(0), bid(0)))), "DUPLICATE_PARENT"),
                 (self.blocks + (self.blocks[1],), "DUPLICATE_BLOCK")]
        for blocks, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(GraphError, error):
                order_dag(blocks, 2)

    def test_missing_deep_or_wide_dependencies_never_returns_partial_order(self):
        for parents, removed in [(((), (0,), (1,), (2,), (3,)), 2),
                                 (((), (0,), (0,), (0,), (1, 2, 3)), 2)]:
            blocks = graph_from_parents(parents)
            with self.assertRaisesRegex(GraphError, "MISSING_PARENT"):
                order_dag(blocks[:removed] + blocks[removed + 1:], 2)
            checked_case(blocks, 2)

    def test_hash_ids_and_exact_container_types_are_required(self):
        for value in ("a", "A" * 64, "g" * 64, 0, None):
            with self.subTest(value=value), self.assertRaisesRegex(GraphError, "BLOCK_ID"):
                order_dag((Block(value, ()),), 0)
        with self.assertRaisesRegex(GraphError, "PARENT_VECTOR"):
            order_dag((Block(bid(0), []),), 0)
        with self.assertRaisesRegex(GraphError, "BLOCK_VECTOR"):
            order_dag(iter(self.blocks), 0)
        with self.assertRaisesRegex(GraphError, "BLOCK_TYPE"):
            order_dag([{"block_id": bid(0), "parents": []}], 0)

    def test_unknown_or_variable_work_and_profiles_are_unsupported(self):
        for value in (0, 2, None, True, 1.0, "1"):
            with self.subTest(value=value), self.assertRaisesRegex(GraphError, "UNSUPPORTED_WORK"):
                order_dag((replace(self.blocks[0], work=value),), 0)
        for profile in ("kaspa", "native-pon", "variable-work", None):
            with self.subTest(profile=profile), self.assertRaisesRegex(GraphError, "UNSUPPORTED_PROFILE"):
                order_dag(self.blocks, 2, profile=profile)
        self.assertEqual(order_dag(self.blocks, 2, profile=PROFILE).profile, PROFILE)

    def test_strict_encoding_rejects_difficulty_extra_fields_and_missing_work(self):
        record = {"block_id": bid(0), "parents": [], "work": 1}
        self.assertEqual(block_from_dict(record), self.blocks[0])
        for bad in ({**record, "difficulty": 1}, {**record, "target": "f" * 64},
                    {"block_id": bid(0), "parents": []}, {**record, "parents": ()}):
            with self.subTest(bad=bad), self.assertRaises(GraphError):
                block_from_dict(bad)

    def test_parameter_bools_and_unbounded_limits_rejected(self):
        for k in (True, -1, 2049, 1.0):
            with self.subTest(k=k), self.assertRaisesRegex(GraphError, "K"):
                order_dag(self.blocks, k)
        for limits in (Limits(max_blocks=True), Limits(max_operations=100_000_001),
                       Limits(max_blocks=2049), Limits(max_cached_entries=-1)):
            with self.subTest(limits=limits), self.assertRaises(GraphError):
                order_dag(self.blocks, 2, limits=limits)

    def test_each_finite_budget_rejects_without_mutating_inputs(self):
        snapshot = tuple(self.blocks)
        limits_cases = [(Limits(max_blocks=4), "BLOCK_BUDGET"),
                        (Limits(max_edges=3), "EDGE_BUDGET"),
                        (Limits(max_cached_entries=1), "CACHED_ENTRY_BUDGET"),
                        (Limits(max_operations=1), "OPERATION_BUDGET")]
        for limits, reason in limits_cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ModelLimit, reason):
                order_dag(self.blocks, 2, limits=limits)
            self.assertEqual(self.blocks, snapshot)
        parents = graph_from_parents(((), (0,), (0,), (1, 2)))
        with self.assertRaisesRegex(ModelLimit, "PARENT_BUDGET"):
            order_dag(parents, 1, limits=Limits(max_parents=1))
        checked_case(self.blocks, 2)

    def test_operation_and_cached_entry_boundaries_are_exact(self):
        result = order_dag(self.blocks, 2)
        operations, entries = result.statistics.operations, result.statistics.cached_entries
        exact = Limits(max_operations=operations, max_cached_entries=entries)
        self.assertEqual(order_dag(self.blocks, 2, limits=exact).decision_sha256,
                         result.decision_sha256)
        with self.assertRaisesRegex(ModelLimit, "OPERATION_BUDGET"):
            order_dag(self.blocks, 2, limits=replace(exact, max_operations=operations - 1))
        with self.assertRaisesRegex(ModelLimit, "CACHED_ENTRY_BUDGET"):
            order_dag(self.blocks, 2, limits=replace(exact, max_cached_entries=entries - 1))


class CampaignReplayTests(unittest.TestCase):
    def setUp(self):
        from experiments.ghostdag_order_campaign import make_report, read_report, replay_report
        self.make_report = make_report
        self.read_report = read_report
        self.replay_report = replay_report

    def test_source_bound_receipt_round_trip_and_exact_replay(self):
        report = self.make_report(3)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(canonical(report) + b"\n")
            loaded = self.read_report(path)
            result = self.replay_report(loaded)
        self.assertEqual(result["cases"], 17)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(len(report["source"]["source_sha256"]), 3)
        self.assertEqual(report["source"]["all_source_files_committed_at_head"],
                         not report["source"]["uncommitted_source_files"])
        self.assertFalse(result["production_activation"])

    def test_forged_scope_source_results_and_counterexample_are_rejected(self):
        baseline = json.loads(canonical(self.make_report(2)))
        mutations = [
            (lambda r: r["scope"].update(production_activation=True), "REPORT_SCOPE"),
            (lambda r: r["observation"].update(cases=999), "REPORT_REPLAY_DIFFERENCE"),
            (lambda r: r["source"].update(all_source_files_committed_at_head=
                                         not r["source"]["all_source_files_committed_at_head"]), "REPORT_SOURCE"),
            (lambda r: r["candidate_only_counterexample"]["correct"].update(red=[]), "REPORT_REPLAY_DIFFERENCE"),
        ]
        for mutate, error in mutations:
            report = json.loads(canonical(baseline))
            mutate(report)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                self.replay_report(report)
        report = json.loads(canonical(baseline))
        source_name = next(iter(report["source"]["source_sha256"]))
        report["source"]["source_sha256"][source_name] = "0" * 64
        with self.assertRaisesRegex(ValueError, "REPORT_SOURCE"):
            self.replay_report(report)

    def test_receipt_parser_rejects_duplicate_keys_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"schema":"one","schema":"two"}')
            with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
                self.read_report(path)
            path.write_bytes(b" " * 1_048_577)
            with self.assertRaisesRegex(ValueError, "REPORT_FILE_BOUND"):
                self.read_report(path)

    def test_campaign_bound_cannot_be_a_boolean_or_unbounded(self):
        for maximum in (True, 0, 7):
            with self.subTest(maximum=maximum), self.assertRaisesRegex(ValueError, "ENUMERATION_BOUND"):
                self.make_report(maximum)


class CampaignPublicationTests(unittest.TestCase):
    def setUp(self):
        from experiments import ghostdag_order_campaign
        self.runner = ghostdag_order_campaign

    def test_existing_and_repeated_targets_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(b"prior evidence")
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                self.runner.publish_new_report(path, b"new evidence")
            self.assertEqual(path.read_bytes(), b"prior evidence")
            fresh = Path(directory) / "new.json"
            self.runner.publish_new_report(fresh, b"first")
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                self.runner.publish_new_report(fresh, b"second")
            self.assertEqual(fresh.read_bytes(), b"first")
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()),
                             ["new.json", "receipt.json"])

    def test_target_created_during_publish_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            actual_link = self.runner.os.link

            def concurrent_create(source, target):
                Path(target).write_bytes(b"competing receipt")
                return actual_link(source, target)

            with mock.patch.object(self.runner.os, "link", side_effect=concurrent_create):
                with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                    self.runner.publish_new_report(path, b"must not overwrite")
            self.assertEqual(path.read_bytes(), b"competing receipt")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_two_concurrent_publishers_have_exactly_one_winner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            barrier = threading.Barrier(2)
            actual_link = self.runner.os.link

            def synchronized_link(source, target):
                barrier.wait(timeout=5)
                return actual_link(source, target)

            with mock.patch.object(self.runner.os, "link", side_effect=synchronized_link):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(self.runner.publish_new_report, path, data)
                               for data in (b"first writer", b"second writer")]
                    errors = [future.exception(timeout=10) for future in futures]
            self.assertEqual(sum(error is None for error in errors), 1)
            self.assertEqual([str(error) for error in errors if error is not None], ["OUTPUT_ALREADY_EXISTS"])
            self.assertIn(path.read_bytes(), (b"first writer", b"second writer"))
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_dangling_symlink_and_prepublication_fsync_failure_do_not_get_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            absent = Path(directory) / "absent.json"
            path.symlink_to(absent)
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                self.runner.publish_new_report(path, b"must not follow or replace")
            self.assertTrue(path.is_symlink())
            self.assertFalse(absent.exists())
            fresh = Path(directory) / "fresh.json"
            with mock.patch.object(self.runner.os, "fsync", side_effect=OSError("injected fsync failure")):
                with self.assertRaisesRegex(OSError, "injected fsync failure"):
                    self.runner.publish_new_report(fresh, b"incomplete publication")
            self.assertFalse(fresh.exists())
            self.assertEqual(list(Path(directory).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
