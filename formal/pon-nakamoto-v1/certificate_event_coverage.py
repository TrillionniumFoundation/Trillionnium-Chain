"""EC1: derive every finite-record confirmation failure before risk accounting.

The probability law, complete execution records, and record filtration are
declared mathematical inputs.  This module authenticates neither their
physical origin nor their coverage of a real network.  It does not construct
an actual-work, random-oracle, or native-finality reduction.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction as F
import hashlib
import json
from pathlib import Path

import certificate_observability_models as co
import native_execution_certificate as native


SCHEMA = "pon-certificate-event-coverage-v1"
FILTRATION = "complete_declared_execution_record_prefixes"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_LEAVES = 64
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_EVENTS = 32768
MAX_TOTAL_COMPARISONS = 8192
MAX_STARTS = co.MAX_WINDOWS
SOURCE_FILES = (
    "formal/pon-nakamoto-v1/certificate_event_coverage.py",
    "formal/pon-nakamoto-v1/certificate_event_coverage_tests.py",
    "formal/pon-nakamoto-v1/CERTIFICATE_EVENT_COVERAGE_V1.md",
    "formal/pon-nakamoto-v1/certificate_observability_models.py",
    "formal/pon-nakamoto-v1/native_execution_certificate.py",
)
UNATTESTED = {
    "actual_probability_law_authenticated": False,
    "actual_record_filtration_authenticated": False,
    "actual_public_or_coalition_knowledge_authenticated": False,
    "native_runtime_attested": False,
    "all_world_events_authenticated": False,
    "physical_clock_authenticated": False,
    "initial_joint_state_authenticated": False,
    "native_work_to_ideal_query_relation_proved": False,
    "native_six_successor_risk_certified": False,
    "native_six_successor_failure_probability": None,
    "production_qualified": False,
}


class EventCoverageError(ValueError):
    """A rejected declared-model join, never a native consensus verdict."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise EventCoverageError(code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return co.canonical(value)


@dataclass(frozen=True)
class LeafExecution:
    document: dict
    # One event sequence cut for (), path[:1], ..., the complete leaf path.
    # Every confirmation must occur exactly at one such cut.  The last cut
    # covers all events.  A cut is a record boundary, not a physical timestamp.
    history_cuts: tuple[int, ...]


@dataclass(frozen=True)
class Allocation:
    start_id: str
    start_history: tuple[str, ...]
    failure_leaves: tuple[str, ...]
    allowance: F


def _law_snapshot(law: co.ProbabilityTree) -> co.ProbabilityTree:
    need(type(law) is co.ProbabilityTree and type(law.leaves) is dict
         and 0 < len(law.leaves) <= MAX_LEAVES, "FINITE_JOINT_LAW_REQUIRED")
    rows = tuple(law.leaves.values())
    need(all(type(row) is co.Leaf for row in rows)
         and set(law.leaves) == {row.name for row in rows}, "MUTATED_JOINT_LAW_KEYS")
    # ProbabilityTree is mutable.  Recheck its original leaves and reconstruct
    # the node set instead of trusting cached nodes or caller-added flags.
    return co.ProbabilityTree(rows)


def _document_snapshot(value: dict) -> tuple[dict, str]:
    need(type(value) is dict, "RAW_EXECUTION_DOCUMENT_REQUIRED")
    try:
        raw = native.canonical(value)
    except (TypeError, ValueError) as error:
        raise EventCoverageError("RAW_JSON_EXECUTION_DOCUMENT_REQUIRED") from error
    need(len(raw) <= MAX_DOCUMENT_BYTES, "EXECUTION_DOCUMENT_BYTE_LIMIT")
    return native.strict_json(raw.decode("utf-8")), sha(raw)


def _record_trace(execution: native.Execution) -> tuple[bytes, ...]:
    """Exact frames visible to the DECLARED COMPLETE-RECORD observer.

    This is deliberately not a projection onto one node's network knowledge.
    It includes recorded hidden-ready/resource events and the initial record.
    Unused future block descriptions, evidence names, and requested comparison
    lists are not revealed by a prefix.  A descriptor enters when first used.
    """
    doc = execution.document
    seen = set(doc["initial"]["ready"])

    def descriptors(ids):
        return [execution.blocks[block] for block in sorted(ids) if block != "g"]

    initial = {
        "schema": doc["schema"],
        "source_commit": doc["provenance"]["source_commit"],
        "clock": doc["clock"],
        "scope": {key: doc["scope"][key] for key in ("nodes", "start_time", "end_time")},
        "owners": doc["owners"],
        "initial": doc["initial"],
        "initial_blocks": descriptors(seen),
    }
    trace = [canonical(initial)]
    for event in doc["events"]:
        referenced = set()
        for key in ("block", "parent", "candidate", "selected", "tip", "included"):
            block = event.get(key)
            if type(block) is str and block in execution.blocks:
                referenced.update(execution.paths[block])
        new = referenced - seen
        trace.append(canonical({"event": event, "first_referenced_blocks": descriptors(new)}))
        seen.update(new)
    return tuple(trace)


def _is_prefix(left: tuple, right: tuple) -> bool:
    return right[:len(left)] == left


def _trace_digest(prefix: tuple[bytes, ...]) -> str:
    framed = hashlib.sha256(b"pon-ec1-record-prefix-v1\0")
    for frame in prefix:
        framed.update(len(frame).to_bytes(8, "big"))
        framed.update(frame)
    return framed.hexdigest()


def _derive(law: co.ProbabilityTree, executions: dict[str, LeafExecution]) -> dict:
    need(type(executions) is dict and set(executions) == set(law.leaves),
         "LEAF_EXECUTION_COVERAGE_MISMATCH")
    parsed, cuts_by_leaf, source_hashes = {}, {}, {}
    node_prefixes: dict[tuple[str, ...], tuple[bytes, ...]] = {}
    node_cuts: dict[tuple[str, ...], int] = {}
    total_events = 0
    for leaf_name in sorted(law.leaves):
        leaf, case = law.leaves[leaf_name], executions[leaf_name]
        need(type(case) is LeafExecution, "RAW_LEAF_EXECUTION_REQUIRED")
        document, source_hashes[leaf_name] = _document_snapshot(case.document)
        execution = native.Execution(document)
        need(document["scope"]["declared_all_branches"]
             and document["scope"]["declared_no_missing_events"], "INCOMPLETE_DECLARED_EXECUTION")
        # Validate any supplied comparison references, then ignore that list
        # when deciding which events the final risk statement must cover.
        execution.report()
        count = len(document["events"])
        total_events += count
        need(total_events <= MAX_TOTAL_EVENTS, "FAMILY_EVENT_LIMIT")
        cuts = case.history_cuts
        need(type(cuts) is tuple and len(cuts) == len(leaf.path) + 1
             and all(type(cut) is int and 0 <= cut <= count for cut in cuts),
             "HISTORY_CUT_ENCODING")
        need(all(left < right for left, right in zip(cuts, cuts[1:])), "HISTORY_CUT_ORDER")
        need(cuts[-1] == count, "TERMINAL_HISTORY_OMITS_EVENTS")
        trace = _record_trace(execution)
        for depth, cut in enumerate(cuts):
            history = leaf.path[:depth]
            prefix = trace[:cut + 1]
            if history in node_prefixes:
                need(node_cuts[history] == cut and node_prefixes[history] == prefix,
                     "HISTORY_CELL_RECORD_PREFIX_MISMATCH")
            else:
                node_cuts[history], node_prefixes[history] = cut, prefix
        parsed[leaf_name], cuts_by_leaf[leaf_name] = execution, cuts

    # A probability-history branch must reveal different recorded information.
    # Merely attaching different future-outcome labels to the same prefix, or
    # stopping one child at a prefix of the other, is not an observed split.
    for parent in sorted(law.nodes):
        children = sorted(node for node in law.nodes
                          if len(node) == len(parent) + 1 and node[:-1] == parent)
        for index, left in enumerate(children):
            for right in children[index + 1:]:
                a, b = node_prefixes[left], node_prefixes[right]
                need(not _is_prefix(a, b) and not _is_prefix(b, a), "HISTORY_SPLIT_NOT_OBSERVED")

    starts: dict[str, dict] = {}
    total_pairs = 0
    for leaf_name in sorted(law.leaves):
        leaf, execution = law.leaves[leaf_name], parsed[leaf_name]
        cuts = cuts_by_leaf[leaf_name]
        observations = sorted(execution.observations.items(), key=lambda row: row[1]["seq"])
        later_views = [(observation_id, observation, "recorded_observation")
                       for observation_id, observation in observations]
        for event in execution.document["events"]:
            if event["kind"] != "select":
                continue
            seq, node = event["seq"], event["node"]
            cut = execution.cuts[seq]
            # This is a replay evaluation of an ORIGINAL select event, not a
            # manufactured native observation or an extra stochastic sample.
            # An ephemeral lookup lets the unchanged deterministic compare()
            # validate the same original Cut and its paid-deficit identity.
            replay_id = "__ec1_replayed_select_" + str(seq)
            while replay_id in execution.observations:
                replay_id += "_"
            view = {"seq": seq, "time": cut.time, "node": node,
                    "tip": cut.active[node], "included": None, "confirmed": None}
            execution.observations[replay_id] = view
            later_views.append((replay_id, view, "replayed_selection_cut"))
        later_views.sort(key=lambda row: row[1]["seq"])
        for observation_id, observation in observations:
            if observation["confirmed"] is not True:
                continue
            seq = observation["seq"]
            need(seq in cuts, "CONFIRMATION_HISTORY_BOUNDARY_MISSING")
            history = leaf.path[:cuts.index(seq)]
            owner = execution.owners[observation["node"]]
            identity = {"namespace": owner["namespace"], "node": owner["node"],
                        "owner_instance": owner["owner_instance"],
                        "configuration_digest": owner["configuration_digest"],
                        "observation_id": observation_id, "start_history": history}
            start_id = "ec1-" + sha(canonical(identity))
            if start_id not in starts:
                need(len(starts) < MAX_STARTS, "CONFIRMATION_START_LIMIT")
                starts[start_id] = {
                    "start_id": start_id, **identity, "event_seq": seq,
                    "event_time": observation["time"], "included": observation["included"],
                    "selected_tip": observation["tip"],
                    "record_prefix_sha256": _trace_digest(node_prefixes[history]),
                    "start_leaves": [], "failure_leaves": [], "comparisons": {},
                }
            row = starts[start_id]
            row["start_leaves"].append(leaf_name)
            comparisons = []
            for later_id, later, kind in later_views:
                if later["seq"] <= seq:
                    continue
                total_pairs += 1
                need(total_pairs <= MAX_TOTAL_COMPARISONS, "DERIVED_COMPARISON_LIMIT")
                result = execution.compare({"name": "automatically_derived",
                                            "confirmed_observation": observation_id,
                                            "later_observation": later_id})
                comparisons.append({"later_view": later_id, "later_view_kind": kind,
                                    "later_node": later["node"], "later_seq": later["seq"],
                                    "result": result})
            if any(item["result"]["outcome"] == "prefix_failure_with_paid_deficit_witness"
                   for item in comparisons):
                row["failure_leaves"].append(leaf_name)
            row["comparisons"][leaf_name] = comparisons
    need(bool(starts), "NO_CONFIRMATION_STARTS")

    union = set()
    for row in starts.values():
        history = row["start_history"]
        descendants = {name for name, leaf in law.leaves.items() if _is_prefix(history, leaf.path)}
        need(set(row["start_leaves"]) == descendants, "START_CELL_OCCURRENCE_MISMATCH")
        row["start_leaves"] = tuple(sorted(row["start_leaves"]))
        row["failure_leaves"] = tuple(sorted(row["failure_leaves"]))
        row["start_probability"] = law.mass(history)
        failure_mass = sum((law.leaves[name].probability for name in row["failure_leaves"]), F(0))
        row["conditional_failure_probability"] = failure_mass / row["start_probability"]
        union.update(row["failure_leaves"])
    law_description = tuple({"name": leaf.name, "path": leaf.path, "probability": leaf.probability}
                            for leaf in sorted(law.leaves.values(), key=lambda item: item.name))
    return {
        "schema": SCHEMA, "scope": "bounded_declared_joint_execution_model",
        "event_definition": "included_block_absent_at_any_later_recorded_observation_or_selection_cut",
        "filtration": FILTRATION, "law_sha256": sha(canonical(law_description)),
        "raw_execution_document_sha256": source_hashes,
        "history_cells_checked": len(node_prefixes), "total_recorded_events": total_events,
        "derived_start_count": len(starts), "derived_comparison_count": total_pairs,
        "starts": tuple(starts[key] for key in sorted(starts)),
        "all_confirmation_starts_derived_from_raw_records": True,
        "caller_comparison_lists_determine_coverage": False,
        "selection_cuts_between_observations_checked": True,
        "same_history_cell_record_prefixes_equal": True,
        "history_branches_have_distinct_record_prefixes": True,
        "failure_union_leaves": tuple(sorted(union)),
        "failure_union_probability": sum((law.leaves[name].probability for name in union), F(0)),
        "beyond_recorded_horizon_covered": False,
        **UNATTESTED,
    }


def derive_event_catalogue(law: co.ProbabilityTree, executions: dict[str, LeafExecution]) -> dict:
    """Recheck complete raw records and derive all their confirmation events."""
    return _derive(_law_snapshot(law), executions)


def check_event_coverage(law: co.ProbabilityTree, executions: dict[str, LeafExecution],
                         allocations: tuple[Allocation, ...], total_allowance: F) -> dict:
    """Bind a COMPLETE event declaration to the existing same-law risk bank.

    No preverified catalogue is accepted.  Every start and every failure leaf
    is independently rederived.  Numeric allowances are checked against the
    actual conditional ratios in this entire DECLARED finite joint law.
    """
    law = _law_snapshot(law)
    catalogue = _derive(law, executions)
    need(type(allocations) is tuple and len(allocations) <= MAX_STARTS, "ALLOCATION_LIST")
    provided = {}
    for allocation in allocations:
        need(type(allocation) is Allocation, "ALLOCATION_TYPE")
        need(type(allocation.start_id) is str and allocation.start_id not in provided,
             "DUPLICATE_OR_INVALID_START_ALLOCATION")
        provided[allocation.start_id] = allocation
    expected = {row["start_id"]: row for row in catalogue["starts"]}
    need(set(provided) == set(expected), "CONFIRMATION_START_COVERAGE_MISMATCH")
    attempts = []
    for start_id, row in expected.items():
        allocation = provided[start_id]
        need(type(allocation.start_history) is tuple
             and allocation.start_history == row["start_history"], "START_HISTORY_MISMATCH")
        event = allocation.failure_leaves
        need(type(event) is tuple and all(type(name) is str for name in event)
             and len(set(event)) == len(event) and set(event) == set(row["failure_leaves"]),
             "FAILURE_EVENT_COVERAGE_MISMATCH")
        attempts.append(co.Attempt(start_id, row["start_history"], row["failure_leaves"],
                                   allocation.allowance))
    bank = co.check_predictable_risk_bank(law, tuple(attempts), total_allowance)
    need(bank["failure_union_probability"] == catalogue["failure_union_probability"],
         "DERIVED_UNION_BANK_MISMATCH")
    return {"schema": "pon-complete-event-risk-bank-v1", "event_catalogue": catalogue,
            "same_joint_law_risk_bank": bank,
            "finite_declared_execution_event_coverage_verified": True,
            "all_declared_confirmation_starts_charged": True,
            "independence_between_failures_required": False,
            "numeric_allowances_checked_against_complete_joint_law": True,
            **UNATTESTED}


def allocations_from_catalogue(catalogue: dict) -> tuple[Allocation, ...]:
    """Convenience only; check_event_coverage still recomputes every premise."""
    return tuple(Allocation(row["start_id"], row["start_history"], row["failure_leaves"],
                            row["conditional_failure_probability"]) for row in catalogue["starts"])


def two_confirmation_fixture() -> tuple[co.ProbabilityTree, dict[str, LeafExecution]]:
    """Two sequential independent Bernoulli model outcomes, with real replay.

    Complete synthetic Execution records, not native node runs.  The first
    inclusion is restored before the second; the second rival preserves the
    first inclusion.  Therefore the automatically derived failure events are
    exactly the first and second bits, even when all later views are checked.
    """
    cases, leaves = {}, []
    p = F(1, 16)
    for first in (False, True):
        for second in (False, True):
            path = ("first_hit" if first else "first_miss", "second_hit" if second else "second_miss")
            name = "_".join(path)
            model = native.ModelBuilder("ec1_two_confirmations")
            model.base()
            model.events[-1]["observation_id"] = "first_confirmed"
            cut1 = len(model.events)
            rival1 = model.block("first_rival", "g", 8 if first else 6, "A")
            model.ready(8, rival1)
            model.available(8, rival1)
            model.select(8, rival1)
            model.observe(8, "first_result")
            parent = "a7"
            for index in range(7):
                block = model.block("second_b" + str(index), parent, 1, "A")
                model.ready(9, block)
                parent = block
            model.available(9, parent)
            model.select(9, parent)
            model.observe(9, "second_confirmed", included="second_b0", confirmed=True)
            cut2 = len(model.events)
            rival2 = model.block("second_rival", "a7", 8 if second else 6, "A")
            model.ready(10, rival2)
            model.available(10, rival2)
            model.select(10, rival2)
            model.observe(20, "second_result")
            doc = model.document()
            cases[name] = LeafExecution(doc, (cut1, cut2, len(model.events)))
            probability = (p if first else 1 - p) * (p if second else 1 - p)
            leaves.append(co.Leaf(name, path, probability))
    return co.ProbabilityTree(tuple(leaves)), cases


def inventory_progress_fixture(opposite: bool) -> tuple[co.ProbabilityTree, dict[str, LeafExecution]]:
    """Same inventory/progress marginals, different complete execution laws."""
    need(type(opposite) is bool, "COUPLING_SELECTOR")
    cases, leaves = {}, []
    for stocked in (False, True):
        growth = not stocked if opposite else stocked
        model = native.ModelBuilder("ec1_inventory_progress")
        model.base()
        model.events.pop()  # The confirmation is recorded after inventory exists.
        common_cut = len(model.events)
        if stocked:
            rival = model.block("private_inventory", "g", 8, "A")
            model.ready(7, rival)
        else:
            # An explicit no-work accounting record distinguishes the complete
            # record histories; this is not a measurement of physical cost.
            model.emit(7, "resource", actor="adversary", account="bytes", amount=0)
        model.observe(7, "inventory_confirmed", included="a1", confirmed=True)
        confirmation_cut = len(model.events)
        if growth:
            progress = model.block("honest_progress", "a7", 2)
            model.bind(8, progress, "a7")
            model.ready(9, progress)
            model.available(9, progress)
            model.select(9, progress)
        else:
            model.emit(9, "resource", actor="h0", account="bytes", amount=0)
        if stocked:
            model.available(10, "private_inventory")
            model.select(10, "private_inventory")
        model.observe(20, "end")
        name = "stock_high" if stocked else "stock_low"
        path = (name, "terminal")
        cases[name] = LeafExecution(model.document(), (common_cut, confirmation_cut, len(model.events)))
        leaves.append(co.Leaf(name, path, F(1, 2)))
    return co.ProbabilityTree(tuple(leaves)), cases


def transient_removal_fixture() -> tuple[co.ProbabilityTree, dict[str, LeafExecution]]:
    """A modeled removal restored before the next explicit observation."""
    leaves, cases = [], {}
    for hit in (False, True):
        model = native.ModelBuilder("ec1_transient_removal")
        model.base()
        start = len(model.events)
        rival = model.block("transient", "g", 8 if hit else 6, "A")
        model.ready(8, rival)
        model.available(8, rival)
        model.select(8, rival)
        restored = model.block("restored", "a7", 2, "A")
        model.ready(9, restored)
        model.available(9, restored)
        model.select(9, restored)
        model.observe(10, "end")
        model.compare("end")
        name = "hit" if hit else "miss"
        leaves.append(co.Leaf(name, (name,), F(1, 16) if hit else F(15, 16)))
        cases[name] = LeafExecution(model.document(), (start, len(model.events)))
    return co.ProbabilityTree(tuple(leaves)), cases


def future_label_split(law: co.ProbabilityTree, cases: dict[str, LeafExecution]):
    """Invalid refinement: reveal a future bit before any record difference."""
    leaves, changed = [], {}
    for name, leaf in law.leaves.items():
        case = cases[name]
        cut1, cut2, end = case.history_cuts
        path = ("unobserved_" + leaf.path[0],) + leaf.path
        leaves.append(co.Leaf(name, path, leaf.probability))
        changed[name] = LeafExecution(case.document, (cut1 - 1, cut1, cut2, end))
    return co.ProbabilityTree(tuple(leaves)), changed


def _refusal(call, code: str) -> str:
    try:
        call()
    except (EventCoverageError, co.ObservabilityError) as error:
        need(str(error) == code, "UNEXPECTED_COUNTEREXAMPLE_REFUSAL:" + str(error))
        return str(error)
    raise EventCoverageError("COUNTEREXAMPLE_NOT_REFUSED:" + code)


def inventory_progress_summary(law: co.ProbabilityTree, cases: dict[str, LeafExecution]) -> dict:
    """Recompute the example's marginal values from every replayed execution."""
    inventory, progress, joint = {}, {}, []
    for name, leaf in sorted(law.leaves.items()):
        execution = native.Execution(cases[name].document)
        start, end = execution.observations["inventory_confirmed"], execution.observations["end"]
        included = start["included"]
        parent = execution.blocks[included]["parent"]
        initial_cut, final_cut = execution.cuts[start["seq"]], execution.cuts[end["seq"]]
        stock = max((max(0, execution.score(block) - execution.score(parent))
                     for block in initial_cut.ready if not execution.contains(block, included)), default=0)
        candidates = {block for view in final_cut.views.values() for block in view
                      if execution.contains(block, included)}
        reference = max([execution.score(start["tip"])] + [execution.score(block) for block in candidates])
        growth = reference - execution.score(start["tip"])
        inventory[stock] = inventory.get(stock, F(0)) + leaf.probability
        progress[growth] = progress.get(growth, F(0)) + leaf.probability
        failure = execution.compare({"name": "joint_counterexample",
                                     "confirmed_observation": "inventory_confirmed",
                                     "later_observation": "end"})
        joint.append({"leaf": name, "initial_inventory": stock, "honest_reference_progress": growth,
                      "probability": leaf.probability,
                      "failure": failure["outcome"] == "prefix_failure_with_paid_deficit_witness"})
    return {"inventory_marginal": tuple({"value": key, "probability": inventory[key]} for key in sorted(inventory)),
            "progress_marginal": tuple({"value": key, "probability": progress[key]} for key in sorted(progress)),
            "joint_outcomes": tuple(joint)}


def build_evidence() -> dict:
    law, cases = two_confirmation_fixture()
    catalogue = derive_event_catalogue(law, cases)
    allocations = allocations_from_catalogue(catalogue)
    first = tuple(a for a in allocations if not a.start_history)
    old_partial = co.check_predictable_risk_bank(law, tuple(
        co.Attempt(a.start_id, a.start_history, a.failure_leaves, a.allowance) for a in first), F(1, 16))
    need(old_partial["failure_union_probability"] == F(1, 16)
         and catalogue["failure_union_probability"] == F(31, 256), "OMITTED_START_COUNTEREXAMPLE")
    target = first[0]
    omitted = Allocation(target.start_id, target.start_history, target.failure_leaves[1:], target.allowance)
    incomplete_event = tuple(omitted if a.start_id == target.start_id else a for a in allocations)
    late = Allocation(target.start_id, ("first_hit",), target.failure_leaves, target.allowance)
    late_start = tuple(late if a.start_id == target.start_id else a for a in allocations)
    invalid_law, invalid_cases = future_label_split(law, cases)
    transient_law, transient_cases = transient_removal_fixture()
    transient = derive_event_catalogue(transient_law, transient_cases)
    observation_only = {
        name: native.Execution(case.document).report()["comparisons"]
        for name, case in transient_cases.items()
    }
    need(transient["failure_union_probability"] == F(1, 16)
         and all(row["outcome"] == "no_prefix_failure_in_this_pair"
                 for rows in observation_only.values() for row in rows),
         "TRANSIENT_REMOVAL_COUNTEREXAMPLE")
    coupling = {}
    for name, opposite in (("together", False), ("opposite", True)):
        other_law, other_cases = inventory_progress_fixture(opposite)
        other = derive_event_catalogue(other_law, other_cases)
        coupling[name] = {"catalogue": other,
                         "replayed_marginals": inventory_progress_summary(other_law, other_cases),
                         "raw_execution_family": serialized_family(other_law, other_cases)}
    need(coupling["together"]["catalogue"]["failure_union_probability"] == 0
         and coupling["opposite"]["catalogue"]["failure_union_probability"] == F(1, 2),
         "JOINT_INVENTORY_PROGRESS_COUNTEREXAMPLE")
    for key in ("inventory_marginal", "progress_marginal"):
        need(coupling["together"]["replayed_marginals"][key]
             == coupling["opposite"]["replayed_marginals"][key], "COUNTEREXAMPLE_MARGINAL_MISMATCH")
    return {
        "schema": "pon-event-coverage-evidence-v1", "result": "PASS",
        "raw_execution_family": serialized_family(law, cases),
        "complete_event_risk_bank": check_event_coverage(law, cases, allocations, F(1, 8)),
        "old_bank_correctly_bounds_only_the_submitted_first_event": old_partial,
        "negative_controls": {
            "omitted_second_start": _refusal(lambda: check_event_coverage(law, cases, first, F(1, 16)),
                                               "CONFIRMATION_START_COVERAGE_MISMATCH"),
            "omitted_failure_leaf": _refusal(lambda: check_event_coverage(law, cases, incomplete_event, F(1, 8)),
                                               "FAILURE_EVENT_COVERAGE_MISMATCH"),
            "late_start": _refusal(lambda: check_event_coverage(law, cases, late_start, F(1)),
                                      "START_HISTORY_MISMATCH"),
            "unobserved_future_label_split": _refusal(lambda: derive_event_catalogue(invalid_law, invalid_cases),
                                                       "HISTORY_SPLIT_NOT_OBSERVED"),
        },
        "invalid_future_label_family": serialized_family(invalid_law, invalid_cases),
        "transient_selection_removal": {
            "raw_execution_family": serialized_family(transient_law, transient_cases),
            "original_observation_only_comparisons": observation_only,
            "complete_event_catalogue": transient,
        },
        "same_marginals_different_joint_laws": coupling,
        "native_program_executed_by_this_evidence_driver": False,
        "source_sha256": source_hashes(),
        **UNATTESTED,
    }


def serialized_family(law: co.ProbabilityTree, cases: dict[str, LeafExecution]) -> dict:
    return {"leaves": tuple({"name": leaf.name, "path": leaf.path, "probability": leaf.probability}
                            for leaf in law.leaves.values()),
            "executions": {name: {"document": case.document, "history_cuts": case.history_cuts}
                           for name, case in cases.items()}}


def source_hashes() -> dict:
    return {name: sha((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-evidence", type=Path, required=True,
                        help="New output directory; existing output is never overwritten.")
    args = parser.parse_args()
    try:
        args.write_evidence.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print(json.dumps({"result": "FAIL", "error": "NEW_EVIDENCE_DIRECTORY_REQUIRED",
                          "detail": str(error)}))
        return 2
    before = {}
    try:
        before = source_hashes()
        evidence = build_evidence()
        need(source_hashes() == before == evidence["source_sha256"], "SOURCE_CHANGED_DURING_EVIDENCE")
        data = canonical(evidence) + b"\n"
        (args.write_evidence / "event-coverage.json").write_bytes(data)
        receipt = {"result": "PASS", "schema": "pon-event-coverage-attempt-v1",
                   "event_coverage_sha256": sha(data), "source_sha256": before,
                   "native_program_executed": False, **UNATTESTED}
        (args.write_evidence / "attempt.json").write_bytes(canonical(receipt) + b"\n")
        print(json.dumps({"result": "PASS", "evidence_sha256": sha(data),
                          "complete_event_failure_probability": "31/256",
                          "native_six_successor_risk_certified": False}))
        return 0
    except Exception as error:  # Retain a failed attempt; no success fallback.
        receipt = {"result": "FAIL", "schema": "pon-event-coverage-attempt-v1",
                   "error_type": type(error).__name__, "error": str(error),
                   "source_sha256_before": before, **UNATTESTED}
        (args.write_evidence / "attempt.json").write_bytes(canonical(receipt) + b"\n")
        print(json.dumps({"result": "FAIL", "error_type": type(error).__name__, "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
