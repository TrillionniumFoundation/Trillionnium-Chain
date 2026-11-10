#!/usr/bin/env python3
"""Finite declared cohort accounting for the conditional PoN fork argument.

This is an offline research checker, not a node, a membership protocol, a miner,
or a probability certificate. Scores, resource units, completeness and clocks
are supplied model premises. No packet is produced, transmitted or admitted.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
from pq_source_reader import SourceReadError, read_regular


SCHEMA = "pon-dynamic-participation-v1"
MAX_EVENTS = 10000
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_VALUE = (1 << 512) - 1
MAX_TIME = (1 << 64) - 1


class ParticipationError(ValueError):
    """Malformed finite evidence, not a native consensus rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ParticipationError(code)


def fields(value: Any, expected: set[str], code: str) -> dict:
    require(type(value) is dict and set(value) == expected, code)
    return value


def integer(value: Any, code: str, *, maximum: int = MAX_VALUE,
            minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= maximum, code)
    return value


def optional_integer(value: Any, code: str, *, maximum: int = MAX_VALUE,
                     minimum: int = 0) -> int | None:
    return None if value is None else integer(value, code, maximum=maximum, minimum=minimum)


def label(value: Any, code: str) -> str:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is not None,
            code)
    return value


def total(left: int, right: int) -> int:
    return integer(left + right, "ACCOUNTING_RANGE")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def strict_json(body: str) -> Any:
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ParticipationError("NONFINITE_JSON")

    def bounded_integer(value):
        require(len(value.lstrip("-")) <= 155, "JSON_INTEGER_RANGE")
        return int(value)

    return json.loads(body, object_pairs_hook=pairs, parse_constant=nonfinite,
                      parse_int=bounded_integer)


@dataclass
class Member:
    generation: int
    phase: str
    view_score: int | None


@dataclass
class Task:
    node: str
    generation: int
    bound_at: int
    parent_score: int | None
    qualified_at_binding: bool
    carry_in: bool = False
    cancelled: bool = False
    ready: bool = False
    failed: bool = False
    known_resource: int = 0
    resource_known: bool = True


class _Audit:
    def __init__(self, document: dict):
        fields(document, {"schema", "source_commit", "clock_domain", "window",
                          "bounds", "initial", "events"}, "DOCUMENT_FIELDS")
        require(document["schema"] == SCHEMA, "SCHEMA")
        require(type(document["source_commit"]) is str and
                re.fullmatch(r"[0-9a-f]{40}", document["source_commit"]) is not None,
                "SOURCE_COMMIT")
        require(document["clock_domain"] in ("declared_model_ticks", "unknown"), "CLOCK_DOMAIN")
        self.document = document
        window = fields(document["window"], {"start", "end", "complete_events_as_declared"},
                        "WINDOW_FIELDS")
        self.start = integer(window["start"], "START_TIME", maximum=MAX_TIME)
        self.end = integer(window["end"], "END_TIME", maximum=MAX_TIME, minimum=self.start)
        require(type(window["complete_events_as_declared"]) is bool, "COMPLETENESS_TYPE")
        bounds = fields(document["bounds"], {"delta_pub", "gamma", "maximum_weight"}, "BOUNDS_FIELDS")
        self.delta = optional_integer(bounds["delta_pub"], "DELIVERY_BOUND", maximum=MAX_TIME)
        self.gamma = optional_integer(bounds["gamma"], "COMPLETION_BOUND", maximum=MAX_TIME)
        self.maximum_weight = optional_integer(bounds["maximum_weight"], "WEIGHT_BOUND", minimum=1)
        self.length = (None if self.delta is None or self.gamma is None else
                       integer(self.delta + self.gamma, "WINDOW_LENGTH", maximum=MAX_TIME))
        if self.length is not None:
            integer(self.start + self.length, "START_WINDOW_RANGE", maximum=MAX_TIME)
        initial = fields(document["initial"], {"reference_score", "active", "carry_in_tasks",
                                               "resource_units"}, "INITIAL_FIELDS")
        self.reference_score = integer(initial["reference_score"], "REFERENCE_SCORE", minimum=1)
        self.floor = self.reference_score
        self.members: dict[str, Member] = {}
        self.tasks: dict[str, Task] = {}
        self.violations: list[dict] = []
        self.unknowns: set[str] = set()
        self.known_resource = 0
        self.resource_known = True
        self.ready_weight = 0
        self.startup_debt = 0
        self.entry_debt = 0
        self.eligible_unpaced_weight = 0
        self.unclassified_weight = 0
        self.paced_weight = 0
        self.pacers: list[dict] = []
        self.debts: list[dict] = []
        self.floor_updates: list[dict] = []
        self.next_maturity = 0
        self.last_pacer_time: int | None = None
        self.departures = 0
        self.admissions = 0
        self.empty_cohort_intervals: list[dict] = []
        self.empty_since: int | None = None
        self._charge(initial["resource_units"], None)
        require(type(initial["active"]) is list and len(initial["active"]) <= MAX_EVENTS,
                "INITIAL_MEMBERS")
        for row in initial["active"]:
            fields(row, {"node", "generation", "view_score"}, "INITIAL_MEMBER_FIELDS")
            node = label(row["node"], "NODE")
            require(node not in self.members, "DUPLICATE_MEMBER")
            generation = integer(row["generation"], "GENERATION", minimum=1)
            score = optional_integer(row["view_score"], "VIEW_SCORE")
            self.members[node] = Member(generation, "qualified", score)
            self._check_floor(node, self.start, 0, "INITIAL_VIEW_BELOW_FLOOR")
        require(type(initial["carry_in_tasks"]) is list and
                len(initial["carry_in_tasks"]) <= MAX_EVENTS, "CARRY_IN_TASKS")
        for row in initial["carry_in_tasks"]:
            fields(row, {"task", "node", "generation", "bound_at", "parent_score",
                         "resource_units"}, "CARRY_IN_FIELDS")
            task_id = label(row["task"], "TASK")
            require(task_id not in self.tasks, "DUPLICATE_TASK")
            bound_at = integer(row["bound_at"], "BOUND_AT", maximum=self.start)
            task = Task(label(row["node"], "NODE"), integer(row["generation"], "GENERATION", minimum=1),
                        bound_at, optional_integer(row["parent_score"], "PARENT_SCORE"),
                        False, carry_in=True)
            if task.parent_score is None:
                self.unknowns.add("UNKNOWN_PARENT_SCORE")
            self.tasks[task_id] = task
            self._charge(row["resource_units"], task)
        if not self.active():
            self.empty_since = self.start
        if document["clock_domain"] == "unknown":
            self.unknowns.add("UNKNOWN_ANALYSIS_CLOCK")
        if self.delta is None or self.gamma is None or self.maximum_weight is None:
            self.unknowns.add("UNKNOWN_TIMING_OR_WEIGHT_BOUND")
        if not window["complete_events_as_declared"]:
            self.unknowns.add("INCOMPLETE_DECLARED_EVENT_WINDOW")

    def active(self) -> list[str]:
        return sorted(node for node, member in self.members.items() if member.phase == "qualified")

    def _violation(self, code: str, time: int, seq: int, **values) -> None:
        self.violations.append({"code": code, "time": time, "seq": seq, **values})

    def _charge(self, amount: Any, task: Task | None) -> None:
        value = optional_integer(amount, "RESOURCE_UNITS")
        if value is None:
            self.resource_known = False
            self.unknowns.add("UNKNOWN_RESOURCE_CHARGE")
            if task is not None:
                task.resource_known = False
        else:
            self.known_resource = total(self.known_resource, value)
            if task is not None:
                task.known_resource = total(task.known_resource, value)

    def _member(self, event: dict, *, allow_left: bool = False) -> Member:
        node = label(event["node"], "NODE")
        generation = integer(event["generation"], "GENERATION", minimum=1)
        require(node in self.members, "UNKNOWN_MEMBER")
        member = self.members[node]
        require(member.generation == generation, "STALE_MEMBER_GENERATION")
        require(allow_left or member.phase != "left", "MEMBER_HAS_LEFT")
        return member

    def _task(self, event: dict) -> tuple[str, Task]:
        task_id = label(event["task"], "TASK")
        require(task_id in self.tasks, "UNKNOWN_TASK")
        return task_id, self.tasks[task_id]

    def _check_floor(self, node: str, time: int, seq: int, code: str) -> bool:
        score = self.members[node].view_score
        if score is None:
            self.unknowns.add("UNKNOWN_FULL_VIEW_SCORE")
            self._violation("UNKNOWN_FULL_VIEW_SCORE", time, seq, node=node, required=self.floor)
            return False
        if score < self.floor:
            self._violation(code, time, seq, node=node, observed=score, required=self.floor)
            return False
        return True

    def _cohort_interval(self, time: int) -> None:
        if self.active():
            if self.empty_since is not None:
                if time > self.empty_since:
                    self.empty_cohort_intervals.append({"start": self.empty_since, "end": time})
                self.empty_since = None
        elif self.empty_since is None:
            self.empty_since = time

    def mature(self, time: int, seq: int, *, inclusive: bool) -> None:
        """Resolve deadlines after all declared events at the deadline timestamp.

        Before that causal cut the older floor remains in force. A right-censored
        deadline is not a successful delivery, even when the producer has left.
        """
        while self.next_maturity < len(self.pacers):
            pacer = self.pacers[self.next_maturity]
            deadline = pacer["deadline"]
            if deadline > time or (deadline == time and not inclusive):
                break
            self.floor = pacer["required_score"]
            for node in self.active():
                self._check_floor(node, deadline, seq, "INHERITED_DELIVERY_OR_RETENTION_DEFICIT")
            self.floor_updates.append({"task": pacer["task"], "time": deadline,
                                       "score_floor": self.floor, "active_nodes": self.active(),
                                       "resolved_after_seq": seq})
            self.next_maturity += 1

    def event(self, event: dict, seq: int, previous_time: int) -> int:
        require(type(event) is dict and {"seq", "time", "kind"} <= set(event), "EVENT_FIELDS")
        require(type(event["seq"]) is int and event["seq"] == seq, "EVENT_SEQUENCE")
        time = integer(event["time"], "EVENT_TIME", maximum=self.end, minimum=previous_time)
        kind = event["kind"]
        shared = {"seq", "time", "kind"}
        shapes = {
            "join": {"node", "generation", "view_score"},
            "view": {"node", "generation", "view_score"},
            "qualify": {"node", "generation"},
            "leave": {"node", "generation"},
            "bind": {"node", "generation", "task", "parent_score", "resource_units"},
            "ready": {"task", "weight", "provider_available", "resource_units"},
            "charge": {"task", "resource_units"},
            "cancel": {"task"},
            "finish_without_output": {"task", "resource_units"},
        }
        require(type(kind) is str and kind in shapes, "EVENT_KIND")
        fields(event, shared | shapes[kind], "EVENT_SHAPE")
        if kind == "join":
            node = label(event["node"], "NODE")
            generation = integer(event["generation"], "GENERATION", minimum=1)
            prior = self.members.get(node)
            require(prior is None or prior.phase == "left", "MEMBER_ALREADY_PRESENT")
            require(generation == (1 if prior is None else prior.generation + 1), "JOIN_GENERATION")
            self.members[node] = Member(generation, "syncing",
                                        optional_integer(event["view_score"], "VIEW_SCORE"))
            if self.members[node].view_score is None:
                self.unknowns.add("UNKNOWN_FULL_VIEW_SCORE")
        elif kind == "view":
            member = self._member(event)
            new_score = optional_integer(event["view_score"], "VIEW_SCORE")
            if new_score is None:
                self.unknowns.add("UNKNOWN_FULL_VIEW_SCORE")
            if (member.phase == "qualified" and member.view_score is not None and
                    (new_score is None or new_score < member.view_score)):
                self._violation("QUALIFIED_VIEW_RETENTION_REGRESSION", time, seq, node=event["node"])
            member.view_score = new_score
            if member.phase == "qualified":
                self._check_floor(event["node"], time, seq, "ACTIVE_VIEW_BELOW_FLOOR")
        elif kind == "qualify":
            member = self._member(event)
            require(member.phase == "syncing", "ALREADY_QUALIFIED")
            if self._check_floor(event["node"], time, seq, "BOOTSTRAP_BELOW_CURRENT_FLOOR"):
                member.phase = "qualified"
                self.admissions += 1
        elif kind == "leave":
            member = self._member(event)
            member.phase = "left"
            self.departures += 1
        elif kind == "bind":
            member = self._member(event)
            task_id = label(event["task"], "TASK")
            require(task_id not in self.tasks, "DUPLICATE_TASK")
            parent_score = optional_integer(event["parent_score"], "PARENT_SCORE")
            matches = parent_score is not None and member.view_score is not None and parent_score == member.view_score
            qualified = bool(member.phase == "qualified" and matches and parent_score >= self.floor)
            if member.phase == "qualified" and not qualified:
                self._violation("QUALIFIED_PARENT_SELECTION_DEFICIT", time, seq, task=task_id)
            if parent_score is None:
                self.unknowns.add("UNKNOWN_PARENT_SCORE")
            task = Task(event["node"], member.generation, time, parent_score, qualified)
            self.tasks[task_id] = task
            self._charge(event["resource_units"], task)
        elif kind == "ready":
            task_id, task = self._task(event)
            require(not task.ready and not task.failed, "DUPLICATE_OR_TERMINAL_OUTPUT")
            weight = integer(event["weight"], "READY_WEIGHT", minimum=1)
            require(event["provider_available"] is None or type(event["provider_available"]) is bool,
                    "PROVIDER_AVAILABLE_TYPE")
            task.ready = True
            self._charge(event["resource_units"], task)
            self.ready_weight = total(self.ready_weight, weight)
            member = self.members.get(task.node)
            reasons = []
            if task.carry_in:
                reasons.append("CARRY_IN_TASK")
            if not task.qualified_at_binding:
                reasons.append("NOT_QUALIFIED_AT_BINDING")
            if member is None or member.phase != "qualified" or member.generation != task.generation:
                reasons.append("ORIGINAL_SESSION_NOT_QUALIFIED")
            if task.cancelled:
                reasons.append("CANCELLATION_REQUEST_RETAINS_OUTPUT")
            if event["provider_available"] is not True:
                reasons.append("NO_DECLARED_READY_PROVIDER")
                if event["provider_available"] is None:
                    self.unknowns.add("UNKNOWN_READY_PROVIDER")
            if self.gamma is not None and time - task.bound_at > self.gamma:
                reasons.append("COMPLETION_BOUND_EXCEEDED")
                self._violation("COMPLETION_BOUND_EXCEEDED", time, seq, task=task_id,
                                duration=time-task.bound_at, gamma=self.gamma)
            if self.maximum_weight is not None and weight > self.maximum_weight:
                reasons.append("WEIGHT_BOUND_EXCEEDED")
                self._violation("WEIGHT_BOUND_EXCEEDED", time, seq, task=task_id, weight=weight)
            if self.length is None or self.maximum_weight is None or task.parent_score is None:
                self.unclassified_weight = total(self.unclassified_weight, weight)
                self.unknowns.add("UNCLASSIFIED_READY_CREDIT")
            elif time <= self.start + self.length:
                self.startup_debt = total(self.startup_debt, weight)
                self.debts.append({"task": task_id, "time": time, "weight": weight,
                                   "account": "startup", "reasons": reasons})
            elif reasons:
                self.entry_debt = total(self.entry_debt, weight)
                self.debts.append({"task": task_id, "time": time, "weight": weight,
                                   "account": "entry_or_carryover", "reasons": reasons})
            elif self.last_pacer_time is None or time > self.last_pacer_time + self.length:
                self.last_pacer_time = time
                self.paced_weight = total(self.paced_weight, weight)
                required_score = total(self.reference_score, self.paced_weight)
                actual_score = total(task.parent_score, weight)
                if actual_score < required_score:
                    self._violation("PACER_PARENT_FRESHNESS_DEFICIT", time, seq, task=task_id,
                                    observed=actual_score, required=required_score)
                deadline = integer(time + self.delta, "DEADLINE_RANGE", maximum=MAX_TIME)
                self.pacers.append({"task": task_id, "time": time, "seq": seq, "weight": weight,
                                    "deadline": deadline, "required_score": required_score,
                                    "completion_score": actual_score})
            else:
                self.eligible_unpaced_weight = total(self.eligible_unpaced_weight, weight)
        elif kind == "charge":
            _, task = self._task(event)
            self._charge(event["resource_units"], task)
        elif kind == "cancel":
            _, task = self._task(event)
            task.cancelled = True
        elif kind == "finish_without_output":
            _, task = self._task(event)
            require(not task.ready and not task.failed, "DUPLICATE_OR_TERMINAL_OUTPUT")
            task.failed = True
            self._charge(event["resource_units"], task)
        self._cohort_interval(time)
        return time

    def run(self) -> dict:
        events = self.document["events"]
        require(type(events) is list and len(events) <= MAX_EVENTS, "EVENT_COUNT")
        previous_time = self.start
        for index, event in enumerate(events, 1):
            require(type(event) is dict, "EVENT_FIELDS")
            event_time = integer(event.get("time"), "EVENT_TIME", maximum=self.end, minimum=previous_time)
            if event_time > previous_time:
                self.mature(previous_time, index-1, inclusive=True)
                self.mature(event_time, index-1, inclusive=False)
            previous_time = self.event(event, index, previous_time)
        self.mature(previous_time, len(events), inclusive=True)
        self.mature(self.end, len(events), inclusive=True)
        for pacer in self.pacers[self.next_maturity:]:
            self._violation("DELIVERY_DEADLINE_CENSORED", self.end, len(events),
                            task=pacer["task"], deadline=pacer["deadline"])
        if self.empty_since is not None and self.end > self.empty_since:
            self.empty_cohort_intervals.append({"start": self.empty_since, "end": self.end})
        partition = (self.startup_debt + self.entry_debt + self.paced_weight +
                     self.eligible_unpaced_weight + self.unclassified_weight)
        require(partition == self.ready_weight, "CREDIT_PARTITION_INVARIANT")
        uncompleted = sorted(task_id for task_id, task in self.tasks.items() if not task.ready and not task.failed)
        refusals = ["DECLARED_RECORDS_ARE_NOT_NATIVE_ATTESTATIONS",
                    "FULL_VIEW_AND_WORK_VALIDITY_NOT_REPLAYED",
                    "ALL_BRANCH_TASK_AND_RESIDUAL_STATE_COVERAGE_UNPROVED",
                    "CLOCK_DELIVERY_AND_RESOURCE_TRUTH_UNPROVED",
                    "QUALIFIED_PRODUCTION_AND_ENTRY_DEBT_TAILS_UNPROVED",
                    "NATIVE_DYNAMIC_FORK_REDUCTION_UNPROVED"]
        if self.paced_weight == 0:
            refusals.append("NO_PACED_PROGRESS_IN_DECLARED_WINDOW")
        return {
            "schema": "pon-dynamic-participation-audit-v1",
            "input_sha256": hashlib.sha256(canonical(self.document)).hexdigest(),
            "source_commit_as_declared": self.document["source_commit"],
            "scope": "finite_declared_score_and_lifecycle_model_only",
            "finite_trace_well_formed": True,
            "declared_contract_holds": not self.violations and not self.unknowns,
            "events_checked": len(events), "admissions": self.admissions, "departures": self.departures,
            "final_active_nodes": self.active(), "final_score_floor": self.floor,
            "paced_progress_credit": self.paced_weight, "total_ready_credit": self.ready_weight,
            "startup_honest_credit_debt": self.startup_debt,
            "entry_or_carryover_credit_debt": self.entry_debt,
            "eligible_unpaced_credit": self.eligible_unpaced_weight,
            "unclassified_ready_credit": self.unclassified_weight,
            "credit_partition_exact": True,
            "known_resource_units": self.known_resource, "all_resource_charges_known": self.resource_known,
            "task_accounts": {task_id: {"node": task.node, "generation": task.generation,
                "qualified_at_binding": task.qualified_at_binding, "carry_in": task.carry_in,
                "cancel_requested": task.cancelled, "ready": task.ready, "failed": task.failed,
                "known_resource_units": task.known_resource, "all_resource_charges_known": task.resource_known}
                for task_id, task in sorted(self.tasks.items())},
            "uncompleted_tasks": uncompleted, "empty_cohort_intervals": self.empty_cohort_intervals,
            "pacers": self.pacers, "credit_debts": self.debts, "floor_updates": self.floor_updates,
            "violations": self.violations, "unknowns": sorted(self.unknowns),
            "qualification": "HOLD_NO_GO", "qualification_refusals": refusals,
            "native_common_prefix_qualified": False, "native_chain_growth_qualified": False,
            "native_chain_quality_qualified": False, "native_six_successor_risk_bound": None,
            "native_common_prefix_failure_bound": None, "native_chain_growth_bound": None,
            "native_chain_quality_bound": None, "physical_resource_cost_authenticated": False,
            "production_activation": False,
        }


def audit_dynamic_participation(document: dict) -> dict:
    """Check only the supplied finite trace; a passing trace never issues native risk."""
    return _Audit(document).run()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, type=Path)
    parser.add_argument("--require-native-qualification", action="store_true")
    args = parser.parse_args()
    try:
        # Keep the same finite JSON contract, but bind the bytes to a bounded
        # ordinary-file read. A pathname stat followed by read_text could block
        # on a FIFO or read beyond the size checked before opening the file.
        # The shared reader rejects aliases and changing entries, uses a
        # nonblocking no-follow fd, and reads at most the ceiling plus one byte.
        path = args.check.absolute()
        document = strict_json(read_regular(path.parent, path.name, MAX_INPUT_BYTES)
                               .decode("utf-8"))
        result = audit_dynamic_participation(document)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 2 if args.require_native_qualification or not result["declared_contract_holds"] else 0
    except (ParticipationError, SourceReadError, OSError, UnicodeError,
            json.JSONDecodeError, RecursionError) as error:
        print(json.dumps({"check": "REFUSED", "reason": str(error), "qualification": "HOLD_NO_GO",
                          "native_six_successor_risk_bound": None}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
