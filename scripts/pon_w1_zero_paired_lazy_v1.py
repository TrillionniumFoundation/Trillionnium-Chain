#!/usr/bin/env python3
"""Strict readback of the registered zero-paired eager/lazy component experiment.

This checks the event grammar, canonical zero material, every ticket/proof
commitment, matched arms and complete cost accounting. It does not replay W1,
authenticate execution/clocks, or establish a minimum cost or production gate.
An unfinished begin has unknown cost; a supplied exit code is not authenticated.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import pon_w1_cost_matrix_reader as common

SCHEMA = "pon-w1-zero-paired-lazy-v1"
SELECTOR = "--zero-paired-lazy-v1"
ARMS = (
    "full-limb-sparse-eager", "full-limb-sparse-lazy", "zero-paired-legacy",
    "zero-paired-eager", "zero-paired-lazy",
)
SAMPLES, LIMIT = 8, 4096
HORIZONS = (1, 8)
TARGETS = ("7f" + "ff" * 31, "07" + "ff" * 31, "00" * 31 + "01", "ff" * 32)
PURPOSES = ("search-cost", "search-cost", "exhaustion-control", "first-hit-control")
COUNTERS = "cohorts setup_calls searches attempts hits misses exhausted materialized verification_calls".split()
MAX_LINE, MAX_BYTES = 1024 * 1024, 2 * 1024 * 1024 * 1024
PROOF_BYTES = 49188
ZERO = bytes(common.CELLS * 4)
TASK = common.pon_hash(b"task", ZERO, ZERO)
PREFIX = b"PNW1" + ZERO * 3
AXES = ("cpu_ns", "wall_ns")
FALSE_FLAGS = dict.fromkeys((
    "source_execution_authenticated", "clock_authenticated", "independent_w1_replay",
    "feature_provenance_verified", "cheapest_strategy_proven", "work_profile_qualified",
    "public_service_qualified", "cross_architecture_qualified", "production_activation",
), False)
STATIC = {
    "arms": list(ARMS), "samples": SAMPLES, "material": "zero", "proof_bytes": PROOF_BYTES,
    "task": TASK.hex(), "prefix_sha256": common.sha(PREFIX),
    "a_sha256": common.sha(ZERO), "b_sha256": common.sha(ZERO),
    "clock": "process-cpu-monotonic-wall", "rotation": "arm=(position+sample)%5",
    "complete_trace_tiles": 512, "shared_preparation": "one-actual-constructor-per-cohort",
    "producer_scope": "setup+attempts+losing-proof-disposal+winner-cleanup+task-teardown",
    "inclusive_scope": "cohort-total-includes-observation-streaming-and-verification-before-end-record",
    "consensus_credit": 0, "production_activation": False, "cheapest_strategy_proven": False,
}
FIELDS = {
    "header": "target_index target horizon max_attempts material_timing ideal_uniform_ticket_assumption " + " ".join(STATIC),
    "cohort_begin": "sample position arm",
    "setup_finish": "sample arm timing setup_calls",
    "search_begin": "sample arm search",
    "attempt_begin": "sample arm search nonce",
    "attempt_finish": "sample arm search nonce challenge trace ticket proof_sha256 hit materialized producer evidence disposal",
    "search_finish": "sample arm search attempts first_hit_nonce timing",
    "verify_begin": "sample arm search nonce kind verifier target proof_sha256",
    "verify_finish": "sample arm search nonce kind verifier target proof_sha256 accepted error timing",
    "cleanup_begin": "sample arm search",
    "cleanup_finish": "sample arm search timing",
    "cohort_end": "sample arm teardown total",
    "footer": "counts complete consensus_credit production_activation cheapest_strategy_proven",
    "failure": "error",
}


def fixed(value, expected, label):
    common.require(type(value) is type(expected) and value == expected,
                   label + ": fixed declaration/identity changed")
    if type(expected) is list:
        for i, item in enumerate(expected):
            fixed(value[i], item, label + f"[{i}]")


def timing(value, label):
    return common.timing(value, label)


def add_times(values):
    values = list(values)
    return {axis: sum(v[axis] for v in values) if all(v[axis] is not None for v in values) else None
            for axis in AXES}


def covers(total, parts, label):
    """Only disjoint phases are added; enclosing timers are never added twice."""
    charged = add_times(parts)
    for axis in AXES:
        if total[axis] is not None and charged[axis] is not None:
            common.require(total[axis] >= charged[axis], label + ": disjoint phases exceed inclusive time")


def challenge(target, sample, search, nonce):
    return common.pon_hash(b"pon-w1-zero-paired-lazy-challenge-v1", TASK, bytes.fromhex(target),
        sample.to_bytes(8, "little"), search.to_bytes(8, "little"), nonce.to_bytes(8, "little"))


def grid():
    return [(target, horizon) for target in range(4)
            for horizon in (HORIZONS if target < 2 else (1,))]


class Records:
    def __init__(self):
        self.sequence = 0
        self.phase = "header"
        self.header = self.cohort = self.search = None
        self.cohorts = []
        self.counts = Counter(dict.fromkeys(COUNTERS, 0))
        self.canonical = {}
        self.logical_prefix_sha256 = {}
        self.failure = None
        self.semantic_failures = []
        self.ended = False
        self.verification_queue = []
        self.verification_position = 0
        self.completed_timings = {key: [] for key in ("producer", "evidence", "verification")}

    def identity(self, row, *, search=False, nonce=False):
        common.require(self.cohort is not None, "event outside cohort")
        for key in ("sample", "arm"):
            fixed(row[key], self.cohort[key], key)
        if search:
            common.require(self.search is not None, "event outside search")
            fixed(row["search"], self.search["search"], "search")
        if nonce:
            fixed(row["nonce"], len(self.search["attempts"]), "consecutive nonce")

    def add(self, row):
        common.require(type(row) is dict and not self.ended and self.failure is None,
                       "record after terminal event or invalid object")
        event = row.get("event")
        common.require(type(event) is str and event in FIELDS, "unknown event")
        common.exact(row, {"schema", "seq", "event", *FIELDS[event].split()}, event)
        fixed(row["schema"], SCHEMA, "schema")
        fixed(row["seq"], self.sequence, "sequence")
        if event != "failure":
            fixed(event, self.phase, "event grammar")
        else:
            common.require(self.header is not None, "failure requires a declared experiment")
        getattr(self, "add_" + event)(row)
        self.sequence += 1

    def add_header(self, row):
        for key, value in STATIC.items():
            fixed(row[key], value, "header." + key)
        index = common.integer(row["target_index"], "target index", 3)
        common.require(type(row["horizon"]) is int and (index, row["horizon"]) in grid(),
                       "undeclared target/horizon")
        fixed(row["target"], TARGETS[index], "target")
        fixed(row["max_attempts"], LIMIT if index < 2 else 3, "attempt limit")
        fixed(row["ideal_uniform_ticket_assumption"], ("1/2", "1/32", None, None)[index],
              "ideal probability assumption")
        timing(row["material_timing"], "shared material")
        self.header = row
        self.phase = "cohort_begin"

    def add_cohort_begin(self, row):
        sample, position = divmod(len(self.cohorts), len(ARMS))
        common.require(sample < SAMPLES, "too many cohorts")
        for key, value in (("sample", sample), ("position", position),
                           ("arm", (position + sample) % len(ARMS))):
            fixed(row[key], value, key)
        self.cohort = {**row, "setup": None, "searches": [], "verifier_timings": []}
        self.phase = "setup_finish"

    def add_setup_finish(self, row):
        self.identity(row)
        fixed(row["setup_calls"], 1, "actual preparation")
        self.cohort["setup"] = timing(row["timing"], "setup")
        self.completed_timings["producer"].append(row["timing"])
        self.counts["setup_calls"] += 1
        self.phase = "search_begin"

    def add_search_begin(self, row):
        self.identity(row)
        index = len(self.cohort["searches"])
        common.require(index < self.header["horizon"], "too many searches")
        fixed(row["search"], index, "search")
        self.search = {**row, "attempts": [], "first_hit_nonce": None, "cleanup": None}
        self.phase = "attempt_begin"

    def add_attempt_begin(self, row):
        self.identity(row, search=True, nonce=True)
        common.require(len(self.search["attempts"]) < self.header["max_attempts"]
                       and self.search["first_hit_nonce"] is None, "work after search stop")
        self.phase = "attempt_finish"

    def add_attempt_finish(self, row):
        self.identity(row, search=True, nonce=True)
        context = challenge(self.header["target"], row["sample"], row["search"], row["nonce"])
        fixed(row["challenge"], context.hex(), "challenge recipe")
        trace = common.hex_bytes(row["trace"], 32, "trace")
        ticket = common.pon_hash(b"ticket", context, trace)
        fixed(row["ticket"], ticket.hex(), "ticket")
        hit = ticket <= bytes.fromhex(self.header["target"])
        fixed(row["hit"], hit, "target outcome")
        fixed(row["materialized"], row["arm"] in (0, 2, 3) or hit, "materialization policy")
        fixed(row["proof_sha256"], common.sha(PREFIX + trace), "full proof commitment")
        for name in ("producer", "evidence", "disposal"):
            timing(row[name], name)
            self.completed_timings["evidence" if name == "evidence" else "producer"].append(row[name])
        self.search["attempts"].append(row)
        self.counts["attempts"] += 1
        self.counts["hits" if hit else "misses"] += 1
        self.counts["materialized"] += row["materialized"]
        if hit:
            self.search["first_hit_nonce"] = row["nonce"]
        self.phase = "search_finish" if hit or len(self.search["attempts"]) == self.header["max_attempts"] else "attempt_begin"

    def add_search_finish(self, row):
        self.identity(row, search=True)
        s = self.search
        fixed(row["attempts"], len(s["attempts"]), "attempt count")
        fixed(row["first_hit_nonce"], s["first_hit_nonce"], "first ordered hit")
        s["timing"] = timing(row["timing"], "inclusive search")
        covers(s["timing"], [a[key] for a in s["attempts"] for key in ("producer", "evidence", "disposal")], "search")
        stream = tuple((a["nonce"], a["challenge"], a["trace"], a["ticket"], a["proof_sha256"], a["hit"])
                       for a in s["attempts"])
        key = row["sample"], row["search"]
        if key in self.canonical:
            common.require(self.canonical[key] == stream, "matched arm complete stream disagreement")
        else:
            self.canonical[key] = stream
        self.logical_prefix_sha256[f"{row['sample']}:{row['arm']}:{row['search']}"] = common.sha(
            json.dumps(stream, separators=(",", ":")).encode())
        self.counts["searches"] += 1
        self.counts["exhausted"] += s["first_hit_nonce"] is None
        if s["first_hit_nonce"] is not None:
            self.verification_queue = [(s["first_hit_nonce"], kind, verifier)
                for kind in ("winner", "product-last") for verifier in ("production", "reference")]
        elif self.header["target_index"] == 2:
            self.verification_queue = [(a["nonce"], "exhausted-replay", verifier)
                for a in s["attempts"] for verifier in ("production", "reference")]
        else:
            self.verification_queue = []
        self.verification_position = 0
        self.phase = "verify_begin" if self.verification_queue else "cleanup_begin"

    def check_verifier(self, row):
        self.identity(row, search=True)
        common.require(self.verification_position < len(self.verification_queue), "unexpected verifier")
        nonce, kind, verifier = self.verification_queue[self.verification_position]
        for key, value in (("nonce", nonce), ("kind", kind), ("verifier", verifier)):
            fixed(row[key], value, "verifier." + key)
        proof = PREFIX + bytes.fromhex(self.search["attempts"][nonce]["trace"])
        if kind == "product-last":
            proof = bytearray(proof)
            proof[4 + 3 * common.CELLS * 4 - 4] = 1
        fixed(row["target"], TARGETS[3] if kind == "exhausted-replay" else self.header["target"],
              "verification target")
        fixed(row["proof_sha256"], common.sha(proof), "verified complete proof bytes")
        return kind

    def add_verify_begin(self, row):
        self.check_verifier(row)
        self.phase = "verify_finish"

    def add_verify_finish(self, row):
        kind = self.check_verifier(row)
        common.require(type(row["accepted"]) is bool and
                       (row["error"] is None or type(row["error"]) is str and bool(row["error"])),
                       "verifier result types")
        common.require(row["accepted"] == (row["error"] is None), "contradictory verifier result")
        self.cohort["verifier_timings"].append(timing(row["timing"], "complete verification"))
        self.completed_timings["verification"].append(row["timing"])
        self.counts["verification_calls"] += 1
        correct = row["error"] == "Product" if kind == "product-last" else row["accepted"]
        if not correct:
            # The native observer can report a genuine verifier failure before
            # emitting failure. Preserve it; it can never close a successful run.
            self.semantic_failures.append({key: row[key] for key in
                ("sample", "arm", "search", "nonce", "kind", "verifier", "accepted", "error")})
            self.phase = "failure"
            return
        self.verification_position += 1
        self.phase = "verify_begin" if self.verification_position < len(self.verification_queue) else "cleanup_begin"

    def add_cleanup_begin(self, row):
        self.identity(row, search=True)
        self.phase = "cleanup_finish"

    def add_cleanup_finish(self, row):
        self.identity(row, search=True)
        self.search["cleanup"] = timing(row["timing"], "winning proof cleanup")
        self.completed_timings["producer"].append(row["timing"])
        self.cohort["searches"].append(self.search)
        self.search = None
        self.phase = "cohort_end" if len(self.cohort["searches"]) == self.header["horizon"] else "search_begin"

    def add_cohort_end(self, row):
        self.identity(row)
        c = self.cohort
        c["teardown"] = timing(row["teardown"], "task teardown")
        c["total"] = timing(row["total"], "inclusive cohort")
        self.completed_timings["producer"].append(c["teardown"])
        phases = [c["setup"], c["teardown"]]
        evidence = []
        for search in c["searches"]:
            phases.append(search["cleanup"])
            for attempt in search["attempts"]:
                phases.extend((attempt["producer"], attempt["disposal"]))
                evidence.append(attempt["evidence"])
        c["producer_total"] = add_times(phases)
        c["evidence_total"] = add_times(evidence)
        c["verification_total"] = add_times(c["verifier_timings"])
        covers(c["total"], [c["producer_total"], c["evidence_total"], c["verification_total"]], "cohort")
        self.cohorts.append(c)
        self.cohort = None
        self.counts["cohorts"] += 1
        self.phase = "footer" if len(self.cohorts) == SAMPLES * len(ARMS) else "cohort_begin"

    def add_footer(self, row):
        common.exact(row["counts"], COUNTERS, "footer counts")
        for key in COUNTERS:
            fixed(row["counts"][key], self.counts[key], "footer." + key)
        for key, value in (("complete", True), ("consensus_credit", 0),
                           ("production_activation", False), ("cheapest_strategy_proven", False)):
            fixed(row[key], value, "footer." + key)
        self.ended = True
        self.phase = "ended"

    def add_failure(self, row):
        common.require(type(row["error"]) is str and bool(row["error"]), "failure needs retained reason")
        self.failure = row["error"]

    def report(self, *, process_exit_code, invalid=None, partial_bytes=0, partial_sha256=None):
        complete = (invalid is None and self.ended and process_exit_code == 0
                    and not partial_bytes and not self.semantic_failures and self.failure is None)
        status = "INVALID" if invalid else "COMPONENT_OBSERVATION" if complete else "INCOMPLETE"
        result = {
            "schema": SCHEMA + "-readback", "status": status,
            "exit_code": {"COMPONENT_OBSERVATION": 0, "INCOMPLETE": 3, "INVALID": 2}[status],
            "native_process_exit_code": process_exit_code,
            "process_exit_authenticated": False, "records_checked": self.sequence,
            "footer_observed": self.ended, "counts": dict(self.counts),
            "error": invalid, "failure": self.failure, "semantic_failures": self.semantic_failures,
            "trailing_partial_bytes": partial_bytes, "trailing_partial_sha256": partial_sha256,
            "next_expected_event": self.phase,
            "unfinished_resource_cost": None,
            "unfinished_cost_policy": "unknown-never-zero-or-imputed-from-a-complete-attempt",
            "completed_phase_costs": {key: add_times(values) for key, values in self.completed_timings.items()},
            "unfinished_cohort": None if self.cohort is None else {key: self.cohort[key] for key in ("sample", "arm")},
            "unfinished_search": None if self.search is None else {key: self.search[key] for key in ("sample", "arm", "search")},
            "begin_semantics": "flushed-before-call-termination-may-precede-or-follow-native-start",
            "material_before_header_requires_outer_receipt": True,
            "outer_process_costs_required": True, "consensus_credit": 0,
            "aggregation": "ratio-of-sums-per-fixed-arm-target-horizon-including-setup-all-misses-disposal-and-teardown",
            "cross_horizon_aggregation": "none-correlated-prefixes", "confidence_bound": None,
            "logical_prefix_sha256": self.logical_prefix_sha256,
            **FALSE_FLAGS,
        }
        if self.header is not None:
            result.update(target_index=self.header["target_index"], target=self.header["target"],
                horizon=self.header["horizon"], purpose=PURPOSES[self.header["target_index"]],
                task=self.header["task"], material_timing=self.header["material_timing"])
        result["arms"] = []
        for index, name in enumerate(ARMS):
            cohorts = [c for c in self.cohorts if c["arm"] == index]
            searches = [s for c in cohorts for s in c["searches"]]
            attempts = [a for s in searches for a in s["attempts"]]
            wins = sum(s["first_hit_nonce"] is not None for s in searches)
            cost = add_times(c["producer_total"] for c in cohorts)
            row = {"arm": index, "name": name, "completed_cohorts": len(cohorts),
                "setup_calls": len(cohorts), "searches": len(searches),
                "accepted_winners": wins, "attempts": len(attempts),
                "misses": sum(not a["hit"] for a in attempts), "exhausted": len(searches) - wins,
                "materialized": sum(a["materialized"] for a in attempts),
                "producer_total": cost, "paid_setup": add_times(c["setup"] for c in cohorts),
                "evidence_total": add_times(c["evidence_total"] for c in cohorts),
                "verification_total": add_times(c["verification_total"] for c in cohorts),
                "inclusive_cohort": add_times(c["total"] for c in cohorts),
                "cost_per_accepted_winner": {axis: {"numerator": cost[axis], "denominator": wins}
                    if complete and wins and cost[axis] is not None else None for axis in AXES},
                "samples": [{"sample": c["sample"], "producer_total": c["producer_total"],
                    "searches": len(c["searches"]),
                    "accepted_winners": sum(s["first_hit_nonce"] is not None for s in c["searches"])}
                    for c in cohorts]}
            result["arms"].append(row)
        return result


def read_stream(stream, *, process_exit_code=None):
    records, total, partial, partial_sha, invalid = Records(), 0, 0, None, None
    try:
        common.require(process_exit_code is None or type(process_exit_code) is int,
                       "process exit must be an integer or unknown")
        while True:
            raw = stream.readline(MAX_LINE + 1)
            if not raw:
                break
            total += len(raw)
            common.require(len(raw) <= MAX_LINE and total <= MAX_BYTES, "bounded journal size exceeded")
            if not raw.endswith(b"\n"):
                partial, partial_sha = len(raw), common.sha(raw)
                break
            records.add(common.decode(raw))
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        invalid = str(error)
    result = records.report(process_exit_code=process_exit_code, invalid=invalid,
                            partial_bytes=partial, partial_sha256=partial_sha)
    result["bytes_read"] = total
    return result


def analyze(path, process_exit_code=None):
    try:
        with Path(path).open("rb") as stream:
            return read_stream(stream, process_exit_code=process_exit_code)
    except OSError as error:
        result = Records().report(process_exit_code=process_exit_code)
        result["input_error"] = type(error).__name__ + ": " + str(error)
        return result


def check_complete_report(report):
    """Reject stripped/contradictory summaries, without authenticating reports.

    A self-consistent forged report is still possible: the source journal and
    external process/source receipts remain the evidence, not this structure.
    """
    for key, value in (("native_process_exit_code", 0), ("exit_code", 0),
                       ("footer_observed", True), ("error", None), ("failure", None),
                       ("semantic_failures", []), ("trailing_partial_bytes", 0),
                       ("trailing_partial_sha256", None), ("next_expected_event", "ended"),
                       ("unfinished_cohort", None), ("unfinished_search", None),
                       ("consensus_credit", 0), ("process_exit_authenticated", False)):
        fixed(report[key], value, "complete report." + key)
    common.require("input_error" not in report, "complete report retains input error")
    target, horizon = report["target_index"], report["horizon"]
    fixed(report["target"], TARGETS[target], "complete report target")
    fixed(report["task"], TASK.hex(), "complete report task")
    fixed(report["purpose"], PURPOSES[target], "complete report purpose")
    count = common.exact(report["counts"], COUNTERS, "complete report counts")
    for name in COUNTERS:
        common.integer(count[name], "complete report count." + name)
    cohorts, searches = SAMPLES * len(ARMS), SAMPLES * len(ARMS) * horizon
    fixed(count["cohorts"], cohorts, "complete report cohorts")
    fixed(count["setup_calls"], cohorts, "complete report setup calls")
    fixed(count["searches"], searches, "complete report searches")
    fixed(count["attempts"], count["hits"] + count["misses"], "complete report all attempts")
    common.require(count["hits"] <= searches, "more winners than searches")
    fixed(count["exhausted"], searches - count["hits"], "complete report exhaustion")
    limit = LIMIT if target < 2 else 3
    common.require(searches <= count["attempts"] <= searches * limit, "attempt budget mismatch")
    expected_verifiers = 4 * count["hits"] + (2 * limit * count["exhausted"] if target == 2 else 0)
    fixed(count["verification_calls"], expected_verifiers, "complete report full verifier roster")
    fixed(report["records_checked"], 2 + 3 * cohorts + 4 * searches
          + 2 * count["attempts"] + 2 * count["verification_calls"], "complete report event count")
    if target == 3:
        fixed(count["attempts"], searches, "maximum-target first hit")
        fixed(count["hits"], searches, "maximum-target winners")

    prefixes = common.exact(report["logical_prefix_sha256"],
        {f"{sample}:{arm}:{search}" for sample in range(SAMPLES)
            for arm in range(len(ARMS)) for search in range(horizon)}, "complete prefix key grid")
    for key, digest in prefixes.items():
        common.hex_bytes(digest, 32, "complete report prefix digest " + key)
    for sample in range(SAMPLES):
        for search in range(horizon):
            for arm in range(1, len(ARMS)):
                fixed(prefixes[f"{sample}:{arm}:{search}"], prefixes[f"{sample}:0:{search}"],
                      "complete report cross-arm prefix")

    common.require(type(report["arms"]) is list and len(report["arms"]) == len(ARMS),
                   "complete report fixed arm roster")
    sums = Counter(dict.fromkeys(COUNTERS, 0))
    for index, row in enumerate(report["arms"]):
        common.require(type(row) is dict, "arm summary must be an object")
        for key, value in (("arm", index), ("name", ARMS[index]), ("completed_cohorts", SAMPLES),
                           ("setup_calls", SAMPLES), ("searches", SAMPLES * horizon)):
            fixed(row[key], value, "complete report arm." + key)
        for key in ("accepted_winners", "attempts", "misses", "exhausted", "materialized"):
            common.integer(row[key], "complete report arm." + key)
        wins = row["accepted_winners"]
        common.require(wins <= row["searches"], "arm winners exceed searches")
        fixed(row["attempts"], wins + row["misses"], "arm attempts")
        fixed(row["exhausted"], row["searches"] - wins, "arm exhausted searches")
        common.require(row["searches"] <= row["attempts"] <= row["searches"] * limit,
                       "arm attempt budget")
        fixed(row["materialized"], row["attempts"] if index in (0, 2, 3) else wins,
              "arm materialization count")
        common.require(type(row["samples"]) is list and len(row["samples"]) == SAMPLES,
                       "eight complete arm samples required")
        for sample, sample_row in enumerate(row["samples"]):
            common.exact(sample_row, ("sample", "producer_total", "searches", "accepted_winners"),
                         "complete sample fields")
            fixed(sample_row["sample"], sample, "complete arm sample")
            fixed(sample_row["searches"], horizon, "complete sample search count")
            common.integer(sample_row["accepted_winners"], "sample winners", horizon)
            timing(sample_row["producer_total"], "sample producer cost")
        fixed(sum(s["accepted_winners"] for s in row["samples"]), wins, "arm sample winner total")
        for name in ("producer_total", "paid_setup", "evidence_total", "verification_total", "inclusive_cohort"):
            timing(row[name], "complete arm." + name)
        fixed(row["producer_total"], add_times(s["producer_total"] for s in row["samples"]),
              "arm sample producer total")
        covers(row["inclusive_cohort"], [row["producer_total"], row["evidence_total"], row["verification_total"]],
               "complete arm")
        common.exact(row["cost_per_accepted_winner"], AXES, "complete report rates")
        for axis in AXES:
            expected = {"numerator": row["producer_total"][axis], "denominator": wins}
            fixed(row["cost_per_accepted_winner"][axis], expected if wins and expected["numerator"] is not None else None,
                  "complete report cost ratio")
        for key, value in (("cohorts", SAMPLES), ("setup_calls", SAMPLES), ("searches", row["searches"]),
                           ("hits", wins), ("attempts", row["attempts"]), ("misses", row["misses"]),
                           ("exhausted", row["exhausted"]), ("materialized", row["materialized"])):
            sums[key] += value
    for key in COUNTERS:
        if key != "verification_calls":
            fixed(sums[key], count[key], "complete report arm aggregate." + key)


def campaign(reports):
    """Require all six original shards; correlated horizons are not pooled."""
    result = {"schema": SCHEMA + "-campaign-readback", "status": "INCOMPLETE", "exit_code": 3,
        "expected_grid": [list(v) for v in grid()], "shards": reports,
        "consensus_credit": 0, "unfinished_resource_cost": None,
        "aggregation": "none-across-targets-or-correlated-horizons", **FALSE_FLAGS}
    try:
        common.require(type(reports) is list, "campaign reports must be a list")
        indexed = {}
        for report in reports:
            common.require(type(report) is dict and report.get("schema") == SCHEMA + "-readback",
                           "foreign reader schema")
            for flag in FALSE_FLAGS:
                fixed(report.get(flag), False, flag)
            status = report.get("status")
            common.require(status in ("COMPONENT_OBSERVATION", "INCOMPLETE", "INVALID"), "unknown shard status")
            if status == "INVALID":
                raise ValueError("invalid shard retained")
            if "target_index" not in report or "horizon" not in report:
                common.require(status != "COMPONENT_OBSERVATION", "complete shard missing identity")
                continue
            key = report["target_index"], report["horizon"]
            common.require(type(key[0]) is int and type(key[1]) is int and key in grid() and key not in indexed,
                           "duplicate or undeclared shard")
            if status == "COMPONENT_OBSERVATION":
                check_complete_report(report)
            indexed[key] = report
        result["observed_shards"] = len(reports)
        if (len(reports) != len(grid()) or set(indexed) != set(grid())
                or any(r["status"] != "COMPONENT_OBSERVATION" for r in reports)):
            result["error"] = "missing or incomplete declared shards; no retry selection"
            return result
        for target in (0, 1):
            short, long = indexed[target, 1], indexed[target, 8]
            for key, digest in short["logical_prefix_sha256"].items():
                common.require(long["logical_prefix_sha256"].get(key) == digest,
                               "correlated horizon changed search prefix")
        result.update(status="COMPONENT_OBSERVATION", exit_code=0,
            total_counts={key: sum(r["counts"][key] for r in reports) for key in COUNTERS})
    except (ValueError, KeyError, TypeError) as error:
        result.update(status="INVALID", exit_code=2, error=str(error))
    return result


def analyze_paths(paths, exits=None):
    paths = list(paths)
    if exits is None:
        exits = [None] * len(paths)
    if len(paths) != len(exits):
        return {"schema": SCHEMA + "-campaign-readback", "status": "INVALID", "exit_code": 2,
                "error": "one process exit per journal is required", **FALSE_FLAGS}
    return campaign([analyze(path, code) for path, code in zip(paths, exits)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    parser.add_argument("--process-exit-code", type=int)
    args = parser.parse_args()
    result = analyze(args.journal, args.process_exit_code)
    print(json.dumps(result, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
