#!/usr/bin/env python3
"""Read explicit actual-reuse V3 records; no W1 or hardware qualification.

The original V2 gate is unchanged. This reader reconstructs all diagnostic
matrices/products, complete proof bytes, challenge/ticket hashes and coverage.
Native transcript verdicts, clocks and source identity still need provenance.
Exit 0 means complete consistent measurements, 1 a retained native disagreement,
and 2 missing/malformed/unknown observations. No exit grants production authority.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

import pon_w1_cost_matrix_reader as common

SCHEMA = "pon-w1-reused-producers-cost-v3"
SELECTOR = "--actual-reuse-v3"
SAMPLES, SEARCHES, ATTEMPT_BUDGET = 8, 4, 4096
ARMS, CLASSES, TARGET = common.ARMS, common.CLASSES, common.TARGET
MAX_LINE, MAX_BYTES = 8 * 1024 * 1024, 192 * 1024 * 1024
COHORTS = len(CLASSES) * SAMPLES * len(ARMS)
SEARCH_COUNT = sum(common.supported(arm, name) for name in CLASSES for arm in ARMS) * SAMPLES * SEARCHES
MAX_RECORDS = 2 + len(CLASSES) + COHORTS + SEARCH_COUNT * 3 + len(CLASSES) * SAMPLES * SEARCHES
FALSE_FLAGS = dict.fromkeys(("hardness_accepted", "work_profile_qualified",
    "resource_fairness_qualified", "independent_hardware_qualified", "public_network_ready",
    "public_service_measured", "production_activation"), False)
FIELDS = {
    "campaign": "selector samples searches_per_setup attempt_budget seed target arms classes clock material_setup setup_reuse producer_timing_scope verifier_timing_scope " + " ".join(FALSE_FLAGS),
    "material": "class source task a_hex b_hex",
    "cohort": "class sample arm invocation_order task target status setup_calls searches setup total",
    "search": "class sample arm search_index task target setup_calls timing status attempts winner",
    "verifier": "class sample arm search_index task target path invocation_order challenge proof_sha256 outcome timing",
    "candidate": "class sample search_index task target challenge proof_hex proof_sha256",
    "end": "material_count cohort_count search_count candidate_count verifier_count complete",
}


def challenge(task, sample, search, nonce):
    return common.pon_hash(b"pon-w1-reused-challenge-v3", task, bytes(8),
        sample.to_bytes(8, "little"), search.to_bytes(8, "little"), nonce.to_bytes(8, "little"))


def measured(value, label):
    common.timing(value, label)
    for axis in ("cpu_ns", "wall_ns"):
        common.require(type(value[axis]) is int and value[axis] > 0,
                       label + ": positive actual CPU/wall observation required; unknown is not zero")
    return value


class Records:
    def __init__(self):
        self.counts = Counter()
        self.materials, self.cohorts, self.candidates = {}, {}, {}
        self.current, self.group, self.streams = None, None, {}
        self.campaign, self.ended, self.alerts = None, False, []

    def context(self, row):
        name = row["class"]
        common.require(type(name) is str and name in self.materials, "class/material not available")
        sample = common.integer(row["sample"], "sample", SAMPLES - 1)
        common.require(row["task"] == self.materials[name][2].hex() and row["target"] == TARGET,
                       "task/target changed")
        return name, sample

    def same_current(self, row):
        key = self.context(row) + (row["arm"],)
        common.require(self.current is not None and self.current["key"] == key,
                       "search/verifier outside its actual cohort")
        return self.current

    def close_current(self):
        if self.current is None:
            return
        current = self.current
        supported = common.supported(current["key"][2], current["key"][0])
        common.require(len(current["searches"]) == (SEARCHES if supported else 0),
                       "actual reuse search coverage incomplete")
        for row in current["searches"]:
            common.require(len(row["verifiers"]) == (2 if row["status"] == "target-hit-unverified" else 0),
                           "full production/reference verification coverage incomplete")
        for axis in ("cpu_ns", "wall_ns"):
            subtotal = current["setup"][axis] + sum(row["timing"][axis] for row in current["searches"])
            common.require(current["total"][axis] >= subtotal, "cohort phases exceed inclusive actual total")

    def close_group(self):
        if self.group is None:
            return
        common.require(len(self.streams) == SEARCHES, "canonical search coverage incomplete")
        expected = {self.group + (index,) for index, row in self.streams.items()
                    if row["status"] == "target-hit-unverified"}
        actual = {key for key in self.candidates if key[:2] == self.group}
        common.require(actual == expected, "complete winner byte coverage incomplete")

    def add(self, row):
        common.require(not self.ended, "records after complete end")
        common.require(type(row) is dict and row.get("schema") == SCHEMA, "explicit V3 schema required")
        kind = row.get("kind")
        common.require(type(kind) is str and kind in FIELDS, "unknown record kind")
        common.exact(row, {"schema", "kind", *FIELDS[kind].split()}, kind)
        common.require(self.campaign is not None or kind == "campaign", "campaign must be first")
        getattr(self, "add_" + kind)(row)
        self.counts[kind] += 1

    def add_campaign(self, row):
        common.require(self.campaign is None, "duplicate campaign")
        for key, value in (("samples", SAMPLES), ("searches_per_setup", SEARCHES),
                           ("attempt_budget", ATTEMPT_BUDGET), ("seed", 0)):
            common.require(common.integer(row[key], key) == value, "fixed campaign parameter changed: " + key)
        common.require(row["selector"] == SELECTOR and row["arms"] == list(ARMS)
                       and row["classes"] == list(CLASSES) and row["target"] == TARGET,
                       "fixed V3 selector/arm/material/target grid changed")
        common.require(row["clock"] == "thread-cpu-and-monotonic-wall-ns"
                       and row["setup_reuse"] == "one-actual-preparation-four-independent-searches",
                       "actual preparation reuse required; modeled amortization is not observation")
        common.require(row["producer_timing_scope"] == "actual-setup-and-complete-search-retention-excludes-json-comparison-verification"
                       and row["verifier_timing_scope"] == "native-full-verification-call-only-no-fact-cache",
                       "measurement scope changed")
        for flag in FALSE_FLAGS:
            common.require(row[flag] is False, "observation cannot grant authority: " + flag)
        measured(row["material_setup"], "material_setup")
        self.campaign = row

    def add_material(self, row):
        self.close_current()
        self.close_group()
        index = len(self.materials)
        common.require(index < len(CLASSES) and row["class"] == CLASSES[index]
                       and self.counts["cohort"] == index * SAMPLES * len(ARMS),
                       "material coverage/order incomplete")
        name = row["class"]
        a, b, task, prefix = common.material(name)
        source = "hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture"
        common.require(row["source"] == source and row["task"] == task.hex(), "material source/task mismatch")
        common.require(common.hex_bytes(row["a_hex"], common.CELLS * 4, "A") == a
                       and common.hex_bytes(row["b_hex"], common.CELLS * 4, "B") == b,
                       "canonical diagnostic matrix recipe mismatch")
        self.materials[name] = a, b, task, prefix

    def add_cohort(self, row):
        self.close_current()
        index = self.counts["cohort"]
        class_index, remainder = divmod(index, SAMPLES * len(ARMS))
        sample, order = divmod(remainder, len(ARMS))
        key = self.context(row)
        common.require(class_index < len(CLASSES) and key == (CLASSES[class_index], sample),
                       "fixed cohort coverage/order incomplete")
        arm = ARMS[(sample + order) % len(ARMS)]
        common.require(row["arm"] == arm and common.integer(row["invocation_order"], "order") == order,
                       "cohort invocation rotation changed")
        if order == 0:
            self.close_group()
            self.group, self.streams = key, {}
        common.require(common.integer(row["setup_calls"], "setup_calls") == 1,
                       "one actual constructor invocation required")
        supported = common.supported(arm, key[0])
        common.require(row["status"] == ("supported" if supported else "unsupported")
                       and common.integer(row["searches"], "searches") == (SEARCHES if supported else 0),
                       "unsupported arm cannot fall back or erase actual searches")
        current = {"key": key + (arm,), "order": order, "searches": [],
                   "setup": measured(row["setup"], "cohort.setup"),
                   "total": measured(row["total"], "cohort.total"), "supported": supported}
        self.cohorts[current["key"]] = self.current = current

    def add_search(self, row):
        current = self.same_current(row)
        index = common.integer(row["search_index"], "search_index", SEARCHES - 1)
        common.require(current["supported"] and index == len(current["searches"]),
                       "independent search coverage/order incomplete")
        if current["searches"]:
            previous = current["searches"][-1]
            common.require(len(previous["verifiers"]) == (2 if previous["status"] == "target-hit-unverified" else 0),
                           "previous actual winner verification incomplete")
        common.require(common.integer(row["setup_calls"], "search.setup_calls") == 0,
                       "search rebuilt preparation; reuse cannot be modeled")
        name, sample, _ = current["key"]
        _, _, task, prefix = self.materials[name]
        stream, last = common._trials(row, task, sample, prefix,
            challenge_at=lambda nonce: challenge(task, sample, index, nonce))
        if index in self.streams:
            canonical = self.streams[index]
            common.require(stream == canonical["stream"] and row["status"] == canonical["status"],
                           "supported reused streams disagree")
        else:
            self.streams[index] = {"stream": stream, "last": last, "status": row["status"]}
        if row["status"] == "target-hit-unverified":
            common.exact(row["winner"], ("challenge", "proof_sha256"), "search.winner")
            common.require(row["winner"] == {key: last[key] for key in ("challenge", "proof_sha256")},
                           "winner does not bind final complete attempt")
        else:
            common.require(row["winner"] is None, "exhausted search cannot have winner")
        current["searches"].append({"index": index, "status": row["status"], "winner": row["winner"],
            "timing": measured(row["timing"], "search.timing"), "attempt_count": len(row["attempts"]),
            "verifiers": []})

    def add_verifier(self, row):
        current = self.same_current(row)
        index = common.integer(row["search_index"], "search_index", SEARCHES - 1)
        common.require(current["searches"] and index == len(current["searches"]) - 1,
                       "verifier outside its actual search")
        search = current["searches"][index]
        order = len(search["verifiers"])
        common.require(search["status"] == "target-hit-unverified" and order < 2,
                       "duplicate verifier or verification without a winner")
        path = "reference" if (current["key"][1] + current["order"] + index + order) % 2 else "production"
        common.require(row["path"] == path and common.integer(row["invocation_order"], "verifier.order") == order,
                       "full verifier path/order changed")
        common.require(all(row[key] == search["winner"][key] for key in ("challenge", "proof_sha256")),
                       "verifier did not use exact actual winner")
        outcome = row["outcome"]
        common.require(type(outcome) is str and 0 < len(outcome) <= 128, "invalid native verdict")
        if outcome != "Accepted":
            self.alerts.append({"class": current["key"][0], "sample": current["key"][1],
                "arm": current["key"][2], "search_index": index, "path": path, "outcome": outcome})
        search["verifiers"].append({"path": path, "outcome": outcome,
                                    "timing": measured(row["timing"], "verifier.timing")})

    def add_candidate(self, row):
        self.close_current()
        key = self.context(row)
        index = common.integer(row["search_index"], "search_index", SEARCHES - 1)
        identity = key + (index,)
        common.require(self.group == key and self.current["order"] == len(ARMS) - 1
                       and identity not in self.candidates and index in self.streams,
                       "candidate before complete arms or duplicate")
        canonical = self.streams[index]
        common.require(canonical["status"] == "target-hit-unverified", "candidate for exhausted search")
        last = canonical["last"]
        proof = common.hex_bytes(row["proof_hex"], common.PROOF_BYTES, "candidate.proof")
        expected = self.materials[key[0]][3] + bytes.fromhex(last["trace"])
        common.require(proof == expected and row["proof_sha256"] == common.sha(proof) == last["proof_sha256"]
                       and row["challenge"] == last["challenge"], "candidate complete bytes/challenge mismatch")
        self.candidates[identity] = row["proof_sha256"]

    def add_end(self, row):
        self.close_current()
        self.close_group()
        common.require(row["complete"] is True, "native campaign incomplete")
        for kind in ("material", "cohort", "search", "candidate", "verifier"):
            common.require(common.integer(row[kind + "_count"], kind + "_count") == self.counts[kind],
                           "end count mismatch: " + kind)
        common.require(self.counts["material"] == len(CLASSES) and self.counts["cohort"] == COHORTS
                       and self.counts["search"] == SEARCH_COUNT, "fixed 13-arm/9-class reuse grid incomplete")
        common.require(self.counts["verifier"] > 0, "no completed native winner verification")
        self.ended = True


def summary(records):
    rows, selected = [], []
    for name in CLASSES:
        comparable = {}
        for arm in ARMS:
            cohorts = [records.cohorts[name, sample, arm] for sample in range(SAMPLES)]
            searches = [search for cohort in cohorts for search in cohort["searches"]]
            wins = sum(search["status"] == "target-hit-unverified" for search in searches)
            eligible = common.supported(arm, name) and wins == SAMPLES * SEARCHES and all(
                verifier["outcome"] == "Accepted" for search in searches for verifier in search["verifiers"])
            totals = {axis: sum(cohort["total"][axis] for cohort in cohorts) for axis in ("cpu_ns", "wall_ns")}
            if eligible:
                comparable[arm] = totals["cpu_ns"]
            rows.append({"class": name, "arm": arm, "supported": common.supported(arm, name),
                "actual_setup_calls": len(cohorts), "actual_searches": len(searches), "actual_winners": wins,
                "attempts": sum(search["attempt_count"] for search in searches),
                "exhausted_searches": len(searches) - wins,
                "setup": {axis: sum(cohort["setup"][axis] for cohort in cohorts) for axis in totals},
                "search": {axis: sum(search["timing"][axis] for search in searches) for axis in totals},
                "inclusive_cohort_total": totals,
                "verification": {path: {axis: sum(verifier["timing"][axis] for search in searches
                    for verifier in search["verifiers"] if verifier["path"] == path) for axis in totals}
                    for path in ("production", "reference")},
                "eligible_for_observed_fixed_cohort_comparison": eligible})
        complete = len(comparable) == sum(common.supported(arm, name) for arm in ARMS)
        arm = min(comparable, key=comparable.get) if complete and comparable else None
        selected.append({"class": name, "all_supported_arms_measured": complete,
            "lowest_observed_supplied_cohort_arm": arm,
            "actual_eight_cohorts_cpu_ns": comparable.get(arm),
            "selection_scope": "one-supplied-algorithm-for-all-eight-four-search-cohorts-not-per-search-or-adversarial-lower-bound"})
    return rows, selected


def analyze(path):
    path = Path(path)
    common.require(path.is_file() and not path.is_symlink(), "regular retained JSONL required")
    records, digest, size, number = Records(), hashlib.sha256(), 0, 0
    with path.open("rb") as source:
        while True:
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            size += len(line)
            number += 1
            common.require(len(line) <= MAX_LINE and line.endswith(b"\n") and size <= MAX_BYTES
                           and number <= MAX_RECORDS, "bounded complete JSONL required")
            digest.update(line)
            try:
                records.add(common.decode(line))
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ValueError(f"line {number}: {error}") from error
    common.require(records.ended, "missing complete end record")
    rows, selected = summary(records)
    return {"schema": "pon-w1-reused-cost-observation-report-v3", "record_consistency": "PASS",
        "input_sha256": digest.hexdigest(), "input_bytes": size, "record_counts": dict(records.counts),
        "semantic_alerts": records.alerts, "actual_reuse_cohorts": rows, "fixed_cohort_comparison": selected,
        "setup_reuse_observation": "actual-one-preparation-four-independent-searches",
        "modeled_setup_division_used": False, "matrix_product_reconstructed": True,
        "w1_transcript_replayed": False, "source_applicability_verified": False,
        "independent_verification": False, "fresh_measurement": False,
        "limitations": ["Native source, execution, clocks and verifier verdicts require separate provenance.",
            "Each sample performs one actual setup and four searches; there is no modeled 1/8/64-winner division.",
            "Candidate bytes and hashes are reconstructed; this Python reader does not replay W1 transcripts.",
            "Fixed diagnostic inputs and supplied algorithms do not bound adversarial hardware or implementations.",
            "Material generation is measured once separately; service admission, lease/eligibility, M06, storage and queues are unmeasured.",
            "No public-network, resource-fairness, work-hardness or production acceptance follows."], **FALSE_FLAGS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        report = analyze(args.input)
    except (OSError, ValueError, OverflowError) as error:
        print(json.dumps({"record_consistency": "FAIL", "error": str(error), **FALSE_FLAGS}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if report["semantic_alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
