#!/usr/bin/env python3
"""Validate actual false-trace reuse records without certifying native execution.

Exit 0 means a complete consistent capture; 1 retains a native-verdict alert;
2 means malformed/incomplete records. No exit qualifies W1 or public service.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import pon_w1_cost_matrix_reader as common

SCHEMA = "pon-w1-false-trace-actual-reuse-v1"
SELECTOR = "--false-trace-actual-reuse-v1"
SAMPLES, SEARCHES, ATTEMPT_BUDGET = 8, 4, 4096
CLASSES, TARGET = common.CLASSES, common.TARGET
PATHS = ("production", "reference", "limb", "column-limb-experimental")
FULL_LIMB_SCHEMA = "pon-w1-false-trace-full-limb-v1"
FULL_LIMB_SELECTOR = "--false-trace-full-limb-v1"
FULL_LIMB_PATHS = PATHS + ("full-limb-experimental",)
MAX_LINE, MAX_BYTES = 8 * 1024 * 1024, 192 * 1024 * 1024
COHORTS = len(CLASSES) * SAMPLES
SEARCH_COUNT = COHORTS * SEARCHES
MAX_RECORDS = 2 + len(CLASSES) + COHORTS + SEARCH_COUNT * (2 + len(PATHS))
FALSE_FLAGS = dict.fromkeys(("valid_proof_acquisition_used", "hardness_accepted",
    "work_profile_qualified", "resource_fairness_qualified", "independent_hardware_qualified",
    "public_network_ready", "public_service_measured", "production_activation"), False)
SETUP_SCOPE = "one-public-prefix-four-independent-false-trace-searches"
ATTACK_SCOPE = "actual-prefix-setup-and-all-searches-including-challenge-hashes-trial-retention-and-winner-clone"
VERIFY_SCOPE = "native-full-verification-call-only-no-fact-cache"
FIELDS = {
    "campaign": "selector samples searches_per_setup attempt_budget seed target paths classes clock material_setup setup_reuse attacker_timing_scope verifier_timing_scope " + " ".join(FALSE_FLAGS),
    "material": "class source task a_hex b_hex",
    "cohort": "class sample task target setup_calls searches setup total",
    "search": "class sample search_index task target setup_calls timing status attempts winner",
    "candidate": "class sample search_index task target challenge proof_hex proof_sha256",
    "verifier": "class sample search_index task target path invocation_order challenge proof_sha256 outcome timing",
    "end": "material_count cohort_count search_count candidate_count verifier_count complete",
}


def challenge(task, sample, search):
    return common.pon_hash(b"pon-w1-false-trace-reuse-challenge-v1", task, bytes(8),
        sample.to_bytes(8, "little"), search.to_bytes(8, "little"))


def measured(value, label):
    common.timing(value, label)
    for axis in ("cpu_ns", "wall_ns"):
        common.require(type(value[axis]) is int and value[axis] > 0,
                       label + ": positive actual CPU/wall required; unknown is not zero")
    return value


class Records:
    def __init__(self, *, full_limb=False):
        common.require(type(full_limb) is bool, "explicit comparison mode must be boolean")
        self.schema = FULL_LIMB_SCHEMA if full_limb else SCHEMA
        self.selector = FULL_LIMB_SELECTOR if full_limb else SELECTOR
        self.paths = FULL_LIMB_PATHS if full_limb else PATHS
        self.max_records = 2 + len(CLASSES) + COHORTS + SEARCH_COUNT * (2 + len(self.paths))
        self.counts = Counter()
        self.materials, self.cohorts = {}, {}
        self.current, self.campaign, self.ended = None, None, False
        self.alerts = []

    def context(self, row):
        name = row["class"]
        common.require(type(name) is str and name in self.materials, "class/material unavailable")
        sample = common.integer(row["sample"], "sample", SAMPLES - 1)
        common.require(row["task"] == self.materials[name][2].hex() and row["target"] == TARGET,
                       "task/target mismatch")
        return name, sample

    def same_current(self, row):
        common.require(self.current is not None and self.context(row) == self.current["key"],
                       "record outside current actual cohort")
        return self.current

    def last_search(self, row):
        current = self.same_current(row)
        index = common.integer(row["search_index"], "search_index", SEARCHES - 1)
        common.require(current["searches"] and index == len(current["searches"]) - 1,
                       "candidate/verifier outside current search")
        return current["searches"][-1]

    def close_search(self):
        if self.current is None or not self.current["searches"]:
            return
        search = self.current["searches"][-1]
        won = search["status"] == "target-hit-unverified"
        common.require((search["candidate"] is not None) == won,
                       "complete forged winner bytes missing or fictitious candidate")
        common.require(len(search["verifiers"]) == (len(self.paths) if won else 0),
                       "full native verifier coverage incomplete")

    def close_current(self):
        if self.current is None:
            return
        self.close_search()
        current = self.current
        common.require(len(current["searches"]) == SEARCHES, "actual search coverage incomplete")
        for axis in ("cpu_ns", "wall_ns"):
            subtotal = current["setup"][axis] + sum(item["timing"][axis] for item in current["searches"])
            common.require(current["total"][axis] >= subtotal, "actual phases exceed inclusive cohort total")

    def add(self, row):
        common.require(not self.ended, "records after complete end")
        common.require(type(row) is dict and row.get("schema") == self.schema, "explicit false-reuse V1 schema required")
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
        common.require(row["selector"] == self.selector and row["paths"] == list(self.paths)
                       and row["classes"] == list(CLASSES) and row["target"] == TARGET,
                       "fixed selector/verifier/material/target grid changed")
        common.require(row["clock"] == "thread-cpu-and-monotonic-wall-ns"
                       and row["setup_reuse"] == SETUP_SCOPE, "one actual public-prefix reuse required")
        common.require(row["attacker_timing_scope"] == ATTACK_SCOPE
                       and row["verifier_timing_scope"] == VERIFY_SCOPE, "measurement scope changed")
        for flag in FALSE_FLAGS:
            common.require(row[flag] is False, "observation cannot acquire proof/qualification: " + flag)
        measured(row["material_setup"], "material_setup")
        self.campaign = row

    def add_material(self, row):
        self.close_current()
        index = len(self.materials)
        common.require(index < len(CLASSES) and row["class"] == CLASSES[index]
                       and self.counts["cohort"] == index * SAMPLES, "material coverage/order incomplete")
        name = row["class"]
        a, b, task, _ = common.material(name)
        source = "hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture"
        common.require(row["source"] == source and row["task"] == task.hex(), "material source/task mismatch")
        common.require(common.hex_bytes(row["a_hex"], common.CELLS * 4, "A") == a
                       and common.hex_bytes(row["b_hex"], common.CELLS * 4, "B") == b,
                       "diagnostic matrix recipe mismatch")
        # The attack never computes C or obtains an honest transcript.
        prefix = b"PNW1" + a + b + bytes(common.CELLS * 4)
        self.materials[name] = a, b, task, prefix

    def add_cohort(self, row):
        self.close_current()
        class_index, sample = divmod(self.counts["cohort"], SAMPLES)
        key = self.context(row)
        common.require(class_index < len(CLASSES) and key == (CLASSES[class_index], sample),
                       "fixed cohort coverage/order incomplete")
        common.require(common.integer(row["setup_calls"], "setup_calls") == 1,
                       "one actual public-prefix setup required")
        common.require(common.integer(row["searches"], "searches") == SEARCHES, "fixed actual reuse count changed")
        current = {"key": key, "searches": [], "setup": measured(row["setup"], "cohort.setup"),
                   "total": measured(row["total"], "cohort.total")}
        self.cohorts[key] = self.current = current

    def add_search(self, row):
        self.close_search()
        current = self.same_current(row)
        index = common.integer(row["search_index"], "search_index", SEARCHES - 1)
        common.require(index == len(current["searches"]), "independent search coverage/order incomplete")
        common.require(common.integer(row["setup_calls"], "search.setup_calls") == 0,
                       "public prefix rebuilt inside search")
        name, sample = current["key"]
        _, _, task, prefix = self.materials[name]
        context = challenge(task, sample, index)
        stream, last = common._trials(row, task, sample, prefix, context=context)
        if row["status"] == "target-hit-unverified":
            proof = prefix + bytes.fromhex(last["trace"])
            expected = {"challenge": context.hex(), "proof_sha256": common.sha(proof)}
            common.exact(row["winner"], expected, "search.winner")
            common.require(row["winner"] == expected, "winner does not bind full forged bytes")
        else:
            proof = None
            common.require(row["winner"] is None, "exhaustion cannot invent a winner")
        current["searches"].append({"index": index, "status": row["status"],
            "context": context, "proof": proof, "attempt_count": len(stream),
            "timing": measured(row["timing"], "search.timing"), "candidate": None, "verifiers": []})

    def add_candidate(self, row):
        search = self.last_search(row)
        common.require(search["proof"] is not None and search["candidate"] is None,
                       "duplicate or fictitious complete candidate")
        common.require(row["challenge"] == search["context"].hex()
                       and common.hex_bytes(row["proof_hex"], common.PROOF_BYTES, "proof") == search["proof"]
                       and row["proof_sha256"] == common.sha(search["proof"]),
                       "complete forged bytes/challenge/hash mismatch")
        search["candidate"] = row["proof_sha256"]

    def add_verifier(self, row):
        search = self.last_search(row)
        common.require(search["candidate"] is not None, "verifier requires complete forged bytes")
        order = len(search["verifiers"])
        common.require(order < len(self.paths) and common.integer(row["invocation_order"], "order") == order,
                       "verifier order/coverage mismatch")
        _, sample = self.current["key"]
        expected = self.paths[(sample + search["index"] + order) % len(self.paths)]
        common.require(row["path"] == expected and row["challenge"] == search["context"].hex()
                       and row["proof_sha256"] == search["candidate"], "verifier identity/rotation mismatch")
        common.require(type(row["outcome"]) is str and row["outcome"] in (
            "Accepted", "AcceptedWrongProduct", "Length", "Version", "Field", "Task", "Target", "Transcript", "Product", "NoiseBudget"),
            "unknown native verifier outcome")
        measured(row["timing"], "verifier.timing")
        search["verifiers"].append(row)
        if row["outcome"] != "Transcript":
            self.alerts.append({"class": row["class"], "sample": sample, "search_index": search["index"],
                "path": row["path"], "expected": "Transcript", "actual": row["outcome"]})

    def add_end(self, row):
        self.close_current()
        common.require(len(self.materials) == len(CLASSES) and len(self.cohorts) == COHORTS
                       and self.counts["search"] == SEARCH_COUNT, "fixed actual-reuse grid incomplete")
        for kind in ("material", "cohort", "search", "candidate", "verifier"):
            common.require(common.integer(row[kind + "_count"], kind + "_count") == self.counts[kind],
                           "complete count mismatch: " + kind)
        common.require(row["complete"] is True and self.counts["candidate"] > 0,
                       "nonzero completed native rejection observation required")
        common.require(self.counts["verifier"] == self.counts["candidate"] * len(self.paths),
                       "full native verifier grid incomplete")
        self.ended = True


def summary(records):
    rows = []
    for name in CLASSES:
        cohorts = [records.cohorts[name, sample] for sample in range(SAMPLES)]
        searches = [search for cohort in cohorts for search in cohort["searches"]]
        wins = sum(search["status"] == "target-hit-unverified" for search in searches)
        totals = {axis: sum(cohort["total"][axis] for cohort in cohorts) for axis in ("cpu_ns", "wall_ns")}
        verifiers = {path: [v for search in searches for v in search["verifiers"] if v["path"] == path] for path in records.paths}
        verification = {path: {axis: sum(v["timing"][axis] for v in values) for axis in totals}
                        for path, values in verifiers.items()}
        rows.append({"class": name, "actual_setup_calls": len(cohorts), "actual_searches": len(searches),
            "actual_candidates": wins, "exhausted_searches": len(searches) - wins,
            "attempts": sum(search["attempt_count"] for search in searches),
            "setup": {axis: sum(cohort["setup"][axis] for cohort in cohorts) for axis in totals},
            "search": {axis: sum(search["timing"][axis] for search in searches) for axis in totals},
            "full_attacker_cohort_total": totals, "verification": verification,
            "receiver_rejection_cpu_over_full_attacker_cpu": {
                path: verification[path]["cpu_ns"] / totals["cpu_ns"]
                if wins and all(v["outcome"] == "Transcript" for v in values) else None
                for path, values in verifiers.items()},
            "outcome_counts": {path: dict(Counter(v["outcome"] for v in values)) for path, values in verifiers.items()}})
    return rows


def analyze(path, *, full_limb=False):
    path = Path(path)
    common.require(path.is_file() and not path.is_symlink(), "regular retained JSONL required")
    records, digest, size, number = Records(full_limb=full_limb), hashlib.sha256(), 0, 0
    with path.open("rb") as source:
        while True:
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            size += len(line)
            number += 1
            common.require(len(line) <= MAX_LINE and line.endswith(b"\n") and size <= MAX_BYTES
                           and number <= records.max_records, "bounded complete JSONL required")
            digest.update(line)
            try:
                records.add(common.decode(line))
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ValueError(f"line {number}: {error}") from error
    common.require(records.ended, "missing complete end record")
    return {"schema": "pon-w1-full-limb-reuse-observation-report-v1" if full_limb else "pon-w1-false-trace-reuse-observation-report-v1", "record_consistency": "PASS",
        "input_sha256": digest.hexdigest(), "input_bytes": size, "record_counts": dict(records.counts),
        "semantic_alerts": records.alerts, "actual_reuse_cohorts": summary(records),
        "modeled_setup_division_used": False, "complete_attack_bytes_reconstructed": True,
        "w1_transcript_replayed": False, "source_applicability_verified": False,
        "independent_verification": False, "fresh_measurement": False,
        "fastest_adversary_lower_bound": False, "public_attack_amplification_measured": False,
        "limitations": ["Native source, execution, clocks and verdicts need separate provenance.",
            "These are actual four-search cohorts, with setup, misses and winning-buffer clone charged in full.",
            "Trial hex/retention overhead is included but is not a necessary cost of a network attacker.",
            "The interval excludes separate material generation, later buffer destruction, JSONL evidence output and network sending.",
            "Hash midstate reuse, different horizons and adversarial implementations/hardware may cost less.",
            "Microbenchmark challenges do not certify live parent/lease/beneficiary binding or public admission.",
            "No service queues, signed transport, storage, network fanout or model utility are measured.",
            "Experimental column-limb and full-limb observations do not change the default production verifier."], **FALSE_FLAGS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--full-limb", action="store_true")
    args = parser.parse_args()
    try:
        report = analyze(args.input, full_limb=args.full_limb)
    except (OSError, ValueError, OverflowError) as error:
        print(json.dumps({"record_consistency": "FAIL", "error": str(error), **FALSE_FLAGS}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if report["semantic_alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
