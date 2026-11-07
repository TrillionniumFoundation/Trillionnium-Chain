#!/usr/bin/env python3
"""Read the fixed paid-rank/batch experiment, retaining every physical attempt.

This reconstructs canonical AB/proof commitments and complete declared ledgers.
It does not replay W1, authenticate native execution or clocks, or qualify work.
Correlated horizons and speculative target hits are never independent winners.
"""
import argparse
from collections import Counter
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
import pon_w1_cost_matrix_reader as common
from pon_w1_preparation_strategy_reader_v4 import material_from_bytes, product_last

SCHEMA = "pon-w1-rank-batch-v5"
SELECTOR = "--rank-batch-v5"
CLASSES = ("zero", "rank-one", "rank-two-left", "rank-four-left", "rank-eight-left",
    "rank-four-right", "rank-nine-left", "full-rank-field", "sparse-diagonal",
    "one-zero-rank-one", "continuity-maintenance-v1")
STRATEGIES = ("full-limb-dense-lazy", "full-limb-sparse-lazy", "full-limb-rank8-lazy",
    "full-limb-rank8-batch4-lazy", *common.ARMS)
TARGETS = ("7f" + "ff" * 31, "07" + "ff" * 31, "00" * 31 + "01", "ff" * 32)
PURPOSES = ("search-cost", "search-cost", "exhaustion-control", "first-hit-control")
HORIZONS, SAMPLES, LIMIT, BATCH = (1, 8), 8, 4096, 4
MAX_LINE, MAX_BYTES = 8 * 1024 * 1024, 4 * 1024 * 1024 * 1024
STATIC = {
    "horizons": list(HORIZONS), "classes": list(CLASSES), "strategies": list(STRATEGIES),
    "samples": SAMPLES, "batch_workers": BATCH, "rank_bound": 8,
    "rank_probe_order": "left-then-right-then-explicit-dense-fallback",
    "complete_trace_tiles": 512, "clock": "process-cpu-and-monotonic-wall",
    "producer_clock_includes_threads": True,
    "worker_policy": "fixed-at-most-four-scoped-workers-per-batch-join-all-in-nonce-order",
    "batch_winner_policy": "first-hit-in-declared-nonce-order-after-completing-entire-batch",
    "post_winner_attempts_charged": True,
    "producer_cost": "paid-setup-plus-complete-attempts-including-misses-speculation-thread-spawn-join-all-proof-buffer-disposal-and-task-teardown",
    "observation_cost": "separate-full-proof-identity-digest-and-JSON-value-work-including-losing-attempts",
    "verification_cost": "separate-both-winner-verifiers-product-mutants-and-both-replays-of-every-post-winner-attempt",
    "reuse_scope": "same-fixed-A-B-preparation-only-no-cross-challenge-trace-cache",
    "horizon_prefixes_correlated": True, "sampling_rotation": "strategy=(position+sample)%17",
    "feature_provenance_verified": False, "consensus_default_changed": False,
    "cheapest_strategy_proven": False, "activation": False,
}
FIELDS = {
    "header": "class target_index target horizon purpose attempt_limit task a_hex b_hex c_hex rank_a rank_b material_setup reference_setup material_source ideal_uniform_ticket_probability_assumption " + " ".join(STATIC),
    "cohort": "sample position strategy_index strategy setup_calls supported setup selection searches_planned",
    "search": "sample strategy_index search_index setup_calls batch_width batches attempt_count complete errors first_hit_nonce speculative_attempts proof_buffers producer observation disposal attempts",
    "verifier": "sample strategy_index search_index nonce path case target challenge proof_sha256 result timing",
    "search-cleanup": "sample strategy_index search_index scope timing",
    "cohort-end": "sample strategy_index teardown total",
    "footer": "setup_calls unsupported_setups search_count attempt_count hit_count miss_count exhausted_searches speculative_attempts proof_buffers verifier_calls all_declared_cohorts_completed status activation",
}
ATTEMPT_FIELDS = "nonce challenge trace ticket target_hit proof_materialized proof_sha256 after_first_hit complete".split()
COUNTERS = "setup_calls unsupported_setups search_count attempt_count hit_count miss_count exhausted_searches speculative_attempts proof_buffers verifier_calls".split()
FALSE_FLAGS = dict.fromkeys(("source_execution_authenticated", "clock_authenticated", "independent_w1_replay",
    "feature_provenance_verified", "cheapest_strategy_proven", "work_profile_qualified", "public_service_qualified",
    "cross_architecture_qualified", "production_activation"), False)


def fixed(value, expected, label):
    common.require(type(value) is type(expected) and value == expected, label + ": fixed declaration changed")
    if type(expected) is dict:
        for key in expected:
            fixed(value[key], expected[key], label + "." + key)
    elif type(expected) in (list, tuple):
        for position, item in enumerate(expected):
            fixed(value[position], item, label + f"[{position}]")


def timing(value, label):
    common.timing(value, label)
    common.require(value["wall_ns"] is not None, label + ": monotonic wall observation required")
    return value


def positive_timing(value, label):
    timing(value, label)
    common.require(value["wall_ns"] > 0 and (value["cpu_ns"] is None or value["cpu_ns"] > 0),
        label + ": actual nonempty work cannot have a zero clock charge")
    return value


def add_times(values):
    return {axis: (sum(v[axis] for v in values) if all(v[axis] is not None for v in values) else None)
        for axis in ("cpu_ns", "wall_ns")}


def challenge(task, target, sample, search, nonce):
    return common.pon_hash(b"pon-w1-rank-batch-challenge-v5", task, target,
        sample.to_bytes(8, "little"), search.to_bytes(8, "little"), nonce.to_bytes(8, "little"))


def ranked(rank, shift):
    n, q = common.N, common.Q
    left = [[int(i == k) if i < rank else (q - 1 - i * 101 - k * 17) % q
        for k in range(rank)] for i in range(n)]
    right = [[int(j == k) if j < rank else (q - 1 - j * 73 - k * 31) % q
        for j in range(n)] for k in range(rank)]
    return [sum(left[(i + shift) % n][k] * right[k][(j + 2 * shift) % n]
        for k in range(rank)) % q for i in range(n) for j in range(n)]


@lru_cache(maxsize=len(CLASSES))
def material(name):
    common.require(name in CLASSES, "unknown material class")
    if name in common.CLASSES:
        a, b, task, prefix = common.material(name)
        source = "hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture"
    else:
        dense_a, dense_b, _, _ = common.material("full-rank-field")
        if name == "one-zero-rank-one":
            a, b = struct.pack("<4096I", *ranked(1, 7)), bytes(common.CELLS * 4)
        elif name == "rank-four-right":
            a, b = dense_a, struct.pack("<4096I", *ranked(4, 11))
        else:
            rank = {"rank-two-left": 2, "rank-four-left": 4, "rank-eight-left": 8, "rank-nine-left": 9}[name]
            a, b = struct.pack("<4096I", *ranked(rank, 7)), dense_b
        _, _, task, prefix = material_from_bytes(a, b)
        source = "synthetic-exact-rank-fixture"
    ranks = tuple(common._rank(struct.unpack("<4096I", raw)) for raw in (a, b))
    return a, b, task, prefix, ranks, source


def supported(index, name):
    if index < 4:
        return True
    legacy_name = "one-zero-right-rank-one" if name == "one-zero-rank-one" else name
    return common.supported(STRATEGIES[index], legacy_name)


def selection(index, ranks, applicable):
    if not applicable:
        return None
    if index >= 4:
        return {"preparation_used": "existing-legacy-constructor", "rank_bound": None}
    if index < 2:
        return {"preparation_used": ("dense", "sparse")[index], "rank_bound": None}
    left, right = ranks
    if left <= 8:
        return {"preparation_used": "left-low-rank", "rank_bound": 8, "rank": left,
            "right_probe": False, "dense_fallback": False}
    if right <= 8:
        return {"preparation_used": "right-low-rank", "rank_bound": 8, "rank": right,
            "left_above_bound": True, "right_probe": True, "dense_fallback": False}
    return {"preparation_used": "dense-after-two-rank-probes", "rank_bound": 8,
        "left_above_bound": True, "right_above_bound": True, "dense_fallback": True}


class Records:
    def __init__(self):
        self.header = self.current = self.current_search = None
        self.ended = False
        self.counts, self.kinds = Counter(dict.fromkeys(COUNTERS, 0)), Counter()
        self.cohorts, self.canonical = [], {}
        self.prefix_digests = {}

    def same(self, row, search=False):
        common.require(self.current is not None, "record outside cohort")
        for key in ("sample", "strategy_index"):
            common.require(common.integer(row[key], key) == self.current[key], "cohort identity/order changed")
        if search:
            common.require(self.current_search is not None and
                common.integer(row["search_index"], "search index") == self.current_search["search_index"], "search identity/order changed")

    def close_search(self):
        if self.current_search is not None:
            s = self.current_search
            common.require(s["cleanup"] is not None and s["verifier_position"] == len(s["expected_verifiers"]),
                "missing cleanup or winner/mutant/post-winner verification")
            self.current_search = None

    def add(self, row):
        common.require(not self.ended and type(row) is dict and row.get("schema") == SCHEMA, "schema/end boundary")
        kind = row.get("kind")
        common.require(type(kind) is str and kind in FIELDS, "unknown record kind")
        common.exact(row, {"schema", "kind", *FIELDS[kind].split()}, kind)
        common.require(self.header is not None or kind == "header", "header must be first")
        getattr(self, "add_" + kind.replace("-", "_"))(row)
        self.kinds[kind] += 1

    def add_header(self, row):
        common.require(self.header is None, "duplicate header")
        common.require(type(row["class"]) is str and row["class"] in CLASSES, "fixed class required")
        index = common.integer(row["target_index"], "target index", 3)
        fixed(row["target"], TARGETS[index], "target")
        common.require(type(row["horizon"]) is int and row["horizon"] in HORIZONS and
            (index < 2 or row["horizon"] == 1), "fixed actual reuse horizon")
        fixed(row["purpose"], PURPOSES[index], "purpose")
        fixed(row["attempt_limit"], LIMIT if index < 2 else 3, "attempt limit")
        for key, expected in STATIC.items():
            fixed(row[key], expected, key)
        fixed(row["ideal_uniform_ticket_probability_assumption"], ("1/2", "1/32", None, None)[index], "probability assumption")
        a, b, self.task, self.prefix, ranks, source = material(row["class"])
        for key, expected in (("a_hex", a.hex()), ("b_hex", b.hex()), ("c_hex", self.prefix[4 + 8 * common.CELLS:].hex()),
                ("task", self.task.hex()), ("rank_a", ranks[0]), ("rank_b", ranks[1]), ("material_source", source)):
            fixed(row[key], expected, key)
        positive_timing(row["material_setup"], "material setup")
        positive_timing(row["reference_setup"], "reference setup")
        self.header = row

    def add_cohort(self, row):
        common.require(self.current is None, "unclosed previous cohort")
        sample, position = divmod(self.kinds["cohort"], len(STRATEGIES))
        index = (position + sample) % len(STRATEGIES)
        common.require(sample < SAMPLES, "too many cohorts")
        applicable = supported(index, self.header["class"])
        expected = {"sample": sample, "position": position, "strategy_index": index,
            "strategy": STRATEGIES[index], "setup_calls": 1, "supported": applicable,
            "searches_planned": self.header["horizon"] if applicable else 0,
            "selection": selection(index, (self.header["rank_a"], self.header["rank_b"]), applicable)}
        for key, value in expected.items():
            fixed(row[key], value, key)
        positive_timing(row["setup"], "paid setup")
        self.counts["setup_calls"] += 1
        self.counts["unsupported_setups"] += not applicable
        self.current = {**row, "searches": [], "verifier_timings": []}

    def add_search(self, row):
        self.close_search()
        self.same(row)
        c, h = self.current, self.header
        common.require(c["supported"], "unsupported producer searched")
        search_index = len(c["searches"])
        index, sample = c["strategy_index"], c["sample"]
        common.require(search_index < h["horizon"], "too many reused searches")
        fixed(row["search_index"], search_index, "search index")
        fixed(row["setup_calls"], 0, "duplicate/free preparation")
        fixed(row["complete"], True, "partial/failed native search retained but not accepted")
        fixed(row["errors"], 0, "failed native attempt")
        width = BATCH if index == 3 else 1
        fixed(row["batch_width"], width, "batch width")
        attempts = row["attempts"]
        common.require(type(attempts) is list and 0 < len(attempts) <= h["attempt_limit"], "complete bounded attempts required")
        fixed(row["attempt_count"], len(attempts), "attempt count")
        fixed(row["batches"], (len(attempts) + width - 1) // width, "batch count")
        target = bytes.fromhex(h["target"])
        first, buffers, signature = None, 0, []
        for nonce, trial in enumerate(attempts):
            common.exact(trial, ATTEMPT_FIELDS, "attempt")
            fixed(trial["nonce"], nonce, "consecutive nonce")
            fixed(trial["complete"], True, "incomplete transcript")
            context = challenge(self.task, target, sample, search_index, nonce)
            fixed(trial["challenge"], context.hex(), "challenge recipe")
            trace = common.hex_bytes(trial["trace"], 32, "trace")
            ticket = common.pon_hash(b"ticket", context, trace)
            fixed(trial["ticket"], ticket.hex(), "ticket")
            hit = ticket <= target
            fixed(trial["target_hit"], hit, "target hit")
            if hit and first is None:
                first = nonce
            after = first is not None and nonce > first
            fixed(trial["after_first_hit"], after, "post-winner accounting")
            materialized = index >= 4 or hit
            fixed(trial["proof_materialized"], materialized, "materialization policy")
            buffers += materialized
            fixed(trial["proof_sha256"], common.sha(self.prefix + trace), "complete proof digest")
            if not after:
                signature.append((nonce, trial["challenge"], trial["trace"], trial["ticket"], trial["proof_sha256"], hit))
            self.counts["hit_count" if hit else "miss_count"] += 1
        expected_attempts = h["attempt_limit"] if first is None else min(h["attempt_limit"], ((first // width) + 1) * width)
        fixed(len(attempts), expected_attempts, "omitted speculation/exhaustion or work after batch stop")
        fixed(row["first_hit_nonce"], first, "first ordered winner")
        speculative = 0 if first is None else len(attempts) - first - 1
        fixed(row["speculative_attempts"], speculative, "speculative count")
        fixed(row["proof_buffers"], buffers, "all materialized buffer count")
        signature = tuple(signature)
        key = sample, search_index
        if key in self.canonical:
            common.require(self.canonical[key] == signature, "complete logical search differs between legal producers")
        else:
            self.canonical[key] = signature
        self.prefix_digests[f"{sample}:{index}:{search_index}"] = common.sha(json.dumps(signature, separators=(",", ":")).encode())
        expected_verifiers = []
        if first is not None:
            expected_verifiers.extend((case, path, first) for case in ("winner", "product-last") for path in ("production", "reference"))
            expected_verifiers.extend(("post-winner-full-replay", path, nonce) for nonce in range(first + 1, len(attempts))
                for path in ("production", "reference"))
        s = {**row, "expected_verifiers": expected_verifiers, "verifier_position": 0, "cleanup": None}
        for phase in ("producer", "observation", "disposal"):
            timing(s[phase], phase)
        positive_timing(s["producer"], "complete attempt work")
        c["searches"].append(s)
        self.current_search = s
        for name, value in (("search_count", 1), ("attempt_count", len(attempts)), ("exhausted_searches", first is None),
                ("speculative_attempts", speculative), ("proof_buffers", buffers)):
            self.counts[name] += value

    def add_verifier(self, row):
        self.same(row, search=True)
        s = self.current_search
        common.require(s["cleanup"] is None and s["verifier_position"] < len(s["expected_verifiers"]), "unexpected verifier")
        case, path, nonce = s["expected_verifiers"][s["verifier_position"]]
        trial = s["attempts"][nonce]
        proof = self.prefix + bytes.fromhex(trial["trace"])
        if case == "product-last":
            proof = product_last(proof)
        expected = {"case": case, "path": path, "nonce": nonce, "challenge": trial["challenge"],
            "target": TARGETS[3] if case == "post-winner-full-replay" else self.header["target"],
            "proof_sha256": common.sha(proof), "result": "Product" if case == "product-last" else "ACCEPT"}
        for key, value in expected.items():
            fixed(row[key], value, "verifier " + key)
        positive_timing(row["timing"], "native verification")
        self.current["verifier_timings"].append(row["timing"])
        s["verifier_position"] += 1
        self.counts["verifier_calls"] += 1

    def add_search_cleanup(self, row):
        self.same(row, search=True)
        s = self.current_search
        common.require(s["cleanup"] is None and s["verifier_position"] == len(s["expected_verifiers"]), "cleanup before full verification or duplicate")
        fixed(row["scope"], "winning-proof-buffer-only", "cleanup scope")
        s["cleanup"] = timing(row["timing"], "winning proof cleanup")

    def add_cohort_end(self, row):
        self.same(row)
        self.close_search()
        c = self.current
        common.require(len(c["searches"]) == c["searches_planned"], "omitted declared searches")
        c["teardown"], c["total"] = timing(row["teardown"], "task teardown"), timing(row["total"], "inclusive cohort")
        producer_phases = [c["setup"], c["teardown"]]
        observations = []
        for s in c["searches"]:
            producer_phases.extend(s[phase] for phase in ("producer", "disposal", "cleanup"))
            observations.append(s["observation"])
        c["producer_total"] = add_times(producer_phases)
        c["observation_total"], c["verification_total"] = add_times(observations), add_times(c["verifier_timings"])
        charged = add_times([c["producer_total"], c["observation_total"], c["verification_total"]])
        for axis in ("cpu_ns", "wall_ns"):
            if charged[axis] is not None and c["total"][axis] is not None:
                common.require(c["total"][axis] >= charged[axis], "disjoint phases exceed inclusive cohort")
        self.cohorts.append(c)
        self.current = None

    def add_footer(self, row):
        common.require(self.current is None and len(self.cohorts) == SAMPLES * len(STRATEGIES), "incomplete cohort grid")
        for key in COUNTERS:
            fixed(row[key], self.counts[key], "footer " + key)
        fixed(row["all_declared_cohorts_completed"], True, "complete grid")
        fixed(row["status"], "COMPONENT_OBSERVATION", "status")
        fixed(row["activation"], False, "activation")
        self.ended = True

    def summary(self):
        common.require(self.ended, "truncated campaign; retained partial costs cannot become complete evidence")
        arms = []
        for index, name in enumerate(STRATEGIES):
            cohorts = [c for c in self.cohorts if c["strategy_index"] == index]
            searches = [s for c in cohorts for s in c["searches"]]
            wins = sum(s["first_hit_nonce"] is not None for s in searches)
            row = {"strategy": name, "strategy_index": index, "supported": cohorts[0]["supported"],
                "selection": cohorts[0]["selection"], "setups": len(cohorts), "searches": len(searches), "accepted_winners": wins,
                "physical_attempts": sum(s["attempt_count"] for s in searches), "speculative_attempts": sum(s["speculative_attempts"] for s in searches),
                "physical_hits": sum(sum(a["target_hit"] for a in s["attempts"]) for s in searches),
                "exhausted_searches": len(searches) - wins,
                "producer_total": add_times([c["producer_total"] for c in cohorts]),
                "paid_setup": add_times([c["setup"] for c in cohorts]),
                "observation_total": add_times([c["observation_total"] for c in cohorts]),
                "verification_total": add_times([c["verification_total"] for c in cohorts]),
                "inclusive_cohort": add_times([c["total"] for c in cohorts])}
            row["cpu_ns_per_accepted_winner"] = {"numerator": row["producer_total"]["cpu_ns"], "denominator": wins} if wins and row["producer_total"]["cpu_ns"] is not None else None
            arms.append(row)
        return {"schema": SCHEMA + "-readback", "status": "COMPLETE_COMPONENT_OBSERVATION",
            "class": self.header["class"], "target_index": self.header["target_index"], "horizon": self.header["horizon"],
            "purpose": self.header["purpose"], "task": self.header["task"], "counts": dict(self.counts),
            "material_setup": self.header["material_setup"], "reference_setup": self.header["reference_setup"],
            "arms": arms, "logical_prefix_sha256": self.prefix_digests,
            "aggregation": "ratio-of-sums-per-class-target-horizon-including-all-setups-failed-probes-misses-and-speculation",
            "cross_horizon_aggregation": "none-correlated-prefixes", "confidence_bound": None,
            "outer_process_costs_required": True, **FALSE_FLAGS}


def analyze(path):
    path = Path(path)
    records, total = Records(), 0
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as stream:
        while True:
            line = stream.readline(MAX_LINE + 1)
            if not line:
                break
            total += len(line)
            common.require(len(line) <= MAX_LINE and total <= MAX_BYTES and line.endswith(b"\n"), "bounded complete JSONL required")
            records.add(common.decode(line))
    return records.summary()


def grid():
    return [(name, target, horizon) for name in CLASSES for target in range(4)
        for horizon in (HORIZONS if target < 2 else (1,))]


def campaign(reports):
    common.require(type(reports) is list and len(reports) == len(grid()), "all 66 declared shards required, including controls")
    indexed = {}
    for report in reports:
        key = report["class"], report["target_index"], report["horizon"]
        common.require(key not in indexed and key in grid(), "duplicate/undeclared shard")
        indexed[key] = report
    common.require(set(indexed) == set(grid()), "incomplete declared grid")
    for name in CLASSES:
        for target in (0, 1):
            short, long = indexed[(name, target, 1)], indexed[(name, target, 8)]
            for key, value in short["logical_prefix_sha256"].items():
                common.require(long["logical_prefix_sha256"].get(key) == value, "correlated horizon changed search prefix")
    return {"schema": SCHEMA + "-campaign-readback", "status": "COMPLETE_COMPONENT_OBSERVATION",
        "shard_count": len(reports), "cost_shards": 44, "control_shards": 22,
        "total_counts": {key: sum(r["counts"].get(key, 0) for r in reports) for key in COUNTERS},
        "aggregation": "none-across-correlated-horizons-or-different-classes-targets",
        "reports": reports, **FALSE_FLAGS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="+", type=Path)
    parser.add_argument("--complete-grid", action="store_true")
    args = parser.parse_args()
    try:
        reports = [analyze(path) for path in args.input]
        result = campaign(reports) if args.complete_grid else reports[0] if len(reports) == 1 else reports
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "HOLD", "error": str(error), **FALSE_FLAGS}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
