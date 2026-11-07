#!/usr/bin/env python3
"""Strict complete-grid readback for factorial legal W1 producers.

This reconstructs bytes, matches all attempts and preserves native verdicts.
It does not replay W1, authenticate clocks or establish a cheapest strategy.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import pon_w1_cost_matrix_reader as common

SCHEMA = "pon-w1-legal-strategy-v3"
SELECTOR = "--legal-strategy-v3"
CLASSES = ("full-rank-field", "zero", "continuity-maintenance-v1",
           "one-zero-left-rank-one", "one-zero-right-rank-one")
TARGETS = ("7f" + "ff" * 31, "07" + "ff" * 31)
HORIZONS = (1, 8, 64)
SAMPLES, ATTEMPT_BUDGET = 8, 4096
STRATEGIES = ("eager-transposed", "lazy-transposed", "eager-full-limb", "lazy-full-limb")
ARITHMETIC = ("transposed", "transposed", "full-limb", "full-limb")
MATERIALIZATION = ("every-attempt", "target-hit", "every-attempt", "target-hit")
PATHS = ("production", "reference", "limb", "full-limb-experimental")
CASES = ("legal", "product-last")
FALSE_FLAGS = dict.fromkeys(("hardness_accepted", "work_profile_qualified",
    "resource_fairness_qualified", "public_service_measured", "independent_hardware_qualified",
    "public_network_ready", "production_activation"), False)
PRODUCER_SCOPE = "one-actual-setup-and-all-complete-transcripts-tickets-and-proof-materializations-including-misses-and-binary-trial-retention-excludes-evidence-digests-hex-json-verification-and-retained-buffer-destruction"
EVIDENCE_SCOPE = "complete-attempt-digests-and-json-value-construction-after-producer-timer-excludes-json-serialization-write-and-native-verification"
VERIFY_SCOPE = "native-full-verification-call-only-no-fact-cache"
MUTATION_SCOPE = "clone-and-canonical-last-product-word-increment-only-excludes-proof-hashing-json-and-verification"
RATE_SCOPE = {
    "observation": "finite-recorded-cohorts-at-one-fixed-strategy-class-target-and-reuse-horizon",
    "denominator": PRODUCER_SCOPE,
    "aggregation": "ratio-of-sums-including-every-setup-miss-exhaustion-and-materialization",
    "common_material_setup": "reported-once-per-shard-separately-not-added-to-each-strategy",
    "cross_horizon_aggregation": "none-shared-search-prefixes-are-not-independent",
    "work_equivalent": "recorded-relation-valid-target-hits-times-required-target-weight-not-ledger-chainwork",
    "native_chainwork_observed": False,
    "network_work_share": None,
    "confidence_bound": None,
}
# The largest new shard may retain 32 * 64 * 4096 attempts on full exhaustion.
# The bound scales with this separate eight-sample/four-cell schema; v1 is unchanged.
# Bound the parser without excluding that complete fixed-denominator observation.
MAX_LINE, MAX_BYTES = 8 * 1024 * 1024, 4 * 1024 * 1024 * 1024
FIELDS = {
    "campaign": "selector class target_index target reuse_winners samples attempt_budget seed classes horizons strategies paths cases arithmetic materialization material_setup clock producer_timing_scope evidence_timing_scope mutation_timing_scope verifier_timing_scope cross_horizon_challenges " + " ".join(FALSE_FLAGS),
    "material": "class source task a_hex b_hex",
    "cohort": "sample strategy invocation_order setup_calls searches arithmetic materialization setup total",
    "search": "sample strategy search_index setup_calls timing evidence_timing proof_materializations serialized_proof_bytes attempts status winner",
    "candidate": "sample search_index challenge proof_hex proof_sha256",
    "product_mutation": "sample strategy search_index source_proof_sha256 proof_sha256 offset before after timing",
    "verifier": "sample strategy search_index case invocation_order path challenge proof_sha256 outcome timing",
    "end": "cohort_count search_count candidate_count product_mutation_count verifier_count complete",
}


def challenge(task, target, sample, search, nonce):
    return common.pon_hash(b"pon-w1-legal-strategy-challenge-v3", task, target, bytes(8),
        sample.to_bytes(8, "little"), search.to_bytes(8, "little"), nonce.to_bytes(8, "little"))


def measured(value, label):
    common.timing(value, label)
    common.require(all(type(value[axis]) is int and value[axis] > 0 for axis in ("cpu_ns", "wall_ns")),
                   label + ": positive measured CPU/wall required")
    return value


def factors(strategy):
    index = STRATEGIES.index(strategy)
    return ARITHMETIC[index], MATERIALIZATION[index]


def fraction(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator} if denominator else None


def product_last(proof):
    """A canonical final-C mutation; neither its construction nor its verdict is work."""
    raw = bytearray(proof)
    offset = common.PROOF_BYTES - 36
    value = int.from_bytes(raw[offset:offset + 4], "little")
    raw[offset:offset + 4] = ((value + 1) % common.Q).to_bytes(4, "little")
    return bytes(raw)


class Records:
    def __init__(self):
        self.counts, self.cohorts, self.canonical = Counter(), {}, {}
        self.campaign = self.current = self.material = None
        self.ended, self.alerts = False, []

    def close_search(self):
        if self.current is None or not self.current["searches"]:
            return
        searched = self.current["searches"][-1]
        won = searched["winner"] is not None
        common.require(searched["candidate_seen"] == won, "complete winner candidate missing")
        common.require((searched["mutation_timing"] is not None) == won, "separate product mutation measurement missing")
        common.require(len(searched["verifiers"]) == (len(PATHS) * len(CASES) if won else 0), "full verifier coverage incomplete")

    def close_cohort(self):
        if self.current is None:
            return
        self.close_search()
        common.require(len(self.current["searches"]) == self.campaign["reuse_winners"], "reuse search coverage incomplete")
        for axis in ("cpu_ns", "wall_ns"):
            subtotal = self.current["setup"][axis] + sum(s["timing"][axis] for s in self.current["searches"])
            common.require(self.current["total"][axis] >= subtotal, "setup and complete searches exceed inclusive total")

    def same_current(self, row, strategy=True):
        common.require(self.current is not None and type(row["sample"]) is int
            and row["sample"] == self.current["sample"], "record outside current cohort")
        if strategy:
            common.require(row["strategy"] == self.current["strategy"], "strategy identity changed")
        return self.current

    def last_search(self, row, strategy=True):
        current = self.same_current(row, strategy)
        index = common.integer(row["search_index"], "search index", self.campaign["reuse_winners"] - 1)
        common.require(current["searches"] and index == len(current["searches"]) - 1, "record outside current search")
        return current["searches"][-1]

    def add(self, row):
        common.require(not self.ended, "records after complete end")
        common.require(type(row) is dict and row.get("schema") == SCHEMA, "explicit legal-strategy schema required")
        kind = row.get("kind")
        common.require(type(kind) is str and kind in FIELDS, "unknown record kind")
        common.exact(row, {"schema", "kind", *FIELDS[kind].split()}, kind)
        common.require(self.campaign is not None or kind == "campaign", "campaign must be first")
        getattr(self, "add_" + kind)(row)
        self.counts[kind] += 1

    def add_campaign(self, row):
        common.require(self.campaign is None, "duplicate campaign")
        common.require(type(row["class"]) is str and row["class"] in CLASSES, "fixed class required")
        index = common.integer(row["target_index"], "target index", len(TARGETS) - 1)
        common.require(row["target"] == TARGETS[index], "fixed target required")
        common.require(type(row["reuse_winners"]) is int and row["reuse_winners"] in HORIZONS, "fixed actual reuse horizon required")
        for key, expected in (("samples", SAMPLES), ("attempt_budget", ATTEMPT_BUDGET), ("seed", 0)):
            common.require(common.integer(row[key], key) == expected, "fixed parameter changed: " + key)
        for key, expected in (("classes", list(CLASSES)), ("horizons", list(HORIZONS)),
                ("strategies", list(STRATEGIES)), ("paths", list(PATHS)), ("cases", list(CASES)),
                ("arithmetic", list(ARITHMETIC)), ("materialization", list(MATERIALIZATION))):
            common.require(row[key] == expected, "frozen strategy/grid changed: " + key)
        common.require(row["selector"] == SELECTOR and row["clock"] == "thread-cpu-and-monotonic-wall-ns"
            and row["producer_timing_scope"] == PRODUCER_SCOPE and row["verifier_timing_scope"] == VERIFY_SCOPE
            and row["evidence_timing_scope"] == EVIDENCE_SCOPE
            and row["mutation_timing_scope"] == MUTATION_SCOPE
            and row["cross_horizon_challenges"] == "same-prefix-not-independent", "scope/selector changed")
        for flag in FALSE_FLAGS:
            common.require(row[flag] is False, "qualification flag cannot be acquired")
        measured(row["material_setup"], "material setup")
        self.campaign = row

    def add_material(self, row):
        common.require(self.material is None and not self.cohorts and row["class"] == self.campaign["class"], "material identity/order")
        a, b, task, prefix = common.material(row["class"])
        source = "hash-generated-rank-checked" if row["class"] == "full-rank-field" else "synthetic-fixture"
        common.require(row["source"] == source and row["task"] == task.hex()
            and common.hex_bytes(row["a_hex"], common.CELLS * 4, "A") == a
            and common.hex_bytes(row["b_hex"], common.CELLS * 4, "B") == b, "complete material recipe mismatch")
        self.material = task, prefix

    def add_cohort(self, row):
        self.close_cohort()
        common.require(self.material is not None, "material missing")
        sample, order = divmod(self.counts["cohort"], len(STRATEGIES))
        common.require(sample < SAMPLES and common.integer(row["sample"], "sample") == sample
            and common.integer(row["invocation_order"], "order") == order, "cohort coverage/order incomplete")
        strategy = STRATEGIES[(sample + self.campaign["target_index"] + order) % len(STRATEGIES)]
        arithmetic, materialization = factors(strategy)
        common.require(row["strategy"] == strategy and row["arithmetic"] == arithmetic
            and row["materialization"] == materialization, "fixed factorial cell mismatch")
        common.require(common.integer(row["setup_calls"], "setup calls") == 1
            and common.integer(row["searches"], "searches") == self.campaign["reuse_winners"], "one actual setup and complete reuse required")
        current = dict(sample=sample, strategy=strategy, order=order, searches=[],
            setup=measured(row["setup"], "setup"), total=measured(row["total"], "total"))
        self.cohorts[sample, strategy] = self.current = current

    def add_search(self, row):
        self.close_search()
        current = self.same_current(row)
        index = common.integer(row["search_index"], "search index", self.campaign["reuse_winners"] - 1)
        common.require(index == len(current["searches"]), "search coverage/order incomplete")
        common.require(common.integer(row["setup_calls"], "search setup") == 0, "hidden setup inside search")
        trials = row["attempts"]
        common.require(type(trials) is list and 0 < len(trials) <= ATTEMPT_BUDGET, "bounded complete attempt list required")
        task, prefix = self.material
        target = bytes.fromhex(self.campaign["target"])
        digest = hashlib.sha256()
        for nonce, trial in enumerate(trials):
            common.exact(trial, ("nonce", "challenge", "trace", "ticket", "proof_sha256", "proof_materialized", "target_hit"), "trial")
            common.require(common.integer(trial["nonce"], "nonce") == nonce, "nonconsecutive nonce")
            context = challenge(task, target, current["sample"], index, nonce)
            common.require(common.hex_bytes(trial["challenge"], 32, "challenge") == context, "challenge binding mismatch")
            trace = common.hex_bytes(trial["trace"], 32, "trace")
            proof_digest = common.sha(prefix + trace)
            common.require(trial["proof_sha256"] == proof_digest, "complete attempt proof digest mismatch")
            ticket = common.pon_hash(b"ticket", context, trace)
            common.require(common.hex_bytes(trial["ticket"], 32, "ticket") == ticket, "ticket hash mismatch")
            hit = ticket <= target
            common.require(type(trial["target_hit"]) is bool and trial["target_hit"] == hit, "target result mismatch")
            common.require(not hit or nonce == len(trials) - 1, "first hit must stop search")
            expected_materialized = factors(current["strategy"])[1] == "every-attempt" or hit
            common.require(type(trial["proof_materialized"]) is bool
                and trial["proof_materialized"] == expected_materialized, "proof materialization differs from fixed cell")
            digest.update(nonce.to_bytes(8, "little") + context + trace + ticket + bytes.fromhex(proof_digest) + bytes([hit]))
        common.require(row["status"] in ("target-hit-unverified", "exhausted"), "search status")
        won = row["status"] == "target-hit-unverified"
        common.require(won == hit and (won or len(trials) == ATTEMPT_BUDGET), "exhaustion/misses incomplete")
        proof = prefix + trace if won else None
        winner = {"challenge": context.hex(), "proof_sha256": common.sha(proof)} if won else None
        common.require(row["winner"] == winner, "winner/complete proof digest mismatch")
        if won:
            common.exact(row["winner"], ("challenge", "proof_sha256"), "winner")
        materializations = sum(t["proof_materialized"] for t in trials)
        common.require(common.integer(row["proof_materializations"], "proof materializations") == materializations
            and common.integer(row["serialized_proof_bytes"], "serialized proof bytes") == materializations * common.PROOF_BYTES,
            "actual proof materialization accounting mismatch")
        evidence_timing = measured(row["evidence_timing"], "separate attempt evidence timing")
        identity = (digest.hexdigest(), len(trials), winner)
        key = current["sample"], index
        first = key not in self.canonical
        if first:
            self.canonical[key] = identity
        else:
            common.require(self.canonical[key] == identity, "matched strategies differ in full attempts/winner")
        current["searches"].append(dict(index=index, timing=measured(row["timing"], "search timing"),
            attempt_count=len(trials), stream_sha256=digest.hexdigest(), winner=winner, proof=proof,
            evidence_timing=evidence_timing, proof_materializations=materializations,
            serialized_proof_bytes=materializations * common.PROOF_BYTES,
            candidate_seen=won and not first, candidate_expected=won and first, mutation_timing=None, verifiers=[]))

    def add_candidate(self, row):
        searched = self.last_search(row, strategy=False)
        common.require(searched["candidate_expected"] and not searched["candidate_seen"], "duplicate/fictitious candidate")
        common.require(row["challenge"] == searched["winner"]["challenge"]
            and row["proof_sha256"] == searched["winner"]["proof_sha256"]
            and common.hex_bytes(row["proof_hex"], common.PROOF_BYTES, "proof") == searched["proof"], "complete candidate bytes mismatch")
        searched["candidate_seen"] = True

    def add_product_mutation(self, row):
        searched = self.last_search(row)
        common.require(searched["winner"] is not None and searched["candidate_seen"]
            and searched["mutation_timing"] is None and not searched["verifiers"], "mutation requires one complete candidate before verifiers")
        offset = common.PROOF_BYTES - 36
        before = int.from_bytes(searched["proof"][offset:offset + 4], "little")
        after = (before + 1) % common.Q
        common.require(common.integer(row["offset"], "mutation offset") == offset
            and common.integer(row["before"], "mutation before", common.Q - 1) == before
            and common.integer(row["after"], "mutation after", common.Q - 1) == after
            and row["source_proof_sha256"] == searched["winner"]["proof_sha256"]
            and row["proof_sha256"] == common.sha(product_last(searched["proof"])), "canonical final product mutation mismatch")
        searched["mutation_timing"] = measured(row["timing"], "separate mutation timing")

    def add_verifier(self, row):
        searched = self.last_search(row)
        common.require(searched["winner"] is not None and searched["candidate_seen"]
            and searched["mutation_timing"] is not None, "native verifier requires candidate and measured mutation")
        case_index, order = divmod(len(searched["verifiers"]), len(PATHS))
        common.require(case_index < len(CASES) and row["case"] == CASES[case_index]
            and common.integer(row["invocation_order"], "verify order") == order, "verifier case/order/coverage")
        path = PATHS[(self.current["sample"] + self.current["order"] + searched["index"] + order) % len(PATHS)]
        expected_digest = searched["winner"]["proof_sha256"] if case_index == 0 else common.sha(product_last(searched["proof"]))
        common.require(row["path"] == path and row["challenge"] == searched["winner"]["challenge"]
            and row["proof_sha256"] == expected_digest, "verifier identity/rotation mismatch")
        common.require(type(row["outcome"]) is str and row["outcome"] in (
            "Accepted", "AcceptedWrongProduct", "AcceptedWrongStatement", "Length", "Version", "Field", "Task", "Target", "Transcript", "Product", "NoiseBudget"), "unknown verdict")
        measured(row["timing"], "verifier timing")
        searched["verifiers"].append(row)
        if row["outcome"] != ("Accepted" if case_index == 0 else "Product"):
            self.alerts.append({key: row[key] for key in ("sample", "strategy", "search_index", "case", "path", "outcome")})

    def add_end(self, row):
        self.close_cohort()
        common.require(self.counts["material"] == 1 and self.counts["cohort"] == SAMPLES * len(STRATEGIES)
            and self.counts["search"] == SAMPLES * len(STRATEGIES) * self.campaign["reuse_winners"], "shard grid incomplete")
        for kind in ("cohort", "search", "candidate", "product_mutation", "verifier"):
            common.require(common.integer(row[kind + "_count"], kind) == self.counts[kind], "record count mismatch")
        common.require(row["complete"] is True, "complete end required")
        self.ended = True


def rate_diagnostic(searches, cpu_ns, target_weight, semantic_alerts):
    """Exact finite rates of retained producer intervals, not admitted blocks.

    Count a hit once, not once per verifier. A shard alert suppresses every
    validity-based rate, including apparently unaffected samples/strategies.
    Attempts remain observable even when native verdicts disagree. Exhaustion
    yields an observed zero-hit rate, not an upper bound on future production.
    """
    accepted = 0
    for searched in searches:
        legal = [v for v in searched["verifiers"] if v["case"] == "legal"]
        accepted += (searched["winner"] is not None and len(legal) == len(PATHS)
                     and all(v["outcome"] == "Accepted" for v in legal))
    attempts = sum(s["attempt_count"] for s in searches)
    return dict(recorded_relation_valid_hits=accepted,
        valid_rates_suppressed_by_shard_alerts=bool(semantic_alerts),
        attempts_per_cpu_second=fraction(attempts * 1_000_000_000, cpu_ns),
        recorded_relation_valid_hits_per_cpu_second=(
            fraction(accepted * 1_000_000_000, cpu_ns) if not semantic_alerts else None),
        hypothetical_required_work_total=(accepted * target_weight if not semantic_alerts else None),
        hypothetical_required_work_per_cpu_second=(
            fraction(accepted * target_weight * 1_000_000_000, cpu_ns) if not semantic_alerts else None))


def summary(records):
    result = []
    target_weight = (1 << 256) // (int(records.campaign["target"], 16) + 1)
    for strategy in STRATEGIES:
        cohorts = [records.cohorts[sample, strategy] for sample in range(SAMPLES)]
        searches = [searched for cohort in cohorts for searched in cohort["searches"]]
        winners = sum(searched["winner"] is not None for searched in searches)
        full = {axis: sum(cohort["total"][axis] for cohort in cohorts) for axis in ("cpu_ns", "wall_ns")}
        verifiers = [v for searched in searches for v in searched["verifiers"]]
        outcomes = {case: dict(Counter(v["outcome"] for v in verifiers if v["case"] == case)) for case in CASES}
        good = all(v["outcome"] == ("Accepted" if v["case"] == "legal" else "Product") for v in verifiers)
        result.append(dict(strategy=strategy, actual_setup_calls=len(cohorts), actual_searches=len(searches),
            target_hits=winners, exhausted_searches=len(searches) - winners,
            attempts=sum(s["attempt_count"] for s in searches), inclusive_cohort_total=full,
            arithmetic=factors(strategy)[0], materialization=factors(strategy)[1],
            per_sample_cohort_totals=[dict(sample=c["sample"], **c["total"]) for c in cohorts],
            per_sample_denominators=[dict(sample=c["sample"], actual_setup_calls=1,
                actual_searches=len(c["searches"]),
                attempts=sum(s["attempt_count"] for s in c["searches"]),
                target_hits=sum(s["winner"] is not None for s in c["searches"]),
                exhausted_searches=sum(s["winner"] is None for s in c["searches"]),
                setup=c["setup"], inclusive_cohort_total=c["total"],
                proof_materializations=sum(s["proof_materializations"] for s in c["searches"]),
                serialized_proof_bytes=sum(s["serialized_proof_bytes"] for s in c["searches"]),
                rate_diagnostic=rate_diagnostic(c["searches"], c["total"]["cpu_ns"],
                                                target_weight, records.alerts)) for c in cohorts],
            proof_materializations=sum(s["proof_materializations"] for s in searches),
            serialized_proof_bytes=sum(s["serialized_proof_bytes"] for s in searches),
            separate_attempt_evidence_total={axis: sum(s["evidence_timing"][axis] for s in searches) for axis in full},
            setup_total={axis: sum(c["setup"][axis] for c in cohorts) for axis in full},
            separate_product_mutation_total={axis: sum(s["mutation_timing"][axis] for s in searches if s["mutation_timing"] is not None) for axis in full},
            native_outcome_counts=outcomes,
            cpu_per_observed_valid_winner=fraction(full["cpu_ns"], winners) if good and not records.alerts else None,
            rate_diagnostic=rate_diagnostic(searches, full["cpu_ns"], target_weight, records.alerts),
            verification={case: {path: {axis: sum(v["timing"][axis] for v in verifiers if v["path"] == path and v["case"] == case)
                for axis in full} for path in PATHS} for case in CASES}))
    return result


def analyze_shard(path):
    records = Records()
    digest, size, count = hashlib.sha256(), 0, 0
    maximum_records = 3 + SAMPLES * (len(STRATEGIES) + max(HORIZONS) * (len(STRATEGIES) * (2 + len(PATHS) * len(CASES)) + 1))
    with Path(path).open("rb") as source:
        while line := source.readline(MAX_LINE + 1):
            size += len(line)
            count += 1
            common.require(len(line) <= MAX_LINE and line.endswith(b"\n") and size <= MAX_BYTES
                and count <= maximum_records, "bounded complete JSONL required")
            digest.update(line)
            try:
                records.add(common.decode(line))
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ValueError(f"line {count}: {error}") from error
    common.require(records.ended, "missing complete end")
    selection = {key: records.campaign[key] for key in ("class", "target_index", "reuse_winners")}
    rows = summary(records)
    cpu = [r["inclusive_cohort_total"]["cpu_ns"] for r in rows]
    ratio = fraction(cpu[0], cpu[3])
    effects = dict(lazy_minus_eager_transposed=cpu[1]-cpu[0],
        lazy_minus_eager_full_limb=cpu[3]-cpu[2],
        full_limb_minus_transposed_eager=cpu[2]-cpu[0],
        full_limb_minus_transposed_lazy=cpu[3]-cpu[1],
        interaction=(cpu[3]-cpu[2])-(cpu[1]-cpu[0]))
    if records.alerts or not rows[0]["target_hits"]:
        ratio = effects = None
    fingerprints = [dict(sample=sample, search_index=index, stream_sha256=identity[0],
        attempts=identity[1], winner=identity[2]) for (sample, index), identity in sorted(records.canonical.items())]
    return dict(schema="pon-w1-legal-strategy-shard-readback-v3", record_consistency="PASS",
        observation_coverage="one-complete-shard-only", observed_complete_shards=1,
        required_complete_shards=len(CLASSES) * len(TARGETS) * len(HORIZONS),
        independent_challenge_samples_per_shard=SAMPLES, qualification_status="HOLD",
        selection=selection, input_sha256=digest.hexdigest(), input_bytes=size, record_counts=dict(records.counts),
        semantic_alerts=records.alerts, strategy_costs=rows, eager_transposed_over_lazy_full_limb_cpu=ratio, factorial_cpu_differences_ns=effects,
        material_setup=records.campaign["material_setup"], search_fingerprints=fingerprints,
        required_target_weight=(1 << 256) // (int(records.campaign["target"], 16) + 1),
        rate_diagnostic_scope=dict(RATE_SCOPE),
        matched_full_search_streams=True, w1_transcript_replayed=False, native_execution_authenticated=False,
        fastest_adversary_lower_bound=False, complete_fixed_grid=False, **FALSE_FLAGS)


def analyze(paths):
    expected = {(name, target, horizon) for name in CLASSES for target in range(len(TARGETS)) for horizon in HORIZONS}
    common.require(len(paths) == len(expected), "complete fixed shard grid required")
    reports, seen, fingerprints = [], set(), {}
    for path in paths:
        report = analyze_shard(path)
        choice = report["selection"]
        key = choice["class"], choice["target_index"], choice["reuse_winners"]
        common.require(key in expected and key not in seen, "duplicate/unknown shard")
        seen.add(key)
        for searched in report["search_fingerprints"]:
            identity = key[:2] + (searched["sample"], searched["search_index"])
            common.require(identity not in fingerprints or fingerprints[identity] == searched,
                           "cross-horizon matched search prefix changed")
            fingerprints[identity] = searched
        reports.append(report)
    common.require(seen == expected, "complete fixed shard grid required")
    reports.sort(key=lambda r: (CLASSES.index(r["selection"]["class"]), r["selection"]["target_index"], r["selection"]["reuse_winners"]))
    policy_raw = common.PROFILE.read_bytes()
    common.require(common.sha(policy_raw) == common.PROFILE_SHA256, "original acceptance profile changed")
    policy = common.decode(policy_raw)
    alerts = [{"selection": r["selection"], **alert} for r in reports for alert in r["semantic_alerts"]]
    return dict(schema="pon-w1-legal-strategy-readback-v3", record_consistency="PASS", complete_fixed_grid=True,
        observation_coverage="complete-fixed-factorial-grid", observed_complete_shards=len(reports),
        required_complete_shards=len(expected), qualification_status="HOLD",
        semantic_alerts=alerts, shards=reports, observed_samples_per_class=SAMPLES,
        required_policy_samples_per_class=policy["minimum_cost_samples_per_class"],
        policy_sample_count_satisfied=SAMPLES >= policy["minimum_cost_samples_per_class"],
        all_policy_materials_or_targets_covered=False, cross_horizon_challenges="same-prefix-not-independent",
        unique_search_streams=len(fingerprints), fixed_strategy_selected_before_measurement=True,
        per_sample_fastest_oracle_used=False, modeled_setup_division_used=False,
        w1_transcript_replayed=False, native_execution_authenticated=False, fastest_adversary_lower_bound=False,
        limitations=["Eight distinct challenge sample identifiers satisfy only the unchanged sample-count requirement.",
            "This finite five-class/two-target cohort is not all selectable tasks or production difficulty.",
            "The two arithmetic kernels share identical AB/prefix preparation; each attempt computes the full original transcript.",
            "Proof materialization is varied independently of arithmetic; every miss and successful proof serialization stays inside its producer timer.",
            "Binary trial retention is paid in producer CPU. Complete attempt proof digests and JSON values are separately timed evidence overhead; JSON output, verification and retained buffer destruction are outside those scopes.",
            "Common material generation is reported separately and is not repeated per winner.",
            "Matched horizons deliberately reuse search prefixes; totals are observations, not newly credited chainwork.",
            "Finite rates divide each fixed strategy's complete producer totals; shared material setup, evidence, verification and end-to-end node costs remain separate. Work-equivalent rates are hypothetical, not observed ledger credit or network share.",
            "Timing and native verdict/source/hardware authenticity require the enclosing execution receipt.",
            "No model improvement, independent WAN service, universally cheapest algorithm or quantum cost is established."], **FALSE_FLAGS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        report = analyze(args.inputs)
    except (OSError, ValueError, OverflowError) as error:
        print(json.dumps(dict(record_consistency="FAIL", error=str(error), **FALSE_FLAGS), sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if report["semantic_alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
