#!/usr/bin/env python3
"""Check complete paid rank-one/reuse observations; never attest clocks or hardness.

Reconstructs canonical material, AB, challenge/ticket streams and exact proof
bytes. Full W1 trace replay is provided by the recorded native/scalar verifiers,
not this reader. Shared horizon prefixes remain correlated observations.
"""
from collections import Counter
from functools import lru_cache
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct

SCHEMA = "pon-w1-rank-one-reuse-v1"
SELECTOR = "--rank-one-reuse-v1"
N, Q, CELLS, PROOF_BYTES = 64, 4294967291, 4096, 49188
SAMPLES, LIMIT = 6, 4096
CLASSES = ("rank-one-field", "rank-one-sparse")
HORIZONS = (1, 8, 64)
ARMS = ("dense-per-search", "dense-warm-horizon", "sparse-per-search", "sparse-warm-horizon",
        "rank-one-per-search", "rank-one-warm-horizon")
PREPARATIONS = ("dense", "sparse", "checked-rank-one")
LIFETIMES = ("per-search", "warm-horizon")
PATHS = ("production", "scalar-reference")
CASES = ("legal", "product-last", "transcript-max-target")
TARGETS = ("7f" + "ff" * 31, "07" + "ff" * 31, "00" * 31 + "01", "ff" * 32)
PURPOSES = ("search-cost", "search-cost", "exhaustion-control", "first-hit-control")
FALSE_FLAGS = ("cheapest_legal_strategy_lower_bound_established", "public_service_measured",
               "batching_measured", "persistent_cache_measured", "hardware_fairness_qualified",
               "production_activation")
PRODUCER_SCOPE = "all-actual-setups-complete-attempts-tickets-lazy-proof-materializations-binary-trial-retention-one-prefix-copy-and-task-destructions-excludes-evidence-verification-json-and-retained-search-buffer-destruction"
ATTEMPT_SCOPE = "challenge-construction-and-complete-FullLimb-attempt-including-ticket-and-hit-proof-bytes"
VERIFY_SCOPE = "native-full-verifier-call-return-only-no-fact-cache-excludes-returned-work-destruction"
MAX_LINE, MAX_BYTES = 16 * 1024 * 1024, 8 * 1024 * 1024 * 1024
ERRORS = {"Length", "Version", "Field", "Task", "Transcript", "Product", "Target", "NoiseBudget"}


def require(ok, message):
    if not ok:
        raise ValueError("rank-one reuse: " + message)


def exact(value, fields, label):
    require(type(value) is dict and set(value) == set(fields.split()), label + " exact fields")


def integer(value, label, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, label + " integer range")
    return value


def raw_hex(value, length, label):
    require(type(value) is str and len(value) == 2 * length and
            re.fullmatch("[0-9a-f]+", value) is not None, label + " canonical hex")
    return bytes.fromhex(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identical(actual, expected):
    # JSON equality must not silently equate True with 1 or 1.0 with 1.
    return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False)


def pon_hash(tag, *parts):
    digest = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    for part in parts:
        digest.update(len(part).to_bytes(4, "little"))
        digest.update(part)
    return digest.digest()


def challenge(task, target, sample, search, nonce):
    return pon_hash(b"pon-w1-rank-one-reuse-challenge-v1", task, target,
                    sample.to_bytes(8, "little"), search.to_bytes(8, "little"), nonce.to_bytes(8, "little"))


@lru_cache(maxsize=2)
def material(name):
    require(name in CLASSES, "known material class")
    factors = []
    for label in range(4):
        vector = []
        for index in range(N):
            word = int.from_bytes(pon_hash(b"pon-w1-rank-one-reuse-factor-v1",
                bytes([label]), index.to_bytes(8, "little"))[:4], "little")
            keep = name != "rank-one-sparse" or (index % 5 == 2 if label == 0
                else index % 7 == 3 if label in (1, 2) else index % 11 == 4)
            vector.append(word % (Q - 1) + 1 if keep else 0)
        factors.append(vector)
    a = [x * y % Q for x in factors[0] for y in factors[1]]
    b = [x * y % Q for x in factors[2] for y in factors[3]]
    # Independent ordinary dense AB, not the new factored product constructor.
    columns = list(zip(*(b[i:i + N] for i in range(0, CELLS, N))))
    product = [sum(x * y for x, y in zip(a[i:i + N], col)) % Q
               for i in range(0, CELLS, N) for col in columns]
    pack = lambda values: struct.pack(f"<{CELLS}I", *values)
    left, right, result = pack(a), pack(b), pack(product)
    return left, right, pon_hash(b"task", left, right), b"PNW1" + left + right + result


def timing(value, label):
    exact(value, "cpu_ns wall_ns", label)
    for axis in ("cpu_ns", "wall_ns"):
        if value[axis] is not None:
            integer(value[axis], label + " " + axis)
    return value


def paid_sum(stamps):
    stamps = list(stamps)
    # A known zero for zero actual calls is different from a missing clock.
    return {axis: None if any(s[axis] is None for s in stamps) else sum(s[axis] for s in stamps)
            for axis in ("cpu_ns", "wall_ns")}


def nested(parent, children, label):
    subtotal = paid_sum(children)
    for axis in subtotal:
        if parent[axis] is not None and subtotal[axis] is not None:
            require(parent[axis] >= subtotal[axis], label + " timing containment " + axis)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key " + key)
        value[key] = item
    return value


def rows(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular non-linked input required")
    opener = gzip.open if path.suffix == ".gz" else open
    total = 0
    with opener(path, "rb") as source:
        while raw := source.readline(MAX_LINE + 1):
            total += len(raw)
            require(len(raw) <= MAX_LINE and total <= MAX_BYTES, "bounded raw record size")
            require(raw.endswith(b"\n"), "complete newline-terminated record")
            yield json.loads(raw, object_pairs_hook=unique,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON constant " + value)))


def take(records, kind, fields):
    try:
        value = next(records)
    except StopIteration as error:
        raise ValueError("rank-one reuse: incomplete record stream, expected " + kind) from error
    exact(value, "schema kind " + fields, kind)
    require(value["schema"] == SCHEMA and value["kind"] == kind, "ordered " + kind + " record")
    return value


def phases(value, expected, label):
    require(type(value) is list and len(value) == len(expected), label + " actual call count")
    for row, index in zip(value, expected):
        exact(row, "search_index timing", label)
        require(integer(row["search_index"], label + " search index") == index, label + " exact search index")
        timing(row["timing"], label)
    return [row["timing"] for row in value]


def expected_cases(proof):
    product = bytearray(proof)
    offset = PROOF_BYTES - 36
    value = int.from_bytes(product[offset:offset + 4], "little")
    product[offset:offset + 4] = ((value + 1) % Q).to_bytes(4, "little")
    transcript = bytearray(proof)
    transcript[-1] ^= 1
    return proof, bytes(product), bytes(transcript)


def check_verifiers(checks, proof, last, task, target, rotation):
    require(type(checks) is list and len(checks) == (0 if proof is None else len(CASES)), "winner verifier coverage")
    if proof is None:
        return [], [], 0
    verifiers, mutations, failures = [], [], 0
    for case, (row, candidate) in enumerate(zip(checks, expected_cases(proof))):
        exact(row, "case target proof_sha256 mutation_timing verifiers", "check")
        require(row["case"] == CASES[case] and row["proof_sha256"] == sha(candidate), "exact mutation bytes")
        require(row["target"] == (TARGETS[3] if case == 2 else target.hex()), "explicit control target")
        if case == 0:
            require(row["mutation_timing"] is None, "legal proof is not a new mutation")
        else:
            mutations.append(timing(row["mutation_timing"], "separate mutation"))
        require(type(row["verifiers"]) is list and len(row["verifiers"]) == len(PATHS), "both native verifiers")
        for order, verifier in enumerate(row["verifiers"]):
            exact(verifier, "path invocation_order timing outcome", "verifier")
            require(verifier["path"] == PATHS[(rotation + order) % len(PATHS)] and
                    integer(verifier["invocation_order"], "verifier order") == order, "verifier rotation")
            verifiers.append(timing(verifier["timing"], "verifier"))
            actual = verifier["outcome"]
            require(type(actual) is dict and "result" in actual, "native outcome")
            if actual["result"] == "Accepted":
                exact(actual, "result challenge task ticket product_sha256", "accepted outcome")
                for key in ("challenge", "task", "ticket", "product_sha256"):
                    raw_hex(actual[key], 32, "accepted " + key)
            else:
                exact(actual, "result", "rejected outcome")
                require(actual["result"] in ERRORS, "native error vocabulary")
            expected = dict(result="Accepted", challenge=last["challenge"], task=task.hex(),
                ticket=last["ticket"], product_sha256=sha(proof[4 + 2 * CELLS * 4:-32])) if case == 0 else {
                    "result": "Product" if case == 1 else "Transcript"}
            failures += actual != expected
    return verifiers, mutations, failures


def analyze_records(records):
    records = iter(records)
    head = take(records, "campaign", "selector class target_index target reuse_searches samples attempt_budget purpose classes horizons arms preparations lifetimes paths cases arithmetic materialization clock producer_timing_scope attempt_timing_scope verifier_timing_scope cross_horizon_challenges proof_bytes_encoding material_timing " + " ".join(FALSE_FLAGS))
    name = head["class"]
    require(type(name) is str and name in CLASSES, "canonical class")
    target_index = integer(head["target_index"], "target index", maximum=3)
    horizon = integer(head["reuse_searches"], "horizon", minimum=1, maximum=64)
    require(horizon in HORIZONS and (target_index < 2 or horizon == 1), "fixed horizon")
    limit = LIMIT if target_index < 2 else 3
    fixed = dict(selector=SELECTOR, target=TARGETS[target_index], samples=SAMPLES, attempt_budget=limit,
        purpose=PURPOSES[target_index], classes=list(CLASSES), horizons=list(HORIZONS), arms=list(ARMS),
        preparations=list(PREPARATIONS), lifetimes=list(LIFETIMES), paths=list(PATHS), cases=list(CASES),
        arithmetic="full-limb", materialization="target-hit", clock="thread-cpu-and-monotonic-wall-ns",
        producer_timing_scope=PRODUCER_SCOPE, attempt_timing_scope=ATTEMPT_SCOPE, verifier_timing_scope=VERIFY_SCOPE,
        cross_horizon_challenges="same-prefix-not-independent", proof_bytes_encoding="shared-exact-prefix-plus-32-byte-trace")
    require(all(identical(head[key], value) for key, value in fixed.items()), "frozen campaign declaration")
    require(all(head[key] is False for key in FALSE_FLAGS), "qualification flags remain false")
    timing(head["material_timing"], "common material")
    left, right, task, prefix = material(name)
    raw = take(records, "material", "class task a_hex b_hex source provenance_verified")
    require(raw["class"] == name and raw["task"] == task.hex() and raw["a_hex"] == left.hex()
            and raw["b_hex"] == right.hex() and raw["source"] == "deterministic-synthetic-rank-one-v1"
            and raw["provenance_verified"] is False, "complete canonical material identity")
    saved = take(records, "proof_prefix", "bytes_hex sha256")
    require(saved["bytes_hex"] == prefix.hex() and saved["sha256"] == sha(prefix), "independent dense AB prefix")
    totals = {arm: dict(counts=Counter(), producer=[], setup=[], destruction=[], search=[], attempt=[],
                       evidence=[], verifier=[], mutation=[]) for arm in ARMS}
    streams, semantic_failures = {}, 0
    for sample in range(SAMPLES):
        for order in range(len(ARMS)):
            arm_index = (sample + order) % len(ARMS)
            arm = ARMS[arm_index]
            paid = totals[arm]
            warm = arm_index % 2 == 1
            cohort = take(records, "cohort", "sample arm invocation_order preparation lifetime prefix_sha256 timing setups destructions searches")
            expected = dict(sample=sample, arm=arm, invocation_order=order,
                preparation=PREPARATIONS[arm_index // 2], lifetime=LIFETIMES[arm_index % 2], prefix_sha256=sha(prefix), searches=horizon)
            require(all(cohort[k] == v for k, v in expected.items()), "exact cohort identity and coverage")
            for key in ("sample", "invocation_order", "searches"):
                integer(cohort[key], "cohort " + key)
            setup = phases(cohort["setups"], [0] if warm else range(horizon), "setup")
            destruction = phases(cohort["destructions"], [horizon - 1] if warm else range(horizon), "destruction")
            total = timing(cohort["timing"], "paid cohort")
            paid["producer"].append(total)
            paid["setup"].extend(setup)
            paid["destruction"].extend(destruction)
            paid["counts"].update(cohorts=1, actual_setup_calls=len(setup), actual_destructions=len(destruction))
            search_times = []
            for index in range(horizon):
                searched = take(records, "search", "sample arm search_index timing attempts winner status evidence_timing checks")
                require(integer(searched["sample"], "search sample") == sample and searched["arm"] == arm
                        and integer(searched["search_index"], "search index") == index, "ordered search identity")
                search_time = timing(searched["timing"], "paid search")
                search_times.append(search_time)
                paid["search"].append(search_time)
                paid["evidence"].append(timing(searched["evidence_timing"], "separate evidence"))
                trials = searched["attempts"]
                require(type(trials) is list and 1 <= len(trials) <= limit, "complete bounded attempts")
                identities, trial_times, hit = [], [], False
                for nonce, trial in enumerate(trials):
                    exact(trial, "nonce challenge trace ticket hit proof_materialized complete_proof_sha256 timing", "attempt")
                    require(not hit, "stop after first hit")
                    require(integer(trial["nonce"], "nonce") == nonce, "retain every losing nonce")
                    context = challenge(task, bytes.fromhex(TARGETS[target_index]), sample, index, nonce)
                    require(trial["challenge"] == context.hex(), "fixed same challenge stream")
                    trace = raw_hex(trial["trace"], 32, "trace")
                    ticket = pon_hash(b"ticket", context, trace)
                    hit = ticket <= bytes.fromhex(TARGETS[target_index])
                    require(trial["ticket"] == ticket.hex() and trial["hit"] is hit and
                            trial["proof_materialized"] is hit, "exact ticket and lazy materialization")
                    require(trial["complete_proof_sha256"] == sha(prefix + trace), "lossless complete proof identity")
                    trial_times.append(timing(trial["timing"], "complete attempt"))
                    identities.append({key: value for key, value in trial.items() if key != "timing"})
                nested(search_time, trial_times, "search")
                paid["attempt"].extend(trial_times)
                require(hit or len(trials) == limit, "exhaustion consumes its full attempt budget")
                require(searched["status"] == ("target-hit-unverified" if hit else "exhausted"), "honest search status")
                proof = prefix + bytes.fromhex(trials[-1]["trace"]) if hit else None
                require(searched["winner"] == ({"proof_sha256": sha(proof)} if hit else None), "actual winner or exhaustion")
                identity = sha(json.dumps(identities, sort_keys=True, separators=(",", ":")).encode())
                key = f"{sample}/{index}"
                require(key not in streams or streams[key] == identity, "six arms have identical complete attempt/proof streams")
                streams[key] = identity
                verifier, mutation, failures = check_verifiers(searched["checks"], proof, trials[-1], task,
                    bytes.fromhex(TARGETS[target_index]), sample + order + index)
                semantic_failures += failures
                paid["verifier"].extend(verifier)
                paid["mutation"].extend(mutation)
                paid["counts"].update(actual_searches=1, attempts=len(trials), misses=len(trials) - int(hit),
                    target_hits=int(hit), exhausted_searches=int(not hit), proof_materializations=int(hit),
                    serialized_proof_bytes=int(hit) * PROOF_BYTES, verifier_calls=len(verifier))
            nested(total, [*setup, *destruction, *search_times], "cohort")
    end = take(records, "end", "cohort_count search_count semantic_failures complete")
    require(integer(end["cohort_count"], "cohort count") == SAMPLES * len(ARMS) and
            integer(end["search_count"], "search count") == SAMPLES * len(ARMS) * horizon and
            integer(end["semantic_failures"], "semantic failure count") == semantic_failures and end["complete"] is True,
            "complete observed final counts")
    require(next(records, None) is None, "no trailing records")
    all_counts = sum((paid["counts"] for paid in totals.values()), Counter())
    control_ok = None if target_index < 2 else (all_counts["target_hits"] == 0 if target_index == 2
        else all_counts["misses"] == 0 and all_counts["exhausted_searches"] == 0)
    def ratio(numerator, denominator):
        return {axis: None if numerator[axis] is None or denominator[axis] in (None, 0)
                else dict(numerator=numerator[axis], denominator=denominator[axis]) for axis in numerator}
    reuse_ratios = {PREPARATIONS[index]: ratio(paid_sum(totals[ARMS[2 * index + 1]]["producer"]),
        paid_sum(totals[ARMS[2 * index]]["producer"])) for index in range(len(PREPARATIONS))}
    return dict(schema=SCHEMA + "-readback", record_consistency="PASS", qualification_status="HOLD",
        selection=dict(material=name, target_index=target_index, reuse_searches=horizon, purpose=PURPOSES[target_index]),
        common_material_timing=head["material_timing"], semantic_failures=semantic_failures,
        native_semantics_pass=semantic_failures == 0, control_expected_outcome_observed=control_ok,
        per_arm_paid_totals={arm: dict(counts=dict(paid["counts"]),
            **{phase + "_total": paid_sum(stamps) for phase, stamps in paid.items() if phase != "counts"})
            for arm, paid in totals.items()},
        canonical_search_stream_sha256=streams,
        warm_over_per_search_paid_ratios=reuse_ratios,
        boundaries=dict(rank_one_fixed_product_preparation_measured=True, full_limb_transcript_unchanged=True,
            low_rank_transcript_shortcut_measured=False, batching_measured=False, persistent_cache_measured=False,
            live_parent_task_eligibility_measured=False, cheapest_legal_strategy_lower_bound_established=False,
            public_service_measured=False, source_attested=False, clock_attested=False,
            uniform_ticket_probabilities_are_assumptions=True, cross_horizon_statistical_pooling=False,
            reader_cryptographically_replays_transcript=False, hardware_fairness_qualified=False))


def file_sha(path):
    digest = hashlib.sha256()
    total = 0
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            require(total <= MAX_BYTES, "bounded input digest size")
            digest.update(block)
    return digest.hexdigest()


def analyze_shard(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular non-linked input required")
    before = file_sha(path)
    result = analyze_records(rows(path))
    require(before == file_sha(path), "input bytes unchanged across readback")
    result["input_sha256"] = before
    return result


def analyze(paths, require_grid=False):
    reports, selections, prefixes = [], set(), {}
    for path in paths:
        report = analyze_shard(path)
        selected = report["selection"]
        key = (selected["material"], selected["target_index"], selected["reuse_searches"])
        require(key not in selections, "no duplicate shard or selective repeat pooling")
        selections.add(key)
        for search, digest in report["canonical_search_stream_sha256"].items():
            overlap = (key[0], key[1], search)
            require(overlap not in prefixes or prefixes[overlap] == digest, "identical shared horizon prefixes")
            prefixes[overlap] = digest
        reports.append(report)
    cost_grid = {(name, target, horizon) for name in CLASSES for target in (0, 1) for horizon in HORIZONS}
    controls = {(name, target, 1) for name in CLASSES for target in (2, 3)}
    missing = sorted((cost_grid | controls) - selections)
    require(not require_grid or not missing, "complete fixed cost grid and separate controls required")
    return dict(schema=SCHEMA + "-campaign-readback", qualification_status="HOLD", shards=reports,
        cost_grid_complete=cost_grid <= selections, separate_controls_complete=controls <= selections,
        missing_shards=[dict(material=a, target_index=b, reuse_searches=c) for a, b, c in missing],
        all_native_semantics_pass=all(r["native_semantics_pass"] and
            r["control_expected_outcome_observed"] is not False for r in reports),
        source_and_clock_authentication=False, cross_horizon_statistical_pooling=False,
        cheapest_legal_strategy_lower_bound_established=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observations", type=Path, nargs="+")
    parser.add_argument("--require-grid", action="store_true")
    args = parser.parse_args()
    result = analyze(args.observations, args.require_grid)
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    if not result["all_native_semantics_pass"]:
        raise SystemExit(1)
