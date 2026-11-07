#!/usr/bin/env python3
"""Strict readback for finite same-transcript/C-variant refusal observations.

Replays the independent scalar W1 relation for every positive control and binds
every false search nonce, proof commitment and progress count. Ratios sum the
recorded local intervals; they do not authenticate clocks or measure service.
"""
from collections import Counter
from functools import lru_cache
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
import work_oracle as oracle

SCHEMA = "pon-w1-rejection-c-variants-cost-v1"
PROFILE = "pon-matmul-transcript-64-v1"
CLASSES = ("zero", "dense-periodic", "rank-one", "sparse")
SAMPLES, VARIANTS, SEARCH_LIMIT = 8, 32, 65536
N, R, Q, CELLS, PROOF_BYTES = oracle.N, oracle.R, oracle.Q, oracle.CELLS, oracle.PROOF_BYTES
TARGETS = ("7f" + "ff" * 31, "07" + "ff" * 31)
TIMING_SCOPE = "same-process local producer and verifier with progress instrumentation; search includes attempt-record construction"
CONTROL_SCOPE = "native-no-cache versus explicitly configured cache; not a before/after deployed service comparison"
MATERIAL_SCOPE = "synthetic fixtures; dense-periodic is a modulo-31 pattern, with no full-rank claim"
POSITIVE_SCOPE = "same challenge and A/B, own exact ticket target; relation acceptance only, not production at attack target"
FALSE_FLAGS = ("public_service_measured", "original_resource_gate_passed", "minimum_work_cost_proved", "production_activation")
UNKNOWN_FIELDS = ("signatures_cpu_ns", "network_bytes", "queue_wall_ns", "energy_joules")
MAX_RAW = 64 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError("W1 refusal variants: " + message)


def exact(value, fields, label):
    require(type(value) is dict and set(value) == set(fields.split()), label + " exact fields")


def integer(value, label, maximum=(1 << 128) - 1):
    require(type(value) is int and 0 <= value <= maximum, label + " integer range")
    return value


def H(tag, *parts):
    digest = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    for part in parts:
        digest.update(len(part).to_bytes(4, "little"))
        digest.update(part)
    return digest.digest()


def timing(value, label):
    exact(value, "wall_ns thread_cpu_ns", label)
    integer(value["wall_ns"], label + " wall")
    if value["thread_cpu_ns"] is not None:
        integer(value["thread_cpu_ns"], label + " CPU", (1 << 64) - 1)
    return value


def total(stamps):
    stamps = list(stamps)
    return {key: None if any(value[key] is None for value in stamps) else sum(value[key] for value in stamps)
            for key in ("wall_ns", "thread_cpu_ns")}


def fraction(numerator, denominator):
    return None if numerator is None or denominator in (None, 0) else dict(numerator=numerator, denominator=denominator)


def ratios(numerator, denominator):
    return {axis: fraction(numerator[axis], denominator[axis]) for axis in ("wall_ns", "thread_cpu_ns")}


def challenge(name, target, sample):
    return H(b"rejection-c-variants-v1", name.encode(), target[:1], sample.to_bytes(8, "little"))


@lru_cache(maxsize=4)
def material(name):
    require(name in CLASSES, "fixed material class")
    def matrix(right):
        if name == "zero":
            return [0] * CELLS
        if name == "rank-one":
            return [(i // N + 1 + int(right)) * (i % N + 1) for i in range(CELLS)]
        if name == "sparse":
            return [int(i // N == i % N) for i in range(CELLS)]
        return [(i * (7 if right else 1)) % 31 for i in range(CELLS)]
    a, b = matrix(False), matrix(True)
    raw_a, raw_b = oracle.field_bytes(a), oracle.field_bytes(b)
    task = H(b"task", raw_a, raw_b)
    prefix = b"PNW1" + raw_a + raw_b + bytes(CELLS * 4 + 32)
    return a, b, task, prefix


def progress_counts(context):
    noise_calls = 0
    for label in range(4):
        words, counter = 0, 0
        while words < N * R:
            require(counter < 128, "independent noise budget")
            chunk = H(b"noise", context, bytes([label]), counter.to_bytes(4, "little"))
            words += sum(value < Q for (value,) in struct.iter_unpack("<I", chunk))
            counter += 1
        noise_calls += counter
    # BeforeReplay + exact noise expansions + two N-row products + all tiles.
    rejection = 1 + noise_calls + 2 * N + (N // R) ** 3
    # BeforeProduct + correction rows (N,N,R,N) + BeforeVerifiedWork.
    accepted = rejection + 1 + 3 * N + R + 1
    return rejection, accepted


@lru_cache(maxsize=64)
def positive_relation(name, context):
    a, b, _, _ = material(name)
    product, trace = oracle.evaluate(context, a, b)
    return tuple(product), trace


def observation(value, label, outcome, tiles, points, product=None):
    exact(value, "outcome timing progress_points transcript_tiles accepted_product", label)
    require(value["outcome"] == outcome, label + " exact verifier outcome")
    require(integer(value["transcript_tiles"], label + " tiles") == tiles and
            integer(value["progress_points"], label + " progress") == points, label + " complete actual work stages")
    if product is None:
        require(value["accepted_product"] is None, label + " must not produce VerifiedWork")
    else:
        actual = value["accepted_product"]
        require(type(actual) is list and len(actual) == CELLS and
                all(type(word) is int and 0 <= word < Q for word in actual) and tuple(actual) == product,
                label + " independent complete accepted product")
    return timing(value["timing"], label)


def summarize(values):
    exact(values, "schema samples variants_per_claim materials rows timing_scope control_scope material_scope cpu_unknown_is_null "
          + " ".join(UNKNOWN_FIELDS + FALSE_FLAGS), "campaign")
    require(values["schema"] == SCHEMA and integer(values["samples"], "samples") == SAMPLES and
            integer(values["variants_per_claim"], "variants") == VARIANTS, "fixed campaign schema and size")
    require(values["timing_scope"] == TIMING_SCOPE and values["control_scope"] == CONTROL_SCOPE and
            values["material_scope"] == MATERIAL_SCOPE, "frozen measurement scope")
    require(values["cpu_unknown_is_null"] is True and all(values[key] is None for key in UNKNOWN_FIELDS)
            and all(values[key] is False for key in FALSE_FLAGS), "unknown costs and unqualified gates preserved")
    require(type(values["materials"]) is list and len(values["materials"]) == len(CLASSES), "complete material set")
    groups = {name: dict(material=[], search=[], construction=[], cache_setup=[], cache_destruction=[],
                        native=[], cached=[], positive_setup=[], positive=[], positive_same_target=[], counts=Counter())
              for name in CLASSES}
    for name, row in zip(CLASSES, values["materials"]):
        exact(row, "class setup task a b setup_charged_once_per_class", "material")
        a, b, task, _ = material(name)
        require(row["class"] == name and row["task"] == task.hex() and row["setup_charged_once_per_class"] is True,
                "one actual material setup per class")
        for key, expected in (("a", a), ("b", b)):
            require(type(row[key]) is list and len(row[key]) == CELLS and
                    all(type(word) is int for word in row[key]) and row[key] == expected, "exact fixed " + key)
        groups[name]["material"].append(timing(row["setup"], "material setup"))
    expected_rows = [(name, bytes.fromhex(target), sample) for name in CLASSES for target in TARGETS for sample in range(SAMPLES)]
    require(type(values["rows"]) is list and len(values["rows"]) == len(expected_rows), "complete class-target-sample grid")
    claims = []
    for row, (name, target, sample) in zip(values["rows"], expected_rows):
        exact(row, "class sample challenge target search attempt_limit attempts exhausted variants cache_setup cache_destruction "
              "positive_setup positive_target positive_trace positive_control_scope positive_same_attack_target positive", "claim cohort")
        _, _, task, prefix = material(name)
        context = challenge(name, target, sample)
        require(row["class"] == name and integer(row["sample"], "sample") == sample and
                row["challenge"] == context.hex() and row["target"] == target.hex(), "exact challenge/task/target identity")
        require(integer(row["attempt_limit"], "attempt limit") == SEARCH_LIMIT and
                row["positive_control_scope"] == POSITIVE_SCOPE, "fixed search and separately scoped positive control")
        paid = groups[name]
        for key in ("search", "cache_setup", "cache_destruction", "positive_setup"):
            paid[key].append(timing(row[key], key))
        attempts = row["attempts"]
        require(type(attempts) is list and 1 <= len(attempts) <= SEARCH_LIMIT, "bounded complete false-claim search")
        selected = None
        for nonce, attempt in enumerate(attempts):
            exact(attempt, "nonce trace ticket meets_target", "false-claim attempt")
            require(selected is None and integer(attempt["nonce"], "nonce") == nonce, "retain all misses and stop on first hit")
            trace = H(b"false-trace-c-variants-v1", context, nonce.to_bytes(8, "little"))
            ticket = H(b"ticket", context, trace)
            hit = ticket <= target
            require(attempt["trace"] == trace.hex() and attempt["ticket"] == ticket.hex() and attempt["meets_target"] is hit,
                    "exact cheap claim/ticket/target relation")
            if hit:
                selected = trace
        exhausted = selected is None
        require(row["exhausted"] is exhausted and (not exhausted or len(attempts) == SEARCH_LIMIT), "true full-budget exhaustion")
        product, honest_trace = positive_relation(name, context)
        honest_target = H(b"ticket", context, honest_trace)
        require(honest_target != bytes(32) and row["positive_trace"] == honest_trace.hex()
                and row["positive_target"] == honest_target.hex(), "independent W1 positive trace and own-ticket target")
        require(selected != honest_trace, "selected claim is actually false")
        reject_points, accepted_points = progress_counts(context)
        variants = row["variants"]
        require(type(variants) is list and len(variants) == (0 if exhausted else VARIANTS), "all submitted C variants retained")
        transcript_claim = None
        product_claims = set()
        for index, variant in enumerate(variants):
            exact(variant, "variant cached_first proof_commitment construction native_no_cache configured_cache", "C variant")
            require(integer(variant["variant"], "variant index") == index and variant["cached_first"] is ((sample+index) % 2 == 0),
                    "exact variant sequence and paired invocation order")
            proof = bytearray(prefix)
            proof[-32:] = selected
            word = (0, CELLS//2, CELLS-1)[index % 3]
            offset = 4 + 2 * CELLS * 4 + word * 4
            proof[offset:offset+4] = (index+1).to_bytes(4, "little")
            require(variant["proof_commitment"] == H(b"measured-proof", proof).hex(), "exact complete proof commitment")
            claim = H(b"w1-negative-transcript-claim-v2", PROFILE.encode(), context, task, target,
                      proof[:4+2*CELLS*4], proof[-32:])
            require(transcript_claim in (None, claim), "same mathematical transcript claim across C variants")
            transcript_claim = claim
            product_claims.add(H(b"w1-negative-product-claim-v2", claim, proof[4+2*CELLS*4:-32]))
            paid["construction"].append(timing(variant["construction"], "variant construction"))
            paid["native"].append(observation(variant["native_no_cache"], "ordinary no-cache refusal", "Transcript", 512, reject_points))
            paid["cached"].append(observation(variant["configured_cache"], "configured-cache refusal", "Transcript",
                512 if index == 0 else 0, reject_points if index == 0 else 1))
        require(len(product_claims) == len(variants), "distinct exact C claims")
        paid["positive"].append(observation(row["positive"], "own-ticket positive control", "Accepted", 512, accepted_points, product))
        same_target = honest_target <= target
        if same_target:
            paid["positive_same_target"].append(observation(row["positive_same_attack_target"], "eligible positive at fixed attack target",
                "Accepted", 512, accepted_points, product))
        else:
            require(row["positive_same_attack_target"] is None, "ineligible positive is not fixed-target evidence")
        paid["counts"].update(claim_cohorts=1, search_attempts=len(attempts), search_misses=len(attempts)-int(not exhausted),
            target_hits=int(not exhausted), exhausted_searches=int(exhausted), submitted_variants=len(variants),
            native_complete_replays=len(variants), cached_complete_replays=int(not exhausted),
            cached_fact_refusals=max(len(variants)-1, 0), positive_controls=1, eligible_same_target_controls=int(same_target))
        claims.append(dict(material=name, target=target.hex(), sample=sample, challenge=context.hex(),
            negative_transcript_claim=None if transcript_claim is None else transcript_claim.hex(),
            distinct_product_claims=len(product_claims), search_attempts=len(attempts), exhausted=exhausted,
            positive_own_ticket=honest_target.hex(), positive_eligible_at_attack_target=same_target))
    def costs(paid):
        attacker = total(paid["material"] + paid["search"] + paid["construction"])
        native = total(paid["native"])
        cached = total(paid["cache_setup"] + paid["cached"] + paid["cache_destruction"])
        return dict(counts=dict(paid["counts"]), attacker_including_paid_material=attacker,
            receiver_native_no_cache=native, receiver_configured_cache_including_lifecycle=cached,
            native_receiver_over_attacker=ratios(native, attacker), configured_receiver_over_attacker=ratios(cached, attacker),
            configured_over_native_receiver=ratios(cached, native),
            component_totals={key: total(value) for key, value in paid.items() if key != "counts"})
    combined = {key: [] for key in groups[CLASSES[0]] if key != "counts"}
    combined["counts"] = Counter()
    for paid in groups.values():
        for key in combined:
            if key == "counts":
                combined[key].update(paid[key])
            else:
                combined[key].extend(paid[key])
    return dict(schema=SCHEMA+"-readback", record_consistency="PASS", qualification_status="HOLD",
        all_materials_and_claims_retained=True, independent_positive_relation_replays=len(expected_rows),
        totals=costs(combined), per_material_paid_totals={name: costs(paid) for name, paid in groups.items()},
        claims=claims, unknown_costs=dict.fromkeys(UNKNOWN_FIELDS),
        scope=dict(positive_control_target_selection="own exact valid-proof ticket; not the predeclared attack target",
            positive_controls_in_attack_denominator=False, same_target_positive_scope="conditional acceptance of an already generated proof; no paid fixed-target mining search",
            denominator="four actual material preparations once each plus all failed/successful false-claim searches and every C-variant construction",
            configured_receiver_denominator="all actual refusal calls plus one cache setup and destruction per claim cohort",
            positive_setup_and_verification="separate component totals, excluded from refusal ratios",
            ratio_interpretation="ratio of serial local instrumented call sums; not whole-process or end-to-end service cost",
            fresh_claims_still_need_complete_replay=True, changed_c_only_is_not_a_new_transcript_claim=True,
            source_attested=False, clock_attested=False, public_service_measured=False,
            original_resource_gate_passed=False, minimum_work_cost_proved=False, production_activation=False))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key " + key)
        result[key] = value
    return result


def analyze(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular non-linked input")
    require(path.stat().st_size <= MAX_RAW, "bounded stored observation")
    with path.open("rb") as source:
        original = source.read(MAX_RAW + 1)
    require(len(original) <= MAX_RAW, "bounded stored observation read")
    if path.suffix == ".gz":
        with gzip.GzipFile(fileobj=io.BytesIO(original), mode="rb") as source:
            raw = source.read(MAX_RAW + 1)
    else:
        raw = original
    require(len(raw) <= MAX_RAW, "bounded decompressed observation")
    parsed = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON constant " + value)))
    result = summarize(parsed)
    result["stored_input_sha256"] = hashlib.sha256(original).hexdigest()
    result["raw_input_sha256"] = hashlib.sha256(raw).hexdigest()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observation", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.observation), indent=2, sort_keys=True, allow_nan=False))
