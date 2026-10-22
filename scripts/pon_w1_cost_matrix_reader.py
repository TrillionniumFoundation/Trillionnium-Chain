#!/usr/bin/env python3
"""Validate retained W1 cost-matrix-v2 observations, without executing a node.

Default exit 0 means complete, internally consistent records, not cost acceptance.
Exit 1 preserves native semantic disagreements; exit 2 means malformed evidence,
or a failed/unmeasured cost gate when --require-cost-gates is explicitly requested.
This reader reconstructs canonical A/B/C bytes and hashes, but does not replay the
W1 transcript or authenticate the claimed native execution/source/hardware.
"""

import argparse
from collections import Counter
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True

SCHEMA = "pon-w1-all-producers-cost-v2"
PROFILE = Path(__file__).resolve().parents[1] / "config/pon/work-security-acceptance-v1.json"
PROFILE_SHA256 = "4ca674c305112d51672efcab6c0f886e477a5397191addb806d209a08266165f"
Q, N, CELLS = 4_294_967_291, 64, 4096
PROOF_BYTES = 4 + 12 * CELLS + 32
TARGET = "7f" + "ff" * 31
SAMPLES, ATTEMPT_BUDGET, MAX_LINE = 8, 4096, 8 * 1024 * 1024
ARMS = (
    "scalar-original", "prepared-generic", "prepared-structured", "tiled-classical",
    "tiled-strassen-one-level", "paired-product", "blocked-zero",
    "blocked-zero-integer-paired", "blocked-one-zero-rank-one", "maintenance-periodic",
    "maintenance-integer-paired", "maintenance-prefix", "maintenance-limb",
)
CLASSES = (
    "periodic-dense-fixture", "full-rank-field", "zero", "identity", "rank-one",
    "sparse-diagonal", "continuity-maintenance-v1", "one-zero-left-rank-one",
    "one-zero-right-rank-one",
)
VARIANTS = ("from-zero-transcript", "product-last")
PATHS = ("production", "facts-cold", "facts-warm")
EXPECTED_OUTCOME = {"legal": "Accepted", "from-zero-transcript": "Transcript", "product-last": "Product"}
COUNTERS = {"full_replays", "hits", "wait_polls", "evictions"}
FALSE_FLAGS = {
    "public_listener_uses_work_facts": False, "hardness_accepted": False,
    "production_activation": False, "independent_verification": False,
    "source_applicability_verified": False, "fresh_measurement": False,
}
FIELDS = {
    "campaign": "samples attempt_budget seed target arms classes clock material_setup setup_amortization public_listener_uses_work_facts hardness_accepted production_activation",
    "material": "class source task a_hex b_hex",
    "producer": "class sample arm invocation_order task target status setup_calls setup search total attempts winner",
    "candidate": "class sample task target challenge proof_hex proof_sha256",
    "forgery": "class sample variant challenge task target status setup search total attempts winner valid_proof_acquisition_used construction_scope",
    "verifier": "class sample case path challenge task target proof_sha256 outcome timing cache_capacity cache_before cache_after cache_setup warmup",
    "end": "material_count producer_count candidate_count forgery_count verifier_count complete",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), f"{label}: exact fields required")
    return value


def integer(value, label, maximum=2**64 - 1):
    require(type(value) is int and 0 <= value <= maximum, f"{label}: expected bounded nonnegative integer")
    return value


def hex_bytes(value, size, label):
    require(type(value) is str and len(value) == size * 2 and
            re.fullmatch(r"[0-9a-f]*", value) is not None, f"{label}: canonical hex length/encoding")
    return bytes.fromhex(value)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def pon_hash(tag, *parts):
    result = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    for part in parts:
        result.update(len(part).to_bytes(4, "little"))
        result.update(part)
    return result.digest()


def challenge(task, sample, nonce):
    return pon_hash(b"pon-w1-cost-matrix-challenge-v2", task,
                    bytes(8), sample.to_bytes(8, "little"), nonce.to_bytes(8, "little"))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_number(value):
    raise ValueError(f"non-integer JSON number: {value}")


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_number, parse_float=reject_number)


def timing(value, label):
    exact(value, ("cpu_ns", "wall_ns"), label)
    for key, number in value.items():
        if number is not None:
            integer(number, f"{label}.{key}")
    return value


def intervals(row, label, unsupported=False):
    setup, total = timing(row["setup"], label + ".setup"), timing(row["total"], label + ".total")
    if unsupported:
        require(row["search"] is None, label + ": unsupported search must be null")
        search = {axis: 0 for axis in setup}
    else:
        search = timing(row["search"], label + ".search")
    for axis in setup:
        for phase in (setup, search):
            if total[axis] is not None and phase[axis] is not None:
                require(total[axis] >= phase[axis], label + ": phase exceeds inclusive total")
        if all(part[axis] is not None for part in (setup, search, total)):
            require(total[axis] >= setup[axis] + search[axis], label + ": disjoint phases exceed total")


def _rank(values):
    rows = [list(values[start:start + N]) for start in range(0, CELLS, N)]
    rank = 0
    for column in range(N):
        pivot = next((i for i in range(rank, N) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], Q - 2, Q)
        rows[rank][column:] = [(v * inverse) % Q for v in rows[rank][column:]]
        for row in rows[rank + 1:]:
            scale = row[column]
            row[column:] = [(row[j] - scale * rows[rank][j]) % Q for j in range(column, N)]
        rank += 1
    return rank


def _full_rank(label):
    for generation in range(32):
        values = []
        for counter in range(1024):
            digest = pon_hash(b"comparison-material", bytes([label]),
                              generation.to_bytes(4, "little"), counter.to_bytes(4, "little"))
            values.extend(v for v in struct.unpack("<8I", digest) if v < Q)
            if len(values) >= CELLS:
                values = values[:CELLS]
                break
        if len(values) == CELLS and _rank(values) == N:
            return values
    raise ValueError("bounded canonical full-rank material construction exhausted")


@lru_cache(maxsize=len(CLASSES))
def material(name):
    """Exact public diagnostic recipes; no claim about real model provenance."""
    require(name in CLASSES, "unknown material class")
    diagonal = lambda i: i // N == i % N
    if name == "periodic-dense-fixture":
        a, b = [i % 31 for i in range(CELLS)], [(i * 7) % 37 for i in range(CELLS)]
    elif name == "full-rank-field":
        a, b = _full_rank(0), _full_rank(1)
    elif name == "zero":
        a, b = [0] * CELLS, [0] * CELLS
    elif name == "identity":
        a, b = [int(diagonal(i)) for i in range(CELLS)], [int(diagonal(i)) for i in range(CELLS)]
    elif name == "rank-one":
        a = [(i // N + 1) * (i % N + 1) for i in range(CELLS)]
        b = [(i // N + 2) * (i % N + 1) for i in range(CELLS)]
    elif name == "sparse-diagonal":
        a = [i // N + 1 if diagonal(i) else 0 for i in range(CELLS)]
        b = [i // N + 2 if diagonal(i) else 0 for i in range(CELLS)]
    elif name == "continuity-maintenance-v1":
        a = [(13 * i + 17) % 257 for i in range(CELLS)]
        b = [(29 * i + 31) % 263 for i in range(CELLS)]
    else:
        nonzero = [(i // N + 1) * (i % N + 2) for i in range(CELLS)]
        a, b = ([0] * CELLS, nonzero) if name == "one-zero-left-rank-one" else (nonzero, [0] * CELLS)
    raw_a, raw_b = struct.pack(f"<{CELLS}I", *a), struct.pack(f"<{CELLS}I", *b)
    columns = list(zip(*(b[start:start + N] for start in range(0, CELLS, N))))
    product = [sum(x * y for x, y in zip(a[start:start + N], column)) % Q
               for start in range(0, CELLS, N) for column in columns]
    prefix = b"PNW1" + raw_a + raw_b + struct.pack(f"<{CELLS}I", *product)
    return raw_a, raw_b, pon_hash(b"task", raw_a, raw_b), prefix


def supported(arm, name):
    if arm in (ARMS[0], ARMS[1], ARMS[3], ARMS[4], ARMS[5]):
        return True
    if arm == "prepared-structured":
        return name in CLASSES[2:6] or name in CLASSES[7:]
    if arm in ("blocked-zero", "blocked-zero-integer-paired"):
        return name == "zero"
    if arm == "blocked-one-zero-rank-one":
        return name in CLASSES[7:]
    return name == "continuity-maintenance-v1"


def _trials(row, task, sample, prefix, context=None):
    label = f"{row['kind']}/{row['class']}/{sample}"
    trials = row["attempts"]
    require(type(trials) is list and 0 < len(trials) <= ATTEMPT_BUDGET, label + ": complete bounded trial list required")
    stream, last = [], None
    for nonce, trial in enumerate(trials):
        exact(trial, ("nonce", "challenge", "trace", "ticket", "proof_sha256", "target_hit"), label + ".trial")
        require(integer(trial["nonce"], label + ".nonce") == nonce, label + ": nonconsecutive nonce")
        expected_challenge = context if context is not None else challenge(task, sample, nonce)
        require(hex_bytes(trial["challenge"], 32, label) == expected_challenge, label + ": challenge recipe mismatch")
        trace = hex_bytes(trial["trace"], 32, label)
        if context is not None:
            require(trace == pon_hash(b"public-v3-from-zero-v1", context, nonce.to_bytes(8, "little")), label + ": false trace recipe mismatch")
            require(trial["proof_sha256"] is None, label + ": false trial must not claim a constructed buffer")
        else:
            hex_bytes(trial["proof_sha256"], 32, label)
            require(trial["proof_sha256"] == sha(prefix + trace), label + ": full trial proof SHA mismatch")
        ticket = pon_hash(b"ticket", expected_challenge, trace)
        require(hex_bytes(trial["ticket"], 32, label) == ticket, label + ": ticket hash mismatch")
        hit = ticket <= bytes.fromhex(TARGET)
        require(type(trial["target_hit"]) is bool and trial["target_hit"] == hit, label + ": target-hit mismatch")
        require(not hit or nonce == len(trials) - 1, label + ": first target hit did not stop search")
        stream.append((nonce, expected_challenge, trace, ticket, trial["proof_sha256"], hit))
        last = trial
    won = row["status"] == "target-hit-unverified"
    require(row["status"] in ("target-hit-unverified", "exhausted") and last["target_hit"] == won, label + ": search status mismatch")
    require(won or len(trials) == ATTEMPT_BUDGET, label + ": exhaustion omitted attempts")
    return tuple(stream), last


class Records:
    def __init__(self):
        self.counts, self.materials, self.producers = Counter(), {}, {}
        self.cohorts, self.candidates, self.forgeries, self.verifiers = {}, {}, {}, {}
        self.current_stream = None
        self.campaign, self.ended = None, False
        self.alerts = []

    def context(self, row):
        name = row["class"]
        require(type(name) is str and name in self.materials, "context: class/material not available")
        sample = integer(row["sample"], "sample", SAMPLES - 1)
        require(row["task"] == self.materials[name][2].hex() and row["target"] == TARGET, "context: task/target mismatch")
        return name, sample

    def add(self, row):
        require(not self.ended, "records after end")
        require(type(row) is dict and row.get("schema") == SCHEMA, "record schema mismatch")
        kind = row.get("kind")
        require(type(kind) is str and kind in FIELDS, "unknown record kind")
        exact(row, {"schema", "kind", *FIELDS[kind].split()}, kind)
        require(self.campaign is not None or kind == "campaign", "campaign must be first")
        getattr(self, "add_" + kind)(row)
        self.counts[kind] += 1

    def add_campaign(self, row):
        require(self.campaign is None, "duplicate campaign")
        for name, value in (("samples", SAMPLES), ("attempt_budget", ATTEMPT_BUDGET), ("seed", 0)):
            require(integer(row[name], name) == value, "fixed campaign parameter changed: " + name)
        require(row["target"] == TARGET and row["arms"] == list(ARMS) and row["classes"] == list(CLASSES), "campaign target/grid/order changed")
        require(row["clock"] == "thread-cpu-and-monotonic-wall-ns", "campaign clock changed")
        require(row["setup_amortization"] == "modeled-setup-divisor-not-observed-multiwinner", "campaign amortization scope changed")
        for flag in ("public_listener_uses_work_facts", "hardness_accepted", "production_activation"):
            require(row[flag] is False, "campaign cannot grant authority: " + flag)
        timing(row["material_setup"], "campaign.material_setup")
        self.campaign = row

    def add_material(self, row):
        index = len(self.materials)
        require(index < len(CLASSES) and row["class"] == CLASSES[index], "material coverage/order mismatch")
        name = row["class"]
        expected_source = "hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture"
        require(row["source"] == expected_source, "material source declaration mismatch")
        a, b, task, prefix = material(name)
        require(hex_bytes(row["a_hex"], CELLS * 4, "A") == a and hex_bytes(row["b_hex"], CELLS * 4, "B") == b, "material recipe/canonical bytes mismatch")
        require(row["task"] == task.hex(), "material task hash mismatch")
        self.materials[name] = (a, b, task, prefix)

    def add_producer(self, row):
        key = self.context(row)
        index = self.counts["producer"]
        class_index, remainder = divmod(index, SAMPLES * len(ARMS))
        sample, order = divmod(remainder, len(ARMS))
        require(class_index < len(CLASSES) and key == (CLASSES[class_index], sample), "producer cohort/order/coverage mismatch")
        arm = ARMS[(sample + order) % len(ARMS)]
        require(row["arm"] == arm and integer(row["invocation_order"], "invocation_order", len(ARMS) - 1) == order, "producer invocation rotation mismatch")
        require(integer(row["setup_calls"], "setup_calls") == 1, "setup not measured once")
        is_supported = supported(arm, key[0])
        intervals(row, str((key, arm)), unsupported=not is_supported)
        if order == 0:
            self.current_stream = None
            self.cohorts[key] = {"count": 0, "status": None, "last": None}
        self.cohorts[key]["count"] += 1
        if not is_supported:
            require(row["status"] == "unsupported" and row["attempts"] == [] and row["winner"] is None, "unsupported arm misreported")
        else:
            _, _, task, prefix = self.materials[key[0]]
            stream, last = _trials(row, task, sample, prefix)
            if self.current_stream is None:
                self.current_stream = stream
                self.cohorts[key].update(status=row["status"], last=last)
            else:
                require(stream == self.current_stream and row["status"] == self.cohorts[key]["status"], "supported legal streams disagree")
            if row["status"] == "target-hit-unverified":
                exact(row["winner"], ("challenge", "proof_sha256"), "producer.winner")
                require(row["winner"] == {field: last[field] for field in ("challenge", "proof_sha256")}, "producer winner does not match final trial")
            else:
                require(row["winner"] is None, "exhausted producer has winner")
        self.producers[key + (arm,)] = {field: row[field] for field in ("status", "setup", "search", "total")}
        self.producers[key + (arm,)]["attempt_count"] = len(row["attempts"])

    def add_candidate(self, row):
        key = self.context(row)
        require(key in self.cohorts and key not in self.candidates and self.cohorts[key]["count"] == len(ARMS), "candidate before complete arms or duplicate")
        cohort = self.cohorts[key]
        require(cohort["status"] == "target-hit-unverified", "candidate for exhausted cohort")
        proof = hex_bytes(row["proof_hex"], PROOF_BYTES, "candidate.proof")
        expected = self.materials[key[0]][3] + bytes.fromhex(cohort["last"]["trace"])
        require(proof == expected, "candidate canonical A/B/C/trace bytes mismatch")
        require(row["proof_sha256"] == sha(proof) == cohort["last"]["proof_sha256"], "candidate SHA does not bind complete proof")
        require(row["challenge"] == cohort["last"]["challenge"], "candidate challenge mismatch")
        self.candidates[key] = {"proof": proof, "challenge": bytes.fromhex(row["challenge"]), "sha": sha(proof)}

    def add_forgery(self, row):
        key = self.context(row)
        require(key in self.candidates, "forgery before candidate")
        candidate = self.candidates[key]
        variant = row["variant"]
        require(type(variant) is str and variant in VARIANTS and key + (variant,) not in self.forgeries, "unknown/duplicate forgery")
        require(row["challenge"] == candidate["challenge"].hex(), "forgery public context changed")
        intervals(row, "forgery")
        acquired = variant == "product-last"
        require(row["valid_proof_acquisition_used"] is acquired, "forgery acquisition scope mismatch")
        scope = "existing-valid-proof-clone-and-canonical-last-cell-increment" if acquired else "full-public-prefix-and-all-hash-trials"
        require(row["construction_scope"] == scope, "forgery construction scope mismatch")
        if acquired:
            require(row["status"] == "target-hit-unverified" and row["attempts"] == [], "product mutation must not search or exhaust")
            buffer = bytearray(candidate["proof"])
            offset = PROOF_BYTES - 36
            struct.pack_into("<I", buffer, offset, (struct.unpack_from("<I", buffer, offset)[0] + 1) % Q)
            proof = bytes(buffer)
        else:
            a, b, task, _ = self.materials[key[0]]
            _, last = _trials(row, task, key[1], None, candidate["challenge"])
            proof = b"PNW1" + a + b + bytes(4 * CELLS) + bytes.fromhex(last["trace"]) if row["status"] == "target-hit-unverified" else None
        if proof is not None:
            exact(row["winner"], ("trace", "proof_sha256"), "forgery.winner")
            require(row["winner"] == {"trace": proof[-32:].hex(), "proof_sha256": sha(proof)}, "forgery full-byte SHA/trace mismatch")
        else:
            require(row["winner"] is None, "exhausted forgery claims winner")
        self.forgeries[key + (variant,)] = {"proof": proof, "row": row}

    def add_verifier(self, row):
        key = self.context(row)
        require(key in self.candidates, "verifier before candidate")
        require(type(row["case"]) is str and row["case"] in EXPECTED_OUTCOME and type(row["path"]) is str and row["path"] in PATHS, "unknown verifier case/path")
        identity = key + (row["case"], row["path"])
        require(identity not in self.verifiers, "duplicate verifier")
        timing(row["timing"], "verifier.timing")
        require(row["challenge"] == self.candidates[key]["challenge"].hex(), "verifier context changed")
        hex_bytes(row["proof_sha256"], 32, "verifier.proof_sha256")
        self.verifiers[identity] = row

    def add_end(self, row):
        require(row["complete"] is True, "incomplete native campaign")
        for kind in ("material", "producer", "candidate", "forgery", "verifier"):
            require(integer(row[kind + "_count"], kind + "_count") == self.counts[kind], "end count mismatch: " + kind)
        require(self.counts["material"] == len(CLASSES) and self.counts["producer"] == len(CLASSES) * SAMPLES * len(ARMS), "incomplete fixed material/producer grid")
        expected_candidates = {key for key, cohort in self.cohorts.items() if cohort["status"] == "target-hit-unverified"}
        require(set(self.candidates) == expected_candidates, "candidate coverage mismatch")
        expected_forgeries = {key + (variant,) for key in expected_candidates for variant in VARIANTS}
        require(set(self.forgeries) == expected_forgeries, "forgery coverage mismatch")
        expected_verifiers = {key + ("legal", path) for key in expected_candidates for path in PATHS}
        expected_verifiers.update(key + (path,) for key, value in self.forgeries.items() if value["proof"] is not None for path in PATHS)
        require(set(self.verifiers) == expected_verifiers, "available-proof verifier coverage mismatch")
        for identity, verifier in self.verifiers.items():
            self.check_verifier(identity, verifier)
        self.ended = True

    def alert(self, identity, stage, actual, expected):
        require(type(actual) is str and 0 < len(actual) <= 128 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", actual), "invalid native outcome string")
        if actual != expected:
            self.alerts.append({"class": identity[0], "sample": identity[1], "case": identity[2], "path": identity[3], "stage": stage, "expected": expected, "actual": actual})

    def check_verifier(self, identity, row):
        key, case, path = identity[:2], identity[2], identity[3]
        candidate = self.candidates[key]
        proof = candidate["proof"] if case == "legal" else self.forgeries[key + (case,)]["proof"]
        require(proof is not None and row["proof_sha256"] == sha(proof), "verifier did not use exact available proof")
        self.alert(identity, "requested", row["outcome"], EXPECTED_OUTCOME[case])
        cache_fields = ("cache_capacity", "cache_before", "cache_after", "cache_setup", "warmup")
        if path == "production":
            require(all(row[field] is None for field in cache_fields), "production verification cannot claim a fact cache")
            return
        require(integer(row["cache_capacity"], "cache_capacity") == 256, "cache capacity changed")
        timing(row["cache_setup"], "cache_setup")
        for field in ("cache_before", "cache_after"):
            exact(row[field], COUNTERS, field)
            for counter, value in row[field].items():
                integer(value, counter)
        before, after = row["cache_before"], row["cache_after"]
        warm = path == "facts-warm"
        warmup_ok = False
        if warm:
            exact(row["warmup"], ("timing", "outcome", "proof_sha256"), "warmup")
            timing(row["warmup"]["timing"], "warmup.timing")
            require(row["warmup"]["proof_sha256"] == candidate["sha"], "warmup must acquire the genuine candidate")
            self.alert(identity, "warmup", row["warmup"]["outcome"], "Accepted")
            warmup_ok = row["warmup"]["outcome"] == "Accepted"
        else:
            require(row["warmup"] is None, "cold cache cannot be prewarmed")
        if warm and not warmup_ok:
            # Unavailable/cheap-error warmup can finish before starting replay.
            require(before["full_replays"] <= 1 and all(before[field] == 0 for field in ("hits", "wait_polls", "evictions")), "failed warmup initial counters mismatch")
        else:
            require(before == {"full_replays": int(warm), "hits": 0, "wait_polls": 0, "evictions": 0}, "cache initial counters mismatch")
        # On an unexpected native verdict preserve the evidence and mark it bad;
        # do not demand the successful-verdict counter pattern from a failed run.
        if row["outcome"] != EXPECTED_OUTCOME[case] or (warm and not warmup_ok):
            require(all(after[field] >= before[field] for field in COUNTERS), "cache counters regressed")
            require(after["full_replays"] - before["full_replays"] + after["hits"] - before["hits"] <= 1
                    and after["wait_polls"] == 0 and after["evictions"] - before["evictions"] <= 1,
                    "unexpected-verdict counters exceed the one sequential invocation")
            return
        hit = warm and case in ("legal", "product-last")
        eviction = 0
        if warm and not hit:
            task = self.materials[key[0]][2]
            slot = lambda trace: int.from_bytes(pon_hash(b"w1-mathematical-fact-slot-v1", b"pon-matmul-transcript-64-v1", candidate["challenge"], task, trace)[:8], "little") % 256
            eviction = int(slot(candidate["proof"][-32:]) == slot(proof[-32:]))
        expected = {"full_replays": int(warm) + int(not hit), "hits": int(hit), "wait_polls": 0, "evictions": eviction}
        require(after == expected, "cache cold/warm replay/hit/eviction mismatch")


def distribution(values):
    known = [value for value in values if value is not None]
    return {"observations": len(values), "known": len(known), "unknown": len(values) - len(known),
            "known_sum_ns": sum(known), "minimum_ns": min(known) if known else None,
            "maximum_ns": max(known) if known else None}


def fraction(value):
    return None if value is None else {"numerator": value.numerator, "denominator": value.denominator, "value": float(value)}


def mean(values, positive=True):
    if len(values) != SAMPLES or any(value is None or (value <= 0 if positive else value < 0) for value in values):
        return None
    return Fraction(sum(values), SAMPLES)


def combined(statuses):
    return "not-accepted" if "not-accepted" in statuses else "unmeasured" if "unmeasured" in statuses else "pass"


def compare(numerator, denominator, minimum=False, coverage=True):
    ratio = numerator / denominator if numerator is not None and denominator is not None and denominator > 0 else None
    if ratio is None:
        gate = "unmeasured"
    elif (ratio < 1 if minimum else ratio > 1):
        gate = "not-accepted"
    else:
        gate = "pass" if coverage else "unmeasured"
    return {"ratio": fraction(ratio), "gate": gate}


def cache_costs(samples):
    setup = mean([value["cache_setup"]["cpu_ns"] if value else None for value in samples], positive=False)
    warmup = mean([value["warmup"]["timing"]["cpu_ns"] if value and value["warmup"] else (0 if value else None) for value in samples], positive=False)
    requested = mean([value["timing"]["cpu_ns"] if value else None for value in samples])
    inclusive = setup + warmup + requested if all(value is not None for value in (setup, warmup, requested)) else None
    return {"cache_setup_cpu_mean_ns": fraction(setup), "warmup_cpu_mean_ns": fraction(warmup),
            "request_plus_cache_setup_and_warmup_cpu_mean_ns": fraction(inclusive), "warmup_is_free": False}


def cost_summary(records, policy):
    rows, cohorts = [], []
    for name in CLASSES:
        arm_means = {}
        for arm in ARMS:
            samples = [records.producers[name, sample, arm] for sample in range(SAMPLES)]
            totals = [sample["total"]["cpu_ns"] for sample in samples]
            setups = [sample["setup"]["cpu_ns"] for sample in samples]
            won = all(sample["status"] == "target-hit-unverified" for sample in samples)
            total, setup = mean(totals), mean(setups, positive=False)
            eligible = supported(arm, name) and won and total is not None and setup is not None
            if eligible:
                arm_means[arm] = (total, setup)
            cohorts.append({"class": name, "arm": arm, "supported": supported(arm, name),
                            "status_counts": dict(Counter(sample["status"] for sample in samples)),
                            "observed_winning_searches": sum(sample["status"] == "target-hit-unverified" for sample in samples),
                            "attempts": sum(sample["attempt_count"] for sample in samples),
                            "total_cpu_ns": distribution(totals), "setup_cpu_ns": distribution(setups),
                            "total_wall_ns": distribution([sample["total"]["wall_ns"] for sample in samples]),
                            "setup_wall_ns": distribution([sample["setup"]["wall_ns"] for sample in samples]),
                            "eligible_for_fixed_cohort_selection": eligible})
        complete = len(arm_means) == sum(supported(arm, name) for arm in ARMS)
        for horizon in policy["setup_amortization_winners"]:
            estimates = {arm: total - setup + setup / horizon for arm, (total, setup) in arm_means.items()}
            selected = min(estimates, key=estimates.get) if estimates else None
            cheapest = estimates.get(selected)
            paths = {}
            for path in PATHS:
                verification = [records.verifiers.get((name, sample, "legal", path)) for sample in range(SAMPLES)]
                request = mean([value["timing"]["cpu_ns"] if value else None for value in verification])
                path_result = {"legal_requested_cpu_mean_ns": fraction(request),
                               "winner_to_verifier": compare(cheapest, request, minimum=True, coverage=complete), "forgeries": {}}
                for variant in VARIANTS:
                    forged = [records.forgeries.get((name, sample, variant)) for sample in range(SAMPLES)]
                    consumed = mean([value["row"]["total"]["cpu_ns"] if value and value["proof"] is not None else None for value in forged])
                    rejected = [records.verifiers.get((name, sample, variant, path)) for sample in range(SAMPLES)]
                    rejection = mean([value["timing"]["cpu_ns"] if value else None for value in rejected])
                    path_result["forgeries"][variant] = {"measured_total_construction_cpu_mean_ns": fraction(consumed),
                        "requested_rejection_cpu_mean_ns": fraction(rejection),
                        "marginal_rejection_amplification": compare(rejection, consumed),
                        "genuine_proof_acquisition_charged_again": False,
                        "requires_previously_acquired_genuine_proof": variant == "product-last"}
                    if path != "production":
                        path_result["forgeries"][variant].update(cache_costs(rejected))
                if path != "production":
                    path_result["legal_cache_costs"] = cache_costs(verification)
                numeric_gate = combined([path_result["winner_to_verifier"]["gate"], *[value["marginal_rejection_amplification"]["gate"] for value in path_result["forgeries"].values()]])
                path_result["measured_cost_gate"] = numeric_gate
                path_result["cost_gate"] = "not-accepted" if any(alert["class"] == name and alert["path"] == path for alert in records.alerts) else numeric_gate
                paths[path] = path_result
            rows.append({"class": name, "target": TARGET, "sample_count": SAMPLES,
                         "setup_amortization_winners": horizon, "amortization_is_modeled": True,
                         "observed_winning_searches_per_supported_arm": sum((name, sample) in records.candidates for sample in range(SAMPLES)),
                         "all_supported_cohorts_measured": complete,
                         "selected_fixed_cohort_algorithm": selected,
                         "known_algorithm_modeled_cpu_ns": {arm: fraction(value) for arm, value in estimates.items()},
                         "cheapest_known_cohort_mean_cpu_ns": fraction(cheapest), "verification_paths": paths,
                         "default_cost_gate": paths["production"]["cost_gate"]})
    gate = combined([row["default_cost_gate"] for row in rows])
    return {"producer_cohorts": cohorts, "costs": rows,
            "local_cost_gate": "not-accepted" if records.alerts else gate}


def analyze(path):
    path = Path(path)
    policy_raw = PROFILE.read_bytes()
    require(sha(policy_raw) == PROFILE_SHA256, "original acceptance profile bytes changed")
    policy = decode(policy_raw)
    require(policy["minimum_cost_samples_per_class"] == SAMPLES and policy["setup_amortization_winners"] == [1, 8, 64]
            and policy["minimum_winner_to_verifier_ratio"] == policy["maximum_marginal_rejection_amplification"] == 1
            and policy["production_activation"] is False and policy["consensus_parameter"] is False, "original acceptance policy changed")
    records, digest, size, number = Records(), hashlib.sha256(), 0, 0
    with path.open("rb") as source:
        while True:
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            number += 1
            require(len(line) <= MAX_LINE and line.endswith(b"\n"), f"line {number}: oversized/truncated JSONL record")
            digest.update(line)
            size += len(line)
            try:
                records.add(decode(line))
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ValueError(f"line {number}: {error}") from error
    require(records.ended, "missing complete end record")
    return {"schema": "pon-w1-cost-matrix-observation-report-v2", "record_consistency": "PASS",
            "input_sha256": digest.hexdigest(), "input_bytes": size, "record_count": number,
            "record_counts": dict(records.counts), "profile_sha256": sha(policy_raw),
            "semantic_alerts": records.alerts, **cost_summary(records, policy),
            "material_setup": records.campaign["material_setup"], "material_setup_charged_per_producer": False,
            "local_observation_gate": "not-accepted", "service": {"status": "unmeasured"},
            "matrix_product_reconstructed": True, "w1_transcript_replayed": False,
            "default_verification_path": "production", "cache_paths_replace_default_gate": False,
            "limitations": ["Native verdicts, clocks and source/binary identity require separate provenance verification.",
                "A/B/C and hashes are checked; the W1 transcript is not independently replayed.",
                "Only eight fixed diagnostic searches per supported algorithm/class are observed.",
                "Setup division by 1/8/64 models reuse; 64 winning searches were not observed.",
                "One fixed supplied algorithm is selected per entire cohort, never per sample.",
                "Supplied algorithm means do not lower-bound adversarial implementations or hardware.",
                "Producer total includes retained-trial SHA/hex/allocation bookkeeping, excludes final JSON serialization; verifier timing measures the native verification call only.",
                "Cached requests retain separately measured acquisition/warmup; the public path remains uncached.",
                "No public service saturation, production qualification or work hardness is established."],
            **FALSE_FLAGS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--require-cost-gates", action="store_true")
    args = parser.parse_args()
    try:
        value = analyze(args.input)
    except (OSError, ValueError, OverflowError) as error:
        print(json.dumps({"record_consistency": "FAIL", "error": str(error), "local_cost_gate": "unmeasured",
                          "local_observation_gate": "not-accepted", "service": {"status": "unmeasured"}, **FALSE_FLAGS}, sort_keys=True))
        return 2
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    if args.require_cost_gates and value["local_cost_gate"] != "pass":
        return 2
    return 1 if value["semantic_alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
