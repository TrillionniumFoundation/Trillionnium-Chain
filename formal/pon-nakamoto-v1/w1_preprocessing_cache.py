"""Bounded, executable cross-challenge preprocessing for complete W1 proofs.

This classical producer caches only exact-input AB products and SHA checkpoints.
It rebuilds challenge-dependent noise, every ordered trace prefix and the ticket
on every attempt, including target misses. The trace/product relation is checked
independently after each complete proof. A cache hit never selects a nonce.

Cache capacities count canonical key/value payload bytes, not Python allocator
overhead. Every lookup, comparison, read, write, refusal and eviction is counted.
These operation counts are not a physical time/energy conversion or a lower
bound for arbitrary algorithms. Runtime observations belong in a separate ledger.
"""
from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import struct

from quantum_oracle_resources import integer
from w1_preprocessing_reuse import (_canonical_template, _padded, FIXED_BLOCKS)
from w1_quantum_oracle import SOURCE_FILES, canonical, h_bytes
from w1_quantum_primitives import INITIAL_STATE, digest_bytes, message_value, sha_compress

SCHEMA = "trnm-w1-complete-proof-preprocessing-cache-v1"
ROOT = Path(__file__).resolve().parents[2]
SOURCES = SOURCE_FILES + (
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-nakamoto-v1/quantum_oracle_resources.py",
    "formal/pon-nakamoto-v1/w1_preprocessing_reuse.py",
    "formal/pon-nakamoto-v1/w1_preprocessing_cache.py",
)
MAX_CONTEXTS = 16
MAX_ATTEMPTS = 128
MAX_CACHE_BYTES = 16 * 1024 * 1024
CACHE_COUNTERS = (
    "lookups", "hits", "misses", "key_bytes_compared", "value_bytes_read",
    "insertions", "insertion_refusals", "key_and_value_bytes_written", "evictions",
    "key_and_value_bytes_evicted",
)
WORK_COUNTERS = (
    "challenge_sha_compressions", "cached_challenge_sha_compressions_reused",
    "ab_products_computed", "ab_products_reused", "ab_field_multiply_add_pairs",
    "noise_hashes", "noise_raw_words_checked", "low_rank_field_multiply_add_pairs",
    "offset_field_additions", "trace_field_multiply_add_pairs", "trace_prefix_words",
    "trace_input_bytes_hashed", "ticket_input_bytes_hashed", "proof_bytes_materialized",
)


def _sources():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _field(values):
    return struct.pack("<" + "I" * len(values), *values)


class PayloadLRU:
    """Deterministic linear LRU with exact byte comparison, never digest equality.

    The payload limit includes each complete key and immutable value. A too-large
    entry is refused without evicting other entries. Computation still completes
    without storing that result, and the refusal remains in the ledger.
    """
    def __init__(self, capacity_bytes):
        integer(capacity_bytes, "CACHE_CAPACITY", 0, MAX_CACHE_BYTES)
        self.capacity_bytes = capacity_bytes
        self.entries = []
        self.resident_bytes = 0
        self.peak_resident_bytes = 0
        self.counters = Counter({name: 0 for name in CACHE_COUNTERS})

    def _equal(self, left, right):
        # The integer length check precedes byte comparisons; it is not claimed
        # to cost zero CPU, only to inspect no key-payload bytes.
        if len(left) != len(right):
            return False
        for a, b in zip(left, right):
            self.counters["key_bytes_compared"] += 1
            if a != b:
                return False
        return True

    def get(self, key):
        if type(key) is not bytes:
            raise ValueError("CACHE_KEY_BYTES")
        self.counters["lookups"] += 1
        for index, (old_key, value) in enumerate(self.entries):
            if self._equal(key, old_key):
                self.entries.append(self.entries.pop(index))
                self.counters["hits"] += 1
                self.counters["value_bytes_read"] += len(value)
                return value
        self.counters["misses"] += 1
        return None

    def put_new(self, key, value):
        if type(key) is not bytes or type(value) is not bytes or not key or not value:
            raise ValueError("CACHE_ENTRY_BYTES")
        # Callers insert only after a miss for this immutable key. Checking that
        # precondition is charged as a separate exact-key scan.
        for old_key, _ in self.entries:
            if self._equal(key, old_key):
                raise ValueError("CACHE_DUPLICATE_INSERTION")
        amount = len(key) + len(value)
        if amount > self.capacity_bytes:
            self.counters["insertion_refusals"] += 1
            return
        while self.resident_bytes + amount > self.capacity_bytes:
            old_key, old_value = self.entries.pop(0)
            freed = len(old_key) + len(old_value)
            self.resident_bytes -= freed
            self.counters["evictions"] += 1
            self.counters["key_and_value_bytes_evicted"] += freed
        self.entries.append((key, value))
        self.resident_bytes += amount
        self.peak_resident_bytes = max(self.peak_resident_bytes, self.resident_bytes)
        self.counters["insertions"] += 1
        self.counters["key_and_value_bytes_written"] += amount

    def record(self):
        return {
            "capacity_payload_bytes": self.capacity_bytes,
            "resident_payload_bytes": self.resident_bytes,
            "peak_resident_payload_bytes": self.peak_resident_bytes,
            "resident_entries": len(self.entries),
            "counters": dict(self.counters),
            "lru_state_sha256": _hash([[key.hex(), value.hex()] for key, value in self.entries]),
            "python_objects_allocator_and_transient_workspace_included_in_capacity": False,
        }


def _challenge(template, nonce, cache, work):
    frame = h_bytes(template.challenge_tag, template.header_for(nonce))
    nonce_start = len(frame) - len(template.header) + template.nonce_offset
    if nonce_start < 64 * FIXED_BLOCKS:
        raise ValueError("CACHE_NONCE_INSIDE_FIXED_PREFIX")
    padded = _padded(frame)
    state, shared = INITIAL_STATE, 0
    # All keys contain the actual tagged/framed prefix. Changing a parent,
    # target, profile, or task cannot reuse a stale incompatible checkpoint.
    for blocks in range(FIXED_BLOCKS, 0, -1):
        key = b"TRNM-W1-SHA-CHECKPOINT1\0" + bytes([blocks]) + frame[:64 * blocks]
        value = cache.get(key)
        if value is not None:
            if len(value) != 32:
                raise ValueError("CACHE_SHA_VALUE_SIZE")
            state, shared = int.from_bytes(value, "little"), blocks
            break
    work["cached_challenge_sha_compressions_reused"] += shared
    for blocks in range(shared, FIXED_BLOCKS):
        state = sha_compress(message_value(padded[64 * blocks:64 * (blocks + 1)]), state)
        work["challenge_sha_compressions"] += 1
        key = b"TRNM-W1-SHA-CHECKPOINT1\0" + bytes([blocks + 1]) + frame[:64 * (blocks + 1)]
        cache.put_new(key, state.to_bytes(32, "little"))
    for offset in range(64 * FIXED_BLOCKS, len(padded), 64):
        state = sha_compress(message_value(padded[offset:offset + 64]), state)
        work["challenge_sha_compressions"] += 1
    return digest_bytes(state)


def _mm(a, b, rows, inner, cols, modulus):
    return [sum(a[i * inner + k] * b[k * cols + j] for k in range(inner)) % modulus
            for i in range(rows) for j in range(cols)]


def _cached_ab(template, cache, work):
    n, modulus = template.shape.n, template.shape.q
    # R, rejection cap, parent, target, profile and nonce are not AB inputs.
    # Conversely, equal task digests alone would not bind the field modulus.
    key = b"TRNM-W1-AB-CACHE1\0" + struct.pack("<II", n, modulus) + _field(template.a) + _field(template.b)
    product = cache.get(key)
    if product is None:
        product = _field(_mm(template.a, template.b, n, n, n, modulus))
        work["ab_products_computed"] += 1
        work["ab_field_multiply_add_pairs"] += n**3
        cache.put_new(key, product)
    else:
        work["ab_products_reused"] += 1
    if len(product) != 4 * n * n:
        raise ValueError("CACHE_AB_VALUE_SIZE")
    return product


def produce(template, nonce, cache):
    """Actually construct every proof byte; misses still pay complete materialization."""
    template = _canonical_template(template)
    integer(nonce, "CACHE_NONCE", 0, (1 << template.nonce_bits) - 1)
    if type(cache) is not PayloadLRU:
        raise ValueError("CACHE_TYPE")
    work = Counter({name: 0 for name in WORK_COUNTERS})
    before = dict(cache.counters)
    challenge = _challenge(template, nonce, cache, work)
    n, r, modulus = template.shape.n, template.shape.r, template.shape.q
    factors, complete = [], []
    for label_index in range(4):
        words = []
        for counter in range(template.shape.noise_counters):
            block = hashlib.sha256(h_bytes(b"noise", challenge, bytes([label_index]),
                                          struct.pack("<I", counter))).digest()
            work["noise_hashes"] += 1
            for (raw,) in struct.iter_unpack("<I", block):
                value = raw & ((1 << template.shape.field_bits) - 1)
                work["noise_raw_words_checked"] += 1
                if value < modulus:
                    words.append(value)
            if len(words) >= n * r:
                break
        complete.append(len(words) >= n * r)
        factors.append(words[:n * r])
    proof = None
    trace = ticket = None
    if all(complete):
        product = _cached_ab(template, cache, work)
        e = _mm(factors[0], factors[1], n, r, n, modulus)
        f = _mm(factors[2], factors[3], n, r, n, modulus)
        work["low_rank_field_multiply_add_pairs"] += 2 * n * n * r
        ap = [(x + y) % modulus for x, y in zip(template.a, e)]
        bp = [(x + y) % modulus for x, y in zip(template.b, f)]
        work["offset_field_additions"] += 2 * n * n
        cells = [0] * (n * n)
        transcript = bytearray(b"TRNM-PON-TRACE1\0" + challenge)
        for i0 in range(0, n, r):
            for j0 in range(0, n, r):
                for k0 in range(0, n, r):
                    for i in range(i0, i0 + r):
                        for j in range(j0, j0 + r):
                            position = i * n + j
                            cells[position] = (cells[position] + sum(
                                ap[i * n + k] * bp[k * n + j] for k in range(k0, k0 + r))) % modulus
                            work["trace_field_multiply_add_pairs"] += r
                            work["trace_prefix_words"] += 1
                            transcript.extend(struct.pack("<I", cells[position]))
        trace = hashlib.sha256(transcript).digest()
        ticket_input = h_bytes(b"ticket", challenge, trace)
        ticket = hashlib.sha256(ticket_input).digest()
        work["trace_input_bytes_hashed"] += len(transcript)
        work["ticket_input_bytes_hashed"] += len(ticket_input)
        proof = b"PNW1" + _field(template.a) + _field(template.b) + product + trace
        work["proof_bytes_materialized"] += len(proof)
    outcome = ("NOISE_EXHAUSTED" if proof is None else
               "TARGET_HIT" if int.from_bytes(ticket, "big") <= template.target else "TARGET_MISS")
    record = {
        "nonce": nonce, "template_sha256": _hash(template.spec()),
        "challenge": challenge.hex(), "noise_complete": complete,
        "trace": None if trace is None else trace.hex(),
        "ticket": None if ticket is None else ticket.hex(), "outcome": outcome,
        "proof_sha256": None if proof is None else hashlib.sha256(proof).hexdigest(),
        "proof_bytes": 0 if proof is None else len(proof),
        "work_units": dict(work),
        "cache_counter_delta": {key: cache.counters[key] - before[key] for key in CACHE_COUNTERS},
        "resident_payload_bytes_after": cache.resident_bytes,
    }
    return record, proof


def _check_exhaustion(record, proof):
    if (proof is not None or record["outcome"] != "NOISE_EXHAUSTED"
            or record["proof_sha256"] is not None or record["proof_bytes"] != 0
            or record["trace"] is not None or record["ticket"] is not None
            or type(record["noise_complete"]) is not list or len(record["noise_complete"]) != 4
            or any(type(value) is not bool for value in record["noise_complete"])
            or all(record["noise_complete"])):
        raise ValueError("CACHE_EXHAUSTION_MISMATCH")


def verify_complete_attempt(template, nonce, record, proof):
    """Independent scalar relation; verification work is separate from producer work.

    Native shape uses work_oracle.evaluate, which derives AB through the low-rank
    correction identity instead of the cached direct multiplication. Reduced
    controls use the separately organized macro relation and a separate product
    loop. Neither path admits a block or promotes a reduced shape to native W1.
    """
    template = _canonical_template(template)
    challenge = hashlib.sha256(h_bytes(template.challenge_tag, template.header_for(nonce))).digest()
    if record["nonce"] != nonce or record["template_sha256"] != _hash(template.spec()) or record["challenge"] != challenge.hex():
        raise ValueError("CACHE_ATTEMPT_INPUT_BINDING")
    if template.shape.native:
        import work_oracle
        try:
            product, trace = work_oracle.evaluate(challenge, list(template.a), list(template.b))
        except ValueError as error:
            if str(error) != "NOISE_BUDGET":
                raise
            _check_exhaustion(record, proof)
            expected_complete = []
            for label_index in range(4):
                try:
                    work_oracle.expand(challenge, label_index, template.shape.n * template.shape.r)
                    expected_complete.append(True)
                except ValueError as exhausted:
                    if str(exhausted) != "NOISE_BUDGET":
                        raise
                    expected_complete.append(False)
            if record["noise_complete"] != expected_complete:
                raise ValueError("CACHE_EXHAUSTION_MISMATCH") from error
            return {"relation": "independent-native-work-oracle", "full_relation_checked": True,
                    "complete_proof": False, "native_block_admitted": False}
        expected = b"PNW1" + _field(template.a) + _field(template.b) + _field(product) + trace
        expected_complete = [True] * 4
        relation = "independent-native-work-oracle"
    else:
        from w1_quantum_oracle import OracleProgram
        reference = OracleProgram(template).execute(nonce)
        trace = bytes.fromhex(reference["trace"])
        expected_complete = reference["noise_complete"]
        size, product = template.shape.n, []
        for i in range(size):
            for j in range(size):
                value = 0
                for k in range(size):
                    value = (value + template.a[i * size + k] * template.b[k * size + j]) % template.shape.q
                product.append(value)
        expected = (b"PNW1" + _field(template.a) + _field(template.b) + _field(product) + trace) if all(expected_complete) else None
        relation = "independent-reduced-macro-control"
    if proof != expected or record["noise_complete"] != expected_complete:
        raise ValueError("CACHE_COMPLETE_PROOF_MISMATCH")
    if expected is None:
        _check_exhaustion(record, proof)
    else:
        ticket = hashlib.sha256(h_bytes(b"ticket", challenge, trace)).digest()
        outcome = "TARGET_HIT" if int.from_bytes(ticket, "big") <= template.target else "TARGET_MISS"
        if (record["trace"] != trace.hex() or record["ticket"] != ticket.hex() or record["outcome"] != outcome
                or record["proof_sha256"] != hashlib.sha256(expected).hexdigest() or record["proof_bytes"] != len(expected)):
            raise ValueError("CACHE_TICKET_OR_PROOF_BINDING")
    return {"relation": relation, "full_relation_checked": True,
            "complete_proof": expected is not None, "native_block_admitted": False}


def validate_plan(templates, schedule, capacities):
    if type(templates) is not tuple or not 1 <= len(templates) <= MAX_CONTEXTS:
        raise ValueError("CACHE_TEMPLATE_LIST")
    checked = tuple(_canonical_template(value) for value in templates)
    if type(schedule) is not tuple or not 1 <= len(schedule) <= MAX_ATTEMPTS:
        raise ValueError("CACHE_SCHEDULE")
    for action in schedule:
        if type(action) is not tuple or len(action) != 2:
            raise ValueError("CACHE_ACTION")
        index, nonce = action
        integer(index, "CACHE_CONTEXT_INDEX", 0, len(checked) - 1)
        integer(nonce, "CACHE_NONCE", 0, (1 << checked[index].nonce_bits) - 1)
    if type(capacities) is not tuple or not 1 <= len(capacities) <= 8:
        raise ValueError("CACHE_CAPACITY_LIST")
    for value in capacities:
        integer(value, "CACHE_CAPACITY", 0, MAX_CACHE_BYTES)
    if len(set(capacities)) != len(capacities):
        raise ValueError("CACHE_DUPLICATE_CAPACITY")
    return checked


def execute_cache_comparison(templates, schedule, capacities=(0, 4096, 262144), *, observe=None):
    """Identical fixed attempt order for every cold-started cache capacity.

    An optional observer times calls without changing inputs or outputs. It gets
    a stage label and zero-argument callable and returns that callable's value.
    Its measurements remain separate from this deterministic relation record.
    """
    templates = validate_plan(templates, schedule, capacities)
    sources = _sources()
    invoke = (lambda name, call: call()) if observe is None else observe
    cells = []
    baseline = None
    for capacity in capacities:
        cache = PayloadLRU(capacity)
        attempts, work = [], Counter({name: 0 for name in WORK_COUNTERS})
        for index, (context, nonce) in enumerate(schedule):
            result, proof = invoke((capacity, index, "producer"), lambda: produce(templates[context], nonce, cache))
            verification = invoke((capacity, index, "independent_full_relation_check"),
                lambda: verify_complete_attempt(templates[context], nonce, result, proof))
            work.update(result["work_units"])
            attempts.append({"attempt_index": index, "context_index": context, **result,
                             "verification": verification})
        outcomes = [{key: row[key] for key in ("context_index", "nonce", "challenge", "trace", "ticket",
                    "outcome", "proof_sha256", "proof_bytes")} for row in attempts]
        if baseline is None:
            baseline = outcomes
        elif outcomes != baseline:
            raise ValueError("CACHE_STRATEGIES_CHANGED_COMPLETE_RESULTS")
        cells.append({"capacity_payload_bytes": capacity, "initial_cache": "empty",
            "attempts": attempts, "work_units_total": dict(work), "cache": cache.record(),
            "target_hits": sum(row["outcome"] == "TARGET_HIT" for row in attempts),
            "target_misses": sum(row["outcome"] == "TARGET_MISS" for row in attempts),
            "noise_exhaustions": sum(row["outcome"] == "NOISE_EXHAUSTED" for row in attempts),
            "all_attempts_and_failures_retained": True})
    report = {
        "schema": SCHEMA, "source_sha256": sources,
        "templates": [value.spec() for value in templates], "schedule": [list(value) for value in schedule],
        "capacities_payload_bytes": list(capacities), "cells": cells,
        "native_shape": all(value.shape.native for value in templates),
        "same_complete_proof_outcomes_across_capacities": True,
        "cache_keys": {"AB": "exact A/B bytes, matrix dimension and field modulus",
            "SHA": "exact tagged/framed header prefix, checkpoint block count and cache namespace"},
        "scope": {
            "cache_policy": "linear exact-byte LRU, empty at each independent capacity run",
            "AB": "proof-product preprocessing; no reduction of coherent W1 oracle arithmetic is inferred",
            "SHA": "classical nonce-header checkpoints only; full suffix always hashed",
            "fresh_per_attempt": "noise, ordered trace, ticket and complete proof serialization, also for target misses",
            "verification": "separately executed complete scalar relation after every producer attempt",
            "memory": "bounded resident key/value payload; Python objects and transient workspace need process-level measurement",
            "time_and_energy": "operation counts only; runtime observations are separate and do not calibrate a QPU",
            "distinct_queries": "no claim that equal cached inputs produce independent cryptographic queries",
        },
        "claims": {"native_block_admission_executed": False, "all_legal_caches_or_algorithms_enumerated": False,
            "physical_costs_calibrated": False, "same_total_economic_budget_proved": False,
            "quantum_hardware_executed": False, "quantum_oracle_cost_reduced_by_ab_cache_proved": False,
            "minimum_attacker_cost_proved": False, "quantum_mining_qualified": False,
            "production_activation": False},
    }
    if _sources() != sources:
        raise ValueError("CACHE_SOURCE_CHANGED")
    report["record_sha256"] = _hash(report)
    return report


def verify_cache_comparison(report):
    """Re-execute all actual cache operations and every complete relation check."""
    if type(report) is not dict or report.get("schema") != SCHEMA:
        raise ValueError("CACHE_REPORT")
    from w1_quantum_oracle import template_from_spec
    if (type(report.get("templates")) is not list or not 1 <= len(report["templates"]) <= MAX_CONTEXTS
            or type(report.get("schedule")) is not list or not 1 <= len(report["schedule"]) <= MAX_ATTEMPTS
            or any(type(entry) is not list or len(entry) != 2 for entry in report["schedule"])
            or type(report.get("capacities_payload_bytes")) is not list):
        raise ValueError("CACHE_SERIALIZED_PLAN")
    rebuilt = execute_cache_comparison(tuple(template_from_spec(value) for value in report["templates"]),
        tuple(tuple(value) for value in report["schedule"]), tuple(report["capacities_payload_bytes"]))
    if canonical(rebuilt) != canonical(report):
        raise ValueError("CACHE_REPLAY_MISMATCH")
    return rebuilt
