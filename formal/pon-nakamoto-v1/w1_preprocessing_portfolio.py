"""Complete W1 producers with charged, bounded preprocessing portfolios.

The four classical algorithms compute identical complete proof bytes.  In
particular, recovering AB from the mandatory ordered trace does not skip that
trace.  Rank-one detection is exact and its dense fallback is explicit.  Cache
keys contain complete inputs, not only hashes.  No coherent quantum oracle,
all-algorithm lower bound, calibrated time bound, or native admission is proved.

Stage-prefix censoring stops before a declared atomic stage.  A caller may use
an observed deadline to choose that prefix; non-preemptive overruns and runtime
costs belong in the separate observation ledger.  Every planned attempt remains
in the record, including partial attempts and attempts never started.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import struct

from quantum_oracle_resources import integer
from w1_preprocessing_cache import (
    CACHE_COUNTERS, SOURCES as CACHE_SOURCES, WORK_COUNTERS as CACHE_WORK_COUNTERS,
    PayloadLRU, _challenge, _field, _mm, validate_plan, verify_complete_attempt,
)
from w1_preprocessing_reuse import _canonical_template
from w1_quantum_oracle import ROOT, canonical, h_bytes, template_from_spec

SCHEMA = "trnm-w1-complete-proof-preprocessing-portfolio-v1"
CELL_SCHEMA = "trnm-w1-preprocessing-portfolio-cell-v1"
STRATEGIES = ("direct-ab", "trace-correction-ab", "sparse-ab", "rank-aware-ab")
CAPACITIES = (0, 4096, 65536, 262144)
SOURCES = CACHE_SOURCES + ("formal/pon-nakamoto-v1/w1_preprocessing_portfolio.py",)
WORK_COUNTERS = CACHE_WORK_COUNTERS + (
    "ab_correction_field_multiply_add_pairs", "ab_correction_field_subtractions",
    "ab_sparse_input_values_scanned", "ab_sparse_zero_products_skipped",
    "ab_sparse_field_multiply_add_pairs", "ab_rank_factorizations_attempted",
    "ab_rank_pivot_values_scanned", "ab_rank_inverse_calls",
    "ab_rank_inverse_failures", "ab_rank_factor_field_multiplications",
    "ab_rank_equality_checks", "ab_rank_product_field_multiply_add_pairs",
    "ab_rank_outer_field_multiplications",
    "ab_rank_zero_products", "ab_rank_left_products", "ab_rank_right_products",
    "ab_rank_dense_fallback_products", "ab_modular_reductions",
    "independent_direct_product_field_multiply_add_pairs",
)
CLAIMS = {
    "all_legal_algorithms_or_caches_enumerated": False,
    "global_minimum_attacker_cost_proved": False,
    "same_total_economic_budget_proved": False,
    "native_block_admission_executed": False,
    "physical_hardware_costs_calibrated": False,
    "quantum_oracle_cost_reduced_by_classical_cache_proved": False,
    "quantum_hardware_executed": False,
    "quantum_mining_qualified": False,
    "production_activation": False,
}
ATTEMPT_STAGES = ("input_binding", "challenge", "noise", "offset_matrices",
                  "ordered_trace", "proof_product", "proof_and_ticket",
                  "independent_full_relation_check")


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in SOURCES}


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _dense_product(a, b, n, q, work):
    out = _mm(a, b, n, n, n, q)
    work["ab_field_multiply_add_pairs"] += n**3
    work["ab_modular_reductions"] += n * n
    return out


def _sparse_product(a, b, n, q, work):
    """Skip only exact zero scalar products; all inspections remain counted."""
    rows = []
    for i in range(n):
        row = []
        for k in range(n):
            value = a[i * n + k]
            work["ab_sparse_input_values_scanned"] += 1
            if value != 0:
                row.append((k, value))
        work["ab_sparse_zero_products_skipped"] += (n - len(row)) * n
        rows.append(row)
    out = [0] * (n * n)
    for i, row in enumerate(rows):
        for k, left in row:
            for j in range(n):
                right = b[k * n + j]
                work["ab_sparse_input_values_scanned"] += 1
                if right == 0:
                    work["ab_sparse_zero_products_skipped"] += 1
                else:
                    out[i * n + j] += left * right
                    work["ab_sparse_field_multiply_add_pairs"] += 1
    work["ab_modular_reductions"] += n * n
    return [value % q for value in out]


def _rank_one(a, n, q, work):
    """Return an exact rank-one factorization, zero, or a charged refusal.

    Reduced controls can use composite moduli.  A non-invertible pivot then
    refuses this optimization; the explicit dense algorithm still computes the
    original relation.  No probabilistic rank test is used.
    """
    work["ab_rank_factorizations_attempted"] += 1
    pivot = None
    for position, value in enumerate(a):
        work["ab_rank_pivot_values_scanned"] += 1
        if value != 0:
            pivot = position
            break
    if pivot is None:
        return "zero", None
    i0, j0 = divmod(pivot, n)
    work["ab_rank_inverse_calls"] += 1
    try:
        inverse = pow(a[pivot], -1, q)
    except ValueError:
        work["ab_rank_inverse_failures"] += 1
        return "refused-noninvertible-pivot", None
    left = [a[i * n + j0] for i in range(n)]
    right = [(a[i0 * n + j] * inverse) % q for j in range(n)]
    work["ab_rank_factor_field_multiplications"] += n
    work["ab_modular_reductions"] += n
    for i in range(n):
        for j in range(n):
            work["ab_rank_factor_field_multiplications"] += 1
            work["ab_rank_equality_checks"] += 1
            work["ab_modular_reductions"] += 1
            if left[i] * right[j] % q != a[i * n + j]:
                return "refused-not-rank-one", None
    return "rank-one", (left, right)


def _rank_product(a, b, n, q, work):
    left_kind, factors = _rank_one(a, n, q, work)
    paths = ["A:" + left_kind]
    if left_kind == "zero":
        work["ab_rank_zero_products"] += 1
        return [0] * (n * n), paths + ["zero-product"]
    if left_kind == "rank-one":
        u, v = factors
        middle = _mm(v, b, 1, n, n, q)
        out = [(u[i] * middle[j]) % q for i in range(n) for j in range(n)]
        work["ab_rank_product_field_multiply_add_pairs"] += n * n
        work["ab_rank_outer_field_multiplications"] += n * n
        work["ab_modular_reductions"] += n + n * n
        work["ab_rank_left_products"] += 1
        return out, paths + ["rank-one-left-product"]
    right_kind, factors = _rank_one(b, n, q, work)
    paths.append("B:" + right_kind)
    if right_kind == "zero":
        work["ab_rank_zero_products"] += 1
        return [0] * (n * n), paths + ["zero-product"]
    if right_kind == "rank-one":
        u, v = factors
        middle = _mm(a, u, n, n, 1, q)
        out = [(middle[i] * v[j]) % q for i in range(n) for j in range(n)]
        work["ab_rank_product_field_multiply_add_pairs"] += n * n
        work["ab_rank_outer_field_multiplications"] += n * n
        work["ab_modular_reductions"] += n + n * n
        work["ab_rank_right_products"] += 1
        return out, paths + ["rank-one-right-product"]
    work["ab_rank_dense_fallback_products"] += 1
    return _dense_product(a, b, n, q, work), paths + ["charged-dense-product"]


def _ab_key(template):
    return (b"TRNM-W1-PORTFOLIO-AB1\0"
            + struct.pack("<II", template.shape.n, template.shape.q)
            + _field(template.a) + _field(template.b))


def _product(template, strategy, cache, factors, bp, trace_cells, work):
    n, r, q = template.shape.n, template.shape.r, template.shape.q
    key = _ab_key(template)
    encoded = cache.get(key)
    if encoded is not None:
        if len(encoded) != 4 * n * n:
            raise ValueError("PORTFOLIO_AB_VALUE_SIZE")
        work["ab_products_reused"] += 1
        return encoded, ["exact-key-cache-hit"]
    work["ab_products_computed"] += 1
    if strategy == "direct-ab":
        product = _dense_product(template.a, template.b, n, q, work)
        path = ["direct-dense-product"]
    elif strategy == "trace-correction-ab":
        # C'=(A+El Er)(B+Fl Fr).  Both ordered trace and its final C'
        # have already actually been computed by this producer.
        c1 = _mm(_mm(template.a, factors[2], n, n, r, q),
                 factors[3], n, r, n, q)
        c2 = _mm(factors[0], _mm(factors[1], bp, r, n, n, q),
                 n, r, n, q)
        product = [(x - y - z) % q for x, y, z in zip(trace_cells, c1, c2)]
        work["ab_correction_field_multiply_add_pairs"] += 4 * n * n * r
        work["ab_correction_field_subtractions"] += 2 * n * n
        work["ab_modular_reductions"] += 3 * n * n + 2 * n * r
        path = ["full-trace-low-rank-correction"]
    elif strategy == "sparse-ab":
        product = _sparse_product(template.a, template.b, n, q, work)
        path = ["exact-zero-skipping-product"]
    elif strategy == "rank-aware-ab":
        product, path = _rank_product(template.a, template.b, n, q, work)
    else:
        raise ValueError("PORTFOLIO_STRATEGY")
    encoded = _field(product)
    cache.put_new(key, encoded)
    return encoded, ["exact-key-cache-miss"] + path


def verify_attempt(template, nonce, record, proof):
    """Independent native/reduced trace relation plus a direct scalar AB check.

    The additional product loop prevents the trace-correction producer from
    sharing its AB recovery identity with the existing native oracle verifier.
    Its CPU work is separately timed and counted by the portfolio executor.
    """
    relation = verify_complete_attempt(template, nonce, record, proof)
    direct_mac = 0
    if proof is not None:
        n, q = template.shape.n, template.shape.q
        product = []
        for i in range(n):
            for j in range(n):
                value = 0
                for k in range(n):
                    value = (value + template.a[i * n + k] * template.b[k * n + j]) % q
                    direct_mac += 1
                product.append(value)
        start = 4 + 8 * n * n
        if proof[start:start + 4 * n * n] != _field(product):
            raise ValueError("PORTFOLIO_INDEPENDENT_DIRECT_AB_MISMATCH")
    return {**relation, "direct_AB_scalar_check": proof is not None,
            "independent_direct_product_field_multiply_add_pairs": direct_mac}


class _Censored(Exception):
    def __init__(self, identity):
        super().__init__("PORTFOLIO_STAGE_PREFIX_CENSORED")
        self.identity = identity


def run_cell(templates, schedule, strategy, capacity, *, max_stages=None,
             observer=None, admit=None):
    """Execute all planned attempts or an explicitly retained stage prefix.

    ``observer(identity, callable)`` observes actual executions.  An optional
    ``admit(identity)`` can refuse the next stage; it cannot select a nonce or
    replace inputs.  Replay uses the exact completed prefix, not its CPU times.
    """
    templates = validate_plan(templates, schedule, (capacity,))
    if type(strategy) is not str or strategy not in STRATEGIES:
        raise ValueError("PORTFOLIO_STRATEGY")
    if max_stages is not None:
        integer(max_stages, "PORTFOLIO_STAGE_LIMIT", 0, 1 + 8 * len(schedule))
    invoke = (lambda identity, call: call()) if observer is None else observer
    stages, attempts = [], []
    cache = None
    work_total = Counter({name: 0 for name in WORK_COUNTERS})
    current_identity = None
    stop, failure = None, None

    def stage(index, name, call):
        nonlocal current_identity
        current_identity = (index, name)
        if max_stages is not None and len(stages) >= max_stages:
            raise _Censored(current_identity)
        if admit is not None:
            allowed = admit(current_identity)
            if type(allowed) is not bool:
                raise ValueError("PORTFOLIO_ADMISSION_BOOL")
            if not allowed:
                raise _Censored(current_identity)
        value = invoke(current_identity, call)
        stages.append(list(current_identity))
        return value

    def blank(index, context, nonce):
        return {"attempt_index": index, "context_index": context, "nonce": nonce,
                "status": "NOT_STARTED", "completed_stages": [], "next_stage": "input_binding",
                "template_sha256": None, "challenge": None, "noise_complete": None,
                "trace": None, "ticket": None, "outcome": "NOT_STARTED",
                "proof_sha256": None, "proof_bytes": 0, "product_path": [],
                "verification": None, "work_units": {key: 0 for key in WORK_COUNTERS},
                "cache_counter_delta": {key: 0 for key in CACHE_COUNTERS},
                "resident_payload_bytes_after": None}

    attempts = [blank(index, context, nonce) for index, (context, nonce) in enumerate(schedule)]
    try:
        cache = stage(-1, "initialize_cache", lambda: PayloadLRU(capacity))
        for index, (context, nonce) in enumerate(schedule):
            row, work = attempts[index], Counter({name: 0 for name in WORK_COUNTERS})
            before = dict(cache.counters)
            proof = None
            start_count = len(stages)
            try:
                def bind():
                    checked = _canonical_template(templates[context])
                    return checked, _hash(checked.spec())
                template, row["template_sha256"] = stage(index, "input_binding", bind)
                row["status"], row["outcome"] = "PARTIAL", "PENDING"
                challenge = stage(index, "challenge", lambda: _challenge(template, nonce, cache, work))
                row["challenge"] = challenge.hex()
                n, r, q = template.shape.n, template.shape.r, template.shape.q

                def noise():
                    factors, complete = [], []
                    for label in range(4):
                        words = []
                        for counter in range(template.shape.noise_counters):
                            block = hashlib.sha256(h_bytes(b"noise", challenge, bytes([label]),
                                                          struct.pack("<I", counter))).digest()
                            work["noise_hashes"] += 1
                            for (raw,) in struct.iter_unpack("<I", block):
                                value = raw & ((1 << template.shape.field_bits) - 1)
                                work["noise_raw_words_checked"] += 1
                                if value < q:
                                    words.append(value)
                            if len(words) >= n * r:
                                break
                        factors.append(words[:n * r])
                        complete.append(len(words) >= n * r)
                    return factors, complete
                factors, row["noise_complete"] = stage(index, "noise", noise)
                if all(row["noise_complete"]):
                    def offset():
                        e = _mm(factors[0], factors[1], n, r, n, q)
                        f = _mm(factors[2], factors[3], n, r, n, q)
                        work["low_rank_field_multiply_add_pairs"] += 2 * n * n * r
                        work["offset_field_additions"] += 2 * n * n
                        return ([(x + y) % q for x, y in zip(template.a, e)],
                                [(x + y) % q for x, y in zip(template.b, f)])
                    ap, bp = stage(index, "offset_matrices", offset)

                    def ordered_trace():
                        cells = [0] * (n * n)
                        transcript = bytearray(b"TRNM-PON-TRACE1\0" + challenge)
                        for i0 in range(0, n, r):
                            for j0 in range(0, n, r):
                                for k0 in range(0, n, r):
                                    for i in range(i0, i0 + r):
                                        for j in range(j0, j0 + r):
                                            pos = i * n + j
                                            cells[pos] = (cells[pos] + sum(
                                                ap[i * n + k] * bp[k * n + j]
                                                for k in range(k0, k0 + r))) % q
                                            work["trace_field_multiply_add_pairs"] += r
                                            work["trace_prefix_words"] += 1
                                            transcript.extend(struct.pack("<I", cells[pos]))
                        work["trace_input_bytes_hashed"] += len(transcript)
                        return cells, hashlib.sha256(transcript).digest()
                    cells, trace = stage(index, "ordered_trace", ordered_trace)
                    row["trace"] = trace.hex()
                    product, row["product_path"] = stage(index, "proof_product", lambda:
                        _product(template, strategy, cache, factors, bp, cells, work))

                    def serialize():
                        message = h_bytes(b"ticket", challenge, trace)
                        ticket = hashlib.sha256(message).digest()
                        proof = b"PNW1" + _field(template.a) + _field(template.b) + product + trace
                        work["ticket_input_bytes_hashed"] += len(message)
                        work["proof_bytes_materialized"] += len(proof)
                        return proof, ticket
                    proof, ticket = stage(index, "proof_and_ticket", serialize)
                    row.update(ticket=ticket.hex(), proof_sha256=hashlib.sha256(proof).hexdigest(),
                               proof_bytes=len(proof), outcome="TARGET_HIT" if int.from_bytes(ticket, "big")
                               <= template.target else "TARGET_MISS")
                else:
                    row["outcome"] = "NOISE_EXHAUSTED"
                verification = stage(index, "independent_full_relation_check", lambda:
                    verify_attempt(template, nonce, row, proof))
                row["verification"] = verification
                work["independent_direct_product_field_multiply_add_pairs"] += verification[
                    "independent_direct_product_field_multiply_add_pairs"]
                row["status"], row["next_stage"] = "VERIFIED", None
            except _Censored as censored:
                row["next_stage"] = censored.identity[1]
                raise
            finally:
                row["completed_stages"] = [entry[1] for entry in stages[start_count:]]
                row["work_units"] = dict(work)
                row["cache_counter_delta"] = {key: cache.counters[key] - before[key] for key in CACHE_COUNTERS}
                row["resident_payload_bytes_after"] = cache.resident_bytes
                work_total.update(work)
    except _Censored as censored:
        stop = list(censored.identity)
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error),
                   "stage": None if current_identity is None else list(current_identity)}
    status = "FAILED" if failure is not None else "CENSORED" if stop is not None else "COMPLETE"
    result = {
        "schema": CELL_SCHEMA, "strategy": strategy, "capacity_payload_bytes": capacity,
        "initial_cache": "empty", "status": status, "failure": failure,
        "planned_attempt_count": len(schedule), "attempts": attempts,
        "completed_stages": stages, "completed_stage_count": len(stages),
        "stopped_before": stop,
        "attempts_verified": sum(row["status"] == "VERIFIED" for row in attempts),
        "attempts_not_started": sum(row["status"] == "NOT_STARTED" for row in attempts),
        "attempts_partial": sum(row["status"] == "PARTIAL" for row in attempts),
        "verified_target_hits": sum(row["status"] == "VERIFIED" and row["outcome"] == "TARGET_HIT" for row in attempts),
        "verified_target_misses": sum(row["status"] == "VERIFIED" and row["outcome"] == "TARGET_MISS" for row in attempts),
        "verified_noise_exhaustions": sum(row["status"] == "VERIFIED" and row["outcome"] == "NOISE_EXHAUSTED" for row in attempts),
        "work_units_total": dict(work_total), "cache": None if cache is None else cache.record(),
        "native_shape": all(template.shape.native for template in templates),
        "claims": dict(CLAIMS),
    }
    result["record_sha256"] = _hash(result)
    return result


def verify_cell(cell, templates, schedule):
    """Replay the admitted prefix, including cache state and unused denominator."""
    if (type(cell) is not dict or cell.get("schema") != CELL_SCHEMA
            or cell.get("status") not in ("COMPLETE", "CENSORED")
            or cell.get("claims") != CLAIMS
            or cell.get("record_sha256") != _hash({k: v for k, v in cell.items() if k != "record_sha256"})):
        raise ValueError("PORTFOLIO_CELL_RECORD")
    limit = cell["completed_stage_count"] if cell["status"] == "CENSORED" else None
    rebuilt = run_cell(templates, schedule, cell["strategy"], cell["capacity_payload_bytes"], max_stages=limit)
    if canonical(cell) != canonical(rebuilt):
        raise ValueError("PORTFOLIO_CELL_REPLAY_MISMATCH")
    return rebuilt


def execute_portfolio(templates, schedule, capacities=CAPACITIES, strategies=STRATEGIES,
                      *, max_stages=None):
    templates = validate_plan(templates, schedule, capacities)
    if (type(strategies) is not tuple or not strategies or len(set(strategies)) != len(strategies)
            or any(type(name) is not str or name not in STRATEGIES for name in strategies)):
        raise ValueError("PORTFOLIO_STRATEGY_LIST")
    sources = source_hashes()
    cells = [run_cell(templates, schedule, strategy, capacity, max_stages=max_stages)
             for strategy in strategies for capacity in capacities]
    if any(cell["status"] == "FAILED" for cell in cells):
        raise ValueError("PORTFOLIO_UNEXPECTED_CELL_FAILURE")
    identities = {}
    for cell in cells:
        for row in cell["attempts"]:
            if row["status"] != "VERIFIED":
                continue
            identity = {key: row[key] for key in ("context_index", "nonce", "challenge", "noise_complete",
                        "trace", "ticket", "outcome", "proof_sha256", "proof_bytes")}
            prior = identities.setdefault(row["attempt_index"], identity)
            if identity != prior:
                raise ValueError("PORTFOLIO_ALGORITHM_PROOF_MISMATCH")
    result = {"schema": SCHEMA, "source_sha256": sources,
        "templates": [template.spec() for template in templates],
        "schedule": [list(action) for action in schedule],
        "capacities_payload_bytes": list(capacities), "strategies": list(strategies),
        "max_stages_per_cell": max_stages, "cells": cells,
        "same_verified_complete_results_across_algorithms": True,
        "cache_scope": "exact A/B/dimension/modulus and exact framed SHA prefix; no guessed cross-task reuse",
        "memory_scope": "resident cache key/value payload only; interpreter, objects and transient buffers separate",
        "censoring_scope": "whole declared stage prefix; no wall-time guarantee or free incomplete work",
        "claims": dict(CLAIMS)}
    if source_hashes() != sources:
        raise ValueError("PORTFOLIO_SOURCE_CHANGED")
    result["record_sha256"] = _hash(result)
    return result


def verify_portfolio(report):
    if (type(report) is not dict or report.get("schema") != SCHEMA
            or report.get("claims") != CLAIMS or report.get("source_sha256") != source_hashes()
            or report.get("record_sha256") != _hash({k: v for k, v in report.items() if k != "record_sha256"})):
        raise ValueError("PORTFOLIO_REPORT")
    rebuilt = execute_portfolio(tuple(template_from_spec(value) for value in report["templates"]),
        tuple(tuple(value) for value in report["schedule"]), tuple(report["capacities_payload_bytes"]),
        tuple(report["strategies"]), max_stages=report["max_stages_per_cell"])
    if canonical(report) != canonical(rebuilt):
        raise ValueError("PORTFOLIO_REPLAY_MISMATCH")
    return rebuilt
