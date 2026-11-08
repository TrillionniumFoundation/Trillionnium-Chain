"""Finite stateful W1 optimization observations with full scalar replay.

This is a Python component experiment, not native admission or a minimum-cost
certificate. The old V5 native rank/batch experiment remains a separate source.
Every issued complete attempt, miss, withheld hit and controlled cancellation
stays in the declared cohort. Timings are observations of this one process.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import time

import work_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
N, R, Q = 64, 8, 4294967291
CELLS, PROOF_BYTES = N * N, 49188
MAX_TARGET = b"\xff" * 32
SCHEMA = "pon-legal-optimization-observation-v1"
CATALOG_PATH = "formal/pon-nakamoto-v1/contracts/legal-optimization-catalog-v1.json"
SOURCE_PATHS = (
    CATALOG_PATH,
    "config/pon/work-profile-v1.json",
    "config/pon/ledger-v1.json",
    "config/pon/model-family-v1.json",
    "config/pon/devnet-v1.json",
    "formal/pon-nakamoto-v1/legal_optimization_catalog_v1.py",
    "formal/pon-nakamoto-v1/test_legal_optimization_catalog_v1.py",
    "docs/protocol/pon-nakamoto-v1/details/LEGAL_OPTIMIZATION_CATALOG_V1.md",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-nakamoto-v1/vectors/header.bin",
)
EXPECTED_CATALOG = {
    "schema": "pon-legal-optimization-catalog-v1",
    "work_profile": "pon-matmul-transcript-64-v1",
    "profiles": ["PNH1", "PGH2"],
    "materials": ["dense", "left-rank-2", "right-rank-4", "zero"],
    "strategies": ["eager-recompute", "prepared-dense", "prepared-rank-8"],
    "complete_nonces": [0, 1, 2, 3],
    "batch_width": 2,
    "cancelled_nonce": 4,
    "cancel_after_transcript_tiles": 1,
    "rank_bound": 8,
    "selection": "first-original-target-hit-in-declared-nonce-order-or-none",
    "bank": "all-complete-candidates-retained-one-local-extraction-no-network-publication",
    "miss_replay": "complete-relation-at-maximum-diagnostic-target-and-separate-original-target-refusal",
    "native_admission": False,
    "minimum_legal_cost_proved": False,
    "production_activation": False,
}
CLAIMS = {
    "finite_declared_python_grid_only": True,
    "original_64_by_64_PNW1_relation": True,
    "complete_misses_and_withheld_candidates_retained": True,
    "controlled_partial_cancellations_retained": True,
    "native_node_admission_executed": False,
    "STARK_proofs_generated": False,
    "all_legal_optimizations_covered": False,
    "all_adversary_initial_state_accounted": False,
    "minimum_legal_cost_proved": False,
    "quantum_cost_envelope_qualified": False,
    "physical_resources_completely_billed": False,
    "network_publication_or_chainwork_observed": False,
    "production_activation": False,
}
MAX_REPORT_BYTES = 8 * 1024 * 1024
COST_SCOPE = {
    "producer": "inclusive-process-CPU-and-wall-with-setup-batches-all-issued-attempts-bank-and-teardown",
    "attempt": "per-thread-CPU-nested-in-producer-do-not-add-to-inclusive-total",
    "shared_material": "one-separate-common-cost-not-free-and-not-added-to-each-cohort",
    "shared_templates": "one-measured-construction-per-profile-and-material-not-repeated-per-strategy",
    "source_and_output_IO": "outside-producer-windows-not-completely-billed",
    "verification": "separate-fresh-full-scalar-replay-not-in-producer-timer",
    "native_admission_cpu_ns": None, "STARK_generation_cpu_ns": None,
    "energy_joules": None, "aggregate_peak_memory_bytes": None,
    "GPU_cost": None, "network_bytes": None,
    "physical_cost_lower_bound": None,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value, name, high=(1 << 64) - 1):
    require(type(value) is int and 0 <= value <= high, name)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def strict_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_REPORT_BYTES, "JSON_BOUND")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def reject(value):
        raise ValueError("NONINTEGER_OR_NONFINITE_JSON:" + value)
    return json.loads(raw, object_pairs_hook=unique, parse_float=reject,
                      parse_constant=reject)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def framed_hash(tag, *parts):
    raw = b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
    return hashlib.sha256(raw + b"".join(struct.pack("<I", len(p)) + p
                                       for p in parts)).digest()


def field_bytes(values):
    return struct.pack("<" + "I" * len(values), *values)


def matrix(values):
    require(type(values) in (list, tuple) and len(values) == CELLS, "MATRIX")
    require(all(type(v) is int and 0 <= v < Q for v in values), "FIELD")
    return tuple(values)


def mm(a, b, rows, inner, columns):
    return tuple(sum(a[i * inner + k] * b[k * columns + j]
                     for k in range(inner)) % Q
                 for i in range(rows) for j in range(columns))


@dataclass(frozen=True)
class Template:
    """A syntactically fixed header, not a native eligible task/parent claim."""
    header: bytes
    a: tuple
    b: tuple

    def __post_init__(self):
        require(type(self.header) is bytes, "HEADER_BYTES")
        pnh = len(self.header) == 318 and self.header[:6] == b"PNH1\x01\0"
        pgh = len(self.header) == 354 and self.header[:10] == b"PGH2PNH1\x01\0"
        require(pnh or pgh, "HEADER_VERSION")
        require(type(self.a) is tuple and type(self.b) is tuple, "MATRIX_TUPLE")
        matrix(self.a)
        matrix(self.b)
        require(self.header[self.nonce_offset:self.nonce_offset + 8] == bytes(8),
                "NONZERO_TEMPLATE_NONCE")
        require(self.task == framed_hash(b"task", field_bytes(self.a), field_bytes(self.b)),
                "HEADER_TASK_BINDING")
        require(self.target != bytes(32), "ZERO_TARGET")

    @property
    def profile(self):
        return "PNH1" if len(self.header) == 318 else "PGH2"

    @property
    def base(self):
        return 0 if self.profile == "PNH1" else 4

    @property
    def nonce_offset(self):
        return self.base + 310

    @property
    def task(self):
        return self.header[self.base + 278:self.base + 310]

    @property
    def target(self):
        return self.header[self.base + 118:self.base + 150]

    def header_for(self, nonce):
        natural(nonce, "NONCE")
        return (self.header[:self.nonce_offset] + struct.pack("<Q", nonce)
                + self.header[self.nonce_offset + 8:])

    def challenge(self, nonce):
        tag = b"challenge" if self.profile == "PNH1" else b"permanent-account-growth-challenge-v2"
        return framed_hash(tag, self.header_for(nonce))

    def bank_domain(self, source_identity):
        require(type(source_identity) is bytes and len(source_identity) == 32,
                "BANK_SOURCE_IDENTITY")
        return hashlib.sha256(b"TRNM-W1-LEGAL-BANK1\0" + source_identity
                              + self.header).digest()


class CandidateBank:
    """Bounded untrusted bytes: a cache lookup grants no verification authority."""
    def __init__(self, template, source_identity):
        require(type(template) is Template, "TEMPLATE_TYPE")
        self.domain = template.bank_domain(source_identity)
        self.entries, self.extracted = {}, set()

    def store(self, template, source_identity, nonce, proof):
        require(type(template) is Template, "TEMPLATE_TYPE")
        require(template.bank_domain(source_identity) == self.domain, "BANK_DOMAIN")
        natural(nonce, "NONCE")
        require(nonce not in self.entries and nonce not in self.extracted, "BANK_DUPLICATE")
        require(len(self.entries) < 4, "BANK_CAPACITY")
        require(type(proof) is bytes and len(proof) == PROOF_BYTES, "BANK_BYTES")
        self.entries[nonce] = proof

    def take(self, template, source_identity, nonce):
        require(type(template) is Template, "TEMPLATE_TYPE")
        require(template.bank_domain(source_identity) == self.domain, "BANK_DOMAIN")
        natural(nonce, "NONCE")
        require(nonce in self.entries and nonce not in self.extracted, "BANK_NOT_AVAILABLE")
        self.extracted.add(nonce)
        return self.entries.pop(nonce)


def factor_rank_bounded(a, bound=8):
    """Exact row-basis algorithm; failed probes remain paid constructor work."""
    matrix(a)
    natural(bound, "RANK_BOUND", 8)
    require(bound > 0, "RANK_BOUND")
    basis, pivots, left_rows = [], [], []
    for row_index in range(N):
        residual = list(a[row_index * N:(row_index + 1) * N])
        coefficients = []
        for pivot, row in zip(pivots, basis):
            scale = residual[pivot]
            coefficients.append(scale)
            if scale:
                residual = [(v - scale * b) % Q for v, b in zip(residual, row)]
        pivot = next((i for i, v in enumerate(residual) if v), None)
        if pivot is not None:
            if len(basis) == bound:
                return None, {"completed": False, "rank": None,
                              "minimum_rank": bound + 1, "rows_examined": row_index + 1}
            scale = residual[pivot]
            coefficients.append(scale)
            inverse = pow(scale, Q - 2, Q)
            basis.append(tuple(v * inverse % Q for v in residual))
            pivots.append(pivot)
        left_rows.append(coefficients)
    rank = len(basis)
    left = tuple(v for row in left_rows for v in row + [0] * (rank - len(row)))
    right = tuple(v for row in basis for v in row)
    return (left, right, rank), {"completed": True, "rank": rank,
                                "minimum_rank": rank, "rows_examined": N}


def prepare(template, strategy):
    require(strategy in EXPECTED_CATALOG["strategies"], "STRATEGY")
    # Each constructor pays fresh validation, even though Template checked them.
    a, b = template.a, template.b
    matrix(a)
    matrix(b)
    probes = []
    if strategy == "eager-recompute":
        return None, {"method": "full-denoise-each-attempt", "rank_probes": []}
    if strategy == "prepared-dense":
        product, method = mm(a, b, N, N, N), "dense-AB"
    else:
        factors, observation = factor_rank_bounded(a)
        probes.append({"operand": "A", **observation})
        if factors is not None:
            u, v, rank = factors
            product = mm(u, mm(v, b, rank, N, N), N, rank, N) if rank else (0,) * CELLS
            method = "left-low-rank"
        else:
            factors, observation = factor_rank_bounded(b)
            probes.append({"operand": "B", **observation})
            if factors is not None:
                u, v, rank = factors
                product = mm(mm(a, u, N, N, rank), v, N, rank, N) if rank else (0,) * CELLS
                method = "right-low-rank"
            else:
                product, method = mm(a, b, N, N, N), "dense-after-two-failed-probes"
    prefix = b"PNW1" + field_bytes(a) + field_bytes(b) + field_bytes(product)
    return prefix, {"method": method, "rank_probes": probes}


class Cancelled(Exception):
    def __init__(self, tiles, partial_digest):
        self.tiles, self.partial_digest = tiles, partial_digest


def expand(challenge, label):
    words = []
    for counter in range(128):
        raw = framed_hash(b"noise", challenge, bytes([label]), struct.pack("<I", counter))
        words.extend(v for (v,) in struct.iter_unpack("<I", raw) if v < Q)
        if len(words) >= N * R:
            return tuple(words[:N * R])
    raise ValueError("NOISE_BUDGET")


def trace(challenge, a, b, cancel_after=None):
    el, er, fl, fr = [expand(challenge, label) for label in range(4)]
    ap = tuple((x + y) % Q for x, y in zip(a, mm(el, er, N, R, N)))
    bp = tuple((x + y) % Q for x, y in zip(b, mm(fl, fr, N, R, N)))
    accum = [0] * CELLS
    transcript = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    tiles = 0
    for bi in range(0, N, R):
        for bj in range(0, N, R):
            for bk in range(0, N, R):
                values = []
                for i in range(bi, bi + R):
                    for j in range(bj, bj + R):
                        offset = i * N + j
                        accum[offset] = (accum[offset] + sum(ap[i * N + k] * bp[k * N + j]
                                                           for k in range(bk, bk + R))) % Q
                        values.append(accum[offset])
                transcript.update(field_bytes(values))
                tiles += 1
                if cancel_after == tiles:
                    raise Cancelled(tiles, transcript.hexdigest())
    return tuple(accum), transcript.digest(), (el, er, fl, fr, bp)


def measured(call, *, thread=False):
    clock = time.thread_time_ns if thread else time.process_time_ns
    cpu, wall = clock(), time.perf_counter_ns()
    value = call()
    return value, {"cpu_ns": clock() - cpu, "wall_ns": time.perf_counter_ns() - wall}


def attempt(template, prefix, nonce, cancel_after=None):
    def execute():
        challenge = template.challenge(nonce)
        try:
            cp, transcript, factors = trace(challenge, template.a, template.b, cancel_after)
        except Cancelled as stopped:
            return {"nonce": nonce, "kind": "cancelled", "challenge": challenge.hex(),
                    "completed_tiles": stopped.tiles, "partial_trace_sha256": stopped.partial_digest,
                    "proof": None, "target_hit": None, "failure": "CONTROLLED_CANCELLATION"}
        if prefix is None:
            el, er, fl, fr, bp = factors
            left = mm(mm(template.a, fl, N, N, R), fr, N, R, N)
            right = mm(el, mm(er, bp, R, N, N), N, R, N)
            product = tuple((x - y - z) % Q for x, y, z in zip(cp, left, right))
            actual_prefix = b"PNW1" + field_bytes(template.a) + field_bytes(template.b) + field_bytes(product)
        else:
            actual_prefix = prefix
        proof = actual_prefix + transcript
        ticket = framed_hash(b"ticket", challenge, transcript)
        return {"nonce": nonce, "kind": "complete", "challenge": challenge.hex(),
                "trace": transcript.hex(), "ticket": ticket.hex(), "proof": proof,
                "proof_sha256": digest(proof), "target_hit": ticket <= template.target,
                "completed_tiles": 512, "failure": None}
    value, timing = measured(execute, thread=True)
    value["timing"] = timing
    return value


def source_record():
    files = {name: digest((ROOT / name).read_bytes()) for name in SOURCE_PATHS}
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    uncommitted = []
    for name in SOURCE_PATHS:
        blob = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT, capture_output=True)
        if blob.returncode or digest(blob.stdout) != files[name]:
            uncommitted.append(name)
    return {"git_head": head, "files_sha256": files,
            "uncommitted_source_files": uncommitted,
            "all_listed_source_files_match_head": not uncommitted}


def load_catalog():
    value = strict_json((ROOT / CATALOG_PATH).read_bytes())
    require(canonical(value) == canonical(EXPECTED_CATALOG), "CATALOG_CHANGED")
    return value


def materials():
    dense_a = tuple(pow(i + 1, j, Q) for i in range(N) for j in range(N))
    dense_b = tuple(pow(i + 65, j, Q) for i in range(N) for j in range(N))
    low_a = tuple((1 + i * j) % Q for i in range(N) for j in range(N))
    low_b = tuple(sum(pow(i + 1, k, Q) * pow(j + 1, k, Q) for k in range(4)) % Q
                  for i in range(N) for j in range(N))
    return {"dense": (dense_a, dense_b), "left-rank-2": (low_a, dense_b),
            "right-rank-4": (dense_a, low_b), "zero": ((0,) * CELLS, (0,) * CELLS)}


def fixture_template(material, profile):
    a, b = material
    header = (HERE / "vectors/header.bin").read_bytes()
    require(len(header) == 318, "RETAINED_HEADER")
    task = framed_hash(b"task", field_bytes(a), field_bytes(b))
    header = header[:278] + task + bytes(8)
    if profile == "PGH2":
        header = b"PGH2" + header + bytes([71]) * 32
    else:
        require(profile == "PNH1", "PROFILE")
    return Template(header, a, b)


def run_cohort(template, name, strategy, source_identity):
    """Two real Python threads, with all issued batches joined before extraction."""
    def producer():
        (prefix, preparation), setup = measured(lambda: prepare(template, strategy))
        rows = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            for nonces in ((0, 1), (2, 3)):
                # map preserves declared order, not favourable completion order.
                rows.extend(pool.map(lambda n: attempt(template, prefix, n), nonces))
        rows.append(attempt(template, prefix, 4, cancel_after=1))
        prefixes = {row["proof"][:-32] for row in rows if row["kind"] == "complete"}
        require(len(prefixes) == 1, "CHALLENGE_DEPENDENT_PRODUCT")
        retained_prefix = prefixes.pop()
        bank = CandidateBank(template, source_identity)
        for row in rows[:4]:
            bank.store(template, source_identity, row["nonce"], row["proof"])
        winner = next((r["nonce"] for r in rows[:4] if r["target_hit"]), None)
        extracted = bank.take(template, source_identity, winner) if winner is not None else None
        for row in rows:
            row.pop("proof")
            row["disposition"] = ("cancelled" if row["kind"] == "cancelled" else
                                  "local-extraction" if row["nonce"] == winner else
                                  "withheld-hit" if row["target_hit"] else "target-miss")
            row["after_first_hit"] = winner is not None and row["nonce"] > winner
        return {"profile": template.profile, "material": name, "strategy": strategy,
                "header_hex": template.header.hex(), "bank_domain": bank.domain.hex(),
                "proof_prefix_hex": retained_prefix.hex(), "preparation": preparation,
                "setup_timing": setup, "attempts": rows, "chosen_nonce": winner,
                "extracted_proof_sha256": digest(extracted) if extracted is not None else None,
                "bank_remaining_nonces": sorted(bank.entries), "bank_extracted_nonces": sorted(bank.extracted),
                "initial_cache_entries": 0, "initial_bank_entries": 0}
    result, timing = measured(producer)
    result["producer_inclusive_timing"] = timing
    return result


def check_timing(value):
    require(type(value) is dict and set(value) == {"cpu_ns", "wall_ns"}, "TIMING_FIELDS")
    for key in value:
        natural(value[key], "TIMING_INTEGER", 1 << 96)


def partial_reference(template, nonce):
    """Separately execute the first scalar tile; cancellation is not a proof."""
    c = template.challenge(nonce)
    el, er, fl, fr = [oracle.expand(c, label, N * R) for label in range(4)]
    ap = [(x + y) % Q for x, y in zip(template.a, oracle.mm(el, er, N, R, N))]
    bp = [(x + y) % Q for x, y in zip(template.b, oracle.mm(fl, fr, N, R, N))]
    first = [sum(ap[i * N + k] * bp[k * N + j] for k in range(R)) % Q
             for i in range(R) for j in range(R)]
    return hashlib.sha256(b"TRNM-PON-TRACE1\0" + c + oracle.field_bytes(first)).hexdigest()


def replay_cohort(row, template, name, strategy, source_identity):
    require(type(row) is dict, "COHORT")
    expected_fields = {"profile", "material", "strategy", "header_hex", "bank_domain",
                       "proof_prefix_hex", "preparation", "setup_timing", "attempts", "chosen_nonce",
                       "extracted_proof_sha256", "bank_remaining_nonces", "bank_extracted_nonces",
                       "initial_cache_entries", "initial_bank_entries", "producer_inclusive_timing"}
    require(set(row) == expected_fields, "COHORT_FIELDS")
    require((row["profile"], row["material"], row["strategy"]) == (template.profile, name, strategy),
            "COHORT_IDENTITY")
    require(row["header_hex"] == template.header.hex(), "HEADER_BINDING")
    require(row["bank_domain"] == template.bank_domain(source_identity).hex(), "BANK_BINDING")
    require(type(row["proof_prefix_hex"]) is str and len(row["proof_prefix_hex"]) == 2 * (PROOF_BYTES - 32),
            "PROOF_PREFIX_LENGTH")
    prefix = bytes.fromhex(row["proof_prefix_hex"])
    require(prefix.hex() == row["proof_prefix_hex"], "PROOF_PREFIX_HEX")
    require(prefix[:4] == b"PNW1" and prefix[4:4 + 8 * CELLS]
            == field_bytes(template.a) + field_bytes(template.b), "PROOF_MATERIAL")
    _, expected_preparation = prepare(template, strategy)
    require(canonical(row["preparation"]) == canonical(expected_preparation), "PREPARATION_PATH")
    for key in ("setup_timing", "producer_inclusive_timing"):
        check_timing(row[key])
    for key in ("initial_cache_entries", "initial_bank_entries"):
        require(type(row[key]) is int and row[key] == 0, "INITIAL_STATE")
    attempts = row["attempts"]
    require(type(attempts) is list and len(attempts) == 5, "ATTEMPT_COVERAGE")
    winner, hits, missed, after, partial = None, 0, 0, 0, 0
    for nonce, observed in enumerate(attempts):
        require(type(observed) is dict, "ATTEMPT")
        common = {"nonce", "kind", "challenge", "completed_tiles", "target_hit", "failure",
                  "timing", "disposition", "after_first_hit"}
        expected = common | ({"trace", "ticket", "proof_sha256"} if nonce < 4 else {"partial_trace_sha256"})
        require(set(observed) == expected, "ATTEMPT_FIELDS")
        require(type(observed["nonce"]) is int and observed["nonce"] == nonce, "NONCE_ORDER")
        require(observed["challenge"] == template.challenge(nonce).hex(), "CHALLENGE_BINDING")
        check_timing(observed["timing"])
        if nonce == 4:
            require(observed["kind"] == "cancelled" and observed["target_hit"] is None
                    and type(observed["completed_tiles"]) is int and observed["completed_tiles"] == 1
                    and observed["failure"] == "CONTROLLED_CANCELLATION"
                    and observed["disposition"] == "cancelled", "CANCELLATION_RECORD")
            require(observed["partial_trace_sha256"] == partial_reference(template, nonce),
                    "CANCELLED_PREFIX_REPLAY")
            partial += 1
        else:
            require(observed["kind"] == "complete" and observed["failure"] is None
                    and type(observed["completed_tiles"]) is int and observed["completed_tiles"] == 512,
                    "COMPLETE_RECORD")
            require(type(observed["trace"]) is str and len(observed["trace"]) == 64, "TRACE_HEX")
            transcript = bytes.fromhex(observed["trace"])
            require(transcript.hex() == observed["trace"], "TRACE_HEX")
            proof = prefix + transcript
            require(observed["proof_sha256"] == digest(proof), "PROOF_DIGEST")
            challenge = template.challenge(nonce)
            ticket = framed_hash(b"ticket", challenge, transcript)
            hit = ticket <= template.target
            require(type(observed["target_hit"]) is bool and observed["target_hit"] is hit
                    and observed["ticket"] == ticket.hex(), "LOTTERY_RESULT")
            # A miss is NOT counted as acceptance at the actual target.
            checked, _ = oracle.verify(challenge, template.task,
                                       template.target if hit else MAX_TARGET, proof)
            require(checked == ticket, "SCALAR_TICKET")
            if hit:
                hits += 1
                if winner is None:
                    winner = nonce
            else:
                try:
                    oracle.verify(challenge, template.task, template.target, proof)
                except ValueError as error:
                    require(str(error) == "TARGET", "ORIGINAL_TARGET_REFUSAL")
                else:
                    raise ValueError("MISS_ACCEPTED_AT_ORIGINAL_TARGET")
                missed += 1
            disposition = "local-extraction" if nonce == winner else "withheld-hit" if hit else "target-miss"
            require(observed["disposition"] == disposition, "DISPOSITION")
        expected_after = winner is not None and nonce > winner
        require(type(observed["after_first_hit"]) is bool and observed["after_first_hit"] is expected_after,
                "POST_FIRST_HIT_ACCOUNTING")
        after += int(expected_after and nonce < 4)
    require(row["chosen_nonce"] is None if winner is None else
            type(row["chosen_nonce"]) is int and row["chosen_nonce"] == winner, "WINNER_SELECTION")
    require(canonical(row["bank_remaining_nonces"]) == canonical([n for n in range(4) if n != winner])
            and canonical(row["bank_extracted_nonces"]) == canonical([] if winner is None else [winner]),
            "BANK_INVENTORY")
    wanted = None if winner is None else attempts[winner]["proof_sha256"]
    require(row["extracted_proof_sha256"] == wanted, "BANK_EXTRACTION_IDENTITY")
    total = row["producer_inclusive_timing"]["cpu_ns"]
    require(total >= row["setup_timing"]["cpu_ns"]
            + sum(r["timing"]["cpu_ns"] for r in attempts), "INCLUSIVE_CPU_WINDOW")
    return {"complete_relation_replays": 4, "original_target_accepted_candidates": hits,
            "original_target_refusals": missed, "controlled_cancellations": partial,
            "withheld_hits": hits - int(winner is not None), "post_first_hit_complete_attempts": after,
            "local_bank_extractions": int(winner is not None), "no_hit_cohorts": int(winner is None)}


def build_report(on_cohort=None):
    catalog = load_catalog()
    before = source_record()
    source_identity = bytes.fromhex(digest(canonical(before["files_sha256"])))
    cases, material_timing = measured(materials)
    cohorts, template_timings = [], {}
    for profile in catalog["profiles"]:
        for name in catalog["materials"]:
            template, timing = measured(lambda: fixture_template(cases[name], profile))
            template_timings[profile + ":" + name] = timing
            for strategy in catalog["strategies"]:
                row = run_cohort(template, name, strategy, source_identity)
                cohorts.append(row)
                if on_cohort is not None:
                    on_cohort(row)
    return {"schema": SCHEMA, "catalog": catalog, "source_before": before,
            "source_after": source_record(), "shared_material_timing": material_timing,
            "shared_template_timings": template_timings,
            "cohorts": cohorts, "claims": dict(CLAIMS),
            "cost_scope": dict(COST_SCOPE),
            "environment": {"python": sys.version, "implementation": platform.python_implementation(),
                            "platform": platform.platform(), "workers_per_batch": 2}}


def replay_report(report):
    fields = {"schema", "catalog", "source_before", "source_after", "shared_material_timing", "shared_template_timings",
              "cohorts", "claims", "cost_scope", "environment"}
    require(type(report) is dict and set(report) == fields and report["schema"] == SCHEMA, "REPORT_SCHEMA")
    require(canonical(report["catalog"]) == canonical(load_catalog()), "CATALOG_BINDING")
    before, after = report["source_before"], report["source_after"]
    require(canonical(before) == canonical(after), "SOURCE_CHANGED_DURING_EXECUTION")
    current = source_record()
    require(canonical(before) == canonical(current), "SOURCE_IDENTITY")
    require(canonical(report["claims"]) == canonical(CLAIMS), "QUALIFICATION_CLAIMS")
    require(canonical(report["cost_scope"]) == canonical(COST_SCOPE), "COST_SCOPE")
    env = report["environment"]
    require(type(env) is dict and set(env) == {"python", "implementation", "platform", "workers_per_batch"},
            "ENVIRONMENT_FIELDS")
    require(type(env["workers_per_batch"]) is int and env["workers_per_batch"] == 2
            and all(type(env[k]) is str and 0 < len(env[k]) <= 4096
                    for k in ("python", "implementation", "platform")), "ENVIRONMENT_VALUES")
    check_timing(report["shared_material_timing"])
    expected_templates = {p + ":" + m for p in EXPECTED_CATALOG["profiles"]
                          for m in EXPECTED_CATALOG["materials"]}
    require(type(report["shared_template_timings"]) is dict
            and set(report["shared_template_timings"]) == expected_templates, "TEMPLATE_COST_COVERAGE")
    for timing in report["shared_template_timings"].values():
        check_timing(timing)
    require(type(report["cohorts"]) is list and len(report["cohorts"]) == 24, "GRID_COVERAGE")
    identity = bytes.fromhex(digest(canonical(before["files_sha256"])))
    cases, total, matches = materials(), {}, {}
    index = 0
    for profile in EXPECTED_CATALOG["profiles"]:
        for name in EXPECTED_CATALOG["materials"]:
            template = fixture_template(cases[name], profile)
            for strategy in EXPECTED_CATALOG["strategies"]:
                row = report["cohorts"][index]
                summary = replay_cohort(row, template, name, strategy, identity)
                for key, value in summary.items():
                    total[key] = total.get(key, 0) + value
                # Matched strategies must have the SAME complete proof stream.
                semantic = (row["proof_prefix_hex"], [
                    {k: v for k, v in a.items() if k != "timing"} for a in row["attempts"]])
                key = profile, name
                if key in matches:
                    require(canonical(semantic) == canonical(matches[key]), "MATCHED_STRATEGY_OUTPUTS")
                else:
                    matches[key] = semantic
                index += 1
    return {"schema": SCHEMA + "-replay", "result": "PASS", "cohorts": index, **total,
            "accepted_candidates_are_repeated_across_matched_strategies": True,
            "independent_mining_samples": False, "native_admitted_blocks": 0,
            "minimum_legal_cost_proved": False, "qualification": "HOLD_NO_GO"}


def write_new(path, value):
    raw = canonical(value) + b"\n"
    require(len(raw) <= MAX_REPORT_BYTES, "OUTPUT_BOUND")
    with path.open("xb") as stream:
        stream.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--output", type=Path)
    choice.add_argument("--replay", type=Path)
    args = parser.parse_args()
    if args.replay:
        with args.replay.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        summary, timing = measured(lambda: replay_report(strict_json(raw)))
    else:
        require(not args.output.exists(), "OUTPUT_EXISTS")
        partial_path = Path(str(args.output) + ".partial.jsonl")
        with partial_path.open("xb") as partial:
            def retain(row):
                partial.write(canonical(row) + b"\n")
                partial.flush()
                os.fsync(partial.fileno())
            report = build_report(retain)
        # Write before replay so a failed audit does not erase actual observations.
        write_new(args.output, report)
        summary, timing = measured(lambda: replay_report(report))
    summary["separate_replay_timing"] = timing
    print(json.dumps(summary, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
