#!/usr/bin/env python3
"""Strict full-certificate reader for the standalone joint-challenge experiment.

Every completed proof is independently replayed, including misses, duplicates
and budget overruns. Recorded CPU is reconciled, not physically authenticated.
Diagnostic headers do not establish parent eligibility, chainweight or hardness.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from read_w1_cost_research import require, uint64, material_recipe, FAMILIES as ORIGINAL_FAMILIES
from contract_wire import H, header_decode, header_encode, u64
import work_oracle

SCHEMA = "pon-w1-joint-challenge-v1"
SUMMARY_SCHEMA = "pon-w1-joint-challenge-verified-v1"
FAMILIES = (*ORIGINAL_FAMILIES, "near-q-full-rank")
N, Q, CELLS, PROOF_BYTES = 64, 4294967291, 4096, 49188
MAX_RAW_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_ROWS = 4 * 4096 + 10

OPTION_FIELDS = (
    "producer", "family", "mode", "attempts", "width", "seed", "sample",
    "target", "cpu_budget_ns", "nonce_space",
)
START_FIXED = {
    "qualification_level": "relation-only-diagnostic-context",
    "native_admitted": False,
    "hardware_attested": False,
    "clock": "linux-process-cpu-time",
    "budget_stop": "inclusive-before-prepare-or-batch",
    "completion_policy": "all-active-proofs-return-to-caller-together-before-raw-emission",
    "cold_policy": "actual-prepare-per-batch-not-cache-flush",
    "warm_policy": "one-actual-prepare-per-invocation",
    "accounting_excludes": [
        "process-startup-before-main-clock",
        "final-end-row-construction-serialization-and-write",
        "post-end-options-and-framework-teardown",
    ],
    "observer_exclusion": "both-complete-original-native-verifiers-and-their-local-allocation-destruction",
    "material_setup_policy": "all-fixture-construction-performed-in-this-invocation-is-charged",
}
ROW_FIELDS = {
    "start": set(START_FIXED) | {"options", "avx2_available", "simd_lanes"},
    "material": set("family source task a_hex b_hex setup_complete_elapsed_cpu_ns setup_complete_inclusive_cpu_ns material_cpu_ns material_wall_ns".split()),
    "charge": set("seq stage batch_index cpu_ns wall_ns cumulative_charged_cpu_ns cumulative_charged_wall_ns".split()),
    "batch": set("batch_index attempt_start active_lanes padded_lanes completion_elapsed_cpu_ns completion_elapsed_wall_ns observer_before_cpu_ns inclusive_producer_cpu_ns inclusive_within_cpu_budget cumulative_charged_cpu_ns".split()),
    "attempt": set("index batch_index lane header_hex challenge task target trace ticket block_id semantic_id proof_hex proof_sha256 proof_bytes target_hit unique qualification_level native_admitted production_full_verify reference_full_verify relation_verification_target observer_cpu_ns observer_wall_ns cumulative_observer_cpu_ns completion_elapsed_cpu_ns inclusive_producer_cpu_ns inclusive_within_cpu_budget".split()),
    "end": set("status complete attempts batches charges target_hits target_misses unique_opportunities unique_target_hits inclusive_budget_unique_opportunities inclusive_budget_unique_target_hits native_admitted production_full_verified reference_full_verified charged_core_cpu_ns charged_core_wall_ns observer_cpu_ns observer_wall_ns elapsed_cpu_ns elapsed_wall_ns inclusive_producer_cpu_ns inclusive_noncore_cpu_ns budget_stop overrun_cost_refunded cache_and_material_teardown_included final_end_emission_included".split()),
}


def _exact(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), label)


def _same(actual, expected, label):
    require(type(actual) is type(expected) and actual == expected, label)


def _hex(value, length, label):
    require(type(value) is str and len(value) == length * 2 and
            re.fullmatch(r"[0-9a-f]*", value) is not None, label)
    return bytes.fromhex(value)


def _bool(value, label):
    require(type(value) is bool, label)
    return value


def validate_options(options):
    _exact(options, OPTION_FIELDS, "OPTION_FIELDS")
    require(type(options["producer"]) is str and
            options["producer"] in ("avx2-joint", "prepared-sequential"), "OPTION_PRODUCER")
    require(type(options["mode"]) is str and options["mode"] in ("hot", "cold"), "OPTION_MODE")
    require(type(options["family"]) is str and options["family"] in FAMILIES, "OPTION_FAMILY")
    for name, upper in (("attempts", 4096), ("width", 4), ("nonce_space", 4096)):
        uint64(options[name], "OPTION_BOUNDS:" + name, 1, upper)
    for name in ("seed", "sample"):
        uint64(options[name], "OPTION_U64:" + name)
    if options["cpu_budget_ns"] is not None:
        uint64(options["cpu_budget_ns"], "OPTION_BUDGET")
    target = options["target"]
    require(type(target) is list and len(target) == 32 and
            all(type(v) is int and 0 <= v <= 255 for v in target), "OPTION_TARGET")
    return options


def options_from_args(argv):
    """Decode this Rust example's exact CLI defaults, without running a child."""
    require(type(argv) is list and len(argv) % 2 == 0 and
            all(type(v) is str for v in argv), "ARGUMENT_PAIRS")
    out = dict(producer="avx2-joint", family="full-rank-field", mode="hot",
               attempts=4, width=4, seed=1, sample=0, target=[127] + [255] * 31,
               cpu_budget_ns=None, nonce_space=0)
    supplied = set()
    for flag, text in zip(argv[::2], argv[1::2]):
        require(flag.startswith("--"), "UNKNOWN_OPTION")
        key = flag[2:].replace("-", "_")
        require(key in out and key not in supplied and
                flag == "--" + key.replace("_", "-"), "UNKNOWN_OR_DUPLICATE_OPTION")
        supplied.add(key)
        if key in ("producer", "family", "mode"):
            out[key] = text
        elif key == "target":
            require(re.fullmatch(r"[0-9a-fA-F]{64}", text) is not None, "ARGUMENT_TARGET")
            out[key] = list(bytes.fromhex(text))
        else:
            require(re.fullmatch(r"\+?[0-9]+", text) is not None, "ARGUMENT_UNSIGNED_INTEGER")
            out[key] = uint64(int(text), "ARGUMENT_U64")
    require("nonce_space" not in supplied or out["nonce_space"] != 0, "ARGUMENT_NONCE_SPACE")
    if out["nonce_space"] == 0:
        out["nonce_space"] = out["attempts"]
    return validate_options(out)


def expected_header(options, task, index):
    context = H("w1-joint-research-context-v1", u64(options["seed"]), u64(options["sample"]))
    return dict(
        network=H("w1-joint-research-network-v1"),
        parameters=H("w1-joint-research-parameters-v1"),
        parent=context, height=1, timestamp=1, target=bytes(options["target"]),
        miner=H("w1-joint-research-miner-v1", context),
        transactions=bytes(32), state=bytes(32), receipts=bytes(32),
        work_task=task, nonce=index % options["nonce_space"],
    )


def _expected_material(family):
    if family == "near-q-full-rank":
        a = struct.pack("<4096I", *(Q - 1 - int(p // N == p % N) for p in range(CELLS)))
        b = struct.pack("<4096I", *(Q - 1 - int((p // N + 1) % N == p % N) for p in range(CELLS)))
        return a, b, "canonical-near-q-full-rank-boundary"
    a, b, _, _, _ = material_recipe(family)
    source = "hash-generated-rank-checked" if family == "full-rank-field" else "synthetic-fixture"
    return a, b, source


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _bad_constant(_):
    raise ValueError("NONFINITE_JSON_NUMBER")


def _records(path, hasher):
    with Path(path).open("rb") as source:
        before = source.fileno()
        import os
        initial = os.fstat(before)
        require(stat.S_ISREG(initial.st_mode), "RAW_NOT_REGULAR_FILE")
        require(initial.st_size <= MAX_RAW_BYTES, "RAW_TOO_LARGE")
        total = 0
        for count in range(MAX_ROWS + 1):
            line = source.readline(MAX_LINE_BYTES + 1)
            if not line:
                final = os.fstat(source.fileno())
                require((initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) ==
                        (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) and
                        total == initial.st_size, "RAW_CHANGED_WHILE_READING")
                return
            require(count < MAX_ROWS, "TOO_MANY_ROWS")
            total += len(line)
            require(total <= MAX_RAW_BYTES and len(line) <= MAX_LINE_BYTES, "RAW_LIMIT")
            require(line.endswith(b"\n"), "TRUNCATED_JSONL_LINE")
            hasher.update(line)
            row = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_bad_constant)
            require(type(row) is dict, "ROW_OBJECT")
            require(row.get("schema") == SCHEMA, "SCHEMA")
            kind = row.get("kind")
            require(type(kind) is str and kind in ROW_FIELDS, "UNKNOWN_ROW_KIND")
            _exact(row, ROW_FIELDS[kind] | {"schema", "kind"}, "ROW_FIELDS:" + kind)
            yield row
        raise ValueError("TOO_MANY_ROWS")


class _Reader:
    def __init__(self, expected_options):
        self.expected_options = expected_options
        self.options = None
        self.phase = "start"
        self.core_cpu = self.core_wall = self.observer_cpu = self.observer_wall = 0
        self.charge_count = self.batch_count = self.attempt_count = 0
        self.last_elapsed_cpu = self.last_elapsed_wall = self.last_inclusive = 0
        self.last_batch_observer_cpu = self.last_batch_observer_wall = 0
        self.material_charge = None
        self.prepared_hot = False
        self.cold_prepared_for = None
        self.batch = None
        self.batch_observed = 0
        self.seen = set()
        self.hits = self.unique_hits = self.budget_unique = self.budget_hits = 0
        self.a = self.b = self.task = None
        self.compact_attempts = []
        self.python_cpu = 0
        self.end = None
        self.stage_cpu = {"material": 0, "prepare": 0, "generate": 0}
        self.prepare_count = 0

    def _can_start(self):
        budget = self.options["cpu_budget_ns"]
        # Every already charged producer interval is also a known lower bound,
        # including a preparation that crossed B before any batch existed.
        require(budget is None or max(self.last_inclusive, self.core_cpu) < budget,
                "START_AFTER_KNOWN_BUDGET_FENCE")
        require(self.attempt_count < self.options["attempts"], "START_AFTER_ATTEMPT_CAP")

    def accept(self, row):
        require(self.phase != "done", "ROWS_AFTER_END")
        kind = row["kind"]
        if kind == "start":
            self.start(row)
        elif kind == "charge":
            self.charge(row)
        elif kind == "material":
            self.material(row)
        elif kind == "batch":
            self.batch_start(row)
        elif kind == "attempt":
            self.attempt(row)
        elif kind == "end":
            self.finish(row)

    def start(self, row):
        require(self.phase == "start", "DUPLICATE_OR_MISPLACED_START")
        self.options = validate_options(row["options"])
        if self.expected_options is not None:
            validate_options(self.expected_options)
            require(self.options == self.expected_options, "EXPECTED_OPTIONS")
        for key, expected in START_FIXED.items():
            _same(row[key], expected, "START_BOUNDARY:" + key)
        available = _bool(row["avx2_available"], "AVX2_FLAG")
        if self.options["producer"] == "avx2-joint":
            require(available, "UNSUPPORTED_AVX2")
        _same(row["simd_lanes"], 4 if self.options["producer"] == "avx2-joint" else 1, "SIMD_LANES")
        self.phase = "material-charge"

    def charge(self, row):
        require(self.options is not None, "CHARGE_BEFORE_START")
        stage = row["stage"]
        require(type(stage) is str and stage in self.stage_cpu, "CHARGE_STAGE")
        _same(row["seq"], self.charge_count, "CHARGE_SEQUENCE")
        cpu = uint64(row["cpu_ns"], "CHARGE_CPU")
        wall = uint64(row["wall_ns"], "CHARGE_WALL")
        if stage == "material":
            require(self.phase == "material-charge", "MATERIAL_CHARGE_ORDER")
            require(row["batch_index"] is None, "MATERIAL_CHARGE_BATCH")
            self.material_charge = (cpu, wall)
            self.phase = "material"
        elif stage == "prepare":
            require(self.phase == "ready", "PREPARE_ORDER")
            self._can_start()
            if self.options["mode"] == "hot":
                require(not self.prepared_hot and row["batch_index"] is None and
                        self.batch_count == 0, "HOT_PREPARE_SCOPE")
                self.prepared_hot = True
            else:
                _same(row["batch_index"], self.batch_count, "COLD_PREPARE_BATCH")
                require(self.cold_prepared_for is None, "DUPLICATE_COLD_PREPARE")
                self.cold_prepared_for = self.batch_count
            self.prepare_count += 1
        else:
            require(self.phase == "ready", "GENERATE_ORDER")
            self._can_start()
            _same(row["batch_index"], self.batch_count, "GENERATE_BATCH")
            require(self.prepared_hot if self.options["mode"] == "hot" else
                    self.cold_prepared_for == self.batch_count, "GENERATE_WITHOUT_PREPARE")
            self.phase = "batch"
        self.core_cpu += cpu
        self.core_wall += wall
        uint64(self.core_cpu, "CORE_CPU_SUM_OVERFLOW")
        uint64(self.core_wall, "CORE_WALL_SUM_OVERFLOW")
        _same(row["cumulative_charged_cpu_ns"], self.core_cpu, "CHARGED_CPU_SUM")
        _same(row["cumulative_charged_wall_ns"], self.core_wall, "CHARGED_WALL_SUM")
        self.stage_cpu[stage] += cpu
        self.charge_count += 1

    def material(self, row):
        require(self.phase == "material", "MATERIAL_ORDER")
        _same(row["family"], self.options["family"], "MATERIAL_FAMILY")
        a, b, source = _expected_material(self.options["family"])
        _same(row["source"], source, "MATERIAL_SOURCE")
        self.a = _hex(row["a_hex"], CELLS * 4, "MATERIAL_A")
        self.b = _hex(row["b_hex"], CELLS * 4, "MATERIAL_B")
        require(self.a == a and self.b == b, "MATERIAL_RECIPE")
        self.task = H("task", a, b)
        require(_hex(row["task"], 32, "MATERIAL_TASK") == self.task, "MATERIAL_TASK_HASH")
        _same(row["material_cpu_ns"], self.material_charge[0], "MATERIAL_CPU_CHARGE")
        _same(row["material_wall_ns"], self.material_charge[1], "MATERIAL_WALL_CHARGE")
        elapsed = uint64(row["setup_complete_elapsed_cpu_ns"], "MATERIAL_ELAPSED")
        _same(row["setup_complete_inclusive_cpu_ns"], elapsed, "MATERIAL_INCLUSIVE")
        require(elapsed >= self.core_cpu, "MATERIAL_ELAPSED_BELOW_CHARGE")
        self.last_elapsed_cpu = self.last_inclusive = elapsed
        self.phase = "ready"

    def batch_start(self, row):
        require(self.phase == "batch", "BATCH_WITHOUT_GENERATION_CHARGE")
        _same(row["batch_index"], self.batch_count, "BATCH_SEQUENCE")
        _same(row["attempt_start"], self.attempt_count, "BATCH_ATTEMPT_START")
        active = min(self.options["width"], self.options["attempts"] - self.attempt_count)
        _same(row["active_lanes"], active, "ACTIVE_LANES")
        _same(row["padded_lanes"], 4 - active if self.options["producer"] == "avx2-joint" else 0, "PADDED_LANES")
        _same(row["observer_before_cpu_ns"], self.observer_cpu, "BATCH_OBSERVER_FENCE")
        elapsed = uint64(row["completion_elapsed_cpu_ns"], "BATCH_ELAPSED")
        wall = uint64(row["completion_elapsed_wall_ns"], "BATCH_WALL")
        inclusive = uint64(row["inclusive_producer_cpu_ns"], "BATCH_INCLUSIVE")
        require(elapsed >= self.observer_cpu and inclusive == elapsed - self.observer_cpu,
                "BATCH_INCLUSIVE_DEDUCTION")
        require(inclusive >= self.core_cpu and inclusive >= self.last_inclusive, "BATCH_CPU_ORDER")
        require(elapsed >= self.last_elapsed_cpu + self.observer_cpu - self.last_batch_observer_cpu,
                "BATCH_ELAPSED_ORDER")
        require(wall >= self.core_wall + self.observer_wall and
                wall >= self.last_elapsed_wall + self.observer_wall - self.last_batch_observer_wall,
                "BATCH_WALL_ORDER")
        _same(row["cumulative_charged_cpu_ns"], self.core_cpu, "BATCH_CORE_SUM")
        budget = self.options["cpu_budget_ns"]
        _same(row["inclusive_within_cpu_budget"], budget is None or inclusive <= budget, "BATCH_BUDGET")
        self.last_elapsed_cpu, self.last_elapsed_wall, self.last_inclusive = elapsed, wall, inclusive
        self.last_batch_observer_cpu, self.last_batch_observer_wall = self.observer_cpu, self.observer_wall
        self.batch = row
        self.batch_observed = 0
        self.phase = "attempts"

    def attempt(self, row):
        require(self.phase == "attempts", "ATTEMPT_OUTSIDE_COMPLETE_BATCH")
        batch = self.batch
        _same(row["index"], self.attempt_count, "ATTEMPT_SEQUENCE")
        _same(row["batch_index"], self.batch_count, "ATTEMPT_BATCH")
        _same(row["lane"], self.batch_observed, "ATTEMPT_LANE")
        for key in ("completion_elapsed_cpu_ns", "inclusive_producer_cpu_ns", "inclusive_within_cpu_budget"):
            _same(row[key], batch[key], "ATTEMPT_COMPLETION_FENCE:" + key)
        for key, value in (
            ("qualification_level", "relation-valid"), ("native_admitted", False),
            ("production_full_verify", True), ("reference_full_verify", True),
            ("relation_verification_target", "ff" * 32), ("proof_bytes", PROOF_BYTES),
        ):
            _same(row[key], value, "ATTEMPT_BOUNDARY:" + key)
        header_bytes = _hex(row["header_hex"], 318, "HEADER_HEX")
        header = header_decode(header_bytes)
        expected = expected_header(self.options, self.task, self.attempt_count)
        require(header == expected and header_encode(header) == header_bytes, "DIAGNOSTIC_HEADER_BINDING")
        challenge = H("challenge", header_bytes)
        require(_hex(row["challenge"], 32, "CHALLENGE") == challenge, "CHALLENGE_HASH")
        require(_hex(row["task"], 32, "ATTEMPT_TASK") == self.task, "ATTEMPT_TASK_BINDING")
        target = bytes(self.options["target"])
        require(_hex(row["target"], 32, "ATTEMPT_TARGET") == target, "LITERAL_TARGET")
        proof = _hex(row["proof_hex"], PROOF_BYTES, "FULL_PROOF_HEX")
        require(proof[:4] == b"PNW1" and proof[4:4 + CELLS * 4] == self.a and
                proof[4 + CELLS * 4:4 + CELLS * 8] == self.b, "PROOF_MATERIAL_BINDING")
        trace = _hex(row["trace"], 32, "TRACE")
        require(proof[-32:] == trace, "TRACE_PROOF_BINDING")
        require(_hex(row["proof_sha256"], 32, "PROOF_SHA") == hashlib.sha256(proof).digest(), "PROOF_HASH")
        ticket = H("ticket", challenge, trace)
        require(_hex(row["ticket"], 32, "TICKET") == ticket, "TICKET_HASH")
        require(_hex(row["block_id"], 32, "BLOCK_ID") == H("block", header_bytes, trace), "BLOCK_ID_HASH")
        semantic = H("w1-cost-game-semantic-ticket-v1", self.task, challenge, ticket)
        require(_hex(row["semantic_id"], 32, "SEMANTIC_ID") == semantic, "SEMANTIC_HASH")
        hit = target != bytes(32) and ticket <= target
        _same(row["target_hit"], hit, "TARGET_PREDICATE")
        unique = semantic not in self.seen
        _same(row["unique"], unique, "SEMANTIC_DUPLICATION")
        # No replay cache: even repeated, losing and over-budget certificates
        # each undergo the independent complete transcript/product verification.
        start = time.process_time_ns()
        verified_ticket, _ = work_oracle.verify(challenge, self.task, b"\xff" * 32, proof)
        self.python_cpu += time.process_time_ns() - start
        require(verified_ticket == ticket, "PYTHON_TICKET")
        self.seen.add(semantic)
        self.observer_cpu += uint64(row["observer_cpu_ns"], "OBSERVER_CPU")
        self.observer_wall += uint64(row["observer_wall_ns"], "OBSERVER_WALL")
        uint64(self.observer_cpu, "OBSERVER_CPU_SUM_OVERFLOW")
        uint64(self.observer_wall, "OBSERVER_WALL_SUM_OVERFLOW")
        _same(row["cumulative_observer_cpu_ns"], self.observer_cpu, "OBSERVER_SUM")
        within = batch["inclusive_within_cpu_budget"]
        self.hits += int(hit)
        self.unique_hits += int(unique and hit)
        self.budget_unique += int(unique and within)
        self.budget_hits += int(unique and within and hit)
        self.compact_attempts.append({
            "index": self.attempt_count, "batch_index": self.batch_count, "lane": self.batch_observed,
            "challenge": challenge.hex(), "task": self.task.hex(), "ticket": ticket.hex(),
            "semantic_id": semantic.hex(), "block_id": row["block_id"],
            "target_hit": hit, "unique": unique, "inclusive_within_cpu_budget": within,
            "inclusive_producer_cpu_ns": batch["inclusive_producer_cpu_ns"],
        })
        self.attempt_count += 1
        self.batch_observed += 1
        if self.batch_observed == batch["active_lanes"]:
            self.batch_count += 1
            self.cold_prepared_for = None
            self.phase = "ready"

    def finish(self, row):
        require(self.phase == "ready" and self.task is not None, "END_WITH_UNFINISHED_RECORDS")
        expected_counts = {
            "attempts": self.attempt_count, "batches": self.batch_count,
            "charges": self.charge_count, "target_hits": self.hits,
            "target_misses": self.attempt_count - self.hits,
            "unique_opportunities": len(self.seen), "unique_target_hits": self.unique_hits,
            "inclusive_budget_unique_opportunities": self.budget_unique,
            "inclusive_budget_unique_target_hits": self.budget_hits,
            "native_admitted": 0, "production_full_verified": self.attempt_count,
            "reference_full_verified": self.attempt_count,
            "charged_core_cpu_ns": self.core_cpu, "charged_core_wall_ns": self.core_wall,
            "observer_cpu_ns": self.observer_cpu, "observer_wall_ns": self.observer_wall,
        }
        for key, value in expected_counts.items():
            _same(row[key], value, "END_RECONCILIATION:" + key)
        for key, value in (
            ("complete", True), ("budget_stop", START_FIXED["budget_stop"]),
            ("overrun_cost_refunded", False), ("cache_and_material_teardown_included", True),
            ("final_end_emission_included", False),
        ):
            _same(row[key], value, "END_BOUNDARY:" + key)
        elapsed = uint64(row["elapsed_cpu_ns"], "END_ELAPSED")
        wall = uint64(row["elapsed_wall_ns"], "END_WALL")
        inclusive = uint64(row["inclusive_producer_cpu_ns"], "END_INCLUSIVE")
        require(elapsed >= self.observer_cpu and inclusive == elapsed - self.observer_cpu,
                "END_INCLUSIVE_DEDUCTION")
        require(inclusive >= self.core_cpu and inclusive >= self.last_inclusive, "END_CPU_ORDER")
        require(elapsed >= self.last_elapsed_cpu + self.observer_cpu - self.last_batch_observer_cpu,
                "END_ELAPSED_ORDER")
        require(wall >= self.core_wall + self.observer_wall and
                wall >= self.last_elapsed_wall + self.observer_wall - self.last_batch_observer_wall,
                "END_WALL_ORDER")
        _same(row["inclusive_noncore_cpu_ns"], inclusive - self.core_cpu, "END_NONCORE")
        if self.attempt_count == self.options["attempts"]:
            _same(row["status"], "attempt-cap-complete", "END_CAP_STATUS")
        else:
            _same(row["status"], "inclusive-cpu-budget-exhausted", "END_BUDGET_STATUS")
            budget = self.options["cpu_budget_ns"]
            require(budget is not None and inclusive >= budget, "PREMATURE_BUDGET_STOP")
        require(self.options["mode"] != "hot" or self.prepare_count <= 1, "HOT_PREPARE_COUNT")
        if self.options["mode"] == "cold":
            require(self.prepare_count in (self.batch_count, self.batch_count + 1), "COLD_PREPARE_COUNT")
        self.end = row
        self.phase = "done"

    def summary(self):
        require(self.phase == "done" and self.end is not None, "MISSING_COMPLETE_END")
        return {
            "schema": SUMMARY_SCHEMA, "options": self.options, "task": self.task.hex(),
            "qualification_level": "relation-valid-diagnostic-only",
            "native_admitted": False, "hardware_attested": False,
            "hardness_accepted": False, "production_activation": False,
            "all_completed_proofs_python_replayed": self.attempt_count,
            "python_verification_cpu_ns": self.python_cpu,
            "native_full_verification_is_reported": True,
            "material_seed_dependency": "seed-and-sample-change-header-challenges-only",
            "source_binary_and_physical_cpu_provenance": "requires-external-source-bound-runner",
            "full_process_accounting": "requires-external-process-receipt",
            "stage_cpu_ns": self.stage_cpu, "prepare_count": self.prepare_count,
            "end": {key: value for key, value in self.end.items() if key not in ("schema", "kind")},
            "attempts": self.compact_attempts,
        }


def read_joint(path, expected_options=None):
    """Return a compact verified result or raise; no partial-result acceptance."""
    start = time.process_time_ns()
    hasher = hashlib.sha256()
    reader = _Reader(expected_options)
    for row in _records(path, hasher):
        reader.accept(row)
    result = reader.summary()
    result.update(raw_path=str(Path(path).resolve()), raw_sha256=hasher.hexdigest(),
                  reader_cpu_ns=time.process_time_ns() - start)
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(read_joint(arguments.raw), indent=2))
