#!/usr/bin/env python3
"""Reconcile W1 research records and independently replay retained certificates.

This reader checks hashes, canonical inputs, original header/challenge bindings,
all charge sums, duplicate semantics and budget completion fences. Native calls
for the nonretained certificates remain recorded observations, not authenticated
remote execution. Finite observed rates are never universal cost lower bounds.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from contract_wire import H, header_decode, header_encode, u64
import work_oracle
from pon_w1_cost_matrix_reader import material as expected_material, _rank

SCHEMA = "pon-w1-valid-cost-game-v1"
MAX_LINE = 2 * 1024 * 1024
N, Q, PROOF_BYTES = 64, 4294967291, 49188
ARMS = (
    "scalar-original", "prepared-generic", "prepared-structured", "tiled-classical",
    "tiled-strassen-one-level", "paired-product", "blocked-zero",
    "blocked-zero-integer-paired", "blocked-one-zero-rank-one", "maintenance-periodic",
    "maintenance-integer-paired", "maintenance-prefix", "maintenance-limb",
    "integer-paired-general",
)
FAMILIES = (
    "periodic-dense-fixture", "full-rank-field", "zero", "identity", "rank-one",
    "sparse-diagonal", "continuity-maintenance-v1", "zero-left-rank-one", "zero-right-rank-one",
)
SETUP_NAMES = ("preflight", "rustc-version", "cargo-version", "metadata", "build")
COUNT_KEYS = (
    "attempts", "evaluation_attempts", "training_attempts", "target_hits", "target_misses",
    "unique_target_hits", "unique_opportunities", "budget_unique_opportunities",
    "inclusive_budget_unique_opportunities", "budget_unique_target_hits", "inclusive_budget_unique_target_hits",
    "evaluation_budget_unique_target_hits", "unique_native_admitted", "auxiliary_original_node_work",
    "auxiliary_original_node_attempts", "all_work_target_hits", "all_work_unique_target_hits",
    "all_work_inclusive_budget_unique_target_hits",
)
REPLAY_KEYS = ("full_relation_attempts", "winning_attempts", "in_core_budget_winning_attempts",
               "in_inclusive_budget_winning_attempts")
ROW_FIELDS = {
    "campaign": "options arm_names profile proof_bytes clock budget_semantics charged_generation_includes observer_excluded batch_semantics material_is_public_input energy_and_hardware_cost_measured invalid_rejection_paths_used hardness_accepted production_activation",
    "material-construction": "timing charged_per_producer reason",
    "material": "family source task a_hex b_hex a_sha256 b_sha256 a_rank b_rank parent_eligibility_claimed",
    "cohort-start": "cohort family sample mode scope arm task cpu_budget_ns attempt_cap qualification_level semantic_dedup_scope cold_definition hot_definition",
    "charge": "cohort seq stage arm timing cumulative within_cpu_budget overrun_cpu_ns detail",
    "attempt": "cohort attempt_index phase ordinal arm nonce challenge task target trace ticket proof_sha256 proof_bytes proof_hex product_sha256 target_hit semantic_id unique_ticket within_cpu_budget cumulative_charged_cpu_ns inclusive_producer_cpu_ns inclusive_within_cpu_budget charge_seq generation_timing relation_valid qualification_level production_verifier reference_verifier parent header_hex block_id native_admission native_admission_timing",
    "selection": "cohort selected_arm scores policy_frozen_before_evaluation training_stream_disjoint training_and_all_candidate_preparation_charged training_unique_wins_counted",
    "cohort-end": "cohort selected_arm status charge_records charged observer_verification_and_admission cohort_elapsed observer_logging_and_unattributed_overhead inclusive_producer_timing inclusive_budget_excludes_global_public_material_construction attempts evaluation_attempts training_attempts target_hits target_misses unique_target_hits budget_unique_target_hits evaluation_budget_unique_target_hits inclusive_budget_unique_target_hits unique_native_admitted auxiliary_original_node_work all_work_target_hits all_work_unique_target_hits all_work_inclusive_budget_unique_target_hits all_work_is_distinct_candidates_not_additive_chainweight cpu_budget_ns overrun_cpu_ns zero_wins_retained successful_work_lower_bound_claimed production_activation",
    "end": "cohorts complete hardness_accepted production_activation",
}


def require(condition, label):
    if not condition:
        raise ValueError(label)


def exact(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), label)
    return value


def uint64(value, label, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, label)
    return value


def validate_options(options):
    exact(options, ("samples", "attempts", "seed", "mode", "scope", "families", "arms",
                    "training_attempts", "batch_size", "cpu_budget_ns", "target", "nonce_space"),
          "OPTION_FIELDS")
    for key, upper in (("samples", 64), ("attempts", 4096), ("training_attempts", 64),
                       ("batch_size", 64), ("nonce_space", 4096)):
        uint64(options[key], "OPTION_BOUNDS:" + key, 1, upper)
    uint64(options["seed"], "OPTION_SEED")
    if options["cpu_budget_ns"] is not None:
        uint64(options["cpu_budget_ns"], "OPTION_BUDGET")
    require(options["scope"] in ("relation", "maintenance-parent") and
            options["mode"] in ("cold", "hot", "batch", "adaptive"), "OPTION_MODE")
    require(type(options["families"]) is list and bool(options["families"]) and
            all(type(value) is str and value in FAMILIES for value in options["families"]) and
            len(set(options["families"])) == len(options["families"]), "OPTION_FAMILIES")
    require(type(options["arms"]) is list and bool(options["arms"]) and
            all(type(value) is int and 0 <= value < len(ARMS) for value in options["arms"]) and
            len(set(options["arms"])) == len(options["arms"]), "OPTION_ARMS")
    require(type(options["target"]) is list and len(options["target"]) == 32 and
            all(type(value) is int and 0 <= value <= 255 for value in options["target"]),
            "OPTION_TARGET")
    if options["scope"] == "maintenance-parent":
        require(options["families"] == ["continuity-maintenance-v1"] and
                options["target"] == [127] + [255] * 31, "NATIVE_OPTION_OVERRIDES")
    return options


def options_from_args(arguments):
    """Independently decode the actual Rust CLI, including its explicit defaults."""
    require(type(arguments) is list and len(arguments) % 2 == 0 and
            all(type(value) is str for value in arguments), "PLAN_ARGUMENT_PAIRS")
    options = dict(samples=1, attempts=8, seed=1, mode="hot", scope="relation",
                   families=["full-rank-field", "zero", "continuity-maintenance-v1"],
                   arms=[1, 5, 13], training_attempts=2, batch_size=4,
                   cpu_budget_ns=None, target=[127] + [255] * 31, nonce_space=0)
    supplied = set()
    for flag, text in zip(arguments[::2], arguments[1::2]):
        require(flag.startswith("--"), "UNKNOWN_PLAN_OPTION")
        key = flag[2:].replace("-", "_")
        require(key in options and key not in supplied, "UNKNOWN_OR_DUPLICATE_PLAN_OPTION")
        supplied.add(key)
        if key in ("mode", "scope"):
            options[key] = text
        elif key in ("families", "arms"):
            allowed = FAMILIES if key == "families" else ARMS
            choices = list(allowed) if text == "all" else text.split(",")
            require(choices and len(set(choices)) == len(choices) and
                    all(choice in allowed for choice in choices), "PLAN_CHOICE")
            options[key] = choices if key == "families" else [ARMS.index(value) for value in choices]
        elif key == "target":
            require(re.fullmatch(r"[0-9a-fA-F]{64}", text) is not None, "PLAN_TARGET")
            options[key] = list(bytes.fromhex(text))
        else:
            require(re.fullmatch(r"[0-9]+", text) is not None, "PLAN_UNSIGNED_INTEGER")
            options[key] = uint64(int(text), "PLAN_U64")
    require("nonce_space" not in supplied or options["nonce_space"] != 0, "PLAN_NONCE_SPACE")
    if options["nonce_space"] == 0:
        options["nonce_space"] = max(options["attempts"], options["training_attempts"])
    if options["scope"] == "maintenance-parent":
        require("target" not in supplied and
                ("families" not in supplied or options["families"] == ["continuity-maintenance-v1"]),
                "NATIVE_PLAN_OVERRIDES")
        options["families"] = ["continuity-maintenance-v1"]
    return validate_options(options)


def registered_grid(options):
    rows = []
    arms = [ARMS[index] for index in options["arms"]]
    for family in FAMILIES:
        if family not in options["families"]:
            continue
        for sample in range(options["samples"]):
            labels = (["adaptive-dispatcher"] if options["mode"] == "adaptive" else
                      [arms[(offset + sample) % len(arms)] for offset in range(len(arms))])
            rows.extend((family, sample, arm) for arm in labels)
    return rows


@lru_cache(maxsize=len(FAMILIES))
def material_recipe(family):
    if family in ("zero-left-rank-one", "zero-right-rank-one"):
        a, b, _, _ = expected_material("rank-one")
        a, b = (bytes(16384), b) if family == "zero-left-rank-one" else (a, bytes(16384))
        prefix = b"PNW1" + a + b + bytes(16384)
    else:
        a, b, _, prefix = expected_material(family)
    return a, b, _rank(list(struct.unpack("<4096I", a))), _rank(list(struct.unpack("<4096I", b))), prefix


def supported_recipe(arm, family):
    """Public fixture support predicates; an unsupported arm is not a free win."""
    if arm in (ARMS[0], ARMS[1], ARMS[3], ARMS[4], ARMS[5], ARMS[13]):
        return True
    if arm == "prepared-structured":
        return family in ("zero", "identity", "rank-one", "sparse-diagonal",
                          "zero-left-rank-one", "zero-right-rank-one")
    if arm in ("blocked-zero", "blocked-zero-integer-paired"):
        return family == "zero"
    if arm == "blocked-one-zero-rank-one":
        return family in ("zero-left-rank-one", "zero-right-rank-one")
    return family == "continuity-maintenance-v1"


def can_start(current):
    budget, used = current["start"]["cpu_budget_ns"], current["sum"]["cpu_ns"]
    return budget is None or (used is not None and used < budget)


def cohort_schedule(options, current):
    """Replay producer control flow, not its unobservable physical execution.

    Each yielded record is mandatory. Budgets are tested at the original Rust
    stage boundaries; batch observation is delayed without losing a charge.
    """
    def generate(arm, phase, ordinal):
        return {"kind": "charge", "stage": "generate", "arm": arm,
                "detail": {"phase": phase, "ordinal": ordinal}}

    def observe(arm, phase, ordinal):
        return {"kind": "attempt", "arm": arm, "phase": phase, "ordinal": ordinal}

    def evaluate(arm):
        if not can_start(current):
            return
        pending = []
        if options["mode"] == "batch":
            yield {"kind": "charge", "stage": "batch-buffer", "arm": arm,
                   "detail": {"capacity": options["batch_size"]}}
        for ordinal in range(options["attempts"]):
            if not can_start(current):
                break
            yield generate(arm, "evaluation", ordinal)
            pending.append(ordinal)
            if options["mode"] != "batch" or len(pending) == options["batch_size"]:
                for item in pending:
                    yield observe(arm, "evaluation", item)
                pending.clear()
        for item in pending:
            yield observe(arm, "evaluation", item)

    if options["scope"] == "maintenance-parent" and can_start(current):
        yield {"kind": "charge", "stage": "context", "arm": None}
    selected = None if options["mode"] == "adaptive" else current["start"]["arm"]
    unsupported = False
    if options["mode"] == "adaptive":
        names = [ARMS[index] for index in options["arms"]]
        candidates = []
        for offset in range(len(names)):
            if not can_start(current):
                break
            arm = names[(offset + current["start"]["sample"]) % len(names)]
            prepared = yield {"kind": "charge", "stage": "prepare", "arm": arm}
            if not prepared["detail"]["supported"]:
                continue
            completed = 0
            for ordinal in range(options["training_attempts"]):
                if not can_start(current):
                    break
                yield generate(arm, "training", ordinal)
                yield observe(arm, "training", ordinal)
                completed += 1
            if completed == options["training_attempts"]:
                candidates.append(arm)
        if can_start(current) and candidates:
            yield {"kind": "charge", "stage": "select", "arm": None,
                   "detail": {"policy": "minimum-measured-training-generation-cpu-mean; arm-order-tie-break"}}
            eligible = [arm for arm in candidates if current["training_timing"][arm]["cpu_ns"] is not None]
            require(bool(eligible), "ADAPTIVE_CPU_CLOCK_UNAVAILABLE")
            selected = min(eligible, key=lambda arm: (
                current["training_timing"][arm]["cpu_ns"] // options["training_attempts"], ARMS.index(arm)))
            yield {"kind": "selection", "selected_arm": selected}
            yield from evaluate(selected)
    elif can_start(current):
        if options["mode"] == "cold":
            for ordinal in range(options["attempts"]):
                if not can_start(current):
                    break
                prepared = yield {"kind": "charge", "stage": "prepare", "arm": selected}
                if not prepared["detail"]["supported"]:
                    unsupported = True
                    break
                if not can_start(current):
                    break
                yield generate(selected, "evaluation", ordinal)
                yield observe(selected, "evaluation", ordinal)
        else:
            prepared = yield {"kind": "charge", "stage": "prepare", "arm": selected}
            if prepared["detail"]["supported"]:
                yield from evaluate(selected)
            else:
                unsupported = True
    status = ("unsupported" if unsupported else "core-cpu-budget-stopped" if not can_start(current)
              else "no-supported-candidate" if selected is None else "attempt-cap-complete")
    yield {"kind": "cohort-end", "status": status, "selected_arm": selected}


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY:" + key)
        result[key] = value
    return result


def reject_number(value):
    raise ValueError("NON_INTEGER_JSON_NUMBER:" + value)


def decode(value):
    return json.loads(value, object_pairs_hook=unique,
                      parse_float=reject_number, parse_constant=reject_number)


def integer(value, label, nullable=False):
    if value is None and nullable:
        return None
    require(type(value) is int and 0 <= value < 1 << 64, label)
    return value


def hx(value, length, label):
    require(type(value) is str and len(value) == 2 * length and
            re.fullmatch("[0-9a-f]*", value) is not None, label)
    return bytes.fromhex(value)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def timing(value):
    require(type(value) is dict and set(value) == {"cpu_ns", "wall_ns"}, "TIMING_FIELDS")
    return {axis: integer(value[axis], "TIMING_VALUE", nullable=True)
            for axis in ("cpu_ns", "wall_ns")}


def add(left, right):
    return {key: None if left[key] is None or right[key] is None else left[key] + right[key]
            for key in ("cpu_ns", "wall_ns")}


def within(cost, budget):
    return True if budget is None else None if cost is None else cost <= budget


def ratio(numerator, denominator):
    if denominator == 0 or numerator is None or denominator is None:
        return None
    value = Fraction(numerator, denominator)
    return {"numerator": value.numerator, "denominator": value.denominator,
            "decimal": float(value)}


def checked_rows(path):
    with Path(path).open("rb") as stream:
        line_number = 0
        while line := stream.readline(MAX_LINE + 1):
            line_number += 1
            require(len(line) <= MAX_LINE and line.endswith(b"\n"),
                    f"TRUNCATED_OR_OVERLONG_RECORD:{line_number}")
            row = decode(line)
            require(type(row) is dict and row.get("schema") == SCHEMA, "ROW_SCHEMA")
            require(row.get("kind") in ROW_FIELDS, "UNKNOWN_RECORD")
            exact(row, {"schema", "kind", *ROW_FIELDS[row["kind"]].split()}, "ROW_FIELDS:" + row["kind"])
            yield row


def validate_raw(path, *, replay=True, expected_options=None):
    campaign = None
    materials = {}
    cohorts = []
    current = None
    finished = False
    material_cost = None
    examples = 0
    retained_families = set()
    winning_families = set()
    global_tickets = set()
    global_winning_tickets = set()
    row_count = 0
    for row in checked_rows(path):
        row_count += 1
        require(not finished, "DATA_AFTER_END")
        kind = row.get("kind")
        if current is not None:
            for key, expected in current["expected_record"].items():
                require(row.get(key) == expected, "COHORT_STATE_MACHINE:" + key)
        if kind == "campaign":
            require(campaign is None and row_count == 1, "CAMPAIGN_ORDER")
            campaign = row
            require(row["profile"] == "pon-matmul-transcript-64-v1" and
                    row["proof_bytes"] == PROOF_BYTES, "WORK_PROFILE")
            require(row["hardness_accepted"] is False and
                    row["production_activation"] is False and
                    row["invalid_rejection_paths_used"] is False, "AUTHORITY_PROMOTION")
            require(row["material_is_public_input"] is True and
                    row["energy_and_hardware_cost_measured"] is False, "CAMPAIGN_SCOPE")
            options = validate_options(row["options"])
            if expected_options is not None:
                require(options == validate_options(expected_options), "REGISTERED_OPTIONS_CHANGED")
            require(row["arm_names"] == [ARMS[index] for index in options["arms"]],
                    "CAMPAIGN_ARM_IDENTITIES")
            continue
        require(campaign is not None, "MISSING_CAMPAIGN")
        options = campaign["options"]
        if kind == "material-construction":
            require(material_cost is None and row_count == 2, "MATERIAL_CONSTRUCTION_ORDER")
            material_cost = timing(row["timing"])
            require(row["charged_per_producer"] is False, "PUBLIC_INPUT_COST_SCOPE")
        elif kind == "material":
            require(material_cost is not None and current is None and
                    row["family"] in options["families"] and row["family"] not in materials,
                    "MATERIAL_ORDER")
            a = hx(row["a_hex"], 4 * N * N, "MATERIAL_A")
            b = hx(row["b_hex"], 4 * N * N, "MATERIAL_B")
            require(all(word[0] < Q for matrix in (a, b)
                        for word in struct.iter_unpack("<I", matrix)), "NONCANONICAL_FIELD")
            require(digest(a) == row["a_sha256"] and digest(b) == row["b_sha256"],
                    "MATERIAL_HASH")
            require(H("task", a, b).hex() == row["task"], "MATERIAL_TASK")
            known_raw_a, known_raw_b, rank_a, rank_b, _ = material_recipe(row["family"])
            require(a == known_raw_a and b == known_raw_b,
                    "MATERIAL_PUBLIC_RECIPE")
            require(type(row["a_rank"]) is int and type(row["b_rank"]) is int and
                    row["a_rank"] == rank_a and row["b_rank"] == rank_b,
                    "MATERIAL_RANK")
            require(row["parent_eligibility_claimed"] is False, "MATERIAL_AUTHORITY")
            materials[row["family"]] = row
        elif kind == "cohort-start":
            require(current is None and row["family"] in materials, "COHORT_ORDER")
            require(row["task"] == materials[row["family"]]["task"], "COHORT_TASK")
            require(row["scope"] == options["scope"] and row["mode"] == options["mode"],
                    "COHORT_OPTIONS")
            require(row["cpu_budget_ns"] == options["cpu_budget_ns"], "COHORT_BUDGET")
            require(row["attempt_cap"] == options["attempts"], "COHORT_ATTEMPT_CAP")
            require(type(row["sample"]) is int and 0 <= row["sample"] < options["samples"] and
                    row["family"] in options["families"], "COHORT_GRID_IDENTITY")
            require(row["arm"] in (["adaptive-dispatcher"] if options["mode"] == "adaptive"
                    else campaign["arm_names"]), "COHORT_ARM")
            grid = registered_grid(options)
            require(len(cohorts) < len(grid) and (row["family"], row["sample"], row["arm"]) == grid[len(cohorts)],
                    "REGISTERED_COHORT_ORDER")
            require(row["cohort"] == "/".join((options["scope"], row["family"], options["mode"],
                                               row["arm"], str(row["sample"]))), "COHORT_CANONICAL_ID")
            require(row["qualification_level"] == ("relation-only-public-input" if options["scope"] == "relation"
                    else "pending-original-parent-acquisition"), "COHORT_QUALIFICATION")
            current = {"start": row, "charges": [], "sum": {"cpu_ns": 0, "wall_ns": 0},
                       "observer": {"cpu_ns": 0, "wall_ns": 0}, "seen": set(),
                       "counts": Counter(), "parents": Counter(), "selection": None,
                       "inclusive_previous": 0, "targets": ({bytes(options["target"]).hex()} if options["scope"] == "relation" else set()), "stage_cpu": Counter(),
                       "training_scores": defaultdict(lambda: [0, 0]),
                       "training_timing": defaultdict(lambda: {"cpu_ns": 0, "wall_ns": 0}),
                       "native_acquisition": None, "prepared_arms": {}, "phase_ordinals": Counter(),
                       "all_work_seen": set(), "all_work_budget_seen": set(), "auxiliary": [],
                       "used_generation_charges": set(), "python_replayed": Counter()}
            current["schedule"] = cohort_schedule(options, current)
            current["expected_record"] = next(current["schedule"])
        elif kind == "charge":
            require(current is not None and row["cohort"] == current["start"]["cohort"],
                    "CHARGE_COHORT")
            require(row["seq"] == len(current["charges"]), "CHARGE_SEQUENCE")
            uint64(row["seq"], "CHARGE_SEQUENCE_TYPE")
            value = timing(row["timing"])
            current["sum"] = add(current["sum"], value)
            require(current["sum"] == timing(row["cumulative"]), "CHARGE_SUM")
            budget = current["start"]["cpu_budget_ns"]
            require(row["within_cpu_budget"] is within(current["sum"]["cpu_ns"], budget),
                    "CHARGE_BUDGET_FENCE")
            expected_overrun = (None if budget is None or current["sum"]["cpu_ns"] is None
                                else max(0, current["sum"]["cpu_ns"] - budget))
            require(row["overrun_cpu_ns"] == expected_overrun, "CHARGE_OVERRUN")
            if value["cpu_ns"] is not None:
                current["stage_cpu"][row["stage"]] += value["cpu_ns"]
            if row["stage"] == "context":
                require(current["native_acquisition"] is None, "DUPLICATE_CONTEXT_CHARGE")
                current["native_acquisition"] = row["detail"]
                context = row["detail"]
                exact(context, ("source", "qualification_level", "parent_count", "genesis", "acquisition",
                                "acquisition_outputs_counted_as_selected_arm_wins",
                                "acquisition_outputs_counted_in_all_work_numerator", "sibling_work_is_not_summed_as_one_chain"),
                      "AUXILIARY_CONTEXT_FIELDS")
                require(context["source"] == "original-Node-make_consensus_maintenance" and
                        context["qualification_level"] == "parent-eligible-maintenance-template" and
                        context["parent_count"] == 3 and
                        context["acquisition_outputs_counted_as_selected_arm_wins"] is False and
                        context["acquisition_outputs_counted_in_all_work_numerator"] is True and
                        context["sibling_work_is_not_summed_as_one_chain"] is True, "AUXILIARY_CONTEXT_SCOPE")
                hx(context["genesis"], 32, "AUXILIARY_GENESIS")
                entries = context["acquisition"]
                require(type(entries) is list and len(entries) == 5 and
                        [(entry["role"], entry["branch"]) for entry in entries] ==
                        [("fork-parent", None), ("fork-parent", None),
                         ("original-node-template", 0), ("original-node-template", 1), ("original-node-template", 2)],
                        "AUXILIARY_CONTEXT_COMPLETENESS")
                previous_completion = 0
                for index, entry in enumerate(entries):
                    exact(entry, ("role", "branch", "block_id", "parent", "height", "header_hex", "task", "target",
                                  "challenge", "trace", "ticket", "semantic_id", "proof_sha256", "proof_bytes",
                                  "target_hit", "winning_nonce", "original_make_complete_attempts",
                                  "original_make_failed_attempts", "inclusive_producer_cpu_ns",
                                  "admission_completion_inclusive_cpu_ns", "qualification_level", "admitted",
                                  "full_relation_verified_by_original_node_admit", "counted_in_selected_arm_numerator",
                                  "counted_in_all_work_numerator"), "AUXILIARY_FIELDS")
                    header_bytes = hx(entry["header_hex"], 318, "AUXILIARY_HEADER")
                    header = header_decode(header_bytes)
                    challenge = H("challenge", header_bytes)
                    trace = hx(entry["trace"], 32, "AUXILIARY_TRACE")
                    ticket = H("ticket", challenge, trace)
                    semantic = H("w1-cost-game-semantic-ticket-v1", header["work_task"], challenge, ticket).hex()
                    require(header_encode(header) == header_bytes and
                            entry["task"] == header["work_task"].hex() == current["start"]["task"] and
                            entry["challenge"] == challenge.hex() and entry["ticket"] == ticket.hex() and
                            entry["target"] == header["target"].hex() and
                            entry["block_id"] == H("block", header_bytes, trace).hex() and
                            entry["semantic_id"] == semantic and entry["parent"] == header["parent"].hex(),
                            "AUXILIARY_BINDING")
                    expected_parent = (context["genesis"] if index <= 2 else entries[index - 3]["block_id"])
                    require(entry["parent"] == expected_parent and
                            entry["height"] == header["height"] == (1 if index <= 2 else 2) and
                            entry["winning_nonce"] == header["nonce"], "AUXILIARY_PARENT_BINDING")
                    hx(entry["proof_sha256"], 32, "AUXILIARY_PROOF_HASH")
                    require(entry["proof_sha256"] == digest(material_recipe(current["start"]["family"])[4] + trace),
                            "AUXILIARY_CANONICAL_PROOF_HASH")
                    require(header["target"] != bytes(32) and ticket <= header["target"] and
                            entry["admitted"] is True and entry["target_hit"] is True and
                            entry["full_relation_verified_by_original_node_admit"] is True and
                            entry["proof_bytes"] == PROOF_BYTES and
                            entry["qualification_level"] == "native-admitted-maintenance" and
                            entry["counted_in_selected_arm_numerator"] is False and
                            entry["counted_in_all_work_numerator"] is True,
                            "AUXILIARY_FULL_VALIDITY")
                    require(1 <= entry["original_make_complete_attempts"] <= 4096 and
                            entry["original_make_complete_attempts"] == header["nonce"] + 1 and
                            entry["original_make_failed_attempts"] == header["nonce"],
                            "AUXILIARY_FAILED_SEARCH_COST")
                    completion = integer(entry["inclusive_producer_cpu_ns"], "AUXILIARY_COMPLETION")
                    admitted = integer(entry["admission_completion_inclusive_cpu_ns"], "AUXILIARY_ADMISSION_COMPLETION")
                    require(previous_completion <= completion <= admitted, "AUXILIARY_COMPLETION_ORDER")
                    previous_completion = admitted
                    fresh = semantic not in current["all_work_seen"]
                    require(fresh, "DUPLICATE_AUXILIARY_WORK")
                    current["all_work_seen"].add(semantic)
                    global_tickets.add(semantic)
                    global_winning_tickets.add(semantic)
                    current["counts"]["all_work_target_hits"] += 1
                    current["counts"]["all_work_unique_target_hits"] += int(fresh)
                    current["counts"]["all_work_inclusive_budget_unique_target_hits"] += int(fresh and within(completion, budget))
                    if within(completion, budget) is True:
                        current["all_work_budget_seen"].add(semantic)
                    current["counts"]["auxiliary_original_node_work"] += 1
                    current["counts"]["auxiliary_original_node_attempts"] += entry["original_make_complete_attempts"]
                    current["auxiliary"].append(entry)
                    if entry["role"] == "original-node-template":
                        current["targets"].add(entry["target"])
                current["inclusive_previous"] = previous_completion
            if row["stage"] == "prepare":
                exact(row["detail"], ("supported",), "PREPARE_DETAIL")
                require(type(row["detail"]["supported"]) is bool, "PREPARE_SUPPORT_TYPE")
                require(row["detail"]["supported"] is supported_recipe(row["arm"], current["start"]["family"]),
                        "PREPARE_PUBLIC_SUPPORT_RECIPE")
                if options["mode"] == "adaptive":
                    require(row["arm"] in campaign["arm_names"] and
                            row["arm"] not in current["prepared_arms"], "ADAPTIVE_PREPARE_SET")
                current["prepared_arms"][row["arm"]] = row["detail"]["supported"]
            current["charges"].append(row)
        elif kind == "attempt":
            require(current is not None and row["cohort"] == current["start"]["cohort"],
                    "ATTEMPT_COHORT")
            counts = current["counts"]
            require(row["attempt_index"] == counts["attempts"], "ATTEMPT_SEQUENCE")
            for field in ("attempt_index", "ordinal", "nonce"):
                uint64(row[field], "ATTEMPT_INTEGER:" + field)
            require(row["phase"] in ("training", "evaluation"), "ATTEMPT_PHASE")
            require(row["arm"] in campaign["arm_names"], "ATTEMPT_ARM")
            phase_key = (row["phase"], row["arm"])
            require(row["ordinal"] == current["phase_ordinals"][phase_key], "PHASE_ORDINAL")
            current["phase_ordinals"][phase_key] += 1
            if options["mode"] == "adaptive":
                if row["phase"] == "evaluation":
                    require(current["selection"] == row["arm"], "EVALUATION_IGNORES_SELECTION")
                else:
                    require(current["selection"] is None, "TRAINING_AFTER_SELECTION")
            else:
                require(row["phase"] == "evaluation" and row["arm"] == current["start"]["arm"],
                        "FIXED_STRATEGY_CHANGED")
            task = hx(row["task"], 32, "TASK")
            require(row["task"] == current["start"]["task"], "ATTEMPT_TASK")
            challenge = hx(row["challenge"], 32, "CHALLENGE")
            trace, ticket = hx(row["trace"], 32, "TRACE"), hx(row["ticket"], 32, "TICKET")
            target = hx(row["target"], 32, "TARGET")
            require(H("ticket", challenge, trace) == ticket, "TICKET_HASH")
            hit = target != bytes(32) and ticket <= target
            require(row["target_hit"] is hit, "TARGET_PREDICATE")
            semantic = H("w1-cost-game-semantic-ticket-v1", task, challenge, ticket).hex()
            require(row["semantic_id"] == semantic, "SEMANTIC_ID")
            fresh = semantic not in current["seen"]
            require(row["unique_ticket"] is fresh, "DUPLICATE_TICKET_CREDIT")
            current["seen"].add(semantic)
            all_fresh = semantic not in current["all_work_seen"]
            global_tickets.add(semantic)
            if hit:
                global_winning_tickets.add(semantic)
                current["all_work_seen"].add(semantic)
            if options["scope"] == "relation":
                logical = row["ordinal"] % options["nonce_space"]
                expected = H("w1-cost-game-challenge-v1", task, u64(options["seed"]),
                             u64(current["start"]["sample"]), row["phase"].encode(), u64(logical))
                require(challenge == expected and row["nonce"] == logical, "RELATION_CHALLENGE")
                require(row["header_hex"] is None and row["parent"] is None and
                        row["block_id"] is None and row["native_admission"] is None,
                        "DIAGNOSTIC_INPUT_GRANTED_NATIVE_AUTHORITY")
                require(target == bytes(options["target"]), "RELATION_TARGET")
                require(row["qualification_level"] == "relation-valid-only", "RELATION_LEVEL")
            else:
                raw_header = hx(row["header_hex"], 318, "HEADER")
                header = header_decode(raw_header)
                require(header_encode(header) == raw_header, "HEADER_CANONICAL")
                require(H("challenge", raw_header) == challenge, "HEADER_CHALLENGE")
                require(header["work_task"] == task and header["target"] == target and
                        header["nonce"] == row["nonce"] and
                        header["parent"].hex() == row["parent"], "HEADER_FIELDS")
                require(H("block", raw_header, trace).hex() == row["block_id"], "BLOCK_ID")
                context = current["native_acquisition"]
                require(context is not None, "UNPAID_NATIVE_CONTEXT")
                templates = [entry for entry in context["acquisition"]
                             if entry["role"] == "original-node-template"]
                expected_template = templates[(row["ordinal"] % options["nonce_space"]) % len(templates)]
                expected_header = header_decode(bytes.fromhex(expected_template["header_hex"]))
                nonce_digest = H("w1-cost-game-native-nonce-v1", u64(options["seed"]),
                                 u64(current["start"]["sample"]), row["phase"].encode(),
                                 u64(row["ordinal"] % options["nonce_space"]))
                expected_header["nonce"] = int.from_bytes(nonce_digest[:8], "little")
                require(header == expected_header, "ORIGINAL_PARENT_TEMPLATE")
                if hit:
                    admission = row["native_admission"]
                    exact(admission, ("admitted", "qualification_level", "block_id", "duplicate_replay_block_id",
                                      "duplicate_replay_creates_new_semantic_work", "activated", "parent", "height", "target"),
                          "NATIVE_ADMISSION_FIELDS")
                    require(admission["admitted"] is True and
                            admission["block_id"] == row["block_id"] and
                            admission["duplicate_replay_block_id"] == row["block_id"] and
                            admission["duplicate_replay_creates_new_semantic_work"] is False and
                            admission["activated"] is False and
                            admission["parent"] == row["parent"] and admission["height"] == header["height"] and
                            admission["target"] == row["target"] and
                            admission["qualification_level"] == row["qualification_level"] == "native-admitted-maintenance",
                            "NATIVE_ADMISSION_OR_DUPLICATE")
                else:
                    require(row["native_admission"] is None and
                            row["qualification_level"] == "parent-eligible-maintenance-relation", "MISS_ADMISSION")
            require(row["proof_bytes"] == PROOF_BYTES and row["relation_valid"] is True,
                    "FULL_RELATION_REQUIRED")
            require(row["production_verifier"]["accepted"] is True and
                    row["reference_verifier"]["accepted"] is True and
                    row["production_verifier"]["error"] is None and
                    row["reference_verifier"]["error"] is None, "FULL_VERIFIERS")
            exact(row["production_verifier"], ("accepted", "timing", "target_used", "error"), "PRODUCTION_VERIFIER_FIELDS")
            exact(row["reference_verifier"], ("accepted", "timing", "error"), "REFERENCE_VERIFIER_FIELDS")
            require(row["production_verifier"]["target_used"] == "ff" * 32,
                    "RELATION_OBSERVER_TARGET")
            hx(row["proof_sha256"], 32, "PROOF_HASH")
            hx(row["product_sha256"], 32, "PRODUCT_HASH")
            prefix = material_recipe(current["start"]["family"])[4]
            require(row["proof_sha256"] == digest(prefix + trace) and
                    row["product_sha256"] == digest(prefix[4 + 8 * N * N:]), "CANONICAL_PROOF_PRODUCT_HASH")
            charge_seq = integer(row["charge_seq"], "ATTEMPT_CHARGE_SEQ")
            require(charge_seq < len(current["charges"]), "ATTEMPT_WITHOUT_CHARGE")
            require(charge_seq not in current["used_generation_charges"], "REUSED_GENERATION_CHARGE")
            current["used_generation_charges"].add(charge_seq)
            charge = current["charges"][charge_seq]
            require(charge["stage"] == "generate" and charge["arm"] == row["arm"] and
                    charge["detail"] == {"ordinal": row["ordinal"], "phase": row["phase"]},
                    "ATTEMPT_CHARGE_BINDING")
            require(row["generation_timing"] == charge["timing"] and
                    row["cumulative_charged_cpu_ns"] == charge["cumulative"]["cpu_ns"],
                    "ATTEMPT_TIMING")
            budget = current["start"]["cpu_budget_ns"]
            require(row["within_cpu_budget"] is within(row["cumulative_charged_cpu_ns"], budget),
                    "ATTEMPT_BUDGET_FENCE")
            inclusive = integer(row["inclusive_producer_cpu_ns"], "INCLUSIVE_CPU", nullable=True)
            require(row["inclusive_within_cpu_budget"] is within(inclusive, budget),
                    "INCLUSIVE_BUDGET_FENCE")
            if inclusive is not None:
                require(inclusive >= current["inclusive_previous"] and
                        (row["cumulative_charged_cpu_ns"] is None or
                         inclusive >= row["cumulative_charged_cpu_ns"]), "INCLUSIVE_CPU_ORDER")
                current["inclusive_previous"] = inclusive
            for item in (row["production_verifier"]["timing"],
                         row["reference_verifier"]["timing"], row["native_admission_timing"]):
                current["observer"] = add(current["observer"], timing(item))
            if options["scope"] == "relation" or not hit:
                require(timing(row["native_admission_timing"]) == {"cpu_ns": 0, "wall_ns": 0},
                        "UNPERFORMED_ADMISSION_TIMING")
            family = current["start"]["family"]
            first_hit = hit and family not in winning_families
            require((row["proof_hex"] is not None) is first_hit, "FIRST_WINNING_CERTIFICATE_RETENTION")
            if hit:
                winning_families.add(family)
            if row["proof_hex"] is not None:
                retained_families.add(family)
                proof = hx(row["proof_hex"], PROOF_BYTES, "PROOF_ENCODING")
                require(digest(proof) == row["proof_sha256"] and proof[-32:] == trace,
                        "RETAINED_CERTIFICATE_HASH")
                require(digest(proof[4 + 8 * N * N:-32]) == row["product_sha256"],
                        "RETAINED_PRODUCT_HASH")
                material = materials[current["start"]["family"]]
                require(proof[4:4 + 4 * N * N].hex() == material["a_hex"] and
                        proof[4 + 4 * N * N:4 + 8 * N * N].hex() == material["b_hex"],
                        "RETAINED_MATERIAL")
                if replay:
                    result, _ = work_oracle.verify(challenge, task, b"\xff" * 32, proof)
                    require(result == ticket, "PYTHON_FULL_RELATION")
                    examples += 1
                    current["python_replayed"]["full_relation_attempts"] += 1
                    current["python_replayed"]["winning_attempts"] += int(hit)
                    current["python_replayed"]["in_core_budget_winning_attempts"] += int(hit and row["within_cpu_budget"] is True)
                    current["python_replayed"]["in_inclusive_budget_winning_attempts"] += int(hit and row["inclusive_within_cpu_budget"] is True)
            counts["attempts"] += 1
            counts[row["phase"] + "_attempts"] += 1
            counts["target_hits"] += int(hit)
            counts["unique_target_hits"] += int(hit and fresh)
            counts["unique_opportunities"] += int(fresh)
            counts["budget_unique_opportunities"] += int(fresh and row["within_cpu_budget"] is True)
            counts["inclusive_budget_unique_opportunities"] += int(fresh and row["inclusive_within_cpu_budget"] is True)
            counts["budget_unique_target_hits"] += int(hit and fresh and row["within_cpu_budget"] is True)
            counts["inclusive_budget_unique_target_hits"] += int(hit and fresh and row["inclusive_within_cpu_budget"] is True)
            counts["all_work_target_hits"] += int(hit)
            counts["all_work_unique_target_hits"] += int(hit and all_fresh)
            counts["all_work_inclusive_budget_unique_target_hits"] += int(hit and all_fresh and row["inclusive_within_cpu_budget"] is True)
            if hit and row["inclusive_within_cpu_budget"] is True:
                current["all_work_budget_seen"].add(semantic)
            counts["evaluation_budget_unique_target_hits"] += int(hit and fresh and
                    row["phase"] == "evaluation" and row["within_cpu_budget"] is True)
            counts["unique_native_admitted"] += int(hit and fresh and options["scope"] == "maintenance-parent")
            if row["parent"] is not None and hit and fresh:
                current["parents"][row["parent"]] += 1
            if row["phase"] == "training":
                score = current["training_scores"][row["arm"]]
                score[0] = (None if score[0] is None or row["generation_timing"]["cpu_ns"] is None
                            else score[0] + row["generation_timing"]["cpu_ns"])
                score[1] += 1
                current["training_timing"][row["arm"]] = add(
                    current["training_timing"][row["arm"]], timing(row["generation_timing"]))
            current["targets"].add(row["target"])
        elif kind == "selection":
            require(current is not None and row["cohort"] == current["start"]["cohort"] and
                    current["selection"] is None, "SELECTION_SCOPE")
            require(options["mode"] == "adaptive", "UNREGISTERED_ADAPTATION")
            scores = row["scores"]
            require(type(scores) is list and bool(scores), "EMPTY_SELECTION")
            require(all(row[key] is True for key in ("policy_frozen_before_evaluation", "training_stream_disjoint",
                    "training_and_all_candidate_preparation_charged", "training_unique_wins_counted")), "SELECTION_SCOPE_FLAGS")
            require(set(current["prepared_arms"]) == set(campaign["arm_names"]),
                    "SELECTION_MISSING_REGISTERED_CANDIDATE")
            supported = {arm for arm, ok in current["prepared_arms"].items() if ok}
            require(len(scores) == len(supported) and {score["arm"] for score in scores} == supported,
                    "SELECTION_CANDIDATE_SET")
            for score in scores:
                exact(score, ("arm", "training_attempts", "training_generation_timing", "training_mean_cpu_ns"),
                      "SELECTION_SCORE_FIELDS")
                observed = current["training_scores"][score["arm"]]
                require(observed == [score["training_generation_timing"]["cpu_ns"],
                                     score["training_attempts"]], "SELECTION_TRAINING_DATA")
                require(timing(score["training_generation_timing"]) == current["training_timing"][score["arm"]],
                        "SELECTION_TRAINING_TIMING")
                require(score["training_attempts"] == options["training_attempts"] and
                        score["training_mean_cpu_ns"] == (None if observed[0] is None else observed[0] // observed[1]),
                        "SELECTION_SCORE")
            eligible = [score for score in scores if score["training_mean_cpu_ns"] is not None]
            require(bool(eligible), "SELECTION_CPU_UNAVAILABLE")
            selected = min(eligible, key=lambda score: (score["training_mean_cpu_ns"],
                              ARMS.index(score["arm"])))
            require(selected["arm"] == row["selected_arm"], "POSTHOC_SELECTION")
            current["selection"] = row["selected_arm"]
        elif kind == "cohort-end":
            require(current is not None and row["cohort"] == current["start"]["cohort"],
                    "COHORT_END_SCOPE")
            require(row["charge_records"] == len(current["charges"]) and
                    timing(row["charged"]) == current["sum"], "END_CHARGE_SUM")
            require(timing(row["observer_verification_and_admission"]) == current["observer"],
                    "END_OBSERVER_SUM")
            for key in ("attempts", "evaluation_attempts", "training_attempts", "target_hits",
                        "unique_target_hits", "budget_unique_target_hits",
                        "evaluation_budget_unique_target_hits", "unique_native_admitted"):
                require(row[key] == current["counts"][key], "END_COUNT:" + key)
                uint64(row[key], "END_COUNT_TYPE:" + key)
            for key in ("inclusive_budget_unique_target_hits", "auxiliary_original_node_work",
                        "all_work_target_hits", "all_work_unique_target_hits",
                        "all_work_inclusive_budget_unique_target_hits"):
                require(row[key] == current["counts"][key], "END_ALL_WORK_COUNT:" + key)
                uint64(row[key], "END_COUNT_TYPE:" + key)
            require(row["target_misses"] == current["counts"]["attempts"] - current["counts"]["target_hits"],
                    "END_TARGET_MISSES")
            uint64(row["target_misses"], "END_TARGET_MISSES_TYPE")
            current["counts"]["target_misses"] = row["target_misses"]
            require(row["all_work_unique_target_hits"] == len(current["all_work_seen"]) and
                    row["all_work_inclusive_budget_unique_target_hits"] == len(current["all_work_budget_seen"]),
                    "ALL_WORK_SEMANTIC_UNION")
            require(len(current["used_generation_charges"]) ==
                    sum(charge["stage"] == "generate" for charge in current["charges"]), "UNOBSERVED_GENERATION_CHARGE")
            budget, cpu_used = current["start"]["cpu_budget_ns"], current["sum"]["cpu_ns"]
            expected_overrun = None if budget is None or cpu_used is None else max(0, cpu_used - budget)
            require(row["cpu_budget_ns"] == budget and row["overrun_cpu_ns"] == expected_overrun, "END_BUDGET")
            elapsed = timing(row["cohort_elapsed"])
            overhead = timing(row["observer_logging_and_unattributed_overhead"])
            require(add(add(current["sum"], current["observer"]), overhead) == elapsed,
                    "INCLUSIVE_INTERVAL_RECONCILIATION")
            inclusive = {key: None if elapsed[key] is None or current["observer"][key] is None
                         else elapsed[key] - current["observer"][key]
                         for key in ("cpu_ns", "wall_ns")}
            require(timing(row["inclusive_producer_timing"]) == inclusive, "END_INCLUSIVE_CPU")
            require(inclusive["cpu_ns"] is None or inclusive["cpu_ns"] >= current["inclusive_previous"],
                    "END_BEFORE_LAST_COMPLETION")
            require(row["successful_work_lower_bound_claimed"] is False and
                    row["production_activation"] is False and row["zero_wins_retained"] is True and
                    row["all_work_is_distinct_candidates_not_additive_chainweight"] is True and
                    row["inclusive_budget_excludes_global_public_material_construction"] is True, "END_AUTHORITY")
            cohorts.append({**current["start"], "seed": options["seed"],
                "nonce_space": options["nonce_space"], "training_attempts_per_arm": options["training_attempts"],
                "batch_size": options["batch_size"],
                "status": row["status"], "counts": dict(current["counts"]),
                "charged": current["sum"], "inclusive": inclusive,
                "observer": current["observer"], "overhead": overhead,
                "stage_cpu_ns": dict(current["stage_cpu"]),
                "selected_arm": row["selected_arm"], "targets": sorted(current["targets"]),
                "parent_winner_counts": dict(current["parents"]),
                "native_context_acquisition": current["native_acquisition"],
                "native_reported": {key: current["counts"][key] for key in COUNT_KEYS},
                "python_replayed": {key: current["python_replayed"][key] for key in REPLAY_KEYS},
                "overrun_cpu_ns": row["overrun_cpu_ns"]})
            current["schedule"].close()
            current = None
        elif kind == "end":
            require(current is None and row["cohorts"] == len(cohorts) and
                    row["complete"] is True, "INCOMPLETE_END")
            require(row["hardness_accepted"] is False and row["production_activation"] is False,
                    "CAMPAIGN_END_AUTHORITY")
            expected = len(options["families"]) * options["samples"]
            if options["mode"] != "adaptive":
                expected *= len(options["arms"])
            require(len(cohorts) == expected and set(materials) == set(options["families"]),
                    "INCOMPLETE_REGISTERED_GRID")
            identities = {(item["family"], item["sample"], item["arm"]) for item in cohorts}
            registered = {(family, sample, arm) for family in options["families"]
                          for sample in range(options["samples"])
                          for arm in (["adaptive-dispatcher"] if options["mode"] == "adaptive"
                                      else campaign["arm_names"])}
            require(identities == registered and len(identities) == len(cohorts),
                    "MISSING_OR_DUPLICATE_COHORT")
            finished = True
        else:
            raise ValueError("UNKNOWN_RECORD:" + str(kind))
        if current is not None and kind in ("charge", "attempt", "selection"):
            current["expected_record"] = current["schedule"].send(row)
    require(finished and material_cost is not None, "MISSING_END_OR_MATERIAL")
    require(retained_families == winning_families, "MISSING_REPRESENTATIVE_CERTIFICATE")
    return {"schema": "pon-w1-cost-research-raw-derived-v1", "file": str(path), "sha256": sha(path), "rows": row_count,
            "options": campaign["options"], "material_construction": material_cost,
            "python_full_relation_replays": examples, "cohorts": cohorts,
            "registered_options_checked": expected_options is not None,
            "native_reported": count_sum(cohorts, "native_reported", COUNT_KEYS),
            "python_replayed": count_sum(cohorts, "python_replayed", REPLAY_KEYS),
            "python_replay_executed": replay,
            "certificate_retention_policy": "first native-reported winning research attempt per family; outcome-selected, not unbiased",
            "retained_winning_families": sorted(retained_families),
            "all_native_reported_attempts_independently_verified": False,
            "native_execution_attested_by_reader": False,
            "inclusive_budget_completion_event": "producer-complete candidate, subsequently confirmed by the observer; not admission completed by B",
            "inclusive_interval_excludes_native_context_and_tempdir_drop_after_endpoint": True,
            "hardness_accepted": False, "production_activation": False,
            "distinct_observed_ticket_identities": len(global_tickets),
            "distinct_observed_winning_ticket_identities": len(global_winning_tickets),
            "counterfactual_cohorts_are_not_additive_chainwork": True}


def sum_nullable(values):
    values = list(values)
    return None if any(value is None for value in values) else sum(values)


def count_sum(rows, field, keys):
    return {key: sum(row[field].get(key, 0) for row in rows) for key in keys}


def pair_identity(row):
    return (row["seed"], row["sample"], row["task"], tuple(row["targets"]),
            row["nonce_space"], row["training_attempts_per_arm"], row["batch_size"])


def derive(raw_results):
    groups = defaultdict(list)
    for raw in raw_results:
        for cohort in raw["cohorts"]:
            key = (cohort["scope"], cohort["mode"], cohort["family"], cohort["arm"],
                   cohort["cpu_budget_ns"], cohort["attempt_cap"], tuple(cohort["targets"]),
                   cohort["nonce_space"], cohort["training_attempts_per_arm"], cohort["batch_size"])
            groups[key].append(cohort)
    summaries = []
    for key, rows in sorted(groups.items(), key=lambda item: str(item[0])):
        scope, mode, family, arm, budget, cap, targets, nonce_space, training, batch_size = key
        identities = [pair_identity(row) for row in rows]
        require(len(set(identities)) == len(identities), "REPEATED_COUNTERFACTUAL_COHORT")
        counts, stages, replays = Counter(), Counter(), Counter()
        for row in rows:
            counts.update(row["native_reported"])
            stages.update(row["stage_cpu_ns"])
            replays.update(row["python_replayed"])
        core = sum_nullable(row["charged"]["cpu_ns"] for row in rows)
        inclusive = sum_nullable(row["inclusive"]["cpu_ns"] for row in rows)
        unsupported = sum(row["status"] == "unsupported" for row in rows)
        summaries.append({"scope": scope, "mode": mode, "family": family, "arm": arm,
            "budget_ns": budget, "attempt_cap": cap, "targets": list(targets),
            "nonce_space": nonce_space, "training_attempts_per_arm": training, "batch_size": batch_size,
            "cohorts": len(rows), "seeds": sorted({row["seed"] for row in rows}),
            "paired_identities": [list(identity) for identity in sorted(identities)],
            "unsupported_cohorts": unsupported, "statuses": dict(Counter(row["status"] for row in rows)),
            "complete_fixed_strategy": unsupported == 0 and mode != "adaptive",
            "complete_fixed_strategy_means": "registered ledger and stopping rule reconciled; no physical cost or hardness qualification",
            "counts": {key: counts[key] for key in COUNT_KEYS},
            "native_reported": {key: counts[key] for key in COUNT_KEYS},
            "python_replayed": {key: replays[key] for key in REPLAY_KEYS},
            "charged_cpu_ns": core, "inclusive_cpu_ns": inclusive, "stage_cpu_ns": dict(stages),
            "core_cpu_per_unique_opportunity": ratio(core, counts["unique_opportunities"]),
            "inclusive_cpu_per_unique_opportunity": ratio(inclusive, counts["unique_opportunities"]),
            "core_cpu_per_in_budget_winner": ratio(core, counts["budget_unique_target_hits"]),
            "inclusive_cpu_per_inclusive_budget_winner": ratio(inclusive, counts["inclusive_budget_unique_target_hits"]),
            "research_producer_inclusive_cpu_per_inclusive_budget_winner": ratio(inclusive, counts["inclusive_budget_unique_target_hits"]),
            "inclusive_cpu_per_all_work_inclusive_budget_winner": ratio(inclusive, counts["all_work_inclusive_budget_unique_target_hits"]),
            "research_producer_denominator_scope": "registered strategy training/evaluation outputs, excluding auxiliary original-node acquisition proofs",
            "all_work_denominator_scope": "distinct research and auxiliary winning candidates production-complete by B; later observer confirmation; no additive sibling chainweight",
            "selected_arms": dict(Counter(row["selected_arm"] for row in rows if row["selected_arm"])),
        })
    def common(row):
        return (row["scope"], row["mode"], row["family"], row["budget_ns"], row["attempt_cap"],
                tuple(row["targets"]), row["nonce_space"], row["training_attempts_per_arm"], row["batch_size"])
    lookup = {(*common(row), row["arm"]): row for row in summaries}
    for row in summaries:
        base = lookup.get((*common(row), "prepared-generic"))
        matched = base is not None and row["paired_identities"] == base["paired_identities"]
        if base is not None:
            require(matched, "UNPAIRED_BASELINE_DENOMINATOR")
        row["same_task_seed_sample_pairs_as_generic"] = matched
        for cost_key, destination in (("charged_cpu_ns", "observed_core_opportunity_rate_ratio_to_generic"),
                                      ("inclusive_cpu_ns", "observed_inclusive_opportunity_rate_ratio_to_generic")):
            row[destination] = None
            if (matched and not row["unsupported_cohorts"] and not base["unsupported_cohorts"] and
                    row[cost_key] is not None and base[cost_key] is not None):
                row[destination] = ratio(base[cost_key] * row["native_reported"].get("unique_opportunities", 0),
                                         row[cost_key] * base["native_reported"].get("unique_opportunities", 0))
        row["observed_all_work_inclusive_winner_rate_ratio_to_generic"] = None
        if (matched and not row["unsupported_cohorts"] and not base["unsupported_cohorts"] and
                row["inclusive_cpu_ns"] is not None and base["inclusive_cpu_ns"] is not None):
            row["observed_all_work_inclusive_winner_rate_ratio_to_generic"] = ratio(
                base["inclusive_cpu_ns"] * row["native_reported"]["all_work_inclusive_budget_unique_target_hits"],
                row["inclusive_cpu_ns"] * base["native_reported"]["all_work_inclusive_budget_unique_target_hits"])
    return summaries


def validate_plan(plan):
    require(type(plan) is dict and plan.get("schema") == "pon-w1-cost-research-plan-v1", "PLAN_SCHEMA")
    require(plan.get("production_activation") is False and plan.get("hardness_accepted") is False and
            plan.get("work_function_changed") is False, "PLAN_AUTHORITY")
    hx(plan["baseline_source"], 20, "PLAN_BASELINE")
    jobs = plan.get("jobs")
    require(type(jobs) is list and 1 <= len(jobs) <= 64, "PLAN_JOB_COUNT")
    names = set(SETUP_NAMES)
    for job in jobs:
        exact(job, ("name", "args", "timeout_seconds"), "PLAN_JOB_FIELDS")
        name = job["name"]
        require(type(name) is str and re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name) is not None and
                name not in names, "PLAN_DUPLICATE_OR_RESERVED_JOB")
        names.add(name)
        require(type(job["args"]) is list and 1 <= len(job["args"]) <= 64 and
                all(type(arg) is str and len(arg) <= 4096 for arg in job["args"]), "PLAN_JOB_ARGS")
        uint64(job["timeout_seconds"], "PLAN_JOB_TIMEOUT", 1, 1800)
        options_from_args(job["args"])
    return jobs


def bundle_file(directory, name, maximum=64 * 1024 * 1024):
    require(type(name) is str and Path(name).name == name and name not in ("", ".", ".."), "BUNDLE_FILE_NAME")
    path = directory / name
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= maximum, "BUNDLE_FILE_SCOPE")
    return path


def verify_source_objects(head, tree, plan_source, plan_sha256, runner_sha256):
    """Bind the owner-supplied identities to immutable local Git objects."""
    command = ["git", "--no-replace-objects", "-C", str(ROOT)]
    actual_tree = subprocess.check_output(command + ["rev-parse", head + "^{tree}"], timeout=30).decode().strip()
    require(actual_tree == tree, "SOURCE_COMMIT_TREE_BINDING")
    for path, expected in ((str(plan_source), plan_sha256), ("scripts/run_w1_cost_research.py", runner_sha256)):
        contents = subprocess.check_output(command + ["show", head + ":" + path], timeout=30)
        require(digest(contents) == expected, "SOURCE_BLOB_BINDING:" + path)


def validate_child_resources(value):
    numeric = ("user_cpu_ns", "system_cpu_ns", "minor_page_faults", "major_page_faults", "input_blocks",
               "output_blocks", "voluntary_context_switches", "involuntary_context_switches", "runner_lifetime_max_child_rss_kib")
    exact(value, (*numeric, "rss_scope", "cpu_scope", "block_counts_are_network_bytes"), "CHILD_RESOURCE_FIELDS")
    for key in numeric:
        uint64(value[key], "CHILD_RESOURCE_VALUE:" + key)
    require(value["rss_scope"] == "Linux cumulative maximum over waited children, including setup; not this step's peak or a sum" and
            value["cpu_scope"] == "whole waited child including all observers, logging and teardown; not producer-only" and
            value["block_counts_are_network_bytes"] is False, "CHILD_RESOURCE_SCOPE")
    return value


def read_bundle(directory, *, expected_head, expected_tree, expected_plan_sha256,
                expected_binary_sha256, expected_manifest_sha256):
    for value, length, label in ((expected_head, 20, "HEAD"), (expected_tree, 20, "TREE"),
                                (expected_plan_sha256, 32, "PLAN"), (expected_binary_sha256, 32, "BINARY"),
                                (expected_manifest_sha256, 32, "MANIFEST")):
        hx(value, length, "EXTERNAL_EXPECTED_" + label)
    directory = Path(directory).resolve()
    manifest_path = bundle_file(directory, "campaign.json", 8 * 1024 * 1024)
    plan_path = bundle_file(directory, "preregistered-plan.json", 1024 * 1024)
    require(sha(manifest_path) == expected_manifest_sha256, "BUNDLE_MANIFEST_PIN")
    bundle, plan = decode(manifest_path.read_bytes()), decode(plan_path.read_bytes())
    require(sha(plan_path) == expected_plan_sha256 == bundle["plan_sha256"], "BUNDLE_PLAN_PIN")
    jobs = validate_plan(plan)
    require(bundle["schema"] == "pon-w1-cost-research-bundle-v1" and
            bundle["complete_success"] is True and bundle["source_unchanged"] is True and
            bundle["failure"] is None, "INCOMPLETE_SOURCE_BOUND_BUNDLE")
    before = exact(bundle["source_before"], ("head", "tree", "branch", "status"), "SOURCE_FIELDS")
    require(before == bundle["source_after"] and before["head"] == expected_head and
            before["tree"] == expected_tree and before["status"] == "" and type(before["branch"]) is str,
            "BUNDLE_SOURCE_PIN")
    raw_source = exact(bundle["raw_source_before"], ("schema", "kind", "tested_commit", "tested_tree", "candidate", "base",
                       "prospective_merge", "tracked_worktree_verified", "tracked_entries", "tracked_bytes",
                       "tests_executed_by_identity_check"), "RAW_SOURCE_FIELDS")
    require(raw_source == bundle["raw_source_after"] and raw_source["schema"] == "trnm-ci-source-v1" and
            raw_source["kind"] == "head" and raw_source["tested_commit"] == raw_source["candidate"] == expected_head and
            raw_source["tested_tree"] == expected_tree and raw_source["base"] is None and
            raw_source["prospective_merge"] is None and raw_source["tracked_worktree_verified"] is True and
            raw_source["tests_executed_by_identity_check"] is False, "RAW_SOURCE_PIN")
    uint64(raw_source["tracked_entries"], "RAW_SOURCE_ENTRIES", 1)
    uint64(raw_source["tracked_bytes"], "RAW_SOURCE_BYTES", 1)
    require(bundle["hardness_accepted"] is False and bundle["production_activation"] is False and
            bundle["independent_hardware_qualification"] is False, "BUNDLE_AUTHORITY")
    require(bundle["profile"] == "release" and bundle["inherited_build_overrides"] == {}, "BUILD_PROFILE")
    require(bundle["target_directory_was_new"] is True, "FRESH_BUILD_DIRECTORY_REQUIRED")
    hx(bundle["runner_sha256"], 32, "RUNNER_HASH")
    plan_source = Path(bundle["plan_source_path"])
    require(not plan_source.is_absolute() and ".." not in plan_source.parts and
            str(plan_source) == bundle["plan_source_path"], "PLAN_SOURCE_PATH")
    verify_source_objects(expected_head, expected_tree, plan_source, expected_plan_sha256, bundle["runner_sha256"])
    binary = exact(bundle["binary"], ("path", "sha256", "bytes"), "BINARY_FIELDS")
    require(Path(binary["path"]).is_absolute() and binary["sha256"] == expected_binary_sha256,
            "BINARY_EXTERNAL_PIN")
    uint64(binary["bytes"], "BINARY_BYTES", 1)
    for key in ("compiler", "cargo"):
        exact(bundle[key], ("path", "sha256"), "TOOLCHAIN_FIELDS")
        require(Path(bundle[key]["path"]).is_absolute(), "TOOLCHAIN_PATH")
        hx(bundle[key]["sha256"], 32, "TOOLCHAIN_HASH")
    compiler, cargo = bundle["compiler"]["path"], bundle["cargo"]["path"]
    require(Path(compiler) == Path(cargo).parent / "rustc", "DIRECT_COMPILER_PATH")
    environment = exact(bundle["declared_build_environment"],
                        ("RUSTC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "CARGO_BUILD_JOBS",
                         "CARGO_INCREMENTAL", "PYTHONDONTWRITEBYTECODE"), "BUILD_ENVIRONMENT_FIELDS")
    require(environment["RUSTC"] == compiler and environment["CARGO_NET_OFFLINE"] == "true" and
            environment["CARGO_BUILD_JOBS"] == "2" and environment["CARGO_INCREMENTAL"] == "0" and
            environment["PYTHONDONTWRITEBYTECODE"] == "1" and
            Path(environment["CARGO_HOME"]).is_absolute() and Path(environment["CARGO_TARGET_DIR"]).is_absolute() and
            Path(binary["path"]) == Path(environment["CARGO_TARGET_DIR"]) / "release/examples/pon_w1_cost_game",
            "BUILD_ENVIRONMENT_BINDING")
    hardware = []
    for when in ("before", "after"):
        path = bundle_file(directory, "hardware-" + when + ".json", 4 * 1024 * 1024)
        require(sha(path) == bundle["hardware_" + when + "_sha256"], "HARDWARE_HASH")
        row = decode(path.read_bytes())
        uint64(row["requested_child_cpu"], "CHILD_CPU")
        require(row["requested_child_cpu"] in row["allowed_affinity"] and
                row["hardware_attested"] is False and row["exclusive_cpu"] is False and
                row["energy_joules"] is None and row["network_transfer_measured"] is False,
                "HARDWARE_SCOPE")
        hardware.append(row)
    require(all(hardware[0][key] == hardware[1][key] for key in ("requested_child_cpu", "machine", "cpu_models")),
            "HARDWARE_CHANGED")
    cpu = hardware[0]["requested_child_cpu"]
    steps = bundle["steps"]
    require(type(steps) is list and [row["name"] for row in steps] ==
            list(SETUP_NAMES) + [job["name"] for job in jobs], "EXACT_REGISTERED_STEPS")
    by_name = {}
    cwd = None
    for step in steps:
        fields = {"name", "command", "cwd", "timeout_seconds", "output_limit_bytes", "returncode", "error",
                     "stdout_truncated", "stderr_truncated", "stdout", "stderr", "wall_ns", "stdout_bytes",
                     "stderr_bytes", "stdout_sha256", "stderr_sha256", "complete_success"}
        if "whole_waited_child_resources" in step:
            fields.add("whole_waited_child_resources")
            validate_child_resources(step["whole_waited_child_resources"])
        exact(step, fields, "STEP_FIELDS")
        require(step["complete_success"] is True and type(step["returncode"]) is int and step["returncode"] == 0 and
                step["error"] is None and step["stdout_truncated"] is False and step["stderr_truncated"] is False,
                "FAILED_STEP")
        require(type(step["command"]) is list and all(type(value) is str for value in step["command"]), "STEP_COMMAND")
        require(type(step["cwd"]) is str and Path(step["cwd"]).is_absolute(), "STEP_CWD")
        cwd = step["cwd"] if cwd is None else cwd
        require(step["cwd"] == cwd and step["output_limit_bytes"] == 64 * 1024 * 1024, "STEP_ENVELOPE")
        uint64(step["wall_ns"], "STEP_WALL")
        for stream in ("stdout", "stderr"):
            require(step[stream] == step["name"] + "." + stream, "STEP_STREAM_IDENTITY")
            path = bundle_file(directory, step[stream], 64 * 1024 * 1024 if stream == "stdout" else 4 * 1024 * 1024)
            require(path.stat().st_size == uint64(step[stream + "_bytes"], "STREAM_BYTES") and
                    sha(path) == step[stream + "_sha256"], "CHANGED_RAW_STREAM")
        receipt = bundle_file(directory, step["name"] + ".step.json", 1024 * 1024)
        require(decode(receipt.read_bytes()) == step, "DIVERGENT_STEP_RECEIPT")
        by_name[step["name"]] = step
    root = Path(cwd)
    expected_configs = {Path(environment["CARGO_HOME"]) / "config", Path(environment["CARGO_HOME"]) / "config.toml"}
    for ancestor in (root, *root.parents):
        expected_configs.update((ancestor / ".cargo/config", ancestor / ".cargo/config.toml"))
    configurations = bundle["cargo_configurations"]
    require(type(configurations) is list and len(configurations) == len(expected_configs) and
            {row["path"] for row in configurations} == {str(path) for path in expected_configs}, "CARGO_CONFIG_COVERAGE")
    for row in configurations:
        exact(row, ("path", "exists", "sha256"), "CARGO_CONFIG_FIELDS")
        require(row["exists"] is False and row["sha256"] is None, "UNDECLARED_CARGO_CONFIGURATION")
    expected_setup = (
        ("preflight", ["bash", "scripts/project-preflight.sh"], 60),
        ("rustc-version", [compiler, "-Vv"], 60),
        ("cargo-version", [cargo, "-Vv"], 60),
        ("metadata", [cargo, "metadata", "--offline", "--locked", "--format-version", "1",
                      "--manifest-path", "trillionnium/Cargo.toml"], 120),
        ("build", [cargo, "build", "--offline", "--locked", "--release", "--jobs", "2", "--manifest-path",
                   "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--example", "pon_w1_cost_game", "--message-format=json"], 1200),
    )
    for name, command, timeout in expected_setup:
        require(by_name[name]["command"] == command and by_name[name]["timeout_seconds"] == timeout,
                "SETUP_COMMAND_BINDING:" + name)
    toolchain = bundle_file(directory, "rustc-version.stdout").read_text()
    require(toolchain == bundle["toolchain"] and toolchain.startswith("rustc 1.95.0 "), "COMPILER_VERSION_RECEIPT")
    preflight = decode(bundle_file(directory, "preflight.stdout").read_bytes())
    require(preflight["result"] == "PASS" and preflight["project"] == "trillionnium-chain" and
            preflight["remote_policy_mutated"] is False and preflight["branch"] == before["branch"], "PREFLIGHT_RECEIPT")
    metadata = decode(bundle_file(directory, "metadata.stdout").read_bytes())
    require(metadata["workspace_root"] == str(root / "trillionnium") and
            metadata["target_directory"] == environment["CARGO_TARGET_DIR"], "CARGO_METADATA_PATHS")
    build_messages = [decode(line) for line in bundle_file(directory, "build.stdout").read_bytes().splitlines()]
    artifacts = [row for row in build_messages if row.get("reason") == "compiler-artifact" and
                 row.get("target", {}).get("name") == "pon_w1_cost_game" and row.get("executable")]
    require(len(artifacts) == 1 and artifacts[0] == bundle["cargo_executable_artifact"] and
            artifacts[0]["executable"] == binary["path"] and "example" in artifacts[0]["target"]["kind"] and
            artifacts[0]["fresh"] is False and
            artifacts[0]["target"]["src_path"] == str(root / "trillionnium/crates/trnm-pon-node/examples/pon_w1_cost_game.rs"),
            "CARGO_EXECUTABLE_ARTIFACT_BINDING")
    require(build_messages and build_messages[-1].get("reason") == "build-finished" and
            build_messages[-1].get("success") is True, "CARGO_BUILD_COMPLETION")
    raw_results = []
    launcher = None
    for job in jobs:
        step = by_name[job["name"]]
        command = step["command"]
        require(len(command) == 4 + len(job["args"]) and Path(command[0]).is_absolute() and
                Path(command[0]).name == "taskset" and command[1:4] == ["-c", str(cpu), binary["path"]] and
                command[4:] == job["args"] and step["timeout_seconds"] == job["timeout_seconds"],
                "REGISTERED_JOB_COMMAND_BINDING")
        launcher = command[0] if launcher is None else launcher
        require(command[0] == launcher, "TASKSET_CHANGED")
        result = validate_raw(directory / step["stdout"], expected_options=options_from_args(job["args"]))
        result["job"] = job["name"]
        result["whole_waited_child_resources"] = step.get("whole_waited_child_resources")
        raw_results.append(result)
    return {"schema": "pon-w1-cost-research-derived-v1", "source": before,
            "binary": binary, "plan_sha256": expected_plan_sha256, "raw_manifest_sha256": expected_manifest_sha256,
            "external_identity_pins_checked": True,
            "external_pins_must_come_from_trusted_owner_not_from_untrusted_bundle": True,
            "reader_sha256": sha(__file__),
            "jobs": raw_results, "summary": derive(raw_results),
            "native_reported": count_sum(raw_results, "native_reported", COUNT_KEYS),
            "python_replayed": count_sum(raw_results, "python_replayed", REPLAY_KEYS),
            "hardness_accepted": False, "production_activation": False,
            "cost_ratio_is_finite_observation": True, "universal_kappa_bound_established": False,
            "native_execution_attested_by_reader": False, "all_native_reported_attempts_independently_verified": False,
            "certificate_retention_is_unbiased_sampling": False,
            "inclusive_budget_completion_event": "producer-complete candidate, subsequently confirmed by the observer; not admission completed by B",
            "inclusive_interval_excludes_native_context_and_tempdir_drop_after_endpoint": True,
            "energy_joules": None, "network_transfer_measured": False,
            "counterfactual_cohorts_are_not_additive_chainwork": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bundle", type=Path)
    group.add_argument("--raw", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-tree")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--expected-manifest-sha256")
    args = parser.parse_args()
    try:
        pins = {key: getattr(args, key) for key in ("expected_head", "expected_tree", "expected_plan_sha256",
                                                  "expected_binary_sha256", "expected_manifest_sha256")}
        require(not args.out.exists(), "OUTPUT_ALREADY_EXISTS")
        if args.bundle:
            require(all(value is not None for value in pins.values()), "BUNDLE_REQUIRES_ALL_EXTERNAL_PINS")
            result = read_bundle(args.bundle, **pins)
        else:
            require(all(value is None for value in pins.values()), "RAW_IS_NOT_A_SOURCE_BOUND_BUNDLE")
            result = validate_raw(args.raw)
        with args.out.open("x") as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        print(json.dumps({"output": str(args.out), "schema": result.get("schema"),
                          "complete_internal_reconciliation": True, "native_execution_attested": False}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration, IndexError, ZeroDivisionError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
