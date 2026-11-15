#!/usr/bin/env python3
"""Paired fixed-target/periodic-DAA experiments under equal declared capacities.

The roster is fixed before observation. A miner follows the public tip or builds
a private, timestamp-compressed branch using the same hypothetical resources.
All cases, unfinished attempts and losing work are retained. No physical W1
cost, network byte budget, task supply, security theorem or optimal policy is
established by this finite event simulation.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from quantum_daa_model import common_history  # noqa: E402
from quantum_network_sim import (  # noqa: E402
    ASSUMPTIONS, NetworkScenario, ParticipationShock, Simulator,
)
from experiments.quantum_network_campaign import (  # noqa: E402
    SOURCE_FILES as NETWORK_SOURCE_FILES, canonical, check_trace_arithmetic,
    digest, load_json, read_rows, write_rows,
)

SCHEMA = "trnm-joint-resource-competition-campaign-v1"
DEFAULT_SEEDS = (6101, 6102, 6103, 6104)
POLICIES = ("fixed-target", "periodic-target")
ENVIRONMENTS = ("steady", "delay", "participation", "proof_cost")
ITERATION_CLOCKS = (0.15, 0.05)
ARMS = ("honest", "private")
ARM_FIELDS = {"name", "quantum_strategy", "quantum_timestamp_mode",
              "private_timestamp_step", "private_release_seconds"}
SOURCE_FILES = tuple(dict.fromkeys(NETWORK_SOURCE_FILES + (
    "formal/pon-nakamoto-v1/experiments/joint_resource_competition_campaign.py",
    "formal/pon-nakamoto-v1/test_joint_resource_competition_campaign.py",
)))
RECORD_KEYS = {"case_id", "parameters", "execution", "summary", "error",
               "trace_file", "trace_rows", "readback", "readback_error"}
REPORT_KEYS = {"schema", "source", "argv", "roster_sha256", "contract",
               "observations", "comparison", "actual_python_process"}
CONTRACT = {
    "scope": "conditional event observations; no native W1 execution or physical calibration",
    "roster": "all declared seeds, both policies, both arms and every environment; no post-sample selection",
    "policy_selection": "two fixed policies; no fitting, optimization, training or held-out efficacy claim",
    "pairing": "same seed, duration, processor count, oracle/proof clocks, classical rates, shocks and delivery latency",
    "capacity_vs_consumption": "equal offered resource capacities; actual paid/cancelled/censored consumption can differ",
    "seed_pairing": "same per-miner seed; policy changes alter event ordering and random-number consumption",
    "network": "same fixed complete-bundle delivery delay; no bandwidth, byte budget, validation queue or eclipse model",
    "task_supply": "UNIMPLEMENTED; proof-cost sensitivity and participation shocks are not task-supply experiments",
    "horizon": "unfinished final attempts retain incurred cost and unknown future outcomes; early stops are incomplete",
    "credit": "required integer work on the observer's final selected branch; stale/private work earns no adopted credit",
    "private_policy": "parent timestamp plus one; publish at three quarters of the horizon; omit the public probe",
    "honest_fast_epochs": "short honest epochs are admitted under the same timestamp and clamp rules",
    "physical_resource_fairness_qualified": False,
    "network_byte_budget_qualified": False,
    "quantum_cost_lower_bound": None,
    "common_prefix_failure_bound": None,
    "chain_growth_failure_bound": None,
    "chain_quality_failure_bound": None,
    "installed_confirmation_failure_bound": None,
    "production_consensus_activation": False,
    "release_ready": False,
}


def same(left: object, right: object) -> bool:
    """Preserve JSON types; Python's false == 0 is not evidence equality."""
    return canonical(left) == canonical(right)


def source_record() -> dict:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    files = {name: digest(ROOT / name) for name in SOURCE_FILES}
    uncommitted = []
    for name in SOURCE_FILES:
        old = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or hashlib.sha256(old.stdout).hexdigest() != files[name]:
            uncommitted.append(name)
    return {"git_head": head, "source_sha256": files,
            "all_source_files_committed_at_head": not uncommitted,
            "uncommitted_source_files": uncommitted}


def validate_source(record: dict) -> None:
    if type(record) is not dict or set(record) != {
            "git_head", "source_sha256", "all_source_files_committed_at_head", "uncommitted_source_files"}:
        raise ValueError("SOURCE_SCHEMA")
    head = record["git_head"]
    if type(head) is not str or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("SOURCE_HEAD")
    kind = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if kind.returncode or kind.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    files = {name: digest(ROOT / name) for name in SOURCE_FILES}
    if not same(record["source_sha256"], files):
        raise ValueError("SOURCE_DIGEST")
    uncommitted = []
    for name in SOURCE_FILES:
        old = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or hashlib.sha256(old.stdout).hexdigest() != files[name]:
            uncommitted.append(name)
    if (record["uncommitted_source_files"] != uncommitted
            or record["all_source_files_committed_at_head"] is not (not uncommitted)):
        raise ValueError("SOURCE_COMMITMENT_CLAIM")


def cases_for(seeds: tuple[int, ...] | list[int] = DEFAULT_SEEDS,
              duration_seconds: float = 3600.0) -> list[NetworkScenario]:
    if type(seeds) not in (tuple, list) or not 1 <= len(seeds) <= 4:
        raise ValueError("SEED_COUNT")
    if any(type(seed) is not int or not 0 <= seed < (1 << 64) for seed in seeds):
        raise ValueError("SEED_VALUE")
    if len(set(seeds)) != len(seeds):
        raise ValueError("DUPLICATE_SEED")
    if (type(duration_seconds) not in (int, float) or not math.isfinite(duration_seconds)
            or not 10 <= duration_seconds <= 3600):
        raise ValueError("DURATION")
    duration = float(duration_seconds)
    cases = []
    for seed in seeds:
        for clock in ITERATION_CLOCKS:
            for environment in ENVIRONMENTS:
                base = NetworkScenario("paired", seed=seed, duration_seconds=duration,
                        quantum_iteration_seconds=clock, quantum_clock_rounding="upward",
                        max_events=30000, max_blocks=3000, max_trace_rows=100000,
                        max_pending_events=30000, cpu_limit_seconds=10.0)
                if environment == "delay":
                    base = replace(base, propagation_seconds=8.0)
                elif environment == "participation":
                    base = replace(base, shocks=(
                        ParticipationShock(duration / 3, 0.1, 1.0),
                        ParticipationShock(2 * duration / 3, 2.0, 0.5),
                        ParticipationShock(5 * duration / 6, 1.0, 1.0)))
                elif environment == "proof_cost":
                    base = replace(base, quantum_proof_seconds=20.0, classical_proof_seconds=1.0)
                for policy in POLICIES:
                    tag = f"{environment}_q{int(round(clock * 1000))}_{policy.replace('-', '_')}"
                    honest = replace(base, name=tag + "_honest", policy=policy)
                    private = replace(honest, name=tag + "_private",
                                      quantum_strategy="private-branch", quantum_timestamp_mode="compressed",
                                      private_timestamp_step=1, private_release_seconds=duration * 0.75)
                    for case in (honest, private):
                        case.validate()
                        cases.append(case)
    return cases


def case_id(case: NetworkScenario) -> str:
    return f"{case.name}_s{case.seed}"


def check_pair(honest: NetworkScenario, private: NetworkScenario) -> dict:
    if (honest.quantum_strategy != "honest-tip" or honest.quantum_timestamp_mode != "wall"
            or honest.private_release_seconds is not None
            or private.quantum_strategy != "private-branch" or private.quantum_timestamp_mode != "compressed"
            or private.private_timestamp_step != 1
            or private.private_release_seconds != private.duration_seconds * 0.75):
        raise ValueError("PAIR_STRATEGY")
    a = {key: value for key, value in asdict(honest).items() if key not in ARM_FIELDS}
    b = {key: value for key, value in asdict(private).items() if key not in ARM_FIELDS}
    if not same(a, b):
        raise ValueError("UNEQUAL_DECLARED_RESOURCE_PREMISES")
    return a


def check_target_policy(rows: list[dict], case: NetworkScenario) -> dict:
    """Independent periodic/fixed integer target and profile readback.

    This uses no Simulator target method, reference.retarget or model.required.
    It imposes no minimum epoch duration beyond the existing clamp arithmetic.
    """
    if case.policy not in POLICIES:
        raise ValueError("READBACK_POLICY")
    check_trace_arithmetic(rows)
    prefix = common_history()
    initial_span = min(600, max(38, max(1, prefix[-1].timestamp - prefix[-16].timestamp)))
    initial = max(1, min((1 << 255) - 1, prefix[-1].target * initial_span // 150))
    profile = hashlib.sha256(json.dumps([case.profile, case.policy, case.half_life,
                                        [asdict(h) for h in prefix]], sort_keys=True).encode()).hexdigest()
    tails = {"prefix": [(h.height, h.timestamp, h.target) for h in prefix[-16:]]}
    retargets, short_epochs, backwards = 0, 0, 0
    for row in rows:
        if row.get("kind") not in ("block", "search-start"):
            continue
        parent = row.get("parent")
        if parent not in tails:
            raise ValueError("TARGET_ANCESTRY")
        history = tails[parent]
        height = history[-1][0] + 1
        target = initial if case.policy == "fixed-target" else history[-1][2]
        span = history[-1][1] - history[-16][1]
        if case.policy == "periodic-target" and height % 16 == 0:
            target = max(1, min((1 << 255) - 1,
                         target * min(600, max(38, max(1, span))) // 150))
        if row.get("target_hex") != f"{target:064x}":
            raise ValueError("REQUIRED_TARGET")
        stamp = row.get("timestamp")
        if type(stamp) is not int or stamp <= sorted(h[1] for h in history[-11:])[5]:
            raise ValueError("TIMESTAMP_MEDIAN")
        if row["kind"] == "block":
            if row.get("profile") != profile:
                raise ValueError("PROFILE_IDENTITY")
            retargets += int(case.policy == "periodic-target" and height % 16 == 0)
            short_epochs += int(case.policy == "periodic-target" and height % 16 == 0 and 0 < span < 38)
            backwards += int(stamp < history[-1][1])
            tails[row["block"]] = (history + [(height, stamp, target)])[-16:]
    return {"blocks_checked": len(tails) - 1, "periodic_retargets_checked": retargets,
            "positive_short_epochs_accepted": short_epochs,
            "backward_adjacent_timestamps": backwards, "native_w1_verified": False}


def number(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(name)
    return float(value)


def close(left: object, right: float, name: str) -> None:
    if not math.isclose(number(left, name), right, rel_tol=1e-10, abs_tol=1e-8):
        raise ValueError(name)


def factor_integral(case: NetworkScenario, classical: bool) -> float:
    previous, factor, total = 0.0, 1.0 if classical else case.quantum_initial_factor, 0.0
    for shock in case.shocks:
        total += (shock.at_seconds - previous) * factor
        previous = shock.at_seconds
        factor = shock.classical_factor if classical else shock.quantum_factor
    return total + (case.duration_seconds - previous) * factor


def upward(value: Fraction) -> float:
    rounded = float(value)
    return math.nextafter(rounded, math.inf) if Fraction.from_float(rounded) < value else rounded


def readback(case: NetworkScenario, summary: dict, rows: list[dict]) -> dict:
    """Recompute selected credit and check charged work against declared caps.

    Final censored attempts count toward spent resources. A non-horizon run is
    retained by the campaign but cannot produce a completed comparison.
    """
    target_check = check_target_policy(rows, case)
    if type(summary) is not dict or summary.get("termination") != "horizon":
        raise ValueError("INCOMPLETE_HORIZON")
    if summary.get("trace_limit_reached") is not False:
        raise ValueError("INCOMPLETE_TRACE")
    if not same(summary.get("observation_seconds"), float(case.duration_seconds)):
        raise ValueError("OBSERVATION_HORIZON")
    if type(summary.get("trace_rows")) is not int or summary["trace_rows"] != len(rows):
        raise ValueError("TRACE_ROW_COUNT")
    if any(row["at_seconds"] > case.duration_seconds for row in rows):
        raise ValueError("TRACE_OUTSIDE_HORIZON")
    miners = tuple(f"c{i}" for i in range(len(case.classical_shares))) + ("q",)
    if type(summary.get("miners")) is not dict or set(summary["miners"]) != set(miners):
        raise ValueError("MINER_INVENTORY")
    if case.quantum_domain_size is not None:
        raise ValueError("READBACK_DOMAIN_SCOPE")
    prefix = common_history()
    initial_span = min(600, max(38, max(1, prefix[-1].timestamp - prefix[-16].timestamp)))
    initial = max(1, min((1 << 255) - 1, prefix[-1].target * initial_span // 150))
    base_probability = float(Fraction(initial + 1, 1 << 256))
    starts, active, won, proofs, blocks, trial_factors = {}, {}, {}, {}, {}, {}
    classical_factor, quantum_factor, shock_index = 1.0, case.quantum_initial_factor, 0
    spent = {miner: {"search_seconds": 0.0, "proof_seconds": 0.0, "wait_seconds": 0.0,
                    "started": 0, "completed": 0, "failed": 0, "cancelled": 0, "censored": 0,
                    "proofs_started": 0, "proofs_completed": 0, "proofs_censored": 0,
                    "logical_iterations": 0, "query_equivalents": 0.0, "candidate_check_seconds": 0.0,
                    "candidate_checks_started": 0, "candidate_checks_completed": 0,
                    "candidate_checks_cancelled": 0, "candidate_checks_censored": 0} for miner in miners}
    for row in rows:
        kind, miner, now = row.get("kind"), row.get("miner"), row["at_seconds"]
        if kind == "shock":
            if shock_index >= len(case.shocks):
                raise ValueError("SHOCK_INVENTORY")
            shock = case.shocks[shock_index]
            if (not same(now, float(shock.at_seconds))
                    or not same(row.get("classical_factor"), shock.classical_factor)
                    or not same(row.get("quantum_factor"), shock.quantum_factor)):
                raise ValueError("SHOCK_BINDING")
            classical_factor, quantum_factor = shock.classical_factor, shock.quantum_factor
            shock_index += 1
        elif kind == "search-start":
            serial = row.get("trial")
            if (miner not in spent or type(serial) is not int or serial in starts
                    or miner in active or miner in proofs or miner in won):
                raise ValueError("SEARCH_LIFECYCLE")
            if number(row.get("scheduled_finish_seconds"), "SEARCH_FINISH") < now:
                raise ValueError("SEARCH_FINISH")
            iterations = row.get("iterations")
            if type(iterations) is not int or not 0 <= iterations <= case.quantum_max_iterations:
                raise ValueError("SEARCH_ITERATIONS")
            # Trace order matters: start() opens trials before consuming an
            # explicitly scheduled time-zero shock. Equal timestamps alone do
            # not identify the active resource regime for those zero-cost trials.
            trial_factors[serial] = quantum_factor if miner == "q" else classical_factor
            if miner == "q":
                speed = trial_factors[serial]
                if speed <= 0:
                    raise ValueError("SEARCH_WHILE_INACTIVE")
                if case.quantum_clock_rounding == "upward":
                    itime = upward(Fraction.from_float(float(case.quantum_iteration_seconds))
                                   / Fraction.from_float(float(speed)))
                    duration = upward(sum((Fraction.from_float(float(value)) for value in (
                        case.quantum_prepare_seconds, case.quantum_measure_seconds,
                        case.quantum_candidate_check_seconds)), Fraction(0))
                        + iterations * Fraction.from_float(itime))
                    finish = upward(Fraction.from_float(float(now)) + Fraction.from_float(duration))
                    if (row.get("clock_rounding") != "upward"
                            or not same(row.get("iteration_seconds_upper"), itime)
                            or not same(row.get("duration_seconds_upper"), duration)
                            or not same(row["scheduled_finish_seconds"], finish)):
                        raise ValueError("QUANTUM_STAGE_CLOCK")
                else:
                    itime = case.quantum_iteration_seconds / speed
                    duration = (case.quantum_prepare_seconds + iterations * itime
                                + case.quantum_measure_seconds + case.quantum_candidate_check_seconds)
                    close(row["scheduled_finish_seconds"], now + duration, "QUANTUM_STAGE_CLOCK")
            elif iterations != 0:
                raise ValueError("CLASSICAL_ITERATIONS")
            starts[serial] = row
            active[miner] = serial
            spent[miner]["started"] += 1
        elif kind in ("search-won", "search-failed", "search-cancelled", "search-censored"):
            serial = row.get("trial")
            if miner not in active or active[miner] != serial:
                raise ValueError("SEARCH_LIFECYCLE")
            start = starts[serial]
            elapsed = min(now, start["scheduled_finish_seconds"]) - start["at_seconds"]
            close(row.get("elapsed_seconds"), elapsed, "SEARCH_ELAPSED")
            status = kind.removeprefix("search-")
            if ((status in ("won", "failed") and now != start["scheduled_finish_seconds"])
                    or now > start["scheduled_finish_seconds"]):
                raise ValueError("SEARCH_TERMINAL_CLOCK")
            logical = row.get("logical_iterations")
            if type(logical) is not int or logical < 0:
                raise ValueError("LOGICAL_ITERATIONS")
            if miner == "q":
                speed = trial_factors[serial]
                if case.quantum_clock_rounding == "upward":
                    itime = upward(Fraction.from_float(float(case.quantum_iteration_seconds))
                                   / Fraction.from_float(float(speed)))
                    exact_elapsed = (Fraction.from_float(float(min(now, start["scheduled_finish_seconds"])))
                                     - Fraction.from_float(float(start["at_seconds"])))
                    prepare = Fraction.from_float(float(case.quantum_prepare_seconds))
                    expected_logical = min(start["iterations"], max(0, (exact_elapsed - prepare)
                                           // Fraction.from_float(itime))) * case.quantum_processors
                    check_start = (prepare + start["iterations"] * Fraction.from_float(itime)
                                   + Fraction.from_float(float(case.quantum_measure_seconds)))
                    checked = float(min(Fraction.from_float(float(case.quantum_candidate_check_seconds)),
                                        max(Fraction(0), exact_elapsed - check_start)))
                else:
                    itime = case.quantum_iteration_seconds / speed
                    expected_logical = min(start["iterations"], max(0, int(math.floor(
                        (elapsed - case.quantum_prepare_seconds) / itime + 1e-9)))) * case.quantum_processors
                    checked = min(case.quantum_candidate_check_seconds, max(0, elapsed
                        - case.quantum_prepare_seconds - start["iterations"] * itime - case.quantum_measure_seconds))
                if logical != expected_logical:
                    raise ValueError("LOGICAL_ITERATION_CHARGE")
                if checked > 0 or status in ("won", "failed"):
                    spent[miner]["candidate_checks_started"] += case.quantum_processors
                    if status in ("won", "failed"):
                        spent[miner]["candidate_checks_completed"] += case.quantum_processors
                        checked = case.quantum_candidate_check_seconds
                    else:
                        spent[miner]["candidate_checks_" + status] += case.quantum_processors
                spent[miner]["candidate_check_seconds"] += checked
            else:
                if logical != 0:
                    raise ValueError("CLASSICAL_ITERATIONS")
                share = case.classical_shares[int(miner[1:])]
                rate = (case.classical_block_rate_at_initial_target * share
                        * trial_factors[serial] / base_probability)
                spent[miner]["query_equivalents"] += elapsed * rate
            spent[miner]["logical_iterations"] += logical
            spent[miner]["search_seconds"] += elapsed
            if status in ("won", "failed"):
                spent[miner]["completed"] += 1
            if status != "won":
                spent[miner][status] += 1
            else:
                won[miner] = (serial, now)
            del active[miner]
        elif kind == "proof-start":
            if (miner not in won or won[miner] != (row.get("trial"), now)
                    or miner in proofs):
                raise ValueError("PROOF_LIFECYCLE")
            duration = case.quantum_proof_seconds if miner == "q" else case.classical_proof_seconds
            close(row.get("proof_seconds"), duration, "PROOF_DURATION")
            if miner == "q" and case.quantum_clock_rounding == "upward":
                exact = Fraction.from_float(float(now)) + Fraction.from_float(float(duration))
                finish = float(exact)
                if Fraction.from_float(finish) < exact:
                    finish = math.nextafter(finish, math.inf)
            else:
                finish = now + duration
            proofs[miner] = (won.pop(miner)[0], now, finish)
            spent[miner]["proofs_started"] += 1
        elif kind == "block":
            if miner not in proofs:
                raise ValueError("BLOCK_WITHOUT_PAID_PROOF")
            serial, began, finish = proofs.pop(miner)
            if now < finish:
                raise ValueError("PREMATURE_BLOCK")
            start = starts[serial]
            if any(not same(row.get(key), start.get(key)) for key in ("parent", "timestamp", "target_hex")):
                raise ValueError("BLOCK_SEARCH_BINDING")
            spent[miner]["proof_seconds"] += finish - began
            spent[miner]["wait_seconds"] += now - finish
            spent[miner]["proofs_completed"] += 1
            blocks[row["block"]] = row
    if active or won:
        raise ValueError("UNCLOSED_SEARCH_COST")
    if shock_index != len(case.shocks):
        raise ValueError("SHOCK_INVENTORY")
    for miner, (_, began, finish) in proofs.items():
        spent[miner]["proof_seconds"] += min(case.duration_seconds, finish) - began
        if finish <= case.duration_seconds:
            spent[miner]["proofs_completed"] += 1
            spent[miner]["wait_seconds"] += case.duration_seconds - finish
        else:
            spent[miner]["proofs_censored"] += 1
    costs = {}
    for miner in miners:
        reported, measured = summary["miners"][miner], spent[miner]
        for source, field in (("started", "searches_started"), ("completed", "searches_completed"),
                              ("failed", "searches_failed"), ("cancelled", "searches_cancelled"),
                              ("censored", "searches_censored"), ("proofs_started", "proofs_started"),
                              ("proofs_completed", "proofs_completed"), ("proofs_censored", "proofs_censored"),
                              ("logical_iterations", "logical_iterations_completed"),
                              *((field, field) for field in ("candidate_checks_started", "candidate_checks_completed",
                                                            "candidate_checks_cancelled", "candidate_checks_censored"))):
            if type(reported.get(field)) is not int or reported[field] != measured[source]:
                raise ValueError("LIFECYCLE_COUNT")
        for source, field in (("search_seconds", "search_seconds"), ("proof_seconds", "proof_seconds"),
                              ("wait_seconds", "future_timestamp_wait_seconds"),
                              ("query_equivalents", "classical_query_equivalents"),
                              ("candidate_check_seconds", "candidate_check_seconds")):
            close(reported.get(field), measured[source], "CHARGED_CLOCK")
        close(reported.get("candidate_check_processor_seconds"),
              measured["candidate_check_seconds"] * (case.quantum_processors if miner == "q" else 1),
              "CANDIDATE_PROCESSOR_CLOCK")
        occupied = measured["search_seconds"] + measured["proof_seconds"] + measured["wait_seconds"]
        if occupied > case.duration_seconds + 1e-8:
            raise ValueError("MINER_WALL_CAPACITY")
        if miner == "q":
            available = case.quantum_processors * factor_integral(case, False) / case.quantum_iteration_seconds
            if measured["logical_iterations"] > available + 1e-8:
                raise ValueError("ORACLE_ITERATION_CAPACITY")
            extra = {"logical_iterations_charged": measured["logical_iterations"],
                     "logical_iteration_capacity_upper": available,
                     "processor_seconds_charged": occupied * case.quantum_processors,
                     "processor_seconds_capacity": case.duration_seconds * case.quantum_processors}
        else:
            queries = number(reported.get("classical_query_equivalents"), "QUERY_EQUIVALENTS")
            share = case.classical_shares[int(miner[1:])]
            available = case.classical_block_rate_at_initial_target * share / base_probability * factor_integral(case, True)
            if queries > available + max(1e-8, available * 1e-10):
                raise ValueError("CLASSICAL_QUERY_CAPACITY")
            extra = {"classical_query_equivalents_charged": queries, "query_capacity_upper": available}
        costs[miner] = {"search_seconds_charged": measured["search_seconds"],
                       "proof_seconds_charged": measured["proof_seconds"],
                       "future_wait_seconds_charged": measured["wait_seconds"],
                       "idle_or_inactive_seconds": max(0, case.duration_seconds - occupied),
                       "right_censored_searches": measured["censored"],
                       "right_censored_proofs": measured["proofs_censored"], **extra}
    tip, chain = summary.get("observer_tip"), []
    while tip != "prefix":
        if tip not in blocks or len(chain) >= len(blocks):
            raise ValueError("OBSERVER_CHAIN")
        chain.append(blocks[tip])
        tip = blocks[tip]["parent"]
    credit = {miner: sum(int(row["required_work"]) for row in chain if row["miner"] == miner)
              for miner in miners}
    if (type(summary.get("observer_added_blocks")) is not int or summary["observer_added_blocks"] != len(chain)
            or summary.get("observer_added_chainwork") != str(sum(credit.values()))
            or type(summary.get("blocks_created")) is not int
            or summary.get("blocks_created") != len(blocks)):
        raise ValueError("OBSERVER_CREDIT")
    observed_adoptions = [row["tip"] for row in rows
                          if row.get("kind") == "adopt" and row.get("recipient") == "observer"]
    if summary["observer_tip"] != (observed_adoptions[-1] if observed_adoptions else "prefix"):
        raise ValueError("OBSERVER_TIP")
    q_blocks = sum(row["miner"] == "q" for row in chain)
    return {"integer_policy_readback": target_check, "resource_charges": costs,
            "quantum_adopted_blocks": q_blocks, "classical_adopted_blocks": len(chain) - q_blocks,
            "quantum_adopted_credit": str(credit["q"]),
            "classical_adopted_credit": str(sum(value for key, value in credit.items() if key != "q")),
            "adopted_credit_by_miner": {key: str(value) for key, value in credit.items()},
            "quantum_adopted_credit_per_simulated_second": credit["q"] / case.duration_seconds,
            "all_declared_capacity_checks_pass": True,
            "physical_resource_fairness_qualified": False, "network_byte_budget_qualified": False}


def observations_comparison(cases: list[NetworkScenario], records: list[dict]) -> dict:
    if len(cases) != len(records) or len(cases) % 2:
        raise ValueError("COMPARISON_DENOMINATOR")
    pairs = []
    for offset in range(0, len(cases), 2):
        honest, private = cases[offset:offset + 2]
        premise = check_pair(honest, private)
        a, b = records[offset:offset + 2]
        complete = all(record["execution"] == "returned" and record["readback"] is not None
                       and record["readback_error"] is None for record in (a, b))
        delta = (int(b["readback"]["quantum_adopted_credit"])
                 - int(a["readback"]["quantum_adopted_credit"])) if complete else None
        pairs.append({"honest": case_id(honest), "private": case_id(private),
                      "policy": honest.policy, "seed": honest.seed,
                      "resource_premises_sha256": hashlib.sha256(canonical(premise)).hexdigest(),
                      "declared_resource_premises_equal": True, "complete": complete,
                      "private_minus_honest_quantum_adopted_credit": str(delta) if delta is not None else None,
                      "private_has_more_adopted_credit": delta > 0 if delta is not None else None,
                      "private_probe_confirmation_reversals": b["summary"]["probe"]["confirmation_reversals"] if complete else None,
                      "private_observer_max_reorg_depth": b["summary"]["observer_max_reorg_depth"] if complete else None})
    groups = []
    for policy in POLICIES:
        subset = [pair for pair in pairs if pair["policy"] == policy]
        completed = [pair for pair in subset if pair["complete"]]
        deltas = [int(pair["private_minus_honest_quantum_adopted_credit"]) for pair in completed]
        groups.append({"policy": policy, "planned_pairs": len(subset), "complete_pairs": len(completed),
                       "incomplete_pairs": len(subset) - len(completed),
                       "private_more_credit_pairs": sum(value > 0 for value in deltas),
                       "equal_credit_pairs": sum(value == 0 for value in deltas),
                       "private_less_credit_pairs": sum(value < 0 for value in deltas),
                       "paired_credit_delta_sum": str(sum(deltas)) if len(completed) == len(subset) else None,
                       "conditional_descriptive_counts_only": True})
    return {"planned_runs": len(cases), "returned_runs": sum(r["execution"] == "returned" for r in records),
            "complete_readback_runs": sum(r["readback"] is not None and r["readback_error"] is None for r in records),
            "planned_pairs": len(pairs), "complete_pairs": sum(p["complete"] for p in pairs),
            "pairs": pairs, "by_policy": groups, "security_probability_estimated": False,
            "cross_policy_credit_units": "same initial prefix and integer required-work formula; endogenous targets differ",
            "physical_resource_fairness_qualified": False, "network_byte_budget_qualified": False,
            "task_supply_experiment_performed": False, "release_ready": False}


def run_campaign(out: Path, argv: list[str], seeds: tuple[int, ...] = DEFAULT_SEEDS,
                 duration_seconds: float = 3600.0) -> dict:
    cases = cases_for(seeds, duration_seconds)
    source = source_record()
    out.mkdir(parents=True, exist_ok=False)
    roster = {"schema": SCHEMA + "-roster", "seeds": list(seeds), "duration_seconds": float(duration_seconds),
              "cases": [asdict(case) for case in cases], "contract": CONTRACT}
    (out / "roster.json").write_bytes(canonical(roster))
    files = {"roster.json": digest(out / "roster.json")}
    started, cpu = time.perf_counter(), time.process_time()
    records = []
    for case in cases:
        simulator, summary, rows, error = None, None, [], None
        try:
            simulator = Simulator(case)
            summary, rows = simulator.run()
        except Exception as caught:  # Preserve the partial original; never replace it with a success.
            rows = simulator.trace if simulator is not None else []
            error = {"type": type(caught).__name__, "message": str(caught)}
        filename = case_id(case) + ".jsonl.gz"
        write_rows(out / filename, rows)
        files[filename] = digest(out / filename)
        checked, check_error = None, None
        try:
            if error is not None:
                raise ValueError("EXECUTION_ERROR")
            checked = readback(case, summary, rows)
        except Exception as caught:
            check_error = {"type": type(caught).__name__, "message": str(caught)}
        record = {"case_id": case_id(case), "parameters": asdict(case),
                  "execution": "returned" if error is None else "error", "summary": summary, "error": error,
                  "trace_file": filename, "trace_rows": len(rows), "readback": checked, "readback_error": check_error}
        # A completed case survives a later case/controller interruption. A missing
        # final manifest/report cannot be accepted as a complete campaign.
        record_name = case_id(case) + ".json"
        (out / record_name).write_bytes(canonical(record))
        files[record_name] = digest(out / record_name)
        records.append(record)
    if source["source_sha256"] != {name: digest(ROOT / name) for name in SOURCE_FILES}:
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    comparison = observations_comparison(cases, records)
    report = {"schema": SCHEMA, "source": source, "argv": argv, "roster_sha256": files["roster.json"],
              "contract": {**CONTRACT, "simulator_assumptions": ASSUMPTIONS},
              "observations": [case_id(case) + ".json" for case in cases], "comparison": comparison,
              "actual_python_process": {"wall_seconds": time.perf_counter() - started,
                                        "cpu_seconds": time.process_time() - cpu,
                                        "python": sys.version, "platform": platform.platform(),
                                        "scope": "simulation, checks and serialization; not mining or hardware costs"}}
    (out / "report.json").write_bytes(canonical(report))
    files["report.json"] = digest(out / "report.json")
    (out / "manifest.json").write_bytes(canonical({"schema": SCHEMA + "-manifest", "files_sha256": files}))
    return {"result": "CONDITIONAL_PAIRED_OBSERVATIONS", "planned_runs": len(cases),
            "complete_readback_runs": comparison["complete_readback_runs"],
            "planned_pairs": comparison["planned_pairs"], "complete_pairs": comparison["complete_pairs"],
            "source_committed": source["all_source_files_committed_at_head"],
            "by_policy": comparison["by_policy"], "release_ready": False}


def verify_campaign(out: Path) -> dict:
    if out.is_symlink() or not out.is_dir():
        raise ValueError("OUTPUT_DIRECTORY")
    report, manifest, roster = (load_json(out / name) for name in ("report.json", "manifest.json", "roster.json"))
    if type(report) is not dict or set(report) != REPORT_KEYS or report.get("schema") != SCHEMA:
        raise ValueError("REPORT_SCHEMA")
    if (type(manifest) is not dict or set(manifest) != {"schema", "files_sha256"}
            or manifest.get("schema") != SCHEMA + "-manifest"):
        raise ValueError("MANIFEST_SCHEMA")
    if (type(roster) is not dict or set(roster) != {"schema", "seeds", "duration_seconds", "cases", "contract"}
            or roster.get("schema") != SCHEMA + "-roster"):
        raise ValueError("ROSTER_SCHEMA")
    if (not same(report["contract"], {**CONTRACT, "simulator_assumptions": ASSUMPTIONS})
            or not same(roster["contract"], CONTRACT)):
        raise ValueError("CONTRACT_SUBSTITUTION")
    cases = cases_for(roster["seeds"], roster["duration_seconds"])
    if not same(roster["cases"], [asdict(case) for case in cases]):
        raise ValueError("ROSTER_SUBSTITUTION")
    expected_records = [case_id(case) + ".json" for case in cases]
    expected = set(expected_records) | {case_id(case) + ".jsonl.gz" for case in cases} | {"report.json", "roster.json"}
    files = manifest["files_sha256"]
    if type(files) is not dict or set(files) != expected:
        raise ValueError("MANIFEST_INVENTORY")
    if {path.name for path in out.iterdir()} != expected | {"manifest.json"}:
        raise ValueError("OUTPUT_INVENTORY")
    for name, wanted in files.items():
        path = out / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
            raise ValueError("ARTIFACT_BOUND")
        if digest(path) != wanted:
            raise ValueError("ARTIFACT_DIGEST")
    if report["roster_sha256"] != files["roster.json"] or report["observations"] != expected_records:
        raise ValueError("OBSERVATION_INVENTORY")
    validate_source(report["source"])
    records = []
    for case, filename in zip(cases, expected_records):
        record = load_json(out / filename)
        if type(record) is not dict or set(record) != RECORD_KEYS:
            raise ValueError("OBSERVATION_SCHEMA")
        if (record["case_id"] != case_id(case) or not same(record["parameters"], asdict(case))
                or record["trace_file"] != case_id(case) + ".jsonl.gz"):
            raise ValueError("SCENARIO_SUBSTITUTION")
        rows = read_rows(out / record["trace_file"])
        if type(record["trace_rows"]) is not int or record["trace_rows"] != len(rows):
            raise ValueError("TRACE_ROW_COUNT")
        if record["execution"] != "returned" or record["error"] is not None:
            raise ValueError("RETAINED_EXECUTION_ERROR")
        actual = readback(case, record["summary"], rows)
        if record["readback_error"] is not None or not same(record["readback"], actual):
            raise ValueError("READBACK_SUBSTITUTION")
        replay_summary, replay_rows = Simulator(case).run()
        if not same(record["summary"], replay_summary) or not same(rows, replay_rows):
            raise ValueError("SEEDED_REPLAY_MISMATCH")
        records.append(record)
    if not same(report["comparison"], observations_comparison(cases, records)):
        raise ValueError("COMPARISON_SUBSTITUTION")
    return {"result": "COMPLETE_PAIRED_REPLAY_AND_READBACK_PASS", "runs": len(cases),
            "pairs": len(cases) // 2, "native_w1_verified": False,
            "physical_resource_fairness_qualified": False, "network_byte_budget_qualified": False,
            "release_ready": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--out", type=Path)
    action.add_argument("--verify", type=Path)
    parser.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    parser.add_argument("--duration-seconds", type=float, default=3600.0)
    args = parser.parse_args()
    result = (verify_campaign(args.verify) if args.verify else
              run_campaign(args.out, sys.argv, tuple(args.seeds), args.duration_seconds))
    print(json.dumps(result, sort_keys=True))
    if args.out and result["complete_readback_runs"] != result["planned_runs"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
