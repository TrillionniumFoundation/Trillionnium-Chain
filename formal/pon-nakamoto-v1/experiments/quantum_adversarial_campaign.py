#!/usr/bin/env python3
"""Bounded conditional attacker search with source-bound seeded readback.

Every observation remains a synthetic-clock experiment. The grid compares
trial policies at the same processor count and searches timestamp/publication
rules using the periodic native DAA arithmetic. Finite fixed-M controls are
separate conditional premises. They are never evidence of a W1 shortcut or
of a small quantum miner attacking the implementation.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from quantum_adversarial_search import ADVERSARIAL_ASSUMPTIONS  # noqa: E402
from quantum_daa_model import common_history  # noqa: E402
from quantum_network_sim import NetworkScenario, PROFILE, run_network_scenario  # noqa: E402
from experiments.quantum_network_campaign import (  # noqa: E402
    SOURCE_FILES as NETWORK_SOURCE_FILES, canonical, check_trace_arithmetic,
    digest, load_json, read_rows, write_rows,
)

SCHEMA = "trnm-quantum-adversarial-campaign-v3"
SOURCE_FILES = tuple(dict.fromkeys(NETWORK_SOURCE_FILES + (
    "formal/pon-nakamoto-v1/quantum_adversarial_search.py",
    "formal/pon-nakamoto-v1/test_quantum_adversarial_search.py",
    "formal/pon-nakamoto-v1/experiments/quantum_adversarial_campaign.py",
)))
REPORT_KEYS = {"schema", "source", "argv", "seeds", "duration_seconds", "assumptions",
               "observations", "bounded_search", "actual_python_process"}


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
    keys = {"git_head", "source_sha256", "all_source_files_committed_at_head", "uncommitted_source_files"}
    if type(record) is not dict or set(record) != keys:
        raise ValueError("SOURCE_SCHEMA")
    head = record["git_head"]
    if type(head) is not str or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("SOURCE_HEAD")
    kind = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if kind.returncode or kind.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    files = {name: digest(ROOT / name) for name in SOURCE_FILES}
    if record["source_sha256"] != files:
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


def cases_for(seeds: tuple[int, ...] | list[int], duration_seconds: float = 900) -> list[NetworkScenario]:
    if type(seeds) not in (tuple, list) or not 1 <= len(seeds) <= 8:
        raise ValueError("SEED_COUNT")
    if any(type(seed) is not int or not 0 <= seed < (1 << 64) for seed in seeds):
        raise ValueError("SEED_VALUE")
    if len(set(seeds)) != len(seeds):
        raise ValueError("DUPLICATE_SEED")
    if type(duration_seconds) not in (int, float) or not 10 <= duration_seconds <= 3600:
        raise ValueError("DURATION")
    base = NetworkScenario("private_peak_q1", duration_seconds=duration_seconds,
                           quantum_strategy="private-branch", quantum_timestamp_mode="mtp-min",
                           quantum_max_iterations=1024, private_release_policy="observed-work-lead",
                           private_release_work_lead=1, max_events=60000, max_trace_rows=200000,
                           cpu_limit_seconds=30)
    candidates = tuple(range(1025))
    optimized = replace(base, quantum_trial_policy="bounded-throughput", quantum_iteration_candidates=candidates)
    cases = []
    for processors in (1, 4):
        cases.extend((replace(base, name=f"private_peak_q{processors}", quantum_processors=processors),
                      replace(optimized, name=f"private_rate_q{processors}", quantum_processors=processors)))
    for mode in ("wall", "future-bound", "retarget-extremes"):
        for lead in (1, 3):
            cases.append(replace(optimized, name=f"adaptive_{mode.replace('-', '_')}_lead{lead}",
                                 quantum_processors=4, quantum_timestamp_mode=mode,
                                 private_release_work_lead=lead,
                                 private_release_max_wait_seconds=min(60, duration_seconds)))
    finite = replace(base, name="finite_empty_persistent", quantum_processors=4,
                     quantum_timestamp_mode="wall", quantum_fixed_iterations=2,
                     quantum_domain_size=16, quantum_domain_marked_count=0,
                     quantum_domain_setup_seconds=0.2)
    cases.extend((finite,
                  replace(finite, name="finite_one_persistent_conditioned", quantum_domain_marked_count=1),
                  replace(finite, name="finite_binomial_persistent", quantum_domain_size=64,
                          quantum_domain_marked_count=None),
                  replace(finite, name="finite_binomial_refresh_fixed", quantum_domain_size=64,
                          quantum_domain_marked_count=None, quantum_domain_trials_before_refresh=1),
                  replace(optimized, name="finite_binomial_refresh_rate", quantum_processors=4,
                          quantum_timestamp_mode="wall", quantum_iteration_candidates=tuple(range(33)),
                          quantum_domain_size=64, quantum_domain_trials_before_refresh=1,
                          quantum_domain_setup_seconds=0.2)))
    result = [replace(case, seed=seed) for seed in seeds for case in cases]
    for case in result:
        case.validate()
    return result


def check_native_periodic_arithmetic(rows: list[dict], case: NetworkScenario) -> dict:
    """Independent integer transcription of native dev-profile periodic DAA.

    No call to reference.retarget, quantum_daa_model.required or Simulator is
    used for these per-branch target decisions. The shared arithmetic prefix
    remains an input, and this reader does not verify W1 or admit native packets.
    """
    if case.policy != "periodic-target" or case.profile != PROFILE:
        raise ValueError("NATIVE_ARITHMETIC_PROFILE")
    check_trace_arithmetic(rows)
    prefix = common_history()
    profile = hashlib.sha256(json.dumps([case.profile, case.policy, case.half_life,
                                        [asdict(h) for h in prefix]], sort_keys=True).encode()).hexdigest()
    tails = {"prefix": [(h.height, h.timestamp, h.target) for h in prefix[-16:]]}
    retargets, backwards = 0, 0
    for row in rows:
        if row.get("kind") not in ("block", "search-start"):
            continue
        parent = row.get("parent")
        if parent not in tails:
            raise ValueError("NATIVE_TARGET_ANCESTRY")
        history = tails[parent]
        height = history[-1][0] + 1
        expected = history[-1][2]
        if height % 16 == 0:
            elapsed = max(1, history[-1][1] - history[-16][1])
            observed = min(600, max(38, elapsed))
            expected = max(1, min((1 << 255) - 1, expected * observed // 150))
        if row.get("target_hex") != f"{expected:064x}":
            raise ValueError("NATIVE_REQUIRED_TARGET")
        timestamp = row.get("timestamp")
        if type(timestamp) is not int or timestamp <= sorted(h[1] for h in history[-11:])[5]:
            raise ValueError("NATIVE_TIMESTAMP_MEDIAN")
        if row["kind"] == "block":
            if row.get("profile") != profile:
                raise ValueError("NATIVE_PROFILE_IDENTITY")
            backwards += int(timestamp < history[-1][1])
            retargets += int(height % 16 == 0)
            tails[row["block"]] = (history + [(height, timestamp, expected)])[-16:]
    return {"blocks_checked": len(tails) - 1, "branch_retargets_checked": retargets,
            "backward_adjacent_timestamps": backwards,
            "required_target_and_integer_work_recomputed": True,
            "native_w1_verified": False}


def bounded_search(records: list[dict]) -> dict:
    """Compare observed harms only within equal processor/domain/clock premises."""
    groups = {}
    for record in records:
        p, s = record["parameters"], record["summary"]
        if s["termination"] != "horizon":
            continue
        premise = {
            "processors": p["quantum_processors"], "domain_size": p["quantum_domain_size"],
            "fixed_marked_count": p["quantum_domain_marked_count"],
            "clock_seconds": {key: p[key] for key in (
                "quantum_iteration_seconds", "quantum_prepare_seconds", "quantum_measure_seconds",
                "quantum_candidate_check_seconds", "quantum_proof_seconds", "quantum_domain_setup_seconds")},
        }
        key = canonical(premise).decode().strip()
        rank = [s["probe"]["confirmation_reversals"], s["observer_reorg_beyond_confirmation_depth"],
                s["observer_max_reorg_depth"], 1 - s["empirical_honest_block_fraction"] if s["observer_added_blocks"] else 0]
        candidate = {"name": p["name"], "seed": p["seed"], "rank": rank, "premise": premise}
        if key not in groups or rank > groups[key]["rank"]:
            groups[key] = candidate
    return {"objective": ["observed_probe_confirmation_reversals", "observed_reorgs_beyond_depth",
                          "observed_max_reorg_depth", "observed_quantum_canonical_block_fraction"],
            "comparison": "lexicographic finite sampled observations; equal processor/domain/clock premise groups",
            "tie_break": "first declared scenario and seed",
            "best_observed_by_premise": [groups[key] for key in sorted(groups)],
            "excluded_non_horizon_observations": sum(r["summary"]["termination"] != "horizon" for r in records),
            "global_attack_optimum_claimed": False, "statistical_security_threshold": None,
            "current_node_exploited": False, "release_ready": False}


def run_campaign(out: Path, argv: list[str], seeds: tuple[int, ...] = (5101, 5102, 5103),
                 duration_seconds: float = 900) -> dict:
    cases = cases_for(seeds, duration_seconds)
    source = source_record()
    out.mkdir(parents=True, exist_ok=False)
    started, cpu = time.perf_counter(), time.process_time()
    records, files = [], {}
    for case in cases:
        summary, rows = run_network_scenario(case)
        readback = check_native_periodic_arithmetic(rows, case)
        filename = f"{case.name}_s{case.seed}.jsonl.gz"
        write_rows(out / filename, rows)
        files[filename] = digest(out / filename)
        records.append({"parameters": asdict(case), "summary": summary,
                        "native_arithmetic_readback": readback, "trace_file": filename})
    if source["source_sha256"] != {name: digest(ROOT / name) for name in SOURCE_FILES}:
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    report = {"schema": SCHEMA, "source": source, "argv": argv, "seeds": list(seeds),
              "duration_seconds": duration_seconds, "assumptions": ADVERSARIAL_ASSUMPTIONS,
              "observations": records, "bounded_search": bounded_search(records),
              "actual_python_process": {"wall_seconds": time.perf_counter() - started,
                                        "cpu_seconds": time.process_time() - cpu,
                                        "python": sys.version, "platform": platform.platform(),
                                        "scope": "conditional event simulation and serialization; no W1/hardware timing"}}
    (out / "report.json").write_bytes(canonical(report))
    files["report.json"] = digest(out / "report.json")
    (out / "manifest.json").write_bytes(canonical({"schema": SCHEMA + "-manifest", "files_sha256": files}))
    return {"result": "BOUNDED_CONDITIONAL_ADVERSARIAL_OBSERVATIONS", "runs": len(records),
            "trace_rows": sum(r["summary"]["trace_rows"] for r in records),
            "horizon_completed_runs": sum(r["summary"]["termination"] == "horizon" for r in records),
            "source_committed": source["all_source_files_committed_at_head"], "release_ready": False}


def verify_campaign(out: Path) -> dict:
    if out.is_symlink() or not out.is_dir():
        raise ValueError("OUTPUT_DIRECTORY")
    report, manifest = load_json(out / "report.json"), load_json(out / "manifest.json")
    if type(report) is not dict or set(report) != REPORT_KEYS or report.get("schema") != SCHEMA:
        raise ValueError("REPORT_SCHEMA")
    if (type(manifest) is not dict or set(manifest) != {"schema", "files_sha256"}
            or manifest.get("schema") != SCHEMA + "-manifest"):
        raise ValueError("MANIFEST_SCHEMA")
    if report.get("assumptions") != ADVERSARIAL_ASSUMPTIONS:
        raise ValueError("ASSUMPTION_SUBSTITUTION")
    cases = cases_for(report.get("seeds"), report.get("duration_seconds"))
    expected = {f"{case.name}_s{case.seed}.jsonl.gz" for case in cases} | {"report.json"}
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
    validate_source(report["source"])
    records = report.get("observations")
    if type(records) is not list or len(records) != len(cases):
        raise ValueError("OBSERVATION_INVENTORY")
    for case, record in zip(cases, records):
        if type(record) is not dict or set(record) != {"parameters", "summary", "native_arithmetic_readback", "trace_file"}:
            raise ValueError("OBSERVATION_SCHEMA")
        filename = f"{case.name}_s{case.seed}.jsonl.gz"
        if canonical(record["parameters"]) != canonical(asdict(case)) or record["trace_file"] != filename:
            raise ValueError("SCENARIO_SUBSTITUTION")
        rows = read_rows(out / filename)
        if record["native_arithmetic_readback"] != check_native_periodic_arithmetic(rows, case):
            raise ValueError("NATIVE_READBACK_MISMATCH")
        summary, replay = run_network_scenario(case)
        if record["summary"] != summary or rows != replay:
            raise ValueError("SEEDED_REPLAY_MISMATCH")
    if report["bounded_search"] != bounded_search(records):
        raise ValueError("BOUNDED_SEARCH_SUBSTITUTION")
    return {"result": "ADVERSARIAL_REPLAY_AND_NATIVE_ARITHMETIC_PASS", "runs": len(cases),
            "native_w1_verified": False, "quantum_resource_verified": False,
            "global_attack_optimum_claimed": False, "release_ready": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--out", type=Path)
    action.add_argument("--verify", type=Path)
    parser.add_argument("--seeds", nargs="+", type=int, default=[5101, 5102, 5103])
    parser.add_argument("--duration-seconds", type=float, default=900)
    args = parser.parse_args()
    result = (verify_campaign(args.verify) if args.verify else
              run_campaign(args.out, sys.argv, tuple(args.seeds), args.duration_seconds))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
