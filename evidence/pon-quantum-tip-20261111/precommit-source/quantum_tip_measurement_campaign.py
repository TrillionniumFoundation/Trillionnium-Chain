#!/usr/bin/env python3
"""Source-bound, same-parameter paired conditional tip-policy observations.

No native W1, quantum hardware, lower bound or consensus security is proved.
Uniform propagation and first-seen equal-work ties imply gamma=0 in the usual
same-parent race after the quantum miner receives an honest block. Seeds couple
initial random streams, not identical post-policy block-arrival trajectories.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
RUNNER_RELATIVE_PATH = "formal/pon-nakamoto-v1/quantum_tip_measurement_campaign.py"
from quantum_network_sim import NetworkScenario, run_network_scenario, ASSUMPTIONS
from experiments.quantum_network_campaign import (
    source_record, validate_source_record, check_trace_arithmetic, write_rows, read_rows, load_json)

SCHEMA = "trnm-quantum-tip-policy-paired-v1"
SEEDS = (4101, 4102, 4103)
DOMAIN_MODES = ("abstract-uniform-p", "sampled-finite-4096")
PROCESSORS = (1, 4)
DELAYS = (0.0, 0.5, 5.0)
TIP_POLICIES = ("discard-restart", "measure-on-tip")
SCOPE = {
    "model": "conditional finite event simulator with exact required-target/work/time arithmetic",
    "durations_seconds": 600,
    "paired_parameters": "only quantum_tip_policy differs within a pair; names and seeds are identical",
    "seed_scope": "same initial RNG seeds; policies change RNG consumption and event histories",
    "finite_domain": "4096 uniform independent 256-bit candidate tickets per context; sampled marked count shared across processors and retries",
    "domain_relation_to_native_w1": "uniform-ticket premise; actual evolving W1 marked sets not verified",
    "finite_domain_scope": "4096 candidates is a small-domain stress panel, not the full native 64-bit nonce domain",
    "network": "uniform propagation to every receiver; strict greater-work fork choice; equal work retains first tip",
    "gamma_limit": "ordinary same-parent competitors measured after receiving the honest block face gamma=0; this panel does not model heterogeneous routing or priority delivery",
    "costs": "declared synthetic clocks, not measured W1/hardware/economic costs",
    "receipt_scope": "source-consistent replay; no authenticated host execution or simulator-time attestation",
    "native_w1_verified": False,
    "quantum_hardware_executed": False,
    "quantum_work_lower_bound_proved": False,
    "cp_cg_cq_proved": False,
    "whole_chain_quantum_security_qualified": False,
    "production_consensus_activation": False,
    "release_ready": False,
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

def source_at(root):
    source = source_record()
    source["tree"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    source["runner_sha256"] = sha(Path(__file__).resolve())
    runner_at_head = subprocess.run(
        ["git", "show", source["git_head"] + ":" + RUNNER_RELATIVE_PATH],
        cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    source["runner_committed_at_head"] = (runner_at_head.returncode == 0
        and hashlib.sha256(runner_at_head.stdout).hexdigest() == source["runner_sha256"])
    return source

def cases():
    for domain in DOMAIN_MODES:
        for processors in PROCESSORS:
            for delay in DELAYS:
                label = "abstract" if domain == "abstract-uniform-p" else "finite4096"
                dlabel = str(delay).replace(".", "p")
                base = NetworkScenario(
                    name=f"qtip_{label}_p{processors}_d{dlabel}",
                    duration_seconds=600.0,
                    quantum_clock_rounding="upward",
                    quantum_processors=processors,
                    propagation_seconds=delay,
                    quantum_domain_size=None if domain == "abstract-uniform-p" else 4096,
                    quantum_domain_marked_count=None,
                    quantum_domain_trials_before_refresh=0,
                    quantum_domain_setup_seconds=0.0 if domain == "abstract-uniform-p" else 0.02,
                    cpu_limit_seconds=30.0)
                for seed in SEEDS:
                    pair_id = f"{base.name}_s{seed}"
                    for policy in TIP_POLICIES:
                        case = replace(base, seed=seed, quantum_tip_policy=policy)
                        yield pair_id, policy, domain, case

def metrics(summary, rows):
    parents = {}
    miners = {}
    for row in rows:
        if row["kind"] == "block":
            parents[row["block"]] = row["parent"]
            miners[row["block"]] = row["miner"]
    tip = summary["observer_tip"]
    q_on_chain = 0
    while tip != "prefix":
        q_on_chain += int(miners[tip] == "q")
        tip = parents[tip]
    q = summary["miners"]["q"]
    return {
        "observer_added_blocks": summary["observer_added_blocks"],
        "observer_added_chainwork": summary["observer_added_chainwork"],
        "quantum_blocks_on_observer_chain": q_on_chain,
        "quantum_blocks_created": q["blocks_created"],
        "quantum_stale_proofs_completed": q["stale_proofs_completed"],
        "quantum_searches_started": q["searches_started"],
        "quantum_searches_completed": q["searches_completed"],
        "quantum_searches_failed": q["searches_failed"],
        "quantum_searches_cancelled": q["searches_cancelled"],
        "quantum_search_seconds": q["search_seconds"],
        "quantum_logical_iterations_all_processors": q["logical_iterations_completed"],
        "quantum_candidate_checks_started": q["candidate_checks_started"],
        "quantum_candidate_check_processor_seconds": q["candidate_check_processor_seconds"],
        "quantum_proofs_started": q["proofs_started"],
        "quantum_proof_seconds": q["proof_seconds"],
        "tip_measurement_requests": q.get("tip_measurement_requests", 0),
        "domains_created": summary.get("adversarial", {}).get("domains_created"),
        "zero_marked_domains": summary.get("adversarial", {}).get("zero_marked_domains"),
        "termination": summary["termination"],
    }

def comparisons(records):
    result = []
    for first, second in zip(records[::2], records[1::2]):
        if first["pair_id"] != second["pair_id"] or first["policy"] != TIP_POLICIES[0] or second["policy"] != TIP_POLICIES[1]:
            raise ValueError("PAIR_IDENTITY")
        a, b = dict(first["parameters"]), dict(second["parameters"])
        a.pop("quantum_tip_policy")
        b.pop("quantum_tip_policy")
        if a != b:
            raise ValueError("PAIR_PARAMETER_MISMATCH")
        result.append({
            "pair_id": first["pair_id"],
            "parameters_except_tip_policy": a,
            "discard": first["metrics"],
            "measure": second["metrics"],
            "delta_measure_minus_discard": {
                name: second["metrics"][name] - first["metrics"][name]
                for name in (
                    "observer_added_blocks", "quantum_blocks_on_observer_chain",
                    "quantum_blocks_created", "quantum_stale_proofs_completed",
                    "quantum_searches_completed", "quantum_search_seconds",
                    "quantum_logical_iterations_all_processors",
                    "quantum_candidate_check_processor_seconds", "quantum_proof_seconds")
            },
        })
    return result

def run(root, out):
    before = source_at(root)
    if not before["all_source_files_committed_at_head"] or not before["runner_committed_at_head"]:
        raise ValueError("UNCOMMITTED_ENUMERATED_SOURCE")
    out.mkdir(parents=True, exist_ok=False)
    wall, cpu = time.perf_counter(), time.process_time()
    records, files = [], {}
    for pair_id, policy, domain, case in cases():
        summary, rows = run_network_scenario(case)
        check_trace_arithmetic(rows)
        filename = f"{pair_id}_{policy}.jsonl.gz"
        write_rows(out / filename, rows)
        files[filename] = sha(out / filename)
        records.append({
            "pair_id": pair_id, "policy": policy, "domain_mode": domain,
            "parameters": asdict(case), "summary": summary,
            "metrics": metrics(summary, rows), "trace_file": filename,
        })
    after = source_at(root)
    if before != after:
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    report = {
        "schema": SCHEMA, "source": before, "source_after": after,
        "scope": SCOPE, "assumptions": ASSUMPTIONS,
        "parameters": {"seeds": SEEDS, "domains": DOMAIN_MODES,
                       "processors": PROCESSORS, "propagation_seconds": DELAYS,
                       "tip_policies": TIP_POLICIES},
        "observations": records, "paired_comparisons": comparisons(records),
        "actual_python_process": {
            "wall_seconds": time.perf_counter() - wall,
            "cpu_seconds": time.process_time() - cpu,
            "python": sys.version, "platform": platform.platform(),
            "scope": "simulator and artifact serialization only",
        },
    }
    (out / "report.json").write_bytes(canonical(report))
    files["report.json"] = sha(out / "report.json")
    (out / "manifest.json").write_bytes(canonical({
        "schema": SCHEMA + "-manifest", "files_sha256": files}))
    complete = sum(r["summary"]["termination"] == "horizon" and not r["summary"]["trace_limit_reached"] for r in records)
    return {
        "status": "CONDITIONAL_PAIRED_OBSERVATIONS",
        "runs": len(records), "pairs": len(records) // 2,
        "complete_horizon_runs": complete,
        "tip_measurement_requests": sum(r["metrics"]["tip_measurement_requests"] for r in records),
        "panel_complete": complete == len(records), "release_ready": False,
        "tested_commit": before["git_head"], "tested_tree": before["tree"],
    }

def verify(root, out):
    if out.is_symlink() or not out.is_dir():
        raise ValueError("OUTPUT_DIRECTORY")
    report = load_json(out / "report.json")
    manifest = load_json(out / "manifest.json")
    if not isinstance(report, dict) or not isinstance(manifest, dict):
        raise ValueError("REPORT_OR_MANIFEST_TYPE")
    if report.get("schema") != SCHEMA or manifest.get("schema") != SCHEMA + "-manifest":
        raise ValueError("SCHEMA")
    if report.get("scope") != SCOPE or report.get("assumptions") != ASSUMPTIONS:
        raise ValueError("ASSUMPTION_SUBSTITUTION")
    expected_parameters = {"seeds": SEEDS, "domains": DOMAIN_MODES,
                           "processors": PROCESSORS, "propagation_seconds": DELAYS,
                           "tip_policies": TIP_POLICIES}
    if canonical(report.get("parameters")) != canonical(expected_parameters):
        raise ValueError("PANEL_PARAMETER_SUBSTITUTION")
    source = source_at(root)
    if report.get("source") != source or report.get("source_after") != source:
        raise ValueError("SOURCE_BINDING")
    validate_source_record(report["source"])
    expected_cases = list(cases())
    expected_names = {f"{pair_id}_{policy}.jsonl.gz" for pair_id, policy, _, _ in expected_cases} | {"report.json"}
    if set(manifest.get("files_sha256", {})) != expected_names or {p.name for p in out.iterdir()} != expected_names | {"manifest.json"}:
        raise ValueError("MANIFEST_INVENTORY")
    for name, wanted in manifest["files_sha256"].items():
        path = out / name
        if path.is_symlink() or not path.is_file() or sha(path) != wanted:
            raise ValueError("ARTIFACT_DIGEST")
    records = report.get("observations")
    if not isinstance(records, list) or len(records) != len(expected_cases):
        raise ValueError("OBSERVATION_INVENTORY")
    for expected, record in zip(expected_cases, records):
        pair_id, policy, domain, case = expected
        if (record.get("pair_id") != pair_id or record.get("policy") != policy
                or record.get("domain_mode") != domain
                or canonical(record.get("parameters")) != canonical(asdict(case))
                or record.get("trace_file") != f"{pair_id}_{policy}.jsonl.gz"):
            raise ValueError("SCENARIO_SUBSTITUTION")
        rows = read_rows(out / record["trace_file"])
        check_trace_arithmetic(rows)
        summary, replay = run_network_scenario(case)
        if record.get("summary") != summary or rows != replay or record.get("metrics") != metrics(summary, replay):
            raise ValueError("SEEDED_REPLAY_MISMATCH")
    if report.get("paired_comparisons") != comparisons(records):
        raise ValueError("PAIR_COMPARISON_MISMATCH")
    return {
        "status": "PAIRED_SOURCE_BOUND_REPLAY_AND_ARITHMETIC_PASS",
        "replayed_runs": len(records), "pairs": len(records) // 2,
        "native_w1_verified": False, "cp_cg_cq_proved": False, "release_ready": False,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--out", type=Path)
    action.add_argument("--verify", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if root != ROOT:
        raise ValueError("ROOT_MISMATCH")
    result = run(root, args.out) if args.out is not None else verify(root, args.verify)
    print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)

if __name__ == "__main__":
    main()
