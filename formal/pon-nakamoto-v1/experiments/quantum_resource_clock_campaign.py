#!/usr/bin/env python3
"""Source-bound finite observations using resource-derived quantum clocks.

The supplied circuit request remains a premise, not a verified W1 certificate.
A concrete W1 construction must accompany it with its own construction receipt.
Physical parameters are hypothetical. No security or release gate is granted.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from quantum_network_sim import NetworkScenario, ParticipationShock  # noqa: E402
from quantum_oracle_resources import SCHEMA as REQUEST_SCHEMA, load_request  # noqa: E402
from quantum_resource_clock import canonical, run_resource_bound, source_fingerprint  # noqa: E402

SCHEMA = "trnm-quantum-resource-clock-campaign-v2"
MAX_RECEIPT_BYTES = 8_000_000


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def source_record(extra_paths=()) -> dict:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    files = {"formal/pon-nakamoto-v1/" + name: value for name, value in source_fingerprint().items()}
    own = "formal/pon-nakamoto-v1/experiments/quantum_resource_clock_campaign.py"
    files[own] = sha((ROOT / own).read_bytes())
    files.update({name: sha((ROOT / name).read_bytes()) for name in extra_paths})
    uncommitted = []
    for path, expected in files.items():
        old = subprocess.run(["git", "show", head + ":" + path], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or sha(old.stdout) != expected:
            uncommitted.append(path)
    return {"git_head": head, "source_sha256": files,
            "all_source_files_committed_at_head": not uncommitted,
            "uncommitted_source_files": uncommitted}


def cases(request, seed: int, duration: float) -> list[NetworkScenario]:
    base = NetworkScenario("resource_honest_restart", seed=seed, duration_seconds=duration,
            quantum_processors=request.workload.independent_instances,
            quantum_fixed_iterations=32, quantum_max_iterations=128,
            propagation_seconds=request.classical.per_winner_propagation_ns / 10**9,
            probe_arrival_seconds=min(1, duration / 4),
            max_events=10000, max_blocks=1000, max_trace_rows=50000,
            shocks=(ParticipationShock(duration / 3, 0.5, 0),
                    ParticipationShock(2 * duration / 3, 1, 1)))
    return [base,
        replace(base, name="resource_private_mtp", quantum_strategy="private-branch",
                quantum_timestamp_mode="mtp-min", private_release_seconds=duration * 0.8),
        replace(base, name="resource_bounded_throughput", quantum_fixed_iterations=None,
                quantum_trial_policy="bounded-throughput",
                quantum_iteration_candidates=(0, 1, 2, 4, 8, 16, 32, 64, 128)),
    ]


def observe(request, model: str, budget: int, seed: int, duration: float,
            construction_spec: dict | None = None) -> dict:
    construction = None
    extra_paths = ()
    if construction_spec is not None:
        from w1_quantum_oracle import OracleProgram, SOURCE_FILES, template_from_spec
        program = OracleProgram(template_from_spec(construction_spec))
        # Only classical/physical costs and workload grouping are caller inputs.
        # Replace every circuit-stage budget from the concrete construction.
        request = program.resource_request(request.workload, request.classical, request.physical_models)
        construction = program.resources()
        extra_paths = SOURCE_FILES
    source = source_record(extra_paths)
    if construction is not None and any(source["source_sha256"].get(name) != expected
            for name, expected in construction["source_sha256"].items()):
        raise ValueError("CONSTRUCTION_SOURCE_CHANGED")
    rows = []
    for case in cases(request, seed, duration):
        summary, trace, resource = run_resource_bound(case, request, model, budget)
        rows.append({"requested_scenario": asdict(case), "summary": summary,
                     "trace_sha256": sha(canonical(trace)), "trace_rows": len(trace),
                     "resources": resource})
    if source_record(extra_paths)["source_sha256"] != source["source_sha256"]:
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    return {"schema": SCHEMA, "source": source,
            "request": {"schema": REQUEST_SCHEMA, **asdict(request)},
            "model_name": model, "physical_qubit_budget": budget,
            "seed": seed, "duration_seconds": duration, "observations": rows,
            "construction_spec": construction_spec, "construction": construction,
            "circuit_budgets_rederived_from_construction": construction is not None,
            "construction_binding_scope": "circuit cost shape; abstract network targets and marked sets are not the fixed header",
            "simulated_success_probabilities_bound_to_constructed_predicate": False,
            "security_theorem": False, "physical_hardware_calibrated": False,
            "W1_semantics_verified_by_this_campaign": False, "release_ready": False}


def verify(record: dict) -> dict:
    if type(record) is not dict or record.get("schema") != SCHEMA:
        raise ValueError("RESOURCE_CAMPAIGN_SCHEMA")
    extra_paths = ()
    if record.get("construction_spec") is not None:
        from w1_quantum_oracle import SOURCE_FILES
        extra_paths = SOURCE_FILES
    source = source_record(extra_paths)
    if source["source_sha256"] != record["source"]["source_sha256"]:
        raise ValueError("RESOURCE_CAMPAIGN_SOURCE")
    # Verify the historical commitment claim as well as the current bytes.
    historical = record["source"]
    head = historical["git_head"]
    if type(head) is not str or len(head) != 40 or any(c not in "0123456789abcdef" for c in head):
        raise ValueError("SOURCE_HEAD")
    commit = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if commit.returncode or commit.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    uncommitted = []
    for path, expected in source["source_sha256"].items():
        old = subprocess.run(["git", "show", head + ":" + path], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or sha(old.stdout) != expected:
            uncommitted.append(path)
    if (historical["uncommitted_source_files"] != uncommitted
            or historical["all_source_files_committed_at_head"] is not (not uncommitted)):
        raise ValueError("SOURCE_COMMITMENT_CLAIM")
    request = load_request(canonical(record["request"]))
    repeated = observe(request, record["model_name"], record["physical_qubit_budget"],
                       record["seed"], record["duration_seconds"], record.get("construction_spec"))
    # A source-identical descendant may replay a receipt; source SHA, not the
    # descendant's unrelated files, determines this experiment's closure.
    repeated["source"] = historical
    if canonical(repeated) != canonical(record):
        raise ValueError("RESOURCE_CAMPAIGN_REPLAY_MISMATCH")
    return {"schema": SCHEMA, "result": "PASS", "replayed_cases": len(record["observations"]),
            "source_git_head": head, "resource_clocks_rederived": True,
            "circuit_budgets_rederived_from_construction": record["circuit_budgets_rederived_from_construction"],
            "full_trace_digests_recomputed": True, "security_theorem": False,
            "release_ready": False}


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def reject_constant(value):
    raise ValueError("NONFINITE_JSON_NUMBER:" + value)


def write_atomic(path: Path, raw: bytes) -> None:
    if path.exists() or path.is_symlink() or len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("OUTPUT_EXISTS_OR_BOUND")
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # Link publishes a complete file atomically and refuses an intervening
    # writer's destination; never overwrite an existing campaign receipt.
    os.link(temporary, path)
    temporary.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--request", type=Path)
    mode.add_argument("--verify", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--qubits", type=int)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--duration", type=float, default=1200)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--oracle-spec", type=Path,
                        help="replace circuit budgets by compiling this fixed-header oracle specification")
    args = parser.parse_args()
    path = args.request if args.request is not None else args.verify
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECEIPT_BYTES:
        raise ValueError("RESOURCE_CAMPAIGN_FILE_BOUND")
    raw = path.read_bytes()
    if args.verify:
        result = verify(json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_constant))
    else:
        if args.model is None or args.qubits is None or args.output is None:
            parser.error("--request requires --model, --qubits and --output")
        spec = None
        if args.oracle_spec is not None:
            if (args.oracle_spec.is_symlink() or not args.oracle_spec.is_file()
                    or args.oracle_spec.stat().st_size > 131072):
                raise ValueError("ORACLE_SPEC_FILE_BOUND")
            spec = json.loads(args.oracle_spec.read_bytes(), object_pairs_hook=strict_object,
                              parse_constant=reject_constant)
        result = observe(load_request(raw), args.model, args.qubits, args.seed, args.duration, spec)
    if args.output:
        write_atomic(args.output, canonical(result) + b"\n")
        print(json.dumps({"path": str(args.output), "sha256": sha(args.output.read_bytes()),
                          "cases": len(result.get("observations", []))}, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
