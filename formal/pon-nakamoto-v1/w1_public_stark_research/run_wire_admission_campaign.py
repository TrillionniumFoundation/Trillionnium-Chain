#!/usr/bin/env python3
"""Compare fixed-profile structural rejections on the same retained full proofs.

This replays actual old proofs, generates zero new proofs, and runs each
verification in a new process. ABBA ordering controls ordering only: the shared
host is not an isolated production resource contract or a worst-case bound.
"""
import argparse
import json
import os
import platform
import statistics
import sys
from pathlib import Path

from run_campaign import execute, save, sha

BASELINE_BINARY = "7700eff6ea4a3ff1f8f6551c323ac5b90b2bb5a96d1eaeca41e108bc54a7e3fc"
RETAINED = {
    "statement.bin": "d8b06f64c5e3ff0242e1fe30110280be56fe9eca9cfb55086f7ed7ab5bdb3b6c",
    "sha.proof.bin": "ca4867c63de4f0d247930944d4c47d87342a4945a399abe9f8a57eba2502e33c",
    "arith.proof.bin": "cfce6e90bd1f171ab6d202e70f2e442f8a88e490a22c806275dde2af1d6cf204",
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["candidate", "baseline", "mutator", "proofs", "fixture_stem", "output"]:
        p.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = p.parse_args()
    candidate = args.candidate.resolve(strict=True)
    baseline = args.baseline.resolve(strict=True)
    mutator = args.mutator.resolve(strict=True)
    proofs = args.proofs.resolve(strict=True)
    header = Path(str(args.fixture_stem) + ".expected-header.bin").resolve(strict=True)
    artifacts = Path(str(args.fixture_stem) + ".artifacts.bin").resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if sha(baseline.read_bytes()) != BASELINE_BINARY:
        raise RuntimeError("frozen baseline binary mismatch")
    for name, expected in RETAINED.items():
        if sha((proofs / name).read_bytes()) != expected:
            raise RuntimeError("retained proof bytes mismatch: " + name)
    paths = [candidate, baseline, mutator, header, artifacts]
    source = Path(__file__).resolve().parent
    paths += [Path(__file__), source / "run_campaign.py", source / "Cargo.toml", source / "Cargo.lock"]
    paths += sorted((source / "src").glob("*.rs")) + sorted((source / "tests").glob("*.rs"))
    paths += sorted((source / "examples").glob("*.rs"))
    bindings = {str(path): {"bytes": path.stat().st_size, "sha256": sha(path.read_bytes())} for path in paths}
    save(output / "source-before.json", bindings)
    save(output / "provenance.json", {
        "schema": "w1-wire-admission-campaign-v1", "qualification": "HOLD_NO_GO",
        "machine": platform.uname()._asdict(), "python": sys.version,
        "rayon_num_threads": os.environ.get("RAYON_NUM_THREADS"),
        "baseline_source_commit": "3bbd072e4983eceee4531d7576d329da5b0d0900",
        "proof_source_commit": "3bbd072e4983eceee4531d7576d329da5b0d0900",
        "retained_full_proof_hashes": RETAINED,
        "new_proofs_generated": 0, "production_resource_contract": False,
        "canonical_field_changes_require_the_original_cryptographic_verifier": True,
    })
    positive = []
    for i in range(3):
        record = execute(f"candidate-valid-{i}", [candidate, "verify", proofs / "statement.bin", header, artifacts, proofs], output, True)
        if record["final"]["status"] != "VERIFIED_COMPLETE_W1_RESEARCH_ONLY":
            raise RuntimeError("not a complete verification")
        positive.append(record)
    controls = []
    modes = ["trace-width-short", "last-input-row-short", "last-fold-extra-query", "final-polynomial-extra"]
    for component, filename in [("sha", "sha.proof.bin"), ("arithmetic", "arith.proof.bin")]:
        for mode in modes:
            label = component + "-" + mode
            case = output / label
            case.mkdir()
            for name in RETAINED:
                if name != filename:
                    os.link(proofs / name, case / name)
            mutation = execute("mutate-" + label, [mutator, component, mode, proofs / filename, case / filename], output, True)
            rows = []
            for block in range(3):
                for position, (which, binary) in enumerate([("baseline", baseline), ("candidate", candidate), ("candidate", candidate), ("baseline", baseline)]):
                    name = f"{label}-{block}-{position}-{which}"
                    result = execute(name, [binary, "verify", case / "statement.bin", header, artifacts, case], output, False)
                    error = (result["final"] or {}).get("error", "")
                    if (result["final"] or {}).get("status") != "REJECTED_OR_FAILED":
                        raise RuntimeError(name + ": process did not return a controlled refusal")
                    phases = {x["phase"] for x in result["phase_events"]}
                    if which == "candidate":
                        if not error.startswith("proof decoding: wire admission") or phases:
                            raise RuntimeError(name + ": rejection was not before setup/decode completion")
                    elif "sha_verifier_independent_preprocessing_setup" not in phases:
                        raise RuntimeError(name + ": baseline did not incur the original setup")
                    rows.append({"binary": which, "block": block, "position": position, "result": result})
            medians = {which: statistics.median(row["result"]["outer_wall_seconds"] for row in rows if row["binary"] == which) for which in ["baseline", "candidate"]}
            control = {"label": label, "mutation": mutation, "rows": rows, "outer_wall_medians": medians,
                       "ratio_of_medians_candidate_over_baseline": medians["candidate"] / medians["baseline"]}
            controls.append(control)
            save(output / (label + ".summary.json"), control)
    after = {str(path): {"bytes": path.stat().st_size, "sha256": sha(path.read_bytes())} for path in paths}
    save(output / "source-after.json", after)
    if after != bindings:
        raise RuntimeError("measured source or binary changed")
    for name, expected in RETAINED.items():
        if sha((proofs / name).read_bytes()) != expected:
            raise RuntimeError("retained original changed")
    summary = {
        "schema": "w1-wire-admission-campaign-summary-v1", "qualification": "HOLD_NO_GO",
        "positive_count": len(positive), "positive": positive,
        "mutated_shapes": len(controls), "rejection_processes": sum(len(x["rows"]) for x in controls),
        "controls": controls, "new_proofs_generated": 0,
        "source_before_after_equal": True,
        "global_malicious_rejection_cost_bound": False,
        "production_node_admission": False,
        "scope": "finite fixed-profile shape controls; no worst-case wall/CPU/heap or production qualification",
    }
    save(output / "summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k not in ["controls", "positive"]}), flush=True)


if __name__ == "__main__":
    main()
