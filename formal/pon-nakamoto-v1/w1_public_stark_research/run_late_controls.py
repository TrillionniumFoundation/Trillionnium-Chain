#!/usr/bin/env python3
"""Typed late FRI rejection controls, separate from the frozen first campaign.

No proof-carried transcript fields, public statement or independent expected
inputs are changed. This measures four concrete late rejection paths, not a
global maximum over malformed proofs or the cheapest from-zero attacker.
"""
import argparse
import json
import os
from pathlib import Path

from run_campaign import ROOT, execute, save, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--binary", type=Path,
                        default=ROOT / "target/release/w1-full-public-stark-research")
    parser.add_argument("--mutator", type=Path,
                        default=ROOT / "target/release/examples/mutate_last_query")
    args = parser.parse_args()
    output = args.output.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    mutator = args.mutator.resolve(strict=True)
    provenance = json.loads((output / "provenance.json").read_text())
    if sha(binary.read_bytes()) != provenance["binary_sha256"]:
        raise RuntimeError("verifier binary changed since this proof's generation")
    positive = json.loads((output / "verification-campaign/summary.json").read_text())
    if positive["positive_count"] != 3 or not all(
            row["final"]["status"] == "VERIFIED_COMPLETE_W1_RESEARCH_ONLY"
            for row in positive["positive"]):
        raise RuntimeError("original proof lacks the three retained positive verifications")
    header = Path(provenance["fixtures"]["header"]["path"])
    artifacts = Path(provenance["fixtures"]["artifacts"]["path"])
    for name, path in [("header", header), ("artifacts", artifacts)]:
        if sha(path.read_bytes()) != provenance["fixtures"][name]["sha256"]:
            raise RuntimeError("independent expected inputs changed")
    campaign = output / "late-query-campaign"
    campaign.mkdir(exist_ok=False)
    original_hashes = {name: sha((output / name).read_bytes())
                       for name in ["statement.bin", "sha.proof.bin", "arith.proof.bin"]}
    for row in positive["positive"]:
        for filename, field in [("statement.bin", "statement_sha256"),
                                ("sha.proof.bin", "sha_proof_sha256"),
                                ("arith.proof.bin", "arith_proof_sha256")]:
            if row["final"].get(field) != original_hashes[filename]:
                raise RuntimeError("mutation baseline differs from the independently verified bytes")
    metadata = {
        "schema": "trnm-w1-typed-late-fri-controls-v1", "qualification": "HOLD_NO_GO",
        "verifier_binary_sha256": sha(binary.read_bytes()),
        "mutator_binary_sha256": sha(mutator.read_bytes()),
        "mutator_source_sha256": sha((ROOT / "examples/mutate_last_query.rs").read_bytes()),
        "campaign_source_sha256": sha(Path(__file__).read_bytes()),
        "retained_campaign_module_sha256": sha((ROOT / "run_campaign.py").read_bytes()),
        "original_artifact_sha256": original_hashes,
        "scope": "one typed value or digest element in a valid public proof; no from-zero attacker cost floor",
    }
    save(campaign / "provenance.json", metadata)
    observations = []
    for component in ["sha", "arith"]:
        for mode, subtype in [("last-fold-query-value", "FinalPolyMismatch"),
                              ("last-fold-auth-sibling", "CommitPhaseMmcsError(CapMismatch)")]:
            label = component + "-" + mode
            case = campaign / label
            case.mkdir()
            changed = component + ".proof.bin"
            for name in ["statement.bin", "sha.proof.bin", "arith.proof.bin"]:
                if name != changed:
                    os.link(output / name, case / name)
            mutation = execute("mutate-" + label,
                               [mutator, mode, output / changed, case / changed], campaign, True)
            m = mutation["final"]
            if (m["status"] != "MUTATED_RESEARCH_PROOF_ONLY"
                    or m["transcript_fields_unchanged"] is not True
                    or m["proof_bytes_before"] != m["proof_bytes_after"]
                    or m["changed_byte_count"] <= 0
                    or m["proof_sha256_before"] != original_hashes[changed]
                    or m["proof_sha256_after"] != sha((case / changed).read_bytes())):
                raise RuntimeError("typed mutation contract failed")
            control = execute("verify-" + label,
                              [binary, "verify", case / "statement.bin", header, artifacts, case],
                              campaign, False)
            expected_prefix = "sha proof rejected:" if component == "sha" else "arithmetic proof rejected:"
            error = (control["final"] or {}).get("error", "")
            if not error.startswith(expected_prefix) or subtype not in error:
                raise RuntimeError(f"{label}: unexpected rejection frontier: {error}")
            if "SiblingCountMismatch" in error:
                raise RuntimeError("shape rejection cannot stand in for the late authentication control")
            required = "sha_stark_verify" if component == "sha" else "arith_stark_verify"
            if required not in {event["phase"] for event in control["phase_events"]}:
                raise RuntimeError("timed STARK rejection phase missing")
            inputs = {name: {"bytes": (case / name).stat().st_size,
                            "sha256": sha((case / name).read_bytes())}
                      for name in ["statement.bin", "sha.proof.bin", "arith.proof.bin"]}
            observations.append({"label": label, "mutation": mutation, "verification": control,
                                 "input_manifest": inputs, "expected_subtype": subtype,
                                 "rejection_frontier_matched": True})
    if original_hashes != {name: sha((output / name).read_bytes()) for name in original_hashes}:
        raise RuntimeError("original artifacts changed")
    save(campaign / "summary.json", {
        "schema": "trnm-w1-typed-late-fri-rejection-summary-v1", "qualification": "HOLD_NO_GO",
        "control_count": len(observations), "observations": observations,
        "largest_observed_outer_seconds": max(x["verification"]["outer_wall_seconds"] for x in observations),
        "is_global_latest_rejection_bound": False,
        "verifier_order": "input multiproofs, all query fold chains and final-polynomial checks, then shared commit-phase authentication in round order",
    })
    print(json.dumps({"status": "FOUR_TYPED_LATE_CONTROLS_REJECTED", "qualification": "HOLD_NO_GO"}), flush=True)


if __name__ == "__main__":
    main()
