#!/usr/bin/env python3
"""Replay retained full proofs with an explicitly different successor verifier.

This does not rewrite historical proof-generation provenance, generate new
proofs, or certify a global rejection bound. Every verification is a fresh
process with independent expected inputs and independently rebuilt setup.
"""
import argparse
import json
import os
from pathlib import Path

from run_campaign import (
    INPUT_BYTES, PREFIX_BYTES, PUBLIC_BYTES, changed_first_commitment,
    changed_word, execute, flipped, save, sha,
)
from run_wire_admission_campaign import RETAINED


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["binary", "mutator", "proofs", "fixture_stem", "output"]:
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    mutator = args.mutator.resolve(strict=True)
    proofs = args.proofs.resolve(strict=True)
    header = Path(str(args.fixture_stem) + ".expected-header.bin").resolve(strict=True)
    artifacts = Path(str(args.fixture_stem) + ".artifacts.bin").resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name, expected in RETAINED.items():
        if sha((proofs / name).read_bytes()) != expected:
            raise RuntimeError("retained proof mismatch: " + name)
    source = Path(__file__).resolve().parent
    paths = [binary, mutator, header, artifacts, Path(__file__),
             source / "run_campaign.py", source / "run_wire_admission_campaign.py",
             source / "Cargo.toml", source / "Cargo.lock"]
    paths += sorted((source / "src").glob("*.rs"))
    paths += sorted((source / "examples").glob("*.rs"))
    before = {str(p): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in paths}
    save(output / "source-before.json", before)
    save(output / "provenance.json", {
        "schema": "trnm-w1-successor-replay-v1", "qualification": "HOLD_NO_GO",
        "historical_proof_source_commit": "3bbd072e4983eceee4531d7576d329da5b0d0900",
        "historical_proof_sha256": RETAINED,
        "historical_provenance_unchanged": True, "new_proofs_generated": 0,
        "successor_verifier_sha256": sha(binary.read_bytes()),
        "global_malicious_rejection_cost_bound": False,
    })
    positive = execute("positive-successor", [binary, "verify", proofs / "statement.bin",
                       header, artifacts, proofs], output, True)
    if positive["final"]["status"] != "VERIFIED_COMPLETE_W1_RESEARCH_ONLY":
        raise RuntimeError("positive did not complete")
    public = (proofs / "statement.bin").read_bytes()
    sp = (proofs / "sha.proof.bin").read_bytes()
    ap = (proofs / "arith.proof.bin").read_bytes()
    controls = [
        ("public-extra-byte", {"statement.bin": public + b"\x00"}, "bounded file length"),
        ("sha-proof-truncated", {"sha.proof.bin": sp[:-32]}, "proof decoding:"),
        ("sha-proof-trailing-byte", {"sha.proof.bin": sp + b"\x00"}, "proof decoding:"),
        ("sha-commitment-changed", {"sha.proof.bin": changed_first_commitment(sp)}, "sha proof rejected:"),
        ("arith-commitment-changed", {"arith.proof.bin": changed_first_commitment(ap)}, "arithmetic proof rejected:"),
        ("last-C-changed", {"statement.bin": changed_word(public, 8 + INPUT_BYTES - 32 - 4)}, "arithmetic proof rejected:"),
        ("last-prefix-changed", {"statement.bin": changed_word(public, 8 + INPUT_BYTES + PREFIX_BYTES - 4)}, "sha proof rejected:"),
        ("last-AB-intermediate-changed", {"statement.bin": changed_word(public, PUBLIC_BYTES - 4)}, "arithmetic proof rejected:"),
        ("unused-noise-tail-changed", {"statement.bin": flipped(public, 8 + INPUT_BYTES + PREFIX_BYTES + 32 + 4 * 128 * 32 - 1)}, "sha proof rejected:"),
        ("wrong-independent-artifacts", {"expected-artifacts.bin": flipped(artifacts.read_bytes(), 63)}, "sha proof rejected:"),
        ("wrong-independent-header", {"expected-header.bin": flipped(header.read_bytes(), 317)}, "IndependentHeader"),
    ]
    ordinary = []
    for label, replacements, prefix in controls:
        case = output / label
        case.mkdir()
        for name in RETAINED:
            if name not in replacements:
                os.link(proofs / name, case / name)
        for name, data in replacements.items():
            with (case / name).open("xb") as f:
                f.write(data)
        ch = case / "expected-header.bin" if "expected-header.bin" in replacements else header
        ca = case / "expected-artifacts.bin" if "expected-artifacts.bin" in replacements else artifacts
        obs = execute(label, [binary, "verify", case / "statement.bin", ch, ca, case], output, False)
        error = (obs["final"] or {}).get("error", "")
        if (obs["final"] or {}).get("status") != "REJECTED_OR_FAILED" or not error.startswith(prefix):
            raise RuntimeError(label + ": wrong rejection frontier: " + error)
        if prefix == "arithmetic proof rejected:":
            phases = {e["phase"] for e in obs["phase_events"]}
            if not {"sha_stark_verify", "arith_verifier_independent_preprocessing_setup", "arith_stark_verify"} <= phases:
                raise RuntimeError(label + ": arithmetic verifier not reached")
        ordinary.append({"label": label, "expected_error_prefix": prefix, "observation": obs})
    late = []
    for component in ["sha", "arith"]:
        for mode, subtype in [("last-fold-query-value", "FinalPolyMismatch"),
                              ("last-fold-auth-sibling", "CommitPhaseMmcsError(CapMismatch)")]:
            label = component + "-" + mode
            case = output / label
            case.mkdir()
            changed = component + ".proof.bin"
            for name in RETAINED:
                if name != changed:
                    os.link(proofs / name, case / name)
            mutation = execute("mutate-" + label, [mutator, mode, proofs / changed, case / changed], output, True)
            m = mutation["final"]
            if (m["status"] != "MUTATED_RESEARCH_PROOF_ONLY" or
                    m["transcript_fields_unchanged"] is not True or
                    m["proof_bytes_before"] != m["proof_bytes_after"] or
                    m["changed_byte_count"] <= 0 or
                    m["proof_sha256_before"] != RETAINED[changed] or
                    m["proof_sha256_after"] != sha((case / changed).read_bytes())):
                raise RuntimeError("typed mutation contract failed")
            obs = execute(label, [binary, "verify", case / "statement.bin", header, artifacts, case], output, False)
            error = (obs["final"] or {}).get("error", "")
            prefix = "sha proof rejected:" if component == "sha" else "arithmetic proof rejected:"
            phase = "sha_stark_verify" if component == "sha" else "arith_stark_verify"
            if (not error.startswith(prefix) or subtype not in error or "SiblingCountMismatch" in error or
                    phase not in {e["phase"] for e in obs["phase_events"]}):
                raise RuntimeError(label + ": wrong late rejection frontier: " + error)
            late.append({"label": label, "expected_subtype": subtype, "mutation": mutation, "observation": obs})
    after = {str(p): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in paths}
    save(output / "source-after.json", after)
    if before != after or any(sha((proofs / n).read_bytes()) != h for n, h in RETAINED.items()):
        raise RuntimeError("source, binary or historical proof changed")
    summary = {
        "schema": "trnm-w1-successor-controls-summary-v1", "qualification": "HOLD_NO_GO",
        "positive_count": 1, "ordinary_count": len(ordinary), "late_count": len(late),
        "positive": positive, "ordinary": ordinary, "late": late,
        "new_proofs_generated": 0, "source_before_after_equal": True,
        "global_malicious_rejection_cost_bound": False, "production_node_admission": False,
    }
    save(output / "summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k not in ["positive", "ordinary", "late"]}), flush=True)


if __name__ == "__main__":
    main()
