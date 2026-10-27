#!/usr/bin/env python3
"""Check actual backend observations; never replace a failed or absent proof."""
import argparse
import hashlib
import json
from pathlib import Path


def load(path):
    return json.loads(path.read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    out = args.out
    manifest = load(out / "backend-manifest.json")
    for filename, key in [("guest.raw.elf", "guest_raw_elf_sha256"),
                          ("guest.bin", "guest_program_sha256")]:
        actual = hashlib.sha256((out / filename).read_bytes()).hexdigest()
        require(actual == manifest[key], f"unreviewed or non-reproducible {filename}: {actual}")
    bake = load(out / "bake.stdout.log")
    require(bake["image_id"] == manifest["guest_image_id"], "unreviewed actual guest image")
    require((out / "input.bin").stat().st_size == 49640, "incorrect fixed W1 input length")
    if args.build_only:
        print(json.dumps({"build_identity_checked": True, "proof_checked": False}))
        return
    observations = {name: load(out / f"{name}.stdout.log")
                    for name in ["native-execute", "execute", "prove", "verify", "audit"]}
    processes = {name: load(out / f"{name}.process.json") for name in observations}
    for name, process in processes.items():
        require(process["returncode"] == 0 and not process["timed_out"], f"failed actual {name}")
    native, executed, proved, verified, audited = (observations[name] for name in observations)
    require(executed["guest_matches_native"], "guest/native execution mismatch")
    require(native["journal_hex"] == executed["journal_hex"], "actual guest journal differs from M01 native oracle")
    for value in [proved, verified]:
        require(value["real_composite_stark_verified"], "missing real proof verification")
        require(value["image_id"] == manifest["guest_image_id"], "proof image mismatch")
        require(value["statement_id"] == native["statement_id"], "proof statement mismatch")
    require(verified["native_w1_recomputed"] is False, "verifier silently recomputed W1")
    require(audited["real_proof_positive_control"], "adversarial tests lack real positive proof")
    expected_cases = {"wrong_image", "wrong_statement_miner", "truncated_receipt",
                      "first_seal_tamper", "last_seal_tamper", "wrong_hash_profile",
                      "wrong_verifier_parameters", "fake_receipt_refused", "groth16_kind_refused",
                      "segment_count_allocation_bomb", "seal_length_allocation_bomb",
                      "empty_seal_before_sdk", "outer_journal_allocation_bomb",
                      "nested_assumptions_refused", "seal_dimension_budget", "trailing_receipt_bytes"}
    cases = audited["negative_cases"]
    require({case["case"] for case in cases} == expected_cases, "missing or duplicate negative controls")
    require(len(cases) == len(expected_cases) and all(case["rejected"] for case in cases), "accepted adversarial control")
    receipt = out / "receipt.bin"
    require(receipt.stat().st_size == proved["receipt_bytes"] == verified["receipt_bytes"], "proof byte count mismatch")
    result = {"schema": "pon-complete-w1-actual-proof-observation-v1",
              "backend_manifest": manifest, "observations": observations,
              "processes": processes, "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
              "full_work_profile_preserved": True, "real_proof_verified": True,
              "maximum_tested_reject_wall_ns": max(case["reject_wall_ns"] for case in cases),
              "native_complete_replay_wall_ns": native["elapsed_wall_ns"],
              "public_ingress_qualified": False, "pq128_qualified": False,
              "consensus_activation": False,
              "limits": ["one research fixture and finite adversarial controls",
                         "98-bit classical conjectured backend claim, not a quantum-bit estimate",
                         "quantum Fiat-Shamir, Poseidon2, Merkle, FRI and multi-target analysis remain separate",
                         "CPU/wall samples under this runner load are observations, not throughput or service guarantees"]}
    (out / "checked-observation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"real_proof_verified": True, "negative_controls": len(cases),
                      "public_ingress_qualified": False, "pq128_qualified": False}))


if __name__ == "__main__":
    main()
