#!/usr/bin/env python3
"""Check actual backend observations; never replace a failed or absent proof."""
import argparse
import hashlib
import json
from pathlib import Path

from observations import read_single_result


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
    bake = read_single_result(out / "bake.stdout.log", "pon-w1-risc0-research-v1", "bake")
    require(bake["image_id"] == manifest["guest_image_id"], "unreviewed actual guest image")
    require((out / "input.bin").stat().st_size == 49640, "incorrect fixed W1 input length")
    if args.build_only:
        print(json.dumps({"build_identity_checked": True, "proof_checked": False}))
        return
    reuse_path = out / "receipt-reuse-observation.json"
    reuse = load(reuse_path) if reuse_path.exists() else None
    current_source = load(out / "source-before.json")["tested_commit"]
    proof_dir = out / "prior-proof" if reuse else out
    observations = {}
    for name, schema, operation in [
        ("native-execute", "pon-w1-local-relation-v1", "execute"),
        ("native-benchmark", "pon-w1-native-fixed-input-cost-v1", None),
        *[(name, "pon-w1-risc0-research-v1", name)
          for name in ["execute", "prove", "verify", "audit"]],
    ]:
        directory = proof_dir if name == "prove" else out
        observations[name] = read_single_result(directory / f"{name}.stdout.log", schema, operation)
    processes = {name: load((proof_dir if name == "prove" else out) / f"{name}.process.json")
                 for name in observations}
    for name, process in processes.items():
        require(process["returncode"] == 0 and not process["timed_out"], f"failed actual {name}")
        if name == "prove" and reuse:
            require(process["source_sha"] == reuse["policy"]["source_commit"], "prior prove source mismatch")
            require(reuse["proof_generated_in_current_run"] is False
                    and reuse["required_acceptance_waived"] is False
                    and reuse["new_guest_raw_elf_and_program_and_input_identical"] is True,
                    "unsupported reuse observation")
            require(reuse["current_source_sha"] == current_source, "reuse caller source mismatch")
        else:
            require(process["schema"] == "pon-w1-actual-process-v2"
                    and process["child_returncode"] == 0 and process["child_reaped"] is True
                    and process["owned_process_group_empty"] is True
                    and process["subreaper_enabled"] is True
                    and process["leader_exited_before_group"] is False
                    and not process["cleanup_errors"] and process["source_sha"] == current_source,
                    f"current {name} lacks its genuine terminal/source observation")
    native, benchmark, executed, proved, verified, audited = (
        observations[name] for name in
        ["native-execute", "native-benchmark", "execute", "prove", "verify", "audit"])
    require(executed["guest_matches_native"], "guest/native execution mismatch")
    require(executed["image_id"] == manifest["guest_image_id"], "execution image mismatch")
    require(native["journal_hex"] == executed["journal_hex"], "actual guest journal differs from M01 native oracle")
    require(benchmark["statement_id"] == native["statement_id"], "native benchmark statement mismatch")
    require(benchmark["debug_assertions"] is False, "native cost must use the release build")
    require(benchmark["samples_per_kernel"] == 31, "missing native samples")
    kernels = benchmark["kernels"]
    require(set(kernels) == {"native_production", "native_scalar_reference", "native_limb", "complete_relation"},
            "missing native comparison kernels")
    for name, kernel in kernels.items():
        samples = kernel["samples_wall_ns"]
        require(len(samples) == 31 and all(type(value) is int and value > 0 for value in samples),
                f"invalid actual samples: {name}")
        ordered = sorted(samples)
        require([kernel[key] for key in ["min_wall_ns", "median_wall_ns", "max_wall_ns"]]
                == [ordered[0], ordered[15], ordered[30]], f"incorrect sample summary: {name}")
    for value in [proved, verified]:
        require(value["real_composite_stark_verified"], "missing real proof verification")
        require(value["image_id"] == manifest["guest_image_id"], "proof image mismatch")
        require(value["statement_id"] == native["statement_id"], "proof statement mismatch")
    require(verified["native_w1_recomputed"] is False, "verifier silently recomputed W1")
    require(audited["real_proof_positive_control"], "adversarial tests lack real positive proof")
    expected_cases = {"wrong_image", "wrong_statement_miner", "truncated_receipt",
                      "first_seal_tamper", "last_seal_tamper", "last_seal_tamper_wire", "wrong_hash_profile",
                      "wrong_verifier_parameters", "fake_receipt_refused", "groth16_kind_refused",
                      "segment_count_allocation_bomb", "seal_length_allocation_bomb",
                      "empty_seal_before_sdk", "outer_journal_allocation_bomb",
                      "nested_assumptions_refused", "seal_dimension_budget", "trailing_receipt_bytes"}
    cases = audited["negative_cases"]
    require({case["case"] for case in cases} == expected_cases, "missing or duplicate negative controls")
    require(len(cases) == len(expected_cases) and all(case["rejected"] for case in cases), "accepted adversarial control")
    require(all(type(case["reject_process_cpu_ns"]) is int and case["reject_process_cpu_ns"] >= 0
                for case in cases), "missing actual verifier CPU observations")
    guest_negatives = []
    for case, error in [("correct-product-false-trace", "Work(Transcript)"),
                        ("correct-trace-wrong-product", "Work(Product)")]:
        prepared = read_single_result(out / f"prepare-{case}.stdout.log",
                                      "pon-w1-guest-negative-v1", "make-invalid")
        rejected = read_single_result(out / f"guest-{case}.stdout.log",
                                      "pon-w1-guest-negative-v1", "reject-input")
        actual_process = load(out / f"guest-{case}.process.json")
        require(prepared["native_late_failure_checked"] is True
                and prepared["witness_commitment_rebound"] is True
                and prepared["expected_error"] == error, "native negative did not reach its late failure")
        require(rejected["guest_executed"] is True
                and rejected["exact_guest_relation_rejection"] is True
                and rejected["native_w1_recomputed"] is False
                and rejected["expected_error"] == error
                and rejected["cryptographic_proof_generated"] is False,
                "native rejection or invalid-proof rejection was substituted for real guest execution")
        require(actual_process["schema"] == "pon-w1-actual-process-v2"
                and actual_process["returncode"] == actual_process["child_returncode"] == 0
                and actual_process["child_reaped"] is True and not actual_process["timed_out"]
                and actual_process["owned_process_group_empty"] is True
                and actual_process["subreaper_enabled"] is True
                and actual_process["leader_exited_before_group"] is False
                and not actual_process["cleanup_errors"] and actual_process["source_sha"] == current_source,
                "guest negative did not complete under the current process/source boundary")
        guest_negatives.append({"case": case, "native_preparation": prepared,
                                "guest": rejected, "process": actual_process})
    receipt = out / "receipt.bin"
    require(receipt.stat().st_size == proved["receipt_bytes"] == verified["receipt_bytes"], "proof byte count mismatch")
    receipt_sha256 = hashlib.sha256(receipt.read_bytes()).hexdigest()
    soundness = load(out / "soundness/soundness-observation.json")
    require(soundness["model_input_kind"] == "receipt_metadata", "execution-only estimates do not qualify a receipt report")
    require(soundness["receipt_sha256"] == receipt_sha256, "calculator evaluated a different certificate")
    require(sum(soundness["actual_segment_po2_histogram"].values()) == proved["segments"], "calculator segment count mismatch")
    late_reject_ns = next(case["reject_wall_ns"] for case in cases if case["case"] == "last_seal_tamper")
    native_median_ns = kernels["native_production"]["median_wall_ns"]
    result = {"schema": "pon-complete-w1-actual-proof-observation-v2",
              "backend_manifest": manifest, "observations": observations,
              "processes": processes, "receipt_sha256": receipt_sha256,
              "input_sha256": hashlib.sha256((out / "input.bin").read_bytes()).hexdigest(),
              "soundness_formula_observation": soundness,
              "full_work_profile_preserved": True, "real_proof_verified": True,
              "current_source_sha": current_source, "receipt_reuse": reuse,
              "proof_generated_in_current_run": reuse is None,
              "proof_generation_cost_is_current_runner_measurement": reuse is None,
              "guest_negative_observations": guest_negatives,
              "maximum_tested_reject_wall_ns": max(case["reject_wall_ns"] for case in cases),
              "maximum_tested_reject_process_cpu_ns": max(case["reject_process_cpu_ns"] for case in cases),
              "native_complete_replay_wall_ns": native["elapsed_wall_ns"],
              "proof_verify_to_native_production_median_ratio": verified["verify_wall_ns"] / native_median_ns,
              "last_seal_reject_to_native_production_median_ratio": late_reject_ns / native_median_ns,
              "public_ingress_qualified": False, "pq128_qualified": False,
              "consensus_activation": False,
              "limits": ["one research fixture and finite adversarial controls",
                         "upstream 96/97/98 descriptions have different scopes; actual conditional model values are separate",
                         "upstream f32 calculator and a conditional segment union bound are not a complete security proof",
                         "quantum Fiat-Shamir, Poseidon2, Merkle, FRI and multi-target analysis remain separate",
                         "CPU/wall samples under this runner load are observations, not throughput or service guarantees"]}
    (out / "checked-observation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"real_proof_verified": True, "negative_controls": len(cases),
                      "public_ingress_qualified": False, "pq128_qualified": False}))


if __name__ == "__main__":
    main()
