"""Actual full-proof acceptance for the explicitly continued session.

Retains the original native/guest/benchmark and 17 adversarial gates, while
requiring a real assembly observation instead of inventing a prove process.
"""
from observations import read_single_result
import segment_continue_source as source

EXPECTED_CASES = {"wrong_image", "wrong_statement_miner", "truncated_receipt",
    "first_seal_tamper", "last_seal_tamper", "last_seal_tamper_wire", "wrong_hash_profile",
    "wrong_verifier_parameters", "fake_receipt_refused", "groth16_kind_refused",
    "segment_count_allocation_bomb", "seal_length_allocation_bomb", "empty_seal_before_sdk",
    "outer_journal_allocation_bomb", "nested_assumptions_refused", "seal_dimension_budget",
    "trailing_receipt_bytes"}
require = source.require


def phase(out, name, current_source):
    value = source.read(out / f"{name}.process.json", 2 * 1024 * 1024)
    source.require_closed_phase(value, True)
    require(value["schema"] == "pon-w1-actual-process-v2"
            and value["child_returncode"] == 0 and value["subreaper_enabled"] is True
            and value["leader_exited_before_group"] is False
            and not value["cleanup_errors"] and value["source_sha"] == current_source,
            f"{name} is missing its actual source/terminal/cleanup fact")
    return value


def validate(out, assembled, current_source):
    manifest = source.read(out / "backend-manifest.json")
    for name, key in [("guest.raw.elf", "guest_raw_elf_sha256"), ("guest.bin", "guest_program_sha256")]:
        require(source.sha(source.checked_bytes(out / name, 64 * 1024 * 1024)) == manifest[key],
                "fresh guest image differs")
    bake = read_single_result(out / "bake.stdout.log", "pon-w1-risc0-research-v1", "bake")
    phase(out, "bake", current_source)
    require(bake["image_id"] == manifest["guest_image_id"], "bake image differs")
    require(len(source.checked_bytes(out / "input.bin", 49640)) == 49640, "full W1 input dimensions differ")
    observations = {}
    for name, schema, operation in [
        ("native-execute", "pon-w1-local-relation-v1", "execute"),
        ("native-benchmark", "pon-w1-native-fixed-input-cost-v1", None),
        *[(name, "pon-w1-risc0-research-v1", name) for name in ["execute", "verify", "audit"]],
    ]:
        observations[name] = read_single_result(out / f"{name}.stdout.log", schema, operation)
        phase(out, name, current_source)
    native, benchmark, executed, verified, audited = (observations[name] for name in
        ["native-execute", "native-benchmark", "execute", "verify", "audit"])
    require(executed["guest_matches_native"] is True
            and executed["image_id"] == manifest["guest_image_id"]
            and native["journal_hex"] == executed["journal_hex"], "actual native/guest full W1 mismatch")
    require(benchmark["statement_id"] == native["statement_id"] and benchmark["debug_assertions"] is False
            and benchmark["samples_per_kernel"] == 31, "native benchmark profile changed")
    kernels = benchmark["kernels"]
    require(set(kernels) == {"native_production", "native_scalar_reference", "native_limb", "complete_relation"},
            "missing native comparison kernels")
    for name, kernel in kernels.items():
        samples = kernel["samples_wall_ns"]
        require(len(samples) == 31 and all(type(v) is int and v > 0 for v in samples), "invalid benchmark samples")
        ordered = sorted(samples)
        require([kernel[key] for key in ["min_wall_ns", "median_wall_ns", "max_wall_ns"]]
                == [ordered[0], ordered[15], ordered[30]], f"incorrect benchmark summary: {name}")
    for value in [assembled, verified]:
        require(value["real_composite_stark_verified"] is True
                and value["image_id"] == manifest["guest_image_id"]
                and value["statement_id"] == native["statement_id"], "full real proof binding missing")
    require(verified["native_w1_recomputed"] is False, "verification was replaced with replay")
    require(audited["real_proof_positive_control"] is True, "invalid-input audit has no real positive control")
    cases = audited["negative_cases"]
    require(len(cases) == len(EXPECTED_CASES)
            and {case["case"] for case in cases} == EXPECTED_CASES
            and all(case["rejected"] is True for case in cases), "missing/duplicate/accepted adversarial case")
    for case in cases:
        for key in ["reject_process_cpu_ns", "reject_wall_ns"]:
            require(type(case[key]) is int and case[key] >= 0, "missing actual negative-input cost")
    for case, error in [("correct-product-false-trace", "Work(Transcript)"),
                        ("correct-trace-wrong-product", "Work(Product)")]:
        prepared = read_single_result(out / f"prepare-{case}.stdout.log", "pon-w1-guest-negative-v1", "make-invalid")
        phase(out, f"prepare-{case}", current_source)
        rejected = read_single_result(out / f"guest-{case}.stdout.log", "pon-w1-guest-negative-v1", "reject-input")
        require(prepared["native_late_failure_checked"] is True
                and prepared["witness_commitment_rebound"] is True and prepared["expected_error"] == error,
                "native negative did not reach the same late failure")
        require(rejected["guest_executed"] is True and rejected["exact_guest_relation_rejection"] is True
                and rejected["native_w1_recomputed"] is False and rejected["expected_error"] == error
                and rejected["cryptographic_proof_generated"] is False, "real guest negative was substituted")
        phase(out, f"guest-{case}", current_source)
    encoded = source.checked_bytes(out / "receipt.bin", 128 * 1024 * 1024)
    require(len(encoded) == assembled["receipt_bytes"] == verified["receipt_bytes"], "full receipt length differs")
    soundness = source.read(out / "soundness/soundness-observation.json")
    require(soundness["model_input_kind"] == "receipt_metadata"
            and soundness["receipt_sha256"] == source.sha(encoded)
            and sum(soundness["actual_segment_po2_histogram"].values()) == assembled["segments"] == 62,
            "conditional soundness model evaluated a different/incomplete receipt")
    native_median = kernels["native_production"]["median_wall_ns"]
    return {"native_and_guest_journal_match": True, "verified": verified, "audit": audited,
        "negative_cases": len(cases), "native_benchmark": benchmark,
        "conditional_soundness": soundness,
        "maximum_tested_reject_wall_ns": max(case["reject_wall_ns"] for case in cases),
        "maximum_tested_reject_process_cpu_ns": max(case["reject_process_cpu_ns"] for case in cases),
        "verify_to_native_production_median_ratio": verified["verify_wall_ns"] / native_median,
        "last_seal_reject_to_native_production_median_ratio":
            next(case["reject_wall_ns"] for case in cases if case["case"] == "last_seal_tamper") / native_median,
        "global_worst_invalid_input_proven": False, "production_throughput_measured": False}
