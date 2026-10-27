#!/usr/bin/env python3
"""Read actual proof observations; separate measurements from bandwidth models.

The sole security-model report is the pinned upstream Rust f32 calculator
already run by soundness_report.py and bound to this actual verified receipt.
This readback adds no second calculator, security proof or quantum-bit estimate.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from observations import read_single_result

HERE = Path(__file__).resolve().parent


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    require(path.stat().st_size <= 8 * 1024**2, "observation JSON exceeds cap")
    return json.loads(path.read_text())


def analyze(out):
    verified = read_single_result(out / "verify.stdout.log", "pon-w1-risc0-research-v1", "verify")
    audited = read_single_result(out / "audit.stdout.log", "pon-w1-risc0-research-v1", "audit")
    native = read_single_result(out / "native-benchmark.stdout.log", "pon-w1-native-fixed-input-cost-v1")
    checked = read(out / "checked-observation.json")
    soundness = read(out / "soundness/soundness-observation.json")
    sources = read(HERE / "backend-source-review.json")
    require(verified["real_composite_stark_verified"] is True, "no actual positive receipt")
    require(verified["native_w1_recomputed"] is False, "verifier recomputed W1")
    require(audited["real_proof_positive_control"] is True, "negative receipt tests lack positive proof")
    require(native["statement_id"] == verified["statement_id"], "different native/proof statements")
    receipt = out / "receipt.bin"
    require(receipt.stat().st_size == verified["receipt_bytes"], "receipt byte count mismatch")
    receipt_sha256 = hashlib.sha256(receipt.read_bytes()).hexdigest()
    require(checked["real_proof_verified"] is True and checked["receipt_sha256"] == receipt_sha256,
            "full current observation checks did not authenticate this receipt")
    require(soundness["model_input_kind"] == "receipt_metadata"
            and soundness["receipt_sha256"] == receipt_sha256
            and soundness["upstream_rust_formulas_executed_verbatim"] is True
            and soundness["source_commit"] == "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9"
            and soundness["pq128_qualified"] is False,
            "missing pinned original calculator observation for this receipt")
    require(checked["soundness_formula_observation"] == soundness,
            "calculator report changed after full observation checks")
    processes = {}
    for name in ["verify", "audit"]:
        process = read(out / f"{name}.process.json")
        require(process["schema"] == "pon-w1-actual-process-v2", "current terminal observations required")
        require(process["returncode"] == process["child_returncode"] == 0
                and process["child_reaped"] is True and process["timed_out"] is False
                and process["owned_process_group_empty"] is True
                and process["subreaper_enabled"] is True
                and process["leader_exited_before_group"] is False
                and not process["cleanup_errors"], f"actual {name} did not succeed")
        processes[name] = process
    segments = verified["verified_segment_profile"]
    require(0 < len(segments) <= 2048, "actual segment profile is missing")
    histogram = Counter()
    for index, segment in enumerate(segments):
        require(segment["index"] == index and segment["hashfn"] == "poseidon2",
                "unexpected verified segment order/hash")
        require(segment["padded_cycles"] == 2**segment["po2"], "inconsistent actual dimension")
        histogram[str(segment["po2"])] += 1
    require(dict(histogram) == soundness["actual_segment_po2_histogram"],
            "calculator dimensions differ from the cryptographically verified segment profile")
    cases = audited["negative_cases"]
    require(cases and all(case["rejected"] is True and type(case["reject_process_cpu_ns"]) is int
                         and case["reject_process_cpu_ns"] >= 0 for case in cases),
            "missing actual invalid-receipt CPU observations")
    native_name, fastest = min(native["kernels"].items(), key=lambda item: item[1]["median_wall_ns"])
    require(native["samples_per_kernel"] == 31 and fastest["median_wall_ns"] > 0,
            "original native benchmark is incomplete")
    payload = verified["receipt_bytes"]
    slow_wall = max(cases, key=lambda case: case["reject_wall_ns"])
    slow_cpu = max(cases, key=lambda case: case["reject_process_cpu_ns"])
    return {"schema": "pon-w1-real-proof-cost-readback-v1",
        "receipt_sha256": receipt_sha256,
        "receipt_bytes": payload, "native_pnw1_bytes": 49188,
        "proof_to_native_witness_bytes_ratio": payload / 49188,
        "native_fixed_input": native, "fastest_measured_native_median_kernel": native_name,
        "verify_wall_ns": verified["verify_wall_ns"],
        "verify_process_cpu_ns": verified["verify_process_cpu_ns"],
        "verify_to_fastest_native_median_wall_ratio": verified["verify_wall_ns"] / fastest["median_wall_ns"],
        "slowest_tested_invalid_receipt_by_wall": slow_wall,
        "slowest_tested_invalid_receipt_by_cpu": slow_cpu,
        "slowest_reject_to_fastest_native_median_wall_ratio": slow_wall["reject_wall_ns"] / fastest["median_wall_ns"],
        "processes": processes, "verified_segments": segments,
        "upstream_security_descriptions": sources["upstream_descriptions"],
        "upstream_soundness_formula_observation": soundness,
        "security_model_scope": "the one pinned upstream f32 calculator report, bound to this authenticated receipt; numerical conditional union estimates do not prove composed Fiat-Shamir, hash, QROM or work-cost security",
        "aggregate_quantum_security_bits": None,
        "bandwidth_serialization_models": [
            {"link_mbit_per_second": rate, "payload_only_seconds": 8 * payload / (rate * 1_000_000),
             "measured_network": False, "scope": "payload serialization lower bound only; excludes protocol overhead, latency, loss, verification and gossip fanout"}
            for rate in [1, 10, 100, 1000]],
        "scope": "one fixed synthetic-context full N64/R8 input on the observed host; shared-host timings and finite corruptions, not a global minimum, public service or WAN throughput",
        "work_hardness_qualified": False, "public_ingress_qualified": False,
        "pq128_qualified": False, "consensus_activation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.out)
    with (args.out / "proof-cost-readback.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"proof_cost_readback_written": True, "public_ingress_qualified": False}))


if __name__ == "__main__":
    main()
