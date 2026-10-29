#!/usr/bin/env python3
"""Check actual backend observations; never replace a failed or absent proof."""
import argparse
import hashlib
import json
import math
from pathlib import Path


UNSUPPORTED_AUTHORITY_FLAGS = frozenset({
    "pq128_qualified", "pq_128_security_qualified", "public_ingress_qualified",
    "consensus_authority", "consensus_activation", "production_activation",
    "production_consensus_activation", "physical_quantum_oracle_measured",
    "quantum_cost_bound", "fake_receipts_allowed", "groth16_receipts_allowed",
    "remote_proving_allowed",
})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def scope_flags(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in UNSUPPORTED_AUTHORITY_FLAGS:
                require(item is False, "unsupported research authority " + key)
            scope_flags(item)
    elif isinstance(value, list):
        for item in value:
            scope_flags(item)


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key " + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError("noncanonical JSON constant " + value)

    def floating(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number

    value = json.loads(path.read_text(), object_pairs_hook=unique, parse_constant=constant,
                       parse_float=floating)
    scope_flags(value)
    return value


def validate_manifest(observed):
    # The same source manifest is compiled into the native host and read by the
    # installer/build driver. The artifact copy is not an independent authority
    # for its image, algorithm, security parameters or source/compiler hashes.
    pinned = load(Path(__file__).with_name("backend-manifest.json"))
    require(type(observed) is dict, "backend manifest must be an object")
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    # JSON encoding retains false versus 0 and integers versus floats, unlike
    # Python container equality. Formatting and object-key order are immaterial.
    require(canonical(observed) == canonical(pinned),
            "backend manifest differs from checker source")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    out = args.out
    manifest = load(out / "backend-manifest.json")
    validate_manifest(manifest)
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
        require(type(process["returncode"]) is int and process["returncode"] == 0
                and process["timed_out"] is False, f"failed actual {name}")
    native, executed, proved, verified, audited = (observations[name] for name in observations)
    require(executed["guest_matches_native"] is True, "guest/native execution mismatch")
    require(executed["image_id"] == manifest["guest_image_id"], "execution image mismatch")
    require(native["journal_hex"] == executed["journal_hex"], "actual guest journal differs from M01 native oracle")
    for value in [proved, verified]:
        require(value["real_composite_stark_verified"] is True, "missing real proof verification")
        require(value["image_id"] == manifest["guest_image_id"], "proof image mismatch")
        require(value["statement_id"] == native["statement_id"], "proof statement mismatch")
    require(verified["native_w1_recomputed"] is False, "verifier silently recomputed W1")
    require(audited["real_proof_positive_control"] is True, "adversarial tests lack real positive proof")
    expected_cases = {"wrong_image", "wrong_statement_miner", "truncated_receipt",
                      "first_seal_tamper", "last_seal_tamper", "wrong_hash_profile",
                      "wrong_verifier_parameters", "fake_receipt_refused", "groth16_kind_refused",
                      "segment_count_allocation_bomb", "seal_length_allocation_bomb",
                      "empty_seal_before_sdk", "outer_journal_allocation_bomb",
                      "nested_assumptions_refused", "seal_dimension_budget", "trailing_receipt_bytes"}
    cases = audited["negative_cases"]
    require({case["case"] for case in cases} == expected_cases, "missing or duplicate negative controls")
    require(len(cases) == len(expected_cases) and all(case["rejected"] is True for case in cases), "accepted adversarial control")
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
