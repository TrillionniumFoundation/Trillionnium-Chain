#!/usr/bin/env python3
"""Externally pinned complete scalar replay of the task-product verifier study.

Matched ratios concern observed verifier-call wall time, with instrumentation.
This does not attest a host, allocate whole-command CPU to arms, or establish a
minimum mining cost, ordinary Node throughput, useful model change or release.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from contract_wire import H
import work_oracle as oracle
from read_w1_cost_research import bundle_file, exact, hx, require, uint64, validate_child_resources
from read_w1_compact_miner_research import reader_tree_snapshot, same_json, source_objects
from run_w1_compact_miner_research import decode, usage_snapshot
from run_w1_task_product_research import BINARY, OUTPUT_LIMIT, SCHEMA, sha, validate_plan

RAW_SCHEMA = "pon-w1-task-product-facts-research-v1"
FAMILIES = ("zero", "identity", "rank1", "sparse", "near_q", "dense")
TARGET = bytes([255]) * 32
SETUP = ("preflight", "rustc-version", "cargo-version", "metadata", "build")
OBSERVATION_SCOPE = (
    "whole native verifier study including proof generation, reference checks, "
    "all arms, controls, output and teardown; not per-arm CPU")


def material(seed, family):
    """Registered source inputs; rank1 names the left matrix only."""
    a, b = [], []
    for i in range(64):
        for j in range(64):
            k = 64 * i + j
            if family == "zero":
                x, y = 0, 0
            elif family == "identity":
                x, y = int(i == j), int(i == j)
            elif family == "rank1":
                x, y = (i + 1) * (j + 3), (7 * i + 11 * j) % 37
            elif family == "sparse":
                x, y = (oracle.Q - 1 if k % 19 == 0 else 0), (oracle.Q - 2 if k % 23 == 0 else 0)
            elif family == "near_q":
                x, y = oracle.Q - 1, oracle.Q - 2
            elif family == "dense":
                raw = H("task-product-facts-material-v1", struct.pack("<Q", seed), struct.pack("<Q", k))
                x, y = (v % oracle.Q for v in struct.unpack("<II", raw[:8]))
            else:
                raise ValueError("UNREGISTERED_FAMILY")
            a.append(x)
            b.append(y)
    return a, b


def schedule():
    return [("main-" + family, [family] * 4, 2, [False, True, True, True]) for family in FAMILIES] + [
        ("eviction", ["zero", "identity", "zero", "zero"], 1, [False, False, False, True])]


def fraction(numerator, denominator):
    if denominator == 0:
        return None
    value = Fraction(numerator, denominator)
    return dict(numerator=value.numerator, denominator=value.denominator, decimal=float(value))


def noise_calls(challenge):
    total = 0
    for label in range(4):
        count = 0
        for counter in range(128):
            raw = H("noise", challenge, bytes([label]), struct.pack("<I", counter))
            count += sum(v < oracle.Q for (v,) in struct.iter_unpack("<I", raw))
            total += 1
            if count >= 512:
                break
        else:
            raise ValueError("NOISE_BUDGET")
    return total


def verify_case(row, seed, group, family, ordinal):
    exact(row, ("type", "id", "group", "family", "ordinal", "challenge", "task", "target",
                "proof_hex", "proof_sha256", "material_wall_ns", "prove_wall_ns", "reference_wall_ns"),
          "CASE_FIELDS")
    require(row["type"] == "case" and row["id"] == f"{group}-{ordinal}" and row["group"] == group
            and row["family"] == family and type(row["ordinal"]) is int and row["ordinal"] == ordinal,
            "CASE_IDENTITY")
    for key in ("material_wall_ns", "prove_wall_ns", "reference_wall_ns"):
        uint64(row[key], "CASE_TIME")
    a, b = material(seed, family)
    task = oracle.task_id(a, b)
    challenge = H("task-product-facts-challenge-v1", struct.pack("<Q", seed), group.encode(),
                  struct.pack("<Q", ordinal), task)
    require(hx(row["challenge"], 32, "CHALLENGE") == challenge and
            hx(row["task"], 32, "TASK") == task and hx(row["target"], 32, "TARGET") == TARGET,
            "REGISTERED_STATEMENT")
    proof = hx(row["proof_hex"], oracle.PROOF_BYTES, "PROOF")
    require(sha_bytes(proof) == row["proof_sha256"], "PROOF_HASH")
    require(proof[:4] == b"PNW1" and proof[4:4 + 8 * oracle.CELLS] ==
            oracle.field_bytes(a) + oracle.field_bytes(b), "REGISTERED_MATERIAL")
    ticket, product = oracle.verify(challenge, task, TARGET, proof)
    return dict(id=row["id"], group=group, family=family, ordinal=ordinal,
                challenge=challenge.hex(), task=task.hex(), proof_sha256=row["proof_sha256"],
                ticket=ticket.hex(), product_sha256=sha_bytes(oracle.field_bytes(product)),
                noise_calls=noise_calls(challenge),
                material_wall_ns=row["material_wall_ns"], prove_wall_ns=row["prove_wall_ns"],
                reference_wall_ns=row["reference_wall_ns"])


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def verify_call(row, case, arm, order, warm, capacity):
    exact(row, ("type", "case_id", "arm", "order", "wall_ns", "ticket", "product_sha256",
                "progress", "observation"), "VERIFY_FIELDS")
    require(row["type"] == "verify" and row["case_id"] == case["id"] and row["arm"] == arm
            and type(row["order"]) is int and row["order"] == order, "VERIFY_ORDER")
    uint64(row["wall_ns"], "VERIFY_WALL")
    require(row["ticket"] == case["ticket"] and row["product_sha256"] == case["product_sha256"],
            "VERIFIED_OUTPUT")
    reused = arm == "facts" and warm
    progress = dict(before_replay=1, noise=case["noise_calls"], matrix_rows_before_product=128,
                    transcript_tiles=512, before_product=1,
                    matrix_rows_after_product=0 if reused else 200, before_verified_work=1)
    require(same_json(row["progress"], progress), "COMPLETE_FRESH_TRANSCRIPT")
    if arm == "raw":
        require(row["observation"] is None, "RAW_HAS_NO_CACHE")
    else:
        observed = row["observation"]
        expected = dict(lookup_probes=1 if warm else capacity, lookup_contended=False,
                        exact_inputs_found=warm, product_reused=warm, transcript_entered=True,
                        transcript_completed=True, product_reconstruction_entered=not warm,
                        product_reconstruction_completed=not warm,
                        publication_probes=0 if warm else capacity,
                        publication="none" if warm else "stored")
        require(same_json(observed, expected), "EXACT_CACHE_PATH")
    return dict(arm=arm, order=order, wall_ns=row["wall_ns"], product_reused=reused,
                progress=row["progress"], observation=row["observation"])


def read_raw(path, seed):
    require(type(seed) is int and seed in (8101, 8102), "REGISTERED_SEED")
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= OUTPUT_LIMIT,
            "RAW_SIZE")
    raw = path.read_bytes()
    lines = raw.splitlines()
    require(raw.endswith(b"\n") and len(lines) == 100 and all(0 < len(v) <= 128 * 1024 for v in lines),
            "COMPLETE_ROW_SET")
    rows = iter(decode(line) for line in lines)
    start = next(rows)
    expected_start = dict(type="start", schema=RAW_SCHEMA, seed=seed,
                          profile="pon-matmul-transcript-64-v1", target=TARGET.hex(), proof_bytes=49188,
                          timing_scope="Instant-wall-per-operation-not-process-CPU",
                          reference_before_measurement=True,
                          whole_process_includes_material_proof_reference_output=True,
                          source_claim=False, production_activation=False, mining_opportunity_claim=False)
    require(same_json(start, expected_start), "START_CONTRACT")
    cases, groups = [], []
    arms = ("raw", "facts") if seed == 8101 else ("facts", "raw")
    for group, families, capacity, hits in schedule():
        opened = exact(next(rows), ("type", "group", "families", "cache_capacity", "cache_software_bytes",
                                   "cache_create_wall_ns"), "GROUP_FIELDS")
        require(opened["type"] == "group" and opened["group"] == group and
                same_json(opened["families"], families) and type(opened["cache_capacity"]) is int
                and opened["cache_capacity"] == capacity, "GROUP_IDENTITY")
        uint64(opened["cache_create_wall_ns"], "CACHE_CREATE_WALL")
        uint64(opened["cache_software_bytes"], "CACHE_STORAGE", capacity * 3 * 4096 * 4, 4 * 1024 * 1024)
        for ordinal, (family, warm) in enumerate(zip(families, hits)):
            case = verify_case(next(rows), seed, group, family, ordinal)
            case["warm"] = warm
            case["calls"] = [verify_call(next(rows), case, arm, order, warm, capacity)
                             for order, arm in enumerate(arms)]
            calls = {c["arm"]: c for c in case["calls"]}
            case["raw_over_facts_wall_ratio"] = fraction(calls["raw"]["wall_ns"], calls["facts"]["wall_ns"])
            cases.append(case)
        closed = exact(next(rows), ("type", "group", "cache_drop_wall_ns"), "GROUP_END_FIELDS")
        require(closed["type"] == "group_end" and closed["group"] == group, "GROUP_END")
        uint64(closed["cache_drop_wall_ns"], "CACHE_DROP_WALL")
        groups.append({**opened, "cache_drop_wall_ns": closed["cache_drop_wall_ns"]})
    end = exact(next(rows), ("type", "schema", "status", "cases", "verifications",
                            "observed_wall_before_final_output_ns", "source_claim", "production_activation",
                            "mining_opportunity_claim"), "END_FIELDS")
    whole = uint64(end["observed_wall_before_final_output_ns"], "NATIVE_WALL")
    require(same_json(end, dict(type="end", schema=RAW_SCHEMA, status="PASS", cases=28, verifications=56,
                               observed_wall_before_final_output_ns=whole, source_claim=False,
                               production_activation=False, mining_opportunity_claim=False)), "END_CONTRACT")
    require(next(rows, None) is None and len({c["challenge"] for c in cases}) == 28, "EXACT_FRESH_CASES")
    phase_sum = sum(c[k] for c in cases for k in ("material_wall_ns", "prove_wall_ns", "reference_wall_ns"))
    phase_sum += sum(v["wall_ns"] for c in cases for v in c["calls"])
    phase_sum += sum(g["cache_create_wall_ns"] + g["cache_drop_wall_ns"] for g in groups)
    require(whole >= phase_sum, "OVERLAPPING_OR_INCONSISTENT_WALL_SCOPES")
    totals = {}
    for state in ("cold", "warm"):
        selected = [c for c in cases if c["warm"] == (state == "warm")]
        by_arm = {arm: sum(v["wall_ns"] for c in selected for v in c["calls"] if v["arm"] == arm)
                  for arm in ("raw", "facts")}
        totals[state] = dict(cases=len(selected), wall_ns=by_arm,
                            raw_over_facts_wall_ratio=fraction(by_arm["raw"], by_arm["facts"]))
    lifecycle = sum(g["cache_create_wall_ns"] + g["cache_drop_wall_ns"] for g in groups)
    raw_total = sum(t["wall_ns"]["raw"] for t in totals.values())
    facts_total = sum(t["wall_ns"]["facts"] for t in totals.values())
    return dict(seed=seed, raw_bytes=len(raw), raw_sha256=sha_bytes(raw), cases=cases, groups=groups,
                proof_records_replayed=28, accepted_verifier_calls=56, distinct_task_products=len({c["task"] for c in cases}),
                totals=totals, cache_lifecycle_wall_ns=lifecycle,
                raw_over_facts_plus_cache_lifecycle_wall_ratio=fraction(raw_total, facts_total + lifecycle),
                observed_wall_before_final_output_ns=whole, accounted_operation_wall_ns=phase_sum,
                unallocated_native_wall_ns=whole - phase_sum, residual_clamped=False,
                wall_ratio_is_cpu_ratio=False, verifier_calls_are_mining_tickets=False,
                original_full_proof_bytes=49188, node_admissions=0, production_activation=False)


def read_bundle(directory, *, expected_head, expected_tree, expected_plan_sha256,
                expected_binary_sha256, expected_manifest_sha256):
    for value, size in ((expected_head, 20), (expected_tree, 20), (expected_plan_sha256, 32),
                        (expected_binary_sha256, 32), (expected_manifest_sha256, 32)):
        hx(value, size, "EXTERNAL_PIN")
    directory = Path(directory).resolve()
    manifest_path = bundle_file(directory, "campaign.json", 4 * 1024 * 1024)
    require(sha(manifest_path) == expected_manifest_sha256, "EXTERNAL_MANIFEST_PIN")
    bundle = decode(manifest_path.read_bytes())
    require(bundle["schema"] == SCHEMA and bundle["complete_success"] is True and bundle["failure"] is None
            and bundle["source_unchanged"] is True and bundle["fresh_target"] is True and bundle["profile"] == "release",
            "COMPLETE_FROZEN_BUNDLE")
    for field in ("production_activation", "hardware_attested", "hardness_accepted", "node_admission_measured"):
        require(bundle[field] is False, "BUNDLE_AUTHORITY")
    before = bundle["source_before"]
    require(same_json(before, bundle["source_after"]) and before["head"] == expected_head and
            before["tree"] == expected_tree and before["status"] == "", "SOURCE_PIN")
    raw_before = bundle["raw_source_before"]
    require(same_json(raw_before, bundle["raw_source_after"]) and raw_before["tested_commit"] == expected_head
            and raw_before["tested_tree"] == expected_tree and raw_before["tracked_worktree_verified"] is True,
            "RAW_SOURCE_PIN")
    closure = reader_tree_snapshot(expected_head)
    plan_path = bundle_file(directory, "preregistered-plan.json", 1024 * 1024)
    require(sha(plan_path) == expected_plan_sha256 == bundle["plan_sha256"], "EXTERNAL_PLAN_PIN")
    jobs = validate_plan(decode(plan_path.read_bytes()))
    require(bundle["operation_clock"] == "std::time::Instant-wall" and
            type(bundle["collection_output_limit_bytes"]) is int and
            bundle["collection_output_limit_bytes"] == OUTPUT_LIMIT, "BUNDLE_MEASUREMENT_ENVELOPE")
    for key in ("repository_root", "output_directory", "target_directory"):
        require(type(bundle[key]) is str and Path(bundle[key]).is_absolute() and
                ".." not in Path(bundle[key]).parts and str(Path(bundle[key])) == bundle[key],
                "RECORDED_ABSOLUTE_PATH")
    hardware = {}
    for when in ("before", "after"):
        path = bundle_file(directory, "hardware-" + when + ".json", 1024 * 1024)
        require(sha(path) == bundle["hardware_" + when + "_sha256"], "HARDWARE_FILE_PIN")
        observed = decode(path.read_bytes())
        cpu = uint64(observed["requested_child_cpu"], "OBSERVED_CPU")
        require(type(observed["allowed_affinity"]) is list and
                all(type(v) is int and v >= 0 for v in observed["allowed_affinity"]) and
                cpu in observed["allowed_affinity"] and observed["exclusive_cpu"] is False and
                observed["hardware_attested"] is False and observed["energy_joules"] is None,
                "HARDWARE_SCOPE")
        hardware[when] = observed
    require(hardware["before"]["requested_child_cpu"] == hardware["after"]["requested_child_cpu"],
            "CHANGED_CPU_AFFINITY")
    cpu = hardware["before"]["requested_child_cpu"]
    require(bundle["plan_source_path"] == "formal/pon-nakamoto-v1/experiments/w1_task_product_plan_v1.json",
            "CANONICAL_PLAN_PATH")
    source_objects(expected_head, expected_tree, {
        bundle["plan_source_path"]: expected_plan_sha256,
        "scripts/run_w1_task_product_research.py": bundle["runner_sha256"]})
    binary = bundle["binary"]
    require(binary["sha256"] == expected_binary_sha256 and binary["cargo_artifact"]["fresh"] is False
            and binary["cargo_artifact"]["target"]["name"] == BINARY
            and binary["cargo_artifact"]["executable"] == binary["path"], "EXTERNAL_BINARY_PIN")
    require(binary["path"] == str(Path(bundle["target_directory"]) / "release/examples" / BINARY)
            and binary["retained_file"] == BINARY, "EXECUTABLE_PATH_BINDING")
    retained = bundle_file(directory, BINARY, 32 * 1024 * 1024)
    require(retained.stat().st_size == uint64(binary["bytes"], "BINARY_SIZE", 1) and
            sha(retained) == expected_binary_sha256, "RETAINED_EXECUTABLE_PIN")
    steps = bundle["steps"]
    require(type(steps) is list and [s["name"] for s in steps] == list(SETUP) + [j["name"] for j in jobs],
            "EXACT_STEP_ORDER")
    cargo, rustc = bundle["cargo"]["path"], bundle["compiler"]["path"]
    expected_setup = (
        (["bash", "scripts/project-preflight.sh"], 60),
        ([rustc, "-Vv"], 60),
        ([cargo, "-Vv"], 60),
        ([cargo, "metadata", "--offline", "--locked", "--format-version", "1",
          "--manifest-path", "trillionnium/Cargo.toml"], 120),
        ([cargo, "build", "--offline", "--locked", "--release", "--jobs", "1",
          "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-crypto-primitives",
          "--example", BINARY, "--message-format=json"], 1200),
    )
    for step, (command, timeout) in zip(steps, expected_setup):
        require(same_json(step["command"], command) and type(step["timeout_seconds"]) is int
                and step["timeout_seconds"] == timeout, "SETUP_COMMAND")
    for step in steps:
        require(step["cwd"] == bundle["repository_root"], "STEP_SOURCE_DIRECTORY")
        require(step["complete_success"] is True and type(step["returncode"]) is int
                and step["returncode"] == 0 and step["error"] is None and
                step["stdout_truncated"] is False and step["stderr_truncated"] is False,
                "FAILED_OR_TRUNCATED_STEP")
        validate_child_resources(step["whole_waited_child_resources"])
        uint64(step["wall_ns"], "STEP_WALL")
        require(type(step["output_limit_bytes"]) is int and step["output_limit_bytes"] == OUTPUT_LIMIT,
                "STEP_OUTPUT_LIMIT")
        for stream in ("stdout", "stderr"):
            require(step[stream] == step["name"] + "." + stream, "STREAM_NAME")
            path = bundle_file(directory, step[stream], OUTPUT_LIMIT if stream == "stdout" else 4 * 1024 * 1024)
            require(path.stat().st_size == uint64(step[stream + "_bytes"], "STREAM_BYTES")
                    and sha(path) == step[stream + "_sha256"], "RAW_STREAM_PIN")
        original = {k: v for k, v in step.items() if k != "command_usage"}
        receipt = bundle_file(directory, step["name"] + ".step.json", 1024 * 1024)
        require(same_json(decode(receipt.read_bytes()), original), "STEP_RECEIPT")
    toolchain = (directory / "rustc-version.stdout").read_text()
    require(toolchain == bundle["toolchain"] and toolchain.startswith("rustc 1.95.0 "), "EXACT_TOOLCHAIN")
    build_rows = [decode(line) for line in (directory / "build.stdout").read_text().splitlines()]
    artifacts = [v for v in build_rows if v.get("reason") == "compiler-artifact" and
                 v.get("target", {}).get("name") == BINARY and v.get("executable")]
    require(len(artifacts) == 1 and same_json(artifacts[0], binary["cargo_artifact"]), "BUILT_ARTIFACT_PIN")
    results = []
    for job, step in zip(jobs, steps[len(SETUP):]):
        expected_command = [bundle["gnu_time_observer"]["executable"], "-f", "%U %S %M %e", "-o",
                            str(Path(bundle["output_directory"]) / (job["name"] + ".usage")),
                            bundle["taskset"]["path"], "-c"]
        require(step["command"][:7] == expected_command and len(step["command"]) == 11
                and step["command"][7] == str(cpu)
                and step["command"][8:] == [binary["path"], *job["args"]]
                and type(step["timeout_seconds"]) is int and step["timeout_seconds"] == job["timeout_seconds"],
                "REGISTERED_NATIVE_COMMAND")
        usage = usage_snapshot(bundle_file(directory, job["name"] + ".usage", 16 * 1024))
        usage["scope"] = OBSERVATION_SCOPE
        require(same_json(usage, step["command_usage"]), "USAGE_RECEIPT")
        observer = decode(bundle_file(directory, job["name"] + ".observer.json", 32 * 1024).read_bytes())
        require(same_json(observer, dict(usage=usage, usage_error=None,
                    original_step_receipt_sha256=sha(directory / (job["name"] + ".step.json")),
                    observer_sha256=bundle["gnu_time_observer"]["sha256"])), "OBSERVER_RECEIPT")
        result = read_raw(directory / step["stdout"], int(job["args"][1]))
        waited = step["whole_waited_child_resources"]
        whole_cpu = waited["user_cpu_ns"] + waited["system_cpu_ns"]
        printed_cpu = int((Decimal(usage["user_seconds_decimal"]) + Decimal(usage["system_seconds_decimal"])) * 10**9)
        require(abs(printed_cpu - whole_cpu) <= 20_002_000, "WHOLE_CPU_OBSERVERS")
        require(step["wall_ns"] >= result["observed_wall_before_final_output_ns"], "WHOLE_WALL_OBSERVERS")
        result.update(job=job["name"], whole_waited_child_resources=waited, command_usage=usage,
                      whole_waited_cpu_ns=whole_cpu, whole_waited_wall_ns=step["wall_ns"])
        results.append(result)
    require(same_json(reader_tree_snapshot(expected_head), closure), "READER_SOURCE_CHANGED")
    return dict(schema="pon-w1-task-product-research-derived-v1", source=before,
                reader_source=closure, raw_manifest_sha256=expected_manifest_sha256,
                plan_sha256=expected_plan_sha256, binary_sha256=expected_binary_sha256,
                retained_executable_verified=True, hardware_observation=hardware,
                external_pins_checked=True, all_original_proofs_scalar_replayed=True, jobs=results,
                proof_records_replayed=sum(v["proof_records_replayed"] for v in results),
                accepted_verifier_calls=sum(v["accepted_verifier_calls"] for v in results),
                wall_ratio_is_cpu_ratio=False, node_admissions=0, production_activation=False,
                universal_cost_bound=False, independent_hardware_evidence=False, energy_joules=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    for name in ("head", "tree", "plan-sha256", "binary-sha256", "manifest-sha256"):
        parser.add_argument("--expected-" + name, required=True)
    args = parser.parse_args()
    result = read_bundle(args.bundle, expected_head=args.expected_head, expected_tree=args.expected_tree,
                         expected_plan_sha256=args.expected_plan_sha256,
                         expected_binary_sha256=args.expected_binary_sha256,
                         expected_manifest_sha256=args.expected_manifest_sha256)
    with args.out.open("x") as output:
        json.dump(result, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    print(json.dumps({k: result[k] for k in ("proof_records_replayed", "accepted_verifier_calls")}))


if __name__ == "__main__":
    main()
