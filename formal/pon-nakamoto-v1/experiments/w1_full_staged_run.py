#!/usr/bin/env python3
"""Run the existing full-W1 stages under one budget, including local delivery.

The cryptographic runner and fresh verifier remain the verification authority.
This coordinator records process observations; local delivery is not publication,
WAN propagation, Node admission, confirmation, or a measured stale-block rate.
"""
import argparse
import json
import math
import os
from pathlib import Path
import resource
import shutil
import sys
import time

sys.dont_write_bytecode = True
from w1_stage_measure import Canceled, cancel_on_signals, measure, sha, write_new

INPUT_BYTES = 49506
HEADER_BYTES = 318
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
SCHEMAS = {1: "TRNM-W1-STAGED-PROOF1", 2: "TRNM-W1-STAGED-PROOF2"}
V2_PROFILE_ID = "trnm-w1-risc0-3.0.6-poseidon2-join-v2"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path, limit=4 * 1024 * 1024):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"nonfinite JSON constant: {value}")

    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number

    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, f"oversized JSON: {path}")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant,
                      parse_float=finite_float)


def footprint(directory):
    files = [path for path in directory.rglob("*") if path.is_file()] if directory.exists() else []
    return {"files": len(files), "logical_bytes": sum(path.stat().st_size for path in files),
            "allocated_bytes": sum(path.stat().st_blocks * 512 for path in files)}


def append_event(path, row):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def checked_image_id(value):
    require(type(value) is list and len(value) == 8
            and all(type(word) is int and 0 <= word < 2**32 for word in value),
            "image_id must contain exactly eight canonical u32 words")
    return list(value)


def checked_manifest(checkpoint, version, runner_hash, r0vm_hash):
    manifest = read_json(checkpoint / "manifest.json")
    require(manifest.get("schema") == SCHEMAS[version], "wrong statement-version manifest")
    require(manifest.get("runner_sha256") == runner_hash, "checkpoint runner identity differs")
    require(manifest.get("r0vm_sha256") == r0vm_hash, "checkpoint prover identity differs")
    checked_image_id(manifest.get("image_id"))
    for field, filename in (("input_sha256", "input.bin"), ("journal_sha256", "expected-journal.bin"),
                            ("guest_sha256", "guest.bin")):
        require(manifest.get(field) == sha(checkpoint / filename), f"checkpoint {field} differs")
    require((checkpoint / "input.bin").stat().st_size == INPUT_BYTES, "wrong complete input length")
    require((checkpoint / "header.bin").stat().st_size == HEADER_BYTES, "wrong header length")
    with (checkpoint / "input.bin").open("rb") as stream:
        require(stream.read(HEADER_BYTES) == (checkpoint / "header.bin").read_bytes(), "header/input mismatch")
    require((checkpoint / "expected-journal.bin").stat().st_size == (16882 if version == 2 else 16818),
            "wrong complete public journal length")
    segments = manifest.get("segments")
    require(type(segments) is list and 0 < len(segments) <= 4096, "invalid frozen segment count")
    require(all(type(row) is dict and type(row.get("index")) is int and row["index"] == index
                for index, row in enumerate(segments)), "noncanonical segment order")
    return manifest


def validate_v2_report(row, identity, kind, iterations):
    """Bind the actual Rust report to this run; the Rust verifier checks seals."""
    require(type(row) is dict, "v2 report must be an object")
    schema = "TRNM-W1-V2-NATIVE1" if kind == "native" else "TRNM-W1-V2-FULL-VERIFY1"
    require(row.get("schema") == schema, "wrong v2 report schema")
    require(type(row.get("iterations")) is int and row["iterations"] == iterations, "wrong replay count")
    require(row.get("admission_authorized") is False, "observer cannot authorize admission")
    require(row.get("parent_eligibility_checked") is False, "standalone report cannot claim parent eligibility")
    require(row.get("profile_id") == V2_PROFILE_ID, "wrong v2 profile identity")
    if kind != "native":
        require(checked_image_id(row.get("image_id")) == checked_image_id(identity.get("image_id")),
                "v2 report image_id differs from verified manifest")
    for field in ("work_id", "header_sha256", "journal_sha256"):
        require(row.get(field) == identity[field], f"v2 report {field} differs")
    field = "input_sha256" if kind == "native" else "receipt_sha256"
    require(row.get(field) == identity[field], f"v2 report {field} differs")
    require(row.get("expected_artifacts_sha256") == identity["external_artifacts_sha256"],
            "v2 report external expected artifacts differ")
    key = "native_replay_ns" if kind == "native" else "decode_and_verify_ns"
    samples = row.get(key)
    require(type(samples) is list and len(samples) == iterations
            and all(type(value) is int and 0 < value < 1 << 63 for value in samples), "invalid actual replay samples")
    return {"schema": schema, "iterations": iterations, "profile_id": row["profile_id"],
            "samples_ns": samples}


def saved_identity(checkpoint, expected_artifacts, version, manifest):
    image_id = checked_image_id(manifest.get("image_id"))
    journal = (checkpoint / "expected-journal.bin").read_bytes()
    require(journal.startswith(f"TRNM-W1-ZK-JOURNAL{version}\0".encode()), "journal domain differs")
    # The full Rust relation, not these offsets, is the acceptance authority.
    base = 20 + HEADER_BYTES
    if version == 2:
        require(expected_artifacts is not None and expected_artifacts.stat().st_size == 64,
                "trusted external A/B commitments must be exactly 64 bytes")
        require(journal[base + 96:base + 160] == expected_artifacts.read_bytes(),
                "journal differs from independently supplied expected artifacts")
    receipt = checkpoint / "succinct.bin"
    require(0 < receipt.stat().st_size <= MAX_RECEIPT_BYTES, "saved receipt size bound")
    return {"work_id": journal[base + 64:base + 96].hex(), "image_id": image_id,
            "input_sha256": sha(checkpoint / "input.bin"),
            "header_sha256": sha(checkpoint / "header.bin"),
            "journal_sha256": sha(checkpoint / "expected-journal.bin"),
            "receipt_sha256": sha(receipt), "receipt_bytes": receipt.stat().st_size,
            "external_artifacts_sha256": sha(expected_artifacts) if expected_artifacts else None}


def validate_external_commitments(checkpoint, expected_artifacts):
    require(expected_artifacts.stat().st_size == 64,
            "trusted external A/B commitments must be exactly 64 bytes")
    journal = (checkpoint / "expected-journal.bin").read_bytes()
    start = 20 + HEADER_BYTES + 96
    require(journal[start:start + 64] == expected_artifacts.read_bytes(),
            "prepared relation differs from independently supplied expected artifacts")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--r0vm", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--prior-result", type=Path, action="append", default=[])
    parser.add_argument("--total-wall-seconds", type=float, default=5400)
    parser.add_argument("--pause-file", type=Path)
    parser.add_argument("--prepare-input", type=Path)
    parser.add_argument("--statement-version", type=int, choices=(1, 2), default=1)
    parser.add_argument("--fresh-verifier", type=Path)
    parser.add_argument("--native-verifier", type=Path)
    parser.add_argument("--expected-artifacts", type=Path)
    parser.add_argument("--local-bytes-per-second", type=int, default=1_000_000)
    args = parser.parse_args(argv)
    if not math.isfinite(args.total_wall_seconds) or not 0 < args.total_wall_seconds <= 7200:
        parser.error("total wall budget must be in (0,7200]")
    if not 1000 <= args.local_bytes_per_second <= 1_000_000_000:
        parser.error("bounded local sender pacing in [1000,1000000000] bytes/s required")
    if args.statement_version == 2 and (not args.fresh_verifier or not args.expected_artifacts):
        parser.error("v2 requires --fresh-verifier and independent --expected-artifacts")
    if args.statement_version == 1 and args.expected_artifacts:
        parser.error("v1 has no independent artifact-commitment statement")
    if args.prepare_input and (args.prior_result or args.checkpoint.exists()):
        parser.error("fresh preparation requires a new checkpoint and no prior-result costs")
    args.runner = args.runner.resolve(strict=True)
    args.r0vm = args.r0vm.resolve(strict=True)
    args.checkpoint = args.checkpoint.resolve()
    args.out = args.out.resolve()
    args.fresh_verifier = (args.fresh_verifier or args.runner.parent / "trnm-w1-zk-host").resolve(strict=True)
    args.native_verifier = (args.native_verifier or (args.fresh_verifier if args.statement_version == 2
                            else args.runner.parent / "w1-native-cost")).resolve(strict=True)
    if args.expected_artifacts:
        args.expected_artifacts = args.expected_artifacts.resolve(strict=True)
    if args.prepare_input:
        args.prepare_input = args.prepare_input.resolve(strict=True)
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    own_cpu_start = resource.getrusage(resource.RUSAGE_SELF)
    prior, stages, benchmarks, local = [], [], {}, {}
    manifest = identity = None
    receipt_verified = experiment_complete = False
    receipt_observed_seconds = verified_observed_seconds = local_delivery_observed_seconds = None
    paused_seconds, prior_seconds, error = 0.0, 0.0, None
    try:
        executable_hashes = {str(path): sha(path) for path in {args.runner, args.r0vm, args.fresh_verifier, args.native_verifier}}
        seen_prior = set()
        for path in args.prior_result:
            result = read_json(path)
            wall = result.get("wall_seconds")
            require(type(wall) in (int, float) and math.isfinite(wall) and wall >= 0, "invalid prior observed stage wall time")
            prior_hash = sha(path)
            stage_key = json.dumps([result.get("started_unix_ns"), result.get("command")], sort_keys=True)
            require(prior_hash not in seen_prior and stage_key not in seen_prior,
                    "same prior stage cannot enter the cumulative denominator twice")
            seen_prior.update((prior_hash, stage_key))
            prior.append({"path": str(path.resolve()), "sha256": prior_hash, "result": result})
            prior_seconds += wall
    except (OSError, ValueError, TypeError, RecursionError) as failure:
        write_new(args.out / "result.json", {"schema": "TRNM-W1-COMPLETE-STAGED-RUN2",
                  "phase": "INITIALIZATION_FAILED", "complete_proof_claim": False,
                  "end_to_end_observation_complete": False,
                  "error": f"{type(failure).__name__}: {failure}", "prior_runs": prior, "stages": []})
        return 1
    deadline = started + args.total_wall_seconds - prior_seconds
    declaration = {
        "schema": "TRNM-W1-COMPLETE-STAGED-RUN2", "statement_version": args.statement_version,
        "started_unix_ns": time.time_ns(), "started_monotonic": started,
        "deadline_monotonic": deadline, "total_wall_budget_seconds": args.total_wall_seconds,
        "prior_bounded_wall_seconds": prior_seconds, "prior_runs": prior,
        "fresh_preparation_included": bool(args.prepare_input),
        "input_fixture_construction_included": False,
        "per_new_segment_wall_seconds": 300, "free_disk_floor_bytes": 1024**3,
        "checkpoint_disk_cap_bytes": 256 * 1024**2,
        "pause_file": str(args.pause_file) if args.pause_file else None,
        "pause_and_controller_wall_consume_budget": True,
        "cleanup_grace_adds_proof_budget": False,
        "executables_sha256": executable_hashes,
        "runner_source_binding": "runner verifies its clean committed source and complete guest image; executable digests are not reproducible-build attestations",
        "expected_artifacts_path": str(args.expected_artifacts) if args.expected_artifacts else None,
        "expected_artifacts_sha256": sha(args.expected_artifacts) if args.expected_artifacts else None,
        "local_offered_bytes_per_second": args.local_bytes_per_second,
        "local_transport_scope": "experimental envelope; actual single-host TCP loopback; no production wire format or real peer admission",
        "complete_proof_claim": False,
    }
    write_new(args.out / "declaration.json", declaration)

    def remaining():
        return deadline - time.monotonic()

    def stage(label, command, cap):
        nonlocal paused_seconds
        while args.pause_file and args.pause_file.exists():
            require(remaining() > 0, "declared wall budget exhausted during coordinated pause")
            pause_started = time.monotonic()
            time.sleep(min(1, remaining()))
            paused_seconds += time.monotonic() - pause_started
        free = shutil.disk_usage(args.checkpoint if args.checkpoint.exists() else args.out).free
        size = footprint(args.checkpoint)
        require(free >= 1024**3 and size["allocated_bytes"] <= 256 * 1024**2,
                "declared disk guard reached before next stage")
        require(remaining() > 0, "declared cumulative wall budget exhausted")
        executable = str(command[0])
        if executable in executable_hashes:
            require(sha(Path(executable)) == executable_hashes[executable], "declared executable changed")
        event = {"stage": label, "status": "STARTED", "remaining_seconds": remaining(),
                 "disk_free_bytes": free, "checkpoint": size, "argv": list(map(str, command))}
        append_event(args.out / "events.jsonl", event)
        print(json.dumps(event), flush=True)
        result = measure(list(map(str, command)), args.out / label, min(cap, 7200), deadline=deadline)
        record = {"stage": label, "result": result}
        stages.append(record)
        append_event(args.out / "stages.jsonl", record)
        print(json.dumps({"stage": label, "status": "FINISHED", "returncode": result["returncode"],
                          "wall_seconds": result["wall_seconds"], "termination_reasons": result["termination_reasons"]}), flush=True)
        require(result["stage_process_complete"], f"actual stage failed: {label}, returncode={result['returncode']}, reasons={result['termination_reasons']}")
        require(remaining() > 0, "declared cumulative budget expired after stage settlement")
        return result

    base = [args.runner, "--r0vm", args.r0vm]
    with cancel_on_signals():
        try:
            if args.prepare_input:
                stage("prepare-full-execution", [*base, "prepare", args.checkpoint, args.prepare_input, "18"], 180)
            manifest = checked_manifest(args.checkpoint, args.statement_version,
                                        executable_hashes[str(args.runner)], executable_hashes[str(args.r0vm)])
            if args.prepare_input:
                require(manifest["input_sha256"] == sha(args.prepare_input), "prepared input differs from declared source")
            if args.statement_version == 2:
                validate_external_commitments(args.checkpoint, args.expected_artifacts)
            stage("reverify-existing-prefix", [*base, "prove", args.checkpoint, "0"], 180)
            for index in range(len(manifest["segments"])):
                path = args.checkpoint / f"receipt-{index:04}.bin"
                if path.exists():
                    continue
                stage(f"prove-{index:04}", [*base, "prove", args.checkpoint, "1"], 300)
                require(path.is_file(), "successful process omitted its required segment receipt")
            stage("complete-recursive-compression", [*base, "compress", args.checkpoint], 7200)
            receipt_observed_seconds = time.monotonic() - started
            identity = saved_identity(args.checkpoint, args.expected_artifacts, args.statement_version, manifest)
            receipt, header = args.checkpoint / "succinct.bin", args.checkpoint / "header.bin"
            fresh_args = [receipt, header, args.expected_artifacts] if args.statement_version == 2 else ["verify", header, receipt]
            stage("fresh-process-strict-verification", [args.fresh_verifier, *fresh_args], 180)
            if args.statement_version == 2:
                row = read_json(args.out / "fresh-process-strict-verification" / "stdout.log")
                benchmarks["fresh"] = validate_v2_report(row, identity, "transparent", 1)
            require(identity == saved_identity(args.checkpoint, args.expected_artifacts, args.statement_version, manifest),
                    "saved proof identity changed during verification")
            require(remaining() > 0, "fresh proof verification was not fully observed before the common deadline")
            receipt_verified = True
            verified_observed_seconds = time.monotonic() - started

            helper = Path(__file__).with_name("w1_local_payload.py")
            payload_out = args.out / "local-payloads"
            encode = [sys.executable, helper, "serialize", "--input", args.checkpoint / "input.bin",
                      "--receipt", receipt, "--statement-version", str(args.statement_version), "--out", payload_out]
            if args.expected_artifacts:
                encode += ["--expected-artifacts", args.expected_artifacts]
            stage("serialize-local-payloads", encode, 180)
            local["serialization"] = read_json(payload_out / "result.json")
            require(local["serialization"]["input_sha256"] == identity["input_sha256"]
                    and local["serialization"]["payloads"]["transparent"]["body_sha256"] == identity["receipt_sha256"]
                    and local["serialization"]["external_artifacts_sha256"] == identity["external_artifacts_sha256"],
                    "serialized payload differs from verified input, receipt, or external commitments")
            for kind in ("transparent", "native"):
                payload = local["serialization"]["payloads"][kind]
                local_out = args.out / f"local-transfer-{kind}"
                stage(f"observe-local-transfer-{kind}", [sys.executable, helper, "transfer", "--payload",
                      payload_out / payload["payload_file"], "--expected-sha256", payload["payload_sha256"],
                      "--bytes-per-second", str(args.local_bytes_per_second), "--out", local_out], 180)
                local[kind] = read_json(local_out / "result.json")
                require(local[kind]["byte_roundtrip_complete"] is True
                        and local[kind]["payload_sha256"] == payload["payload_sha256"], "incomplete local byte transfer")
                if kind == "transparent":
                    local_delivery_observed_seconds = time.monotonic() - started
            many_args = ["--verify-many", receipt, header, args.expected_artifacts] if args.statement_version == 2 else ["verify-many", header, receipt]
            native_args = ["--native", args.checkpoint / "input.bin", args.expected_artifacts] if args.statement_version == 2 else [args.checkpoint / "input.bin"]
            stage("fixed-receipt-verifier-cost", [args.fresh_verifier, *many_args], 180)
            stage("native-full-verifier-cost", [args.native_verifier, *native_args], 180)
            if args.statement_version == 2:
                for kind, label, count in (("transparent", "fixed-receipt-verifier-cost", 100),
                                            ("native", "native-full-verifier-cost", 1000)):
                    benchmarks[kind] = validate_v2_report(read_json(args.out / label / "stdout.log"), identity, kind, count)
                require(benchmarks["fresh"]["profile_id"] == benchmarks["transparent"]["profile_id"]
                        == benchmarks["native"]["profile_id"], "replay reports name different candidate profiles")
            require(identity == saved_identity(args.checkpoint, args.expected_artifacts, args.statement_version, manifest),
                    "saved artifacts changed during cost observations")
            require(remaining() > 0, "final observations completed after the common deadline")
            experiment_complete = True
        except (Canceled, KeyboardInterrupt, OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError) as failure:
            error = f"{type(failure).__name__}: {failure}"
    own_cpu_end = resource.getrusage(resource.RUSAGE_SELF)
    elapsed = time.monotonic() - started
    wait4_rows = [row["result"]["rusage"] for row in stages]
    result = {
        **declaration, "complete_proof_claim": receipt_verified, "end_to_end_observation_complete": experiment_complete,
        "error": error, "stages": stages, "manifest": manifest, "identity": identity,
        "new_controller_wall_seconds": elapsed, "cumulative_bounded_wall_seconds": prior_seconds + elapsed,
        "coordinated_pause_seconds": paused_seconds, "checkpoint_final": footprint(args.checkpoint),
        "disk_free_final_bytes": shutil.disk_usage(args.out).free,
        "receipt_saved_observed_seconds_from_start": receipt_observed_seconds,
        "fresh_verified_receipt_observed_seconds_from_start": verified_observed_seconds,
        "local_transparent_delivery_observed_seconds_from_start": local_delivery_observed_seconds,
        "fresh_proof_pipeline_seconds": verified_observed_seconds if args.prepare_input and receipt_verified else None,
        "fresh_proof_pipeline_scope": "preparation, full execution, all segments, recursion, source/checkpoint checks, controller pauses, and fresh strict verification; starts after fixture availability; excludes build/setup",
        "observer_own_user_cpu_seconds": own_cpu_end.ru_utime - own_cpu_start.ru_utime,
        "observer_own_system_cpu_seconds": own_cpu_end.ru_stime - own_cpu_start.ru_stime,
        "observed_new_stage_wait4_user_cpu_seconds": sum(row["user_seconds"] or 0 for row in wait4_rows),
        "observed_new_stage_wait4_system_cpu_seconds": sum(row["system_seconds"] or 0 for row in wait4_rows),
        "all_new_stage_wait4_usage_available": all(row["user_seconds"] is not None for row in wait4_rows),
        "wait4_cpu_sum_scope": "new stages only; prior raw costs retained separately; no reconstruction of unreaped or missed descendants",
        "aggregate_process_tree_peak_rss_bytes": None,
        "benchmarks": benchmarks, "local_observations": local,
        "post_find_publish_seconds": None, "real_network_propagation_seconds": None,
        "node_admission_seconds": None, "confirmation_seconds": None, "stale_block_rate": None,
        "proof_randomness_tickets": 0, "independent_full_proof_trials_observed": int(receipt_verified),
        "prover_p99_established": False, "prover_resource_completeness_established": False,
        "benefit_gate_passed": None, "production_qualification": False, "consensus_admission": False,
    }
    if experiment_complete and time.monotonic() >= deadline:
        experiment_complete = False
        error = "final result construction exceeded the common deadline"
        result["end_to_end_observation_complete"] = False
        result["error"] = error
    write_new(args.out / "result.json", result)
    print(json.dumps({"complete_proof_claim": receipt_verified, "end_to_end_observation_complete": experiment_complete,
                      "error": error, "completed_stages": len(stages)}), flush=True)
    return 0 if experiment_complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
