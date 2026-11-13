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
import statistics
import sys
import time
import uuid

sys.dont_write_bytecode = True
from w1_stage_measure import (CANCELLATION_SCHEMA, SNAPSHOT_SCHEMA, Canceled,
                              DeferredCancellation, cancel_on_signals, measure,
                              publish_cancellation, run_cli, sha, write_new)

INPUT_BYTES = 49506
HEADER_BYTES = 318
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
SCHEMAS = {1: "TRNM-W1-STAGED-PROOF1", 2: "TRNM-W1-STAGED-PROOF2"}
V2_PROFILE_ID = "trnm-w1-risc0-3.0.6-poseidon2-join-v2"
# Fail before any segment proof if a rebuilt guest cannot satisfy the independent
# verifier's fixed profile. This is only a preflight, never proof verification.
V2_IMAGE_ID = (1958252411, 3287394615, 1805488136, 1516578702,
               78549041, 790278610, 301018785, 4279049364)


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
    image_id = checked_image_id(manifest.get("image_id"))
    if version == 2:
        require(tuple(image_id) == V2_IMAGE_ID,
                "prepared image_id differs from the independent v2 verifier pin")
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



def observed_cost_comparison(result):
    """Summarize already checked v2 observations; never verify a seal or admit work.

    Fixed-receipt replays measure verification cost, not independent proof trials.
    This derived report retains incomplete delivery/resource accounting and cannot
    promote an inexpensive sample into a minimum-node or full-Cell benefit claim.
    """
    require(result.get("statement_version") == 2 and result.get("complete_proof_claim") is True
            and result.get("end_to_end_observation_complete") is True,
            "cost comparison needs a completed v2 observation")
    require(type(result.get("independent_full_proof_trials_observed")) is int
            and result["independent_full_proof_trials_observed"] == 1,
            "fixed receipt samples are one full proof trial")
    identity, benchmarks = result["identity"], result["benchmarks"]
    require(tuple(checked_image_id(identity.get("image_id"))) == V2_IMAGE_ID,
            "cost comparison image differs from v2 verifier")
    summaries = {}
    for kind, iterations in (("native", 1000), ("transparent", 100), ("fresh", 1)):
        row = benchmarks[kind]
        schema = "TRNM-W1-V2-NATIVE1" if kind == "native" else "TRNM-W1-V2-FULL-VERIFY1"
        require(row.get("schema") == schema and row.get("profile_id") == V2_PROFILE_ID
                and type(row.get("iterations")) is int and row["iterations"] == iterations,
                "cost comparison replay profile/count differs")
        samples = row.get("samples_ns")
        require(type(samples) is list and len(samples) == iterations and all(
            type(value) is int and 0 < value < 1 << 63 for value in samples),
            "cost comparison requires real positive integer sample durations")
        summaries[kind] = dict(iterations=iterations, median_ns=statistics.median(samples),
                               minimum_ns=min(samples), maximum_ns=max(samples))
    local = result["local_observations"]
    serialization = local["serialization"]
    require(serialization.get("schema") == "TRNM-W1-LOCAL-PAYLOAD1"
            and serialization.get("statement_version") == 2,
            "cost comparison local serialization profile differs")
    for field in ("input_sha256", "header_sha256", "external_artifacts_sha256"):
        require(serialization.get(field) == identity[field], "cost comparison artifact binding differs")
    payloads = serialization["payloads"]
    require(payloads["transparent"].get("body_sha256") == identity["receipt_sha256"]
            and payloads["transparent"].get("body_bytes") == identity["receipt_bytes"],
            "cost comparison receipt binding differs")
    transfers = {}
    for kind in ("native", "transparent"):
        payload, transfer = payloads[kind], local[kind]
        for key in ("body_bytes", "payload_bytes", "envelope_encode_ns", "durable_local_file_write_ns"):
            require(type(payload.get(key)) is int and 0 < payload[key] < 1 << 63,
                    "invalid local payload cost")
        require(payload["payload_bytes"] >= payload["body_bytes"], "payload smaller than its body")
        receiver = transfer.get("receiver")
        require(transfer.get("schema") == "TRNM-W1-LOCAL-TCP-TRANSFER1"
                and transfer.get("byte_roundtrip_complete") is True and type(receiver) is dict
                and receiver.get("error") is None
                and transfer.get("payload_bytes") == receiver.get("received_bytes") == payload["payload_bytes"]
                and transfer.get("payload_sha256") == receiver.get("received_sha256") == payload["payload_sha256"],
                "cost comparison has incomplete or substituted local transfer")
        seconds, rate = transfer.get("send_receive_and_durable_write_seconds"), transfer.get("offered_bytes_per_second")
        require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds > 0
                and type(rate) is int and rate > 0, "invalid local transfer cost")
        transfers[kind] = dict(body_bytes=payload["body_bytes"], payload_bytes=payload["payload_bytes"],
            envelope_encode_ns=payload["envelope_encode_ns"],
            durable_local_file_write_ns=payload["durable_local_file_write_ns"],
            send_receive_and_durable_write_seconds=seconds, offered_bytes_per_second=rate)
    require(transfers["native"]["offered_bytes_per_second"] == transfers["transparent"]["offered_bytes_per_second"],
            "different local transport offered rates are not comparable")
    ratio = summaries["transparent"]["median_ns"] / summaries["native"]["median_ns"]
    return dict(schema="TRNM-W1-OBSERVED-COST-COMPARISON1", profile_id=V2_PROFILE_ID,
        work_id=identity["work_id"], receipt_sha256=identity["receipt_sha256"],
        scope="derived same-host v2 observations; no seal verification or independent machine qualification",
        complete_relation="W1-v2", complete_cell_relation_proven=False,
        independent_full_proof_trials_observed=1, reused_receipt_replays=100,
        verification=summaries, transparent_over_native_median_verify_ratio=ratio,
        local_delivery=transfers,
        transparent_over_native_payload_bytes_ratio=transfers["transparent"]["payload_bytes"] / transfers["native"]["payload_bytes"],
        transparent_over_native_loopback_seconds_ratio=transfers["transparent"]["send_receive_and_durable_write_seconds"] / transfers["native"]["send_receive_and_durable_write_seconds"],
        fresh_proof_pipeline_seconds=result.get("fresh_proof_pipeline_seconds"),
        fresh_local_delivery_seconds_from_start=result.get("local_transparent_delivery_observed_seconds_from_start"),
        generation_and_fresh_verification_scope=result.get("fresh_proof_pipeline_scope"),
        observed_new_stage_wait4_user_cpu_seconds=result.get("observed_new_stage_wait4_user_cpu_seconds"),
        observed_new_stage_wait4_system_cpu_seconds=result.get("observed_new_stage_wait4_system_cpu_seconds"),
        all_new_stage_wait4_usage_available=result.get("all_new_stage_wait4_usage_available"),
        cpu_accounting_scope=result.get("wait4_cpu_sum_scope"),
        aggregate_process_tree_peak_rss_bytes=result.get("aggregate_process_tree_peak_rss_bytes"),
        comparison="slower-than-native-on-observed-verification" if ratio >= 1 else "faster-on-observed-verification-only",
        unmeasured_costs=["build/setup", "aggregate process-tree peak memory", "failures across independent proof trials",
                          "production queueing", "WAN propagation", "Node admission", "independent confirmation"],
        minimum_node_configuration_measured=False, full_delivery_cost_complete=False,
        benefit_gate_passed=None, production_qualification=False, consensus_admission=False)


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


def current_boot_id():
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(str(uuid.UUID(value)) == value, "noncanonical local Linux boot ID")
    return value


def effective_deadline(started, total, prior, original=None):
    local = started + total - prior
    return min(local, original) if original is not None else local


def resource_plan(segment_workers, compression_mode, compression_workers, rayon_threads):
    require(type(segment_workers) is int and 1 <= segment_workers <= 4,
            "segment workers must be in [1,4]")
    require(type(compression_workers) is int and 1 <= compression_workers <= 4,
            "compression workers must be in [1,4]")
    require(compression_mode in ("sequential", "balanced"), "unknown compression mode")
    require(compression_mode != "sequential" or compression_workers == 1,
            "sequential compression has exactly one worker")
    require(type(rayon_threads) is int and 1 <= rayon_threads <= 8,
            "Rayon threads must be in [1,8]")
    require(segment_workers * rayon_threads <= 8 and compression_workers * rayon_threads <= 8,
            "every planned worker count times Rayon threads must be at most eight")
    return {"segment_workers": segment_workers,
            "segment_mode": "sequential" if segment_workers == 1 else "parallel",
            "compression_mode": compression_mode, "compression_workers": compression_workers,
            "rayon_threads": rayon_threads,
            "maximum_planned_rayon_workers": max(segment_workers, compression_workers) * rayon_threads,
            "rayon_scope": "explicit child Rayon pool sizes; not an aggregate CPU quota or host isolation"}


def segment_command(base, checkpoint, workers):
    if workers == 1:
        return [*base, "prove", checkpoint, "1"]
    return [*base, "prove-parallel", checkpoint, str(workers), str(workers)]


def compression_command(base, checkpoint, mode, workers):
    if mode == "sequential":
        return [*base, "compress", checkpoint]
    return [*base, "compress-balanced", checkpoint, str(workers)]


def completion_hook_declaration(path):
    before = sha(path)
    value = read_json(path, limit=1024 * 1024)
    require(sha(path) == before, "completion hook declaration changed during read")
    require(type(value) is dict and set(value) == {"schema", "argv", "ack_path"}
            and value["schema"] == "TRNM-W1-COMPLETION-HOOK1", "invalid completion hook schema")
    argv = value["argv"]
    require(type(argv) is list and 0 < len(argv) <= 128
            and all(type(arg) is str and arg and "\0" not in arg for arg in argv),
            "completion hook requires a bounded nonempty string argv")
    executable = Path(argv[0])
    require(executable.is_absolute() and executable.is_file(),
            "completion hook executable must be an existing absolute file")
    require(type(value["ack_path"]) is str and value["ack_path"]
            and "\0" not in value["ack_path"], "invalid completion ACK path")
    ack = Path(value["ack_path"])
    require(ack.is_absolute() and not os.path.lexists(ack),
            "completion ACK path must be absolute and initially absent")
    return {**value, "config_path": str(path), "config_sha256": before,
            "argv0_sha256": sha(executable),
            "scope": "predeclared independent receiver command; no Node admission authority"}


def validate_receiver_ack(row, identity):
    require(type(row) is dict and row.get("schema") == "TRNM-W1-RECEIVER-ACK2",
            "wrong independent receiver ACK schema")
    require(row.get("receiver_operation_complete") is True and row.get("verified") is True
            and row.get("admission_authorized") is False,
            "receiver ACK does not establish bounded independent completion")
    require(row.get("error") is None and row.get("cancellation_event") is None
            and row.get("canceled_signal") is None and row.get("cleanup_unknown") is not True
            and row.get("deadline_exhausted_at_snapshot") is False,
            "receiver ACK records error, cancellation, unknown cleanup, or expiry")
    for field, expected in (("work_id", "work_id"), ("header_sha256", "header_sha256"),
                            ("expected_artifacts_sha256", "external_artifacts_sha256"),
                            ("receipt_sha256", "receipt_sha256")):
        require(row.get(field) == identity[expected], f"receiver ACK {field} differs")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--r0vm", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--prior-result", type=Path, action="append", default=[])
    parser.add_argument("--total-wall-seconds", type=float, default=5400)
    parser.add_argument("--deadline-monotonic", type=float)
    parser.add_argument("--deadline-boot-id")
    parser.add_argument("--segment-workers", type=int, default=1)
    parser.add_argument("--compression-mode", choices=("sequential", "balanced"), default="sequential")
    parser.add_argument("--compression-workers", type=int, default=1)
    parser.add_argument("--rayon-threads", type=int, default=8)
    parser.add_argument("--completion-hook-json", type=Path)
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
    if (args.deadline_monotonic is None) != (args.deadline_boot_id is None):
        parser.error("original monotonic deadline and local boot ID must be supplied together")
    if args.deadline_monotonic is not None and not math.isfinite(args.deadline_monotonic):
        parser.error("finite original monotonic deadline required")
    try:
        boot_id = current_boot_id()
        plan = resource_plan(args.segment_workers, args.compression_mode,
                             args.compression_workers, args.rayon_threads)
    except (OSError, ValueError) as failure:
        parser.error(str(failure))
    if args.deadline_boot_id is not None and args.deadline_boot_id != boot_id:
        parser.error("original monotonic deadline belongs to a different host or boot")
    if not 1000 <= args.local_bytes_per_second <= 1_000_000_000:
        parser.error("bounded local sender pacing in [1000,1000000000] bytes/s required")
    if args.statement_version == 2 and (not args.fresh_verifier or not args.expected_artifacts):
        parser.error("v2 requires --fresh-verifier and independent --expected-artifacts")
    if args.statement_version == 1 and args.expected_artifacts:
        parser.error("v1 has no independent artifact-commitment statement")
    if args.completion_hook_json and args.statement_version != 2:
        parser.error("independent completion hook requires the complete v2 statement")
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
    if args.completion_hook_json:
        args.completion_hook_json = args.completion_hook_json.resolve(strict=True)
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    own_cpu_start = resource.getrusage(resource.RUSAGE_SELF)
    prior, stages, benchmarks, local = [], [], {}, {}
    stage_dispatch_attempts = []
    manifest = identity = None
    receipt_verified = experiment_complete = False
    controller_cancellation = None
    hook = receiver_ack_observation = None
    receipt_observed_seconds = verified_observed_seconds = local_delivery_observed_seconds = None
    paused_seconds, prior_seconds, error = 0.0, 0.0, None
    try:
        executable_hashes = {str(path): sha(path) for path in {args.runner, args.r0vm, args.fresh_verifier, args.native_verifier}}
        if args.completion_hook_json:
            hook = completion_hook_declaration(args.completion_hook_json)
            executable_hashes[hook["argv"][0]] = hook["argv0_sha256"]
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
        write_new(args.out / "result.json", {"schema": "TRNM-W1-COMPLETE-STAGED-RUN3",
                  "phase": "INITIALIZATION_FAILED", "complete_proof_claim": False,
                  "end_to_end_observation_complete": False,
                  "error": f"{type(failure).__name__}: {failure}", "prior_runs": prior, "stages": []})
        return 1
    deadline = effective_deadline(started, args.total_wall_seconds, prior_seconds, args.deadline_monotonic)
    declaration = {
        "schema": "TRNM-W1-COMPLETE-STAGED-RUN3", "statement_version": args.statement_version,
        "cancellation_schema": CANCELLATION_SCHEMA, "result_is_pre_handoff_snapshot": True,
        "started_unix_ns": time.time_ns(), "started_monotonic": started,
        "deadline_monotonic": deadline, "total_wall_budget_seconds": args.total_wall_seconds,
        "deadline_boot_id": boot_id, "original_deadline_monotonic": args.deadline_monotonic,
        "original_deadline_boot_id": args.deadline_boot_id,
        "original_local_deadline_supplied": args.deadline_monotonic is not None,
        "effective_deadline_rule": "minimum of original local deadline and started plus total minus prior wall",
        "resource_plan": plan, "completion_hook": hook,
        "prior_bounded_wall_seconds": prior_seconds, "prior_runs": prior,
        "fresh_preparation_included": bool(args.prepare_input),
        "input_fixture_construction_included": False,
        "per_new_segment_wall_seconds": 300, "free_disk_floor_bytes": 1024**3,
        "per_segment_batch_wall_seconds": 300 * args.segment_workers,
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
        stage_cancellation = None
        try:
            stage_dispatch_attempts.append(label)
            result = measure(list(map(str, command)), args.out / label, min(cap, 7200), deadline=deadline,
                             environment_overrides={"RAYON_NUM_THREADS": str(args.rayon_threads)})
        except (Canceled, KeyboardInterrupt) as failure:
            stage_cancellation = failure
            snapshot = getattr(failure, "observed_snapshot", None)
            if not (type(snapshot) is dict and snapshot.get("schema") == SNAPSHOT_SCHEMA
                    and snapshot.get("kind") == "stage"
                    and snapshot.get("path") == str(args.out / label / "result.json")
                    and type(snapshot.get("value")) is dict):
                raise
            result = snapshot["value"]
        with DeferredCancellation(stage_cancellation,
                                  phase="coordinator-stage-retention") as retention:
            try:
                record = {"stage": label, "result": result}
                stages.append(record)
                if retention.observed_snapshot is None:
                    retention.published_snapshot("stage", args.out / label / "result.json")
                append_event(args.out / "stages.jsonl", record)
                print(json.dumps({"stage": label, "status": "FINISHED", "returncode": result["returncode"],
                                  "wall_seconds": result["wall_seconds"], "termination_reasons": result["termination_reasons"]}), flush=True)
            except Exception as failure:
                # F2: the stage already appended above must survive a failed
                # append/fsync/print, and that I/O error cannot replace cancel.
                retention.record_error("retention_error", failure)
                raise
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
            while True:
                missing = [index for index in range(len(manifest["segments"]))
                           if not (args.checkpoint / f"receipt-{index:04}.bin").exists()]
                if not missing:
                    break
                batch = missing[:args.segment_workers]
                label = (f"prove-{batch[0]:04}" if args.segment_workers == 1
                         else f"prove-batch-{batch[0]:04}")
                stage(label, segment_command(base, args.checkpoint, args.segment_workers),
                      300 * args.segment_workers)
                require(all((args.checkpoint / f"receipt-{index:04}.bin").is_file() for index in batch),
                        "successful process omitted its required segment receipt")
            stage("complete-recursive-compression", compression_command(
                base, args.checkpoint, args.compression_mode, args.compression_workers), 7200)
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

            if hook is not None:
                require(sha(args.completion_hook_json) == hook["config_sha256"],
                        "completion hook declaration changed before dispatch")
                ack_path = Path(hook["ack_path"])
                require(not os.path.lexists(ack_path), "completion ACK existed before receiver dispatch")
                stage("independent-receiver", hook["argv"], 7200)
                ack_hash = sha(ack_path)
                ack = read_json(ack_path, limit=16 * 1024 * 1024)
                validate_receiver_ack(ack, identity)
                require(sha(ack_path) == ack_hash, "receiver ACK changed during readback")
                require(identity == saved_identity(args.checkpoint, args.expected_artifacts,
                                                    args.statement_version, manifest),
                        "saved proof identity changed during receiver verification")
                require(remaining() > 0, "receiver completion missed original effective deadline")
                observed_ns = time.monotonic_ns()
                require(observed_ns / 1e9 < deadline,
                        "parent ACK observation missed original effective deadline")
                receiver_ack_observation = {
                    "monotonic_ns": observed_ns, "boot_id": boot_id,
                    "ack": {"path": str(ack_path), "sha256": ack_hash, "value": ack}}

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
        except (Canceled, KeyboardInterrupt) as failure:
            controller_cancellation = failure
            experiment_complete = False
            error = f"{type(failure).__name__}: {failure}"
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError) as failure:
            experiment_complete = False
            error = f"{type(failure).__name__}: {failure}"
        try:
            with DeferredCancellation(controller_cancellation,
                                      phase="controller-finalization",
                                      live_deadline=(deadline, boot_id)) as completion:
                own_cpu_end = resource.getrusage(resource.RUSAGE_SELF)
                elapsed = time.monotonic() - started
                wait4_rows = [row["result"]["rusage"] for row in stages]
                completion.phase = "controller-snapshot"
                if completion.canceled_signal is not None:
                    experiment_complete = False
                    if error is None:
                        error = "cancellation observed during controller finalization"
                result = {
                    **declaration, "complete_proof_claim": receipt_verified, "end_to_end_observation_complete": experiment_complete,
                    "error": error, "stages": stages, "manifest": manifest, "identity": identity,
                    "controller_canceled_signal": completion.canceled_signal,
                    "stage_dispatch_attempts": list(stage_dispatch_attempts),
                    "unretained_stage_labels": [label for label in stage_dispatch_attempts
                        if not any(row["stage"] == label for row in stages)],
                    "deadline_exhausted_at_snapshot": time.monotonic() >= deadline,
                    "controller_cancellation_event": completion.pending_event(),
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
                    "all_new_stage_wait4_usage_available": (len(stages) == len(stage_dispatch_attempts)
                        and all(row["user_seconds"] is not None and row["system_seconds"] is not None
                                for row in wait4_rows)),
                    "wait4_cpu_sum_scope": "new stages only; prior raw costs retained separately; no reconstruction of unreaped or missed descendants",
                    "aggregate_process_tree_peak_rss_bytes": None,
                    "benchmarks": benchmarks, "local_observations": local,
                    "independent_receiver_ack": (receiver_ack_observation["ack"]
                                                 if receiver_ack_observation else None),
                    "parent_observed_receiver_ack_monotonic_ns": (receiver_ack_observation["monotonic_ns"]
                                                                  if receiver_ack_observation else None),
                    "parent_observed_receiver_ack_boot_id": (receiver_ack_observation["boot_id"]
                                                             if receiver_ack_observation else None),
                    "parent_ack_observation_scope": "local coordinator monotonic clock after receiver process settlement, ACK binding checks, and original-deadline check; no cross-host clock subtraction",
                    "post_find_publish_seconds": None, "real_network_propagation_seconds": None,
                    "node_admission_seconds": None, "confirmation_seconds": None, "stale_block_rate": None,
                    "proof_randomness_tickets": 0, "independent_full_proof_trials_observed": int(receipt_verified),
                    "fresh_full_pipeline_trials_observed": int(bool(args.prepare_input) and receipt_verified),
                    "prover_p99_established": False, "prover_resource_completeness_established": False,
                    "benefit_gate_passed": None, "production_qualification": False, "consensus_admission": False,
                }
                result["observed_cost_comparison"] = None
                if experiment_complete and args.statement_version == 2:
                    try:
                        result["observed_cost_comparison"] = observed_cost_comparison(result)
                    except (ValueError, TypeError, KeyError) as failure:
                        experiment_complete = False
                        error = f"cost comparison failed: {type(failure).__name__}: {failure}"
                        result["end_to_end_observation_complete"] = False
                        result["error"] = error
                result["deadline_exhausted_at_snapshot"] = time.monotonic() >= deadline
                if experiment_complete and result["deadline_exhausted_at_snapshot"]:
                    experiment_complete = False
                    error = "final result construction exceeded the common deadline"
                    result["end_to_end_observation_complete"] = False
                    result["error"] = error
                write_new(args.out / "result.json", result)
                completion.published_snapshot("controller", args.out / "result.json")
                print(json.dumps({"complete_proof_claim": receipt_verified, "end_to_end_observation_complete": experiment_complete,
                                  "error": error, "completed_stages": len(stages)}), flush=True)
        except (Canceled, KeyboardInterrupt) as failure:
            publish_cancellation(args.out / "cancellation.json", failure, "controller")
            raise
    # A durable snapshot remains an observation if its fsync/handoff crosses
    # the deadline. The live operation must nevertheless return failure.
    return 0 if experiment_complete and time.monotonic() < deadline else 1


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
