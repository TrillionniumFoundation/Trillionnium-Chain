#!/usr/bin/env python3
"""Two explicit bounded continuations of one retained incomplete full W1 session.

The original failed attempt remains spent and failed. Neither shard is a whole
proof. Only the original native Composite assembler/verifier can produce one.
"""
import argparse
import json
import math
import os
from pathlib import Path
import signal
import sys
import time

import prove_segments as scheduler
from observations import read_single_result
from proof_resources import require_runner
import segment_continue_source as source

require = source.require
read = source.read
write_json = source.write_json


def run_identity():
    result = {"source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"),
              "run_id": os.environ.get("GITHUB_RUN_ID"),
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT")}
    require(isinstance(result["source_sha"], str) and len(result["source_sha"]) == 40
            and all(c in "0123456789abcdef" for c in result["source_sha"]), "exact source SHA required")
    for key in ["run_id", "run_attempt"]:
        require(isinstance(result[key], str) and result[key].isdigit()
                and int(result[key]) > 0, "actual GitHub run/attempt identity required")
    return result


def source_identity(directory, expected):
    before, after = read(directory / "source-before.json"), read(directory / "source-after.json")
    require(before == after and before["tested_commit"] == expected["source_sha"]
            and before["candidate"] == expected["source_sha"] and before["kind"] == "head"
            and before["tracked_worktree_verified"] is True
            and before["tests_executed_by_identity_check"] is False,
            "source-before/after identity is not the exact continuation head")
    return before


def select():
    # Absence is the original path. Invalid declared continuation never falls
    # back to a fresh expensive proof or to a different artifact.
    if not os.path.lexists(source.POLICY):
        mode = "generate"
    else:
        policy, manifest = source.load_policy(policy_path=source.POLICY)
        source.original_members(policy, manifest)
        mode = "continue"
    output = os.environ.get("GITHUB_OUTPUT")
    require(output is not None, "GITHUB_OUTPUT is required")
    with open(output, "a") as stream:
        stream.write(f"mode={mode}\n")
    print(json.dumps({"mode": mode, "partial_receipts_are_complete_proofs": False}))


def check_stage_terminal(terminal, expected_source, timeout):
    require(terminal.get("schema") == "pon-w1-segment-worker-process-v1"
            and terminal.get("returncode") == 0 and terminal.get("child_reaped") is True
            and terminal.get("source_sha") == expected_source
            and terminal.get("timeout_seconds") == timeout,
            "segment terminal missing or source/budget differs")
    for key in ["wall_seconds", "user_cpu_seconds", "system_cpu_seconds"]:
        value = terminal.get(key)
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                "actual stage cost unavailable")
    require(terminal["wall_seconds"] <= timeout, "actual completed stage exceeded its original wall budget")


def check_stage(stage):
    code = stage.check()
    if code is not None:
        check_stage_terminal(stage.record, os.environ.get("TRNM_EXPECTED_SOURCE_SHA"), stage.timeout)
    return code


def wait_stage(stage):
    while check_stage(stage) is None:
        if scheduler.STOP:
            raise InterruptedError("owned continuation group cancelled")
        time.sleep(0.025)


def require_work_finished(elapsed):
    require(type(elapsed) in (int, float) and math.isfinite(elapsed)
            and 0 <= elapsed < 3500, "continuation work exceeded its original work-stop budget")


def prove(args):
    require(os.getpid() == os.getpgrp(), "continuation requires the original owned process-group wrapper")
    require(os.environ.get("RAYON_NUM_THREADS") == "2", "unchanged two-thread worker profile required")
    identity = run_identity()
    signal.signal(signal.SIGTERM, scheduler.stopping)
    signal.signal(signal.SIGINT, scheduler.stopping)
    started = time.monotonic()
    directory = args.out / "continuation"
    directory.mkdir()
    steps, receipts, session_dir = directory / "steps", directory / "receipts", directory / "session"
    steps.mkdir()
    receipts.mkdir()
    stages = []
    outcome = {"schema": "pon-w1-session-continuation-attempt-v2", **identity,
        "shard": args.shard, "completed_segment_indexes": [], "shard_complete": False,
        "real_composite_stark_verified": False, "partial_receipts_are_complete_proofs": False,
        "original_failure_reclassified": False, "consensus_authority": False}
    try:
        policy, manifest = source.load_policy()
        require(type(args.shard) is int and args.shard in (0, 1), "unknown fixed shard")
        files = source.original_members(policy, manifest)
        source.compare_fresh_inputs(files, Path(args.elf), Path(args.input))
        source.extract_original(files, args.out / "original")
        proof_session_dir = args.out / "original/segmented/session"
        session = source.checked_original_session(files, proof_session_dir)
        outcome.update(original=policy["origin"], budgets=policy["budgets"],
                       original_session_sha256=policy["session_sha256"],
                       segment_asset_source=policy["segment_asset_source"],
                       fresh_execution_role=policy["fresh_execution_role"],
                       selected_segment_indexes=policy["shards"][args.shard]["indexes"])
        require_runner(directory / "resources.json")
        export = scheduler.Stage(steps, "export", [args.host, "export-segments", args.r0vm,
            args.elf, args.input, "18", str(session_dir)], 300)
        stages.append(export)
        wait_stage(export)
        source.check_independent_execution(files, session_dir)
        outcome["independent_execution_sha256"] = source.sha(source.checked_bytes(session_dir / "session.json", 1024 * 1024))
        pending = list(outcome["selected_segment_indexes"])
        active = {}
        while pending or active:
            if scheduler.STOP or time.monotonic() - started >= 3500:
                raise TimeoutError("declared continuation work stopped within the original 3600s phase cap")
            while pending and len(active) < 2:
                index = pending.pop(0)
                stage = scheduler.Stage(steps, f"segment-{index}", [args.host, "prove-segment",
                    args.r0vm, str(proof_session_dir), str(index), str(receipts / f"segment-{index}.bin"),
                    str(receipts / f"segment-{index}.json")], 300, logs=True)
                stages.append(stage)
                active[index] = stage
            for index, stage in list(active.items()):
                if check_stage(stage) is None:
                    continue
                report = read(receipts / f"segment-{index}.json")
                encoded = source.checked_bytes(receipts / f"segment-{index}.bin", 2 * 1024 * 1024)
                source.check_receipt(index, session, encoded, report)
                outcome["completed_segment_indexes"].append(index)
                print(json.dumps({"completed_segment": index, "shard": args.shard,
                    "wall_seconds": stage.record["wall_seconds"],
                    "user_cpu_seconds": stage.record["user_cpu_seconds"],
                    "system_cpu_seconds": stage.record["system_cpu_seconds"],
                    "receipt_bytes": len(encoded)}), file=sys.stderr, flush=True)
                del active[index]
            time.sleep(0.025)
        require(sorted(outcome["completed_segment_indexes"]) == outcome["selected_segment_indexes"],
                "incomplete continuation shard")
        outcome["work_finished_elapsed_seconds"] = time.monotonic() - started
        require_work_finished(outcome["work_finished_elapsed_seconds"])
        outcome["shard_complete"] = True
    except BaseException as error:
        outcome["error"] = repr(error)
        raise
    finally:
        try:
            outcome["direct_children_missing_terminal"] = scheduler.cleanup(stages)
        except BaseException as error:
            outcome["cleanup_error"] = repr(error)
            raise
        finally:
            outcome["wall_seconds"] = time.monotonic() - started
            write_json(directory / "attempt.json", outcome)
    require(not outcome["direct_children_missing_terminal"], "worker closure unavailable")
    print(json.dumps(outcome), flush=True)


def indexed_files(directory):
    return source.bounded_file_index(directory)


def finalize(out):
    directory = out / "continuation"
    if not directory.is_dir():
        return
    phase = read(out / "continue.process.json")
    source.require_closed_phase(phase, False)
    write_json(out / "continuation-evidence-index.json", {
        "schema": "pon-w1-continuation-final-evidence-index-v1", "phase": phase,
        "files": indexed_files(directory), "source_sha": phase["source_sha"],
        "partial_receipts_are_complete_proofs": False, "consensus_authority": False})


def check_shard(directory, shard, policy, original, identity):
    source_id = source_identity(directory, identity)
    phase = read(directory / "continue.process.json")
    source.require_closed_phase(phase, True)
    require(phase["source_sha"] == identity["source_sha"] and phase["timeout_seconds"] == 3600,
            "continuation phase source/budget differs")
    index = read(directory / "continuation-evidence-index.json", 2 * 1024 * 1024)
    require(index["schema"] == "pon-w1-continuation-final-evidence-index-v1"
            and index["phase"] == phase and index["source_sha"] == identity["source_sha"]
            and index["files"] == indexed_files(directory / "continuation")
            and index["partial_receipts_are_complete_proofs"] is False,
            "continuation finalized evidence changed")
    outcome = read(directory / "continuation/attempt.json")
    for name, value in identity.items():
        require(outcome[name] == value, "cross-source/run/attempt continuation refused")
    selected = policy["shards"][shard]["indexes"]
    require(outcome["schema"] == "pon-w1-session-continuation-attempt-v2"
            and outcome["shard"] == shard and outcome["shard_complete"] is True
            and outcome["selected_segment_indexes"] == selected
            and sorted(outcome["completed_segment_indexes"]) == selected
            and outcome["original"] == policy["origin"] and outcome["budgets"] == policy["budgets"]
            and outcome["original_session_sha256"] == policy["session_sha256"]
            and outcome["segment_asset_source"] == policy["segment_asset_source"]
            and outcome["fresh_execution_role"] == policy["fresh_execution_role"]
            and outcome["direct_children_missing_terminal"] == []
            and "error" not in outcome and "cleanup_error" not in outcome,
            "missing/foreign/failed continuation shard")
    for key in ["real_composite_stark_verified", "partial_receipts_are_complete_proofs",
                "original_failure_reclassified", "consensus_authority"]:
        require(outcome[key] is False, "continuation scope differs")
    require_work_finished(outcome.get("work_finished_elapsed_seconds"))
    check_stage_terminal(read(directory / "continuation/steps/export.terminal.json"),
                         identity["source_sha"], 300)
    session_dir = directory / "continuation/session"
    source.check_independent_execution(original, session_dir)
    require(outcome["independent_execution_sha256"] == source.sha(source.checked_bytes(session_dir / "session.json", 1024 * 1024)),
            "independent execution record changed")
    session = source.checked_original_session(original, directory / "original/segmented/session")
    results = {}
    for i in selected:
        data = source.checked_bytes(directory / f"continuation/receipts/segment-{i}.bin", 2 * 1024 * 1024)
        report = read(directory / f"continuation/receipts/segment-{i}.json")
        source.check_receipt(i, session, data, report)
        terminal = read(directory / f"continuation/steps/segment-{i}.terminal.json")
        check_stage_terminal(terminal, identity["source_sha"], 300)
        results[i] = data
    return results, phase, source_id


def assemble(args):
    require(os.getpid() == os.getpgrp(), "assembly requires the original owned wrapper")
    signal.signal(signal.SIGTERM, scheduler.stopping)
    signal.signal(signal.SIGINT, scheduler.stopping)
    identity = run_identity()
    policy, manifest = source.load_policy()
    files = source.original_members(policy, manifest)
    source.compare_fresh_inputs(files, Path(args.elf), Path(args.input))
    source.extract_original(files, args.out / "original")
    directory = args.out / "assembly-work"
    directory.mkdir()
    receipts, steps = directory / "receipts", directory / "steps"
    receipts.mkdir()
    steps.mkdir()
    segments = {i: files[f"segmented/receipts/segment-{i}.bin"] for i in range(26)}
    observed_sources = []
    for shard in (0, 1):
        extra, _, observed = check_shard(args.out / "shards" / str(shard), shard, policy, files, identity)
        require(not set(extra).intersection(segments), "duplicate segment ownership")
        segments.update(extra)
        observed_sources.append(observed)
    current_source = read(args.out / "source-before.json")
    require(all(item == current_source for item in observed_sources), "assembly/shards source trees differ")
    require(sorted(segments) == list(range(62)), "full segment set unavailable")
    for i, data in sorted(segments.items()):
        source.write_bytes(receipts / f"segment-{i}.bin", data)
    stages = []
    try:
        stage = scheduler.Stage(steps, "assemble", [args.host, "assemble-segments", args.elf, args.input,
            str(args.out / "original/segmented/session"), str(receipts), str(args.out / "receipt.bin")], 300)
        stages.append(stage)
        wait_stage(stage)
        result = read_single_result(steps / "assemble.stdout.log", "pon-w1-segmented-assembly-v1")
        session = source.decode(files["segmented/session/session.json"])
        require(result["real_composite_stark_verified"] is True and result["segments"] == 62
                and result["image_id"] == session["image_id"]
                and result["statement_id"] == session["statement_id"]
                and result["user_cycles"] == session["user_cycles"]
                and result["assumption_receipts"] == 0 and result["povw_requested"] is False,
                "original strict full Composite verification did not succeed")
        receipt = source.checked_bytes(args.out / "receipt.bin", 128 * 1024 * 1024)
        require(result["receipt_sha256"] == source.sha(receipt) and result["receipt_bytes"] == len(receipt),
                "actual full receipt bytes differ")
        result.update(schema="pon-w1-continuation-assembly-v1", **identity,
                      original_failure_reclassified=False, consensus_authority=False,
                      additional_pow=False, fresh_generation_phases=2, reused_original_segments=26)
    finally:
        missing = scheduler.cleanup(stages)
        require(not missing, "assembly child closure unavailable")
    print(json.dumps(result), flush=True)


def optional_phase(path):
    if not path.exists():
        return {"status": "NOT_RUN_OR_UNAVAILABLE", "actual": None}
    try:
        value = read(path, 2 * 1024 * 1024)
        source.require_closed_phase(value, False)
        return {"status": "OBSERVED", "actual": value}
    except (OSError, ValueError, KeyError) as error:
        return {"status": "INVALID_OR_UNAVAILABLE", "actual": None, "error": str(error)}


def report(out):
    policy, manifest = source.load_policy()
    files = source.original_members(policy, manifest)
    phases = {"original_failed_proof": {"status": "OBSERVED", "actual": source.decode(files["prove.process.json"])}}
    for shard in (0, 1):
        phases[f"continuation_{shard}"] = optional_phase(out / "shards" / str(shard) / "continue.process.json")
    for name in ["assembly", "verify", "audit", "soundness"]:
        phases[name] = optional_phase(out / f"{name}.process.json")
    costs = {}
    for name, item in phases.items():
        phase = item["actual"]
        costs[name] = {"status": item["status"], "returncode": phase["returncode"] if phase else None,
            **{key: phase.get(key) if phase else None for key in ["wall_seconds", "user_cpu_seconds",
                "system_cpu_seconds", "max_waited_descendant_rss_kib"]}}
    success, errors, result, validation = False, [], None, None
    try:
        identity = run_identity()
        current_source = source_identity(out, identity)
        for shard in (0, 1):
            _, _, shard_source = check_shard(out / "shards" / str(shard), shard, policy, files, identity)
            require(shard_source == current_source, "report/shards source trees differ")
        from continuation_validate import phase, validate
        for name, timeout in [("assembly", 300), ("verify", 900), ("audit", 900), ("soundness", 120)]:
            require(phases[name]["actual"] is not None, f"{name} not observed")
            checked = phase(out, name, identity["source_sha"])
            require(checked == phases[name]["actual"] and checked["timeout_seconds"] == timeout,
                    f"{name} phase changed or original budget differs")
        check_stage_terminal(read(out / "assembly-work/steps/assemble.terminal.json"),
                             identity["source_sha"], 300)
        result = read_single_result(out / "assembly.stdout.log", "pon-w1-continuation-assembly-v1")
        require(result["real_composite_stark_verified"] is True, "complete proof not verified")
        require(all(result.get(name) == value for name, value in identity.items()),
                "assembly result came from a different source/run/attempt")
        require(result.get("original_failure_reclassified") is False
                and result.get("consensus_authority") is False and result.get("additional_pow") is False
                and result.get("fresh_generation_phases") == 2 and result.get("reused_original_segments") == 26,
                "assembly result scope differs")
        receipt = source.checked_bytes(out / "receipt.bin", 128 * 1024 * 1024)
        require(result["receipt_bytes"] == len(receipt) and result["receipt_sha256"] == source.sha(receipt),
                "report full receipt bytes changed")
        # The existing strict verifier/audit logs must contain actual positive
        # and negative outcomes; exit status alone is not a successful audit.
        validation = validate(out, result, identity["source_sha"])
        success = True
    except (OSError, ValueError, KeyError, RuntimeError, ImportError) as error:
        errors.append(repr(error))
    proving = [costs[name] for name in ["original_failed_proof", "continuation_0", "continuation_1", "assembly"]]
    complete_cost = all(item["status"] == "OBSERVED" for item in proving)
    observed = [item for item in proving if item["status"] == "OBSERVED"]
    cpu = sum(item["user_cpu_seconds"] + item["system_cpu_seconds"] for item in observed)
    wall = sum(item["wall_seconds"] for item in observed)
    value = {"schema": "pon-w1-continuation-cost-observation-v1", "original": policy["origin"],
        "complete_proof_and_audit_observed": success, "errors": errors, "phase_costs": costs,
        "complete_generation_cost_observed": complete_cost,
        "generation_cpu_seconds_including_original_failure": cpu if complete_cost else None,
        "generation_cumulative_independent_phase_wall_seconds": wall if complete_cost else None,
        "known_generation_cpu_seconds_subtotal": cpu,
        "known_generation_phase_wall_seconds_subtotal": wall,
        "wall_scope": "sum of separately measured phases, not parallel critical-path elapsed time",
        "cpu_scope": "outer wait4 child-family totals exactly once; per-segment costs are not added again",
        "memory_scope": "per-phase maximum waited-descendant RSS; neither physical memory nor summed concurrent peak",
        "build_and_control_costs_included_in_generation": False,
        "loopback_cost_scope": "separate loopback observation after this report; no WAN or gossip qualification",
        "assembly_result": result, "actual_validation": validation, "original_failure_reclassified": False,
        "global_worst_invalid_input_proven": False, "quantum_128_security_claimed": False,
        "public_ingress_qualified": False, "consensus_authority": False}
    write_json(out / "continuation-costs.json", value)
    print(json.dumps(value), flush=True)
    require(success, "continuation incomplete or unverified; all observed failures retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["select", "prove", "finalize", "assemble", "report"])
    parser.add_argument("--out", type=Path)
    parser.add_argument("--shard", type=int)
    for name in ["host", "r0vm", "elf", "input"]:
        parser.add_argument("--" + name)
    args = parser.parse_args()
    if args.operation == "select":
        select()
        return
    require(args.out is not None, "output directory required")
    if args.operation in ("prove", "assemble"):
        require(all([args.host, args.elf, args.input]), "real native host, fresh image and input required")
    if args.operation == "prove":
        require(args.r0vm is not None, "actual pinned r0vm required")
        prove(args)
    elif args.operation == "assemble":
        assemble(args)
    elif args.operation == "finalize":
        finalize(args.out)
    elif args.operation == "report":
        report(args.out)


if __name__ == "__main__":
    main()
