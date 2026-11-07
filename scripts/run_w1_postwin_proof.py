#!/usr/bin/env python3
"""Run the full backend and receiver after a fixed native winner event.

The native event, its input, and its Linux boot/deadline are selected by the
caller before funded generation dispatch. A new invocation never extends that
deadline. Publication observations and settlement/admission authority are separate.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import sys
import time

import run_w1_deployment_comparison as comparison

measure = comparison.measure
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "TRNM-W1-POSTWIN-PROOF2"
# The nested controller owns a five-second TERM grace plus reap/report work.
# This is settlement time, never an extension of the native winner deadline.
CONTROLLER_TERMINATION_GRACE_SECONDS = 12


def read_object(path, maximum=8 * 1024 * 1024):
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("bounded full-path observation exceeded")
    value = json.loads(raw, object_pairs_hook=comparison.strict_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if type(value) is not dict:
        raise ValueError("object observation required")
    return value


def winner_identity(directory, now_ns, boot):
    value = read_object(directory / "result.json")
    intent = read_object(directory / "intent.json")
    if (value.get("schema") != "TRNM-W1-NATIVE-WINNER2"
            or intent.get("schema") != value["schema"]
            or value.get("winner_observed") is not True
            or value.get("native_replay_verified") is not True
            or value.get("native_ticket_before_deadline") is not True
            or value.get("winner_saved_before_deadline") is not True
            or value.get("node_admission") is not False):
        raise ValueError("actual complete native winner observation required")
    for key in ("original_deadline_monotonic_ns", "original_deadline_boot_id"):
        if value.get(key) != intent.get(key):
            raise ValueError("native original deadline changed between intent and result")
    if value["original_deadline_boot_id"] != boot:
        raise ValueError("native winner belongs to a different boot; no deadline rebasing")
    clock_keys = ("native_winner_monotonic_ns", "winner_saved_monotonic_ns", "original_deadline_monotonic_ns")
    if any(type(value.get(k)) is not int for k in clock_keys):
        raise ValueError("integer native clock observations required")
    winner, saved, deadline = (value[k] for k in clock_keys)
    if not 0 <= winner <= saved <= now_ns < deadline or deadline - now_ns > 7_200_000_000_000:
        raise ValueError("native event time order or original remaining budget invalid")
    for name, key in (("input.bin", "input_sha256"), ("header.bin", "header_sha256"),
                      ("expected-artifacts.bin", "expected_artifacts_sha256")):
        if measure.sha(directory / name) != value.get(key):
            raise ValueError("native winner input changed")
    if value["expected_artifacts_sha256"] != intent.get("expected_artifacts_sha256"):
        raise ValueError("winner commitments differ from pre-search independent selection")
    with (directory / "input.bin").open("rb") as stream:
        header = stream.read(318)
    if header != (directory / "header.bin").read_bytes():
        raise ValueError("native winner full input and independent header disagree")
    return value



def capture_winner_identity(directory, now_ns, boot):
    """Bind the exact caller-selected original records, without authenticating them."""
    before = {name: measure.sha(directory / name) for name in ("result.json", "intent.json")}
    winner = winner_identity(directory, now_ns, boot)
    after = {name: measure.sha(directory / name) for name in before}
    if after != before:
        raise ValueError("native winner records changed during initial identity capture")
    return winner, before


def require_unchanged_winner(directory, winner, original_records, now_ns, boot):
    current, records = capture_winner_identity(directory, now_ns, boot)
    if current != winner or records != original_records:
        raise ValueError("original native winner or pre-search intent changed")
    return current


def execute(args):
    entered = time.monotonic_ns()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    native_dir = args.winner_dir.resolve()
    winner, winner_records = capture_winner_identity(native_dir, entered, boot)
    deadline_ns = winner["original_deadline_monotonic_ns"]
    deadline = deadline_ns / 1e9
    if args.segment_workers not in range(1, 5) or args.compression_workers not in range(1, 5):
        raise ValueError("bounded research worker count required")
    if args.rayon_threads < 1 or max(args.segment_workers, args.compression_workers) * args.rayon_threads > 8:
        raise ValueError("research request must remain within eight requested CPU threads")
    if args.compression_mode == "sequential" and args.compression_workers != 1:
        raise ValueError("sequential compression has exactly one requested worker")
    if not 0 <= args.comparison_repeats <= 250:
        raise ValueError("bounded ABBA repetition count required")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    programs = {name: getattr(args, name).resolve() for name in ("runner", "r0vm", "verifier")}
    for name, path in programs.items():
        if measure.sha(path) != getattr(args, name + "_sha256"):
            raise ValueError("selected executable digest mismatch: " + name)
    checkpoint = out / "checkpoint"
    receiver_out = out / "receiver"
    env = {"RAYON_NUM_THREADS": str(args.rayon_threads)}
    intent = {"schema": SCHEMA, "entered_monotonic_ns": entered,
              "winner_record_path": str(native_dir / "result.json"),
              "winner_record_sha256": winner_records["result.json"],
              "winner_intent_path": str(native_dir / "intent.json"),
              "winner_intent_sha256": winner_records["intent.json"],
              "winner": winner, "original_deadline_monotonic_ns": deadline_ns,
              "original_deadline_boot_id": boot, "requested_segment_workers": args.segment_workers,
              "compression_mode": args.compression_mode,
              "requested_compression_workers": args.compression_workers,
              "requested_rayon_threads_per_worker": args.rayon_threads,
              "controller_termination_grace_seconds": CONTROLLER_TERMINATION_GRACE_SECONDS,
              "programs": {name: {"path": str(path), "sha256": getattr(args, name + "_sha256")}
                           for name, path in programs.items()},
              "cgroup_membership": Path("/proc/self/cgroup").read_text(),
              "resource_scope_complete": False, "original_business_budget_reproduced": False,
              "native_event_provenance_authority": "caller retained actual native process identity and event; JSON alone is not authentication",
              "admission_authorized": False, "production_qualified": False}
    measure.write_new(out / "intent.json", intent)
    stages, controller, abba, failure = [], None, None, None

    def stage(label, command, *, termination_grace_seconds=measure.TERMINATION_GRACE_SECONDS):
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError("original native winner deadline exhausted before " + label)
        row = {"label": label, "dispatched": True, "stage": None}
        stages.append(row)
        try:
            row["stage"] = measure.measure(list(map(str, command)), out / label,
                min(7200., max(.001, deadline - time.monotonic())), deadline=deadline,
                environment_overrides=env, termination_grace_seconds=termination_grace_seconds)
        except BaseException as caught:
            saved = getattr(caught, "observed_snapshot", None)
            if saved and saved.get("kind") == "stage":
                row["stage"] = saved["value"]
            row["error"] = {"type": type(caught).__name__, "message": str(caught)}
            raise
        if row["stage"].get("stage_process_complete") is not True:
            raise ValueError("owned stage did not complete: " + label)

    try:
        # Independently replay the selected statement before dispatching the
        # expensive backend. This uses the same original winner deadline.
        stage("native-statement-recheck", [programs["verifier"], "--native-once", native_dir / "input.bin",
              native_dir / "header.bin", native_dir / "expected-artifacts.bin"])
        native_report = read_object(out / "native-statement-recheck/stdout.log")
        compare_ids = {k: winner[k] for k in ("input_sha256", "header_sha256", "expected_artifacts_sha256")}
        work_id, _ = comparison.validate_observation("native", stages[-1]["stage"], native_report, compare_ids, None)
        hook = {"schema": "TRNM-W1-COMPLETION-HOOK1", "ack_path": str(receiver_out / "ack.json"),
                "argv": [sys.executable, str(ROOT / "scripts/run_w1_receiver.py"),
                         "--verifier", str(programs["verifier"]), "--verifier-sha256", args.verifier_sha256,
                         "--receipt", str(checkpoint / "succinct.bin"), "--header", str(native_dir / "header.bin"),
                         "--expected-artifacts", str(native_dir / "expected-artifacts.bin"),
                         "--out", str(receiver_out), "--wall-seconds", "7200",
                         "--deadline-monotonic", repr(deadline), "--deadline-boot-id", boot]}
        measure.write_new(out / "completion-hook.json", hook)
        command = [sys.executable, ROOT / "formal/pon-nakamoto-v1/experiments/w1_full_staged_run.py",
                   "--runner", programs["runner"], "--r0vm", programs["r0vm"],
                   "--checkpoint", checkpoint, "--out", out / "controller",
                   "--prepare-input", native_dir / "input.bin", "--statement-version", "2",
                   "--expected-artifacts", native_dir / "expected-artifacts.bin",
                   "--fresh-verifier", programs["verifier"], "--native-verifier", programs["verifier"],
                   "--total-wall-seconds", "7200", "--deadline-monotonic", repr(deadline),
                   "--deadline-boot-id", boot, "--segment-workers", str(args.segment_workers),
                   "--compression-mode", args.compression_mode,
                   "--compression-workers", str(args.compression_workers), "--rayon-threads", str(args.rayon_threads),
                   "--completion-hook-json", out / "completion-hook.json"]
        stage("complete-controller", command,
              termination_grace_seconds=CONTROLLER_TERMINATION_GRACE_SECONDS)
        controller = read_object(out / "controller/result.json")
        if (controller.get("schema") != "TRNM-W1-COMPLETE-STAGED-RUN3"
                or controller.get("complete_proof_claim") is not True
                or controller.get("end_to_end_observation_complete") is not True
                or controller.get("error") is not None):
            raise ValueError("full controller lacks a complete eligible observation")
        ack = read_object(receiver_out / "ack.json")
        if (ack.get("schema") != "TRNM-W1-RECEIVER-ACK2" or ack.get("verified") is not True
                or ack.get("receiver_operation_complete") is not True
                or ack.get("work_id") != work_id or ack.get("admission_authorized") is not False
                or (receiver_out / "operation-cancellation.json").exists()):
            raise ValueError("independent receiver has no eligible final acknowledgement")
        for key in ("header_sha256", "expected_artifacts_sha256"):
            if ack.get(key) != winner[key]:
                raise ValueError("receiver acknowledged another winner statement")
        if ack.get("receipt_sha256") != measure.sha(checkpoint / "succinct.bin"):
            raise ValueError("receiver acknowledged different receipt bytes")
        observed_ack = controller.get("parent_observed_receiver_ack_monotonic_ns")
        if (controller.get("parent_observed_receiver_ack_boot_id") != boot
                or type(observed_ack) is not int
                or not winner["native_winner_monotonic_ns"] <= observed_ack <= time.monotonic_ns() < deadline_ns):
            raise ValueError("receiver completion lacks an original-clock observation under the original deadline")
        if args.comparison_repeats:
            stage("deployment-comparison", [sys.executable, ROOT / "scripts/run_w1_deployment_comparison.py",
                  "--verifier", programs["verifier"], "--verifier-sha256", args.verifier_sha256,
                  "--receipt", checkpoint / "succinct.bin", "--input", native_dir / "input.bin",
                  "--header", native_dir / "header.bin", "--expected-artifacts", native_dir / "expected-artifacts.bin",
                  "--out", out / "abba", "--repeats", str(args.comparison_repeats), "--wall-seconds", "7200",
                  "--deadline-monotonic", repr(deadline), "--deadline-boot-id", boot])
            abba = read_object(out / "abba/result.json")
            if abba.get("operation_complete") is not True:
                raise ValueError("final ABBA comparison did not complete")
        require_unchanged_winner(native_dir, winner, winner_records, time.monotonic_ns(), boot)
        if any(measure.sha(path) != getattr(args, name + "_sha256") for name, path in programs.items()):
            raise ValueError("selected executable bytes changed during full pipeline")
    except BaseException as caught:
        failure = caught
        if controller is None and (out / "controller/result.json").is_file():
            try:
                controller = read_object(out / "controller/result.json")
            except Exception:
                pass
    try:
        prior = failure if isinstance(failure, (measure.Canceled, KeyboardInterrupt)) else None
        with measure.DeferredCancellation(prior, phase="postwin-final-publication", live_deadline=(deadline, boot)) as handoff:
            complete = failure is None and handoff.canceled_signal is None and time.monotonic_ns() < deadline_ns
            observed_ack = controller.get("parent_observed_receiver_ack_monotonic_ns") if controller else None
            valid_clock = (controller is not None and controller.get("parent_observed_receiver_ack_boot_id") == boot
                           and type(observed_ack) is int
                           and winner["native_winner_monotonic_ns"] <= observed_ack <= time.monotonic_ns()
                           and observed_ack < deadline_ns)
            report = {**intent, "stages": stages, "operation_complete": complete,
                      "deadline_exhausted_at_snapshot": time.monotonic_ns() >= deadline_ns,
                      "error": None if failure is None else {"type": type(failure).__name__, "message": str(failure)},
                      "cancellation_event": handoff.pending_event(),
                      "full_proof_verified_observed": bool(controller and controller.get("complete_proof_claim") is True),
                      "parent_observed_receiver_ack_monotonic_ns": observed_ack,
                      "winner_to_receiver_seconds": (observed_ack - winner["native_winner_monotonic_ns"]) / 1e9 if valid_clock else None,
                      "winner_latency_scope": "native ticket hit through caller-clock independent receiver process completion; build before winner excluded",
                      "controller_result": ({"path": str(out / "controller/result.json"),
                                             "sha256": measure.sha(out / "controller/result.json")}
                                            if controller else None),
                      "comparison": abba, "prover_population_p99_established": False,
                      "node_admission_seconds": None, "production_qualified": False}
            measure.write_new(out / "result.json", report)
            handoff.published_snapshot("postwin", out / "result.json")
    except (measure.Canceled, KeyboardInterrupt) as canceled:
        measure.publish_cancellation(out / "operation-cancellation.json", canceled, "native-winner-postwin-proof")
    if failure is not None:
        raise failure
    if not report["operation_complete"] or time.monotonic_ns() >= deadline_ns:
        raise TimeoutError("postwin operation did not finish before original deadline")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--winner-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    for name in ("runner", "r0vm", "verifier"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--segment-workers", type=int, default=2)
    parser.add_argument("--compression-mode", choices=("sequential", "balanced"), default="balanced")
    parser.add_argument("--compression-workers", type=int, default=2)
    parser.add_argument("--rayon-threads", type=int, default=4)
    parser.add_argument("--comparison-repeats", type=int, default=10)
    args = parser.parse_args(argv)
    with measure.cancel_on_signals():
        report = execute(args)
    print(json.dumps({"schema": SCHEMA, "operation_complete": report["operation_complete"],
                      "full_proof_verified_observed": report["full_proof_verified_observed"],
                      "winner_to_receiver_seconds": report["winner_to_receiver_seconds"],
                      "admission_authorized": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(measure.run_cli(main))
