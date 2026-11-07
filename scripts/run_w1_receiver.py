#!/usr/bin/env python3
"""Independent complete-W1 receiver process with immutable ACK and cancellation veto.

Transport is performed by the caller. A saved ACK is a verification observation;
its process must also return cleanly under the sender's original deadline before
the sender may count completion. This command does not implement Node admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import time

import run_w1_deployment_comparison as comparison

measure = comparison.measure
SCHEMA = "TRNM-W1-RECEIVER-ACK2"


def execute(args):
    entered = time.monotonic_ns()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not math.isfinite(args.wall_seconds) or not 0 < args.wall_seconds <= 7200:
        raise ValueError("finite bounded receiver wall time required")
    if (args.deadline_monotonic is None) != (args.deadline_boot_id is None):
        raise ValueError("original local deadline and boot ID are a pair")
    if args.deadline_boot_id is not None and args.deadline_boot_id != boot:
        raise ValueError("receiver cannot interpret a different host/boot monotonic deadline")
    deadline = entered / 1e9 + args.wall_seconds
    if args.deadline_monotonic is not None:
        if not math.isfinite(args.deadline_monotonic):
            raise ValueError("finite original deadline required")
        deadline = min(deadline, args.deadline_monotonic)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    paths = {name: getattr(args, name).resolve() for name in ("verifier", "receipt", "header", "expected_artifacts")}
    identities = {name + "_sha256": measure.sha(path) for name, path in paths.items()}
    if identities["verifier_sha256"] != args.verifier_sha256:
        raise ValueError("receiver verifier executable identity mismatch")
    if paths["header"].stat().st_size != 318 or paths["expected_artifacts"].stat().st_size != 64:
        raise ValueError("receiver requires independent exact header and A/B commitments")
    statement = {"schema": "TRNM-W1-INDEPENDENT-RECEIVER-STATEMENT2",
                 "header_sha256": identities["header_sha256"],
                 "expected_artifacts_sha256": identities["expected_artifacts_sha256"],
                 "verifier_profile": comparison.PROFILE}
    statement_hash = hashlib.sha256(json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    intent = {"schema": SCHEMA, "statement": statement, "statement_sha256": statement_hash,
              "identities": identities, "entered_monotonic_ns": entered,
              "effective_deadline_monotonic": deadline, "deadline_boot_id": boot,
              "sender_original_local_deadline_supplied": args.deadline_monotonic is not None,
              "pid": os.getpid(), "hostname": os.uname().nodename,
              "cgroup_membership": Path("/proc/self/cgroup").read_text(),
              "resource_scope_complete": False, "node_admission": False}
    measure.write_new(out / "intent.json", intent)
    stage = value = work_id = None
    verified = False
    failure = None
    try:
        command = [str(paths[name]) for name in ("verifier", "receipt", "header", "expected_artifacts")]
        stage = measure.measure(command, out / "verify", args.wall_seconds, deadline=deadline)
        if stage.get("stage_process_complete") is not True:
            if stage.get("timed_out") or time.monotonic() >= deadline:
                raise TimeoutError("receiver verifier missed its original effective deadline")
            raise ValueError("receiver verifier did not exit cleanly")
        value = comparison.read_json(out / "verify/stdout.log")
        work_id, _ = comparison.validate_observation("proof", stage, value, identities, None)
        if any(measure.sha(path) != identities[name + "_sha256"] for name, path in paths.items()):
            raise ValueError("receiver fixed input or executable bytes changed")
        verified = True
        if time.monotonic() >= deadline:
            raise TimeoutError("receiver completion missed original effective deadline")
    except BaseException as caught:
        failure = caught
        saved = getattr(caught, "observed_snapshot", None)
        if stage is None and saved and saved.get("kind") == "stage":
            stage = saved["value"]
        # Preserve an actual successful verifier exit observed before a later
        # cancellation. This fact never changes the canceled operation to success.
        if stage is not None and not verified:
            try:
                candidate = comparison.read_json(out / "verify/stdout.log")
                candidate_work, _ = comparison.validate_observation("proof", stage, candidate, identities, None)
                if any(measure.sha(path) != identities[name + "_sha256"] for name, path in paths.items()):
                    raise ValueError("saved verified bytes changed")
                verified, value, work_id = True, candidate, candidate_work
            except Exception:
                pass
    try:
        prior = failure if isinstance(failure, (measure.Canceled, KeyboardInterrupt)) else None
        with measure.DeferredCancellation(prior, phase="receiver-ack-publication", live_deadline=(deadline, boot)) as handoff:
            complete = verified and failure is None and time.monotonic() < deadline and handoff.canceled_signal is None
            report = {**intent, **identities, "verified": verified,
                      "receiver_operation_complete": complete, "work_id": work_id,
                      "verifier_report": value, "stage": stage,
                      "ack_snapshot_monotonic_ns": time.monotonic_ns(),
                      "deadline_exhausted_at_snapshot": time.monotonic() >= deadline,
                      "cancellation_event": handoff.pending_event(),
                      "error": None if failure is None else {"type": type(failure).__name__, "message": str(failure)},
                      "admission_authorized": False, "production_qualified": False,
                      "transport_measurement_authority": "sender original clock; receiver clocks are not subtracted across hosts"}
            # Failure observations use a different filename; no negative or
            # incomplete execution can create the successful-ACK filename.
            target = out / ("ack.json" if complete else "failure.json")
            measure.write_new(target, report)
            handoff.published_snapshot("receiver", target)
    except (measure.Canceled, KeyboardInterrupt) as canceled:
        measure.publish_cancellation(out / "operation-cancellation.json", canceled, "independent-receiver")
    if failure is not None:
        raise failure
    if not report["receiver_operation_complete"] or time.monotonic() >= deadline:
        raise TimeoutError("receiver ACK did not complete before the original effective deadline")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "receipt", "header", "expected-artifacts", "out"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--wall-seconds", type=float, default=60)
    parser.add_argument("--deadline-monotonic", type=float)
    parser.add_argument("--deadline-boot-id")
    args = parser.parse_args(argv)
    with measure.cancel_on_signals():
        result = execute(args)
    print(json.dumps({"schema": SCHEMA, "verified": result["verified"],
                      "receiver_operation_complete": result["receiver_operation_complete"],
                      "work_id": result["work_id"], "admission_authorized": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(measure.run_cli(main))
