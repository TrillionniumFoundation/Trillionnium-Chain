#!/usr/bin/env python3
"""Matched cold-process ABBA observations for one fixed complete W1 v2 claim.

Each A executes one full native replay; each B executes one independent complete
receipt verification. Repeated verification of a receipt is never another proof
generation sample. The caller supplies an independently selected header and A/B
commitments, plus the exact qualified verifier binary digest.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "w1_comparison_measure", ROOT / "formal/pon-nakamoto-v1/experiments/w1_stage_measure.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)

SCHEMA = "TRNM-W1-DEPLOYMENT-COMPARISON2"
PROFILE = "trnm-w1-risc0-3.0.6-poseidon2-join-v2"
MAX_JSON = 1 << 20


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_JSON + 1)
    if len(data) > MAX_JSON:
        raise ValueError("JSON report exceeds limit")
    value = json.loads(data, object_pairs_hook=strict_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return value


def plan(repeats):
    if type(repeats) is not int or not 1 <= repeats <= 250:
        raise ValueError("ABBA repeats must be in 1..250")
    return [kind for _ in range(repeats) for kind in ("native", "proof", "proof", "native")]


def distribution(values):
    if not values or any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("nonempty finite nonnegative measurements required")
    ordered = sorted(values)
    def percentile(p):
        return ordered[max(0, math.ceil(p * len(ordered)) - 1)]
    return {"count": len(values), "median": statistics.median(values),
            "p95_nearest_rank": percentile(.95), "p99_nearest_rank": percentile(.99),
            "minimum": ordered[0], "maximum": ordered[-1],
            "scope": "descriptive repeated verification of this fixed claim on this host"}


def validate_observation(kind, stage, value, identities, reference_work_id):
    if (stage.get("schema") != "TRNM-W1-STAGE-MEASUREMENT3"
            or stage.get("stage_process_complete") is not True
            or stage.get("returncode") != 0 or stage.get("error") is not None
            or stage.get("canceled_signal") is not None
            or stage.get("cancellation_event") is not None
            or stage.get("termination_reasons") != []
            or stage.get("deadline_exhausted_at_snapshot") is not False
            or stage.get("owned_session_observation_complete") is not True):
        raise ValueError("verifier process has no eligible terminal observation")
    expected_schema = "TRNM-W1-V2-NATIVE-ONCE1" if kind == "native" else "TRNM-W1-V2-FULL-VERIFY1"
    if (value.get("schema") != expected_schema or value.get("profile_id") != PROFILE
            or type(value.get("iterations")) is not int or value["iterations"] != 1
            or value.get("admission_authorized") is not False
            or value.get("header_sha256") != identities["header_sha256"]
            or value.get("expected_artifacts_sha256") != identities["expected_artifacts_sha256"]):
        raise ValueError("independent verifier profile or statement mismatch")
    work_id = value.get("work_id")
    if (not isinstance(work_id, str) or len(work_id) != 64
            or any(c not in "0123456789abcdef" for c in work_id)
            or reference_work_id is not None and work_id != reference_work_id):
        raise ValueError("work identity changed")
    journal_hash = value.get("journal_sha256")
    if (not isinstance(journal_hash, str) or len(journal_hash) != 64
            or any(c not in "0123456789abcdef" for c in journal_hash)
            or "journal_sha256" in identities and journal_hash != identities["journal_sha256"]):
        raise ValueError("complete public journal identity changed")
    identities.setdefault("journal_sha256", journal_hash)
    if kind == "native":
        if (type(value.get("full_replay_calls")) is not int or value["full_replay_calls"] != 1
                or value.get("input_sha256") != identities["input_sha256"]):
            raise ValueError("native comparison must execute exactly one matching full replay")
        timings = value.get("full_native_verify_ns")
    else:
        if (value.get("receipt_sha256") != identities["receipt_sha256"]
                or value.get("independent_proof_trials") != 1):
            raise ValueError("receipt identity mismatch")
        timings = value.get("decode_and_verify_ns")
    if (type(timings) is not list or len(timings) != 1
            or type(timings[0]) is not int or timings[0] <= 0):
        raise ValueError("one positive integer verification duration required")
    return work_id, timings[0]


def summary(rows, planned, identities, error, deadline, started, resource_record):
    complete = (error is None and len(rows) == len(planned)
                and all(row.get("accepted") is True for row in rows)
                and time.monotonic() < deadline)
    report = {"schema": SCHEMA, "started_monotonic": started,
              "original_deadline_monotonic": deadline, "finished_unix_ns": time.time_ns(),
              "original_deadline_clock_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              "operation_complete": complete, "deadline_exhausted_at_snapshot": time.monotonic() >= deadline,
              "planned_order": planned, "rows": rows, "identities": identities,
              "error": error, "resource_observation": resource_record,
              "independent_receipts": 1, "fresh_proof_generations": 0,
              "tail_scope": "verification repetitions only; no population winner/prover tail estimate",
              "original_business_budget_reproduced": False,
              "cryptographic_security_qualified": False, "admission_authorized": False,
              "production_qualified": False, "cost_comparison": None}
    if complete:
        groups = {kind: [r for r in rows if r["kind"] == kind] for kind in ("native", "proof")}
        cost = {}
        for kind, selected in groups.items():
            cost[kind] = {
                "cold_process_wall_seconds": distribution([r["stage"]["wall_seconds"] for r in selected]),
                "verifier_inner_ns": distribution([r["inner_ns"] for r in selected]),
                "wait4_cpu_seconds": distribution([
                    r["stage"]["rusage"]["user_seconds"] + r["stage"]["rusage"]["system_seconds"]
                    for r in selected]),
            }
        cost["proof_over_native_inner_median"] = (cost["proof"]["verifier_inner_ns"]["median"]
                                                     / cost["native"]["verifier_inner_ns"]["median"])
        cost["proof_over_native_cold_wall_median"] = (cost["proof"]["cold_process_wall_seconds"]["median"]
                                                         / cost["native"]["cold_process_wall_seconds"]["median"])
        cost["receipt_over_native_payload_bytes"] = identities["receipt_bytes"] / identities["input_bytes"]
        cost["verification_inner_benefit_observed"] = cost["proof_over_native_inner_median"] < 1
        cost["cold_process_benefit_observed"] = cost["proof_over_native_cold_wall_median"] < 1
        cost["payload_byte_benefit_observed"] = cost["receipt_over_native_payload_bytes"] < 1
        report["cost_comparison"] = cost
    return report


def execute(args):
    planned = plan(args.repeats)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if (args.deadline_monotonic is None) != (args.deadline_boot_id is None):
        raise ValueError("deadline and original clock boot identity must be supplied together")
    if args.deadline_boot_id is not None and args.deadline_boot_id != boot_id:
        raise ValueError("deadline belongs to another boot clock")
    deadline = min(started + args.wall_seconds, args.deadline_monotonic) if args.deadline_monotonic is not None else started + args.wall_seconds
    if not math.isfinite(deadline) or not 0 < args.wall_seconds <= 7200:
        raise ValueError("finite bounded deadline required")
    paths = {name: getattr(args, name).resolve() for name in ("verifier", "receipt", "input", "header", "expected_artifacts")}
    identities = {name + "_sha256": measure.sha(path) for name, path in paths.items()}
    identities.update({name + "_bytes": path.stat().st_size for name, path in paths.items()})
    if identities["verifier_sha256"] != args.verifier_sha256:
        raise ValueError("qualified verifier binary digest mismatch")
    if identities["header_bytes"] != 318 or identities["expected_artifacts_bytes"] != 64:
        raise ValueError("independent full header and A/B commitment lengths required")
    resource_record = {"hostname": os.uname().nodename, "boot_id": boot_id,
                       "cpu_affinity": sorted(os.sched_getaffinity(0)),
                       "cgroup_membership": Path("/proc/self/cgroup").read_text(),
                       "task_exclusive_resource_ownership_established": False,
                       "same_supervisor": True, "same_verifier_binary": True,
                       "same_original_deadline_supplied": args.deadline_monotonic is not None}
    measure.write_new(out / "intent.json", {"schema": SCHEMA, "planned_order": planned,
                      "identities": identities, "deadline_monotonic": deadline,
                      "deadline_boot_id": boot_id, "resource_observation": resource_record})
    rows, reference_work_id, error, failure = [], None, None, None
    try:
        for index, kind in enumerate(planned):
            if time.monotonic() >= deadline:
                raise TimeoutError("original comparison deadline exhausted")
            if any(measure.sha(path) != identities[name + "_sha256"] for name, path in paths.items()):
                raise ValueError("fixed comparison source bytes changed")
            argv = [str(paths["verifier"])]
            argv += (["--native-once", str(paths["input"])] if kind == "native" else [str(paths["receipt"])])
            argv += [str(paths["header"]), str(paths["expected_artifacts"])]
            row = {"index": index, "kind": kind, "dispatched": True, "accepted": False,
                   "stage": None, "observation_error": None}
            rows.append(row)
            try:
                stage = measure.measure(argv, out / f"row-{index:04d}-{kind}",
                                        min(7200., max(.001, deadline - time.monotonic())), deadline=deadline)
                row["stage"] = stage
                value = read_json(out / f"row-{index:04d}-{kind}/stdout.log")
                reference_work_id, inner = validate_observation(kind, stage, value, identities, reference_work_id)
                if any(type(stage["rusage"].get(k)) not in (int, float) for k in ("user_seconds", "system_seconds")):
                    raise ValueError("wait4 CPU observation unavailable")
                row.update(accepted=True, verifier_report=value, inner_ns=inner)
            except BaseException as caught:
                row["observation_error"] = {"type": type(caught).__name__, "message": str(caught)}
                snapshot = getattr(caught, "observed_snapshot", None)
                if row["stage"] is None and snapshot and snapshot.get("kind") == "stage":
                    row["stage"] = snapshot["value"]
                    row["saved_stage_snapshot"] = {k: snapshot[k] for k in ("schema", "kind", "path", "sha256")}
                raise
            finally:
                primary = sys.exc_info()[1]
                prior_cancel = primary if isinstance(primary, (measure.Canceled, KeyboardInterrupt)) else None
                with measure.DeferredCancellation(prior_cancel, phase="comparison-row-publication", live_deadline=(deadline, boot_id)) as handoff:
                    measure.write_new(out / f"row-{index:04d}-observation.json", row)
                    handoff.published_snapshot("comparison-row", out / f"row-{index:04d}-observation.json")
    except BaseException as caught:
        failure = caught
        error = {"type": type(caught).__name__, "message": str(caught)}
    try:
        prior_cancel = failure if isinstance(failure, (measure.Canceled, KeyboardInterrupt)) else None
        with measure.DeferredCancellation(prior_cancel, phase="comparison-final-publication", live_deadline=(deadline, boot_id)) as handoff:
            report = summary(rows, planned, identities, error, deadline, started, resource_record)
            if handoff.canceled_signal is not None:
                report["operation_complete"] = False
                report["cancellation_event"] = handoff.pending_event()
                report["cost_comparison"] = None
            measure.write_new(out / "result.json", report)
            handoff.published_snapshot("comparison", out / "result.json")
    except (measure.Canceled, KeyboardInterrupt) as canceled:
        measure.publish_cancellation(out / "operation-cancellation.json", canceled, "deployment-comparison")
    if failure is not None:
        raise failure
    if not report["operation_complete"] or time.monotonic() >= deadline:
        raise TimeoutError("comparison did not complete under its original deadline")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "receipt", "input", "header", "expected-artifacts", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--wall-seconds", type=float, default=600)
    parser.add_argument("--deadline-monotonic", type=float)
    parser.add_argument("--deadline-boot-id")
    args = parser.parse_args(argv)
    with measure.cancel_on_signals():
        result = execute(args)
    print(json.dumps({"schema": SCHEMA, "operation_complete": result["operation_complete"],
                      "cost_comparison": result["cost_comparison"], "admission_authorized": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(measure.run_cli(main))
