"""Derive phase counts from the exact retained original campaign ZIP; no native execution."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

EXPECTED = "9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e"
archive = Path(sys.argv[1])
with archive.open("rb") as stream:
    observed_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if observed_digest != EXPECTED:
        raise SystemExit("refusing an archive with a different SHA256")
rows = []
pins = []
with zipfile.ZipFile(archive) as bundle:
    for run in range(1, 4):
        name = f"run-{run}-raw/report.json"
        raw = bundle.read(name)
        pins.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        report = json.loads(raw)
        for phase in report["phases"]:
            submissions = phase["submissions"]
            honest_bodies = {s["public_request_body_digest"] for s in submissions}
            receiver = phase["receiver_observation"]
            accepted_records = [r for r in receiver["records"] if r["full_work_accepted"] is True]
            matched_accepted = [r for r in accepted_records if bytes(r["body_digest"]).hex() in honest_bodies]
            unacknowledged = []
            for submission in submissions:
                if submission["status"] == "ok" and submission.get("response", {}).get("ok") is True and submission["returned_after_window"] is False:
                    continue
                matching = [r for r in receiver["records"] if bytes(r["body_digest"]).hex() == submission["public_request_body_digest"]]
                unacknowledged.append({
                    "height": submission["height"], "status": submission["status"],
                    "error": submission.get("error"), "returned_after_window": submission["returned_after_window"],
                    "matched_receiver_records": len(matching),
                    "full_work_accepted": [r["full_work_accepted"] for r in matching],
                    "dispatch_accepted": [r["dispatch_accepted"] for r in matching],
                    "durable_or_external_effect_inferred": False,
                })
            history = phase["history"]
            imports = [h["client_import"] for h in history if h.get("client_import") is not None]
            confirmations = [c for c in phase["confirmations"] if c["confirmed_inside_pressure_window"] is True]
            errors = {}
            for imp in imports:
                if imp["succeeded"] is False:
                    error = str(imp["error"])
                    errors[error] = errors.get(error, 0) + 1
            checkpoints = []
            native_imports = []
            owners = []
            for imp in imports:
                native = imp.get("native_import_observation")
                if native is None:
                    continue
                checkpoints.extend(h for h in native["host_checks"] if h["phase"] == "checkpoint")
                native_imports.extend(p for p in native["phases"] if p["phase"] == "history_import")
                owners.append(native["native_attribution"]["page"]["owner_mode"])
            def observed_sum(items, field):
                values = [i.get(field) for i in items]
                return {"known_sum": sum(x for x in values if type(x) is int),
                        "known_count": sum(type(x) is int for x in values),
                        "unknown_count": sum(type(x) is not int for x in values)}
            rows.append({
                "run": run, "mode": phase["mode"],
                "original_seconds": phase["duration_seconds"],
                "attackers": phase["attacker_processes_requested"],
                "submit_attempts": len(submissions),
                "submit_acknowledged_in_window": sum(s["status"] == "ok" and s.get("response", {}).get("ok") is True and s["returned_after_window"] is False for s in submissions),
                "receiver_full_work_accepted": phase["full_work_accepted"],
                "receiver_full_work_failed": phase["full_work_failed"],
                "receiver_accepted_records": len(accepted_records),
                "receiver_accepted_records_matching_original_honest_body": len(matched_accepted),
                "receiver_unmatched_accepted_records": len(accepted_records) - len(matched_accepted),
                "receiver_records_not_retained": receiver["records_not_retained"],
                "receiver_measurement_failures": receiver["measurement_failures"],
                "submissions_without_in_window_ack": unacknowledged,
                "history_rpc_ok": sum(h["status"] == "ok" and h.get("response", {}).get("ok") is True for h in history),
                "history_imports": len(imports),
                "history_import_succeeded": sum(i["succeeded"] is True for i in imports),
                "history_import_errors": errors,
                "history_owner_modes": sorted(set(owners), key=str),
                "checkpoint_calls": observed_sum(checkpoints, "calls_completed"),
                "checkpoint_calling_thread_cpu_ns": observed_sum(checkpoints, "thread_cpu_ns"),
                "importer_calling_thread_cpu_ns": observed_sum(native_imports, "thread_cpu_ns"),
                "confirmations_in_window": len(confirmations),
                "confirmation_ended_ns": [c["ended_ns"] for c in confirmations],
                "transaction_ids": sorted({c["transaction"] for c in confirmations}),
                "phase_passed": phase["finite_phase_criteria_met"],
                "receiver_client_state_equal": phase["receiver_client_state_equal"],
                "original_depletion_observed": phase["genuine_budget_depletion_observed"],
            })
print(json.dumps({"schema": "chain-security-original-phase-counts-v1", "original_archive_sha256": EXPECTED,
                  "original_source": "53e1b98a7955898b9feff4778f7136c0fd0199c8", "report_pins": pins,
                  "rows": rows, "native_execution_performed": False,
                  "checkpoint_and_import_cpu_overlap": True,
                  "qualification": "HOLD_NO_GO", "production_activation": False}, indent=2, sort_keys=True))
