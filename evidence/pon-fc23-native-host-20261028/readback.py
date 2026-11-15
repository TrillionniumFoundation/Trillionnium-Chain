"""Read exact retained GitHub diagnostic ZIPs without rerunning their work."""

import collections
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
EXPECTED = {
    12783021727: (
        "protocol-head",
        "28fd8eb823511681bb81e0111f4e0573e7fdd704965559b27f929aabb8b530be",
    ),
    12783296539: (
        "cross-arch-x64",
        "8b25a31a9eaea8e4928037538c2ad116c227066c5c78473128307fb344572468",
    ),
    12782961722: (
        "cross-arch-arm64",
        "06f2702c5565878742a5ae22bc4c5a38039f129559ef6a448c3245ce42d15cc9",
    ),
    12782458035: (
        "protocol-merge",
        "56c3f4fc0fb454ca2352faae6d3466abc22c7de367745da68c59c719b8bfa463",
    ),
    12782512072: (
        "cleanup-macos-head",
        "6235f9ea530370654c256b6e0a2526ee6232ea6d7b546971dfde4ae0448b3540",
    ),
}


def calls(rows):
    return {
        "attempts": len(rows),
        "statuses": dict(collections.Counter(row.get("status") for row in rows)),
        "errors": dict(
            collections.Counter(row.get("error") for row in rows if row.get("error"))
        ),
        "timely_successes": sum(
            row.get("status") == "ok"
            and row.get("returned_after_deadline") is False
            and row.get("returned_after_window") is False
            for row in rows
        ),
        "after_deadline": sum(
            row.get("returned_after_deadline") is True for row in rows
        ),
        "after_window": sum(row.get("returned_after_window") is True for row in rows),
    }


def timing_rows(rows):
    keys = (
        "height",
        "status",
        "error",
        "started_ns",
        "ended_ns",
        "elapsed_wall_ns",
        "returned_after_deadline",
        "returned_after_window",
    )
    return [{key: row[key] for key in keys if key in row} for row in rows]


result = {
    "schema": "fc23-original-ci-diagnostic-readback-v1",
    "source": "fc23fa6de10380dd9ce9cae6cddd1db4d87551ce",
    "actual_merge": "9ae4fd76ede88a1cff56ca2e1afe28ed39668ff0",
    "original_failures_reclassified": False,
    "independent_wan_accepted": False,
    "lanes": [],
}
for artifact_id, (lane, expected) in EXPECTED.items():
    path = ROOT / f"fc23-artifact-{artifact_id}.zip"
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    assert actual == expected
    row = {
        "lane": lane,
        "artifact_id": artifact_id,
        "archive": path.name,
        "archive_bytes": len(raw),
        "archive_sha256": actual,
    }
    with zipfile.ZipFile(path) as archive:
        row["members"] = len(archive.infolist())
        if "from-zero-native/manifest.json" not in archive.namelist():
            log = archive.read("tests.log").decode()
            summary = json.loads(
                next(line for line in log.splitlines() if line.startswith('{"scope":'))
            )
            row.update(
                modules=summary["results"],
                executed=84,
                failures=1,
                skipped=0,
                failure_assertion="timeout.log was empty; expected OUTERR",
            )
            result["lanes"].append(row)
            continue
        manifest = json.loads(archive.read("from-zero-native/manifest.json"))
        controller = json.loads(
            archive.read("from-zero-native-host/controller-result.json")
        )
        prepared = controller["preparation"]
        child = json.loads(archive.read("from-zero-native-host/child-result.json"))
        report_raw = archive.read("from-zero-native/confirmation/report.json")
        report = json.loads(report_raw)
        row.update(
            source_before=manifest["source_before"],
            source_after=manifest["source_after"],
            host_errors=child["host_errors"],
            final_host_errors=controller["final_host_errors"],
            warmup_completed=prepared["completed"],
            warmup=prepared["process"],
            native_build=manifest["build"],
            binary_sha256=manifest["binary_sha256_before"],
            exact_binary_preparation_execution_equal=prepared["binary_sha256"]
            == manifest["binary_sha256_before"]
            == manifest["binary_sha256_after"],
            exact_source_preparation_execution_equal=prepared["source_before"]
            == prepared["source_after"]
            == manifest["source_before"]
            == manifest["source_after"],
            all_named_tests_passed=manifest["all_named_tests_passed"],
            named_tests=[
                {"name": r["name"], "passed": r["passed"], "process": r["process"]}
                for r in manifest["runs"]
            ],
            original_passed=manifest["passed"],
            original_failures=manifest["failures"],
            confirmation_report_sha256=hashlib.sha256(report_raw).hexdigest(),
            confirmation_report_bytes=len(report_raw),
            finite_target_met=report["finite_target_met"],
            invariant_target_met=report["invariant_target_met"],
            phases=[],
        )
        for phase in report["phases"]:
            attack_rows = [
                call for worker in phase["attacks"] for call in worker["calls"]
            ]
            summary = {
                key: phase[key]
                for key in (
                    "mode",
                    "workers",
                    "requested_window_ns",
                    "initial_meter",
                    "final_meter",
                    "finite_business_target_met",
                    "invariant_target_met",
                    "full_native_state_equal",
                    "client_confirmed_transactions",
                    "client_confirmation_latency_ns",
                    "business_started_ns",
                    "confirmation_ended_ns",
                    "completed_false_calls_before_business",
                    "completed_false_calls_at_confirmation",
                    "overlap_demonstrated",
                    "overlapping_false_calls",
                    "maximum_honest_head_gap_ns",
                    "verification_errors",
                    "accounting_closed",
                    "no_attack_accepted",
                    "attacker_workers_cpu_ns",
                    "reader_cpu_ns",
                    "independent_replay_and_confirmation_cpu_ns",
                    "independent_replay_and_confirmation_wall_ns",
                )
            }
            summary.update(
                attacks=calls(attack_rows),
                honest_heads=calls(phase["honest_heads"]),
                honest_submissions=calls(phase["honest_submissions"]),
                honest_history=calls(phase["honest_history"]),
                honest_submission_timing_rows=timing_rows(phase["honest_submissions"]),
                honest_history_timing_rows=timing_rows(phase["honest_history"]),
                service_metrics=phase["service"]["metrics"],
                resource_coverage={
                    key: phase["observations"][key]
                    for key in (
                        "accepted_connections_seen",
                        "records_not_retained",
                        "counter_overflow",
                        "measurement_failures",
                    )
                },
            )
            row["phases"].append(summary)
    result["lanes"].append(row)
output = ROOT / "fc23-ci-readback-summary.json"
output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
for row in result["lanes"]:
    print(
        json.dumps(
            {
                "lane": row["lane"],
                "artifact_id": row["artifact_id"],
                "original_failures": row.get("original_failures"),
                "named_passed": row.get("all_named_tests_passed"),
                "phases": [
                    {
                        key: phase[key]
                        for key in (
                            "mode",
                            "client_confirmed_transactions",
                            "client_confirmation_latency_ns",
                            "honest_heads",
                            "honest_submissions",
                            "honest_history",
                            "attacks",
                            "final_meter",
                        )
                    }
                    for phase in row.get("phases", [])
                ],
            }
        )
    )
