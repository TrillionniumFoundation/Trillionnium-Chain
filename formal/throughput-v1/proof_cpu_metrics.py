#!/usr/bin/env python3
"""Recompute #795 historical CPU observations, without inferring TPS.

This reader pins the exact published Git blobs.  It does not execute a prover,
authenticate a host, certify a CPU limit, or turn a repeated fixture into a new
task. Decimal-valued output fields are strings to preserve receipt precision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import statistics
from decimal import Decimal


COMMIT = "1fe2f31c70977a030aec73b63fe0617f34d15a77"
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
SOURCE_ROOT = (
    "formal/pon-nakamoto-v1/p3_shared_primitive_qualification/"
    "evidence/native-v2-base-sync/abba-v2"
)
RUN_IDS = (
    "00-retained-A", "01-retained-B", "02-retained-B", "03-retained-A",
    "04-dense-A", "05-dense-B", "06-dense-B", "07-dense-A",
)
# GitHub returned these blob identities for the exact COMMIT above. This is a
# fixed-corpus reader: a caller-controlled source-index file cannot repin it.
PINNED_BLOBS = {
    "manifest.json": "9711d39a4475bd7297ccd52a6e1f2b0c1300dbf0",
    "summary.json": "269740cb14f111df561d400b0ac707c99a68d70f",
    "00-retained-A.resource.txt": "cb5118f19ee78ff3f51b3331ef734563a6131521",
    "01-retained-B.resource.txt": "2a0d3139335f863b887f9c80389eb37e7df7dc9f",
    "02-retained-B.resource.txt": "659ae9c256eaa6f83e2869b648935621fea11d2d",
    "03-retained-A.resource.txt": "bb77e914d9fd7591d2d69c8bd49cbc87ea60a6ae",
    "04-dense-A.resource.txt": "2623e1a9767c249cc2f85b88728f061e93e4a16d",
    "05-dense-B.resource.txt": "5df7a715c208f037ea81b1bbd5023aa87c47f409",
    "06-dense-B.resource.txt": "dd1774e3c06b14c48cf535416efeddf303a9d2d5",
    "07-dense-A.resource.txt": "94f0fa660125c319c840f3f13e5852c47397d62a",
}
PINNED_SHA256 = {
    "manifest.json": "ea0380c4dbdaa253ef7a6fb779e7fe2efbe1fff012af36a1e8b7debc00f96137",
    "summary.json": "65b519541152e400c79f08e59a954a8f1ba516fbaea60dbf0ac3dd9123dc0de0",
    "00-retained-A.resource.txt": "6fff7ed3a199779dcbc3f8726c96c9096ffe2f06e98a50abc50a37ce56495c46",
    "01-retained-B.resource.txt": "3a34a2c3ce610252d33cc79c8e3ac38ad755a995060e6553e4b60dd7bf18cc39",
    "02-retained-B.resource.txt": "afdca3298c30c99a5daefd2d407a71b23702f2a1c9fa878c4ea98677c4da5259",
    "03-retained-A.resource.txt": "2dcd81c10d625b336db17656db487c17c14189e43dd358aa51f4333f4e1c901e",
    "04-dense-A.resource.txt": "a9ac690a2d0d9594872e292138eed519fc405b3fa178010c7ca764fb7defe72d",
    "05-dense-B.resource.txt": "a2e242bff8e5c894c1cf86da30313e390516bbb7525af9ad1c3261ed1576ee0d",
    "06-dense-B.resource.txt": "b19b0e7a8d2e5f787be8ce93f99e023e2ad6b3fbfe61ee595db62ebb6ecfa0fa",
    "07-dense-A.resource.txt": "4db05e3d23329cce2842412587f223c77e57747d3683145cd96099f5434f33b9",
}
PLAN = [
    {"index": index, "run_id": run_id, "case": run_id.split("-")[1],
     "variant": run_id.split("-")[2]}
    for index, run_id in enumerate(RUN_IDS)
]
MAX_SOURCE_BYTES = 512 * 1024
EPSILON = Decimal("0.000000001")
MAX_SECONDS = Decimal(86400)


def source_path(name: str) -> str:
    if name.endswith(".resource.txt"):
        name = name.removesuffix(".resource.txt") + "/verify_stage/resource.txt"
    return SOURCE_ROOT + "/" + name


def source_url(name: str) -> str:
    return f"https://github.com/{REPOSITORY}/blob/{COMMIT}/{source_path(name)}"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(text: str):
    def reject_constant(value):
        raise ValueError(f"nonfinite JSON constant: {value}")
    return json.loads(text, parse_float=Decimal, parse_constant=reject_constant,
                      object_pairs_hook=_unique_object)


def _number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ValueError(f"{label}: nonnumeric or missing")
    if type(value) is int and not 0 <= value <= 86400:
        raise ValueError(f"{label}: outside bounded duration range")
    value = Decimal(value)
    if not value.is_finite() or value < 0:
        raise ValueError(f"{label}: nonfinite or negative")
    representation = value.as_tuple()
    if (not -30 <= representation.exponent <= 5
            or len(representation.digits) > 40 or value > MAX_SECONDS):
        raise ValueError(f"{label}: exceeds bounded duration or decimal representation")
    return value


def _mapping(value, label):
    if type(value) is not dict:
        raise ValueError(f"{label}: expected an object")
    return value


def _exact_count(value, expected):
    return type(value) is int and value == expected


def _decimal_string(value):
    if value is None:
        return None
    result = format(value, "f")
    return result.rstrip("0").rstrip(".") if "." in result else result


def _median(values):
    return statistics.median(values) if values else None


def parse_resource(text: str, expected_argv: list[str]) -> dict:
    """Parse one GNU time receipt, rejecting absent/duplicate/invalid fields."""
    if type(text) is not str or len(text) > MAX_SOURCE_BYTES:
        raise ValueError("resource must be bounded text")
    lines = text.splitlines()

    def field(label):
        prefix = label + ": "
        values = [line.strip()[len(prefix):] for line in lines
                  if line.strip().startswith(prefix)]
        if len(values) != 1:
            raise ValueError(f"resource field {label!r}: expected exactly one")
        return values[0]

    command = field("Command being timed")
    if type(expected_argv) is not list or not expected_argv or not all(type(x) is str for x in expected_argv):
        raise ValueError("missing or malformed expected argv")
    if command != '"' + " ".join(expected_argv) + '"':
        raise ValueError("resource command differs from manifest verifier argv")
    times = []
    for label in ("User time (seconds)", "System time (seconds)"):
        value = field(label)
        if not re.fullmatch(r"[0-9]{1,6}\.[0-9]{2}", value):
            raise ValueError(f"resource {label}: expected nonnegative centiseconds")
        times.append(_number(Decimal(value), label))
    exit_text = field("Exit status")
    rss_text = field("Maximum resident set size (kbytes)")
    if not re.fullmatch(r"[0-9]+", exit_text) or not re.fullmatch(r"[0-9]+", rss_text):
        raise ValueError("invalid resource exit status or RSS")
    signal_lines = [line.strip() for line in lines
                    if line.strip().startswith("Command terminated by signal")]
    nonzero_lines = [line.strip() for line in lines
                     if line.strip().startswith("Command exited with non-zero status")]
    return {
        "user_seconds": times[0], "system_seconds": times[1],
        "cpu_seconds": sum(times, Decimal(0)), "exit_code": int(exit_text),
        "peak_rss_kib": int(rss_text),
        "signal_observations": signal_lines,
        "nonzero_exit_observations": nonzero_lines,
        "cpu_input_precision_seconds": "0.01",
    }


def _cohorts(rows):
    result = {}
    for case in ("all", "retained", "dense"):
        result[case] = {}
        for variant in ("A", "B"):
            chosen = [row for row in rows if row["variant"] == variant
                      and (case == "all" or row["case"] == case)]
            successes = [row for row in chosen if row["eligible_completed_observation"]]
            cpu_rows = [row for row in chosen if row["verifier_cpu_seconds"] is not None]
            group = {
                "planned_count": len(chosen),
                "records_present": sum(row["record_present"] for row in chosen),
                "completed_count": len(successes),
                "incomplete_or_invalid_count": len(chosen) - len(successes),
                "cpu_observed_count": len(cpu_rows),
                "all_observed_cpu_seconds_sum": _decimal_string(sum(
                    (row["verifier_cpu_seconds"] for row in cpu_rows), Decimal(0)
                )) if cpu_rows else None,
                "medians_scope": "eligible completed observations only; denominator retained",
            }
            for field in ("verifier_cpu_seconds", "verifier_wall_seconds", "pipeline_wall_seconds"):
                group[field + "_median"] = _decimal_string(_median([
                    row[field] for row in successes
                ]))
            result[case][variant] = group
    return result


def analyze_records(manifest: dict, declared_summary: dict, resources: dict) -> dict:
    """Arithmetic/structure analysis only; build_report adds pinned provenance.

    This function intentionally cannot qualify throughput or establish source
    authenticity. The fixed eight-slot plan survives missing or failed records.
    """
    _mapping(manifest, "manifest")
    _mapping(declared_summary, "summary")
    _mapping(resources, "resources")
    issues = []
    expected_order = [{"case": row["case"], "variant": row["variant"]} for row in PLAN]
    if manifest.get("planned_order") != expected_order:
        issues.append("manifest planned_order differs from fixed published eight-slot plan")
    if not _exact_count(manifest.get("fresh_full_proofs_planned"), 8):
        issues.append("declared planned proof denominator differs from eight")
    source = manifest.get("source_before")
    source_consistent = bool(source) and source == manifest.get("source_after")
    if not source_consistent or manifest.get("source_binaries_and_inputs_unchanged") is not True:
        issues.append("source/binary/input snapshots do not match")
    source = _mapping(source, "source_before") if source is not None else {}
    fixtures = _mapping(source.get("fixtures", {}), "source fixtures")
    binaries = _mapping(source.get("binaries", {}), "source binaries")
    fixture_identities = [
        _mapping(_mapping(fixtures.get(case, {}), "fixture case").get("input", {}),
                 "fixture input").get("sha256")
        for case in ("retained", "dense")
    ]
    fixture_count = None
    if all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
           for value in fixture_identities):
        fixture_count = len(set(fixture_identities))
    if fixture_count != 2:
        issues.append("two distinct input-fixture identities are not established")
    if not _exact_count(manifest.get("distinct_input_tasks"), 2) or manifest.get("small_test_proofs_counted") is not False:
        issues.append("distinct-task or small-proof accounting differs from frozen campaign")
    records = manifest.get("runs", [])
    if not isinstance(records, list):
        issues.append("manifest runs is not a list")
        records = []
    unexpected = [index for index, row in enumerate(records)
                  if not isinstance(row, dict) or type(row.get("index")) is not int
                  or row["index"] not in range(8)]
    if unexpected:
        issues.append(f"unplanned or malformed record positions: {unexpected}")
    rows = []
    for planned in PLAN:
        matches = [row for row in records if isinstance(row, dict)
                   and type(row.get("index")) is int and row["index"] == planned["index"]]
        row = dict(planned, record_present=len(matches) == 1,
                   eligible_completed_observation=False, issues=[],
                   stage_outcomes={phase: {"exit_code": None, "timeout": None}
                                   for phase in ("prepare", "prove", "verify")},
                   resource_exit_code=None, resource_signal_observations=None,
                   verifier_user_seconds=None, verifier_system_seconds=None,
                   verifier_cpu_seconds=None, verifier_wall_seconds=None,
                   pipeline_wall_seconds=None, receipt_path=planned["run_id"] + ".resource.txt")
        if len(matches) != 1:
            row["issues"].append("missing record" if not matches else "duplicate record index")
            rows.append(row)
            continue
        recorded = matches[0]
        if any(recorded.get(key) != planned[key] for key in ("case", "variant")):
            row["issues"].append("case or variant mismatch")
        if recorded.get("full_fresh_proof_verified") is not True:
            row["issues"].append("full fresh proof not reported verified")
        stages = recorded.get("stages", {})
        stages = stages if isinstance(stages, dict) else {}
        wall_values = []
        for phase in ("prepare", "prove", "verify"):
            stage = stages.get(phase, {})
            stage = stage if isinstance(stage, dict) else {}
            code, timeout = stage.get("exit_code"), stage.get("timeout")
            row["stage_outcomes"][phase] = {
                "exit_code": code if type(code) is int else None,
                "timeout": timeout if type(timeout) is bool else None,
            }
            if type(code) is not int or code != 0 or timeout is not False:
                row["issues"].append(f"{phase}: nonzero/missing exit or timeout/unknown")
            try:
                wall = _number(stage.get("outer_wall_s"), phase + " wall")
                wall_values.append(wall)
                if phase == "verify":
                    row["verifier_wall_seconds"] = wall
            except ValueError as error:
                row["issues"].append(str(error))
        verify = stages.get("verify", {})
        verify = verify if isinstance(verify, dict) else {}
        report = verify.get("report", {})
        report = report if isinstance(report, dict) else {}
        if report.get("status") != "VERIFIED_COMPLETE_W1_RESEARCH_ONLY" or report.get("qualification") != "HOLD_NO_GO":
            row["issues"].append("verifier did not report complete research-only verification")
        try:
            pipeline = _number(recorded.get("pipeline_outer_s"), "pipeline wall")
            row["pipeline_wall_seconds"] = pipeline
            if len(wall_values) != 3 or abs(sum(wall_values) - pipeline) > EPSILON:
                row["issues"].append("pipeline wall differs from sum of recorded stages")
        except ValueError as error:
            row["issues"].append(str(error))
        argv = verify.get("argv", [])
        binary = _mapping(binaries.get(planned["variant"], {}), "source binary")
        if (type(argv) is not list or len(argv) != 6
                or not all(type(value) is str for value in argv)
                or argv[:2] != [binary.get("path"), "verify"]):
            row["issues"].append("verifier argv not bound to campaign binary")
        elif (type(binary.get("sha256")) is not str
              or not re.fullmatch(r"[0-9a-f]{64}", binary["sha256"])
              or not argv[2].endswith("/" + planned["run_id"] + "/prepared/statement.bin")
              or not argv[5].endswith("/" + planned["run_id"] + "/proof")):
            row["issues"].append("verifier argv/run or binary hash binding invalid")
        resource = resources.get(row["receipt_path"])
        if resource is None:
            row["issues"].append("missing or untrusted CPU receipt; CPU unknown")
        else:
            try:
                parsed = parse_resource(resource, argv)
                row.update(verifier_user_seconds=parsed["user_seconds"],
                           verifier_system_seconds=parsed["system_seconds"],
                           verifier_cpu_seconds=parsed["cpu_seconds"],
                           resource_exit_code=parsed["exit_code"],
                           resource_signal_observations=parsed["signal_observations"])
                if parsed["exit_code"] != 0 or parsed["exit_code"] != verify.get("exit_code") or parsed["signal_observations"]:
                    row["issues"].append("resource exit/signal is not successful manifest exit")
                if parsed["nonzero_exit_observations"]:
                    row["resource_nonzero_exit_observations"] = parsed["nonzero_exit_observations"]
                    row["issues"].append("resource contains nonzero-exit diagnostic; printed exit zero cannot override it")
                if parsed["peak_rss_kib"] != verify.get("peak_rss_kib"):
                    row["issues"].append("resource RSS differs from manifest")
            except (TypeError, ValueError) as error:
                row["issues"].append("invalid CPU receipt: " + str(error))
        row["eligible_completed_observation"] = not row["issues"] and source_consistent
        rows.append(row)
    cohorts = _cohorts(rows)
    completed = sum(row["eligible_completed_observation"] for row in rows)
    if not _exact_count(manifest.get("completed_full_proofs"), completed):
        issues.append("reported completion count differs from validated observations")
    if len(records) != 8 or manifest.get("all_planned_runs_finished") is not True:
        issues.append("campaign does not contain exactly eight finished planned records")
    for key in ("schema", "qualification", "completed_full_proofs", "distinct_input_tasks",
                "source_binaries_and_inputs_unchanged", "result"):
        if (type(declared_summary.get(key)) is not type(manifest.get(key))
                or declared_summary.get(key) != manifest.get(key)):
            issues.append(f"summary/manifest disagreement: {key}")
    if declared_summary.get("observed_medians") != manifest.get("observed_medians"):
        issues.append("summary/manifest median tables disagree")
    summary_medians = _mapping(declared_summary.get("observed_medians", {}), "summary medians")
    for case, variants in cohorts.items():
        for variant, cohort in variants.items():
            claimed = _mapping(_mapping(summary_medians.get(case, {}), "summary case").get(variant, {}),
                               "summary arm")
            if not _exact_count(claimed.get("count"), cohort["completed_count"]):
                issues.append(f"summary count disagreement: {case}/{variant}")
            for output, original in (("pipeline_wall_seconds_median", "pipeline_outer_s"),
                                     ("verifier_wall_seconds_median", "verify_outer_s")):
                try:
                    measured = cohort[output]
                    if measured is None or abs(Decimal(measured) - _number(claimed.get(original), original)) > EPSILON:
                        issues.append(f"summary median disagreement: {case}/{variant}/{original}")
                except ValueError as error:
                    issues.append(str(error))
    return {"issues": issues, "rows": rows, "cohorts": cohorts,
            "completed_count": completed, "record_count": len(records),
            "source_reported_distinct_fixture_identities": fixture_count,
            "unexpected_record_positions": unexpected,
            "source_snapshots_consistent": source_consistent,
            "historical_measurement_source": {key: source.get(key) for key in
                ("head", "merge_head", "index_tree", "tracked_diff_sha256")}}


def read_pinned_sources(evidence_dir: Path):
    originals = evidence_dir / "originals"
    texts, index, issues = {}, [], []
    for name, expected in PINNED_BLOBS.items():
        path = originals / name
        entry = {"local_path": "originals/" + name, "source_url": source_url(name),
                 "git_path": source_path(name), "expected_git_blob_sha1": expected,
                 "expected_sha256": PINNED_SHA256[name],
                 "status": "unknown", "bytes": None, "sha256": None, "git_blob_sha1": None}
        try:
            if originals.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("source is not an ordinary file")
            if path.stat().st_size > MAX_SOURCE_BYTES:
                raise ValueError("source exceeds bounded read size")
            with path.open("rb") as stream:
                data = stream.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError("source grew beyond bounded read size")
            entry.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                         git_blob_sha1=git_blob_sha1(data))
            if entry["git_blob_sha1"] != expected or entry["sha256"] != PINNED_SHA256[name]:
                raise ValueError("source differs from fixed published Git blob")
            texts[name] = data.decode("utf-8", errors="strict")
            entry["status"] = "verified"
        except (OSError, UnicodeError, ValueError) as error:
            entry["status"] = "missing" if isinstance(error, FileNotFoundError) else "invalid"
            entry["error"] = str(error)
            issues.append(f"{name}: {error}")
        index.append(entry)
    return texts, index, issues


def build_report(evidence_dir: Path) -> dict:
    texts, source_index, source_issues = read_pinned_sources(evidence_dir)
    parsed = {}
    for name in ("manifest.json", "summary.json"):
        try:
            value = load_json(texts[name])
            if not isinstance(value, dict):
                raise ValueError("JSON root is not an object")
            parsed[name] = value
        except (KeyError, ValueError) as error:
            parsed[name] = {}
            source_issues.append(f"{name}: unavailable or malformed JSON ({error})")
    analysis = analyze_records(parsed["manifest.json"], parsed["summary.json"], texts)
    manifest = parsed["manifest.json"]
    valid = not source_issues and not analysis["issues"] and analysis["completed_count"] == 8
    for row in analysis["rows"]:
        for key in ("verifier_user_seconds", "verifier_system_seconds", "verifier_cpu_seconds",
                    "verifier_wall_seconds", "pipeline_wall_seconds"):
            row[key] = _decimal_string(row[key])
    cpu = analysis["cohorts"]["all"]["B"]["verifier_cpu_seconds_median"]
    return {
        "schema": "trnm-proof-cpu-readback-v1",
        "result": "COMPLETE_HISTORICAL_READBACK" if valid else "INCOMPLETE_OR_INVALID_READBACK",
        "qualification": "HOLD_NO_GO", "qualified_tps": None,
        "fresh_proof_executions": 0, "original_resource_contract_replayed": False,
        "source": {"repository": REPOSITORY, "published_evidence_commit": COMMIT,
                   "blobs_verified": len(source_index) - len([x for x in source_index if x["status"] != "verified"]),
                   "blobs_planned": len(PINNED_BLOBS), "issues": source_issues,
                   "files": source_index},
        "planned_attempts": 8, "planned_distinct_input_tasks": 2,
        "source_declared_distinct_input_tasks": manifest.get("distinct_input_tasks"),
        "same_fixture_repeats_are_not_new_tasks": True,
        "analysis": analysis,
        "observed_resources": {"cpu_affinity": manifest.get("cpu_affinity"),
                               "rayon_threads": manifest.get("rayon_threads"),
                               "host_exclusive": manifest.get("host_exclusive"),
                               "initial_reported_cgroup_cpu_max": manifest.get("initial_system", {}).get("cgroup_values", {}).get("cpu.max"),
                               "initial_reported_cgroup_memory_max": manifest.get("initial_system", {}).get("cgroup_values", {}).get("memory.max"),
                               "cpu_input_precision_seconds": "0.01"},
        "original_service_envelope": {
            "cpu_cores": "0.25", "deadline_seconds": "4", "nominal_cpu_seconds": "1",
            "nominal_cpu_budget_is_arithmetic_not_a_fresh_kernel_observation": True,
            "memory_bytes": 2147483648, "swap_bytes": 0, "pids": 256,
            "hostile_inputs": 16, "honest_submissions": 7,
        },
        "budget_comparison": {
            "tagged_completed_verifier_cpu_seconds_median": cpu,
            "median_exceeds_nominal_one_cpu_second": Decimal(cpu) > 1 if valid and cpu is not None else None,
            "resource_scopes_match": False,
            "extrapolated_wall_seconds": None, "universal_cpu_lower_bound": None,
            "interpretation": "Eight-thread verifier wall time does not establish the 0.25-CPU service gate. A new resource-matched native campaign is required; threading and implementation can change paid CPU work.",
        },
        "combination_obligation": {
            "fresh_same_resource_four_arm_experiment_required": True,
            "multiply_historical_speedups": False,
            "arms": ["Poseidon2 + original SHA", "Poseidon2 + scheduled SHA",
                     "tagged SHA3 R1 + original SHA", "new tagged scheduled-SHA namespace"],
            "scheduled_tagged_measurement_present": False,
        },
        "limits": [
            "This is a pinned historical readback and arithmetic reproduction, not a fresh execution or independent host attestation.",
            "The observed resolved merge snapshot differs from the later commit that publishes its evidence; both identities remain separate.",
            "CPU seconds include user plus system time reported by GNU time; printed centiseconds are not exact physical costs.",
            "Success-only medians retain full planned denominators and all missing, failed, timed-out or unknown outcomes.",
            "Two observations per arm per fixture do not support tail, confidence, production or worst-case claims.",
            "No mining, WAN, production queue, native confirmation, cryptographic security or service qualification follows.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = build_report(args.evidence_dir)
    encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        # Existing observations are immutable; reruns should use a new output.
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
    else:
        print(encoded, end="")
    return 0 if report["result"] == "COMPLETE_HISTORICAL_READBACK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
