#!/usr/bin/env python3
"""Diagnose failed original-campaign ZIPs without executing or extracting them.

Exit 0 means that retained bytes were read consistently. It is NOT a native
campaign pass. The report preserves the original native/process verdicts and
never supplies production, cryptographic, or external-effect authority.
The original positive-acceptance reader is unchanged; its strict helpers and
the original phase derivation are reused, not replaced with this diagnostic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

import read_original_native_campaign as original


MAX_ARCHIVE = 256 * 1024 * 1024
MAX_MEMBER = original.MAX_FILE_BYTES
MAX_TOTAL = original.MAX_TOTAL_BYTES
MAX_MEMBERS = original.MAX_FILES + 1
MAX_MANIFEST = original.MAX_MANIFEST_BYTES
MAX_JSON = original.MAX_JSON_BYTES
CHUNK = 1024 * 1024
MODES = ("baseline", "from-zero", "late-product")
ATTACKERS = (0, 24, 24)
ROUNDS = 3
ORIGINAL_INPUTS = {
    "seed_transfers": 1024,
    "seed_blocks": 4,
    "business_blocks": 21,
    "phase_seconds": 30,
    "modes": list(MODES),
    "attacker_processes": list(ATTACKERS),
}


class EvidenceError(ValueError):
    """The retained bytes cannot support the requested readback."""


def require(condition, label):
    if not condition:
        raise EvidenceError(label)


def integer(value, label):
    try:
        return original.integer(value)
    except ValueError as error:
        raise EvidenceError(label) from error


def boolean(value, label):
    require(type(value) is bool, label)
    return value


def parse_json(data):
    return original.strict_json(data)


def same_json(left, right):
    """JSON booleans must not compare equal to integer counters."""
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False)


def hex_digest(value, length, label):
    try:
        return original.exact_digest(value, length)
    except ValueError as error:
        raise EvidenceError(label) from error


def sha_stream(stream, limit):
    digest = hashlib.sha256()
    count = 0
    for block in iter(lambda: stream.read(CHUNK), b""):
        count += len(block)
        require(count <= limit, "STREAM_BYTE_LIMIT")
        digest.update(block)
    return count, digest.hexdigest()


def safe_name(value):
    return "/".join(original.Bundle.path_parts(value))


class RetainedZip:
    """Only reads bounded regular members; no archive paths are materialized."""

    def __init__(self, path, expected_sha256):
        self.path = Path(path)
        hex_digest(expected_sha256, 64, "EXPECTED_ARCHIVE_SHA256_REQUIRED")
        # Pin a descriptor for both digest verification and all subsequent reads.
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.stream = os.fdopen(fd, "rb")
        try:
            self.initial_stat = os.fstat(self.stream.fileno())
            require(stat.S_ISREG(self.initial_stat.st_mode), "REGULAR_ARCHIVE_REQUIRED")
            require(self.initial_stat.st_size <= MAX_ARCHIVE, "ARCHIVE_LIMIT")
            self.size, self.sha256 = sha_stream(self.stream, MAX_ARCHIVE)
            require(self.size <= MAX_ARCHIVE, "ARCHIVE_LIMIT")
            require(self.sha256 == expected_sha256, "ARCHIVE_SHA256_MISMATCH")
            self.stream.seek(0)
            self.archive = zipfile.ZipFile(self.stream)
            infos = self.archive.infolist()
            require(0 < len(infos) <= MAX_MEMBERS, "MEMBER_COUNT_LIMIT")
            self.members = {}
            total = 0
            for info in infos:
                name = safe_name(info.filename)
                require(name not in self.members, "DUPLICATE_ZIP_MEMBER")
                mode = stat.S_IFMT(info.external_attr >> 16)
                require(mode in (0, stat.S_IFREG) and not info.is_dir()
                        and not info.flag_bits & 1, "REGULAR_UNENCRYPTED_MEMBER_REQUIRED")
                require(0 <= info.file_size <= MAX_MEMBER, "MEMBER_LIMIT")
                total += info.file_size
                require(total <= MAX_TOTAL, "TOTAL_MEMBER_LIMIT")
                self.members[name] = info
            manifest = self.json("artifact-files.json", MAX_MANIFEST)
            require(isinstance(manifest, dict) and isinstance(manifest.get("files"), list),
                    "MANIFEST_REQUIRED")
            self.manifest = {}
            for row in manifest["files"]:
                require(isinstance(row, dict), "MANIFEST_ROW")
                name = safe_name(row.get("path"))
                require(name != "artifact-files.json" and name not in self.manifest,
                        "DUPLICATE_OR_SELF_MANIFEST_ROW")
                integer(row.get("bytes"), "MANIFEST_BYTES")
                hex_digest(row.get("sha256"), 64, "MANIFEST_SHA256")
                self.manifest[name] = row
            require(set(self.members) == set(self.manifest) | {"artifact-files.json"},
                    "MANIFEST_MEMBER_SET_MISMATCH")
            for name, row in self.manifest.items():
                require(self.members[name].file_size == row["bytes"],
                        f"MEMBER_SIZE_MISMATCH:{name}")
                with self.archive.open(name) as source:
                    count, digest = sha_stream(source, row["bytes"])
                require(count == row["bytes"] and digest == row["sha256"],
                        f"MEMBER_SHA256_MISMATCH:{name}")
            self.uncompressed_bytes = total
            # Existing strict step/resource readers consume this same interface.
            self.files = self.manifest
        except BaseException:
            self.stream.close()
            raise

    def close(self):
        self.archive.close()
        self.stream.close()

    def verify_unchanged(self):
        self.stream.seek(0)
        size, digest = sha_stream(self.stream, MAX_ARCHIVE)
        now = os.fstat(self.stream.fileno())
        require(size == self.size and digest == self.sha256
                and now.st_size == self.initial_stat.st_size
                and now.st_mtime_ns == self.initial_stat.st_mtime_ns
                and now.st_ctime_ns == self.initial_stat.st_ctime_ns,
                "ARCHIVE_CHANGED_DURING_READ")

    def raw(self, name, limit=MAX_JSON):
        require(name in self.members, f"MISSING_MEMBER:{name}")
        info = self.members[name]
        require(info.file_size <= limit, f"JSON_MEMBER_LIMIT:{name}")
        with self.archive.open(name) as source:
            content = source.read(limit + 1)
        require(len(content) == info.file_size and len(content) <= limit,
                f"JSON_MEMBER_LENGTH:{name}")
        if hasattr(self, "manifest") and name in self.manifest:
            require(hashlib.sha256(content).hexdigest() == self.manifest[name]["sha256"],
                    f"MEMBER_CHANGED_DURING_READ:{name}")
        return content

    def json(self, name, limit=MAX_JSON):
        return parse_json(self.raw(name, limit))

    def identity(self, name):
        row = self.manifest[name]
        return {"path": name, "bytes": row["bytes"], "sha256": row["sha256"]}


def source_receipt(value, head, tree):
    original.source(value, head, tree)
    return value


def stage_deltas(before, after):
    if before is None or after is None:
        return {"available": False, "stages": None}
    require(isinstance(before, dict) and isinstance(after, dict), "STAGE_OBJECT_REQUIRED")
    stages = []
    def index(rows):
        require(isinstance(rows, list), "STAGE_ARRAY_REQUIRED")
        indexed = {}
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get("stage"), str)
                    and row["stage"] not in indexed, "UNIQUE_STAGE_REQUIRED")
            indexed[row["stage"]] = row["totals"]
        return indexed
    old, new = index(before["stages"]), index(after["stages"])
    require(set(old) == set(new), "STAGE_ROSTER_CHANGED")
    for name in old:
        require(set(old[name]) == set(new[name]), "STAGE_COUNTER_ROSTER_CHANGED")
        delta = {}
        for key, value in old[name].items():
            prior = integer(value, "STAGE_COUNTER")
            current = integer(new[name][key], "STAGE_COUNTER")
            require(current >= prior, "STAGE_COUNTER_REGRESSION")
            delta[key] = current - prior
        stages.append({"stage": name, "delta": delta})
    return {"available": True, "stages": stages,
            "intervals_are_nested_not_additive": True}


def selected_spans(rows):
    require(isinstance(rows, list), "SPAN_ARRAY_REQUIRED")
    return [{key: span.get(key) for key in (
        "phase", "parent_phase", "started", "completed", "accepted",
        "started_ns", "ended_ns", "error_code", "thread_cpu_ns", "wall_ns")}
        for span in rows if span.get("started") is True]


# Optional diagnostic extension; no acceptance authority.
HOST_CHECKPOINT_PHASES = (
    "decode", "context_owner_wait", "context", "work",
    "admission_owner_wait", "admission", "submit_result",
    "admission_prepare", "execution", "commit_owner_wait", "commit",
    "cpu_wait", "body_decode", "response_encoding", "history_epoch_open",
    "history_epoch_close", "history_import", "cpu_settle", "root_commitment", None,
)
HOST_CHECKPOINT_COUNTERS = (
    "calls_started", "calls_completed", "calls_accepted", "calls_rejected",
    "calls_unfinished", "wall_clock_unknown_calls", "cpu_clock_unknown_calls",
)
HOST_CHECKPOINT_TIMES = ("first_started_ns", "last_ended_ns", "wall_ns", "thread_cpu_ns")
HOST_CHECKPOINT_SCOPE = (
    "actual Host checkpoint calls classified once at entry by the innermost open owner phase; "
    "worker calls use the current owner phase context; absent or ambiguous contexts remain unattributed; "
    "the same existing call clocks feed aggregate and bucket records, which overlap; "
    "summed call wall intervals are not elapsed runtime and may overlap across threads; "
    "Host CPU includes each invoking thread, while native phase CPU excludes scoped workers; "
    "observer overhead remains in outer measured work"
)


def checkpoint_attribution(observation):
    """Read optional stage buckets without turning absent clocks or scope into zero."""
    def require(ok, message):
        if not ok:
            raise ValueError("invalid host checkpoint attribution: " + message)

    def u64(value, label):
        require(type(value) is int and 0 <= value <= (1 << 64) - 1, label)
        return value

    if "host_checkpoint_attribution" not in observation:
        return {
            "availability": "absent",
            "reason": "not recorded by this artifact; no retrospective stage attribution",
        }
    value = observation["host_checkpoint_attribution"]
    require(isinstance(value, dict), "extension must be an object")
    require(set(value) == {
        "schema", "buckets", "all_checkpoint_calls_attributed",
        "has_consensus_authority", "scope",
    }, "extension field set")
    require(value["schema"] == "pon-local-history-host-phase-attribution-v1", "schema")
    require(value["has_consensus_authority"] is False, "consensus authority")
    require(type(value["all_checkpoint_calls_attributed"]) is bool, "attribution flag")
    require(value["scope"] == HOST_CHECKPOINT_SCOPE, "measurement scope")
    failures = u64(observation.get("measurement_failures"), "measurement_failures")
    buckets = value["buckets"]
    require(isinstance(buckets, list) and len(buckets) == 20, "twenty fixed buckets")
    checks = observation.get("host_checks")
    require(isinstance(checks, list) and len(checks) == 4, "original Host aggregates")
    row_keys = set(HOST_CHECKPOINT_COUNTERS + HOST_CHECKPOINT_TIMES) | {"phase", "last_error_code"}

    def checked_row(row, label):
        require(isinstance(row, dict) and set(row) == row_keys, label + " field set")
        require(row["phase"] == "checkpoint", label + " phase")
        for key in HOST_CHECKPOINT_COUNTERS:
            u64(row[key], label + " " + key)
        for key in HOST_CHECKPOINT_TIMES:
            if row[key] is not None:
                u64(row[key], label + " " + key)
        started = row["calls_started"]
        completed = row["calls_completed"]
        unfinished = row["calls_unfinished"]
        ended = completed + unfinished
        require(ended <= started, label + " ended calls")
        require(completed == row["calls_accepted"] + row["calls_rejected"], label + " outcome partition")
        if failures == 0:
            require(ended == started, label + " complete accounting")
        for unknown, timing in (
            ("wall_clock_unknown_calls", "wall_ns"),
            ("cpu_clock_unknown_calls", "thread_cpu_ns"),
        ):
            require(row[unknown] <= ended, label + " clock unknown calls")
            if row[unknown] > 0 or ended == 0:
                require(row[timing] is None, label + " unavailable clock must stay null")
            elif failures == 0:
                require(row[timing] is not None, label + " known clock total missing")
        error = row["last_error_code"]
        require(error is None or (isinstance(error, str) and 0 < len(error) <= 256), label + " error")
        require(error is None or row["calls_rejected"] > 0, label + " error without rejection")
        if started == 0:
            require(all(row[k] is None for k in HOST_CHECKPOINT_TIMES), label + " unused times")
            require(error is None, label + " unused error")
        if row["first_started_ns"] is not None and row["last_ended_ns"] is not None:
            require(row["first_started_ns"] <= row["last_ended_ns"], label + " time order")
        return row

    aggregate = checked_row(checks[2], "aggregate")
    rows = []
    for index, (bucket, name) in enumerate(zip(buckets, HOST_CHECKPOINT_PHASES)):
        require(isinstance(bucket, dict) and set(bucket) == {"owner_phase", "calls"},
                "bucket " + str(index) + " fields")
        require(bucket["owner_phase"] == name, "bucket " + str(index) + " owner phase")
        rows.append(checked_row(bucket["calls"], "bucket " + str(index)))
    counts = {key: sum(row[key] for row in rows) for key in HOST_CHECKPOINT_COUNTERS}
    started_sum_valid = counts["calls_started"] <= (1 << 64) - 1
    derived = (
        failures == 0 and rows[-1]["calls_started"] == 0
        and started_sum_valid and counts["calls_started"] == aggregate["calls_started"]
    )
    require(value["all_checkpoint_calls_attributed"] is derived, "all-attributed claim mismatch")
    if failures == 0:
        require(all(counts[key] == aggregate[key] for key in HOST_CHECKPOINT_COUNTERS),
                "bucket counters do not conserve original checkpoint counters")
        active = [row for row in rows if row["calls_completed"] + row["calls_unfinished"] > 0]
        for timing in ("wall_ns", "thread_cpu_ns"):
            if active and aggregate[timing] is not None and all(row[timing] is not None for row in active):
                require(sum(row[timing] for row in active) == aggregate[timing],
                        "known bucket clocks do not conserve original checkpoint clocks")
    return {
        "availability": "present",
        "observer_measurement_failures": failures,
        "checkpoint_calls": aggregate["calls_started"],
        "unattributed_checkpoint_calls": rows[-1]["calls_started"],
        "derived_all_checkpoint_calls_attributed": derived,
        "raw": value,
        "qualification_granted": False,
    }


def history_row(index, row):
    require(isinstance(row, dict), "HISTORY_ROW_REQUIRED")
    result = {"index": index, **{key: row.get(key) for key in (
        "status", "error", "started_ns", "ended_ns", "elapsed_wall_ns",
        "calling_process_cpu_ns", "returned_after_window")}}
    imported = row.get("client_import")
    result["client_import_available"] = imported is not None
    if imported is None:
        result["client_import"] = None
        return result
    require(isinstance(imported, dict), "IMPORT_OBJECT_REQUIRED")
    observation = imported.get("native_import_observation")
    observed = {key: imported.get(key) for key in (
        "succeeded", "error", "started_ns", "ended_ns", "wall_ns",
        "thread_cpu_ns", "thread_cpu_observation_available", "scope")}
    observed["native_observation_available"] = observation is not None
    if observation is not None:
        require(isinstance(observation, dict), "NATIVE_IMPORT_OBJECT_REQUIRED")
        observed.update({key: observation.get(key) for key in (
            "schema", "supplied_packets", "measurement_failures",
            "observation_has_consensus_authority", "clock_scope")})
        observed["host_checks"] = observation.get("host_checks")
        observed["host_checkpoint_attribution"] = checkpoint_attribution(observation)
        observed["native_spans"] = selected_spans(observation.get("phases", []))
        observed["packet_failures"] = [
            {"packet_index": packet.get("packet_index"),
             "spans": [span for span in selected_spans(packet.get("phases", []))
                       if span["error_code"] is not None]}
            for packet in observation.get("packets", [])
            if any(span.get("error_code") is not None for span in packet.get("phases", []))]
    result["client_import"] = observed
    return result


def phase_summary(phase, position, derived):
    mode = MODES[position]
    require(phase.get("mode") == mode
            and integer(phase.get("duration_seconds"), "PHASE_SECONDS") == 30
            and integer(phase.get("attacker_processes_requested"), "ACTOR_COUNT") == ATTACKERS[position],
            "ORIGINAL_PHASE_INPUTS_CHANGED")
    rounds = phase.get("confirmations")
    require(isinstance(rounds, list) and len(rounds) <= ROUNDS,
            "CONFIRMATION_ROUNDS_REQUIRED")
    require([integer(r.get("round"), "ROUND_INDEX") for r in rounds] == list(range(len(rounds))),
            "CONFIRMATION_ORDER_REQUIRED")
    confirmations = []
    for row in rounds:
        inside = boolean(row.get("confirmed_inside_pressure_window"), "CONFIRMATION_BOOLEAN")
        observation = row.get("observation")
        if inside:
            require(isinstance(observation, dict) and observation.get("confirmed") is True
                    and integer(row.get("ended_ns"), "CONFIRMATION_END") <= 30_000_000_000,
                    "CONFLICTING_CONFIRMATION")
        confirmations.append({key: row.get(key) for key in (
            "round", "started_ns", "ended_ns", "confirmed_inside_pressure_window",
            "paid_credit_depletion_observed_during_round")})
        confirmations[-1]["observation_confirmed"] = (
            observation.get("confirmed") if isinstance(observation, dict) else None)
        confirmations[-1]["observed_depth"] = (
            observation.get("depth") if isinstance(observation, dict) else None)
    confirmed = sum(row["confirmed_inside_pressure_window"] for row in confirmations)
    counts = {"scheduled_confirmation_rounds": ROUNDS,
              "observed_confirmation_rounds": len(rounds),
              "confirmed_rounds": confirmed,
              "unobserved_scheduled_rounds": ROUNDS - len(rounds)}
    require(derived.get("mode") == mode
            and all(type(derived.get(key)) is int and derived[key] == value for key, value in counts.items()),
            "ORIGINAL_PHASE_READBACK_COUNT_MISMATCH")
    submissions = phase.get("submissions")
    require(isinstance(submissions, list), "SUBMISSIONS_REQUIRED")
    status_counts = {}
    for row in submissions:
        status = row.get("status")
        require(isinstance(status, str), "SUBMISSION_STATUS_REQUIRED")
        status_counts[status] = status_counts.get(status, 0) + 1
    context = phase.get("phase_process_context") or {}
    receiver = phase.get("receiver_observation") or {}
    result = {"mode": mode, **counts, "confirmations": confirmations,
              "window_seconds": phase["duration_seconds"],
              "attacker_processes_requested": phase["attacker_processes_requested"],
              "attacker_processes_ready": phase.get("attacker_processes_ready"),
              "startup_or_campaign_error": phase.get("startup_or_campaign_error"),
              "native_phase_criteria_met": boolean(phase.get("finite_phase_criteria_met"),
                                                    "PHASE_VERDICT_REQUIRED"),
              "observer_complete": phase.get("observer_complete"),
              "verifier_errors": phase.get("verifier_errors"),
              "receiver_client_state_equal": phase.get("receiver_client_state_equal"),
              "genuine_budget_depletion_observed": phase.get("genuine_budget_depletion_observed"),
              "submission_count": len(submissions), "submission_status_counts": status_counts,
              "submission_failures": [{key: row.get(key) for key in (
                  "packet_index", "height", "status", "error", "started_ns", "ended_ns",
                  "returned_after_window")} for row in submissions if row.get("status") != "ok"],
              "full_work_accepted": phase.get("full_work_accepted"),
              "full_work_failed": phase.get("full_work_failed"),
              "final_cpu_meter": phase.get("final_meter"),
              "final_actual_flow": phase.get("final_actual_flow"),
              "history": [history_row(i, row) for i, row in enumerate(phase.get("history", []))],
              "client_native_stage_deltas": stage_deltas(
                  phase.get("client_native_history_arithmetic_before"),
                  phase.get("client_native_history_arithmetic_after")),
              "receiver_native_stage_deltas": stage_deltas(
                  phase.get("native_history_arithmetic_before"),
                  phase.get("native_history_arithmetic_after")),
              "phase_placement": context,
              "public_resource_policy": phase.get("public_resource_policy"),
              "native_service_outcome": phase.get("service_outcome"),
              "receiver_observation_coverage": {key: receiver.get(key) for key in (
                  "schema", "records_not_retained", "measurement_failures", "counter_overflow")},
              "whole_parent_phase_cpu_ns": phase.get("whole_parent_phase_cpu_ns"),
              "whole_parent_phase_wall_ns": phase.get("whole_parent_phase_wall_ns")}
    return result


def summarize(path, expected_sha256, expected_head, expected_tree, run_id, artifact_id):
    hex_digest(expected_head, 40, "EXPECTED_HEAD_REQUIRED")
    hex_digest(expected_tree, 40, "EXPECTED_TREE_REQUIRED")
    integer(run_id, "RUN_ID_REQUIRED")
    integer(artifact_id, "ARTIFACT_ID_REQUIRED")
    archive = RetainedZip(path, expected_sha256)
    try:
        native = archive.json("results.json")
        require(native.get("schema") == "pon-original-native-campaign-ci-v1"
                and native.get("expected_head") == expected_head
                and native.get("expected_tree") == expected_tree,
                "ORIGINAL_CAMPAIGN_SOURCE_REQUIRED")
        require(same_json(native.get("original_inputs"), ORIGINAL_INPUTS)
                and integer(native.get("planned_complete_runs"), "PLANNED_RUNS") == 3
                and native.get("state_backend") == "authenticated-v1"
                and native.get("profile") == "release"
                and native.get("source_kind") == "head"
                and native.get("toolchain") == "1.95.0"
                and native.get("build_timeout_seconds") == 1800
                and native.get("original_campaign_outer_timeout_seconds") == 600
                and native.get("expected_resources") == {"cpu_max": "400000 100000",
                    "memory_max": "17179869184", "nice": 10},
                "ORIGINAL_CAMPAIGN_CONTRACT_CHANGED")
        receipts = ["source-before.json", "source-before-build.json", "source-before-campaigns.json",
                    "source-after-native.json", "source-after.json"]
        receipts += [f"run-{n}-source-after.json" for n in range(1, 4)]
        original_source = source_receipt(archive.json(receipts[0]), expected_head, expected_tree)
        for name in receipts[1:]:
            require(source_receipt(archive.json(name), expected_head, expected_tree) == original_source,
                    f"SOURCE_RECEIPT_CHANGED:{name}")
        require(native.get("source_after") == archive.json("source-after-native.json"),
                "FINAL_SOURCE_RECEIPT_MISMATCH")
        resource_names = ["resource-before-build.json", "resource-after-native.json"]
        resource_names += [f"run-{n}-resource-{when}.json" for n in range(1, 4)
                           for when in ("before", "after")]
        resources = [archive.json(name) for name in resource_names]
        limits = [original.resource(value) for value in resources]
        require(all(value == limits[0] for value in limits)
                and all(value["cgroup"] == resources[0]["cgroup"] for value in resources),
                "ORIGINAL_RESOURCE_PROFILE_CHANGED")
        require(native.get("runner_sha256") == archive.files["run-native-campaign.py"]["sha256"],
                "ORIGINAL_RUNNER_SHA256_MISMATCH")
        build_stdout = original.step(archive, native["build"], "build", build=True)
        artifacts = [row for row in map(parse_json, build_stdout.splitlines())
                     if row.get("reason") == "compiler-artifact"
                     and row.get("target", {}).get("name") == "public_v3_multiprocess"
                     and row.get("profile", {}).get("test") is True and row.get("executable")]
        require(len(artifacts) == 1, "ONE_ORIGINAL_COMPILER_ARTIFACT_REQUIRED")
        binary = native.get("binary")
        require(isinstance(binary, dict) and binary.get("retained") == "public_v3_multiprocess.bin",
                "ORIGINAL_BINARY_REQUIRED")
        require(binary.get("sha256_before") == binary.get("sha256_after")
                == archive.manifest[binary["retained"]]["sha256"]
                and binary.get("bytes") == archive.manifest[binary["retained"]]["bytes"],
                "RETAINED_BINARY_MISMATCH")
        require(binary.get("actual_compiler_artifact_profile") == artifacts[0]["profile"]
                and same_json(artifacts[0]["profile"], {"debug_assertions": False, "debuginfo": 0,
                    "opt_level": "3", "overflow_checks": False, "test": True})
                and binary.get("build_artifact") == artifacts[0]["executable"]
                and binary.get("build_separate_from_measured_campaign") is True,
                "ORIGINAL_RELEASE_PROFILE_MISMATCH")
        before_binary = archive.json("binary-before.json")
        require(before_binary.get("sha256_after") is None
                and {k: v for k, v in before_binary.items() if k != "sha256_after"}
                == {k: v for k, v in binary.items() if k != "sha256_after"},
                "ORIGINAL_BINARY_BEFORE_MISMATCH")
        attempts = native.get("attempts")
        require(isinstance(attempts, list)
                and [integer(a.get("number"), "ATTEMPT_NUMBER") for a in attempts] == [1, 2, 3],
                "THREE_ORIGINAL_ATTEMPTS_REQUIRED")
        summaries = []
        run_attempt = None
        for attempt in attempts:
            number = attempt["number"]
            prefix = f"run-{number}"
            require(archive.json(f"{prefix}-result.json") == attempt, "ATTEMPT_RECEIPT_MISMATCH")
            require(attempt.get("report_directory") == f"{prefix}-raw", "REPORT_DIRECTORY_MISMATCH")
            report_name = f"{prefix}-raw/report.json"
            identity = archive.identity(report_name)
            require(attempt.get("report_sha256") == identity["sha256"], "REPORT_SHA256_MISMATCH")
            report = archive.json(report_name)
            require(report.get("schema") == "native-public-v3-separate-process-campaign-v2",
                    "ORIGINAL_REPORT_SCHEMA_REQUIRED")
            require(report.get("state_backend") == "authenticated-v1", "ORIGINAL_BACKEND_REQUIRED")
            require(all(report.get(key) is False for key in (
                "cryptographic_hardness_qualified", "work_profile_qualified", "independent_operators",
                "wan_qualified", "production_candidate", "release_ready")),
                "UNSUPPORTED_NATIVE_QUALIFICATION_CLAIM")
            preparation = report.get("preparation") or {}
            require(preparation.get("actual_signed_seed_transfers") == 1024
                    and preparation.get("seed_blocks") == 4
                    and preparation.get("business_blocks") == 21,
                    "ORIGINAL_PREPARATION_REQUIRED")
            readback_name = f"{prefix}-phase-readback.json"
            readback = archive.json(readback_name)
            require(readback.get("schema") == "pon-public-v3-multiprocess-phase-derivation-v3"
                    and readback.get("input", {}).get("sha256") == identity["sha256"]
                    and readback.get("input", {}).get("bytes") == identity["bytes"],
                    "ORIGINAL_READBACK_INPUT_MISMATCH")
            original_derivation = original.phase_reader.analyze_for_retained_schema(
                report, readback["schema"])
            require(same_json({key: value for key, value in readback.items() if key != "input"},
                              original_derivation), "ORIGINAL_PHASE_DERIVATION_MISMATCH")
            original_path = readback["input"].get("report")
            require(isinstance(original_path, str), "ORIGINAL_REPORT_PATH_REQUIRED")
            match = re.search(rf"/pon-native-campaign-{run_id}-([1-9][0-9]*)/{prefix}-raw/report\.json$",
                              original_path)
            require(match is not None, "ORIGINAL_WORKFLOW_RUN_ID_MISMATCH")
            observed_attempt = int(match.group(1))
            require(run_attempt is None or run_attempt == observed_attempt, "WORKFLOW_ATTEMPT_CHANGED")
            run_attempt = observed_attempt
            phases = report.get("phases")
            require(isinstance(phases, list) and len(phases) == 3
                    and isinstance(readback.get("phases"), list) and len(readback["phases"]) == 3,
                    "THREE_ORIGINAL_PHASES_REQUIRED")
            summarized = [phase_summary(p, i, readback["phases"][i]) for i, p in enumerate(phases)]
            criteria = (report.get("finite_experiment_criteria_met") is True
                        and report.get("economics_complete") is True
                        and all(p["native_phase_criteria_met"] for p in summarized))
            require(boolean(attempt.get("original_criteria_met"), "CRITERIA_BOOLEAN") == criteria,
                    "NATIVE_CRITERIA_RECEIPT_MISMATCH")
            boolean(attempt.get("complete_success"), "ATTEMPT_SUCCESS_BOOLEAN")
            step = attempt.get("step") or {}
            # The old positive step guard must still reject an original exit 101.
            # Only its explicit unsuccessful-step refusal is recorded here; an
            # invalid command/identity is an integrity failure, not a diagnostic pass.
            positive_step_refusal = None
            try:
                original.step(archive, step, prefix)
            except ValueError as error:
                require(str(error) == "original step did not complete successfully inside its budget",
                        f"ORIGINAL_STEP_INTEGRITY_REFUSAL:{error}")
                positive_step_refusal = str(error)
            require(type(step.get("returncode")) is int
                    and step.get("outer_stage_timeout_seconds") == 600
                    and 0 < integer(step.get("elapsed_ns"), "STEP_ELAPSED") <= 600_000_000_000
                    and step.get("elapsed_seconds") == step["elapsed_ns"] / 1_000_000_000,
                    "ORIGINAL_STEP_TIMING_REQUIRED")
            for stream in ("stdout", "stderr"):
                log_name = step.get(stream)
                require(log_name == f"{prefix}.{stream}.log", "ORIGINAL_LOG_PATH_REQUIRED")
                require(step.get(f"{stream}_sha256") == archive.manifest[log_name]["sha256"]
                        and step.get(f"{stream}_bytes") == archive.manifest[log_name]["bytes"]
                        and step.get(f"{stream}_truncated") is False, "ORIGINAL_LOG_RECEIPT_MISMATCH")
            stderr = archive.raw(step["stderr"]).decode("utf-8")
            launched = re.findall(r"^\s*Running tests/public_v3_multiprocess\.rs \(([^)]+)\)$", stderr, re.M)
            require(launched == [binary["build_artifact"]]
                    and step.get("cwd") == native["build"].get("cwd")
                    and PurePosixPath(step["cwd"]).is_absolute(), "ORIGINAL_EXECUTABLE_SOURCE_MISMATCH")
            if attempt.get("complete_success") is True:
                require(criteria and step.get("returncode") == 0 and step.get("complete_success") is True,
                        "CONFLICTING_NATIVE_SUCCESS")
            summaries.append({"number": number, "report": identity,
                              "original_readback": archive.identity(readback_name),
                              "native_process_returncode": step.get("returncode"),
                              "native_complete_success": attempt.get("complete_success"),
                              "native_original_criteria_met": attempt.get("original_criteria_met"),
                              "native_economics_complete": report.get("economics_complete"),
                              "native_qualification_flags": {key: report.get(key) for key in (
                                  "cryptographic_hardness_qualified", "work_profile_qualified",
                                  "independent_operators", "wan_qualified", "production_candidate", "release_ready")},
                              "original_positive_step_reader_refusal": positive_step_refusal,
                              "phase_startup_errors": attempt.get("phase_startup_errors"),
                              "report_validation_failure": attempt.get("report_validation_failure"),
                              "phases": summarized})
        if boolean(native.get("complete_success"), "CAMPAIGN_SUCCESS_BOOLEAN"):
            require(all(a["native_complete_success"] is True for a in summaries)
                    and native.get("finalization_failures") == [], "CONFLICTING_CAMPAIGN_SUCCESS")
            raise EvidenceError("SUCCESSFUL_CAMPAIGNS_REQUIRE_ORIGINAL_ACCEPTANCE_READER")
        all_phases = [p for a in summaries for p in a["phases"]]
        report = {
            "schema": "pon-original-campaign-artifact-readback-v1",
            "scope": "Offline readback of retained original bytes; no native workload executed; no acceptance or execution authority granted.",
            "evidence_read_success": True,
            "qualification_granted": False,
            "timing_scope": "Host checkpoint, native stage, and import intervals are nested and must not be added; importer-thread CPU excludes scoped workers; Host CPU includes each actual calling thread.",
            "archive": {"name": archive.path.name, "bytes": archive.size, "sha256": archive.sha256,
                        "member_count": len(archive.members), "uncompressed_bytes": archive.uncompressed_bytes,
                        "all_manifest_members_verified": True},
            "source_url": f"https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/{run_id}",
            "artifact_id": artifact_id,
            "run_attempt": run_attempt,
            "source": original_source,
            "binary": archive.identity(binary["retained"]),
            "hardware": archive.json("hardware.json"),
            "original_inputs": native["original_inputs"],
            "expected_resources": native.get("expected_resources"),
            "public_phase_placement": native.get("public_phase_placement"),
            "native_campaign_complete_success": native.get("complete_success"),
            "native_failure": native.get("failure"),
            "native_finalization_failures": native.get("finalization_failures"),
            "totals": {key: sum(p[key] for p in all_phases) for key in (
                "scheduled_confirmation_rounds", "observed_confirmation_rounds",
                "confirmed_rounds", "unobserved_scheduled_rounds")},
            "attempts": summaries,
        }
        archive.verify_unchanged()
        return report
    finally:
        archive.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = summarize(args.archive, args.archive_sha256, args.expected_head,
                           args.expected_tree, args.run_id, args.artifact_id)
        # A previous report is never overwritten or relabeled.
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        print(f"ARTIFACT_READBACK_REFUSED: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"evidence_read_success": True,
                      "native_campaign_complete_success": report["native_campaign_complete_success"],
                      "qualification_granted": False, "totals": report["totals"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
