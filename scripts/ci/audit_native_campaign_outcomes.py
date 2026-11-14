#!/usr/bin/env python3
"""Audit retained original campaign outcomes without running or qualifying a node.

The exact ZIP, producer file list and measured source are caller-pinned. Every
listed artifact member is verified, including failed/partial rows. This reader
then reconciles the existing result/phase projections with the raw reports and
retains the predeclared denominator. Exit zero means this read-only audit
completed; it does not mean the original campaign passed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

MODES = ("baseline", "from-zero", "late-product")
INPUTS = {"attacker_processes": [0, 24, 24], "business_blocks": 21,
          "modes": list(MODES), "phase_seconds": 30, "seed_blocks": 4,
          "seed_transfers": 1024}
PLACEMENT = {
    "attacker_processes_remain_in_original_controller_domain": True,
    "fixed_parent": "/sys/fs/cgroup/trnmponpublic.slice",
    "original_3x3_workload_and_depletion_predicates_changed": False,
    "profile": "fixed-public-phase-external-actors-v1",
    "receiver_and_verifier_cpu_max": "25000 100000",
    "receiver_and_verifier_memory_max": "2147483648",
}
MAX_FILES = 4096
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
SELECTOR = "separate_process_work_and_signed_confirmation_campaign"
IMPORT_PHASES = ("decode", "context_owner_wait", "context", "work", "admission_owner_wait",
                 "admission", "submit_result", "admission_prepare", "execution", "commit_owner_wait",
                 "commit", "cpu_wait", "body_decode", "response_encoding", "history_epoch_open",
                 "history_epoch_close", "history_import", "cpu_settle", "root_commitment")
PHASE_FIELDS = ("phase", "parent_phase", "started", "completed", "accepted", "error_code",
                "started_ns", "ended_ns", "wall_ns", "thread_cpu_ns")
HOST_FIELDS = ("phase", "calls_started", "calls_completed", "calls_accepted", "calls_rejected",
               "calls_unfinished", "first_started_ns", "last_ended_ns", "wall_ns", "thread_cpu_ns",
               "wall_clock_unknown_calls", "cpu_clock_unknown_calls", "last_error_code")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    require(type(value) is int and 0 <= value < 2**127, "bounded nonnegative integer required")
    return value


def boolean(value):
    require(type(value) is bool, "exact boolean required")
    return value


def digest(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value),
            "canonical digest required")
    return value


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("nonfinite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def relative_name(name):
    require(type(name) is str and name and "\\" not in name and "\0" not in name,
            "invalid artifact path")
    require(not PurePosixPath(name).is_absolute()
            and all(part not in ("", ".", "..") for part in name.split("/")),
            "noncanonical artifact path")
    return name


class Artifact:
    """Read the pinned archive; never extract or execute its members."""
    def __init__(self, path, expected_zip_sha256, expected_manifest_sha256):
        self.stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")
        try:
            self.before = os.fstat(self.stream.fileno())
            require(stat.S_ISREG(self.before.st_mode)
                    and 0 < self.before.st_size <= MAX_TOTAL_BYTES, "bounded regular ZIP required")
            self.zip_sha256 = hashlib.file_digest(self.stream, "sha256").hexdigest()
            require(self.zip_sha256 == digest(expected_zip_sha256), "ZIP SHA256 mismatch")
            self.stream.seek(0)
            self.archive = zipfile.ZipFile(self.stream)
            infos = self.archive.infolist()
            require(0 < len(infos) <= MAX_FILES + 1, "bounded ZIP member count required")
            self.members = {}
            for info in infos:
                name = relative_name(info.filename)
                mode = info.external_attr >> 16
                require(name not in self.members and not info.is_dir()
                        and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                        and info.flag_bits & 1 == 0, "regular unique unencrypted members required")
                require(0 <= info.file_size <= MAX_MEMBER_BYTES, "ZIP member byte limit")
                self.members[name] = info
            require("artifact-files.json" in self.members, "producer file list missing")
            raw = self.read_unchecked("artifact-files.json", MAX_MANIFEST_BYTES)
            self.manifest_sha256 = hashlib.sha256(raw).hexdigest()
            require(self.manifest_sha256 == digest(expected_manifest_sha256),
                    "artifact file-list SHA256 mismatch")
            rows = strict_json(raw)["files"]
            require(type(rows) is list and 0 < len(rows) <= MAX_FILES, "bounded producer file list required")
            self.files = {}
            total = 0
            for row in rows:
                name = relative_name(row["path"])
                require(name not in self.files and name != "artifact-files.json", "duplicate or recursive file list")
                size = integer(row["bytes"])
                require(size <= MAX_MEMBER_BYTES, "producer member byte limit")
                digest(row["sha256"])
                total += size
                require(total <= MAX_TOTAL_BYTES, "producer total byte limit")
                self.files[name] = row
            require(set(self.members) == set(self.files) | {"artifact-files.json"},
                    "ZIP and producer inventory differ")
            for name, row in self.files.items():
                require(self.members[name].file_size == row["bytes"], "artifact length mismatch: " + name)
                measured, count = hashlib.sha256(), 0
                with self.archive.open(name) as stream:
                    while chunk := stream.read(1024 * 1024):
                        count += len(chunk)
                        require(count <= row["bytes"], "artifact expanded beyond declared size")
                        measured.update(chunk)
                require(count == row["bytes"] and measured.hexdigest() == row["sha256"],
                        "artifact SHA256 mismatch: " + name)
            self.total_bytes = total
        except BaseException:
            self.stream.close()
            raise

    def read_unchecked(self, name, limit):
        require(name in self.members and self.members[name].file_size <= limit,
                "missing or oversized artifact member: " + name)
        with self.archive.open(name) as stream:
            raw = stream.read(limit + 1)
        require(len(raw) == self.members[name].file_size, "artifact read length mismatch")
        return raw

    def raw(self, name, limit=MAX_JSON_BYTES):
        require(name in self.files, "member absent from producer inventory: " + name)
        raw = self.read_unchecked(name, limit)
        require(len(raw) == self.files[name]["bytes"]
                and hashlib.sha256(raw).hexdigest() == self.files[name]["sha256"],
                "artifact changed after inventory verification")
        return raw

    def json(self, name):
        return strict_json(self.raw(name))

    def close(self):
        try:
            after = os.fstat(self.stream.fileno())
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            require(all(getattr(self.before, key) == getattr(after, key) for key in fields),
                    "ZIP changed during audit")
        finally:
            self.archive.close()
            self.stream.close()


def source_observation(value, head, tree):
    require(value["schema"] == "trnm-ci-source-v1" and value["kind"] == "head"
            and value["candidate"] == value["tested_commit"] == head
            and value["tested_tree"] == tree and value["base"] is None
            and value["prospective_merge"] is None
            and value["tracked_worktree_verified"] is True
            and value["tests_executed_by_identity_check"] is False,
            "retained source identity mismatch")
    counts = (integer(value["tracked_entries"]), integer(value["tracked_bytes"]))
    require(all(counts), "nonempty complete-source observation required")
    return counts


def step_observation(bundle, row, name, *, build=False):
    command = ["+1.95.0", "test", "--locked", "--offline", "--release", "--manifest-path",
               "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--test", "public_v3_multiprocess"]
    command += (["--no-run", "--message-format=json"] if build else
                [SELECTOR, "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"])
    require(row == bundle.json(name + ".step.json") and row["name"] == name
            and row["command"][1:] == command
            and PurePosixPath(row["command"][0]).is_absolute()
            and PurePosixPath(row["command"][0]).name == "cargo", "original command identity mismatch")
    require(type(row["returncode"]) is int and row["error"] is None
            and boolean(row["complete_success"]) == (row["returncode"] == 0),
            "only completed original process observations are supported")
    require(row["outer_stage_timeout_seconds"] == (1800 if build else 600)
            and integer(row["elapsed_ns"]) > 0
            and row["elapsed_seconds"] == row["elapsed_ns"] / 1_000_000_000,
            "original stage timing mismatch")
    for kind in ("stdout", "stderr"):
        filename = name + "." + kind + ".log"
        require(row[kind] == filename and row[kind + "_truncated"] is False
                and row[kind + "_bytes"] == bundle.files[filename]["bytes"]
                and row[kind + "_sha256"] == bundle.files[filename]["sha256"],
                "complete original step log identity mismatch")
    return row["returncode"]


def optional_integer(value):
    return None if value is None else integer(value)


def phase_measurement_state(rows):
    """Retain each page/packet interval; never add nested phase costs."""
    if rows is None:
        return {"records": None, "roster_complete": False, "measurement_fields_complete": False,
                "started_spans": None, "completed_spans": None, "unfinished_spans": None,
                "started_spans_without_cpu": None, "started_spans_without_wall": None,
                "lifecycle_complete": False}
    require(type(rows) is list and len(rows) <= len(IMPORT_PHASES), "bounded native phase observations required")
    records = []
    complete = True
    for row in rows:
        require(type(row) is dict, "native phase observation required")
        observed = {key: row.get(key) for key in PHASE_FIELDS}
        missing = [key for key in PHASE_FIELDS if key not in row]
        for key in ("started", "completed"):
            if observed[key] is not None:
                boolean(observed[key])
        if observed["accepted"] is not None:
            boolean(observed["accepted"])
        for key in ("started_ns", "ended_ns", "wall_ns", "thread_cpu_ns"):
            optional_integer(observed[key])
        started, ended = observed["started"], observed["completed"]
        slot_complete = (not missing and type(started) is bool and type(ended) is bool
                         and ((started and ended and type(observed["accepted"]) is bool
                               and (observed["accepted"] is False or observed["error_code"] is None))
                              or (not started and not ended and observed["accepted"] is None
                                  and observed["error_code"] is None
                                  and all(observed[key] is None for key in
                                          ("started_ns", "ended_ns", "wall_ns", "thread_cpu_ns")))))
        complete = complete and slot_complete
        records.append(dict(observed, missing_fields=missing, lifecycle_complete=slot_complete))
    roster = [row["phase"] for row in records] == list(IMPORT_PHASES)
    return {"records": records, "roster_complete": roster,
            "measurement_fields_complete": all(not row["missing_fields"] for row in records),
            "started_spans": sum(row["started"] is True for row in records),
            "completed_spans": sum(row["completed"] is True for row in records),
            "unfinished_spans": sum(row["started"] is True and row["completed"] is not True for row in records),
            "started_spans_without_cpu": sum(row["started"] is True and row["thread_cpu_ns"] is None for row in records),
            "started_spans_without_wall": sum(row["started"] is True and row["wall_ns"] is None for row in records),
            "lifecycle_complete": roster and complete}


def host_measurement_state(rows):
    if rows is None:
        return None
    require(type(rows) is list and len(rows) <= 4, "bounded Host observation roster required")
    result = []
    for row in rows:
        require(type(row) is dict, "Host observation required")
        observed = {key: row.get(key) for key in HOST_FIELDS}
        missing = [key for key in HOST_FIELDS if key not in row]
        for key in HOST_FIELDS:
            if key not in ("phase", "last_error_code"):
                optional_integer(observed[key])
        counts = [observed[key] for key in ("calls_started", "calls_completed", "calls_accepted",
                                          "calls_rejected", "calls_unfinished")]
        known = all(value is not None for value in counts)
        started, completed, accepted, rejected, unfinished = counts
        balanced = known and completed == accepted + rejected and started >= completed + unfinished
        pending = started - completed - unfinished if balanced else None
        closed = not missing and balanced and pending == 0 and unfinished == 0
        no_calls = (closed and started == 0 and all(observed[key] is None for key in
                    ("first_started_ns", "last_ended_ns", "wall_ns", "thread_cpu_ns"))
                    and observed["cpu_clock_unknown_calls"] == observed["wall_clock_unknown_calls"] == 0)
        cpu_complete = (closed and started > 0 and observed["cpu_clock_unknown_calls"] == 0
                        and observed["thread_cpu_ns"] is not None)
        wall_complete = (closed and started > 0 and observed["wall_clock_unknown_calls"] == 0
                         and observed["wall_ns"] is not None)
        result.append(dict(observed, missing_fields=missing, counts_consistent=balanced,
                           calls_not_ended=pending, lifecycle_complete=closed,
                           unentered_slot=no_calls, cpu_measurement_complete=cpu_complete,
                           wall_measurement_complete=wall_complete))
    return result


def import_observations(phase):
    imports = []
    for index, call in enumerate(phase["history"]):
        item = call.get("client_import")
        if item is None:
            continue
        require(type(item) is dict, "client import observation required")
        client_fields = ("started_ns", "ended_ns", "wall_ns", "thread_cpu_ns",
                         "thread_cpu_observation_available", "scope", "succeeded", "error")
        client = {key: item.get(key) for key in client_fields}
        client_missing = [key for key in client_fields if key not in item]
        for key in ("started_ns", "ended_ns", "wall_ns", "thread_cpu_ns"):
            optional_integer(client[key])
        if client["thread_cpu_observation_available"] is not None:
            boolean(client["thread_cpu_observation_available"])
        client_complete = (not client_missing and type(client["succeeded"]) is bool
                           and client["started_ns"] is not None and client["ended_ns"] is not None
                           and client["started_ns"] <= client["ended_ns"] and client["wall_ns"] is not None
                           and type(client["scope"]) is str)
        client_cpu_complete = (client_complete and client["thread_cpu_observation_available"] is True
                               and client["thread_cpu_ns"] is not None)
        native = item.get("native_import_observation")
        require(native is None or type(native) is dict, "native import observation required")
        metadata_fields = ("schema", "measurement_failures", "packet_capacity", "supplied_packets",
                           "host_checks_are_nested_not_additive", "cpu_intervals_are_nested_not_additive",
                           "phase_cpu_excludes_scoped_workers", "host_cpu_includes_each_calling_thread",
                           "host_cpu_is_full_worker_cpu", "observation_has_consensus_authority", "clock_scope")
        metadata = {key: None if native is None else native.get(key) for key in metadata_fields}
        metadata_missing = [key for key in metadata_fields if native is None or key not in native]
        failures = optional_integer(metadata["measurement_failures"])
        packet_capacity = optional_integer(metadata["packet_capacity"])
        supplied_packets = optional_integer(metadata["supplied_packets"])
        page = phase_measurement_state(None if native is None else native.get("phases"))
        packet_rows = None if native is None else native.get("packets")
        require(packet_rows is None or (type(packet_rows) is list and len(packet_rows) <= 16
                                       and all(type(row) is dict for row in packet_rows)),
                "bounded packet phase observations required")
        packets = None if packet_rows is None else [
            {"packet_index": optional_integer(row.get("packet_index")), "packet_id": row.get("packet_id"),
             "phase_measurements": phase_measurement_state(row.get("phases"))} for row in packet_rows]
        host = host_measurement_state(None if native is None else native.get("host_checks"))
        host_roster_complete = (host is not None and [row["phase"] for row in host]
                                == ["resolve", "initial", "checkpoint", "final"])
        native_complete = (not metadata_missing and failures == 0 and page["lifecycle_complete"]
                           and metadata["schema"] == "pon-local-history-import-observation-v1"
                           and packet_capacity == 16 and supplied_packets is not None
                           and 0 <= supplied_packets <= packet_capacity
                           and any(row["phase"] == "history_import" and row["started"] is True
                                   and row["completed"] is True for row in page["records"])
                           and packets is not None and all(row["phase_measurements"]["lifecycle_complete"]
                                                           for row in packets)
                           and [row["packet_index"] for row in packets] == list(range(len(packets)))
                           and len(packets) <= supplied_packets
                           and metadata["host_checks_are_nested_not_additive"] is True
                           and metadata["cpu_intervals_are_nested_not_additive"] is True
                           and metadata["phase_cpu_excludes_scoped_workers"] is True
                           and metadata["host_cpu_includes_each_calling_thread"] is True
                           and metadata["host_cpu_is_full_worker_cpu"] is False
                           and metadata["observation_has_consensus_authority"] is False)
        known_cpu_slots = [] if host is None else [row["thread_cpu_ns"] for row in host
                                                   if row["thread_cpu_ns"] is not None]
        known_host_cpu = sum(known_cpu_slots) if known_cpu_slots else None
        unknown_host_cpu = (sum(row["cpu_clock_unknown_calls"] for row in host)
                            if host is not None and all(row["cpu_clock_unknown_calls"] is not None for row in host)
                            else None)
        host_cpu_complete = (client_complete and native_complete and host_roster_complete
                             and all(row["unentered_slot"] or row["cpu_measurement_complete"] for row in host)
                             and any(row["cpu_measurement_complete"] for row in host))
        imports.append({
            "history_index": index,
            "network_call_wall_ns": integer(call["elapsed_wall_ns"]),
            "client_import_wall_ns": client["wall_ns"] if client_complete else None,
            "client_import_calling_thread_cpu_ns": client["thread_cpu_ns"] if client_cpu_complete else None,
            "client_import_measurement": dict(client, missing_fields=client_missing,
                                               lifecycle_complete=client_complete,
                                               cpu_measurement_complete=client_cpu_complete),
            "succeeded": boolean(item["succeeded"]), "error": item["error"],
            "native_measurement": dict(metadata, missing_fields=metadata_missing,
                                        lifecycle_complete=native_complete,
                                        page_phase_measurements=page, packet_phase_measurements=packets),
            "host_checks": host, "host_roster_complete": host_roster_complete,
            "host_check_calls": (sum(row["calls_started"] for row in host)
                                 if host is not None and all(row["calls_started"] is not None for row in host) else None),
            "host_cpu_ns_known_sum": known_host_cpu,
            "host_cpu_known_slots": len(known_cpu_slots),
            "host_cpu_unknown_calls": unknown_host_cpu,
            "host_cpu_measurement_complete": host_cpu_complete,
            "host_cpu_ns": known_host_cpu if host_cpu_complete else None,
        })
    return imports


def phase_observation(raw, projection, requested):
    mode = raw["mode"]
    require(raw["duration_seconds"] == 30 and raw["attacker_processes_requested"] == requested,
            "original phase inputs changed")
    rounds = raw["confirmations"]
    require(type(rounds) is list and len(rounds) <= 3
            and [integer(row["round"]) for row in rounds] == list(range(len(rounds))),
            "confirmation rounds must retain original ordered prefix")
    confirmed = sum(boolean(row["confirmed_inside_pressure_window"]) for row in rounds)
    require(boolean(raw["all_signed_rounds_confirmed_in_window"]) == (len(rounds) == 3 and confirmed == 3),
            "native confirmation flag contradicts original denominator")
    expected = {
        "mode": mode, "scheduled_confirmation_rounds": 3,
        "observed_confirmation_rounds": len(rounds), "confirmed_rounds": confirmed,
        "unobserved_scheduled_rounds": 3 - len(rounds), "window_seconds": 30,
        "native_phase_criteria_met": boolean(raw["finite_phase_criteria_met"]),
        "genuine_budget_depletion_observed": boolean(raw["genuine_budget_depletion_observed"]),
        "receiver_client_state_equal": boolean(raw["receiver_client_state_equal"]),
        "native_verifier_errors": raw["verifier_errors"],
        "startup_or_campaign_error": raw.get("startup_or_campaign_error"),
    }
    require(all(projection[key] == value for key, value in expected.items()),
            "retained phase projection contradicts raw report")
    return dict(expected,
                service_returned_ok=isinstance(raw["service_outcome"], dict) and "Ok" in raw["service_outcome"],
                observed_rounds=[{"round": row["round"],
                                  "started_ns": integer(row["started_ns"]),
                                  "ended_ns": integer(row["ended_ns"]),
                                  "confirmed_inside_pressure_window": row["confirmed_inside_pressure_window"]}
                                 for row in rounds],
                history_imports=import_observations(raw))


def audit(path, expected_zip_sha256, expected_manifest_sha256, expected_head, expected_tree):
    digest(expected_head, 40)
    digest(expected_tree, 40)
    bundle = Artifact(path, expected_zip_sha256, expected_manifest_sha256)
    try:
        result = bundle.json("results.json")
        require(result["schema"] == "pon-original-native-campaign-ci-v1"
                and result["source_kind"] == "head" and result["profile"] == "release"
                and result["toolchain"] == "1.95.0" and result["state_backend"] == "authenticated-v1"
                and result["expected_head"] == expected_head and result["expected_tree"] == expected_tree
                and result["planned_complete_runs"] == 3 and result["original_inputs"] == INPUTS
                and result["public_phase_placement"] == PLACEMENT,
                "original campaign/source/profile declaration mismatch")
        source_names = ["source-before.json", "source-before-build.json", "source-before-campaigns.json",
                        "source-after-native.json", "source-after.json"]
        source_names += [f"run-{n}-source-after.json" for n in (1, 2, 3)]
        source_counts = [source_observation(bundle.json(name), expected_head, expected_tree)
                         for name in source_names]
        require(all(row == source_counts[0] for row in source_counts)
                and result["source_after"] == bundle.json("source-after-native.json"),
                "retained source counts or final observation changed")
        require(result["runner_sha256"] == bundle.files["run-native-campaign.py"]["sha256"],
                "retained runner identity mismatch")
        require(step_observation(bundle, result["build"], "build", build=True) == 0,
                "successful original build required for this diagnostic")
        binary = result["binary"]
        require(binary["retained"] == "public_v3_multiprocess.bin"
                and binary["sha256_before"] == binary["sha256_after"]
                == bundle.files[binary["retained"]]["sha256"]
                and binary["bytes"] == bundle.files[binary["retained"]]["bytes"],
                "retained binary bytes changed")
        attempts = result["attempts"]
        require([integer(row["number"]) for row in attempts] == [1, 2, 3],
                "all three predeclared attempts required")
        runs = []
        for attempt in attempts:
            number = attempt["number"]
            name = f"run-{number}"
            require(attempt == bundle.json(name + "-result.json")
                    and attempt["report_directory"] == name + "-raw"
                    and attempt["report_validation_failure"] is None, "original attempt identity mismatch")
            code = step_observation(bundle, attempt["step"], name)
            report_name = name + "-raw/report.json"
            require(attempt["report_sha256"] == bundle.files[report_name]["sha256"], "raw report pin mismatch")
            raw = bundle.json(report_name)
            projected = bundle.json(name + "-phase-readback.json")
            preparation = raw["preparation"]
            require(raw["schema"] == "native-public-v3-separate-process-campaign-v2"
                    and raw["state_backend"] == "authenticated-v1"
                    and preparation["state_backend"] == "authenticated-v1"
                    and preparation["actual_signed_seed_transfers"] == 1024
                    and preparation["seed_blocks"] == len(preparation["seed"]) == 4
                    and preparation["business_blocks"] == len(preparation["business"]) == 21
                    and sum(integer(row["transactions"]) for row in preparation["seed"]) == 1024
                    and [phase["mode"] for phase in raw["phases"]] == list(MODES)
                    and [phase["mode"] for phase in projected["phases"]] == list(MODES)
                    and projected["input"]["sha256"] == attempt["report_sha256"]
                    and projected["input"]["bytes"] == bundle.files[report_name]["bytes"],
                    "raw/projection input identity mismatch")
            policy = raw["public_resource_policy"]
            require(policy["schema"] == "public-protected-resource-policy-observation-v1"
                    and policy["policy_id"] == digest(result["expected_public_policy_id"])
                    and policy["ticket_bits"] == 8 and policy["lifetime_ms"] == 2000
                    and policy["transport_profile"] == "public-protected-development-v3"
                    and all(phase["public_resource_policy"] == policy for phase in raw["phases"]),
                    "recorded public policy changed across original phases")
            require(all(raw[key] is False for key in ("cryptographic_hardness_qualified",
                    "work_profile_qualified", "independent_operators", "wan_qualified",
                    "production_candidate", "release_ready")), "unsupported native qualification claim")
            phases = [phase_observation(phase, projection, requested)
                      for phase, projection, requested in zip(raw["phases"], projected["phases"], (0, 24, 24))]
            startup = [{"mode": p["mode"], "error": p["startup_or_campaign_error"]}
                       for p in phases if p["startup_or_campaign_error"] is not None]
            require(attempt["phase_startup_errors"] == startup, "phase startup error projection mismatch")
            criteria = (boolean(raw["finite_experiment_criteria_met"])
                        and boolean(raw["economics_complete"])
                        and all(p["native_phase_criteria_met"] for p in phases))
            require(boolean(attempt["original_criteria_met"]) == criteria
                    and boolean(attempt["complete_success"]) == (criteria and code == 0),
                    "retained run outcome contradiction")
            runs.append({"number": number, "returncode": code,
                         "complete_success": attempt["complete_success"],
                         "original_criteria_met": criteria, "phase_startup_errors": startup,
                         "raw_report_sha256": attempt["report_sha256"], "phases": phases})
            # A raw campaign report can be tens of MiB. The returned rows hold
            # only the selected projection; release this report before parsing
            # the next one, rather than briefly retaining two full ASTs.
            del raw, projected
        require(boolean(result["complete_success"]) == (all(run["complete_success"] for run in runs)
                                                       and not result["finalization_failures"]),
                "campaign outcome contradicts predeclared attempts")
        phases = [phase for run in runs for phase in run["phases"]]
        return {
            "schema": "pon-original-campaign-outcome-audit-v2", "audit_completed": True,
            "expected_head": expected_head, "expected_tree": expected_tree,
            "artifact": {"zip_bytes": bundle.before.st_size, "zip_sha256": bundle.zip_sha256,
                         "manifest_sha256": bundle.manifest_sha256,
                         "verified_members": len(bundle.files), "verified_member_bytes": bundle.total_bytes,
                         "no_unlisted_zip_members": True},
            "retained_binary_sha256": binary["sha256_after"],
            "original_inputs": INPUTS, "declared_public_phase_placement": PLACEMENT,
            "recorded_complete_success": result["complete_success"], "recorded_failure": result["failure"],
            "recorded_finalization_failures": result["finalization_failures"],
            "denominators": {"planned_runs": 3, "observed_runs": len(runs),
                             "successful_runs": sum(run["complete_success"] for run in runs),
                             "planned_phases": 9, "observed_phases": len(phases),
                             "planned_confirmation_rounds": 27,
                             "observed_confirmation_rounds": sum(p["observed_confirmation_rounds"] for p in phases),
                             "confirmed_rounds": sum(p["confirmed_rounds"] for p in phases),
                             "unobserved_scheduled_rounds": sum(p["unobserved_scheduled_rounds"] for p in phases)},
            "runs": runs,
            "scope": {"native_tests_executed": False, "consensus_or_signatures_replayed": False,
                      "source_and_host_authenticated": False, "phase_projection_scope": "listed fields only",
                      "artifact_integrity_is_not_execution_authenticity": True,
                      "nested_timing_intervals_are_not_additive": True,
                      "client_import_cpu_scope": "calling thread; excludes scoped worker CPU",
                      "host_cpu_scope": "sum across individual calling threads; not full worker or process-tree CPU",
                      "host_cpu_known_sum_scope": "only available per-Host-slot aggregates; incomplete slots and missing observations remain explicit",
                      "unknown_cpu_is_not_zero": True, "sole_cause_established": False,
                      "host_four_second_acceptance_closed": False, "independent_wan_acceptance_closed": False,
                      "production_activation": False},
        }
    finally:
        bundle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-zip", type=Path, required=True)
    parser.add_argument("--expected-zip-sha256", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    args = parser.parse_args()
    try:
        value = audit(args.artifact_zip, args.expected_zip_sha256, args.expected_manifest_sha256,
                      args.expected_head, args.expected_tree)
    except (OSError, ValueError, KeyError, TypeError, IndexError, zipfile.BadZipFile) as error:
        parser.exit(1, "campaign outcome audit refused: " + str(error) + "\n")
    print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
