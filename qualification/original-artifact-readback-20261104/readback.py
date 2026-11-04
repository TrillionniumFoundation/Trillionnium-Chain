#!/usr/bin/env python3
"""Bounded read-only inspection of two frozen original Actions artifacts.

No archive member is extracted or executed. Download and ZIP/JSON validation
success is evidence-readback success, never native or business qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
REPOSITORY_ID = 1323087357
BRANCH = "refs/heads/research/chain-original-cpu-readback-20261103-gpt6"
COMPRESSED_BUDGET = 96 * 1024 * 1024
DECODED_BUDGET = 512 * 1024 * 1024
MEMBER_BUDGET = 256 * 1024 * 1024
JSON_MEMBER_BUDGET = 16 * 1024 * 1024
REPORT_JSON_BUDGET = 128 * 1024 * 1024
JSON_RETAINED_BUDGET = 64 * 1024 * 1024
DERIVED_BUDGET = 8 * 1024 * 1024
ADDRESS_SPACE_BUDGET = 4 * 1024 * 1024 * 1024
PRINT_BUDGET = 2 * 1024 * 1024
CHUNK = 64 * 1024


class Rejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    require(math.isfinite(number), "NONFINITE_JSON_NUMBER")
    return number


def parse_json(data):
    def invalid_constant(_value):
        raise Rejected("NONFINITE_JSON_CONSTANT")
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_float=finite_float, parse_constant=invalid_constant)


def safe_url(url):
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == "https" and parts.hostname is not None
            and parts.username is None and parts.password is None
            and parts.port in (None, 443) and not parts.fragment,
            "ARCHIVE_URL_NOT_HTTPS")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def api_request(path, token):
    require(path.startswith("/repos/" + REPOSITORY + "/"), "API_REPOSITORY")
    return urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "trnm-frozen-artifact-readback",
    })


def api_json(path, token):
    with urllib.request.build_opener(NoRedirect()).open(
            api_request(path, token), timeout=60) as response:
        payload = response.read(1024 * 1024 + 1)
    require(len(payload) <= 1024 * 1024, "API_JSON_BUDGET")
    return parse_json(payload)


def archive_location(artifact_id, token):
    request = api_request(
        f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip", token)
    try:
        with urllib.request.build_opener(NoRedirect()).open(
                request, timeout=60) as response:
            raise Rejected("ARCHIVE_REDIRECT_REQUIRED")
    except urllib.error.HTTPError as error:
        try:
            require(error.code in (302, 303, 307), "ARCHIVE_REDIRECT_STATUS")
            location = error.headers.get("Location")
            require(isinstance(location, str), "ARCHIVE_REDIRECT_LOCATION")
            return safe_url(location)
        finally:
            error.close()


def check_metadata(spec, artifact, run, commit):
    require(artifact.get("id") == spec["artifact_id"]
            and artifact.get("name") == spec["artifact_name"]
            and artifact.get("size_in_bytes") == spec["bytes"]
            and artifact.get("digest") == "sha256:" + spec["sha256"]
            and artifact.get("expired") is False, "ARTIFACT_METADATA_CHANGED")
    workflow = artifact.get("workflow_run", {})
    require(workflow.get("id") == spec["run_id"]
            and workflow.get("head_sha") == spec["source"]
            and workflow.get("repository_id") == REPOSITORY_ID
            and workflow.get("head_repository_id") == REPOSITORY_ID,
            "ARTIFACT_WORKFLOW_SOURCE")
    require(run.get("id") == spec["run_id"]
            and run.get("head_sha") == spec["source"]
            and run.get("run_attempt") == 1
            and run.get("status") == "completed"
            and run.get("conclusion") == "failure", "ORIGINAL_FAILED_RUN_REQUIRED")
    require(commit.get("sha") == spec["source"]
            and commit.get("tree", {}).get("sha") == spec["tree"],
            "SOURCE_COMMIT_TREE")


def download(spec, token, path, budget):
    require(spec["bytes"] <= budget["compressed"], "COMPRESSED_TOTAL_BUDGET")
    location = archive_location(spec["artifact_id"], token)
    # The API Authorization header is deliberately absent from this new request.
    request = urllib.request.Request(location, headers={
        "User-Agent": "trnm-frozen-artifact-readback"})
    digest = hashlib.sha256()
    count = 0
    with urllib.request.build_opener(HttpsRedirect()).open(
            request, timeout=60) as response, path.open("xb") as output:
        while True:
            block = response.read(min(CHUNK, spec["bytes"] - count + 1))
            if not block:
                break
            count += len(block)
            budget["compressed"] -= len(block)
            require(count <= spec["bytes"] and budget["compressed"] >= 0,
                    "COMPRESSED_STREAM_BUDGET")
            digest.update(block)
            output.write(block)
    require(count == spec["bytes"] and digest.hexdigest() == spec["sha256"],
            "ARCHIVE_BYTES_OR_DIGEST")


def validate_members(infos, remaining):
    require(0 < len(infos) <= 10000, "MEMBER_COUNT")
    seen = set()
    total = 0
    for info in infos:
        name = info.filename
        require(isinstance(name, str) and name and "\\" not in name
                and not any(ord(c) < 32 or ord(c) == 127 for c in name),
                "MEMBER_PATH_ENCODING")
        bare = name[:-1] if info.is_dir() else name
        require(bare and not bare.startswith("/")
                and not re.match(r"^[A-Za-z]:", bare)
                and all(p not in ("", ".", "..") for p in bare.split("/")),
                "MEMBER_PATH")
        require(name not in seen, "DUPLICATE_MEMBER")
        seen.add(name)
        mode = info.external_attr >> 16
        require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                "MEMBER_TYPE")
        require(not (info.flag_bits & 1), "ENCRYPTED_MEMBER")
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                "MEMBER_COMPRESSION")
        require(0 <= info.file_size <= MEMBER_BUDGET, "MEMBER_SIZE")
        total += info.file_size
        require(total <= remaining, "DECLARED_DECODED_TOTAL")
    return total


def wanted_json(name, spec):
    return name in spec["required_json"] or name in spec["project_json"]


def large_original_report(name, spec):
    if spec["kind"] == "campaign":
        return name in {f"run-{i}-raw/report.json" for i in (1, 2, 3)}
    return name in {"execution/raw/report.json", "execution/raw/baseline.json",
                    "execution/raw/valid-work-root.json"}


def inspect_zip(path, spec, budget):
    files, documents, projected, summaries, client_costs = {}, {}, {}, {}, {}
    seen_documents = set()
    retained = 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        declared = validate_members(infos, budget["decoded"])
        for info in infos:
            selected = not info.is_dir() and wanted_json(info.filename, spec)
            if selected:
                limit = (REPORT_JSON_BUDGET if large_original_report(info.filename, spec)
                         else JSON_MEMBER_BUDGET)
                if info.file_size > limit:
                    print(json.dumps({"selected_json_size_rejected": {
                        "known_member": info.filename,
                        "declared_bytes": info.file_size, "limit_bytes": limit,
                        "archive_digest_verified": True,
                        "complete_zip_crc_verification": False,
                        "native_executed": False}}, sort_keys=True), flush=True)
                    raise Rejected("SELECTED_JSON_SIZE")
                if not large_original_report(info.filename, spec):
                    retained += info.file_size
                    require(retained <= JSON_RETAINED_BUDGET, "SELECTED_JSON_TOTAL")
            parts = [] if selected else None
            digest = hashlib.sha256()
            count = 0
            # Every member reaches EOF, so zipfile checks the original CRC.
            # No paths from the ZIP are used for writes or command execution.
            with archive.open(info) as member:
                while True:
                    block = member.read(min(CHUNK, budget["decoded"] + 1))
                    if not block:
                        break
                    count += len(block)
                    budget["decoded"] -= len(block)
                    require(count <= info.file_size and budget["decoded"] >= 0,
                            "RETURNED_DECODED_BUDGET")
                    digest.update(block)
                    if parts is not None:
                        parts.append(block)
            require(count == info.file_size, "MEMBER_SHORT_READ")
            files[info.filename] = {
                "bytes": count, "sha256": digest.hexdigest(),
                "crc32": f"{info.CRC:08x}", "directory": info.is_dir(),
            }
            if parts is not None:
                # A known original report is parsed, projected and discarded
                # before reading the next one; it is never retained as a raw
                # parsed report beside other large original reports.
                value = parse_json(b"".join(parts))
                seen_documents.add(info.filename)
                if info.filename in spec["project_json"]:
                    projected[info.filename] = projection(value)
                    if isinstance(value, dict) and "phases" in value:
                        summaries[info.filename] = phase_summary(value)
                        client_costs[info.filename] = client_cost_summary(value)
                if not large_original_report(info.filename, spec):
                    documents[info.filename] = value
                del value
                del parts
    require(all(name in seen_documents for name in spec["required_json"]),
            "REQUIRED_JSON_MISSING")
    for name in spec["source_json"]:
        source = documents[name]
        require(source.get("schema") == "trnm-ci-source-v1"
                and source.get("candidate") == spec["source"]
                and source.get("tested_commit") == spec["source"]
                and source.get("tested_tree") == spec["tree"]
                and source.get("tracked_worktree_verified") is True,
                "ORIGINAL_SOURCE_RECEIPT")
    if spec["kind"] == "campaign":
        result = documents["results.json"]
        require(result.get("schema") == "pon-original-native-campaign-ci-v1"
                and result.get("expected_head") == spec["source"]
                and result.get("expected_tree") == spec["tree"]
                and result.get("complete_success") is False
                and result.get("failure") == "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED",
                "ORIGINAL_CAMPAIGN_RESULT")
        require(result.get("original_inputs") == {
            "attacker_processes": [0, 24, 24], "business_blocks": 21,
            "modes": ["baseline", "from-zero", "late-product"],
            "phase_seconds": 30, "seed_blocks": 4, "seed_transfers": 1024,
        }, "ORIGINAL_CAMPAIGN_INPUTS")
        binary = result["binary"]
        require(files["public_v3_multiprocess.bin"]["sha256"]
                == binary["sha256_before"] == binary["sha256_after"]
                and files["public_v3_multiprocess.bin"]["bytes"] == binary["bytes"],
                "ORIGINAL_NATIVE_BINARY")
        attempts = result["attempts"]
        require(len(attempts) == 3, "ORIGINAL_ATTEMPTS")
        for ordinal, attempt in enumerate(attempts, 1):
            report_name = f"run-{ordinal}-raw/report.json"
            require(attempt["number"] == ordinal
                    and attempt["report_sha256"] == files[report_name]["sha256"],
                    "ORIGINAL_REPORT_HASH")
    return files, documents, declared, projected, summaries, client_costs


BLOCKED = re.compile(
    r"header|packet|transaction|signature|private|secret|payload|state_rows|"
    r"proof|witness|seed$|business$|key_material|signed_request|raw_body",
    re.IGNORECASE)
# Closed field labels copied from the immutable producer's static JSON labels
# (public_v3_multiprocess.rs Git blob ec6420becaba837f22d45c917d15554a8e653275)
# plus the explicit controller/metric labels below. Unknown labels are hashed.
SAFE_FIELDS = set("""
abandoned_tasks accepted_work_admission_refusals account_parse_calls account_parse_cpu_ns account_parse_wall_ns account_rows acquisition
acquisition_cpu_ns acquisition_wall_ns acquisitions actor_call_cap actor_readiness actor_reports_successful_without_cap_or_kill actors
actual_compiler_artifact_profile actual_flow actual_signed_seed_transfers address admission_cpu_ns adversarial_key_churn_service_qualified aggregate_membership_verified
aggregate_scoped_cpu_ns all_attempts_or_error all_signed_rounds_confirmed_in_window at_ns attack_calls_overlapping_each_signed_round attacker_process_rss attacker_processes
attacker_processes_ready attacker_processes_requested attempt_cap_reached attempt_count attempts balance_identity_has_work_or_execution_authority best_observed_cold_legal_method
binary body_bytes body_digest budget_samples business business_blocks business_packets
business_started_ns bytes call calls candidate checked_acquisitions_complete checkpoints
children children_os_usage_after children_os_usage_before client_thread_cost clock clock_failures cold_state_equal
cold_unchanged command complete_success completed_utc confirmations confirmed_inside_pressure_window controller_cgroup
cost_scope count cpu_max cpu_ns credit_freshness credit_freshness_ended_ns credit_freshness_started_ns
criteria_met cryptographic_hardness_qualified cwd debug_assertions debuginfo decode_cpu_ns decode_wall_ns
depleted depletion_at_ns depletion_meter depletion_qualified diagnostic_cpu_ns diagnostic_result diagnostic_wall_ns
dispatch_started dispatch_thread_cpu_ns dispatch_wall_ns domain_cpu_scope duration_seconds each_rejection_unchanged economics
economics_complete edges elapsed elapsed_ns elapsed_seconds encoded_packet_bytes encoding_measured
end_ns ended_ns entire_actor_cpu_ns entire_actor_wall_ns entries epoch_ns error
errors executor_refusals exit_status exit_success expected_head expected_legal_counts_and_tip expected_public_policy_id
expected_resources expected_state_rows expected_stats expected_tree failure failures final_actual_flow
final_client_tip final_flow final_meter final_receiver_tip final_state_rows final_stats finalization_failures
finite_experiment_criteria_met finite_phase_criteria_met fixture_packet_encoding_cost flow_after flow_before full_work_accepted full_work_failed
genuine_budget_depletion_observed graph_cpu_ns graph_wall_ns hash_cpu_ns hash_wall_ns header history
hits hostile_packet_ids hostile_packets_absent_cold hostile_packets_absent_live id identity_scope included_block
independent_operators independent_reference_w1_verification_cost independent_verification_cpu_ns independent_verification_wall_ns independent_wrong_root_w1_verification_cost initial_flow initial_meter
initial_setup_cpu_ns initial_setup_wall_ns initial_state initial_stats initial_tip kind legal_after_cold_reopen
legal_cold_equal legal_equal live_unchanged log m06_workers matched_requests max
max_cpu_ns max_wall_ns memory_max memory_swap_max meter method method_index
min misses mode modes mutation_cpu_charged_ns mutation_cpu_clock_failures mutation_cpu_ns
mutation_owner_cpu_ns name native_history_arithmetic_after native_history_arithmetic_before native_stats_after nodes nonce
number observation observation_ended_ns observation_started_ns observed_terminal_mutation_cpu_refusals observer observer_complete
ok operation opt_level ordinal original_campaign_qualified original_criteria_met original_inputs
overflow_checks packet_bytes packet_digest paid_owner_plus_scoped_worker_cpu_ns parent_forced_kill parent_height passed
path peak_bytes pending_grant_wait_ns phase phase_seconds phase_startup_errors phase_summaries
phases pid pids_max planned_complete_runs pool_context preparation preparation_cost
preparation_cost_known preparation_measured producer_method producer_setup_cost producer_state_equal production_activation production_candidate
profile proof_digest public_phase_placement public_request_body_digest queue_backpressure_events queue_wait_ns quiescent
reads reason receiver_and_verifier_cpu_max receiver_and_verifier_memory_max receiver_and_verifier_setup_cpu_ns receiver_and_verifier_setup_wall_ns receiver_client_state_equal
receiver_hostile_after receiver_hostile_before receiver_hostile_work_rejected_during_round receiver_observation receiver_setup_cost records reference_acceptance_cost
reference_cost reference_packet reference_packet_id refusal rejected_work_cpu_ns rejections relation_diagnostics
relation_rejection_matches_mode release_ready replies_match report report_path report_validation_failure request_encoding_cost
response result results retained_bytes retained_software_bytes returncode returned_after_window
reuse reuse_preparation root_cpu_ns root_wall_ns round round_snapshot_scope rss
rss_after rss_before same_task_target_from_zero_samples sample sample_at_ns samples schema
scope search search_cpu_ns search_wall_ns searches seed seed_blocks
seed_packets seed_transfers selection_candidates_cpu_ns separately_observed_public_settled_cpu_ns service service_outcome settings_profile
settled setup_calls setup_calls_per_sample setup_cpu_ns setup_wall_ns sha256_after sha256_before
signed_seed_transfers signed_transactions slots source_after source_before source_kind spawn_to_reap_wall_ns
sql_cpu_ns sql_wall_ns stages_match start_marker started_ns started_utc startup_or_campaign_error
state_backend status stderr stdout step strict_changed_header_verification strict_reference_verification
submissions success sum supplemental_criteria_met target_hit test tested_commit
tested_tree thread_cpu_ns thread_cpu_observation_available tip total total_cpu_ns total_paid_owner_plus_scoped_worker_cpu_ns
total_wall_ns traffic_cpu_ns traffic_wall_ns transaction transactions valid_work_for_root_rejection value
verified_winners verifier_errors wall_ns wan_qualified whole_domain_paid_reconciled whole_entry_cpu_ns whole_entry_wall_ns
whole_parent_phase_cpu_ns whole_parent_phase_wall_ns winning_header work_accepted work_finished work_profile_qualified work_rejected
work_started worker writes wrong_absence_after_legal_error wrong_absence_error wrong_packet_id wrong_root_packet
""".split())
SAFE_FIELDS.update({"Ok", "Err", "Invalid", "Io", "BudgetExhausted",
                    "Protocol", "Resource", "message", "code"})
# Fixed labels from the exact 312 fresh-service manifest producer. Values
# still pass through the same closed scalar/error projection and output caps.
SAFE_FIELDS.update("""
all_named_tests_passed execution_finished source_recompiled requested_window_ns
attack_workers independent_wan_accepted work_hardness_accepted failure_diagnostic
native_returncode finite_target_met last_history_replay replay_error replay_accepted
history_call_index acceptance_authority
""".split())

SAFE_STRINGS = {
  "baseline",
  "from-zero",
  "late-product",
  "valid-work-root",
  "head",
  "prospective-merge",
  "authenticated-v1",
  "release",
  "test",
  "ok",
  "success",
  "failure",
  "completed",
  "queued",
  "in_progress",
  "accepted",
  "refused",
  "rejected",
  "timeout",
  "run-1",
  "run-2",
  "run-3",
  "25000 100000",
  "400000 100000",
  "2147483648",
  "17179869184",
  "0",
  "256",
  "max",
  "pon-original-native-campaign-ci-v1",
  "trnm-ci-source-v1",
  "native-public-v3-separate-process-campaign-v2",
  "native-public-v3-root-rejection-supplement-v1",
  "f35ee6dc61feaba7c68b16e1f9384b5c3794a976",
  "87870eb9fc3d6477ee35e59334ccdbb669721777"
}
SAFE_STRINGS.update({
    "312c9abc0d5bfafb6aa5409f4596f85c2993241e",
    "a53dc18d56df9d61179114aa16b341253a940acb",
    "trnm-w1-fresh-service-execution-v1",
    "trnm-w1-fresh-failure-diagnostic-v1",
    "from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline",
    "fresh_challenge::fresh_challenge_signed_confirmation_keeps_original_pressure_budget",
    "attack-free-baseline", "from-zero-pressure", "unknown",
})
ERROR_FIELDS = re.compile(r"error|failure|reason|refusal", re.IGNORECASE)
KNOWN_CODES = {
    "PUBLIC_REQUEST_DEADLINE", "PUBLIC_MUTATION_CPU_BUDGET", "ROOT",
    "UNKNOWN_PARENT", "OwnerReorgTerminationCpuRequired",
    "FRESH_NATIVE_PROCESS_REQUIRED", "CONFIRMATION_TARGET",
    "WouldBlock", "TimedOut", "ConnectionRefused", "BROKEN_PIPE",
    "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED",
}


def safe_field(name):
    require(isinstance(name, str), "JSON_KEY_TYPE")
    if name in SAFE_FIELDS:
        return name
    return "field_sha256:" + hashlib.sha256(name.encode()).hexdigest()


def omitted_value(value):
    digest = hashlib.sha256()
    count = 0
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False)
    for part in encoder.iterencode(value):
        encoded = part.encode()
        digest.update(encoded)
        count += len(encoded)
    return {"canonical_json_sha256": digest.hexdigest(),
            "canonical_json_bytes": count, "value_omitted": True}


def safe_member_manifest(files, spec):
    known = set(spec["required_json"] + spec["source_json"] + spec["project_json"])
    known.add("public_v3_multiprocess.bin")
    output = {}
    for name, metadata in files.items():
        label = name if name in known else (
            "member_path_sha256:" + hashlib.sha256(name.encode()).hexdigest())
        require(label not in output, "MEMBER_LABEL_COLLISION")
        output[label] = metadata
    return output


def aggregate_records(rows):
    groups = {}
    for row in rows:
        if not isinstance(row, dict):
            group_key = ("malformed", None)
        else:
            op = row.get("operation")
            dispatch = row.get("dispatch_started")
            group_key = (op if op is None or (type(op) is int and 0 <= op <= 255) else "unknown",
                         dispatch if type(dispatch) is bool else None)
        group = groups.setdefault(group_key, {"rows": 0, "numeric": {}, "nulls": {}})
        group["rows"] += 1
        def visit(item, path="", depth=0):
            if depth > 8:
                return
            if item is None:
                group["nulls"][path] = group["nulls"].get(path, 0) + 1
            elif type(item) in (int, float):
                group["numeric"].setdefault(path, []).append(item)
            elif isinstance(item, dict):
                for name, child in item.items():
                    if name in SAFE_FIELDS and not BLOCKED.search(name):
                        visit(child, f"{path}.{name}" if path else name, depth + 1)
        visit(row)
    result = []
    for (op, dispatch), group in groups.items():
        statistics = {}
        for name, values in group["numeric"].items():
            values.sort()
            label = ".".join(safe_field(part) for part in name.split("."))
            require(label not in statistics, "METRIC_LABEL_COLLISION")
            statistics[label] = {
                "samples": len(values), "sum": sum(values),
                "min": values[0], "max": values[-1],
                "p50_nearest_rank": values[max(0, math.ceil(len(values) * .50) - 1)],
                "p95_nearest_rank": values[max(0, math.ceil(len(values) * .95) - 1)],
                "p99_nearest_rank": values[max(0, math.ceil(len(values) * .99) - 1)],
            }
        result.append({"operation": op, "dispatch_started": dispatch,
                       "recorded_rows": group["rows"], "statistics": statistics,
                       "null_counts": {".".join(safe_field(part) for part in name.split(".")): count
                                       for name, count in group["nulls"].items()}})
    return {"recorded_rows": len(rows), "groups": result,
            "scope": "numeric fields reached by this bounded projection, grouped across all recorded rows; unknown labels hashed; nested costs are not additive; no network/business acceptance claim"}

def projection(value, key="", depth=0):
    if depth > 16:
        return {"omitted_deeper_structure": True}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if value in SAFE_STRINGS:
            return value
        if ERROR_FIELDS.search(key):
            return {"text_sha256": hashlib.sha256(value.encode()).hexdigest(),
                    "characters": len(value),
                    "known_codes": sorted(code for code in KNOWN_CODES if code in value),
                    "literal_code": value if value in KNOWN_CODES else None}
        return {"omitted_string_sha256": hashlib.sha256(value.encode()).hexdigest(),
                "characters": len(value)}
    if isinstance(value, list):
        if key == "records":
            return aggregate_records(value)
        if key == "budget_samples":
            return {"recorded_samples": len(value),
                    "first": projection(value[0], "", depth + 1) if value else None,
                    "last": projection(value[-1], "", depth + 1) if value else None,
                    "scope": "endpoint projection only; all original samples remain in the verified archive"}
        return [projection(item, key, depth + 1) for item in value]
    if isinstance(value, dict):
        output = {}
        for name, item in value.items():
            if BLOCKED.search(name) or name in (
                    "economics", "children", "preparation", "environment",
                    "command", "cwd", "scope"):
                continue
            label = safe_field(name)
            require(label not in output, "JSON_LABEL_COLLISION")
            output[label] = (projection(item, name, depth + 1)
                             if name in SAFE_FIELDS else omitted_value(item))
        return output
    raise Rejected("JSON_VALUE_TYPE")


def phase_summary(report):
    phases = report.get("phases")
    require(isinstance(phases, list), "PHASE_ARRAY")
    def optional_bool(value):
        require(value is None or type(value) is bool, "PHASE_BOOL")
        return value
    def optional_int(value, allowed):
        require(value is None or (type(value) is int and value in allowed),
                "PHASE_INTEGER")
        return value
    output = []
    for phase in phases:
        require(isinstance(phase, dict), "PHASE_OBJECT")
        mode = phase.get("mode")
        require(mode in ("baseline", "from-zero", "late-product", "valid-work-root"),
                "PHASE_MODE")
        confirmations = phase.get("confirmations")
        require(confirmations is None or isinstance(confirmations, list),
                "CONFIRMATION_ARRAY")
        flags = []
        if confirmations is not None:
            for row in confirmations:
                require(isinstance(row, dict), "CONFIRMATION_OBJECT")
                flags.append(optional_bool(row.get("confirmed_inside_pressure_window")))
        root = phase.get("root_supplement")
        require(root is None or isinstance(root, dict), "ROOT_SUPPLEMENT_OBJECT")
        output.append({
            "mode": mode,
            "duration_seconds": optional_int(phase.get("duration_seconds"), {30}),
            "attacker_processes_requested": optional_int(
                phase.get("attacker_processes_requested"), {0, 24}),
            "attacker_processes_ready": optional_int(
                phase.get("attacker_processes_ready"), set(range(25))),
            "planned_signed_rounds": 3,
            "recorded_rounds": len(flags) if confirmations is not None else None,
            "confirmed_rounds": sum(flag is True for flag in flags)
                if confirmations is not None else None,
            "confirmation_flag_unknowns": sum(flag is None for flag in flags)
                if confirmations is not None else None,
            "finite_phase_criteria_met":
                optional_bool(phase.get("finite_phase_criteria_met")),
            "all_signed_rounds_confirmed_in_window":
                optional_bool(phase.get("all_signed_rounds_confirmed_in_window")),
            "startup_or_campaign_error":
                projection(phase.get("startup_or_campaign_error"), "error"),
            "root_criteria":
                optional_bool(root.get("criteria_met")) if root is not None else None,
        })
    return output


def encode_json(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def write_outputs(out, payloads, budget):
    total = sum(len(payload) for payload in payloads.values())
    require(total <= budget["derived"], "DERIVED_TOTAL_BUDGET")
    budget["derived"] -= total
    for name, payload in payloads.items():
        with (out / name).open("xb") as stream:
            stream.write(payload)




CLIENT_NATIVE_PHASES = (
    "decode", "context_owner_wait", "context", "work", "admission_owner_wait",
    "admission", "submit_result", "admission_prepare", "execution",
    "commit_owner_wait", "commit", "cpu_wait", "body_decode",
    "response_encoding", "history_epoch_open", "history_epoch_close",
    "history_import", "cpu_settle", "root_commitment",
)
CLIENT_HOST_PHASES = ("resolve", "initial", "checkpoint", "final")


def metric_stats(values):
    require(all(value is None or (type(value) is int and 0 <= value < (1 << 128))
                for value in values), "CLIENT_METRIC_INTEGER")
    known = [value for value in values if value is not None]
    return {"known_samples": len(known), "unknown_samples": len(values) - len(known),
            "sum": sum(known) if known else None,
            "min": min(known) if known else None,
            "max": max(known) if known else None}


def metric_flags(values):
    require(all(value is None or type(value) is bool for value in values),
            "CLIENT_METRIC_BOOL")
    return {"true": sum(value is True for value in values),
            "false": sum(value is False for value in values),
            "unknown": sum(value is None for value in values)}


def client_cost_summary(report):
    """Fixed public timing fields only; no packet/state/path/string readback."""
    phases = report.get("phases")
    require(isinstance(phases, list), "CLIENT_PHASE_ARRAY")
    output = []
    for phase in phases:
        require(isinstance(phase, dict), "CLIENT_PHASE_OBJECT")
        mode = phase.get("mode")
        require(mode in ("baseline", "from-zero", "late-product", "valid-work-root"),
                "CLIENT_PHASE_MODE")
        history = phase.get("history")
        require(history is None or (isinstance(history, list) and len(history) <= 64
                and all(isinstance(row, dict) for row in history)), "CLIENT_HISTORY_ROWS")
        if history is None:
            # A retained failed phase may never reach client observations.
            # Absence is not an observed empty set or zero CPU.
            output.append({
                "mode": mode, "recorded_history_calls": None,
                "client_import": None, "client_confirmation": None,
                "native_snapshots_present": None, "native_phases": None,
                "host_checks": None,
                "scope": "original phase has no client History observations; costs and counts are unknown; no acceptance",
            })
            continue
        imports, confirmations, snapshots = [], [], []
        for row in history:
            for key, target in (("client_import", imports),
                                ("client_confirmation", confirmations)):
                stamp = row.get(key)
                require(stamp is None or isinstance(stamp, dict), "CLIENT_STAMP_OBJECT")
                if stamp is not None:
                    target.append(stamp)
            stamp = row.get("client_import")
            snapshot = stamp.get("native_import_observation") if stamp is not None else None
            require(snapshot is None or isinstance(snapshot, dict), "CLIENT_SNAPSHOT_OBJECT")
            if snapshot is not None:
                snapshots.append(snapshot)
        native_groups = {name: [] for name in CLIENT_NATIVE_PHASES}
        host_groups = {name: [] for name in CLIENT_HOST_PHASES}
        for snapshot in snapshots:
            for key, allowed, groups in (
                    ("phases", CLIENT_NATIVE_PHASES, native_groups),
                    ("host_checks", CLIENT_HOST_PHASES, host_groups)):
                rows = snapshot.get(key)
                require(isinstance(rows, list) and len(rows) == len(allowed)
                        and all(isinstance(row, dict) for row in rows),
                        "CLIENT_OBSERVATION_ROWS")
                identities = [row.get("phase") for row in rows]
                require(all(isinstance(name, str) and name in allowed for name in identities)
                        and len(set(identities)) == len(allowed), "CLIENT_PHASE_IDENTITIES")
                for row in rows:
                    groups[row["phase"]].append(row)
        def stamp_summary(rows):
            return {
                "observed_stamps": len(rows),
                "succeeded": metric_flags([row.get("succeeded") for row in rows]),
                "wall_ns": metric_stats([row.get("wall_ns") for row in rows]),
                "thread_cpu_ns": metric_stats([row.get("thread_cpu_ns") for row in rows]),
                "thread_cpu_observation_available": metric_flags(
                    [row.get("thread_cpu_observation_available") for row in rows]),
            }
        output.append({
            "mode": mode, "recorded_history_calls": len(history),
            "client_import": stamp_summary(imports),
            "client_confirmation": stamp_summary(confirmations),
            "native_snapshots_present": len(snapshots),
            "native_measurement_failures": metric_stats(
                [row.get("measurement_failures") for row in snapshots]),
            "native_phases": [
                {"phase": name, "observed_slots": len(rows),
                 "started": metric_flags([row.get("started") for row in rows]),
                 "completed": metric_flags([row.get("completed") for row in rows]),
                 "accepted": metric_flags([row.get("accepted") for row in rows]),
                 "wall_ns": metric_stats([row.get("wall_ns") for row in rows]),
                 "thread_cpu_ns": metric_stats([row.get("thread_cpu_ns") for row in rows])}
                for name, rows in native_groups.items()],
            "host_checks": [
                {"phase": name, "observed_slots": len(rows),
                 **{field: metric_stats([row.get(field) for row in rows])
                    for field in ("calls_started", "calls_completed", "calls_accepted",
                                  "calls_rejected", "calls_unfinished", "wall_ns",
                                  "thread_cpu_ns", "wall_clock_unknown_calls",
                                  "cpu_clock_unknown_calls")}}
                for name, rows in host_groups.items()],
            "scope": "all recorded client History rows in this original report, at most 64; importer phase CPU excludes scoped workers; Host and child phases are nested and must not be added to the parent or each other; missing clocks stay unknown; no business or native acceptance",
        })
    return output


def stdout_projection(projected, encoded):
    """A deliberately incomplete view; full safe projection stays in its file."""
    remaining = [4096]
    def visit(value, depth=0):
        if remaining[0] <= 0 or depth > 12:
            return {"stdout_omitted": True}
        remaining[0] -= 1
        if isinstance(value, dict):
            output, omitted = {}, 0
            items = list(value.items())
            for index, (name, item) in enumerate(items):
                if remaining[0] <= 0:
                    omitted += len(items) - index
                    break
                if name.startswith("field_sha256:") or name in (
                        "omitted_string_sha256", "canonical_json_sha256",
                        "canonical_json_bytes", "characters", "value_omitted"):
                    omitted += 1
                    continue
                output[name] = visit(item, depth + 1)
            if omitted:
                output["stdout_omitted_fields"] = omitted
            return output
        if isinstance(value, list):
            if len(value) > 16:
                return {
                    "recorded_items": len(value),
                    "first": [visit(item, depth + 1) for item in value[:8]],
                    "last": [visit(item, depth + 1) for item in value[-8:]],
                    "stdout_omitted_items": len(value) - 16,
                }
            return [visit(item, depth + 1) for item in value]
        return value
    return {
        "complete_projection_bytes": len(encoded),
        "complete_projection_sha256": hashlib.sha256(encoded).hexdigest(),
        "stdout_projection_is_complete": False,
        "stdout_node_limit": 4096,
        "projection": visit(projected),
        "scope": "limited view of the already-sanitized projection; opaque hash fields, deeper structure and middle array elements may be omitted; complete projected bytes remain in the output artifact",
    }


def self_test():
    count = 0
    def rejects(function, code):
        nonlocal count
        try:
            function()
        except Rejected as error:
            require(str(error) == code, "SELF_TEST_WRONG_REJECTION")
        else:
            raise Rejected("SELF_TEST_ACCEPTED_NEGATIVE")
        count += 1
    valid = zipfile.ZipInfo("nested/report.json")
    valid.file_size = 2
    require(validate_members([valid], 2) == 2, "SELF_TEST_VALID_MEMBER")
    count += 1
    for name in ("../escape", "/absolute", "C:/escape", "nested//file"):
        bad = zipfile.ZipInfo(name)
        rejects(lambda bad=bad: validate_members([bad], 100), "MEMBER_PATH")
    bad = zipfile.ZipInfo("nested\\file")
    rejects(lambda: validate_members([bad], 100), "MEMBER_PATH_ENCODING")
    rejects(lambda: validate_members([valid, valid], 100), "DUPLICATE_MEMBER")
    link = zipfile.ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    rejects(lambda: validate_members([link], 100), "MEMBER_TYPE")
    rejects(lambda: validate_members([valid], 1), "DECLARED_DECODED_TOTAL")
    rejects(lambda: parse_json(b'{"a":1,"a":2}'), "DUPLICATE_JSON_KEY")
    rejects(lambda: parse_json(b'{"a":1e999}'), "NONFINITE_JSON_NUMBER")
    rejects(lambda: parse_json(b'{"a":NaN}'), "NONFINITE_JSON_CONSTANT")
    require(parse_json(b'{"a":1,"b":[true,null]}') == {"a": 1, "b": [True, None]},
            "SELF_TEST_VALID_JSON")
    count += 1
    sample = projection({"packet": "DO_NOT_PRINT", "cpu_ns": 42,
                         "error": "PUBLIC_REQUEST_DEADLINE",
                         "environment": {"TOKEN": "DO_NOT_PRINT"}})
    require(sample["cpu_ns"] == 42 and "packet" not in sample
            and "environment" not in sample
            and sample["error"]["literal_code"] == "PUBLIC_REQUEST_DEADLINE",
            "SELF_TEST_REDACTION")
    count += 1
    # Actual ZIP read and CRC validation, including a single-bit stored corruption.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("plain", b"abcdef")
    raw = bytearray(buffer.getvalue())
    offset = raw.index(b"abcdef")
    raw[offset] ^= 1
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            archive.read("plain")
    except zipfile.BadZipFile:
        count += 1
    else:
        raise Rejected("SELF_TEST_CRC_ACCEPTED")
    # Replay actual prior reader functions on synthetic data only. The old
    # committed reader is hash-bound before import; no artifact code is imported.
    prior_path = Path(__file__).with_name("previous_readback.py")
    require(hashlib.sha256(prior_path.read_bytes()).hexdigest()
            == "d66f06561c3057247a71c567b9391a03faed461673d43ebf5a8f3e5f6ee48ce8",
            "PREVIOUS_READER_BYTES")
    module_spec = importlib.util.spec_from_file_location("previous_readback", prior_path)
    prior = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(prior)
    sentinel = "SYNTHETIC_UNREVIEWED_SENTINEL"
    baseline = {"mode": "baseline", "duration_seconds": 30,
                "attacker_processes_requested": 0, "attacker_processes_ready": 0,
                "confirmations": [], "finite_phase_criteria_met": False,
                "all_signed_rounds_confirmed_in_window": False}
    for field, value, rejection in [
            ("mode", sentinel, "PHASE_MODE"),
            ("duration_seconds", {sentinel: True}, "PHASE_INTEGER"),
            ("finite_phase_criteria_met", sentinel, "PHASE_BOOL"),
            ("root_supplement", {"criteria_met": {sentinel: True}}, "PHASE_BOOL")]:
        case = {"phases": [dict(baseline, **{field: value})]}
        require(sentinel in json.dumps(prior.phase_summary(case)),
                "PREVIOUS_PHASE_NEGATIVE_NOT_REPRODUCED")
        rejects(lambda case=case: phase_summary(case), rejection)
    for case in [
            {sentinel: 7}, {"name": sentinel}, {"error": sentinel},
            {"records": [{"operation": 1, "dispatch_started": True, sentinel: 42}]},
            {"records": [{"operation": 1, "dispatch_started": True, sentinel: None}]}]:
        require(sentinel in json.dumps(prior.projection(case)),
                "PREVIOUS_PROJECTION_NEGATIVE_NOT_REPRODUCED")
        require(sentinel not in json.dumps(projection(case)),
                "PROJECTED_SENTINEL_LEAK")
        count += 1
    observed = phase_summary({"phases": [baseline]})[0]
    require(observed["mode"] == "baseline" and observed["recorded_rounds"] == 0
            and observed["confirmed_rounds"] == 0, "VALID_TYPED_PHASE")
    unknown = phase_summary({"phases": [{"mode": "baseline"}]})[0]
    require(unknown["recorded_rounds"] is None
            and unknown["confirmed_rounds"] is None,
            "ABSENT_CONFIRMATIONS_ARE_UNKNOWN")
    count += 1
    with tempfile.TemporaryDirectory(prefix="trnm-reader-output-control-") as root:
        out = Path(root)
        rejects(lambda: write_outputs(out, {"a.json": b"aa", "b.json": b"bb"},
                                      {"derived": 3}), "DERIVED_TOTAL_BUDGET")
        require(list(out.iterdir()) == [], "NO_WRITES_BEFORE_OUTPUT_BUDGET")
        budget = {"derived": 4}
        write_outputs(out, {"a.json": b"aa", "b.json": b"bb"}, budget)
        require(budget["derived"] == 0 and (out / "a.json").read_bytes() == b"aa"
                and (out / "b.json").read_bytes() == b"bb", "BOUNDED_OUTPUT_POSITIVE")
        count += 1

    # The old complete stdout view exceeds its fixed cap on this bounded
    # synthetic case. Keep that cap; emit a declared partial view instead.
    synthetic = {"submissions": [
        {"started_ns": index, "ended_ns": index + 1,
         "field_sha256:" + "a" * 64: {
             "canonical_json_bytes": 1, "canonical_json_sha256": "b" * 64,
             "value_omitted": True}}
        for index in range(10000)]}
    encoded = encode_json(synthetic)
    require(len(json.dumps(synthetic).encode()) > PRINT_BUDGET,
            "PREVIOUS_STDOUT_CAP_NEGATIVE_NOT_REPRODUCED")
    limited = stdout_projection(synthetic, encoded)
    require(len(encode_json(limited)) < 128 * 1024
            and limited["complete_projection_bytes"] == len(encoded)
            and limited["complete_projection_sha256"] == hashlib.sha256(encoded).hexdigest()
            and limited["stdout_projection_is_complete"] is False,
            "LIMITED_STDOUT_PRESERVES_COMPLETE_DIGEST")
    rows = limited["projection"]["submissions"]
    require(rows["recorded_items"] == 10000 and rows["stdout_omitted_items"] == 9984
            and rows["first"][0]["started_ns"] == 0
            and rows["last"][-1]["started_ns"] == 9999,
            "STDOUT_ENDPOINTS_EXPLICIT")
    count += 1
    nested = {"confirmed_inside_pressure_window": False}
    for _ in range(20):
        nested = {"value": nested}
    bounded = stdout_projection(nested, encode_json(nested))
    require('"stdout_omitted": true' in json.dumps(bounded),
            "STDOUT_DEPTH_BOUND")
    count += 1
    flags = {"finite_phase_criteria_met": False, "confirmed_rounds": None}
    limited_flags = stdout_projection(flags, encode_json(flags))
    require(limited_flags["projection"] == flags, "STDOUT_FALSE_AND_UNKNOWN")
    count += 1

    require(metric_stats([None, None]) == {
        "known_samples": 0, "unknown_samples": 2,
        "sum": None, "min": None, "max": None}, "UNKNOWN_CLOCK_NOT_ZERO")
    require(metric_stats([None, 0, 7])["sum"] == 7
            and metric_flags([True, False, None]) == {
                "true": 1, "false": 1, "unknown": 1}, "TYPED_CLIENT_METRICS")
    count += 1
    absent = client_cost_summary({"phases": [{"mode": "baseline"}]})[0]
    require(absent["recorded_history_calls"] is None
            and absent["client_import"] is None
            and absent["native_phases"] is None, "ABSENT_CLIENT_ROWS_UNKNOWN")
    count += 1
    rejects(lambda: metric_stats([True]), "CLIENT_METRIC_INTEGER")
    rejects(lambda: metric_flags([1]), "CLIENT_METRIC_BOOL")
    rejects(lambda: client_cost_summary({"phases": [
        {"mode": "baseline", "history": [{}] * 65}]}), "CLIENT_HISTORY_ROWS")
    phase_rows = [{"phase": name, "started": False, "completed": False,
                   "accepted": None, "thread_cpu_ns": None, "wall_ns": None}
                  for name in CLIENT_NATIVE_PHASES]
    host_rows = [{"phase": name} for name in CLIENT_HOST_PHASES]
    snapshot = {"phases": phase_rows, "host_checks": host_rows,
                "measurement_failures": 0}
    stamp = {"succeeded": False, "wall_ns": 9, "thread_cpu_ns": None,
             "thread_cpu_observation_available": False,
             "native_import_observation": snapshot}
    original = {"phases": [{"mode": "baseline",
        "history": [{"client_import": stamp}, {}]}]}
    costs = client_cost_summary(original)[0]
    require(costs["recorded_history_calls"] == 2
            and costs["client_import"]["observed_stamps"] == 1
            and costs["client_import"]["succeeded"]["false"] == 1
            and costs["client_import"]["thread_cpu_ns"]["sum"] is None
            and costs["native_phases"][0]["accepted"]["unknown"] == 1
            and costs["client_confirmation"]["observed_stamps"] == 0,
            "CLIENT_COST_FAILED_AND_ABSENT")
    count += 1
    phase_rows[-1] = dict(phase_rows[0])
    rejects(lambda: client_cost_summary(original), "CLIENT_PHASE_IDENTITIES")

    # Only fixed manifest labels are newly readable. This is a diagnostic
    # projection, not validation or acceptance of its business flags.
    fresh = projection({
        "requested_window_ns": 4_000_000_000, "attack_workers": 16,
        "source_recompiled": True, "execution_finished": True,
        "all_named_tests_passed": False,
        "failure_diagnostic": {"native_returncode": 101,
            "finite_target_met": False, "acceptance_authority": False,
            "last_history_replay": {"phase": "from-zero-pressure",
                "history_call_index": 2, "replay_accepted": False,
                "replay_error": "PUBLIC_REQUEST_DEADLINE"}}})
    require(fresh["requested_window_ns"] == 4_000_000_000
            and fresh["attack_workers"] == 16
            and fresh["all_named_tests_passed"] is False
            and fresh["failure_diagnostic"]["native_returncode"] == 101
            and fresh["failure_diagnostic"]["last_history_replay"]["replay_error"]["literal_code"]
                == "PUBLIC_REQUEST_DEADLINE", "FIXED_FRESH_MANIFEST_PROJECTION")
    count += 1
    injected = projection({"failure_diagnostic": {
        "native_returncode": "SYNTHETIC_UNREVIEWED_SENTINEL",
        "last_history_replay": {"replay_error": "SYNTHETIC_UNREVIEWED_SENTINEL",
                               "SYNTHETIC_UNREVIEWED_SENTINEL": 7}}})
    require("SYNTHETIC_UNREVIEWED_SENTINEL" not in json.dumps(injected)
            and injected["failure_diagnostic"]["last_history_replay"]["replay_error"]["literal_code"]
                is None, "FRESH_UNKNOWN_STRINGS_AND_KEYS_REMAIN_OMITTED")
    count += 1

    print(json.dumps({"self_tests_passed": count, "prior_reader_negatives_reproduced": 9,
                      "native_tests_executed": 0, "artifact_members_executed": 0}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    require(args.out is not None, "OUTPUT_REQUIRED")
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == BRANCH, "READBACK_JOB_SCOPE")
    token = os.environ.get("GH_TOKEN")
    require(isinstance(token, str) and len(token) > 0, "READ_TOKEN_REQUIRED")
    specs = parse_json(Path(__file__).with_name("inputs.json").read_bytes())
    require(isinstance(specs, list) and len(specs) == 2, "TWO_FROZEN_ARTIFACTS")
    args.out.mkdir(parents=True, exist_ok=False)
    limits = resource.getrlimit(resource.RLIMIT_AS)
    address_cap = min([ADDRESS_SPACE_BUDGET] + [value for value in limits if value >= 0])
    require(address_cap >= 512 * 1024 * 1024, "READER_ADDRESS_SPACE_UNAVAILABLE")
    resource.setrlimit(resource.RLIMIT_AS, (address_cap, address_cap))
    budget = {"compressed": COMPRESSED_BUDGET, "decoded": DECODED_BUDGET,
              "derived": DERIVED_BUDGET}
    printed = 0
    snapshots = []
    with tempfile.TemporaryDirectory(prefix="trnm-original-artifacts-") as scratch:
        for spec in specs:
            artifact = api_json(
                f"/repos/{REPOSITORY}/actions/artifacts/{spec['artifact_id']}", token)
            run = api_json(
                f"/repos/{REPOSITORY}/actions/runs/{spec['run_id']}/attempts/1", token)
            commit = api_json(
                f"/repos/{REPOSITORY}/git/commits/{spec['source']}", token)
            check_metadata(spec, artifact, run, commit)
            path = Path(scratch) / f"{spec['artifact_id']}.zip"
            download(spec, token, path, budget)
            files, documents, declared, projected, summaries, client_costs = inspect_zip(path, spec, budget)
            snapshot = {
                "artifact": spec, "archive_digest_and_size_verified": True,
                "members_crc_and_sha256_verified": len(files),
                "declared_decoded_bytes": declared,
                "source_receipts_verified": spec["source_json"],
                "original_binary_verified": spec["kind"] == "campaign",
                "phase_summaries": summaries,
                "client_cost_summaries": client_costs,
                "reader_address_space_cap_bytes": address_cap,
                "qualification": {"readback_only": True, "native_executed": False,
                                  "performance_qualified": False,
                                  "production_activation": False},
            }
            prefix = str(spec["artifact_id"])
            # Validate every serialized output budget before writing any of
            # this artifact's derived files or emitting its projection.
            payloads = {
                prefix + "-members.json": encode_json(safe_member_manifest(files, spec)),
                prefix + "-selected.json": encode_json(projected),
                prefix + "-readback.json": encode_json(snapshot),
            }
            stdout_selected = stdout_projection(projected, payloads[prefix + "-selected.json"])
            lines = [kind + " " + json.dumps(value, sort_keys=True, allow_nan=False)
                     for kind, value in (("READBACK", snapshot), ("SELECTED", stdout_selected))]
            printed_after = printed + sum(len(line.encode()) + 1 for line in lines)
            require(printed_after <= PRINT_BUDGET, "STDOUT_PROJECTION_BUDGET")
            require(sum(len(data) for data in payloads.values()) <= budget["derived"],
                    "DERIVED_TOTAL_BUDGET")
            write_outputs(args.out, payloads, budget)
            printed = printed_after
            for line in lines:
                print(line, flush=True)
            snapshots.append(snapshot)
            path.unlink()
    summary = encode_json({
        "schema": "trnm-frozen-original-artifact-readback-v1",
        "source": os.environ["GITHUB_SHA"], "snapshots": snapshots,
        "remaining_budgets_before_summary": budget, "archive_members_executed": 0,
        "scope": "integrity/source-bound diagnostic readback, not native qualification",
    })
    write_outputs(args.out, {"SUMMARY.json": summary}, budget)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Rejected as error:
        print(json.dumps({"readback_failed": str(error), "native_executed": False}))
        raise SystemExit(1) from None
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            urllib.error.URLError, RecursionError, MemoryError) as error:
        # Do not print signed redirect URLs, request headers, or arbitrary bytes.
        print(json.dumps({"readback_failed": type(error).__name__,
                          "native_executed": False}))
        raise SystemExit(1) from None
