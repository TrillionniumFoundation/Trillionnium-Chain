#!/usr/bin/env python3
"""Read-only, same-source qualification accounting; this v1 NEVER grants GO.

CLI: --plan PLAN --plan-sha256 INDEPENDENT_PIN --packet PACKET
     --evidence-root DIRECTORY. Exit 2 means a valid HOLD report; exit 1 means
     malformed/unreadable input. A collector's exit zero is not native success.

Both JSON documents reject duplicate/extra fields and nonfinite numbers. Plan
fields: schema, campaign_id, profile_sha256, source_pair, build_load, cases,
effect_intents, identity_observation_sha256. The latter independently pins the
source collector's entire observation or stays null. source_pair has chain/hepta {sha,tree,locks}; locks map repository
paths to SHA-256 or null. build_load has the IDENTITY_FIELDS below, each a SHA-256
or null. Build/load identify the actual executable; other fields bind the full
interpreter/library/environment/configuration closures and, for Hepta, the full
weights/tokenizer/router model closure. Missing identities remain null, never
placeholder evidence. cases maps EVERY fixed obligation to its frozen case IDs;
an empty list means unconfigured, not waived. effect_intents freezes the exact
{intent_sha256,operation_id,provider_id,idempotency_key} for every external effect.

Packet fields: schema, plan_sha256, identity_observation, records, learning,
effects. identity_observation is a retained source-collector {path,sha256} or
null; it must report verified tracked bytes, not merely matching HEAD. Each record has
RECORD_FIELDS below. Evidence is {path,sha256}: a retained regular file beneath
evidence-root, never a downloaded URL. source_url is provenance text only, never
an authentication claim. source_pair/profile/build_load_sha256 may be null when
unobserved; records with missing or different identities cannot count as current
materials. Counts and every numbered attempt survive the report, including
ignored, filtered, timeout, and unknown outcomes. A PASS plus nonzero native exit
is inconsistent even if collector_exit is zero. Retrying never erases an attempt.

learning is null or LEARNING_FIELDS: all eight STAGES are record IDs or null.
NoUpdate requires a completed evaluation and exact complete parent manifest AND
bundle retention, with no reset receipt; cold fetch/install can be absent on that
legal retained-model path. Unknown evaluation cannot become NoUpdate. Each stage
must bind the same iteration and unique frozen context. effects preserves ordered
DISPATCH/QUERY/RECONCILE steps, each referencing one retained record. UNKNOWN
forbids redispatch, including under a new operation ID for the same intent. A
revocation/cancellation does not prove that an earlier effect did not occur.

This joins declared materials and verifies their retained hashes. It does NOT
authenticate issuers/hosts, execute native owners, verify cryptographic proofs,
establish independent custody, or reconstruct omitted original attempts. Use the
existing specialized native/source/evidence readers for those checks. Even fully
consistent materials remain HOLD_NO_GO; all production/FinalUse flags are false.
In particular this v1 has no full native outcome adapter: every record carries
RAW_OUTCOME_UNVERIFIED. declared_result_consistent describes the supplied record,
not the truth of its outcome. Known raw failures are surfaced as contradictions;
no raw format can turn an unverified outcome into a successful current gate.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

PLAN_SCHEMA = "trnm-chain-hepta-qualification-plan-v1"
PACKET_SCHEMA = "trnm-chain-hepta-qualification-packet-v1"
REPORT_SCHEMA = "trnm-chain-hepta-qualification-review-v1"
GATES = {
    "P0_INTEGRATION": ("source_locks", "build_load", "native_registry"),
    "P0_CONSENSUS": ("w1_minimum_cost", "timestamp_daa_chainweight", "hostile_honest_confirmation"),
    "P0_PERMISSION": ("entry_to_effect", "current_revocation_load", "recovery_effects"),
    "P0_HEPTA": ("same_iteration", "no_update", "unknown_timeout", "revocation", "restart", "reorg"),
    "P1_DATA": ("dependency_closure", "independent_custody_wan", "renewal_repair_recovery"),
    "P2_THROUGHPUT": ("cost_decomposition", "matched_confirmation_tail_latency"),
    "P3_PQ": ("account_transaction_service", "release_root_authority", "content_commitment",
              "stark_fri_qrom", "quantum_work_daa_weight", "rollback_external_effects",
              "lifetime_composition", "independent_crypto_implementation_review"),
}
OBLIGATIONS = frozenset(item for group in GATES.values() for item in group)
IDENTITY_FIELDS = {
    name: ("build_sha256", "load_sha256", "interpreter_sha256", "libraries_sha256",
           "environment_sha256", "configuration_sha256") +
          (("model_closure_sha256",) if name == "hepta" else ())
    for name in ("chain", "hepta")
}
LOCKS = {"chain": {"trillionnium/Cargo.lock"}, "hepta": {"codex-rs/Cargo.lock", "MODULE.bazel.lock"}}
OUTCOMES = ("PASS", "FAIL", "TIMEOUT", "IGNORED", "FILTERED", "UNKNOWN")
COUNTS = ("passed", "failed", "ignored", "filtered", "unknown")
SCOPES = ("native-test", "native-owner", "provider-readback", "engineering-control", "sanitized-history")
STAGES = ("training", "evaluation", "selection", "payment", "cold_fetch", "installation", "load", "next_task")
RECORD_FIELDS = ("id obligation case_id attempt source_pair campaign_id profile_sha256 "
                 "build_load_sha256 iteration_id stage manifest_sha256 bundle_sha256 "
                 "effect_intent_sha256 operation_id effect_outcome outcome native_exit "
                 "collector_exit counts scope evidence source_url")
LEARNING_FIELDS = ("iteration_id decision evaluation_status parent_manifest selected_manifest "
                   "parent_bundle selected_bundle reset_receipt_sha256 payment_intent_sha256 stages")
EFFECT_FIELDS = "intent_sha256 operation_id provider_id idempotency_key"
MAX_JSON = 8 * 1024 * 1024
MAX_IDENTITY_JSON = 64 * 1024 * 1024
MAX_RECORDS = 1024


class Refusal(ValueError):
    """Malformed input, separate from a valid but incomplete/failed HOLD review."""


def require(ok, code):
    if not ok:
        raise Refusal(code)


def fields(value, names, code):
    names = names.split() if isinstance(names, str) else names
    require(type(value) is dict and set(value) == set(names), code)


def digest(value, size=64, nullable=False):
    require(nullable and value is None or type(value) is str and
            re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None and value != "0" * size,
            "INVALID_DIGEST")


def label(value, nullable=False):
    require(nullable and value is None or type(value) is str and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", value) is not None,
            "INVALID_ID")


def integer(value, minimum=0, maximum=2**63 - 1, nullable=False):
    require(nullable and value is None or type(value) is int and minimum <= value <= maximum,
            "INVALID_INTEGER")


def sequence(value, maximum=MAX_RECORDS):
    require(type(value) is list and len(value) <= maximum, "LIST_BOUND")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw, maximum=MAX_JSON):
    require(type(raw) is bytes and len(raw) <= maximum, "JSON_BOUND")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "DUPLICATE_JSON_FIELD")
            result[key] = value
        return result

    def nonfinite(_):
        raise Refusal("NONFINITE_JSON_NUMBER")

    def finite_float(value):
        result = float(value)
        require(math.isfinite(result), "NONFINITE_JSON_NUMBER")
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=nonfinite, parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal("INVALID_JSON") from error


def relative_path(value):
    require(type(value) is str and 0 < len(value) <= 1024 and not value.startswith("/") and
            all(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", p) and p not in (".", "..")
                for p in value.split("/")), "EVIDENCE_PATH")


def read_regular(path, maximum=MAX_JSON):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "FILE_BOUND")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) <= maximum and key(before) == key(after), "FILE_CHANGED")
        return raw


def source_pair(value):
    fields(value, "chain hepta", "SOURCE_PAIR_FIELDS")
    for repo in ("chain", "hepta"):
        fields(value[repo], "sha tree locks", "REPOSITORY_FIELDS")
        digest(value[repo]["sha"], 40); digest(value[repo]["tree"], 40)
        locks = value[repo]["locks"]
        require(type(locks) is dict and LOCKS[repo] <= set(locks) and len(locks) <= 512,
                "LOCKFILE_ROSTER")
        for path, pin in locks.items():
            relative_path(path); digest(pin, nullable=True)


def build_load_digest(plan):
    return sha(b"TRNM-CHAIN-HEPTA-BUILD-LOAD-V1\0" + canonical(plan["build_load"]))


def effect_identity(value):
    fields(value, EFFECT_FIELDS, "EFFECT_IDENTITY_FIELDS")
    digest(value["intent_sha256"])
    for key in ("operation_id", "provider_id", "idempotency_key"):
        label(value[key])


def validate_plan(plan):
    fields(plan, "schema campaign_id profile_sha256 source_pair build_load cases effect_intents identity_observation_sha256", "PLAN_FIELDS")
    require(plan["schema"] == PLAN_SCHEMA, "PLAN_SCHEMA")
    label(plan["campaign_id"]); digest(plan["profile_sha256"])
    digest(plan["identity_observation_sha256"], nullable=True)
    source_pair(plan["source_pair"])
    fields(plan["build_load"], "chain hepta", "BUILD_LOAD_FIELDS")
    for repo, required in IDENTITY_FIELDS.items():
        fields(plan["build_load"][repo], required, "RUNTIME_IDENTITY_FIELDS")
        for pin in plan["build_load"][repo].values():
            digest(pin, nullable=True)
    fields(plan["cases"], OBLIGATIONS, "OBLIGATION_ROSTER")
    all_cases = []
    for cases in plan["cases"].values():
        sequence(cases, 64)
        for case in cases:
            label(case)
        all_cases.extend(cases)
    require(len(all_cases) == len(set(all_cases)), "DUPLICATE_CASE_ID")
    sequence(plan["effect_intents"], 64)
    for item in plan["effect_intents"]:
        effect_identity(item)
    for field in ("intent_sha256", "operation_id", "idempotency_key"):
        require(len({item[field] for item in plan["effect_intents"]}) == len(plan["effect_intents"]),
                "DUPLICATE_PLANNED_EFFECT")


def evidence_hash(root, reference, remaining, maximum=MAX_JSON):
    """No-follow traversal; a hash match is integrity, never source authenticity."""
    fields(reference, "path sha256", "EVIDENCE_REFERENCE_FIELDS")
    relative_path(reference["path"]); digest(reference["sha256"])
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = reference["path"].split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "EVIDENCE_FILE_BOUND")
            require(before.st_size <= remaining[0], "EVIDENCE_TOTAL_BOUND")
            remaining[0] -= before.st_size
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            require(len(raw) <= maximum and
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "EVIDENCE_FILE_CHANGED")
            require(sha(raw) == reference["sha256"], "EVIDENCE_HASH_MISMATCH")
            return raw
    finally:
        os.close(descriptor)


def identity_observation(reference, plan, root, remaining):
    """Review the pinned source collector; never infer clean bytes from HEAD."""
    if reference is None:
        return ["MISSING_SOURCE_OBSERVATION"]
    fields(reference, "path sha256", "EVIDENCE_REFERENCE_FIELDS")
    relative_path(reference["path"]); digest(reference["sha256"])
    if reference["sha256"] != plan["identity_observation_sha256"]:
        return ["SOURCE_OBSERVATION_PIN_MISMATCH"]
    try:
        observed = decode(evidence_hash(root, reference, remaining, MAX_IDENTITY_JSON), MAX_IDENTITY_JSON)
        require(type(observed) is dict and observed.get("schema") == "trnm-chain-hepta-identity-observation-v1",
                "SOURCE_OBSERVATION_SCHEMA")
        require(observed.get("source_pair") == plan["source_pair"], "SOURCE_OBSERVATION_PAIR")
        require(observed.get("status") == "HOLD_NO_GO" and observed.get("production_qualified") is False and
                observed.get("actual_model_execution_proved") is False and
                observed.get("tests_executed_by_identity_check") is False, "SOURCE_OBSERVATION_OVERCLAIM")
        details = observed.get("source_observations")
        fields(details, "chain hepta", "SOURCE_OBSERVATION_ROSTER")
        for repo in ("chain", "hepta"):
            detail = details[repo]
            require(type(detail) is dict and detail.get("source_status") == "VERIFIED" and
                    detail.get("expected_sha") == plan["source_pair"][repo]["sha"] and
                    all(detail.get(key) is True for key in (
                        "tracked_worktree_verified", "raw_tracked_entries_match", "index_matches")) and
                    detail.get("dirty") is False and detail.get("errors") == [] and
                    detail.get("untracked_paths_including_ignored") == [], "SOURCE_NOT_CLEAN:" + repo)
            # The pinned collector hashes EVERY raw file and retains a full
            # manifest commitment. This consumer checks its summary, not a new
            # filesystem snapshot; it does not relabel that hash as our proof.
            integer(detail.get("tracked_entries"), 1, 50000)
            integer(detail.get("tracked_bytes"), maximum=4 * 1024**3)
            digest(detail.get("tracked_manifest_sha256"))
            require(detail.get("mismatched_entries") == [], "SOURCE_ENTRY_MISMATCH:" + repo)
            locks = plan["source_pair"][repo]["locks"]
            require(detail.get("lock_paths") == sorted(locks) and
                    all(pin is not None for pin in locks.values()),
                    "SOURCE_LOCK_BINDING:" + repo)
    except OSError:
        return ["SOURCE_OBSERVATION_UNAVAILABLE"]
    except Refusal as error:
        return [str(error)]
    return []


def plan_from_identity_observation(observation_raw, campaign_id, profile_sha256):
    """Create an UNCONFIGURED plan from actual retained identity output, not IDs we invent.

    Freeze real case/effect rosters separately. Serialize with canonical() before
    making packet_for_plan(); --plan-sha256 must come from an independent holder.
    """
    observation = decode(observation_raw, MAX_IDENTITY_JSON)
    require(type(observation) is dict and observation.get("schema") == "trnm-chain-hepta-identity-observation-v1",
            "SOURCE_OBSERVATION_SCHEMA")
    plan = dict(schema=PLAN_SCHEMA, campaign_id=campaign_id, profile_sha256=profile_sha256,
                source_pair=copy.deepcopy(observation.get("source_pair")),
                build_load=copy.deepcopy(observation.get("build_load")),
                cases={name: [] for name in sorted(OBLIGATIONS)}, effect_intents=[],
                identity_observation_sha256=sha(observation_raw))
    validate_plan(plan)
    return plan


def packet_for_plan(plan_raw, identity_reference=None):
    validate_plan(decode(plan_raw))
    return dict(schema=PACKET_SCHEMA, plan_sha256=sha(plan_raw), identity_observation=identity_reference,
                records=[], learning=None, effects=[])


def raw_negative_observations(raw, record):
    """Surface contradictions only; an unknown raw format can NEVER supply PASS.

    This v1 has no native log/result adapter. A hash alone cannot prove that the
    record's normalized counts/outcome match a native log. Every such record is
    therefore RAW_OUTCOME_UNVERIFIED, even when no contradiction is found here.
    The existing command receipt's native exit is not its collector's exit.
    """
    try:
        value = decode(raw)
    except Refusal:
        return {}, []
    if type(value) is not dict:
        return {}, []
    summary, issues = {}, []
    native_exit = value.get("native_exit")
    if value.get("schema") == "trnm-pq-native-command-v1":
        native_exit = value.get("exit_code")
        summary["status"] = value.get("status")
    if type(native_exit) is int:
        summary["native_exit"] = native_exit
        if native_exit != record["native_exit"]:
            issues.append("RAW_NATIVE_EXIT_CONFLICT")
    for key in COUNTS:
        if type(value.get(key)) is int:
            summary[key] = value[key]
            if value[key] != record["counts"][key]:
                issues.append("RAW_COUNT_CONFLICT:" + key)
    for key in ("qualification", "full_learning_iteration_completed", "real_model_training_verified",
                "physical_installation_accepted", "settlement_verified", "hepta_final_use_accepted",
                "production_activation", "engineering_controls_only", "actual_model_execution"):
        if key in value:
            summary[key] = value[key]
    return summary, issues


def review_record(record, plan, root, remaining, complete_identity):
    fields(record, RECORD_FIELDS, "RECORD_FIELDS")
    for name in ("id", "case_id", "campaign_id"):
        label(record[name])
    label(record["iteration_id"], nullable=True)
    label(record["operation_id"], nullable=True)
    for key in ("manifest_sha256", "bundle_sha256", "effect_intent_sha256"):
        digest(record[key], nullable=True)
    require(record["stage"] is None or record["stage"] in STAGES, "STAGE_KIND")
    require(record["effect_outcome"] in (None, "COMMITTED", "NOT_APPLIED", "UNKNOWN", "REVOKED", "CANCELLED"),
            "EFFECT_OUTCOME")
    require(type(record["obligation"]) is str and record["obligation"] in OBLIGATIONS, "UNKNOWN_OBLIGATION")
    integer(record["attempt"], 1, 64)
    require(record["outcome"] in OUTCOMES and record["scope"] in SCOPES, "OUTCOME_OR_SCOPE")
    integer(record["native_exit"], -255, 255, nullable=True)
    integer(record["collector_exit"], -255, 255, nullable=True)
    fields(record["counts"], COUNTS, "COUNT_FIELDS")
    for value in record["counts"].values():
        integer(value, maximum=10**7)
    require(type(record["source_url"]) is str and len(record["source_url"]) <= 2048 and
            record["source_url"].startswith("https://github.com/TrillionniumFoundation/"), "PROVENANCE_URL")
    digest(record["profile_sha256"], nullable=True)
    digest(record["build_load_sha256"], nullable=True)
    if record["source_pair"] is not None:
        source_pair(record["source_pair"])
    issues = [] if complete_identity else ["INCOMPLETE_EXPECTED_IDENTITY"]
    for key, expected in (("source_pair", plan["source_pair"]), ("campaign_id", plan["campaign_id"]),
                          ("profile_sha256", plan["profile_sha256"]),
                          ("build_load_sha256", build_load_digest(plan))):
        if record[key] != expected:
            issues.append("CONTEXT_MISMATCH:" + key)
    if record["case_id"] not in plan["cases"][record["obligation"]]:
        issues.append("UNPLANNED_CASE")
    if record["scope"] in ("engineering-control", "sanitized-history"):
        issues.append("NOT_PRODUCTION_EVIDENCE:" + record["scope"])
    raw_summary, raw_issues = {}, []
    try:
        raw = evidence_hash(root, record["evidence"], remaining)
        raw_summary, raw_issues = raw_negative_observations(raw, record)
    except OSError:
        issues.append("EVIDENCE_UNAVAILABLE")
    except Refusal as error:
        # Malformed reference fields remain a schema refusal, not a missing file.
        if str(error) in ("EVIDENCE_FILE_BOUND", "EVIDENCE_TOTAL_BOUND", "EVIDENCE_FILE_CHANGED", "EVIDENCE_HASH_MISMATCH"):
            issues.append(str(error))
        else:
            raise
    bindings_consistent = not issues
    if record["outcome"] != "PASS":
        issues.append("RETAINED_OUTCOME:" + record["outcome"])
    if record["native_exit"] != 0:
        issues.append("NATIVE_EXIT_NOT_ZERO_OR_UNKNOWN")
    if record["collector_exit"] != 0:
        issues.append("COLLECTION_INCOMPLETE")
    for key in ("failed", "ignored", "filtered", "unknown"):
        if record["counts"][key]:
            issues.append("RETAINED_COUNT:" + key)
    if record["scope"] == "native-test" and record["counts"]["passed"] == 0:
        issues.append("NO_EXECUTED_PASS")
    issues.extend(raw_issues)
    declared_result_consistent = not issues
    issues.append("RAW_OUTCOME_UNVERIFIED")
    return dict(record=copy.deepcopy(record), issues=issues,
                retained_bindings_consistent=bindings_consistent,
                declared_result_consistent=declared_result_consistent,
                raw_result_summary=raw_summary, raw_result_conflicts=raw_issues,
                result_payload_verified=False,
                current_materials_consistent=False)


def learning_issues(learning, records, planned_effects):
    if learning is None:
        return ["MISSING_SAME_ITERATION"], None
    fields(learning, LEARNING_FIELDS, "LEARNING_FIELDS")
    label(learning["iteration_id"])
    require(learning["decision"] in ("UPDATE", "NO_UPDATE", "UNKNOWN") and
            learning["evaluation_status"] in ("COMPLETED", "FAILED", "UNKNOWN"), "LEARNING_STATUS")
    for key in ("parent_manifest", "parent_bundle"):
        digest(learning[key])
    for key in ("selected_manifest", "selected_bundle", "reset_receipt_sha256", "payment_intent_sha256"):
        digest(learning[key], nullable=True)
    fields(learning["stages"], STAGES, "LEARNING_STAGE_ROSTER")
    issues = []
    if learning["evaluation_status"] != "COMPLETED":
        issues.append("EVALUATION_NOT_COMPLETED")
    decision = learning["decision"]
    if decision == "UNKNOWN":
        issues.append("UNKNOWN_DECISION")
    elif decision == "NO_UPDATE":
        if any(learning["selected_" + part] != learning["parent_" + part] for part in ("manifest", "bundle")):
            issues.append("NO_UPDATE_CHANGED_COMPLETE_PARENT")
        if learning["reset_receipt_sha256"] is not None:
            issues.append("NO_UPDATE_FABRICATED_RESET")
    elif learning["reset_receipt_sha256"] is None or any(
            learning["selected_" + part] in (None, learning["parent_" + part]) for part in ("manifest", "bundle")):
        issues.append("UPDATE_MISSING_OR_UNCHANGED_SELECTION")
    used = []
    for stage, reference in learning["stages"].items():
        label(reference, nullable=True)
        if reference is None:
            if decision != "NO_UPDATE" or stage not in ("cold_fetch", "installation"):
                issues.append("MISSING_STAGE:" + stage)
            continue
        used.append(reference)
        row = records.get(reference)
        if row is None or not row["declared_result_consistent"]:
            issues.append("UNQUALIFIED_STAGE_RECORD:" + stage)
        else:
            if row["record"]["iteration_id"] != learning["iteration_id"]:
                issues.append("ITERATION_MISMATCH:" + stage)
            if row["record"]["stage"] != stage:
                issues.append("STAGE_KIND_MISMATCH:" + stage)
            if stage in ("cold_fetch", "installation", "load", "next_task") and any(
                    row["record"][part + "_sha256"] != learning["selected_" + part]
                    for part in ("manifest", "bundle")):
                issues.append("STAGE_VERSION_MISMATCH:" + stage)
    if len(set(used)) != len(used):
        issues.append("REUSED_STAGE_RECORD")
    payment = records.get(learning["stages"]["payment"])
    planned = {item["intent_sha256"]: item for item in planned_effects}.get(learning["payment_intent_sha256"])
    if payment is None or planned is None or any(payment["record"][key] != expected for key, expected in (
            ("effect_intent_sha256", learning["payment_intent_sha256"]),
            ("operation_id", planned["operation_id"] if planned else None), ("effect_outcome", "COMMITTED"))):
        issues.append("PAYMENT_NOT_BOUND_TO_ORIGINAL_EFFECT")
    return issues, copy.deepcopy(learning)


def review_effects(effects, planned, records):
    sequence(effects, 64)
    by_intent = {item["intent_sha256"]: item for item in planned}
    seen, reports, global_issues = set(), [], []
    for effect in effects:
        fields(effect, EFFECT_FIELDS + " steps", "EFFECT_FIELDS")
        identity = {key: effect[key] for key in EFFECT_FIELDS.split()}
        effect_identity(identity); sequence(effect["steps"], 128)
        intent = effect["intent_sha256"]
        issues, state, revoked, ever_committed = [], None, False, False
        if intent in seen:
            issues.append("SAME_INTENT_MULTIPLE_OPERATIONS")
        seen.add(intent)
        if by_intent.get(intent) != identity:
            issues.append("EFFECT_IDENTITY_NOT_PLANNED")
        for step in effect["steps"]:
            fields(step, "action outcome record_id", "EFFECT_STEP_FIELDS")
            label(step["record_id"])
            action, outcome = step["action"], step["outcome"]
            require(action in ("DISPATCH", "QUERY", "RECONCILE") and
                    outcome in ("COMMITTED", "NOT_APPLIED", "UNKNOWN", "REVOKED", "CANCELLED"), "EFFECT_STEP")
            row = records.get(step["record_id"])
            usable = row is not None and row["retained_bindings_consistent"] and not row["raw_result_conflicts"] and all(
                row["record"][key] == expected for key, expected in (
                    ("effect_intent_sha256", intent), ("operation_id", effect["operation_id"]),
                    ("effect_outcome", outcome)))
            if not usable:
                issues.append("UNQUALIFIED_EFFECT_RECORD:" + step["record_id"])
            if action == "DISPATCH":
                if state in ("UNKNOWN", "COMMITTED") or revoked or ever_committed:
                    issues.append("REDISPATCH_AFTER_UNKNOWN_COMMIT_OR_REVOCATION")
                if outcome in ("COMMITTED", "NOT_APPLIED", "UNKNOWN"):
                    if outcome == "COMMITTED" and usable and row["declared_result_consistent"]:
                        ever_committed = True
                    state = "COMMITTED" if ever_committed else outcome if usable and outcome != "COMMITTED" else "UNKNOWN"
            else:
                authoritative = usable and row["declared_result_consistent"] and row["record"]["scope"] == "provider-readback"
                if not authoritative:
                    issues.append("MISSING_PROVIDER_READBACK")
                if authoritative and outcome in ("COMMITTED", "NOT_APPLIED"):
                    if ever_committed and outcome == "NOT_APPLIED":
                        issues.append("COMMITTED_EFFECT_CANNOT_BE_ERASED")
                    else:
                        state = outcome
                        ever_committed = ever_committed or outcome == "COMMITTED"
                elif outcome == "UNKNOWN":
                    state = "COMMITTED" if ever_committed else "UNKNOWN"
            if outcome in ("REVOKED", "CANCELLED"):
                revoked = True  # Neither proves the earlier external effect absent.
        if state not in ("COMMITTED", "NOT_APPLIED"):
            issues.append("UNRESOLVED_EXTERNAL_EFFECT")
        reports.append(dict(effect=copy.deepcopy(effect), reported_terminal_state=state,
                            reported_commit_observed=ever_committed,
                            issues=sorted(set(issues)), effects_verified=False))
    for intent in sorted(set(by_intent) - seen):
        global_issues.append("MISSING_EFFECT:" + intent)
    if not planned:
        global_issues.append("NO_FROZEN_EXTERNAL_EFFECT_ROSTER")
    return reports, global_issues


def review(plan_raw, expected_plan_sha256, packet_raw, evidence_root):
    require(type(plan_raw) is bytes and type(packet_raw) is bytes and
            len(plan_raw) <= MAX_JSON and len(packet_raw) <= MAX_JSON, "JSON_BOUND")
    digest(expected_plan_sha256)
    require(sha(plan_raw) == expected_plan_sha256, "PLAN_PIN_MISMATCH")
    plan, packet = decode(plan_raw), decode(packet_raw)
    validate_plan(plan)
    fields(packet, "schema plan_sha256 identity_observation records learning effects", "PACKET_FIELDS")
    require(packet["schema"] == PACKET_SCHEMA, "PACKET_SCHEMA")
    require(packet["plan_sha256"] == expected_plan_sha256, "PACKET_PLAN_MISMATCH")
    sequence(packet["records"])
    identity_issues = []
    for repo in ("chain", "hepta"):
        for path, pin in plan["source_pair"][repo]["locks"].items():
            if pin is None:
                identity_issues.append("MISSING_LOCK:" + repo + ":" + path)
        observed = plan["build_load"][repo]
        for name, pin in observed.items():
            if pin is None:
                identity_issues.append("MISSING_IDENTITY:" + repo + ":" + name)
        if observed["build_sha256"] != observed["load_sha256"]:
            identity_issues.append("BUILD_LOAD_MISMATCH:" + repo)
    remaining = [128 * 1024 * 1024]
    source_issues = identity_observation(packet["identity_observation"], plan, evidence_root, remaining)
    identity_issues.extend(source_issues)
    rows = [review_record(record, plan, evidence_root, remaining, not identity_issues)
            for record in packet["records"]]
    require(len({row["record"]["id"] for row in rows}) == len(rows), "DUPLICATE_RECORD_ID")
    attempts = {}
    for row in rows:
        record = row["record"]
        key = (record["obligation"], record["case_id"])
        attempts.setdefault(key, []).append(record["attempt"])
    for numbers in attempts.values():
        require(sorted(numbers) == list(range(1, len(numbers) + 1)), "MISSING_OR_DUPLICATE_ATTEMPT")
    by_id = {row["record"]["id"]: row for row in rows}
    learning_blockers, learning = learning_issues(packet["learning"], by_id, plan["effect_intents"])
    effects, effect_blockers = review_effects(packet["effects"], plan["effect_intents"], by_id)
    gates = {}
    for gate, obligations in GATES.items():
        blockers = list(identity_issues)
        selected = [row for row in rows if row["record"]["obligation"] in obligations]
        for obligation in obligations:
            if not plan["cases"][obligation]:
                blockers.append("UNCONFIGURED_CASE_ROSTER:" + obligation)
            for case in plan["cases"][obligation]:
                if (obligation, case) not in attempts:
                    blockers.append("MISSING_CASE:" + case)
        for row in selected:
            blockers.extend(row["record"]["id"] + ":" + issue for issue in row["issues"])
        if gate == "P0_HEPTA":
            blockers.extend(learning_blockers)
        if gate in ("P0_HEPTA", "P0_PERMISSION"):
            blockers.extend(effect_blockers)
            blockers.extend(effect["effect"]["operation_id"] + ":" + issue
                            for effect in effects for issue in effect["issues"])
        gates[gate] = dict(qualification="HOLD_NO_GO",
                          material_status="BLOCKED" if blockers else "MATERIALS_RECORDED",
                          blockers=sorted(set(blockers)),
                          records=[row["record"]["id"] for row in selected],
                          recorded_outcomes={value: sum(row["record"]["outcome"] == value for row in selected)
                                             for value in OUTCOMES},
                          recorded_counts_across_attempts={name: sum(row["record"]["counts"][name] for row in selected)
                                                           for name in COUNTS})
    return dict(schema=REPORT_SCHEMA, qualification="HOLD_NO_GO", authority="DENY_ALL",
                plan_sha256=expected_plan_sha256, packet_sha256=sha(packet_raw),
                campaign_id=plan["campaign_id"], profile_sha256=plan["profile_sha256"],
                source_pair=plan["source_pair"], build_load=plan["build_load"],
                identity_observation=packet["identity_observation"],
                identity_observation_consistent=not source_issues,
                gates=gates, records=rows, learning=learning, learning_blockers=learning_blockers,
                effects=effects, effect_blockers=effect_blockers,
                engineering_controls_only=True, actual_model_execution=False,
                source_objects_verified=False, original_evidence_authenticated=False,
                original_attempt_inventory_verified=False, loaded_bytes_verified=False,
                independent_control_accepted=False, independent_wan_accepted=False,
                settlement_verified=False, full_pq_security_qualified=False,
                production_final_use_qualified=False, production_activation=False,
                qualification_note="MATERIALS_RECORDED means retained bindings only; original owners and independent review remain required.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = review(read_regular(args.plan), args.plan_sha256,
                        read_regular(args.packet), args.evidence_root)
    except (OSError, Refusal, ValueError) as error:
        print(json.dumps(dict(schema=REPORT_SCHEMA, qualification="HOLD_NO_GO", authority="DENY_ALL",
                              input_refused=str(error), production_final_use_qualified=False,
                              production_activation=False), sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 2


if __name__ == "__main__":
    sys.exit(main())
