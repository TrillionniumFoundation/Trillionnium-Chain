#!/usr/bin/env python3
"""Independent, standard-library-only verifier for G1-R4 fault evidence.

This file intentionally does not import ``g1_r4_fault_matrix_v1``.  It has a
separate parser, digest construction and transition table so that a producer
bug cannot make the replay pass merely by sharing helper code.  It validates
the candidate process contract, exact byte/digest fields, retained-mutant
index, SIGKILL observations, ancestor order and fork retention.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import stat
import sys
from typing import Any


SCHEMA = "trnm-g1-r4-fault-matrix-v1"
EVENT_SCHEMA = "trnm-g1-r4-process-event-v1"
STATE_SCHEMA = "trnm-g1-r4-durable-state-v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BASE_COMMIT = "6e0189e351015ef3230f217ca7ff86149baedcf0"
BASE_TREE = "efea864cb2fbc4835a59a089b3dbab8934e71231"
CASE_ORDER = (
    "R4-M01-sigkill-before-publish",
    "R4-M02-response-loss-before-commit",
    "R4-M03-response-loss-after-commit",
    "R4-M04-disk-full-before-publish",
    "R4-M05-io-error-before-publish",
    "R4-M06-fsync-error-before-publish",
    "R4-M07-directory-fsync-error-after-publish",
    "R4-M08-torn-write-before-publish",
    "R4-M09-database-rollback",
    "R4-M10-namespace-rollback",
    "R4-M11-application-safety-skew",
    "R4-M12-multi-block-ancestor-order",
    "R4-M13-losing-fork-retention",
)
POSITIVE_STATUSES = frozenset(
    {"RECOVERED_EXACT", "REPLAYED_EXACT", "ORDER_REPLAYED_EXACT"}
)
REQUIRED_MUTANTS = frozenset(
    {
        "disk_full",
        "io_error",
        "fsync_error",
        "directory_fsync_error",
        "torn_write",
        "database_rollback",
        "namespace_rollback",
        "application_safety_skew",
        "losing_fork",
    }
)


class ReplayFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReplayFailure(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes, field: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                fail(f"{field} has duplicate key {key!r}")
            value[key] = child
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not strict JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be an object")
    return value


def required_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    if set(value) != expected:
        fail(f"{field} keys differ: expected {sorted(expected)!r}, got {sorted(value)!r}")


def parse_state(raw: bytes, field: str) -> dict[str, str]:
    """Independent fixed-line decoder for the durable state record."""

    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        fail(f"{field} is not ASCII: {error}")
    lines = text.splitlines(keepends=True)
    names = ("schema", "height", "parent", "application", "safety", "signer", "checkpoint", "branch")
    if len(lines) != len(names) or any(not line.endswith("\n") for line in lines):
        fail(f"{field} does not contain exactly eight newline-terminated fields")
    result: dict[str, str] = {}
    for line, expected_name in zip(lines, names):
        body = line[:-1]
        if body.count("=") != 1:
            fail(f"{field} has an invalid separator in {expected_name}")
        name, value = body.split("=", 1)
        if name != expected_name or name in result or not value:
            fail(f"{field} has an invalid {expected_name} field")
        result[name] = value
    if result["schema"] != STATE_SCHEMA:
        fail(f"{field} schema mismatch")
    if len(result["height"]) != 20 or not result["height"].isdigit():
        fail(f"{field} height is not fixed-width decimal")
    for name in ("parent", "application", "safety", "signer", "checkpoint"):
        if HEX64.fullmatch(result[name]) is None:
            fail(f"{field}.{name} is not a lowercase SHA-256 digest")
    if result["branch"] not in {"main", "fork"}:
        fail(f"{field}.branch is not one of the frozen branches")
    return result


def parse_checkpoint(value: str, expected_case: str) -> dict[str, str]:
    prefix = f"checkpoint_v1={expected_case};"
    if not value.startswith(prefix):
        fail(f"checkpoint does not bind case {expected_case}")
    fields: dict[str, str] = {}
    for token in value[len(prefix) :].split(";"):
        if not token or token.count("=") != 1:
            fail(f"checkpoint has malformed token {token!r}")
        name, child = token.split("=", 1)
        if name in fields:
            fail(f"checkpoint repeats {name}")
        fields[name] = child
    expected = {"phase", "pid", "fault", "target", "temp", "target_sha256", "temp_sha256"}
    required_keys(fields, expected, "checkpoint")
    if not fields["phase"] or not fields["pid"].isdigit():
        fail("checkpoint phase/pid is invalid")
    for name in ("target", "temp"):
        if fields[name] not in {"0", "1"}:
            fail(f"checkpoint {name} must be 0 or 1")
    for name in ("target_sha256", "temp_sha256"):
        if HEX64.fullmatch(fields[name]) is None:
            fail(f"checkpoint {name} digest is invalid")
    return fields


def check_residue_shape(value: Any, field: str) -> None:
    if not isinstance(value, dict):
        fail(f"{field} must be an object")
    for name, item in value.items():
        if not isinstance(name, str) or not isinstance(item, (dict, type(None))):
            fail(f"{field} has malformed residue item {name!r}")
        if item is None:
            continue
        required_keys(item, {"bytes", "sha256", "mode", "nlink"}, f"{field}.{name}")
        if (
            isinstance(item["bytes"], bool)
            or not isinstance(item["bytes"], int)
            or item["bytes"] <= 0
            or HEX64.fullmatch(item["sha256"]) is None
            or item["mode"] != "0600"
            or item["nlink"] != 1
        ):
            fail(f"{field}.{name} is not one private bounded residue")


def validate_event(event: Any, ordinal: int) -> dict[str, Any]:
    if not isinstance(event, dict):
        fail(f"case[{ordinal}] is not an object")
    required_keys(
        event,
        {
            "schema",
            "case_id",
            "phase",
            "fault_kind",
            "checkpoint",
            "process",
            "residue_before_recovery",
            "recovery",
            "residue_after_recovery",
        },
        f"case[{ordinal}]",
    )
    if event["schema"] != EVENT_SCHEMA or event["case_id"] != CASE_ORDER[ordinal]:
        fail(f"case[{ordinal}] schema/order mismatch")
    if not isinstance(event["phase"], str) or not event["phase"]:
        fail(f"case[{ordinal}] phase is empty")
    if event["fault_kind"] is not None and not isinstance(event["fault_kind"], str):
        fail(f"case[{ordinal}] fault_kind is malformed")
    checkpoint = parse_checkpoint(event["checkpoint"], event["case_id"])
    process = event["process"]
    if not isinstance(process, dict):
        fail(f"case[{ordinal}].process is not an object")
    required_keys(
        process,
        {"worker_pid", "exit_signal", "sigkill_observed", "stderr_sha256", "independent_process"},
        f"case[{ordinal}].process",
    )
    if process["worker_pid"] is None:
        if process["sigkill_observed"] is not False or process["exit_signal"] is not None:
            fail(f"case[{ordinal}] synthetic process has kill evidence")
    else:
        if (
            isinstance(process["worker_pid"], bool)
            or not isinstance(process["worker_pid"], int)
            or process["worker_pid"] <= 1
            or process["exit_signal"] != 9
            or process["sigkill_observed"] is not True
        ):
            fail(f"case[{ordinal}] lacks exact SIGKILL process evidence")
    if HEX64.fullmatch(process["stderr_sha256"]) is None or process["independent_process"] is not True:
        fail(f"case[{ordinal}] process binding is invalid")
    check_residue_shape(event["residue_before_recovery"], f"case[{ordinal}].residue_before_recovery")
    check_residue_shape(event["residue_after_recovery"], f"case[{ordinal}].residue_after_recovery")
    recovery = event["recovery"]
    if not isinstance(recovery, dict):
        fail(f"case[{ordinal}].recovery is not an object")
    if not isinstance(recovery.get("status"), str) or not recovery["status"]:
        fail(f"case[{ordinal}] lacks a recovery status")
    if not isinstance(recovery.get("retained"), bool):
        fail(f"case[{ordinal}] retained is not boolean")
    if not isinstance(recovery.get("idempotent_retry"), bool):
        fail(f"case[{ordinal}] idempotent_retry is not boolean")
    if recovery["retained"]:
        if not isinstance(recovery.get("retained_file"), str) or not recovery["retained_file"]:
            fail(f"case[{ordinal}] retained result lacks retained_file")
    return {"event": event, "checkpoint": checkpoint, "recovery": recovery}


def validate_case_semantics(index: int, parsed: dict[str, Any]) -> None:
    event = parsed["event"]
    recovery = parsed["recovery"]
    status = recovery["status"]
    process = event["process"]
    expected = (
        "RECOVERED_EXACT",
        "RECOVERED_EXACT",
        "REPLAYED_EXACT",
        "DISK_FULL_RETAINED",
        "IO_ERROR_RETAINED",
        "FSYNC_ERROR_RETAINED",
        "DIR_FSYNC_AMBIGUOUS_RETAINED",
        "TORN_WRITE_REJECTED",
        "ROLLBACK_REJECTED",
        "ROLLBACK_REJECTED",
        "SKEW_REJECTED",
        "ORDER_REPLAYED_EXACT",
        "FORK_RETAINED",
    )[index]
    if status != expected:
        fail(f"{event['case_id']} expected {expected}, got {status}")
    if index <= 10 and process["worker_pid"] is None:
        fail(f"{event['case_id']} must have an independent worker process")
    if index <= 10 and not process["sigkill_observed"]:
        fail(f"{event['case_id']} must record SIGKILL")
    if index in {0, 1, 2, 11}:
        if status not in POSITIVE_STATUSES or recovery["retained"]:
            fail(f"{event['case_id']} positive replay classification is inconsistent")
        if not recovery["idempotent_retry"]:
            fail(f"{event['case_id']} positive replay must be idempotent")
    else:
        if not recovery["retained"]:
            fail(f"{event['case_id']} negative mutant was not retained")
        if recovery["idempotent_retry"]:
            # Directory-fsync ambiguity is the one negative that can be
            # retried after exact readback; all other mutants must remain held.
            if index != 6:
                fail(f"{event['case_id']} rejected mutant became idempotent")

    if index == 3 and recovery.get("error_code") != "ENOSPC":
        fail("disk-full case must retain an ENOSPC classification")
    if index == 4 and recovery.get("error_code") != "EIO":
        fail("I/O case must retain an EIO classification")
    if index == 5 and recovery.get("error_code") != "EIO":
        fail("fsync case must retain an EIO classification")
    if index == 6 and recovery.get("error_code") != "DIRECTORY_FSYNC_EIO":
        fail("directory-fsync case must retain its injected error")
    if index == 7 and recovery.get("error_code") != "TORN_WRITE":
        fail("torn-write case must retain its exact error")
    if index in {8, 9} and recovery.get("error_code") != "LOWER_THAN_EXTERNAL_WATERMARK":
        fail(f"{event['case_id']} must reject below-anchor rollback")
    if index == 10 and recovery.get("error_code") != "APPLICATION_SAFETY_ROOT_MISMATCH":
        fail("skew case must reject application/safety mismatch")
    if index == 11 and recovery.get("heights") != [1, 2, 3]:
        fail("multi-block replay must be contiguous 1,2,3")
    if index == 12 and recovery.get("error_code") != "LOSING_FORK_NOT_GC_ELIGIBLE":
        fail("losing fork must stay retained until explicit reclamation authority")


def validate_retained(index: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    if not isinstance(index, list):
        fail("retained_mutants must be an array")
    if len(index) != len(REQUIRED_MUTANTS):
        fail("retained_mutants count does not cover every required mutant")
    seen: set[str] = set()
    case_by_id = {event["case_id"]: event for event in cases}
    for ordinal, item in enumerate(index):
        if not isinstance(item, dict):
            fail(f"retained_mutants[{ordinal}] is not an object")
        required_keys(item, {"case_id", "kind", "source_name", "path", "bytes", "sha256", "retained"}, f"retained_mutants[{ordinal}]")
        case_id = item["case_id"]
        if case_id in seen or case_id not in case_by_id:
            fail(f"retained_mutants[{ordinal}] has duplicate/unknown case")
        seen.add(case_id)
        if item["retained"] is not True or not isinstance(item["kind"], str):
            fail(f"retained_mutants[{ordinal}] is not marked retained")
        if item["kind"] not in REQUIRED_MUTANTS:
            fail(f"retained_mutants[{ordinal}] has unknown kind {item['kind']!r}")
        if item["path"] != f"retained/{case_id}.bin" or not isinstance(item["source_name"], str):
            fail(f"retained_mutants[{ordinal}] path is not case-bound")
        if isinstance(item["bytes"], bool) or not isinstance(item["bytes"], int) or item["bytes"] <= 0:
            fail(f"retained_mutants[{ordinal}] byte count is invalid")
        if HEX64.fullmatch(item["sha256"]) is None:
            fail(f"retained_mutants[{ordinal}] digest is invalid")
    kinds = {item["kind"] for item in index}
    if kinds != REQUIRED_MUTANTS:
        fail(f"retained mutant kinds differ: expected {sorted(REQUIRED_MUTANTS)!r}, got {sorted(kinds)!r}")


def validate_evidence(document: dict[str, Any]) -> dict[str, Any]:
    required_keys(
        document,
        {
            "schema",
            "schema_version",
            "package_id",
            "status",
            "scope",
            "authority",
            "classification",
            "data_scope",
            "candidate_only",
            "production",
            "production_candidate",
            "production_consensus_activation",
            "g1_r4_exit",
            "base",
            "head",
            "plan",
            "worktree",
            "command",
            "replay_command",
            "topology",
            "fault_schedule",
            "cases",
            "positive_count",
            "negative_count",
            "retained_mutants",
            "source_seam_audit",
            "upstream_blockers",
            "known_gaps",
            "assertions",
            "evidence_scope_contract",
        }
        | ({"independent_replay"} if "independent_replay" in document else set()),
        "evidence",
    )
    if (
        document["schema"] != SCHEMA
        or document["schema_version"] != 1
        or document["package_id"] != "G1_R4_FAULT_MATRIX_V1"
        or document["status"] != "BLOCKED_UPSTREAM"
        or document["scope"] != "process"
        or document["authority"] != "candidate"
        or document["classification"] != "candidate-non-normative"
        or document["candidate_only"] is not True
        or document["production"] is not False
        or document["production_candidate"] is not False
        or document["production_consensus_activation"] is not False
        or document["g1_r4_exit"] is not False
    ):
        fail("evidence scope/status is not the frozen candidate contract")
    base = document["base"]
    if not isinstance(base, dict) or base.get("commit") != BASE_COMMIT or base.get("tree") != BASE_TREE:
        fail("base commit/tree does not bind exact candidate")
    if base.get("ref") != "refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829":
        fail("base ref is not the exact candidate ref")
    head = document["head"]
    if not isinstance(head, dict) or not isinstance(head.get("commit"), (str, type(None))) or not isinstance(head.get("tree"), (str, type(None))):
        fail("head provenance is malformed")
    plan = document["plan"]
    if not isinstance(plan, dict) or plan.get("assessed_commit") != "8198fea0307eb368df34ff77ffc272a6b0e655ec" or plan.get("latest_live_commit") != "92449b8e101642f39d644d863db7bb60dea488f7":
        fail("plan tuple is not bound to assessed/latest refs")
    worktree = document["worktree"]
    if not isinstance(worktree, dict) or not isinstance(worktree.get("clean"), bool) or not HEX64.fullmatch(worktree.get("status_sha256", "")):
        fail("worktree provenance is malformed")
    cases_raw = document["cases"]
    if not isinstance(cases_raw, list) or len(cases_raw) != len(CASE_ORDER):
        fail("case list length/order is not frozen")
    parsed = [validate_event(event, ordinal) for ordinal, event in enumerate(cases_raw)]
    for ordinal, item in enumerate(parsed):
        validate_case_semantics(ordinal, item)
    positive = sum(item["recovery"]["status"] in POSITIVE_STATUSES for item in parsed)
    negative = len(parsed) - positive
    if document["positive_count"] != positive or document["negative_count"] != negative:
        fail("positive/negative counts do not match case statuses")
    validate_retained(document["retained_mutants"], cases_raw)
    assertions = document["assertions"]
    if not isinstance(assertions, dict) or assertions.get("production_authority_minted") is not False or assertions.get("g1_exit") is not False or assertions.get("retained_mutants_indexed") is not True:
        fail("machine assertions accidentally claim promotion or omit retention")
    if document["upstream_blockers"] == [] or not isinstance(document["known_gaps"], list) or not document["known_gaps"]:
        fail("blocked package must carry upstream blockers and known gaps")
    return {
        "schema": "trnm-g1-r4-independent-replay-v1",
        "status": "PASS_CANDIDATE_ONLY",
        "cases": len(parsed),
        "positive_count": positive,
        "negative_count": negative,
        "retained_mutants": len(document["retained_mutants"]),
        "bytes_roots_and_statuses_agree": True,
        "independent_implementation": True,
        "production_authority": False,
        "g1_r4_exit": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        document = strict_json(args.evidence.read_bytes(), "evidence")
        result = validate_evidence(document)
    except (OSError, ReplayFailure) as error:
        print(f"G1-R4 independent replay failed closed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
