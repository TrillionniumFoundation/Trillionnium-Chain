#!/usr/bin/env python3
"""Truth contract for the active D0 P2P admission helper.

The Rust helper performs a real two-ended signed handshake and grants only a
bounded process-local peer lease.  This module intentionally does not open a
socket or start a validator; it validates the evidence/truth boundary emitted
by a targeted Rust test or a future runner.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any


PROFILE = "active-p2p-admission-helper-v1"
SCHEMA_VERSION = 1

ACTIVE_TRUTH_FIELDS = {
    "active_helper": True,
    "dual_ended_signed_handshake": True,
    "nonce_freshness_and_replay_rejection": True,
    "epoch_binding": True,
    "validator_set_binding": True,
    "peer_lease_fencing": True,
    "bounded_cleanup_rebind": True,
}
INACTIVE_TRUTH_FIELDS = {
    "host_attestation": False,
    "multihost_observed": False,
    "consensus_transport": False,
    "validator_runtime_started": False,
    "validator_run_completed": False,
    "production_activation": False,
}
TRUTH_FIELDS = {**ACTIVE_TRUTH_FIELDS, **INACTIVE_TRUTH_FIELDS}
REPORT_KEYS = {"schema_version", "profile", "source_commit", *TRUTH_FIELDS}
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class AdmissionTruthError(ValueError):
    """The helper report crossed its fail-closed truth boundary."""


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_truth_report(source_commit: str) -> dict[str, Any]:
    if not isinstance(source_commit, str) or COMMIT.fullmatch(source_commit) is None:
        raise AdmissionTruthError("source_commit must be one full lowercase Git hash")
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "source_commit": source_commit,
        **TRUTH_FIELDS,
    }


def validate_truth_report(report: object) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != REPORT_KEYS:
        raise AdmissionTruthError("report keys differ from the exact helper contract")
    if type(report["schema_version"]) is not int or report["schema_version"] != SCHEMA_VERSION:
        raise AdmissionTruthError("schema_version differs")
    if report["profile"] != PROFILE:
        raise AdmissionTruthError("profile differs")
    if (
        not isinstance(report["source_commit"], str)
        or COMMIT.fullmatch(report["source_commit"]) is None
    ):
        raise AdmissionTruthError("source_commit is not bound")
    for field, expected in TRUTH_FIELDS.items():
        if type(report[field]) is not bool or report[field] is not expected:
            raise AdmissionTruthError(f"{field} must be exactly {str(expected).lower()}")
    return report


def parse_truth_report(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > 16 * 1024:
        raise AdmissionTruthError("report exceeds the bounded byte profile")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionTruthError("report is not strict JSON") from error
    if canonical_json_bytes(value) != raw:
        raise AdmissionTruthError("report is not canonical JSON")
    return validate_truth_report(value)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: p2p_admission_helper_v1.py FULL_GIT_COMMIT")
    print(canonical_json_bytes(build_truth_report(sys.argv[1])).decode("utf-8"), end="")
