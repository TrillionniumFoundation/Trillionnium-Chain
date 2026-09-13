#!/usr/bin/env python3
"""Closed evidence-profile and artifact-role vocabulary for G3 LAN bundles.

The profile is an evidence-semantics boundary, not a presentation label.  A
no-fault run and a future mixed-authority fault campaign therefore cannot
share one manifest/collector contract or silently substitute for each other.
"""

from __future__ import annotations

from dataclasses import dataclass


NO_FAULT_V1 = "no-fault-v1"
NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1 = "no-fault-signed-runtime-observer-v1"
NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1 = (
    "no-fault-signed-runtime-external-load-v1"
)
MIXED_AUTHORITY_FAULT_MATRIX_V1 = "mixed-authority-fault-matrix-v1"
KNOWN_PROFILES = {
    NO_FAULT_V1,
    NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1,
    NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1,
    MIXED_AUTHORITY_FAULT_MATRIX_V1,
}
ACTIVE_BUNDLE_PROFILES = {NO_FAULT_V1}

# This is the exact singleton subset of coordinator.manifest.public_files
# emitted by prepare_run_material.py. Validator configs and the mac observer
# config are cardinality-bearing roles and are therefore added separately.
COORDINATOR_PUBLIC_SINGLETON_PATHS = {
    "topology": "topology.json",
    "validator_set": "public/validator-set.json",
    "workload_corpus": "public/workload.corpus",
    "workload_policy": "public/workload-policy.json",
    "bootstrap_h1_proposal": "public/bootstrap/h1.proposal",
    "bootstrap_h2_proposal": "public/bootstrap/h2.proposal",
    "bootstrap_h3_proposal": "public/bootstrap/h3.proposal",
    "bootstrap_finality_proof": "public/bootstrap/finality-proof.cev0",
    "bootstrap_manifest": "public/bootstrap/bootstrap.json",
}

FROZEN_LAN_HOST_SUBJECTS = frozenset(
    {"local", "x230", "desktop", "rog", "j3160", "mac"}
)

LEGACY_UNSIGNED_VALIDATOR_ROLES = frozenset(
    {"validator_event_log", "validator_metrics", "validator_final_state"}
)
LEGACY_OBSERVER_REPORT_ROLE = "observer_report"


@dataclass(frozen=True)
class BundleRoleVocabulary:
    """One closed role/subject vocabulary selected by evidence profile."""

    singleton: frozenset[str]
    validator: frozenset[str]
    host: frozenset[str]
    observer: frozenset[str]
    fault: frozenset[str]
    host_subjects: frozenset[str] = frozenset()

    @property
    def all_roles(self) -> frozenset[str]:
        return self.singleton | self.validator | self.host | self.observer | self.fault


_CANDIDATE_SINGLETON_ROLES = frozenset(
    {
        "candidate_source",
        "linux_binary",
        "macos_binary",
        "material_builder_binary",
        "build_report",
        "coordinator_manifest",
        *COORDINATOR_PUBLIC_SINGLETON_PATHS,
    }
)
_SIGNED_RUNTIME_VALIDATOR_ROLES = frozenset(
    {
        "validator_config",
        "validator_fleet_start_certificate",
        "validator_runtime_event_journal",
        "validator_consensus_run_report",
        "validator_runtime_metrics",
        "validator_runtime_final_state",
    }
)
_LEGACY_SINGLETON_ROLES = _CANDIDATE_SINGLETON_ROLES | {"collector_report"}
_LEGACY_VALIDATOR_ROLES = (
    _SIGNED_RUNTIME_VALIDATOR_ROLES | LEGACY_UNSIGNED_VALIDATOR_ROLES
)
_LEGACY_OBSERVER_ROLES = frozenset({"observer_config", LEGACY_OBSERVER_REPORT_ROLE})
_LEGACY_FAULT_ROLES = frozenset({"fault_schedule", "fault_command_log"})

# A-tier is the observer-only signed-runtime contract. It deliberately has no
# legacy unsigned projection roles. ``signed_observer_report`` is a new role,
# not an alias for the legacy unsigned ``observer_report`` artifact.
_A_TIER_SINGLETON_ROLES = _CANDIDATE_SINGLETON_ROLES | frozenset(
    {
        "observer_public_manifest",
        "coordinator_anchor_record",
        "runner_prestart_plan",
        "runner_resource_preflight",
        "runner_clock_envelope",
        "runner_lifecycle",
        "runner_launch_observation",
        "runner_summary",
        "runner_output_manifest",
        "collector_report",
    }
)
_A_TIER_VALIDATOR_ROLES = _SIGNED_RUNTIME_VALIDATOR_ROLES | frozenset(
    {
        "validator_deployment_manifest",
        "validator_replay_archive_context",
        "validator_replay_archive_entries",
        "validator_replay_archive_head",
        "validator_replay_archive_terminal_seal",
        "validator_process_stdout",
        "validator_process_stderr",
    }
)
_A_TIER_HOST_ROLES = frozenset({"host_run_provenance"})
_A_TIER_OBSERVER_ROLES = frozenset({"observer_config", "signed_observer_report"})

ROLE_VOCABULARIES = {
    NO_FAULT_V1: BundleRoleVocabulary(
        singleton=_LEGACY_SINGLETON_ROLES,
        validator=_LEGACY_VALIDATOR_ROLES,
        host=frozenset(),
        observer=_LEGACY_OBSERVER_ROLES,
        fault=_LEGACY_FAULT_ROLES,
    ),
    # The fault profile is still plan-only and retains the old input surface
    # only so its existing planning diagnostics remain reproducible. No legacy
    # fault artifact is active authority.
    MIXED_AUTHORITY_FAULT_MATRIX_V1: BundleRoleVocabulary(
        singleton=_LEGACY_SINGLETON_ROLES,
        validator=_LEGACY_VALIDATOR_ROLES,
        host=frozenset(),
        observer=_LEGACY_OBSERVER_ROLES,
        fault=_LEGACY_FAULT_ROLES,
    ),
    NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1: BundleRoleVocabulary(
        singleton=_A_TIER_SINGLETON_ROLES,
        validator=_A_TIER_VALIDATOR_ROLES,
        host=_A_TIER_HOST_ROLES,
        observer=_A_TIER_OBSERVER_ROLES,
        fault=frozenset(),
        host_subjects=FROZEN_LAN_HOST_SUBJECTS,
    ),
    NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1: BundleRoleVocabulary(
        singleton=_A_TIER_SINGLETON_ROLES,
        validator=_A_TIER_VALIDATOR_ROLES
        | frozenset({"validator_workload_receipt_log"}),
        host=_A_TIER_HOST_ROLES,
        observer=_A_TIER_OBSERVER_ROLES
        | frozenset({"signed_observer_load_submission_log"}),
        fault=frozenset(),
        host_subjects=FROZEN_LAN_HOST_SUBJECTS,
    ),
}

PROFILE_AUTHORITY_BLOCKERS = {
    NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1: (
        "signed-macos-observer-report-producer-unavailable",
        "content-addressed-host-provenance-unavailable",
    ),
    NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1: (
        "signed-macos-observer-report-producer-unavailable",
        "content-addressed-host-provenance-unavailable",
        "external-workload-ingress-and-n-of-n-receipts-unavailable",
    ),
    MIXED_AUTHORITY_FAULT_MATRIX_V1: (
        "distinct-connectivity-evidence-unavailable",
        "process-instance-2-recovery-start-catchup-authority-unavailable",
        "signed-degraded-window-binding-unavailable",
        "stable-restart-cut-scheduler-join-unavailable",
        "isolated-startup-rejection-scheduler-unavailable",
        "signed-operational-epoch-handoff-unavailable",
    ),
}


def require_known(profile: object, field: str = "evidence_profile") -> str:
    if not isinstance(profile, str) or profile not in KNOWN_PROFILES:
        raise ValueError(
            f"{field} must be one of {sorted(KNOWN_PROFILES)!r}"
        )
    return profile


def role_vocabulary(profile: object) -> BundleRoleVocabulary:
    return ROLE_VOCABULARIES[require_known(profile)]


def authority_blockers(profile: object) -> tuple[str, ...]:
    value = require_known(profile)
    return PROFILE_AUTHORITY_BLOCKERS.get(value, ())


def require_active(profile: object) -> str:
    value = require_known(profile)
    if value not in ACTIVE_BUNDLE_PROFILES:
        raise RuntimeError(
            f"{value} is plan-only until all authority blockers are closed: "
            + ", ".join(authority_blockers(value))
        )
    return value


def fault_artifacts_allowed(profile: str) -> bool:
    """Legacy primary fault schedule/log roles are authoritative for no profile."""

    require_known(profile)
    return False
