#!/usr/bin/env python3
"""Frozen authority map for the PoCO G3 eight-fault campaign.

The Rust fault vocabulary is deliberately broader than the observations the
current runtime can authoritatively sign.  Fleet code must consult this table
before applying an effect or assembling evidence; vocabulary membership alone
is never evidence support.
"""

from __future__ import annotations

import dataclasses
from typing import Any


FAULT_ORDER = (
    "leader_loss",
    "validator_process_kill",
    "host_loss",
    "asymmetric_partition",
    "bounded_delay_loss",
    "stale_snapshot",
    "rollback_attempt",
    "epoch_handoff",
)

SIGNED_CONNECTIVITY_TRANSITION = "signed-runtime-connectivity-transition-v1"
SIGNED_RESTART_CATCHUP = "signed-runtime-restart-catchup-v1"
ISOLATED_STARTUP_REJECTION = "isolated-negative-startup-rejection-v1"
SIGNED_DEGRADED_RECOVERY = "signed-timeout-degraded-recovery-v1"
SIGNED_EPOCH_HANDOFF = "signed-epoch-handoff-v1"

CONNECTIVITY_FAULTS = frozenset(
    {"leader_loss", "host_loss", "asymmetric_partition"}
)
NEGATIVE_STARTUP_FAULTS = frozenset({"stale_snapshot", "rollback_attempt"})


@dataclasses.dataclass(frozen=True)
class FaultEvidencePolicyV1:
    kind: str
    evidence_mode: str
    runtime_authority_supported: bool
    runner_execution_supported: bool
    primary_journal_applied_recovered: bool
    isolated_startup_attempt: bool
    main_campaign_must_continue: bool
    exact_rejection_required: bool
    signed_restart_catchup_required: bool
    signed_timeout_or_tc_required: bool
    recovered_finality_required: bool
    signed_epoch_handoff_required: bool
    blocker: str

    def plan_record(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _policy(
    kind: str,
    evidence_mode: str,
    *,
    runtime_authority_supported: bool,
    runner_execution_supported: bool,
    primary_journal_applied_recovered: bool = False,
    isolated_startup_attempt: bool = False,
    main_campaign_must_continue: bool = False,
    exact_rejection_required: bool = False,
    signed_restart_catchup_required: bool = False,
    signed_timeout_or_tc_required: bool = False,
    recovered_finality_required: bool = False,
    signed_epoch_handoff_required: bool = False,
    blocker: str = "",
) -> FaultEvidencePolicyV1:
    return FaultEvidencePolicyV1(
        kind=kind,
        evidence_mode=evidence_mode,
        runtime_authority_supported=runtime_authority_supported,
        runner_execution_supported=runner_execution_supported,
        primary_journal_applied_recovered=primary_journal_applied_recovered,
        isolated_startup_attempt=isolated_startup_attempt,
        main_campaign_must_continue=main_campaign_must_continue,
        exact_rejection_required=exact_rejection_required,
        signed_restart_catchup_required=signed_restart_catchup_required,
        signed_timeout_or_tc_required=signed_timeout_or_tc_required,
        recovered_finality_required=recovered_finality_required,
        signed_epoch_handoff_required=signed_epoch_handoff_required,
        blocker=blocker,
    )


POLICIES: dict[str, FaultEvidencePolicyV1] = {
    kind: _policy(
        kind,
        SIGNED_CONNECTIVITY_TRANSITION,
        runtime_authority_supported=True,
        runner_execution_supported=True,
        primary_journal_applied_recovered=True,
        recovered_finality_required=True,
    )
    for kind in CONNECTIVITY_FAULTS
}
POLICIES.update(
    {
        "validator_process_kill": _policy(
            "validator_process_kill",
            SIGNED_RESTART_CATCHUP,
            runtime_authority_supported=False,
            runner_execution_supported=False,
            signed_restart_catchup_required=True,
            recovered_finality_required=True,
            blocker="process-instance-2-recovery-start-catchup-authority-unavailable",
        ),
        "bounded_delay_loss": _policy(
            "bounded_delay_loss",
            SIGNED_DEGRADED_RECOVERY,
            runtime_authority_supported=False,
            runner_execution_supported=False,
            signed_timeout_or_tc_required=True,
            recovered_finality_required=True,
            blocker="signed-degraded-window-binding-unavailable",
        ),
        "stale_snapshot": _policy(
            "stale_snapshot",
            ISOLATED_STARTUP_REJECTION,
            runtime_authority_supported=False,
            runner_execution_supported=False,
            isolated_startup_attempt=True,
            main_campaign_must_continue=True,
            exact_rejection_required=True,
            blocker="stable-restart-cut-scheduler-join-unavailable",
        ),
        "rollback_attempt": _policy(
            "rollback_attempt",
            ISOLATED_STARTUP_REJECTION,
            runtime_authority_supported=False,
            runner_execution_supported=False,
            isolated_startup_attempt=True,
            main_campaign_must_continue=True,
            exact_rejection_required=True,
            blocker="stable-restart-cut-scheduler-join-unavailable",
        ),
        "epoch_handoff": _policy(
            "epoch_handoff",
            SIGNED_EPOCH_HANDOFF,
            runtime_authority_supported=False,
            runner_execution_supported=False,
            signed_epoch_handoff_required=True,
            recovered_finality_required=True,
            blocker="signed-operational-epoch-handoff-unavailable",
        ),
    }
)


def _validate_table() -> None:
    if set(POLICIES) != set(FAULT_ORDER):
        raise AssertionError("fault evidence policy is not the exact eight-fault matrix")
    for kind in FAULT_ORDER:
        policy = POLICIES[kind]
        if policy.kind != kind or not policy.evidence_mode:
            raise AssertionError("fault evidence policy identity regressed")
        if policy.runner_execution_supported and not policy.runtime_authority_supported:
            raise AssertionError("runner support cannot exceed runtime authority")
        if policy.primary_journal_applied_recovered != (kind in CONNECTIVITY_FAULTS):
            raise AssertionError("only connectivity faults may use primary Applied/Recovered")
        if policy.isolated_startup_attempt != (kind in NEGATIVE_STARTUP_FAULTS):
            raise AssertionError("negative startup classification regressed")
        if policy.runtime_authority_supported and policy.blocker:
            raise AssertionError("supported fault must not retain a blocker")
        if not policy.runtime_authority_supported and not policy.blocker:
            raise AssertionError("unsupported fault must name its blocker")


_validate_table()


def policy_for(kind: str) -> FaultEvidencePolicyV1:
    try:
        return POLICIES[kind]
    except KeyError as error:
        raise ValueError(f"unknown fault kind {kind!r}") from error


def plan_matrix() -> list[dict[str, Any]]:
    return [policy_for(kind).plan_record() for kind in FAULT_ORDER]


def active_campaign_blockers() -> list[dict[str, str]]:
    return [
        {
            "kind": policy.kind,
            "evidence_mode": policy.evidence_mode,
            "blocker": policy.blocker,
        }
        for policy in (policy_for(kind) for kind in FAULT_ORDER)
        if not policy.runner_execution_supported
    ]


def require_active_campaign_supported() -> None:
    blockers = active_campaign_blockers()
    if blockers:
        rendered = ", ".join(
            f"{item['kind']}={item['blocker']}" for item in blockers
        )
        raise RuntimeError(
            "eight-fault campaign authority is incomplete; no fault effect was applied: "
            f"{rendered}"
        )


def require_primary_signed_transition(kind: str) -> None:
    policy = policy_for(kind)
    if not policy.primary_journal_applied_recovered:
        raise RuntimeError(
            f"{kind} uses {policy.evidence_mode}, not primary-journal "
            "FaultApplied/FaultRecovered"
        )


def bundle_assembly_blockers() -> list[dict[str, str]]:
    """Return blockers in the current exact-eight bundle checker contract.

    The existing checker requires primary signed Applied/Recovered for every
    fault.  That representation is unsound for five fault classes, so active
    assembly remains disabled until the checker has distinct artifact roles
    for restart, negative startup, degraded recovery, and epoch handoff.
    """

    blockers = active_campaign_blockers()
    return [
        *blockers,
        {
            "kind": "bundle-checker",
            "evidence_mode": "mixed-authority-eight-fault-matrix-v1",
            "blocker": "mixed-fault-evidence-artifact-contract-unavailable",
        },
    ]


def require_bundle_assembly_supported() -> None:
    blockers = bundle_assembly_blockers()
    rendered = ", ".join(
        f"{item['kind']}={item['blocker']}" for item in blockers
    )
    raise RuntimeError(
        "active bundle assembly is fail-closed because the legacy exact-eight "
        f"Applied/Recovered contract is not authoritative: {rendered}"
    )
