#!/usr/bin/env python3
"""Static positive/negative controls for the eight-fault authority map."""

from __future__ import annotations

import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fault_evidence_semantics_v1 as semantics  # noqa: E402


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except (RuntimeError, ValueError) as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def main() -> None:
    assert tuple(item["kind"] for item in semantics.plan_matrix()) == semantics.FAULT_ORDER
    assert set(semantics.POLICIES) == set(semantics.FAULT_ORDER)
    assert {
        kind
        for kind, policy in semantics.POLICIES.items()
        if policy.primary_journal_applied_recovered
    } == semantics.CONNECTIVITY_FAULTS
    assert {
        kind
        for kind, policy in semantics.POLICIES.items()
        if policy.isolated_startup_attempt
    } == semantics.NEGATIVE_STARTUP_FAULTS

    for kind in semantics.CONNECTIVITY_FAULTS:
        policy = semantics.policy_for(kind)
        assert policy.evidence_mode == semantics.SIGNED_CONNECTIVITY_TRANSITION
        assert policy.runtime_authority_supported is True
        assert policy.runner_execution_supported is True
        assert policy.recovered_finality_required is True
        semantics.require_primary_signed_transition(kind)

    restart = semantics.policy_for("validator_process_kill")
    assert restart.evidence_mode == semantics.SIGNED_RESTART_CATCHUP
    assert restart.signed_restart_catchup_required is True
    assert restart.runtime_authority_supported is False

    for kind in semantics.NEGATIVE_STARTUP_FAULTS:
        policy = semantics.policy_for(kind)
        assert policy.evidence_mode == semantics.ISOLATED_STARTUP_REJECTION
        assert policy.exact_rejection_required is True
        assert policy.main_campaign_must_continue is True
        assert policy.blocker == "stable-restart-cut-scheduler-join-unavailable"
        expect_failure(
            lambda kind=kind: semantics.require_primary_signed_transition(kind),
            "not primary-journal",
        )

    delay = semantics.policy_for("bounded_delay_loss")
    assert delay.evidence_mode == semantics.SIGNED_DEGRADED_RECOVERY
    assert delay.signed_timeout_or_tc_required is True
    assert delay.recovered_finality_required is True

    handoff = semantics.policy_for("epoch_handoff")
    assert handoff.evidence_mode == semantics.SIGNED_EPOCH_HANDOFF
    assert handoff.signed_epoch_handoff_required is True

    blockers = semantics.active_campaign_blockers()
    assert {item["kind"] for item in blockers} == {
        "validator_process_kill",
        "bounded_delay_loss",
        "stale_snapshot",
        "rollback_attempt",
        "epoch_handoff",
    }
    expect_failure(
        semantics.require_active_campaign_supported,
        "no fault effect was applied",
    )
    expect_failure(
        semantics.require_bundle_assembly_supported,
        "legacy exact-eight Applied/Recovered contract",
    )
    expect_failure(lambda: semantics.policy_for("unknown"), "unknown fault kind")

    print(
        "poco_g3_fault_evidence_semantics_v1_test=passed positives=25 negatives=5 "
        "connectivity_primary_signed=3 restart_catchup=distinct "
        "negative_startup_isolated=2 bounded_delay_degraded=required "
        "epoch_handoff_signed=required active_campaign=fail-closed "
        "active_bundle_assembly=fail-closed g3_complete=false"
    )


if __name__ == "__main__":
    main()
