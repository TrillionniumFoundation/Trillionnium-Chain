# TRNM Native Validator Rotation and Disaster Recovery

Status: operator runbook

## Purpose

Define planned validator rotation, emergency replacement, host rebuild, and disaster-recovery evidence for the native PoCO network.

## Planned rotation

1. Record current chain height, finalized block, state root, validator set, and voting power.
2. Generate the replacement consensus key in the approved signer boundary.
3. Verify possession of the new key.
4. Submit the committed validator-set transition with the required approvals and activation height.
5. Keep simultaneous offline voting power below the configured safety threshold.
6. Start the replacement node as an observer, synchronize, and verify state-root agreement.
7. Enable signing only at the authorized activation boundary.
8. Verify that the old key is rejected and the new validator participates in quorum.
9. Preserve transition, vote, state-root, and operator evidence.

Inspect active native processes:

```bash
ps -ef | grep -E 'trnm-chain-node|trnm-chain-validator' | grep -v grep
```

## Emergency replacement

Use emergency replacement only after containment and evidence preservation. Determine whether the incident involves host loss, signer compromise, double-sign risk, corrupted storage, or network isolation.

Required fields:

```text
incident_id=
last_trusted_height=
last_trusted_block=
last_trusted_state_root=
validator_set_id=
retired_validator_id=
replacement_validator_id=
retired_public_key=
replacement_public_key=
activation_height=
```

## Disaster recovery

1. Stop affected services and preserve failed data/logs.
2. Select a trusted release commit and signed configuration set.
3. Restore signer anti-double-sign state independently from application state.
4. Restore application data from a verified backup or authenticated state source.
5. Verify chain history, finality receipts, validator set, and state root before signing.
6. Rejoin as an observer when possible.
7. Enable voting only after convergence and authorization checks pass.
8. Run restart, replay, and network-healing checks.

## Rollback boundary

Rollback may restore software and uncommitted operational state; it must not silently reverse a finalized chain state. Any chain-level recovery that changes committed history requires an explicit governance and incident process, independent review, and a new signed network decision.

## Acceptance criteria

- no two conflicting blocks finalized at one height;
- all healthy validators agree on the committed state root;
- the validator transition is committed and activated once;
- old keys and stale nonces are rejected;
- signer state survives restart;
- replacement and rebuild procedures have complete artifact hashes;
- alerts, dashboards, rollback, and replay commands are verified.

## Sign-off

```text
operator_decision=GO|CONDITIONAL_GO|NO-GO
validator_signoffs=
security_signoff=
release_owner=
open_blockers=
completed_at_utc=
```
