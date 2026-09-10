# TRNM Native Signer Rotation and Compromise SOP

Status: operator runbook

## Scope

This procedure covers validator, operator, governance, worker, and consumer signing keys used by the native PoCO chain.

## Immediate containment

1. Freeze affected transaction or validator ingress where the protocol permits it.
2. Preserve logs, vote records, state roots, receipts, process lists, and signer-service audit trails.
3. Identify the affected role, public key, validator set, nonce range, first suspected time, and last trusted height.
4. Prevent the compromised signer from producing new signatures.
5. Do not delete state, logs, or signer anti-double-sign records.

Inspect native processes:

```bash
ps -ef | grep -E 'trnm-chain-node|trnm-chain-validator' | grep -v grep
```

For an emergency stop on the affected host only:

```bash
pkill -f 'trnm-chain-node|trnm-chain-validator'
```

Do not use broad process patterns on shared hosts.

## Evidence packet

Record:

```text
incident_id=
chain_id=
affected_role=
affected_public_key=
validator_id=
first_suspected_utc=
last_trusted_height=
last_trusted_state_root=
current_validator_set_id=
containment_action=
```

Never copy private key material into the packet.

## Planned rotation

1. Generate the replacement key in the approved signer boundary.
2. Prove possession without exporting the private key.
3. Prepare a signed validator-set or authority-policy transition.
4. Require the configured governance approvals and activation delay.
5. Verify that old and new identities cannot both act after activation.
6. Observe at least one full finality and recovery window after activation.
7. Archive public transition evidence and revoke the old key.

## Compromise replacement

A compromise replacement must additionally:

- search for conflicting votes or unauthorized transactions;
- verify nonce and replay state;
- compare state roots across unaffected validators;
- quarantine artifacts from the affected host;
- rebuild from a trusted binary, configuration, and state source;
- rotate adjacent credentials that may share the same trust boundary;
- document whether rollback, replay, slashing, refund, or governance action is required.

## Validation

The incident cannot close until:

- quorum and unique finality are restored;
- all healthy validators agree on height and state root;
- the retired key is rejected;
- the replacement key passes possession and authorization checks;
- restart and replay do not re-enable the old signer;
- monitoring alerts on any later use of the retired identity;
- all evidence is hashed and bound to a repository commit.

## Post-incident review

Classify root cause, exposure duration, affected protocol actions, economic impact, missing controls, and follow-up gates. Any suspected conflicting finality or supply/escrow violation requires independent security review before resuming release activity.
