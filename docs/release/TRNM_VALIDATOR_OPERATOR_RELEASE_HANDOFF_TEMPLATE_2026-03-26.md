# TRNM Native Validator / Operator Release Handoff Template

Use this template for a native PoCO validator rehearsal, upgrade, rollback, replacement, or operational handoff.

A handoff is fail-closed: missing identity, artifact, configuration, rollback, or sign-off fields mean the run is evidence-incomplete.

## 1. Run identity

```text
operator_id=
window_type=rehearsal|upgrade|rollback|replacement|handoff
change_ticket=
started_at_utc=
worktree_root=
workspace_root=
branch=
branch_ref=
head_sha=
worktree_status=clean|dirty
```

## 2. Native binaries

```text
node_binary_path=
node_binary_sha256=
validator_binary_path=
validator_binary_sha256=
cli_binary_path=
cli_binary_sha256=
build_command=
rust_toolchain=
```

Expected binaries are produced from `trnm-node` and `trnm-cli` in the `trillionnium/` workspace.

## 3. Network and validator identity

```text
chain_id=
validator_set_id=
validator_count=
node_id=
validator_id=
consensus_public_key=
p2p_listen_address=
rpc_listen_address=
seed_mode=static|dynamic|mixed
seed_or_allowlist_source=
```

Never place private keys or seed material in this record.

## 4. Genesis and configuration

```text
genesis_path=
genesis_sha256=
config_set_id=
node_config_sha256=
validator_config_sha256=
policy_config_sha256=
```

All participants must use the same chain identity, validator-set definition, protocol version, and genesis commitment.

## 5. Preflight evidence

Record commands and artifact paths for:

- repository/worktree identity verification;
- `cargo test --workspace --locked`;
- native four-validator smoke;
- restart and replay recovery;
- message authentication and anti-replay;
- round-change and partition safety;
- state-root and finality-receipt verification;
- PoCO conservation, challenge, resolve, timeout, and slashing gates;
- operator observability and alert checks.

```text
preflight_summary_path=
preflight_summary_sha256=
raw_log_root=
artifact_manifest=
artifact_manifest_sha256=
```

## 6. Rollout

```text
rollout_order=
quorum_floor=
maximum_simultaneous_offline_power=
health_probe=
finality_probe=
state_root_probe=
observation_window=
```

Stop the rollout when quorum, state-root agreement, finality uniqueness, message authentication, or resource safety cannot be proven.

## 7. Rollback

```text
previous_stable_anchor=
rollback_entrypoint=
rollback_trigger=
state_restore_source=
replay_entrypoint=
post_rollback_validation=
```

Rollback commands must be copied from tested artifacts rather than reconstructed from memory.

## 8. Sign-off

```text
operator_decision=GO|CONDITIONAL_GO|NO_GO
validator_signoffs=
security_signoff=
release_owner=
open_blockers=
accepted_risks=
completed_at_utc=
```

A local pass is not public-network readiness. Preserve exact commit, artifact hashes, topology, workload, and limitations with every decision.
