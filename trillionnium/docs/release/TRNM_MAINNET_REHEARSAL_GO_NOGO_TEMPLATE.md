# TRNM Native PoCO Mainnet Rehearsal GO / NO-GO Template

Status: operator decision template  
Scope: native node, validator, PoCO state transition, finality, recovery, and release evidence

## 1. Rehearsal identity

```text
change_ticket=
release_candidate=
branch=
commit_sha=
worktree_status=clean|dirty
started_at_utc=
completed_at_utc=
operator_lead=
security_lead=
```

A dirty tree, unresolved commit identity, or missing artifact hash is an automatic **NO-GO**.

## 2. Native binary identity

```text
node_binary=
node_binary_sha256=
validator_binary=
validator_binary_sha256=
cli_binary=
cli_binary_sha256=
rust_toolchain=
build_command=
```

Verify the active processes without matching unrelated software:

```bash
ps -ef | grep -E 'trnm-chain-node|trnm-chain-validator' | grep -v grep
```

Private keys must never appear in the evidence packet.

## 3. Network and validator set

```text
chain_id=
validator_set_id=
validator_count=
total_voting_power=
quorum_power=
peer_topology_artifact=
peer_topology_sha256=
genesis_artifact=
genesis_sha256=
```

All validators must use the same chain identity, protocol version, validator set, genesis commitment, and policy configuration.

## 4. Required gates

Record command, result, raw log path, and SHA-256 for each gate:

- repository/project preflight;
- full Rust workspace tests;
- native four-validator safety and liveness;
- proposal authentication and independent execution;
- vote authentication, anti-replay, and anti-equivocation;
- round change and proposer failure;
- minority and half-split partition behavior;
- crash before/after durable vote and state writes;
- restart, replay, rollback, and state-root convergence;
- validator join, replacement, rotation, and rejoin;
- PoCO value conservation, challenge, resolve, expiry, refund, and slashing;
- RPC, mempool, worker-agent, and operator-observability checks;
- sustained-load and resource-limit tests.

```text
gate_manifest=
gate_manifest_sha256=
raw_evidence_root=
failed_gate_count=
waived_gate_count=
```

Consensus, state-root, supply, escrow, signer, or rollback failures cannot be waived.

## 5. Fault matrix

```text
offline_validator_test=PASS|FAIL
process_crash_test=PASS|FAIL
network_partition_test=PASS|FAIL
packet_loss_test=PASS|FAIL
clock_skew_test=PASS|FAIL
disk_full_test=PASS|FAIL
signer_outage_test=PASS|FAIL
state_rebuild_test=PASS|FAIL
```

The result is **NO-GO** when safety cannot be proven, quorum recovery is ambiguous, or evidence is incomplete.

## 6. Rollout and rollback

```text
rollout_order=
maximum_simultaneous_offline_power=
observation_window=
rollback_trigger=
rollback_command=
replay_command=
previous_stable_commit=
state_restore_source=
```

Rollback and replay commands must come from tested artifacts, not operator memory.

## 7. Decision

```text
decision=GO|CONDITIONAL_GO|NO-GO
open_blockers=
accepted_non_consensus_risks=
validator_signoffs=
operator_signoff=
security_signoff=
release_owner_signoff=
```

A local rehearsal pass is not proof of public-network readiness. Preserve the exact topology, workload, duration, hardware, latency distribution, resource peaks, and limitations with the decision.
