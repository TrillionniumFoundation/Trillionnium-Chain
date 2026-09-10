# TRNM Native Validator Bootstrap and Re-bootstrap

Status: operator runbook for the self-developed PoCO validator network

## 1. Required inputs

```text
repository_commit=
release_manifest=
node_binary_sha256=
validator_binary_sha256=
chain_id=
genesis_sha256=
validator_set_id=
validator_id=
consensus_public_key=
peer_allowlist_or_seed_source=
```

Private keys must be provisioned through the approved signer boundary and must never be packaged with binaries or configuration archives.

## 2. Host preparation

- create a dedicated service account;
- limit filesystem permissions;
- reserve data, log, snapshot, and temporary-disk capacity;
- configure time synchronization and monitoring;
- expose only required RPC and peer ports;
- prevent public access to administrative or signer endpoints;
- install exact, hashed release binaries.

Check for an existing native process before bootstrap:

```bash
ps -ef | grep -E 'trnm-chain-node|trnm-chain-validator' | grep -v grep
```

## 3. Configuration validation

Verify that local configuration matches the signed inputs for:

- chain ID and protocol version;
- genesis and validator-set commitments;
- validator ID, public key, and voting power;
- peer identities and transport policy;
- data and WAL locations;
- RPC exposure and rate limits;
- metrics, logs, alerts, and signer endpoint;
- rollback and trusted-state source.

Reject unknown fields and unresolved placeholders.

## 4. Initial bootstrap

1. Start the native node in non-voting or observer mode where supported.
2. Authenticate peers and confirm the expected network identity.
3. Synchronize from genesis or an approved trusted state source.
4. Verify block history, finality receipts, and state roots.
5. Start the validator signer only after state convergence.
6. Confirm that the validator votes at the expected height and round.
7. Observe quorum, finality, and state-root agreement for the required window.

## 5. Re-bootstrap after failure

1. Stop native node and validator processes.
2. Preserve the failed data directory and logs as evidence.
3. Record the last trusted height, state root, validator set, and signer anti-double-sign state.
4. Rebuild the host from trusted binaries and configuration.
5. Restore from an approved offline backup or authenticated state source.
6. Verify continuity before enabling signing.
7. Confirm that replay cannot cause duplicate vote, command, nonce, receipt, reward, or settlement credit.

Stop only the intended native processes:

```bash
pkill -f 'trnm-chain-node|trnm-chain-validator'
```

## 6. Acceptance checks

Bootstrap is complete only when:

- peer identity and chain identity match;
- the local committed height and state root converge with quorum peers;
- the validator set and voting power are correct;
- no conflicting vote exists for the restored signer state;
- RPC, metrics, disk, clock, and signer alerts are healthy;
- a controlled restart returns to the same committed state;
- evidence and configuration hashes are recorded.

## 7. Fail-closed conditions

Do not enable voting when chain identity, genesis, state root, signer state, validator authorization, peer authentication, or rollback source cannot be proven.
