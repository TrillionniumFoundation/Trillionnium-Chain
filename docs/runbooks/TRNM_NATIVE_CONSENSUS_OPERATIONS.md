# Native Consensus Operator Runbook

## Scope

This runbook covers only the self-developed `trnm-chain-node` and `trnm-chain-validator` processes.

## Preflight

```bash
bash scripts/project-preflight.sh --audit
bash scripts/ci/check_self_consensus_only.sh
cd trillionnium
cargo test --workspace --locked
cargo build -p trnm-node --features self-consensus --bins --locked
```

Record the full commit, clean status, binary hashes, chain ID, genesis hash, node configuration hashes, validator public keys, voting power, and rollback anchor.

## Start a local validation set

Use distinct data directories and keys for each validator. For the repository development fixture:

```bash
cd trillionnium
./scripts/devnet_up.sh
```

Confirm:

- every validator has the expected chain ID and validator-set hash;
- no signing-state directory is shared;
- finalized height advances with identical AppHash across nodes;
- RPC, P2P, and metrics listeners match the recorded configuration.

## Stop

```bash
cd trillionnium
./scripts/devnet_down.sh
```

Confirm all native node and validator processes have stopped before copying, restoring, or rotating signing state.

## Recovery

1. Isolate the failed node.
2. Preserve logs, WAL/checkpoints, database files, configuration, and signing-state metadata.
3. Verify chain ID, genesis hash, validator identity, last signed height/round, finalized height, and AppHash.
4. Restore only from an authenticated source whose height and root are independently verified.
5. Start in catch-up mode without enabling signing until anti-equivocation continuity is proven.
6. Re-enable signing only after the node converges and the operator records approval evidence.

Never reset last-signed metadata merely to make a node start.

## Key rotation

A rotation packet must bind old and new public keys, validator identity, activation height, voting power, authorization proof, operator approvals, rollback condition, and observed finality after activation. The old signer remains isolated after handoff.

## Incident stop conditions

Immediately stop signing and escalate on:

- conflicting vote or root evidence;
- unexpected chain/genesis/validator-set identity;
- missing or rolled-back anti-equivocation state;
- unauthorized validator-set change;
- non-contiguous durable state;
- repeated replay/authentication failures;
- state sync that cannot prove the expected root.
