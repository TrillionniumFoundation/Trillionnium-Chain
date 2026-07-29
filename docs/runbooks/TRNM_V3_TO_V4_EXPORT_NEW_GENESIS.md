# TRNM v3 → v4 Offline Export-New-Genesis Runbook

Status: review-only migration tooling. This is not an in-place database migration,
not a state-sync snapshot, and not proof that a v4 network has been launched.

## Boundary

`trnm-v3-export-new-genesis` accepts only an offline
`trnm_cometbft_app_state_v3` JSON file. It does not read a live SQLite database,
does not change the source file, does not preserve the old height as a target live
height, and does not calculate or assert a target v4 AppHash.

The target chain ID must be new and different from the chain ID committed by the
source validator lifecycle. Reusing the old chain ID, CometBFT data directory,
application database, snapshot, or validator signing state is unsupported.

## Prepare the source

1. Stop transaction ingress, CometBFT, and the v3 ABCI application.
2. Preserve the authoritative database and CometBFT data independently.
3. Obtain the exact validated v3 JSON export. The best-effort status cache is not
   sufficient.
4. Record the source path, file SHA-256, height, AppHash, chain ID, and custody
   owner out of band.
5. Run this tool on a copy in an offline review environment.

## Export

From the repository root:

```bash
cargo run \
  --manifest-path trillionnium/Cargo.toml \
  --locked \
  -p trnm-consensus-app \
  --bin trnm-v3-export-new-genesis -- \
  --source-v3 /offline/source/app-state-v3.json \
  --target-chain-id trnm-public-testnet-v4-new \
  --output-dir /offline/review/trnm-v4-new-genesis-bundle
```

The output directory must not already exist. The tool writes a sibling temporary
directory, fsyncs each artifact, and publishes the complete directory by rename.
It fails closed on unknown JSON fields, unsupported schemas, non-canonical hashes,
object value-hash mismatch, malformed validator lifecycle, duplicate replay
indexes, legacy AppHash mismatch, source changes during export, target/source
chain-ID equality, or an existing output directory.

## Bundle contents

- `manifest.json`: source SHA-256, height, verified legacy AppHash, source/target
  chain IDs, target `app_version=4`, artifact hashes, and explicit review flags.
- `canonical-objects.json`: sorted, value-hash-verified v3 objects.
- `legacy-replay-indexes.json`: command IDs and signer nonces preserved for review;
  automatic v4 import is explicitly unsupported.
- `validator-lifecycle.json`: exact source lifecycle plus a proposed target-genesis
  review view. Pending transitions are never carried automatically.
- `README.md`: mandatory human review and signing checklist.
- `ROLLBACK.md`: abort/rollback boundary.

The bundle intentionally contains no target AppHash and is not directly consumable
by a node.

## Mandatory review and signing

Before constructing a v4 genesis, reviewers must:

1. independently reproduce all source and artifact hashes;
2. review every object and decide how chain-ID-bearing values are transformed;
3. review replay protection instead of silently dropping command IDs/nonces;
4. supply the complete authorized-signer identities and public keys, because v3
   commits only their hash;
5. resolve any pending validator transition explicitly;
6. review active validators, governance, fees, balances, escrow, and issued supply;
7. construct a separate v4 genesis through the approved genesis tooling;
8. obtain the required human approvals/signatures; and
9. start with fresh CometBFT/application data and independently verify the first
   v4 AppHash.

## Abort and rollback

Before target launch, abort by quarantining the bundle and preserving the unchanged
v3 source evidence. After target launch there is no database downgrade. Stop the
new chain, preserve evidence, and make an explicit governance/operations decision.
Never copy v4 state into the v3 store or reuse validator signing state across the
two chain IDs.
