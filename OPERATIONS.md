# TRNM Native PoCO Operations

Status: development operations; not a public-mainnet runbook.

## Build

The obsolete adapter dependency graph has been removed. Regenerate and review
the workspace lock before using locked release commands:

```bash
cd trillionnium
cargo generate-lockfile
cargo build --workspace
cargo test --workspace
```

The native node binaries are provided by `trnm-node`:

- `trnm-chain-node`
- `trnm-chain-validator`
- `trnm-chain-cli`
- `trnm-sim`

## Local development

Use the checked-in node configurations and scripts under
`trillionnium/configs/` and `trillionnium/scripts/`. Record the exact commit,
configuration hashes, validator identities and generated state before treating
a run as evidence.

## Key discipline

Consensus keys, operator keys and governance keys must be separate. Never place
production private keys in packages, repositories or generated evidence.
Development fixtures must be clearly marked and must not be reused outside
isolated environments.

## Recovery

1. Stop transaction ingress.
2. Preserve logs, checkpoints, write-ahead files and process metadata.
3. Verify the last committed height, block hash and state root from at least a
   quorum of independent nodes.
4. Restore only from an authenticated checkpoint and replay verified entries.
5. Rejoin as a non-voting observer until state convergence is proven.
6. Re-enable voting only after peer, key and state checks pass.

## Incident handling

For suspected equivocation, key compromise, state-root divergence or replay:

- isolate the affected validator;
- preserve signing and write-ahead evidence;
- halt any unsafe automated rotation;
- compare quorum certificates and state roots;
- execute the approved rotation or rollback procedure;
- publish a commit-bound incident record.

See `trillionnium/docs/runbooks/native-poco-validator-operations.md` for the
development validator procedure and `RELEASE_READINESS.md` for blockers.
