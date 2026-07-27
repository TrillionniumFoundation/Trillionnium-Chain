# TRNM Chain Devnet v1 Rollback

Rollback is an operator-controlled binary/config switch. It must not rewrite or
silently discard consensus history.

## Before promotion

1. Independently verify the candidate archive, archive checksum signature,
   internal `SHA256SUMS` signature, and every payload checksum.
2. Record the current package archive digest, genesis digest, validator-set id,
   node database path, and each validator database path.
3. Stop new Hepta/Nakama submissions and allow in-flight commands to reach a
   terminal receipt or remain explicitly pending.
4. Take read-only copies of the node and validator databases. Do not copy live
   SQLite files without the application-supported checkpoint/backup path.
5. Keep the previous verified package immutable and available.

## Roll back binaries/config

1. Stop the node first, then all validator processes.
2. Restore the previous package by its previously verified archive digest.
3. Restore the previous config and genesis as one unit. Never combine a node
   config from one package/instance with a different genesis or validator set.
4. Repoint the deployment symlink or service paths atomically.
5. Start validators, verify their public keys and durable tips, then start the
   node.
6. Verify chain id, genesis hash, validator-set id, tip height/hash, and finality
   receipt verification before reopening ingress.

## State compatibility

- If the candidate wrote no blocks, reuse of the previously recorded state may
  be allowed after the identity checks above.
- If the candidate finalized blocks, do not copy an older database over the
  newer history. Treat this as a protocol recovery/replay event and follow the
  WAL/checkpoint recovery runbook.
- A validator database contains anti-equivocation history. Never delete or
  replace it merely to make a conflicting proposal signable.
- If the previous binary cannot read the current schema, stop and restore the
  complete pre-promotion backup. Do not run ad-hoc downgrade SQL.

## Abort conditions

Keep ingress closed if any archive/signature/checksum differs, a trusted key is
unavailable, genesis/config identities disagree, a validator public key changes
unexpectedly, a validator reports a conflicting signed height, or a third party
cannot independently verify a finality receipt.
