# TRNM CometBFT Adapter Spike — 2026-07-27

Status: **four-validator recovery and fresh-node state sync proven locally**

## Proven

- CometBFT `v0.38.17` runs against the Rust `tendermint-abci` `v0.40.4`
  ABCI++ adapter.
- `CheckTx`, deterministic `PrepareProposal`, `ProcessProposal`,
  `FinalizeBlock`, `Commit`, and the ABCI snapshot methods reuse TRNM signed
  command validation, authorized signer policy, deterministic command execution,
  and the canonical state commitment.
- `PrepareProposal` applies transactions against a temporary ordered overlay and
  filters malformed, expired, replayed command ID/signer nonce, conflicting, and
  over-limit transactions before they can poison a proposal.
- `InitChain` fails closed unless the CometBFT chain ID, genesis application
  schema/version, and authorized signer set match the local application config.
  The fixtures also pin `consensus_params.version.app=2`; omitting that pin was
  proven to make a fresh node reject state sync with an app-version mismatch.
- Application hash v2 commits the object state, accepted command IDs, and signer
  nonces so state sync cannot preserve the object root while weakening replay
  protection.
- Two independent application instances produce the same application hash for
  the same ordered transaction block.
- A tampered signed envelope is rejected during proposal processing.
- Finalization stages state without advancing committed height before `Commit`.
- Committed application state uses a SQLite WAL store with `synchronous=FULL`.
  Each `Commit` transaction writes only this block's object, command-ID, and
  signer-nonce delta before atomically advancing the height/app-hash head.
- `CheckTx`, `PrepareProposal`, and `ProcessProposal` use a touched-object
  overlay instead of cloning the complete committed state. `PendingBlock` also
  retains only the block delta; `FinalizeBlock` computes the canonical v2 root
  once using a root-only Merkle path that is byte-compatible with the prior
  proof-building implementation.
- Legacy `trnm_cometbft_app_state_v2` JSON is hash-validated, backed up, and
  migrated into SQLite. The JSON path then becomes a small recoverable
  height/app-hash status mirror; SQLite remains authoritative if a crash occurs
  after SQL commit but before mirror refresh.
- Store corruption, chain/app-version mismatch, or a non-contiguous expected tip
  fails closed. The store also binds the canonical authorized-signer policy, so
  a signer ID, role, or key cannot drift silently across a restart. Unit
  failpoints prove a crash before SQL commit restores the old tip and a crash
  after SQL commit restores the new tip.
- Backup/restore and file-authority rules are documented in
  `docs/runbooks/TRNM_COMETBFT_APPLICATION_STORE.md`; the JSON status cache is
  explicitly not sufficient backup evidence.
- The reproducible live-process fixture is
  `trillionnium/scripts/consensus/spike_cometbft_single_node.sh`.
- A real four-validator network commits identical application hashes, continues
  with one validator offline, and catches that validator up after restart.
- Production configurations write an atomic disk-backed snapshot every five
  committed heights and retain three generations. Snapshot chunks are served
  directly from disk, avoiding the previous `16 × full_state` resident-memory
  cost while keeping a discovered snapshot available as the chain advances.
- A fifth node with no application state restores a light-client-verified ABCI
  snapshot, catches up, and converges on the same application hash.
- The four-validator fixture is
  `trillionnium/scripts/consensus/spike_cometbft_four_validator.sh`.

## Not Yet Proven

- A truly logarithmic keyed incremental Merkle tree is not implemented. App-hash
  v2 compatibility still requires an ordered O(N) root pass during
  `FinalizeBlock`, although it no longer builds inclusion proofs or clones full
  object payloads. A sparse/Jellyfish-style v3 commitment requires an explicit
  app-version and snapshot-format migration.
- proposal/vote/commit crash-boundary recovery across four nodes;
- `3-1` and `2-2` partition healing without conflicting finalized heights;
- authenticated multi-host peer transport and remote validator bootstrap;
- validator-set updates, HSM/KMS, production networking, or public testnet SLOs.

The adapter is a spike boundary, not a readiness claim. The existing bespoke
loopback validator protocol must not be extended in parallel with this path.
