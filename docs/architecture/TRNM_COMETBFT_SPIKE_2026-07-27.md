# TRNM CometBFT Adapter Spike — 2026-07-27

Status: **four-validator crash recovery and fresh-node state sync proven locally**

## Proven

- CometBFT `v0.38.17` runs against the Rust `tendermint-abci` `v0.40.4`
  ABCI++ adapter.
- `CheckTx`, deterministic `PrepareProposal`, `ProcessProposal`,
  `FinalizeBlock`, `Commit`, and the ABCI snapshot methods reuse TRNM signed
  command validation, authorized signer policy, deterministic command execution,
  and the canonical state commitment.
- `PrepareProposal` applies transactions against a temporary ordered overlay and
  filters malformed, expired, replayed sequential account nonce, conflicting,
  and over-limit transactions before they can poison a proposal.
- `InitChain` fails closed unless the CometBFT chain ID, genesis application
  schema/version, authorized signer set, validator set, and committed governance
  policy match the local application config. The current fixtures pin
  `consensus_params.version.app=6`; app-version-5 genesis/version bindings are
  rejected rather than migrated. Omitting the application-version pin was proven
  to make a fresh node reject state sync with an app-version mismatch.
- Application hash v4 is a versioned Jellyfish Merkle Tree root over namespaced
  canonical objects, sequential account nonces, chain/app identity,
  authorized-signer policy, active validators, pending transition, and governance
  policy. State sync therefore cannot preserve the object root while weakening
  replay protection or changing validation identity.
- Validator transitions use a full canonical target set, base-set-hash CAS,
  delayed activation, bidirectional greater-than-two-thirds overlap, CometBFT
  power ceilings, and Ed25519 possession proofs for every new consensus key.
  The ABCI update is returned at `A-2` and becomes active at height `A`.
- Two independent application instances produce the same application hash for
  the same ordered transaction block.
- A tampered signed envelope is rejected during proposal processing.
- Finalization stages state without advancing committed height before `Commit`.
- Committed application state uses a SQLite WAL store with `synchronous=FULL`.
  Each production `Commit` transaction writes only this block's object, JMT, and
  lifecycle delta before atomically advancing the height/app-hash head.
- `CheckTx`, `PrepareProposal`, and `ProcessProposal` use a touched-object
  overlay instead of cloning the complete committed state. `PendingBlock` also
  retains only the block delta; `FinalizeBlock` plans the next JMT version
  directly against a pinned SQLite read transaction. Persistent startup and
  point queries do not rebuild the complete tree or materialize all objects.
- Store schema 4 persists lifecycle, canonical objects, JMT nodes/values,
  preimages, stale-node/value successor indices, roots, the durable proof-query
  floor, and the application head atomically with the block delta. An indexed,
  budgeted worker physically collects retained history outside `Commit` and
  yields to consensus writes and pinned snapshots. The legacy
  `trnm_cometbft_app_state_v3` JSON is never migrated in-place because changing
  an already committed root would break the CometBFT handshake.
  `trnm-v3-export-new-genesis` instead emits an explicitly reviewed bundle for
  a different chain ID while leaving the source untouched. The JSON state path
  is now only a best-effort height/app-hash status mirror; SQLite remains
  authoritative if a crash occurs after SQL commit but before mirror refresh.
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
- A real four-validator network commits identical application hashes and keeps
  finalizing while one validator crashes during proposal processing, during
  `FinalizeBlock` after the vote-selected block, and after durable SQLite commit
  but before the ABCI `Commit` response. One-shot marker files make each boundary
  deterministic. Every validator restarts, replays or accepts the authoritative
  SQLite tip as appropriate, and converges without conflicting finalized heights.
- Production configurations request a pinned SQLite format-4 snapshot every
  five committed heights, mark a busy worker for catch-up and pin the latest
  committed head only when that worker is free, and retain three validated
  generations. Snapshot chunks are served
  directly from disk; receives are written at fixed offsets with a durable
  resume journal instead of retaining or concatenating the payload in memory.
  Correctness is covered for multi-chunk restart and hostile-input rejection.
  A separate single-host release gate records persistent planning/fsync,
  budgeted pruning, restart, format-4 resume/restore, and WAL/temporary-disk
  peaks for smoke and formal million-object profiles.
- A fifth node with no application state restores a light-client-verified ABCI
  format-4 snapshot, catches up, and converges on the same application hash.
  The fixture asserts CometBFT's restored snapshot format/height and verified
  ABCI AppHash and writes a dedicated state-sync evidence record.
- The four-validator fixture is
  `trillionnium/scripts/consensus/spike_cometbft_four_validator.sh`.
- App-hash v4 commits application content but not height metadata, so a truly
  empty block keeps the same state root and does not force CometBFT into an
  unbounded empty-block loop.
- A six-node live fixture proves 4→5 addition, 5→4 removal, one-key rotation,
  post-rotation liveness, identical application hashes, and per-height block-ID
  uniqueness. The fixture is
  `trillionnium/scripts/consensus/spike_cometbft_validator_lifecycle.sh`.
- Rootless proxy-driven `3-1` and `2-2` cuts prove majority-only progress,
  minority/half-split stall, conflicting-nonce resolution, healing, and
  post-heal convergence without conflicting finalized heights. The fixture is
  `trillionnium/scripts/consensus/spike_cometbft_partition_matrix.sh`.

## Not Yet Proven

- The v4 JMT update path and physical retained-history deletion are
  incremental. Startup and hostile-snapshot verification still perform
  scale-dependent full-tree work. The persistent release gate measures SQLite
  fsync, restart/prune/restore, WAL, and temporary-disk peaks on one host; it
  does not measure CometBFT end-to-end or multi-host block latency.
- authenticated multi-host peer transport and remote validator bootstrap;
- threshold validator governance, HSM/KMS, production networking, cross-host
  fault recovery, long-duration soak, or public testnet SLOs.

The adapter is a spike boundary, not a readiness claim. The existing bespoke
loopback validator protocol must not be extended in parallel with this path.
