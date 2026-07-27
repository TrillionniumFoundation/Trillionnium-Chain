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
- Committed application state is atomically persisted and survives an adapter
  process restart while CometBFT remains running.
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

- proposal/vote/commit crash-boundary recovery across four nodes;
- `3-1` and `2-2` partition healing without conflicting finalized heights;
- authenticated multi-host peer transport and remote validator bootstrap;
- validator-set updates, HSM/KMS, production networking, or public testnet SLOs.

The adapter is a spike boundary, not a readiness claim. The existing bespoke
loopback validator protocol must not be extended in parallel with this path.
