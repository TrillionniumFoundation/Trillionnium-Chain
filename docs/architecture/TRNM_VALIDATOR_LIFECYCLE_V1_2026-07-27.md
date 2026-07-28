# TRNM Validator Lifecycle v1 — 2026-07-27

Status: implemented, unit/crash-recovery tested, and proven in a six-node local
CometBFT process fixture. Cross-host operations and production governance remain
required before public-testnet readiness.

## State and commitment

App version 3 commits one validator-lifecycle state containing:

- immutable chain ID, app version, and canonical authorized-signer-policy hash;
- an explicit governance operator and minimum activation delay;
- the canonical active validator set;
- at most one pending transition; and
- the last applied transition ID.

The same state is included in app-hash v3, SQLite store schema v2, and snapshot
format v2. A fresh state-sync target validates the committed identity against
its local chain and signer configuration before replacing empty state.

## Transition command

`trnm_validator_set_transition_v1` carries the complete target set, not an
unordered list of mutations. It binds:

- chain and outer command/transition ID;
- current validator-set hash as compare-and-swap base;
- activation height;
- canonical target public keys and voting powers; and
- an Ed25519 possession proof from every key newly entering the set.

The outer signed envelope must come from the governance signer with role
`operator`. This v1 authorization is deliberately a single-operator,
fail-closed prototype boundary. Threshold governance and HSM/KMS-backed
approval remain required before public testnet.

## Timing

For activation height `A`, the application returns CometBFT
`validator_updates` in `FinalizeBlock(A-2)`. CometBFT applies them at `A`; the
application moves the committed active set at that same height. Pending state
survives restart and snapshot recovery, so replay emits the same updates.

## Safety constraints

- Target sets contain at least four validators.
- No validator may hold one third or more of target voting power.
- Total and individual power stay within CometBFT's maximum total power.
- Retained keys hold strictly more than two thirds of both the old and new
  total power.
- Only one transition may be pending.
- Public keys use canonical lowercase hex; binary-key case aliases are rejected.
- A committed `unsafe_allow_single_validator_genesis=true` exists only for the
  single-node local spike. It permits exactly one genesis validator and does not
  weaken transition-target checks.

These rules permit controlled 4→5, 5→4, power change, and one-key rotation while
rejecting quorum-destroying bulk replacement.

## Live-process evidence

`trillionnium/scripts/consensus/spike_cometbft_validator_lifecycle.sh` starts six
applications and six CometBFT nodes, then proves 4→5 addition with possession
proof, 5→4 removal, one-key rotation, removed/added local voting power, continued
post-rotation finalization, app-hash convergence, and per-height block-ID safety.
The fixture uses loopback-only unsafe mempool flush RPC to make phase boundaries
deterministic; that RPC is not part of a production configuration or trust claim.
