# TRNM PoCO-BFT Mainline and CometBFT Cutover Decision — 2026-08-25

Status: **binding decision; implementation and production activation remain incomplete**

This document is the current consensus-route authority. It supersedes the
delivery choice in `TRNM_CONSENSUS_DELIVERY_DUAL_TRACK_DECISION_2026-08-11.md`
and the engine comparison in `TRNM_CONSENSUS_ENGINE_DECISION_2026-07-27.md`.
Those files remain historical evidence only.

## 1. One production route

TRNM adopts **self-developed native PoCO-BFT as the sole future production
consensus route**. The only intended production path is:

```text
authenticated PoCO ingress
  -> native PoCO node / bounded P2P / pacemaker
  -> deterministic PoCO Core + authoritative SafetyRules
  -> native application execution and JMT/ICS23 state
  -> ordered finalization + durable application acknowledgement
```

CometBFT is no longer a competing delivery track, fallback, compatibility
mode, or production differential authority. The existing CometBFT/ABCI
application is **migration residue and historical replay input only**. It must
not be shipped, deployed, included in a PoCO release SBOM, used for readiness
evidence, or receive new protocol features.

The machine-readable source for this decision is
`config/consensus-mainline.json`. A readiness or activation bit must remain
false until its corresponding evidence exists; declaring the route does not
declare a working node.

## 2. Current truth at the PoCO branch

The active PoCO workspace already excludes `trnm-consensus-app` and
`trnm-node`, and its normal Cargo lock has no CometBFT/Tendermint/ABCI
packages. That is only a **dependency-closure milestone**. The excluded
application, nested lockfile, Comet workflow, scripts, schemas, and historical
docs still exist and are intentionally retained until cutover.

The native node remains a fail-closed scaffold:

- `production_candidate=false` and `production_consensus_activation=false`;
- the default binary refuses startup;
- the production effect driver, Vote signing loop, authoritative SafetyRules,
  authenticated P2P/pacemaker, application/JMT adapter, ordered finalization,
  state sync, and deployable artifact are not complete;
- current unit and candidate-fleet results are development evidence, not real
  4/7-node or public-testnet evidence;
- a development-only `trnm-application-tx-builder-v0` now provides one
  external-signer, byte-stable envelope construction surface. It does not yet
  own nonce reservation, WAL replay, CheckTx-equivalent admission, or
  broadcast; the CLI remains a development/template adapter;
- a dirty worktree or a candidate-index mismatch cannot be used as a release
  candidate.

The current stage is `G1-native-host-incomplete`, not `public-testnet` or
`mainnet`.

## 3. Migration model: finalized export, fresh genesis

There is **no in-place Comet-to-PoCO database or WAL conversion**. Once the
native migration contract is implemented:

1. Stop old-chain ingress at a reviewed, finalized height `H`.
2. Pin a read-only source transaction and independently verify the old
   AppHash, object/value commitments, replay indexes, validator lifecycle,
   and source chain identity.
3. Emit a content-addressed `CometStateExportV1` manifest. It includes the
   source chain/app/store IDs, `H`, block ID, old AppHash, every exported
   object/index digest, mapping/profile digest, and operator signatures. Live
   WAL/SHM, blockstore, `priv_validator_state`, snapshots, pending blocks, and
   mempool are never copied.
4. Import the manifest into a **new** PoCO data directory and recompute the
   native JMT/state root. The old AppHash is recorded only as a signed
   `legacy_app_hash_attestation`; it is not assumed equal to the PoCO root.
5. Bind the export digest, mapping/profile digest, resulting root, source
   height/block ID, validator-set digest, protocol version, and genesis
   descriptor into the PoCO genesis ceremony / GenesisQC. An operator-local
   root or configuration value is insufficient.
6. Generate fresh PoCO SafetyState, signer journal, external watermark, node
   WAL, chain ID, network magic, and validator key IDs. Old validator signing
   state is not trusted or imported.
7. Re-run the first 100 blocks, roots, receipts, proofs, validator set, and
   RPC queries from a clean clone. Only after signed review may the new chain
   be called a migration candidate.

Rollback is asymmetric: before the first PoCO finalized block, the unchanged
old chain may be isolated and resumed; after PoCO finality, copying a PoCO
database/WAL back to Comet or silently downgrading is forbidden. Further
changes require a PoCO governance migration.

## 4. Cutover and cleanup gates

### C0 — replacement complete

C0 requires the G0–G4 gates in the execution board, including a real native
node, cross-host fault/recovery evidence, state sync, independent replay/light
client, signed artifacts, and migration rehearsal. The following must all be
true on one clean commit/tag:

- no production dependency, binary, API, wire, storage, release, SBOM, or
  operator path imports CometBFT, Tendermint, ABCI, or ABCI++;
- PoCO finality is independently verifiable and no conflicting finalized block
  or double-sign is observed;
- source export/import is deterministic and the new genesis commitments are
  independently reproduced;
- all Critical/High blockers are closed and production activation is explicitly
  reviewed.

### C1 — Comet tombstone and removal

C1 runs only after C0. Preserve a signed, immutable external/tagged archive of
the historical oracle first; then remove from the active tree:

- `trnm-consensus-app`, its nested `Cargo.lock`, `trnm-node`, and Comet-only
  binaries/types/fixtures;
- the Comet workflow, download/install steps, spike/soak scripts, environment
  variables, and schemas;
- Comet dependencies from manifests, lockfiles, `deny.toml`, SBOM and release
  tooling;
- active docs and package names that imply a second consensus route.

The cleanup gate must run a negative dependency/source scan with an explicit
allowlist for the immutable archive and any versioned historical-domain
mapping retained for root compatibility. Do not mechanically rename
`trnm.cometbft.*` hash domains: changing a commitment domain changes roots and
requires a protocol-versioned mapping and replay vectors.

## 5. Non-negotiable anti-ambiguity rules

1. **One mainline:** only native PoCO-BFT may receive new consensus features.
2. **One safety domain per node:** Comet WAL, validator state, and PoCO
   SafetyState/signer watermark are never combined.
3. **One-way migration:** old finalized state is exported and attested, then
   imported into fresh PoCO genesis; no live-file copying or root substitution.
4. **Evidence labels are strict:** Comet fixtures are historical migration
   evidence; Core/simulator/unit green is not real-node evidence; a local or
   dirty run is not a release candidate.
5. **Feature order is strict:** finish protocol/core/node safety and recovery
   before TPS, parallel execution, DA, ZK/TEE, or activated PoCO economics.

## 6. Required references

- `docs/development/TRNM_POCO_BFT_EXECUTION_BOARD_2026-08-25.md`
- `docs/protocol/poco-bft-v0/IMPLEMENTATION_GAP_REGISTER.md`
- `docs/architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md`
- `docs/architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`
- `config/consensus-mainline.json`
