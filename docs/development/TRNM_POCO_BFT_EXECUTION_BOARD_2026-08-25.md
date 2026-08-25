# TRNM PoCO-BFT Execution Board — 2026-08-25

Status: **active execution board; no production or public-testnet gate is complete**

This is the executable plan for the native PoCO-BFT-only decision. It replaces
the old dual-track schedule as the current sequencing authority. Calendar
ranges are planning windows, not evidence; a gate is closed only by its exit
criteria.

## 1. Dependency graph

```text
M0 truth/branch freeze
  -> M1 P0 protocol + independent review
    -> M2 P1 Core/SafetyRules + epoch/finality/replay
      -> M3 native single-node host + application/JMT
        -> M4 export/import + fresh PoCO genesis
          -> M5 authenticated P2P/pacemaker/signer/state sync
            -> M6 4/7-node cross-host fault and soak
              -> M7 cutover rehearsal and signed release candidate
                -> M8 Comet tombstone/cleanup
                  -> M9 research testnet / later mainnet review
```

Execution may parallelize specification, tooling, and observability, but no
downstream gate inherits completion from an incomplete predecessor.

### Current machine evidence (2026-08-25)

- `trnm-poco-node` is intentionally fail-closed: the default binary still
  reports missing signer, SafetyRules, application, finalization, P2P and state
  sync contracts. Core/SafetyRules/node-library unit suites are local evidence,
  not a live-node or production-consensus pass.
- The lock-pinned Quint and `protoc` toolchains are now installed and have
  passed their local type/protobuf gates; a final clean formal run and CI
  reproduction remain required for the P0 exit.
- The native execution crash/WAL metadata boundary drift was closed in
  `06f1733e6`; the gate remains fail-closed and still does not imply automatic
  WAL/SHM recovery.
- CEV0 admission now has root-byte, signature-work and validator-set TC-share
  budgets, with explicit limits clamped to intrinsic hard caps (`5b28425df`,
  `cd7602693`). The normative wire/conformance review and independent second
  implementation are still open.
- A development-only canonical application tx-builder candidate now emits
  exact inner/outer bytes and uses an external signer boundary. It deliberately
  does not reserve nonces, write WAL, query a node or broadcast; native-node
  integration remains a G2 blocker.
- The deployed recovery owner now performs a final paired K/P readback over
  every terminal validation row and its exact durable application artifact
  immediately before returning the inert owner. This narrows the observed
  mutation window and fails closed on any digest/head drift; it is not yet a
  cross-database atomic lock, so MIG-004 remains open.
- Remote-signer, checkpoint and state-sync crates currently expose adapters or
  data types; production credential, SafetyRules, validator-runtime and
  activation flags remain false.

## 2. Gate board

| Gate | Scope | Current status | Exit evidence |
|---|---|---|---|
| G0 | canonical branch, status, schema/error registry, zero active Comet dependency | partial | clean reproducible commit; machine truth and CI agree |
| G1 | frozen-v0 deterministic Core, authoritative SafetyRules, durable safety/signing boundaries | open | 100,000 non-empty blocks, exact replay, no double-sign/root drift |
| G2 | native node effect driver, execution/JMT, mempool, pacemaker, P2P, signer, state sync | not started as a complete node | default binary runs a real proposal-to-apply path and survives crash matrix |
| G3 | 4→7 validators across hosts, partitions, equivocation, disk/resource faults, metrics | not started | repeatable multi-host evidence with zero conflicting finality |
| G4 | upgrade/rollback, independent verifier/light client, governance/economics, audit and soak | not started | signed RC, 7–30 day soak, all Critical/High closed |
| C0 | PoCO replacement and migration rehearsal | blocked by G1–G4 | signed export/import and first PoCO finality |
| C1 | remove Comet residue from active tree | blocked by C0 | negative dependency/source/CI scan and external archive |

## 3. Ordered work packages

### MIG-000 — freeze truth and scope (G0, now)

- Keep one clean canonical PoCO branch and one signed commit/tag per candidate.
- Make `config/consensus-mainline.json`, Cargo metadata, CI, README and
  release truth agree that native PoCO-BFT is the only production route.
- Mark Comet as `migration-residue-only`; forbid new features, release builds,
  deployments, and readiness claims from the residue.
- Repair candidate-index/source drift, workspace/schema/error-registry drift,
  and excluded-package workflow references.

### MIG-001 — close P0 protocol and proof contracts

- Complete QC/TC, epoch/activation/handoff, evidence, network envelope,
  decoder/allocation bounds, and same-/cross-epoch light-client schemas.
- Add CPU, byte, signer-count, and admission budgets for large TC/CEV0 inputs;
  a 10,000-share certificate cannot cause unbounded verification work.
- Keep the CEV0 budgeted decoder on every active wire/collector ingress and
  freeze the resulting limits in the normative vector/independent replay set.
- Obtain an independent consensus-engineer review and a second implementation
  that reproduces every normative vector and retained mutant.
- Do not set `wire_conformance=true` or enable network signing before this exit.

### MIG-002 — finish deterministic Core and SafetyRules (G1)

- Promote SafetyRules from inert/shadow evaluation to one authoritative owner
  for Vote and Timeout, with persist-before-sign and exact lock/QC/TC replay.
- Complete pacemaker inputs/outputs, epoch transitions, trusted-checkpoint
  catch-up beyond `max_blocks`, ordered ancestor finalization, and permanent
  terminal execution records.
- Bind full canonical body, parent, runtime/configuration and roots into the
  validation contract; remove legacy APIs that can bypass the native path.
- Exercise SIGKILL, response loss, disk-full, read-only/corrupt store, stale
  checkpoint, signer-watermark skew, and whole-namespace rollback cases.

### MIG-003 — make `trnm-poco-node` a real single-node host (G2)

- Replace the fail-closed startup scaffold with a private production constructor
  that owns Core, SafetyStore, signer journal, native application, overlay,
  mempool, pacemaker and effect driver.
- Integrate the development-only canonical transaction-builder candidate with
  the node-owned external signer, pending-nonce reservation, epoch resource
  policy, and durable replay. The exit path is exact inner/outer envelope bytes
  -> reservation -> CheckTx-equivalent admission -> commit receipt/AppHash
  replay; the builder alone is not this gate.
- Execute `ingress -> proposal -> validate -> Safety persist -> sign -> QC/TC ->
  ordered finalize -> JMT/App commit -> acknowledgement` with one source of
  truth for block, receipt and state roots.

### MIG-004 — close storage, signer and rollback authority

- Unify lineage checks across SafetyStore v7/Safety schema v13, signer journal,
  node-event WAL, native application schema, and whole-node checkpoint.
- Add independently administered remote signer/HSM/KMS and monotonic watermark;
  never reconstruct signing state from an application snapshot.
- Close file identity/TOCTOU, clone, namespace, WAL/SHM, fsync, power-loss,
  disk-full and commit-uncertain cases. The current K/P audit now has a final
  paired readback, but must still become shared-locked (and use fd-bound
  identity where required); path identity plus a readback is not atomic
  authority.

### MIG-005 — extract execution and authenticated state (G2)

- Move canonical objects, validator lifecycle, fees, replay indexes, JMT/ICS23,
  receipts/events, and snapshot/state-sync manifests behind the native app.
- Define PoCO header commitments for block/body/receipt/event/DA/execution roots
  and explicit empty-block behavior.
- Prove serial runtime and native adapter produce byte-identical roots, receipts,
  plans and replay outcomes in an independent verifier.

### MIG-006/007 — export old finalized state and import fresh PoCO genesis

- Implement the read-only `CometStateExportV1` manifest at finalized height H.
- Implement deterministic `PoCOGenesisV1` import with a fresh chain ID/data
  directory and synthetic GenesisQC/validator set.
- Include source AppHash only as `legacy_app_hash_attestation`; bind export,
  mapping/profile, new root and source identity into the signed genesis
  descriptor. Never import Comet WAL/blockstore/validator signing state.

### MIG-008/009 — production network and signer ladder (G2/G3)

- Authenticated encrypted P2P, peer discovery/admission, bounded decode and
  backpressure, proposer rotation, timeout/pacemaker, vote/QC/TC relay,
  durable mempool replay, checkpoint/state sync and light-client verification.
- Run 4 validators, then 7 validators on at least three physical hosts / two
  network domains with remote signer ceremony, rotation, compromise and
  recovery drills.

### MIG-010/011 — public surfaces and upgrade safety (G3/G4)

- Versioned PoCO RPC/WS/gRPC and durable indexer keyed by block ID + state root
  + finality proof; no ABCI semantics in the release API.
- Define hot/full/archive/pruned node tiers, task terminal-row archival/GC,
  snapshot quotas, retention/restore accounting and lag SLOs.
- Add forward-only protocol/store/epoch upgrade, crash-at-prepare/commit,
  rollback-before-activation, downgrade/mixed-version refusal, and cutover
  rollback runbooks.

### MIG-012/013 — cutover rehearsal and promotion

- Run two clean-clone export/import rehearsals, verify first 100 blocks and all
  roots/receipts/proofs/RPC queries, and sign the migration bundle.
- Complete 7→20 controlled WAN/fault/resource campaigns, 7–30 day soak,
  independent light client/replay implementation, external consensus/crypto/
  economics review, SBOM/provenance and operator DR.

### MIG-014/016 — Comet cleanup (C1, only after C0)

- Tag or externally archive the old oracle and migration evidence.
- Remove excluded app/node packages, nested locks, Comet binaries/types,
  workflow/downloads, spike scripts, fixtures, env vars, schemas and active
  docs. Replace them with native PoCO gates and names.
- Keep only explicitly allowlisted historical hash domains until a versioned
  root-mapping/replay gate permits their removal.

## 4. Remaining blockers, ranked

### P0 — cannot enable network signing

1. No independent review of the complete protocol and remaining schema/vector
   corpus; formal/protobuf tooling is not reproducible on every workstation.
2. `wire_conformance=false`; remaining epoch, evidence, network-envelope,
   upgrade, light-client and weighted TC limits are open. CEV0 must be bounded
   by validator-set, CPU, bytes, signature count and admission budgets.
3. Source-of-truth drift: dirty PoCO worktree, candidate-index mismatch,
   workspace/CI/schema/error-registry and old dual-track wording. Boundary
   metadata must be generated/validated from one schema.

### P1 — deterministic safety/core blockers

1. Core and SafetyRules are prototypes/shadow evaluators, not an authoritative
   Vote/Timeout signer owner.
2. Pacemaker, complete epoch transition, checkpoint-scale catch-up, ordered
   ancestor finalization and permanent terminal execution log are incomplete.
3. Full proposal body/parent/runtime validation and cross-crash replay are not
   closed; current bounded facts cannot reconstruct every post-crash input.
4. The additive authenticated-genesis ceremony now rejects foreign application
   commitments, but the GenesisQC wire/hash itself still does not carry a
   cross-peer application-root commitment. Migration provenance and imported
   root must be committed into a versioned GenesisQC/ceremony before G1/C0.

### P2 — real-node blockers

1. `trnm-poco-node` default startup intentionally fails; effect driver, Vote
   signing, application adapter and process integration are absent.
2. The canonical tx-builder candidate is not yet connected to a node-owned
   CheckTx-equivalent ingress, pending-nonce WAL/replay, or production signer;
   CLI transfer/receipt paths remain development-only shell/template adapters.
3. No authenticated production P2P/pacemaker, remote signer/HSM/watermark,
   durable mempool replay, state sync or native RPC/indexer path.
4. No real 4/7-node cross-host crash, partition, equivocation, reorder, disk,
   clock-skew or long-soak evidence; current G3 ledger remains false.
5. K/P dual-store audit now re-reads the complete paired K/P inventory at the
   return boundary and fails closed on observed drift. It still has a
   non-atomic window under a rewrite after that read; close with one shared
   cross-store lock and fd-bound identity where required.

### P3/P4 — promotion and economics blockers

1. PoCO weights, bonds, staking/jailing/slashing and governance activation are
   shadow-only; no permissionless-account/economic anti-abuse closure.
2. Terminal TaskV1 rows lack archive/GC/retention/charging policy; long history
   will grow SQLite, snapshots and full-node replication without bound. JMT
   pruning alone does not reclaim business rows.
3. DA, AI verification profiles, independent light client, resource/network
   attack campaigns, external audits and 7–30 day soak are not complete.

## 5. Stop conditions and release labels

Until C0 and C1 are signed:

- release names are `internal-devnet` or `research-testnet` only;
- `production_candidate`, `production_consensus_activation`, and public-mainnet
  claims remain false;
- Comet evidence may be cited only as historical/migration evidence and never
  as PoCO finality, node, or performance evidence;
- TPS, parallel execution, DA, ZK/TEE and AI-economics work is subordinate to
  the blockers above.

The shortest honest next slice is: clean canonical commit → candidate-index/CI
truth repair → authoritative SafetyRules/Core owner → native application
execution/ordered finalization → real single-node crash matrix. Only then start
the authenticated multi-host ladder.
