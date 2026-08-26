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

### Current machine evidence (2026-08-26)

- `trnm-poco-node` is intentionally fail-closed: the default binary still
  reports missing signer, SafetyRules, application, finalization, P2P and state
  sync contracts. Core/SafetyRules/node-library unit suites are local evidence,
  not a live-node or production-consensus pass.
- The clean all-features node library run
  (`cargo test --locked -p trnm-poco-node --all-features --lib`) completed
  189/189 in 620.06 seconds. This is feature-surface evidence only; the
  default binary, live effect driver, network and production activation remain
  fail-closed.
- The checksum-pinned `protoc` bootstrap (`eaf1db12e`) and lock-pinned Quint
  toolchains are installed; the clean local formal gate
  (`scripts/ci/check_poco_bft_v0_formal.sh`) passed all listed
  safety/TC/epoch/partition/upgrade/handoff/light-client/application
  invariants and mutant witnesses in this worktree. The independent wire,
  QC/TC, handoff, parameter, and ordered-root reconstructions also pass. CI
  reproduction, independent review, and a second implementation remain
  required for the P0 exit.
- The five previously failing Rust/schema taxonomy boundaries were corrected
  in `5a4bfccb8`: the four node-local SignIntent/HandoffSignIntent errors are
  explicitly scoped outside the B2-A..E peer vocabulary. All 15
  `check_poco_bft_v0_*_schema.sh` gates now pass; this closes only the local
  registry drift, not the independent review/second-implementation gate.
  `bd6d3b148` also corrected the protocol gap-register/conformance wording:
  48 B2-A..E peer codes plus four node-local signer-intent codes means 52 Rust
  enum values overall; node-local values remain outside peer wire taxonomy.
- `7b55fd1bb` now makes the decoder taxonomy machine-checked from the Rust
  `DecodeErrorCode::ALL` registry and a generated 52-entry
  `decoder-error-registry-v0.json`; the registry checker and all schema/truth
  gates pass on this clean candidate. This closes local artifact drift only;
  independent review, a second implementation, wire conformance and network
  signing remain open.
- `a9a395421` adds a separately curated, standard-library-only 52-entry
  registry reference and deterministic drift mutations. Its cross-check and
  self-test pass; this is independent taxonomy/metadata evidence only, not a
  second consensus implementation or protocol review.
- The native execution crash/WAL metadata boundary drift was closed in
  `06f1733e6`; the gate remains fail-closed and still does not imply automatic
  WAL/SHM recovery.
- CEV0 admission now has root-byte, signature-work and validator-set TC-share
  budgets, with explicit limits clamped to intrinsic hard caps (`5b28425df`,
  `cd7602693`) and public derivation bound to run/validator context
  (`b1e3f3528`, `cba106bd8`, `488e015f9`, `50b8a0dbd`). `760d60e79` aligns
  the authenticated validator-set ceiling with the frozen 100x100=10,000
  share schema bound and rejects a 101st reference before nested allocation.
  The normative wire/conformance review, fuzz corpus and independent second
  implementation are still open.
- The laboratory wire surface no longer exposes a protocol-default budget as
  a public decode entry: `decode_*_with_context` and the proposal budgeted
  decoder derive the CEV0 ceiling from
  the authenticated `ConsensusParametersV0` and active `ValidatorSet`, while
  the public low-level `protocol_v0` primitive is trusted-local vocabulary only
  and is not active network ingress; its lab replay wrappers remain explicitly
  limited to pinned local replay. Before deriving any public budget, the supplied
  consensus-parameter hash must equal the active validator-set hash (the
  fail-closed checks landed in `b1e3f3528`, `cba106bd8`, `488e015f9`, and
  `50b8a0dbd`); a
  mismatched parameter hash therefore cannot widen the byte, signature, or nested-TC
  limits. Authenticated network ingress continues to consume one shared
  derived budget in the collector. This closes the API-level budget bypass
  only; CPU/fuzz/formal coverage and production activation remain open.
- A development-only canonical application tx-builder candidate now emits
  exact inner/outer bytes, uses an external signer boundary, and exposes an
  exact typed `trnm-mempool` view. The view passes the builder's immutable body,
  digest, signer identity, nonce and resource claims into the pending-nonce
  admission API. The feature-gated `trnm-poco-node` `tx-admission-wal` slice
  (`5891e9c8f`, hardened through `e48376dfa`, `84bc4f83`, `617cbb15a`,
  `fecca250b`, `1ad718fd2`, `d0cc52e2e`, `01b378560`, `6611ef07f`,
  `72f89abe6`, `3f5432682`, `4d16d42ae`, `c68500676`, and `d97ec3ee8`)
  now provides a node-owned SQLite WAL/FULL pending-nonce
  reservation lifecycle with namespace/path fences, private-file checks,
  retained-row bounds, a typed builder-to-boundary API, and exact restart retry
  for `Reserved`. Ordinary startup remains fail-closed on `HandedOff`; the
  explicit candidate `recover_handed_off_with_receipt` path (`51a1954d8`) now
  accepts only exact authenticated metadata paired with a
  `VerifiedNativeCommitReceiptV0` token and commits that row transactionally.
  It never guesses, deletes, or rewrites an ambiguous row. Insert failures now
  distinguish constraint replay from disk/IO/busy errors while remaining
  fail-closed.
  It is not compiled by the default node and does not yet provide production
  CheckTx ingress, a production signer/broadcast loop, or tombstone GC. The
  candidate now has a signature-checked CheckTx seam, an authority-owned
  signer resolver with mismatch/no-resolver fail-closed tests, a node-owned
  chain/time context seam, a typed commit-receipt gate, authority-affined
  lifecycle tokens, and explicit candidate receipt binding; low-level typed
  admission remains a composition escape hatch, while automatic/production
  HandedOff resolution, production AppHash/readback integration, and
  production context ownership remain G2 blockers; the explicit recovery seam
  is candidate-only and production activation remains false. `f1b20e40b`
  closes a fail-open resolution path in this candidate: a durable `HandedOff`
  row can no longer be released by an explicit cancel or lease drop; only the
  exact authenticated receipt-recovery seam may resolve it. Production
  ingress/integration remains open.
- The deployed recovery owner now performs a final paired K/P readback over
  every terminal validation row and its exact durable application artifact
  immediately before returning the inert owner. A new private
  `cross_store_lock` helper holds a descriptor-bound shared lock on the
  canonical private authority directory for that paired pass, rechecks the
  directory's descriptor/path identity, and has adversarial rename/recreate
  coverage. Selected native P/K mutation windows (P execute/reserve, P anchor
  reopen, K acknowledgement/retry, and lab finalization application commit)
  now take the corresponding exclusive lock; H1 takeover requires a derived
  common root and process2 activation acquires its lock before the first paired
  read, with a final identity check at successful commit boundaries. The full
  entry-point matrix is recorded in
  `TRNM_POCO_P2_STORE_WRITER_MATRIX_2026-08-26.md` and landed in `6850b57f1`.
  `d696ce01d` extends the same fence across finalization-marker load, proof-
  bound P readback, and marker clear, with a focused mutual-exclusion and
  rename/recreate test. This is still an advisory, cooperating-owner fence:
  all writer adoption and
  the full cross-database atomicity proof remain open under MIG-004.
- `7e04803cf` extends the selected paired windows with descriptors for both
  concrete P/K database files. Canonical direct-child paths, inode/link/owner/
  mode identity and descriptor-versus-path rechecks now fail closed on child
  rename/recreate or unsafe permissions; the focused lock module is 7/7.
  This narrows pathname TOCTOU exposure only and does not prove SQLite
  cross-database atomicity, fsync/power-loss recovery, or adoption by every
  external writer.
- The live Core application-finalization receipt path now checks the exact
  ancestor-ordered queue front before mutating state (`567d24aeb`). Empty or
  replaced queue fronts return `UnexpectedFinalizationAck` transactionally;
  two negative tests and the 223-test Core library suite pass. This tightens
  an execution boundary only; authoritative Core/SafetyRules integration and
  crash/replay equivalence remain open.
- `2ffbb40bd` adds a single Core Vote/Timeout transition-install boundary:
  predecessor digest, complete successor state/context, canonical intent and
  revision are checked before the watermark is installed. Pending persistence
  and `StorageAck` retain the transition/predecessor binding, and a detached
  transition is rejected transactionally. The Core library suite is now
  223/223; this remains a legacy/shadow Core slice, not a live signer/effect
  driver.
- `5994d07e8` adds an explicit ignored long-horizon SafetyRules test. Two
  independent kernel executions inside the release test over 100,000
  genesis-anchored Vote/Timeout views produce byte-identical traces, final
  state digests and revision 200,000 (18.16 seconds locally). It is kernel-only
  evidence with a fixed fixture; it does not close the G1 non-empty-block,
  node, or crash-replay requirement.
- Remote-signer, checkpoint and state-sync crates currently expose adapters or
  data types; production credential, SafetyRules, validator-runtime and
  activation flags remain false.
- `286ae09a9` adds a static activation-manifest test that enumerates every
  currently exposed node/checkpoint/recovery/remote-signer/WAL/sidecar/lab
  activation or candidate flag. It requires all of them to remain false and
  requires the production gate to retain named blockers, including under the
  feature combination used by the lab/runtime candidates. This closes a
  capability-accounting gap only; it does not create an effect driver, vote
  loop, network ingress, or production authority.
- `d69063fe9` closes a concrete restart/state-sync namespace gap: retained
  checkpoints, the live validator-set QC, and the state-sync proof now share
  one typed chain-id binding. A checksum-valid record rewritten into a foreign
  namespace is rejected before QC recheck or state installation, with focused
  durable-tamper and proof-consumption tests. This hardens the boundary but
  does not make production state sync live.
- `ab16d676f` adds an exact, bounded decoder for the typed target-genesis
  manifest. It round-trips canonical bytes and rejects trailing, wrong-profile,
  and oversized inputs; it is still an inert migration-root seam with no source
  reader, target replay, GenesisQC conversion, or activation side effect.
- `d26e30a60` applies the intrinsic `MAX_CEV0_ROOT_BYTES_V0` ceiling before
  parsing on every unbudgeted exact CEV0 root entry (parameters, validator set,
  QC/TC, evidence, headers, finality/checkpoint, epoch and handoff kernels).
  Oversized roots now fail before parser work; application payloads retain their
  separate authenticated block/message limits. This is a parser hard-cap seam,
  not a complete network-DoS or wire-envelope solution.
- `4d30c44ce` enforces the authenticated validator-set aggregate-TC ceiling
  before nested QC/TC allocation in every budgeted certified-header, finality,
  checkpoint, and ordinary/trusted decode path. The consensus-types suite is
  155/155 after the regression; wire conformance, fuzz coverage, and network
  signing remain false.
- `bea0a5d5b` re-verifies the exact `FinalityProofV0` immediately before Core
  consumes an application-finalization acknowledgement. Invalid or substituted
  signatures leave the queue and Core state unchanged; the Core unit/doctest
  suites (now 223/223 + 46 doctests) and clippy gate are green. Core/SafetyRules are still not the sole
  production authority.
- `16cd45ee9` closes a drained-tag-3 recovery substitution: once the durable
  finalization queue is empty, recovery now requires the consumed transition
  proof id to equal the persisted `last_finalization` proof id before handing
  control back to the host reconciler. A foreign proof-id mutation is rejected
  transactionally; non-empty queues retain the existing exact host-reconciliation
  path. This narrows replay ambiguity but does not make Core authoritative.
- `be7e55e98` adds a candidate-only native readback verifier that binds the
  exact outer/inner transaction, native finalized block/proof/state root,
  occurrence index, and receipt commitment before a WAL row becomes
  `Committed`. Mutation tests reject mismatches and the feature-gated node
  target passes `clippy -D warnings`; production CheckTx/AppHash
  integration and the live node owner remain open, and activation stays false.
- `d73d74bbf` exercises that verifier against a real
  `DurableNativeApplicationV0` preview -> execute -> commit fixture. A
  coordinate-correct but bogus-signature three-chain proof is rejected before
  receipt minting; the WAL remains `HandedOff` and a reopen returns
  `AmbiguousHandoff`. The same test rejects outer/receipt/index cardinality
  drift. This proves a candidate fail-closed readback seam, not a valid-proof
  Core/SafetyRules join or production CheckTx/effect-driver path.

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

- Keep the `2ffbb40bd` transition-install boundary as the only Vote/Timeout
  watermark source in the current Core path, then promote the still-shadow
  Core/SafetyRules state to one production owner with persist-before-sign and
  exact lock/QC/TC replay.
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
  policy, and durable replay. A candidate node-owned SQLite WAL boundary now
  exists behind `tx-admission-wal`: ordinary startup intentionally fails
  closed on `HandedOff`, while `recover_handed_off_with_receipt` accepts only
  exact authenticated metadata plus a verified receipt token (`51a1954d8`) and
  performs the `Committed` transition transactionally. This explicit seam is
  not automatic or production-integrated. The exit path is exact inner/outer
  envelope bytes -> reservation -> CheckTx-equivalent admission -> commit
  receipt/AppHash replay; the builder or WAL slice alone is not this gate.
- Execute `ingress -> proposal -> validate -> Safety persist -> sign -> QC/TC ->
  ordered finalize -> JMT/App commit -> acknowledgement` with one source of
  truth for block, receipt and state roots.

### MIG-004 — close storage, signer and rollback authority

- Unify lineage checks across SafetyStore v7/Safety schema v13, signer journal,
  node-event WAL, native application schema, and whole-node checkpoint.
- Add independently administered remote signer/HSM/KMS and monotonic watermark;
  never reconstruct signing state from an application snapshot.
- Close file identity/TOCTOU, clone, namespace, WAL/SHM, fsync, power-loss,
  disk-full and commit-uncertain cases. The current K/P audit has a
  descriptor-bound shared reader lock, pathname/descriptor identity fence, and
  selected exclusive native-writer hooks, but the lock is advisory and not all
  P/K mutation paths are proven to adopt it. Path identity plus a readback is
  not, by itself, atomic authority; complete the writer matrix and use
  fd-bound identity where required.

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
- A typed `CometStateExportV1` manifest shape and bounded exact decoder now
  exist. It commits source application/store identity, cutoff block/finality
  references, legacy AppHash, object/index/receipt/rejected-object roots,
  source validator-set digest, application-schema/runtime profiles and mapping
  profile. This is a canonical evidence container only; no Comet store reader,
  finality verifier or import side effect is enabled yet.
- A typed `PocoGenesisV1` ceremony descriptor now exists in
  `trnm-consensus-types`. Legacy Comet genesis-document digest, finalized
  BlockID/part-set identity, and AppHash are separate types and cannot be
  substituted for native PoCO `GenesisHash`/`BlockId`/`StateRoot`. The
  descriptor binds source namespace, cutoff/migration-instance inputs, export
  and mapping/profile digests, fresh target chain/genesis, independently
  computed native root, target validator-set digest and protocol version. Its
  `PocoGenesisQcBindingV1` is profile-tagged and content-addressed while
  preserving the frozen GenesisQC v0 wire bytes.
- The descriptor has a bounded exact decoder (`1 KiB` pre-parse ceiling,
  canonical re-encoding, namespace/instance rechecks and trailing-byte
  refusal). The QC ceremony envelope has a separate bounded exact decoder and
  importer-owned trusted-set recheck, so a second importer can replay the same
  bytes without trusting a local JSON/YAML interpretation.
- An additive `GenesisQcCeremonyEvidenceV1` envelope now carries only ordered,
  target-validator signature shares over a distinct migration signing domain.
  Its exact decoder performs bounded parsing, signer-order/duplicate checks,
  trusted-set membership and weighted-quorum rechecks. A crypto verifier is an
  explicit caller-supplied trait; source-export quorum, cross-peer authority,
  and activation remain disabled (`false`) until the independent source
  verifier and dual-authority ceremony are complete.
- `CometStateExportV1::verify_with` now exposes an explicit, fail-closed
  importer boundary (`CometStateExportVerifierV1`) and returns a distinct
  `VerifiedCometStateExportV1` token only after source identity, source
  finality-proof, and mapping checks each return success. The token retains the
  exact export commitment but cannot be converted into a genesis, QC, or
  activation capability. No concrete Comet reader/finality verifier is wired
  yet, so the machine truth `source_export_and_finality_verifier` remains
  `false`.
- Only a `VerifiedCometStateExportV1` can construct the new inert
  `PocoTargetProjectionV1` statement. It rebinds the source export commitment
  and mapping profile to a fresh target chain/genesis, target manifest digest
  (whose preimage must include target validator/protocol coordinates), and a
  claimed native `StateRoot`; the legacy AppHash is absent from this
  target type and an explicit guard rejects byte-for-byte AppHash reuse. The
  bounded exact decoder requires the verified source token. Its
  `PocoTargetProjectionVerifierV1` manifest/recompute interface passes target
  identity and mapping context, but deliberately withholds the claimed root
  from the recomputation callback; only a successful independent replay
  returns an inert `VerifiedPocoTargetProjectionV1` token. No target replay,
  genesis/QC conversion, or activation is wired, so
  `target_projection_root_recomputed` remains `false`.
- Commit `8bee224b6` adds the next inert composition gate:
  `verify_against_target_projection_v1` checks exact export/mapping/
  target-manifest/chain/genesis/root commitments and the projection
  commitment, then re-runs trusted-set weighted quorum and the supplied
  Ed25519 verifier. It rejects cross-descriptor/projection substitution but
  creates no startup, GenesisQC, or activation authority; source readers,
  target-manifest/JMT replay, dual authority and cross-peer rehearsal remain
  open.
- `PocoGenesisV1::new_from_unverified_export_v1` is deliberately named as a
  shape/commitment assembly helper. It computes the typed export commitment
  and rechecks copied fields, but does not verify source finality, export-root
  preimages, mapping data, or the recomputed target root; no activation path
  may treat it as a verified import proof. The eventual activation API must
  consume an independently verified export plus a quorum/cross-peer
  GenesisQC ceremony.
- Include source AppHash only as `legacy_app_hash_attestation`; bind export,
  mapping/profile, new root, source namespace and complete migration-instance
  digest into the ceremony descriptor commitment. A signed/quorum ceremony is
  still required before activation. Never import Comet WAL/blockstore/validator
  signing state.
- This is still a typed commitment/decoder plus verifier-interface slice, not
  an export reader, concrete finality/mapping verifier, import implementation,
  quorum-signed GenesisQC v1, or cross-peer activation.
  `MIG-ROOT-001` remains open until source/target manifests are independently
  verified and two clean export/import rehearsals reproduce the descriptor and
  native root.

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
3. Candidate source-of-truth closure is now clean and the decoder registry is
   generated/gated on this branch. Independent CI reproduction, workspace/old
   dual-track wording and complete boundary metadata review remain open; all
   metadata must still be generated/validated from one schema.

### P1 — deterministic safety/core blockers

1. The Core transition boundary now rejects detached Vote/Timeout transitions
   and installs only a fully checked successor, but the surrounding Core and
   SafetyRules remain prototypes/shadow evaluators rather than an authoritative
   production signer owner.
2. Pacemaker, complete epoch transition, checkpoint-scale catch-up, ordered
   ancestor finalization and permanent terminal execution log are incomplete.
3. Full proposal body/parent/runtime validation and cross-crash replay are not
   closed; current bounded facts cannot reconstruct every post-crash input.
4. The additive migration ceremony now separates legacy evidence types and
   rechecks a caller-supplied trusted validator set, but the GenesisQC wire/hash
   itself still does not carry a quorum-signed cross-peer application-root
   commitment. Source finality/export and target-genesis manifest digests are
   opaque until typed verifiers exist; migration provenance and imported root
   must be committed into a versioned GenesisQC/ceremony before G1/C0.

### P2 — real-node blockers

1. `trnm-poco-node` default startup intentionally fails; effect driver, Vote
   signing, application adapter and process integration are absent.
2. The canonical tx-builder candidate now reaches the typed mempool admission
   boundary, and a feature-gated candidate node-owned SQLite pending-nonce WAL
   (`tx-admission-wal`, through `d97ec3ee8`) covers
   durable `Reserved`/`HandedOff`/`Committed`/`Released` lifecycle tests, a
   typed builder-to-boundary API, and a
   bounded retained-row admission cap. It is not a
   production path: the default node does not compile or activate it. The
   candidate has a signature-checked CheckTx seam, node-owned signer/context
   resolver seams (with mismatch/no-resolver and caller-context compatibility
   tests), typed commit-receipt gate, owner-affined lifecycle tokens, and a
   real native preview/execute/commit negative fixture (`d73d74bbf`) that keeps
   bogus-proof rows `HandedOff` across reopen; production resolver/context
   ownership, signing/broadcast, valid-proof Core/SafetyRules/AppHash readback
   integration, automatic/ambiguous-handoff resolution, and tombstone GC remain
   open. The explicit exact-metadata/verified-receipt recovery seam is
   candidate-only; ordinary startup stays fail-closed. CLI transfer/receipt
   paths remain development-only shell/template adapters.
3. No authenticated production P2P/pacemaker, remote signer/HSM/watermark,
   durable mempool replay, state sync or native RPC/indexer path.
4. No real 4/7-node cross-host crash, partition, equivocation, reorder, disk,
   clock-skew or long-soak evidence; current G3 ledger remains false.
5. K/P dual-store audit now takes a descriptor-bound shared lock for the final
   paired inventory, rechecks root identity, and fails closed on observed
   digest/head drift. Selected native P/K writer windows take an exclusive
   lock, with mutual-exclusion and rename/recreate tests. H1 takeover now
   requires a derived common root, and process2 activation locks before its
   first paired read and validates identity at successful commit boundaries.
   This is still an advisory cooperating-owner fence: every mutation path must
   adopt the exclusive hook before the cross-database atomicity blocker can
   close. `7e04803cf` additionally pins concrete child-file descriptors in the
   selected paired windows; fsync/power-loss, WAL/SHM and all-writer coverage
   remain MIG-004 work. The candidate admission WAL's separate sidecar
   identity hardening does not substitute for this K/P proof.

### Immediate execution queue (next dependency-ordered slices)

1. **P0-PROTOCOL / P0-TC:** freeze the complete normative vectors and
   independent replay, then close the remaining weighted TC, epoch, envelope,
   upgrade and light-client bounds. No network signing is enabled before this
   gate.
2. **P1-CORE:** make Core/SafetyRules the sole authoritative Vote/Timeout
   owner; persist-before-sign, pacemaker, epoch handoff, ordered finalization,
   and 100,000-block exact replay are the acceptance line.
3. **P2-NODE + P2-TX:** wire the candidate WAL to real node ingress and an
   external/remote signer, add CheckTx-equivalent admission, commit-uncertain
   recovery and receipt/AppHash readback, then prove clean restart replay.
4. **P2-NET / P2-STORE:** add authenticated encrypted P2P, effect driver,
   state sync, remote signer/HSM watermark, and complete the shared K/P lock
   adoption matrix with fd-bound identity where needed. The current lock
   helper and selected native writer hooks are evidence, not a closed gate.
5. **MIG-ROOT / G3:** implement source export/finality and target-root
   verifiers, cross-peer GenesisQC/quorum ceremony, then run two clean
   export/import rehearsals before any C0 decision.
6. **G3/G4:** run 4 -> 7 cross-host crash/partition/equivocation/WAN campaigns,
   upgrade/rollback drills, independent replay/light client, and 7--30 day
   soak. Only after these gates may C1 remove Comet residue.

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
