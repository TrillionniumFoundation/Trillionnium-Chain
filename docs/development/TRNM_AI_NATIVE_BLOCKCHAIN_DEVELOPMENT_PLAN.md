# TRNM AI-native Blockchain Development Plan (Canonical)

Plan ID: `trnm-ai-native-blockchain-development-plan-v1`
Effective date: **2026-08-26 (Asia/Shanghai)**
Execution revision: **2026-08-27 (Asia/Shanghai)**
Status: **one active engineering plan; implementation and production claims remain gated**
Canonical branch: `docs/chain-poco-bft-mainline-20260825`
Canonical worktree: `/home/alex/projects/worktrees/trillionnium-chain/poco-mainline-20260825`
Machine truth: [`../../config/consensus-mainline.json`](../../config/consensus-mainline.json)
Audit companion: [`../audits/TRNM_CHAIN_ALL_VERSIONS_AUDIT_2026-08-26.md`](../audits/TRNM_CHAIN_ALL_VERSIONS_AUDIT_2026-08-26.md)

This is the **only live development plan** for Trillionnium Chain. Protocol
specifications, architecture decisions, release-readiness truth, runbooks,
formal models, and evidence records remain separate authorities; none of them
is a second roadmap. A date, percentage, passing unit test, candidate crate,
or benchmark target cannot promote a machine flag.

### 0.0 Plan authority, manifest, and clean-clone contract

The pathname is not authority by itself. This plan becomes a reproducible
engineering authority only through the following immutable tuple:

```text
(plan_id, canonical_ref, assessed_commit, assessed_tree,
 plan_sha256, plan_manifest_sha256)
```

The tuple MUST be recorded in a versioned `plan-manifest-v1` companion (the
planned canonical path is `docs/development/plan-manifest-v1.toml`) and the
manifest MUST bind the exact plan bytes, canonical branch/ref, assessed source
commit and tree, audit date, machine-truth file digest, protocol-manifest
digest, toolchain/container digest, and the deterministic clean-clone replay
command. The manifest is a pointer and integrity record; it cannot override
`config/consensus-mainline.json` or any protocol contract.

Before any gate can be promoted, the plan and its manifest MUST be tracked by
Git (`git ls-files --error-unmatch` succeeds), present at the manifest's
assessed commit in a clean clone, and byte/hash identical in the worktree,
index, clean clone, and release source archive. CI MUST reject an untracked
plan, a hash/tree/ref mismatch, a missing required-file reference, a dirty
plan/manifest/status path, or a plan that exists only in another worktree.
An assessed source worktree may retain explicitly enumerated dirty files for
review, but those files and their effects are not part of a promoted release
artifact until committed and independently replayed. A working-tree SHA is
therefore provisional and never a release claim.

The canonical-plan gate also verifies that `assessed_commit` is a full Git
object present in the clone, that its tree equals `assessed_tree`, that it is an
ancestor of the checked-out ref, and that the machine-truth JSON, v1 protocol
manifest, evidence contract, and locked Cargo input each match the four
manifest-bound SHA-256 values. A plan hash by itself is not sufficient when
one of those inputs has drifted.

Any normative plan change MUST update the plan ID/version, manifest hashes,
review record, and dependent machine-truth references in one atomic commit.
No mutable symlink, copied branch plan, timestamp, or generated summary may
create a second execution entry point. A clean clone at the manifest commit is
the only starting point for a gate run; a local plan copy is an audit input.

## 0. Canonical truth, product thesis, and version boundary

### 0.1 Current truth snapshot (2026-08-27)

- The sole future production consensus route is native PoCO-BFT. CometBFT is
  migration residue and historical differential input only; it cannot receive
  new features or provide release authority.
- The audit baseline is `b1c71e189bf6f31ba278f1f0806a13196107b354`. The
  five-file finalization-permit predecessor binding was reviewed as one source
  graph and committed at `fcdc16104` (tree
  `c7559225bd40ad08e2f0bdf089888684355b52a0`). The former E0061 missing
  `SafetyRulesFinalityPredecessorV1` argument is fixed; focused Core,
  SafetyRules, and all-features node tests pass. This closes a source defect,
  not the G1 exit.
- The cumulative candidate source head immediately preceding this revision is
  `236a7b50b546caafe9228f056f1697493d14d600` (tree
  `0070fde2b67394f3a122345dd664367b3c0557d5`). It retains the real-process G1
  fixture, native receipt binding, WAL restart/schema checks, semantic-wire
  mutation evidence and strict nested candidate signatures from
  `dff1ac5b6`, then adds the following separately tested source tranches:
  `d73ac583e` separates Core's one-shot Safety replay fence from simulator-local
  QC/TC fetch recovery; `a73b606e8` fsyncs genesis and H1 TrustedBase durable
  transitions and requires idempotent retries to re-establish the same fence;
  `41ccdd8e7` adds an opt-in private P2P handshake replay journal/head with
  restart, tamper, retained-sidecar rollback, path/lock and fixed-ID negatives;
  and `8c23c0374` repairs the real pre-genesis SIGKILL rollback case by accepting
  only a schema-valid, completely virgin metadata/P/H1 inventory, then proves
  initialize and H1 TrustedBase source/target convergence at three independent
  child-process kill cuts each. Any partial inventory still fails closed.
  `09f0a1955` makes the candidate-only replay-anchor guard const-safe under the
  current `-D warnings` toolchain; it changes no runtime behavior or activation
  flag. `e2016c8e9` makes the offline legacy exporter use the shared strict JSON
  decoder and reject a zero finalized source height, with duplicate/trailing/
  unknown-field and zero-height negatives; it does not add a source reader,
  cutover, or node-start capability. `a69618f7a` additionally requires the
  source validator set and QC signer list to be strictly ordered by validator
  ID, with unsorted and duplicate negatives; this removes witness-order
  ambiguity but remains an offline candidate check. `236a7b50b` rejects an
  exact-schema application file with a missing metadata singleton unless both
  durable P and H1 inventories are empty, on both reopen and live initialize;
  this closes the residual-inventory-as-virgin ambiguity while leaving the
  indistinguishable all-empty rollback case to external anti-rollback.
  These surfaces remain candidate-only and do not supply a production effect
  driver, socket/peer lease, external monotonic anti-rollback, whole-node CAS,
  Node/Core/Safety authority, or production activation.
- `stage = G1-native-host-incomplete`, `production_candidate = false`,
  `production_consensus_activation = false`, and Comet cleanup eligibility is
  false. There is no completed validator run and no native PoCO listener
  evidence.
- The currently exposed `zero_comet_production_dependency_achieved = true`
  bit is **only** an active-Cargo/build-closure bit. For unambiguous plan
  language it is called `zero_comet_active_dependency` below. It does not
  assert repository-residue removal, finalized-state migration,
  `comet_replacement_complete`, production candidacy, or activation; those
  are independent bits and all remain false or open at this snapshot.
- `docs/protocol/poco-ai-native-v1/status.toml` remains
  `specification_status = "draft"`, `design_only = true`,
  `implementation_status = "not-implemented"`, `node_support = false`, and
  `release_ready = false`. Every v1 plane is design-only or a bounded,
  non-authoritative candidate.
- The physical root checkout on `feature/chain-paper-raid-receipt-v2` is a
  diverged integration checkout, not this plan's canonical development ref.
  Other worktrees and branches are inputs to the audit, never parallel
  authorities.

### 0.2 Product thesis: an agent economy with verifiable work

TRNM is not trying to put model weights, prompts, GPU kernels, or nondeterministic
inference inside consensus. It is a chain for **agents, tasks, capabilities,
data commitments, compute receipts, verification challenges, and settlement**:

```text
Agent identity/capability
  -> Task market/lease/escrow
  -> committed input + certified availability
  -> deterministic execution envelope or explicit verifier profile
  -> result/challenge finality
  -> consumption receipt, fee, reward, slash, and settlement
```

The chain orders and settles commitments and proofs. Large models, private
inputs, long outputs, external tools, and GPU execution remain off-chain and
are admitted only through a declared verification profile. Order finality and
AI-result/settlement finality are separate state machines; a challenge moves
state forward and never rewrites a finalized block.

### 0.3 Version and authority matrix

| Version surface | Truth | Role in this plan |
| --- | --- | --- |
| Legacy mock/Comet runtime | Historical/development oracle | Differential tests and one-way finalized export only |
| Public-testnet/Comet generation (`e73d1a930` lineage) | Superseded | No new protocol work; never cite as native evidence |
| PoCO-BFT v0 | Frozen safety baseline, incomplete host | Close protocol, Core/Safety, node, migration, and network gates first |
| Current PoCO mainline (`236a7b50b`) | Canonical execution ref; bounded source tranches committed and locally replayed | Only branch that can receive the next ordered slices after review |
| PoCO AI-native v1 design | Draft/candidate, non-normative | Freeze schemas and implement planes only after v0 authority exists |
| v1 activated network | Not implemented | Requires every gate below plus an explicit versioned activation proof |

### 0.4 Non-negotiable anti-pollution rules

1. One live plan path: this file. Old delivery boards are audit-only and have
   no active navigation links.
2. Machine status leads prose. `production_candidate`, activation, migration,
   validator-run, and performance flags stay false until exact evidence exists.
3. Chain and Trillionnium World/game lanes remain physically and conceptually
   separate. Nakama/gameplay/Bevy code is not Chain evidence.
4. Safety and recoverability precede throughput, DA, ZK/TEE, tokenomics, and
   marketing. A benchmark never overrides a failed invariant.
5. v0 and v1 have separate codecs, domains, schemas, roots, vectors, and
   upgrade verification. No silent reinterpretation or fallback.
6. Only committed goodput, finality tails, proof/DA latency, recovery, and
   per-resource cost count as performance evidence; ingress TPS does not.
7. A gate may cite only an accepted, content-addressed evidence bundle whose
   plan/manifest/source/tree/toolchain digests match the assessed tuple. A
   candidate, fixture, simulator, or crate-local result cannot satisfy a
   node-process, multi-node, public-testnet, or production obligation.
8. A failed invariant, changed authority input, manifest/hash drift, expired
   evidence, or unreviewed source change reopens the affected gate and
   invalidates every dependent promotion transitively. Historical evidence is
   retained, labelled, and never silently upgraded.
9. `zero_comet_active_dependency`, `comet_replacement_complete`,
   `production_candidate`, and `production_consensus_activation` are separate
   predicates. A true dependency-closure bit can never satisfy a migration,
   safety, release, or activation exit.

### 0.5 Architecture planes and intended differentiation

| Plane | Canonical responsibility | First-line capability it must combine |
| --- | --- | --- |
| PoCO-Agent | Agent IDs, controller/session keys, attenuated capabilities, revocation, budgets, nonce lanes | Account abstraction plus least-privilege autonomous agents |
| PoCO-Market/Task | Task, bid, lease, escrow, checkpoint, cancel/timeout/refund, SLA | A verifiable compute market rather than a generic transfer ledger |
| PoCO-DA | Separate transaction-batch and AI-artifact namespaces, commitments, retrieval, repair, withholding, and a versioned sampling profile | Celestia-like availability with task-level provenance and settlement; the initial v1 baseline is full replication |
| PoCO-Order | Weighted PoCO-BFT v0, QC/TC/three-chain finality, epoch handoff, persist-before-sign | HotStuff-derived safety with explicit agent/task commitments |
| PoCO-Execution | Deterministic runtime, object/MVCC serial equivalence, four-dimensional resource meter | Sui/Aptos/Monad-style parallelism with replayable receipts |
| PoCO-Compute/Verify | Replay, TEE, zk/optimistic profiles with strength labels and challenges | Verifiable AI outputs without pretending hashes are proofs |
| PoCO-Settlement | Consumption receipts, fee deltas, escrow conservation, rewards/slashing, rollups | Native payment for profile-admitted, challenged, auditable work; usefulness is only asserted when a declared profile/governance rule defines it |
| Proof/API/Interop | State roots, independent light client, JSON-RPC/WS, SDKs, migration and bridge proofs | Ethereum-grade verifiability and composability |

### 0.6 Comparator matrix (targets, not achievements)

| Reference | What it demonstrates | TRNM must add or beat on a declared workload |
| --- | --- | --- |
| Ethereum | Settlement depth, decentralized verification, mature light-client/tooling model | Agent/task/receipt semantics and verified-compute settlement without weakening proof or custody |
| Solana | High-throughput pipelining and low-latency committed execution | Same-hardware committed (not submitted) goodput plus deterministic AI receipt/challenge paths |
| Sui / Aptos | Object/state parallelism and serial-equivalent execution | Agent capability/lease/escrow objects, cross-plane proof roots, and conflict-aware fee accounting |
| Celestia | Dedicated DA and sampling economics | Artifact DA tied to verifier profiles, withholding challenges, repair, retention, and settlement |
| Monad and similar parallel L1s | Parallel EVM execution and high-throughput consensus engineering | Native task/compute receipts and replayable verification, measured under identical workloads |
| Bittensor / Gensyn / compute networks | AI-worker incentives or compute verification research | One canonical chain for identity, DA, order, result challenge, and conserved settlement |

No row is a claim of superiority. Public “surpasses” language is permitted
only when the same workload, hardware, RTT, transaction bytes, failure model,
and committed-vs-submitted definition are published and independently
reproduced.

The DA comparison is versioned. The current v1 release baseline is
`DA-FULLREP-V1` (full replication, authenticated retrieval, withholding
negatives and repair); `erasure_coding_active=false` and
`data_availability_sampling_active=false` remain honest machine truth. A
Celestia-like sampling claim belongs only to a separately specified and
activated `DA-DAS-V1` profile with committee/randomness, sampling soundness,
withholding proof, repair economics, retention and a new evidence epoch.

### 0.7 Quantified release and “surpass” envelope

These are exit criteria to measure, not present results:

| Domain | Release floor | Surpass bar |
| --- | --- | --- |
| Safety/finality | 10,000 adversarial campaigns, zero conflicting finality; 7-node LAN p95/p99 <= 1s/2s | 30-day / 10^7-vote campaign, 20 operators, WAN p95/p99 <= 3s/6s at <=150 ms RTT |
| Committed goodput | 7-node W0 512-byte >=5k tx/s and W1 2-KiB stateful >=1k tx/s for 30 min | 20-node W0 >=50k, W1 >=10k, plus >=1k AI envelopes/s, all committed and replay-verified |
| Parallel execution | 100% serial-equivalent roots; deterministic replay | >=4x at 8 workers on independent state and >=2x at 50% conflicts without root/finality drift |
| DA | `DA-FULLREP-V1`: three-provider retrieval >=99.9% with bounded withholding negatives; no sampling claim | `DA-DAS-V1` only after separate activation: >=99.99% artifact retrieval under one-third withholding, >=99.9% sample detection, repair <=5 min |
| State sync/light client | 1M-block fresh sync <=15 min with root match | 64-epoch/10k-header jump, two independent clients, proof p95 <=50 ms |
| Custody/operations | No raw key in node; 100k crash/restart attempts, zero double-sign | HSM/KMS rotation/revocation <=15 min, zero equivocation over 30-day campaign |
| AI lifecycle | Complete schemas/vectors and one end-to-end task path | Three independent clients/verifiers, tamper/challenge detection >=99.9%, artifact p99 <=5s |
| API/release | Versioned RPC/WS, indexer replay, reproducible artifacts | Read p95 <=100 ms, 99.99% availability, two independent builders, signed SBOM/provenance |

The public superiority rule is conjunctive: meet every release floor, show a
>=1.2x advantage on one declared workload, be no weaker on safety/availability
/custody/proof than the comparator, and reproduce the result with two
independent teams. Until then, use “PoCO design/candidate” wording.

### 0.8 Promotion ledger

Every gate promotion must include the source commit, protocol manifest,
toolchain, binary/SBOM hashes, topology, workload, fault schedule, raw traces,
formal/vector output, known gaps, and the exact machine flags changed. A failed
invariant reopens the gate and retains a negative mutant. Calendar dates and
completion percentages never promote a gate.

### 0.8.1 Evidence envelope, acceptance, and reopen rules

Every claim that appears in a gate exit, machine manifest, release note, or
benchmark comparison MUST be carried by a signed `TrnmGateEvidenceV1` envelope
or an explicitly referenced protocol evidence type. The minimum envelope is:

| Field | Required binding |
| --- | --- |
| `gate_id`, `package_id`, `evidence_id`, `status` | Stable ID; status is one of `candidate-non-normative`, `reproducible`, `reviewed`, `accepted`, `superseded`, `invalidated`, or `reopened`; free-text PASS is not a status |
| `plan_id`, `plan_sha256`, `plan_manifest_sha256` | Exact canonical plan tuple; no timestamp-only association |
| `source_commit`, `source_tree`, `worktree_ref`, `machine_truth_sha256` | Assessed code and machine state; dirty paths are enumerated or the bundle is invalid |
| `protocol_manifest_sha256`, `schema/vector/formal_revision` | Exact protocol inputs, codec/domain registry, vectors, model and mutant revisions |
| `scope`, `authority`, `data_scope` | `scope` is one of `crate`, `fixture`, `process`, `host`, `network`, or `production`; `authority` is one of `candidate`, `simulation`, `normative`, or `production`; `data_scope` identifies synthetic/replay/private-alpha/public-testnet/mainnet data; no inferred scope |
| `toolchain`, `container`, `binary`, `SBOM` digests | Rebuild and provenance closure, including compiler and relevant host/kernel assumptions |
| `command`, `replay_command`, `topology`, `workload`, `fault_schedule`, `seed` | Deterministic reproduction inputs; measured runs include warm-up, sample count, percentile denominator, and raw-trace location/root |
| `assertions`, `positive_count`, `negative_count`, `invariants`, `mutants` | Machine-checkable results, retained failing mutants, severity and expected error codes |
| `reviewers`, `signatures`, `created_at`, `expires_at` | Independent review and evidence freshness; signer identity is bound to the assessed tree |

An evidence bundle is **accepted** only after the producer replay and an
independent replay agree on bytes, roots, error classes, counts, and machine
flags. `candidate-non-normative` is useful engineering evidence but can never
be substituted for `accepted` production authority. A gate exit names each
required evidence ID, its scope, and its reviewer; an aggregate dashboard or
latest file does not close a missing item.

The following events reopen a gate: source/protocol/schema/parameter or
validator-set change; plan or manifest hash drift; toolchain/container or
binary/SBOM change; a failed invariant, new critical/high finding, or mutant
that no longer fails; crash/replay/root mismatch; changed topology, fault
model, workload grammar, or measurement denominator; evidence expiry or
revocation; or a machine flag changed without a matching accepted envelope.
On reopen, the old envelope remains immutable and is marked `superseded` or
`invalidated` with a reason. The gate returns to `open`, all dependent gates
are reopened transitively, and the plan records the minimum rerun set and any
rollback/light-client/migration boundary affected. No prior signature, result,
or flag is silently reused after a reopen.

### 0.9 Migration work-package anchors

The old execution board's dependency IDs are retained as stable identifiers in
this single plan so CI and evidence bundles do not lose lineage:

- `MIG-000` — truth/branch/manifest freeze;
- `MIG-001` — normative protocol, schema, bounds, and independent-reproduction
  closure;
- `MIG-002` through `MIG-005` — authoritative Core/SafetyRules, node effect
  driver, K/P storage authority, execution/JMT, and crash replay;
- `UP-V0-V1` — frozen v0 to v1 upgrade, dual-quorum handoff, first v1 block,
  and independent light-client proof; this is the G1.5/G2 path and never
  imports Comet state;
- `MIG-COMET-POCO` (`MIG-006/007`) — finalized legacy export, independently
  recomputed target root, and fresh PoCO genesis/GenesisQC rehearsal; this is
  the C0/G5 migration path and never mutates a v0/v1 database in place;
- `MIG-008/009` — authenticated P2P, signer custody, state sync, and validator
  ladder;
- `MIG-010/013` — public surfaces, upgrade, governance, and cutover rehearsal;
- `MIG-014/016` — signed C0 completion followed by the C1 Comet tombstone and
  removal gate. These IDs never authorize cleanup before C0 evidence.

### 0.9.1 Two migration paths (never interchangeable)

The word “migration” is reserved for the two explicit, independently
verifiable paths below. A local fixture, a copied database, or an AppHash
comparison is not a migration proof.

| Path | Source → target | Trigger and authority | Required proof/evidence | Gate order and hard prohibitions |
| --- | --- | --- | --- | --- |
| `UP-V0-V1` | Frozen PoCO-BFT v0 finalized checkpoint at `H_v0` → versioned v1 first block at `H_v1` | Explicit upgrade/governance decision in the frozen v0 domain; old and new validator sets each prove their own quorum; one height/configuration and no-downgrade rule | Exact CEV0/CEV1 codecs and domains, source finality/checkpoint, validator-set and parameter hashes, dual-quorum handoff, deterministic target JMT/root recomputation, first-v1 proposal/QC, independent light-client replay, old-byte rejection | Specification lane may prepare during late G1, but activation is `G1 → G1.5 → G2`; no v1 BatchRef/Agent bytes in v0, no v0 byte reinterpretation, no implicit fallback or rollback to v0 after target finality |
| `MIG-COMET-POCO` | Finalized legacy Comet export at `H_comet` → fresh PoCO genesis/data directory and GenesisQC | C0/C1 cutover ceremony after independently verified source finality, mapping, target manifest, and target-validator GenesisQC; migration operator is not a consensus authority | Typed source export and provenance, source identity/finality/quorum, mapping/profile digest, independently recomputed JMT root, fresh-genesis descriptor, cross-peer GenesisQC, old WAL/SHM/key/data-directory rejection, signed rehearsal and rollback boundary | Runs only at C0/G5; never in-place DB/WAL conversion, never imports old Safety/watermarks/keys, never treats legacy AppHash as PoCO root, never uses `UP-V0-V1` evidence as source finality |

`UP-V0-V1` is a protocol-version transition inside the PoCO lineage. It is
not a substitute for `MIG-COMET-POCO`, and `MIG-COMET-POCO` is not a shortcut
around v0 safety or v1 specification gates. Each path has a separate source,
target, trigger height, verifier, evidence namespace, and rollback/light-client
boundary. If both are needed for an eventual deployment, complete and sign
`MIG-COMET-POCO` first to create the fresh PoCO genesis, then run
`UP-V0-V1` at its explicitly governed height; never combine their roots or
quorum signatures in one untyped record.

### 0.10 Authoritative inputs

- [`TRNM_POCO_BFT_MAINLINE_CUTOVER_2026-08-25.md`](../architecture/TRNM_POCO_BFT_MAINLINE_CUTOVER_2026-08-25.md)
- [`TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md`](../architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md)
- [`TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`](../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md)
- [`TRNM_POCO_AI_NATIVE_V1_PRODUCTION_CONTRACTS.md`](../architecture/TRNM_POCO_AI_NATIVE_V1_PRODUCTION_CONTRACTS.md)
- [`poco-bft-v0` implementation gap register](../protocol/poco-bft-v0/IMPLEMENTATION_GAP_REGISTER.md)
- [`poco-ai-native-v1` status and manifest](../protocol/poco-ai-native-v1/status.toml)
- [`all-version audit`](../audits/TRNM_CHAIN_ALL_VERSIONS_AUDIT_2026-08-26.md)
- [`plan-manifest-v1`](plan-manifest-v1.toml)
- [`engineering evidence contract`](TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)

## 1. Delivery rules

1. Machine truth leads narrative truth. A target stays false until its code,
   dependency graph, release closure, tests, and external evidence pass.
2. Safety precedes throughput. Persist-before-sign, lock recovery, whole-node
   monotonic checkpointing, durable-before-attest, and exact finalization apply
   cannot be weakened to improve a benchmark.
3. V0 and v1 have separate parsers, types, domains, state schemas, and
   conformance vectors. Cross-version behavior exists only in the upgrade
   verifier.
4. Order, DA, execution, AI verification, and settlement have separate metrics
   and fault domains. A slow or unavailable layer cannot fabricate a positive
   result in another layer.
5. Only committed goodput, p50/p95/p99 finality, recovery time, availability,
   correctness, and per-resource cost are reported. Ingress TPS is not a
   performance claim.
6. An Order safety-kernel change is evidence-driven. Protocol novelty alone is
   not a requirement.

## 2. Gate board

| Gate | Objective | Initial truth | Promotion prerequisite | Exit authority |
| --- | --- | --- | --- | --- |
| G0 | Clean, reproducible, zero-Comet native boundary | Active Cargo dependency subgate has evidence; clean-clone, release/SBOM, and legacy-data rejection closure remain open | None; plan/manifest authority must be reproducible first | Dependency/release/SBOM truth and clean-clone reproduction |
| G1 | Minimal frozen-v0 non-empty vertical safety path | Bounded application/storage candidates exist; authoritative Node/Core/Safety/CAS wiring is absent and G1 remains open | Accepted G0 exit; no v1 authority | Crash-safe execution -> Vote -> finality -> apply evidence |
| G1.5 | Freeze v1 specification; measure only a minimal 4/7-node v0 baseline | Design-only v1 specification plus bounded non-normative foundation/order candidate tranches; normative freeze is false | Accepted G1 exit for promotion; specification work may be prepared during late G1, but measurement and acceptance cannot bypass G1 | Normative schemas/vectors/formal review plus reproducible baseline |
| G2.0 | Canonical vertical traceability and wire/transaction conformance | Design-only object catalog; global operation-kind codecs and transport are incomplete | Accepted G1.5 exit; candidate kernels may be prepared but cannot bypass this conformance subgate | 30 operation rows, two independent parsers, negative/fuzz corpus, and signed replay |
| G2 | Integrate v1 candidate planes after v0 authority | Bounded local DA, Agent/Market, Verify/Challenge and object-MVCC/fee probes only; node support and activation are false | Accepted G1, G1.5 **and G2.0** exits; no plane may promote from a local candidate alone | End-to-end private alpha contracts and fault evidence |
| G3 | Profile 7/31/100 validators under WAN/fault workloads | Not started | Accepted G2 exit and signed benchmark manifest | Reproducible bottleneck report and Order decision record |
| G4 | Adversarial campaigns and public-testnet readiness | Not started | Accepted G3 exit and all release floors | Soak, audits, independent clients, operations and public-testnet sign-off |
| G5 | Economic/security/governance closure and signed mainnet activation | Not started | Accepted **G0, G1, G1.5, G2.0, G2, G3, and G4** exits plus signed C0 replacement evidence; C1 follows activation | Signed release manifest, genesis ceremony, activation decision, and rollback authority |

Parallel prototypes are allowed, but a later gate cannot inherit completion
from an earlier incomplete gate. No calendar estimate overrides an exit gate.

The dependency chain is strict even when implementation work is parallel:
`G0 -> G1 -> G1.5 -> G2.0 -> G2A -> G2B -> G2D -> G2C -> G2E -> G2F -> G3 -> G4 -> G5`. A specification draft may be
authored before G1 closes, and a measurement harness may be built in advance,
but neither may be labelled frozen, reproducible baseline, or accepted until
its stated prerequisite is accepted. A reopened gate transitively reopens all
downstream gates and invalidates their promotion evidence.

## 3. G0 — zero-Comet clean native baseline

### Scope

- Keep the assessed source tranche reviewable and reproducible; include
  every source file referenced by the build and eliminate staged/worktree
  ambiguity.
- Extract TRNM-owned application request/result, execution receipt, validator
  transition, snapshot, state proof, commit, recovery, and event types into a
  native boundary.
- Move reusable runtime, JMT/ICS23, storage, overlay, and PoCO state-machine
  logic behind that boundary.
- Remove the production node's normal dependency path through
  `trnm-consensus-app` and every unconditional Tendermint/ABCI dependency.
- Isolate any one-way legacy export tool outside the active build and release
  closure; it may emit a reviewed migration manifest but cannot import legacy
  WAL, lock state, finality, signer state, or local watermarks.
- Freeze the TRNM chain descriptor, genesis, network magic, node identity,
  validator keys, native data-directory marker, wire negotiation, release name,
  and rejection behavior for old Comet data directories.
- Generate a single machine-readable status/schema manifest from source and
  make CI compare it with Cargo metadata, dependency graphs, binaries,
  containers, SBOMs, runbooks, and documentation.
- Provide a clean offline build and test entry that any reviewer can reproduce
  without a private workspace or mutable external service.

### Scope-to-exit traceability

Every row is a named closure item in the G0 evidence index. A row is closed
only by an accepted evidence envelope with canonical `scope` and `authority`
values; prose describing a partial slice leaves the row open.

| ID | Scope obligation | Required evidence | Exit assertion |
| --- | --- | --- | --- |
| `G0-S01` | Dirty/source and branch boundary | Committed source/tree manifest, explicit dirty-path list, clean-clone replay | The assessed plan, manifest, source, and release paths are unambiguous; no staged/worktree ambiguity is hidden |
| `G0-S02` | Native TRNM application/request/result boundary | Native type/schema registry, dependency graph, two-way decode/encode and legacy-token negatives | Production-facing values have TRNM-owned types and no legacy adapter authority |
| `G0-S03` | Runtime/JMT/storage/overlay isolation | Cargo graph, symbol/type scan, storage namespace manifest, root/replay vectors | Reusable runtime/state logic is behind the native boundary without importing legacy ownership |
| `G0-S04` | Zero active Comet dependency | Default/all-features Cargo trees, lockfile, binary and SBOM scans, reproducible command | `zero_comet_active_dependency` may be true only for the audited active build graph; this row does not close migration or cutover |
| `G0-S05` | One-way legacy export boundary | Export schema, source-type separation, old-WAL/key/data-dir rejection vectors, no active-build edge | Legacy input is historical migration evidence only and cannot create native finality or signer state |
| `G0-S06` | Chain/genesis/network/data-directory freeze | Descriptor/genesis/network-magic/identity manifest and a startup rejection contract/vector | Native identity and wire negotiation are exact; the default-node rejection/recovery behavior is a G1 obligation, not silently counted here |
| `G0-S07` | Machine-readable truth closure | Generated status/schema manifest diffed against Cargo, binaries, containers, SBOM, runbooks, and docs | Every claimed flag has one source and no contradictory duplicate |
| `G0-S08` | Offline reproducibility and release provenance | Clean-clone command, pinned toolchain/container, raw logs, binary/SBOM hashes and independent replay | A reviewer can rebuild identical native artifacts without private or mutable services |

### Exit gate

G0 is complete only when a clean clone builds the same native artifacts and:

- every `G0-S01` through `G0-S08` row is accepted and indexed; a closed
  active-Cargo subgate alone is insufficient;
- no production node/application/signer/sync/light-client normal or build
  dependency contains CometBFT, Tendermint, ABCI, ABCI++, or the legacy adapter;
- public native APIs, wire, storage, genesis, release, SBOM, and operator paths
  contain no ABCI-owned type or compatibility mode;
- the only production node family is TRNM native and its startup contract
  deterministically rejects legacy data; the real default-node rejection and
  recovery execution is separately closed by `G1-S05`/`G1-S06`;
- CI truth passes from worktree, staged index, clean clone, and pushed commit;
- `zero_comet_active_dependency` is explicitly scoped to active Cargo/build
  closure, while `comet_replacement_complete`, `production_candidate`, and
  `production_consensus_activation` remain independent and false; and
- readiness and production-activation flags remain false.

### Current bounded evidence tranche (candidate; not G0/G1 completion)

The first active-Cargo G0 slice adds `trnm-native-application`, a dependency-free boundary
crate with checked native types for genesis, block execution/result, receipts,
events, commit, validator transition, proof, snapshot, and recovery. Its CI
gate proves the crate has no normal/build dependency and no Comet/Tendermint/
ABCI or legacy App/Node token. The PoCO node's direct development dependencies
and source references to the old transport crates have also been removed; its
legacy genesis fixture is now behind the migration-residue App test helper.
The Node default and all-features closures, complete active workspace graph,
and lockfile no longer include `trnm-consensus-app`, Tendermint, or ABCI for
the audited active graph. The
historical App and legacy-node crates are explicitly outside the workspace and
the remaining adapter/config markers carry no executable authority. This
closes only the audited active-Cargo dependency subgate; it does not close G0
or create production readiness. The default Node now imports the
native contract and contains a private, non-cloneable, exact-binding,
fail-closed owner scaffold. Production can construct neither the raw owner nor
its separate finality permit; the owner has no native store/engine,
authenticated recovery, commit-uncertainty recovery, Core/effect-driver path,
or finalization reachability. Machine truth therefore separates
`default_node_boundary_owner=true` from
`node_application_engine_integration=false` and
`node_process_integration=false`. A separate native SQLite slice now owns the
bounded canonical bytes for one candidate `NativeExecutedBlockV0` as durable P
and performs digest/checksum, strict decode, exact re-encode, full proposal
binding, and fresh-connection readback. It still has no native execution
engine, Core-D/Safety-C authority, restart capability takeover, committed-head
advance, Node/process wiring, whole-node CAS, or production status. The store's
terminal K row now retains request-bound, C-shaped readback provenance -- the
validation ID and Core-delivery digest, an exact Core/Safety revision mapping,
Safety-record digest, and vote-intent digest -- under the row checksum and
fresh/reopen audit. It also rejects a self-consistent C
substitution whose Core-delivery digest differs from the durable D row. This
covers request-bound provenance inside the scaffold only; the raw adapter
response is still untrusted and does not supply the real SafetyStore adapter
or make K a Core/Safety authority. Existing clean schema-v3 stores are
immutable-read-only preflighted before any WAL pragma/writable connection and
are never implicitly recreated or migrated; any WAL/SHM/rollback-journal
sidecar is fenced because recovery authority is absent. The D value likewise no
longer has an external constructor: until a Node-private Core acceptance
carrier exists, outside code cannot forge the missing authority.

The **native PoCO workflow surface** is retired from legacy authority, but the
repository still contains legacy migration/development workflows and probes:
some have automatic or manual triggers and may mention Comet/ABCI, the old
`26657` port, or legacy harnesses. They are not release authority and their
cleanup remains open until the signed C0/C1 cutover; they must not be described
as inert or as evidence for the native node. Local legacy release,
operator-transition, Comet rehearsal, persistent-scale, and emergency-drill
entrypoints remain fail-closed or audit-only where their individual guards
prove that behavior. The active **Cargo dependency-graph subgate** is closed
for its audited slice only; clean pushed-commit evidence, native release/SBOM,
default-Node integration of the deterministic application, and legacy-data
rejection proof remain separate readiness/G1 obligations.

The default Node now additionally proves one private linear splice from a
genuine Core-issued ordinary non-empty Proposal through a Node-owned exact-
binding `NativeApplicationV0` test fixture to canonical durable P and exact
fresh/reopen readback. The fixture supplies synthetic expected roots and is not
a complete deterministic execution engine. The private carrier retains the
Core permit and P token; it cannot construct D, C, K, a Valid callback,
`RequestSignature`, signing, broadcast, or restart takeover. Advancing beyond P
requires a durable speculative-overlay manifest/write plan joined with the
issuing Core's affined application seal plus real Safety authority.

A separate bounded candidate-only G1 slice exercises a subset of the frozen-v0
ordinary-body transition and `NativeApplicationV0` owner. It exercises
runtime, validator-lifecycle, PoCO/cutoff, and mandatory system writes against
one authenticated parent snapshot; independently derives four roots; and
atomically persists candidate P, a target JMT snapshot/overlay, replay sets,
lifecycle bytes, store identity, and monotonic local sequence. Immutable
fresh/reopen validation recomputes the target root before the candidate
`Valid`, and reopen audits the candidate P chain. Two ordered transactions
exercise in-block overlay visibility; artifact, snapshot, store, sequence,
root, replay, and missing-P substitutions fail closed. This non-normative
slice is not connected to the default Node or a Core application seal and has
no real Safety-C, whole-node CAS, process takeover, `RequestSignature`,
signing, or broadcast authority; G1 remains open and no machine flag is
promoted.

## 4. G1 — minimal frozen-v0 vertical safety

### Scope

Implement the narrowest real validator path that makes the existing v0 safety
kernel operational without expanding v0 into the v1 architecture:

```text
bounded ingress
  -> complete v0 payload dissemination
  -> exact decode and deterministic execution
  -> sealed BlockId overlay and roots
  -> durable SafetyState
  -> complete canonical Vote/Timeout SignIntent
  -> signer journal and external watermark
  -> QC/TC and three-chain finality
  -> ordered application apply and durable acknowledgement
```

Required work:

- build one process host/effect driver with generation-aware pacemaker,
  bounded queues, typed backpressure, metrics, tracing, and authenticated
  ingress;
- route both Vote and Timeout through one production SafetyRules owner;
- implement the independent Safety/Application/Signer whole-node checkpoint
  and compare-and-swap recovery protocol;
- complete arbitrary non-empty regular blocks, BlockId-keyed speculative
  overlays, ordered ancestor finalization, idempotent apply, overlay pruning,
  and general recovery rather than another special empty-height carrier;
- retain v0 complete-payload-before-vote and sequential reference semantics;
  v1 BatchRef/DA certificates and v1 Agent semantics are forbidden here;
- test every persist/sign/broadcast/validation/outbox/finalize/checkpoint cut
  under SIGKILL, commit success with response loss, disk full, I/O error,
  restart, database rollback, full namespace rollback, and signer/Safety/App
  skew; and
- add authenticated state replay sufficient for this single-node vertical
  path without claiming general state sync.

### Scope-to-exit traceability

G1 evidence MUST distinguish a real node process from a fixture, simulator, or
crate-local owner. The following rows are the minimum signed closure index:

| ID | Scope obligation | Required evidence | Exit assertion |
| --- | --- | --- | --- |
| `G1-S01` | Process host/effect driver, bounded ingress and pacemaker | Built native node binary, process topology, authenticated ingress trace, queue/backpressure and generation metrics | One real process can drive the complete bounded v0 path; a unit harness cannot close this row |
| `G1-S02` | One authoritative SafetyRules owner for Vote and Timeout | Exact intent/Safety revision records, signer-journal and watermark replay, stale/mixed-cut negatives | Both signing paths share the same durable owner and fail closed before signature release |
| `G1-S03` | Whole-node Safety/Application/Signer checkpoint CAS | Crash matrix with SIGKILL, response loss, disk/I/O failure, rollback and skew; source/target readback proofs | Every durable boundary resolves only to the exact source or target; a third/mixed value reopens G1 |
| `G1-S04` | Arbitrary non-empty v0 execution/finalization | 100,000-block corpus manifest, real-node logs, independent replay, roots/receipts/apply index and ancestor order | No double-sign, duplicate apply, lost obligation, skipped ancestor, or root/receipt drift |
| `G1-S05` | Frozen v0 semantics and v1 rejection | CEV0 codec/domain vectors, complete-payload-before-vote checks, explicit v1 BatchRef/Agent rejection | v0 remains sequential and cannot silently accept v1 semantics |
| `G1-S06` | Restart/recovery/state replay for this vertical | Fresh/reopen and restart traces, authenticated state proof, recovery time and rollback-boundary record | Recovery converges to exact source/target without claiming general sync |
| `G1-S07` | Five-file Core/SafetyRules source closure | Clean committed diff for `core.rs`, `lib.rs`, `model.rs`, `tests.rs`, and SafetyRules `lib.rs`; successful compile/test log and independent review | The former `verify_v1` predecessor-argument defect is closed at `fcdc16104`; independent clean-clone replay and the full G1 exit remain open |

### Exit gate

- Every `G1-S01` through `G1-S07` row is accepted; in particular, the five
  Core/SafetyRules files are committed, compiled, reviewed, and independently
  replayed before this exit can be signed.
- At least 100,000 arbitrary non-empty deterministic v0 blocks complete with
  zero double-sign, duplicate apply, lost obligation, skipped ancestor,
  receipt/root drift, or unsafe rollback.
- Vote and Timeout exact replay are idempotent; any mixed or stale local cut
  fails before a signature or application effect escapes.
- All durable-boundary crash cases converge to the exact source or target.
- The corpus, topology, fault schedule, binary/SBOM, commands, and raw traces
  are bound in the evidence envelope; fixture-only or candidate-local counts
  cannot satisfy the 100,000-block assertion.
- The binary is still not called a production candidate, public testnet, or
  mainnet node.

## 5. G1.5 — freeze v1 and establish the minimal v0 baseline

G1.5 has two deliberately bounded lanes. The specification lane may run in
parallel with late G1 engineering. The measurement lane starts only after the
G1 vertical path is stable.
All positive counts and checks below are bounded, non-normative candidate
evidence; they do not constitute a v1 freeze, implementation, node support,
production candidate, or activation result.

### 5.1 V1 specification freeze lane

The design-only v1 lane covers only the listed CEV1 foundation and Order
candidate carriers (contexts, validator/parameter facts, ordered roots, header,
Vote/QC, Timeout/TC, and minimum activation/handoff anchors) with 27 positive,
one ordered-root derivation, and 24 negative vectors plus a standard-library
authoring checker. A separately authored standard-library-only parser now
strictly decodes, re-encodes, semantically validates, and reproduces every
listed digest; it also rejects the bounded negative corpus and checker-owned
malformed-input mutants. This is independent parser evidence only for this
listed candidate tranche. It is explicitly
non-normative and scoped only to its listed types; it provides no proposal,
DA, execution, settlement, state-sync, light-client, cryptographic interop, or
complete formal-model evidence. Three bounded Quint candidates separately
check the weighted-order kernel, timeout-lock discipline, and epoch
handoff/activation with 15 bounded invariants, three reachable legal witnesses,
and seven retained mutants that must produce counterexamples. These finite
models are not a complete proof. All global evidence and freeze flags remain
false.

A second candidate tranche now checks the bounded Order signature surface with
an independent standard-library strict-Ed25519 verifier: four deterministic
validators, one Vote statement, two distinct Timeout statement roots, four QC
signatures and four complete per-entry TC statement/signatures, checked
weighted quorum, and 18 retained negative controls. It reproduces the
validator-set digests, Vote/Timeout domain separation, and the foundation TC
context/justification projection, but does not prove complete QC/TC transition
semantics, provide a light client, or make global crypto-interoperability or
freeze claims. A third bounded candidate checks the v0-to-v1 activation kernel
with one positive and 31 negative cases, exact CEV0/CEV1 validator-set hash
reproduction, independent old/new weighted quorums, strict role-separated
Ed25519 signatures, NoFallback, and the empty first-v1 projection. It does not
verify complete v0 governance/finality authority, execute migration, implement
a light client, or complete the upgrade contract.

A fourth cumulative candidate checks one cross-version carrier ambiguity
without changing frozen v0: it exact-decodes raw CEV0 `UpgradePlanV0` field
12, requires frozen fields 13/14 absent on the v0-to-v1 route, and verifies a
separate CEV1 `V0ActivationFirst` proposal witness plus its direct three-chain
finality. Its corpus has one positive and 44 exact-error negatives; the
stdlib verifier checks one proposer and twelve QC signatures, and OpenSSL
cross-checks all 13 valid signatures plus a bad control. This does not prove
field-12 governance membership/finality, complete source-v0 authority,
deterministic migration, full `OrderProposalV1` admission, durability, or
upgrade freeze. Those remain G1.5 blockers.

A fifth bounded candidate exercises same-version Order trust across exact
0/1/2/3-hop paths. The first nonempty step is still the existing raw
FreshGenesis transition; later steps use the new versioned checkpoint-anchored
carrier, so no old anchor tag is reinterpreted. The stdlib-only checker
strict-decodes and re-encodes every path/step, consumes each prior certified
head QC, derives each intermediate trusted state, enforces strict epoch/height
progression, and verifies 88 QC plus 24 handoff signatures in the three-hop
case. It binds the global length-prefixed `DigestV1` construction and exact
one-item `V1HandoffFirst` sidecar root over the complete handoff wrapper and
both signature lists. The third hop also exercises one exact epoch-start TC at
`initial_new_view+1`, bound to the identical handoff safe parent, no lock, and
the latest finalized checkpoint. Its 63 exact-error mutants—including empty,
wrong, and different-wrapper sidecar-root controls plus 11 TC controls—and all
116 OpenSSL cross-checks pass. This
exercises only a bounded composition corpus: v0 activation, weak-subjectivity
selection, arbitrary-length trust advancement, other proof classes, complete
wire/crypto conformance, a second implementation, and normative freeze remain
G1.5 blockers.

A sixth bounded candidate derives a trusted state from the exact
FreshGenesis-to-Ordinary source proof and verifies two sequential same-epoch
Ordinary finality advances. Each advance has exactly three certified headers,
consumes the prior certified-head QC, and permits at most one skipped view
under a complete checkpoint-anchored TC. Four positive controls, 52
exact-error mutants, and 48 OpenSSL QC/TC cross-checks pass. This remains a
bounded continuation relation: payload execution, arbitrary history, epoch
transition, global light-client completion, a second implementation, and
normative freeze remain G1.5 blockers.

A seventh bounded candidate now verifies deterministic weak-subjectivity
checkpoint renewal over that exact three-hop path. The prior and renewed
anchors are derived from authenticated checkpoint objects, with exact
chain/genesis/protocol lineage, epoch, validator-set, parameters, application
root, and state-schema-root bindings. Positive epoch/block trusting windows,
strict epoch/height advancement, minimum advance, and same-height conflict
rejection are exercised by two positive controls and 45 exact-error mutants.
Operator/governance authentication, wall-clock policy, arbitrary checkpoint
selection, unbounded history, complete wire/crypto interoperability, global
light-client completion, and normative freeze remain G1.5 blockers.

Freeze, review, and publish:

- protocol scope, threat model, trust boundaries, status taxonomy, and version
  negotiation;
- one canonical binary codec, object-kind registry, exact domain registry, and
  limits; no JSON or transport bytes as signing authority;
- the complete object catalog for protocol manifests, Agent/capability/session
  authorization, nonce lanes, tasks/offers/leases/checkpoints/results,
  verification profiles and attestations, challenges/settlements, DA
  descriptors/votes/certificates/repair/withholding/retention, BatchRefs,
  blocks/QCs/TCs/finality, consumption rollups, epochs/upgrades and light-client
  proofs;
- separate transaction-batch DA and AI-artifact DA namespaces and policies;
- proof-carrying task lifecycle and dual order/result finality;
- deterministic MVCC serial semantics, explicit receipt outcome, multi-resource
  fees, fee-delta aggregation, escrow conservation, and rollup challenge rules;
- v0-to-v1 upgrade plan, deterministic migration, dual-quorum handoff, first
  v1 block, no-downgrade rule, and independent light-client verification; and
- canonical byte/hash/signature/ID/root vectors, cross-version and cross-domain
  negatives, limits, reference parsers, fuzz corpora, and implementation-
  independent conformance harnesses.

Required formal models and retained failing mutants cover at least:

- weighted QC/lock/TC/three-chain safety with v1 BatchRef bindings;
- DA persist-before-attest, retrievability, withholding, repair and retention
  GC;
- proposal AC validation and complete retrieval-before-vote;
- capability scope/revocation/budget/expiry and nonce-lane replay safety;
- deterministic MVCC serial equivalence and conflict replay;
- task/escrow conservation, dual finality and forward-only challenge effects;
- consumption-rollup uniqueness, cumulative monotonicity and one settlement;
- multi-resource fee conservation and checked arithmetic;
- atomic migration, both handoff quorums, one configuration per height, no
  downgrade, and deterministic migration root; and
- multi-hop light-client verification with a non-rolling weak-subjectivity
  anchor.

### 5.1.1 Scope-to-exit traceability

The G1.5 exit is the intersection of the specification and measurement lanes,
not the union of their best results. Each row below must point to exact
schemas, vectors, formal outputs, review signatures, or replay traces:

| ID | Scope obligation | Required evidence | Exit assertion |
| --- | --- | --- | --- |
| `G15-S01` | Protocol scope, threat model, trust boundaries and status/version negotiation | Normative contract, threat matrix, status taxonomy, version-negotiation vectors and independent review | No ambiguous status can be read as implementation, and v0/v1 bytes/domains are rejected across versions |
| `G15-S02` | Canonical codec, object/domain registry, bounds and complete catalog | Registry/manifest, exact byte/hash/signature/root vectors, two independent strict parsers, limit/overflow/trailing/duplicate negatives | Every enabled object has one canonical schema/domain and bounded parser behavior; unassigned objects remain explicitly disabled |
| `G15-S03` | Agent/task/DA/result/challenge/settlement lifecycle and dual finality | State-machine table, transition/expiry/idempotency vectors, order-vs-result finality proofs and forward-only challenge tests | A task cannot settle from an order-only or hash-only claim; every transition has a terminal outcome or explicit retry/expiry |
| `G15-S04` | Transaction-batch and AI-artifact DA namespaces/policies | Descriptor/certificate/BatchRef schemas, retention/repair/withholding vectors, provider/namespace policy and negative retrieval evidence | DA claims are scoped to the declared baseline (full replication or a separately activated sampling profile); no unsupported Celestia-like bar is implied |
| `G15-S05` | Deterministic MVCC, execution receipts and fee/escrow conservation | Serial-equivalence model, conflict/retry corpus, resource-meter and checked-arithmetic vectors, conservation proof | Parallel/candidate results cannot become global JMT or settlement authority until the canonical wire and apply path exist |
| `G15-S06` | `UP-V0-V1` upgrade and dual-quorum handoff | Source/target heights, CEV0/CEV1 roots, old/new validator quorums, first-v1 block, no-downgrade and independent light-client replay | The protocol transition is deterministic, one-way after target finality, and cannot be confused with `MIG-COMET-POCO` |
| `G15-S07` | Formal models, retained mutants and independent domain reviews | Model revision, invariant/mutant index, expected errors, consensus/encoding/app/DA/crypto/economics/light-client signatures | Zero open Critical/High specification findings; bounded model evidence is labelled bounded and never called a proof beyond its scope |
| `G15-S08` | Minimal 4/7-node v0 baseline | Signed benchmark manifest, hardware/topology/fault schedule, seeds/warm-up/run count, raw traces, replay and statistical summary | Baseline is reproducible and honestly labelled; it does not promote v1 or claim AI-native performance |

The freeze requires independent consensus, canonical-encoding, application,
DA, cryptography, economics, and light-client review. `design-only` becomes
`spec-frozen` only when all normative documents, registries, vectors, models,
mutants, and review findings agree **and the accepted G1 exit is present**.
The `UP-V0-V1` upgrade package is part of this specification closure; it must
have a source/target proof even though its activation remains a later G2
operation. It does not become `implemented`, `node_support`, or a production
candidate merely by being frozen.

### 5.2 Minimal v0 measurement lane

After the accepted G1 exit, measure only enough v0 to establish a trustworthy
external baseline. A harness prepared earlier is not a measurement result:

- four equal-weight validators and seven unequal-weight validators;
- at least three physical hosts and controlled LAN/WAN delay/loss/jitter;
- empty, 512-byte and near-limit transactions, several block sizes, and low/
  high state-conflict workloads;
- normal operation, leader loss, one-third-minus-one Byzantine/offline power,
  3–1 progress, 2–2 safe stall, heal, restart, catch-up, and shortened epoch
  handoff; and
- committed goodput, p50/p95/p99 finality, CPU, memory, disk/fsync, network,
  state growth, recovery time, and unit resource cost.

Do not productionize the v0 full-payload network, add 31/100-node campaigns, or
market the baseline as AI-native performance. Its purpose is to locate costs
and provide a reproducible control for v1.

### Exit gate

- The accepted G1 exit and every `G15-S01` through `G15-S08` traceability row
  are present in the evidence index; no row is inferred from a neighbouring
  candidate or a stale dashboard.
- V1 normative freeze and independent review **must be complete** with zero open
  Critical or High specification finding. This plan uses one severity
  vocabulary throughout: Critical, High, Medium, Low.
- The 4/7-node v0 dataset and harness are reproducible and honestly labelled,
  with real process/host topology, fault schedule, seeds, raw traces,
  independent replay, and declared percentile denominators in its evidence
  envelope.
- `UP-V0-V1` is a reviewed, deterministic, no-downgrade specification package;
  `MIG-COMET-POCO` evidence is kept in its separate C0/G5 namespace and cannot
  satisfy this exit.
- V1 implementation and production flags remain false.

## 6. G2 — implement and integrate the PoCO AI-native v1 stack (future gate)

Build in dependency order; do not begin with an alternative Order theorem.
Every “current tranche” or positive result in this section is
`candidate-non-normative` evidence for a bounded local surface. It does not
promote v1 `implementation_status`, `node_support`, `production_candidate`,
or activation flags; those remain false until the G2 exit gate and machine
manifest agree.

### G2 contract: dependency order, evidence, and authority

G2 is a single vertical integration gate, not six independent feature claims.
The only admissible dependency order is:

```text
G1 authoritative Node/Core/Safety/CAS
  -> G1.5 v1 normative freeze + reproducible v0 baseline
  -> G2.0 wire/transaction conformance
  -> G2A DA certificate and BatchRef
  -> G2B Agent/Task admission and lifecycle
  -> G2D deterministic execution/MVCC/fees
  -> G2C result verification/challenge
  -> G2E canonical settlement
  -> G2F whole-node cross-plane authority, state sync, and light-client proof
```

G2A, G2B, and G2D may develop bounded kernels in parallel after G2.0, but
integration evidence follows the order above and cannot skip a predecessor.
G2D produces the `Executed` receipt/resource intent consumed by G2C; an
off-chain verification profile still enters through that same lifecycle state
and cannot bypass the wire or execution envelope. G2E consumes the canonical
execution and verification outputs; G2F consumes all of them and is the only
subgate allowed to claim a private-alpha node path. This ordering removes the
former C↔E and D↔E semantic cycles: execution meters resources, verification
produces a result/challenge decision, and settlement alone changes economic
state.

Every subgate exit is a signed record with the same fields: `gate_id`,
`status`, source commit/tree hash, protocol and benchmark manifest hashes,
toolchain/container/SBOM, exact replay command, topology and fault schedule,
artifact index, independent reviewer signatures, negative-mutant results,
known gaps, and the exact machine flags changed. A local SQLite root, a
candidate carrier, or a passing unit test is never an authority substitution.
Until the complete record exists, the subgate status is
`candidate-non-normative` or `blocked`, never `passed`.

### G2.0 — canonical vertical traceability and wire conformance (prerequisite)

The following matrix is the required end-to-end trace. It is a closure table,
not a claim that any row is implemented today. Each row must carry a schema
hash, version/domain, byte and resource limits, two independent parser results,
positive/negative vectors, and a content-addressed evidence bundle.

| Link | Canonical object and binding | Required proof/evidence | Consumer and gate | Current truth |
| --- | --- | --- | --- | --- |
| W0 | CEV1 operation kind `0..29` (or an explicit disabled/rejected kind) | Frozen logical codec, domain tag, nested-length/depth/signature/CPU limits, unknown/trailing/duplicate/cross-version rejection vectors | Admission parser, RPC/SDK, G2.0/G2B | Operation-kind wire assignment and global parser false; object catalog only has the existing foundation tag |
| W1 | `AgentTransactionV1` with agent/controller key, capability, nonce lane, expiry, task/resource scope, and operation payload | Canonical bytes and authorization predicate; no fallback to local kernel inputs | Mempool/admission and transaction batch, G2B | Design-only; not a global wire |
| W2 | `TransactionBatch` content root and ordered `BatchRef` | Exact byte reconstruction, author/queue bounds, DA certificate, retention/challenge window, `ArtifactEvidence` namespace | Proposal/retrieval-before-vote, G2A | Local full-replication candidate only; no Order/Node authority |
| W3 | Proposal, Vote, QC/TC and three-chain predicate bound to `BatchRef` | Domain-separated headers, validator-set/epoch proof, complete retrieval predicate, independent replay | PoCO Order/Safety, G2A/G2F | v0 authority is the predecessor gate; v1 binding absent |
| W4 | Deterministic execution receipt and application JMT `post_state_root` | Read/write/version/conflict commitments, resource receipt, serial-equivalence replay, inclusion proof | State sync, RPC, light client, G2D/G2F | Local MVCC candidate; composite root is not JMT |
| W5 | `ResultEvidence`, `ChallengeReceipt`, and verification-profile commitment | Profile-specific proof/quote/replay/evaluator set, expiry, bond, appeal and forward-only transition | G2C and lifecycle state machine | One local StakeQuorum candidate; global profiles disabled |
| W6 | `SettlementIntentV1` → `SettlementReceiptV1` | Fee-schedule root, escrow/bond/slash/reward/refund/treasury conservation, maturity and exactly-once CAS | Economic state/JMT and PoCO eligibility, G2E | One local single-asset rollup; not canonical |
| W7 | RPC/WS/SDK/indexer vectors and independent light-client proof | Version negotiation, error registry, replay fixture, multi-hop proof and weak-subjectivity anchor | External clients and release evidence, G2F | Public interop and light-client closure absent |

No row may be marked complete when it terminates in a local SQLite root or a
candidate composite root. The required trace is:

```text
CEV1 -> AgentTransactionV1 -> TransactionBatch/content root ->
DA certificate + BatchRef -> proposal/QC/vote -> execution receipt/JMT root ->
result/challenge proof -> SettlementIntent/Receipt -> RPC/SDK/indexer/light client
```

The closure artifact must contain 30 machine-generated operation rows (kinds
`0` through `29`). An intentionally disabled kind terminates at a canonical
rejection vector and is never counted as admitted throughput; an enabled kind
must traverse every applicable W1–W7 link or the G2 exit is blocked.

The G2.0 wire/transaction conformance exit freezes two layers separately:

1. **Logical CEV1 codec:** every enabled operation kind has a versioned schema,
   domain separator, canonical field order, integer/length/depth/CPU budgets,
   signer and nonce rules, and an explicit disabled response for unsupported
   kinds. Unknown fields, trailing bytes, duplicate signers, duplicate map
   keys, cross-version domains, overflow, decompression bombs, and replayed
   nonces must fail closed.
2. **Authenticated transport:** P2P and RPC/WS request/response envelopes bind
   peer identity, chain/network, request ID, limits, timeout, response hash,
   and capability. Rate limits and anti-amplification rules are part of the
   wire contract; a transport success is not a DA or Order attestation.

Two independently implemented parsers (including one independent client or
conformance implementation), differential/mutation/fuzz corpus, canonical
byte fixtures, and an exact clean-clone replay command are mandatory. A single
Rust serializer, a SQLite schema, or a hand-written test is insufficient.
G2.0 remains `blocked` until the matrix, parser pair, vectors, and evidence
index are complete; unsupported objects are rejected rather than silently
accepted or downgraded.

### AI-native lifecycle and verification launch contract

Every admitted task follows one explicit state machine. State transitions are
forward-only, idempotent on `(task_id, operation_nonce)`, and expire according
to the committed task/profile policy:

```text
Draft
  -> Admitted
  -> DA-certified
  -> Ordered
  -> Executed{Success|Reverted|OutOfResource}
  -> ResultPending
  -> Verified(profile)
  -> ChallengeWindow
  -> ResultFinal | ResultRejected
  -> Settled | Refunded | Slashed
```

`Draft` is not executable; `Admitted` requires an authorized
`AgentTransactionV1`; `DA-certified` requires the exact `BatchRef` and
certificate; `Ordered` requires PoCO order finality; `Executed` requires a
deterministic receipt or an explicitly selected off-chain profile; and
`ResultFinal` requires profile verification plus challenge expiry or a
finalized challenge decision. A failed/expired predecessor, duplicate nonce,
stale profile hash, missing artifact, or retry after a terminal state is a
rejection, never an implicit retry or profile downgrade. Challenge success is
a new forward transaction and cannot rewrite an Order block.

The profile launch matrix is normative. A profile marked `disabled` must reject
admission with a versioned error and may not produce an objective result,
settlement, reward, slash, or PoCO weight.

| Profile | Statement/evidence backend | Trust root and mandatory checks | Challenge/expiry semantics | Launch status |
| --- | --- | --- | --- | --- |
| Deterministic re-execution | Re-execution receipt, runtime/image digest, input/output commitments | Reproducible toolchain, deterministic numeric/runtime policy, exact replay | Bounded challenge and replay window | Design-only/disabled |
| Reproducible ML | Model/data/runtime digests, tokenizer/precision/seed, reproducible trace | Provenance/license/privacy policy and numeric tolerance contract | Independent rerun, expiry, appeal | Design-only/disabled |
| ZK | Proof, public statement, verification key/setup digest | Circuit/version, soundness, setup ceremony and key revocation | Proof invalidity is terminal; setup/key expiry is explicit | Design-only/disabled |
| TEE | Quote, measurement, TCB and freshness evidence | Attestation roots, rollback/fork detection, enclave key custody and revocation | Quote freshness/TCB expiry; no stale quote settlement | Design-only/disabled |
| StakeQuorum | Unique weighted verifier claims over one statement/evidence/sequence | Fixed verifier set, checked weight, anti-collusion and identity policy | Bonded challenge, response, expiry, appeal | Local candidate only/disabled globally |
| Optimistic | Provider result plus bonded assertion and fraud proof | Timeout, bond sizing, fraud-proof VM and challenger eligibility | Challenge window and deterministic resolution | Design-only/disabled |
| Subjective | Human/curator or policy judgement with declared scope | Explicitly non-objective trust root and audit trail | Appeal/revocation only; never objective finality | Design-only/disabled |

Each profile row must have a frozen `VerificationProfileV1` hash, wire schema,
negative vectors, cost meter, evidence retention rule, revocation/expiry rule,
and an owner. Model weights, private prompts, private inputs and long outputs
stay off chain; only commitments, policy-approved metadata and admissible proof
references enter the chain. Provenance/license, privacy, malicious tool use,
evaluator collusion, Sybil/related-party and challenge-griefing tests are part
of the profile exit. No profile is “implemented” merely because a local
receipt can be stored.

Profile promotion is monotonic and per-profile: `design-only` → `spec-frozen`
→ `candidate-local` → `testnet-enabled` → `mainnet-enabled`. G2 may promote at
most one objective profile for the private-alpha first slice, and only after
its own parser, verifier, cost, expiry, challenge, revocation, and negative
vector bundle is signed. A profile being enabled never enables another profile
or supplies a fallback. `ERR_PROFILE_DISABLED`, `ERR_PROFILE_EXPIRED`, and
`ERR_PROFILE_EVIDENCE_MISSING` are canonical rejection outcomes. Subjective
evaluation can remain an explicitly declared audit signal, but it is forbidden
from `ResultFinal` objective settlement or PoCO weight at every promotion
level. A profile regression invalidates only its dependent result/settlement
evidence and reopens the corresponding G2C/G2E/G2F exit; it cannot silently
reuse a weaker profile hash.

### G2A — certified DA

Current bounded tranche: `trnm-poco-da-v1` implements a local, full-replication
`TransactionBatch` candidate with durable-before-attest, author/queue bounds,
strict weighted certificates, retrieval, repair, retention, and durable GC.
Its local schema-v2 attestation journal has a checksummed high-watermark and
immutable durable manifest. GC can be exercised only through a test-only
permit issuer; production byte deletion is unreachable until Node finality/CAS
owns the authority. It has no network, ArtifactEvidence namespace,
BatchRef/Order integration, whole-node CAS, Node reachability, or production
signer/GC authority; therefore G2A and G2 remain incomplete.

A bounded follow-on covers only the cryptographic **full-range** portion of
remote retrieval/repair. An out-of-band pinned requester signs an exact
certificate/range/window request; a committee member signs a response whose
canonical per-chunk paths reach the certified chunk root. The verifier rebuilds
the complete transaction batch and yields a non-copyable carrier bound to the
target scope/store/config/certificate. Repair still passes through the original
immutable durable manifest and ends with a fresh complete-byte/certificate
readback. This is transport-independent candidate evidence: generic ranges,
requester registry, responder signer journal, peer routing, non-response/
withholding adjudication, ArtifactEvidence, Node integration and global G2 all
remain false.

#### DA mode boundary and authenticated dissemination

The v1 launch baseline is explicitly **`DA-FULLREP-V1`**: complete transaction
and artifact bytes are replicated by the admitted provider set before an
availability certificate can be used by Order. The current shadow profile has
`full_replication_first=true`, while erasure coding and data-availability
sampling are not active or required. Therefore the release floor in this plan
must not be read as a Celestia-like DAS claim. `DA-DAS-V1` is a separately
versioned future profile, not an implicit upgrade of full replication.

`DA-DAS-V1` cannot activate until its committee/validator sampling randomness,
erasure layout, sample soundness and withholding proof, repair/retention
economics, availability window, and light-client verification vectors are
frozen and independently reproduced. If those conditions are not met, a node
must reject a sampling-only certificate and require the full-range baseline.

G2A's canonical path must include authenticated P2P request/response envelopes
with peer identity, namespace, `BatchRef`, exact byte range, request nonce,
expiry, response hash, anti-amplification quota, and rate-limit accounting.
`ArtifactEvidence` has a distinct content-addressed namespace from transaction
batches. A certificate is not enough: the proposal predicate must verify the
exact `BatchRef`, complete retrieval (or the activated DAS proof), validator
set/epoch, retention/challenge window, and repair authority before a Vote. GC
and byte deletion remain unreachable until the Node-owned whole-node CAS and
anti-rollback authority in G2F are closed.

- Implement bounded multi-worker transaction-batch and artifact dissemination,
  canonical descriptors, durable store manifests, durable-before-attest
  journals, weighted availability certificates, quotas and backpressure.
- Implement complete retrieval/reconstruction, repair, withholding evidence,
  retention/GC, restart reconciliation, and DA whole-node checkpoint facts.
- Integrate exact BatchRef + certificate verification and complete retrieval-
  before-vote with the retained HotStuff Order kernel.

#### G2A exit (signed, independently reproducible)

No attestation may escape without its promised durable bytes. Every certified
test batch must remain retrievable through its retention/challenge window under
the declared fault model; missing data, an unauthenticated peer response,
namespace confusion, a stale/duplicate `BatchRef`, or an incomplete repair must
never produce a Vote. The signed exit must include the authenticated transport
vectors, full-replication availability matrix, withholding/repair negatives,
GC authority proof, and the exact proposal-to-`BatchRef` replay. `DA-DAS-V1`
remains disabled unless its separate profile evidence is attached. G2A is not
passed by local retrieval tests alone.

### G2B — Agent and task market

Current bounded tranche: `trnm-poco-agent-market-v1` implements a local
candidate for root capability/session grants, explicit nonzero session lanes,
one shared capability budget, `Task + funded Escrow`, Bid, atomic requester
lease acceptance (Task/Bid/Escrow/Bond/Lease), and provider Offered-to-Active.
It now enforces every representable Task/model/tool/profile/privacy/exact-
resource scope; unsupported `CommittedSet` and uncarried market/endpoint scopes
fail closed, and provider acceptance resolves its Lease back to the Task. Its
SQLite schema-v2 journal separates immutable genesis trust from a per-call
Order-finalized height/block context, persists a monotonic expected-tip CAS,
checks durable state/journal roots on every verified open/read/write, provides
exact replay/read-only reopen preflight/sidecar/schema/tamper rejection, and
permanently fences an ambiguous third state. It is not the global
`AgentTransactionV1` wire, complete identity/key/capability or task lifecycle,
an authenticated state tree, whole-node CAS, or Node-backed Order-proof
authority; committed-set verification, Verify/Challenge/Settlement and
production authority also remain absent. G2B and G2 remain incomplete.

- Implement Agent identity, capability grants/revocation, session keys,
  budgets, model/tool/endpoint/rate/time scopes, nonce lanes, and bounded Agent
  batches as canonical `AgentTransactionV1` admissions; local kernel inputs
  that cannot be decoded and authorized by that wire are rejected.
- Implement task specs, offers, leases, funded escrow, deadlines,
  checkpoint/resume, migration/cancel/timeout/refund, artifact references, and
  immutable verification/settlement profiles. Every transition must project to
  the lifecycle state machine above with an idempotency key and a versioned
  rejection for an expired, disabled, or weaker profile.

#### G2B exit (signed, independently reproducible)

Capability escalation, cross-lane replay, missing-scope, expiry, duplicate
nonce, profile-downgrade, and terminal-retry mutants must fail. The `AgentTransactionV1`
authorization predicate, task lifecycle model, capability/revocation vectors,
and escrow reservation model must agree across two parsers and crash/reopen
tests. The exit must show a W1→W2 trace for every enabled operation kind and
must prove that no local Agent/Market SQLite root is treated as global state.

### G2C — compute verification and challenge

Current bounded tranche: `trnm-poco-verify-challenge-v1` implements a local
candidate for one `StakeQuorum` profile. It admits an exact provider-signed
receipt, counts strictly unique verifier identities under checked weight,
requires every claim to bind the same deterministic
statement/evidence/sequence, persists the atomic virtual BeginEvaluation plus
decision pair, and supports one challenge through evidence, response and
Upheld/Rejected bond resolution. Duplicate trust keys and inconsistent
verifier-set/profile commitments fail closed; verifier membership is fixed to
four, all revision/bond arithmetic is checked, and evidence is capped at 64
entries. Its schema-v2 SQLite journal immutable-read-only preflights an existing
store before writable access, persists a monotonic per-call Order-finalized
height/block CAS and checks durable state/operation-tail roots on every verified
access. The Order context
is not a proof and has no Node authority; ArtifactEvidence DA, the other six
verification classes, expiry/withdraw/appeal, concurrent challenges,
Agent/Market/Settlement integration, whole-store CAS, global wire and
production authority remain absent. G2C and G2 remain incomplete.

- Keep AI compute off chain and implement the frozen verification profiles:
  deterministic re-execution, reproducible ML, ZK, TEE, stake quorum,
  optimistic challenge, and explicitly subjective evaluation as separate
  semantics. A profile that is not fully launched is a hard admission reject;
  no automatic fallback from ZK/TEE/replay to StakeQuorum or subjective
  evaluation is allowed.
- Implement proof/evaluator/repair/challenge durable outboxes, idempotent result
  ingestion, deadlines, evidence retention, profile expiry/revocation,
  compensation and appeal rules. Emit a canonical result/challenge decision for
  G2E to consume; do not mutate settlement state from this gate.
- Separate BFT order finality from AI result/settlement finality; challenge
  success is a forward transaction, never a block rollback.

#### G2C exit (signed, independently reproducible)

Every result and challenge decision is traceable through exact task, lease,
profile hash, artifact/DA evidence, statement, proof/quote/replay, challenge,
expiry and outbox IDs; no ambiguous `Valid` status crosses profiles. The exit
must include one negative vector for each disabled profile, concurrent and
duplicate challenge tests, verifier-set/weight and bond arithmetic checks,
profile-specific trust-root and revocation evidence, and a W5 proof that ends
in `ResultFinal` or `ResultRejected` only. It must not claim canonical
`SettlementReceiptV1`, PoCO weight, or economic conservation; those belong to
G2E.

### G2D — deterministic parallel execution and fees

Current bounded tranche: `trnm-poco-mvcc-fee-v1` implements one local
single-block typed-object candidate. Every transaction declares exact read and
write object IDs; speculative parent-snapshot versions are validated in
gap-free transaction-index order and mismatches re-execute deterministically
against the canonical prefix. Success, Reverted and OutOfResource receipts bind
read/write versions, roots, conflict/retry evidence, four resource classes and
checked fees. Per-transaction fee deltas debit only their payer; sorted
block-end reduction credits each destination once, avoiding a global collector
write hotspot. SQLite schema v1 atomically persists objects, receipts, resource
totals, fee deltas and journal roots with immutable existing-store preflight and
exact crash/full-journal replay. This is not global AgentTransaction authorization, real
parallelism, JMT/state proof, the complete resource schedule, Order/Node
authority, Settlement or G2 completion.

- Implement object-aware MVCC with canonical read/write/conflict commitments,
  deterministic replay and reference serial semantics.
- Add explicit outcome/status receipts, batched authenticated-state commits,
  nonce-lane advances, block-level fee deltas, and hot-key-free distribution.
- Implement the frozen execution resource schedule and checked debits/credits
  across order, state, transaction DA, artifact DA/retention, proof
  verification, and priority. Reserve challenge bonds and escrow obligations
  as typed intents for G2E; G2D must not mint, slash, refund, burn, or pay a
  provider directly.
- Commit every successful, reverted, and out-of-resource outcome to the
  application JMT with an inclusion proof and a deterministic
  `ExecutionReceiptV1`; the candidate composite root is not a substitute for
  `post_state_root` or a light-client proof.

#### G2D exit (signed, independently reproducible)

Randomized conflict schedules reproduce serial state/receipt/JMT roots;
runtime timing, worker count, and retry order do not change validity; all
execution-metered resources conserve under success, failure, retry and crash.
The exit must include AgentTransaction authorization, nonce-lane advancement,
reference-serial replay, inclusion-proof vectors, fee-schedule hash, and
explicit handoff records for G2E `SettlementIntentV1`. It must demonstrate
that an execution receipt cannot itself create settlement, reward, slash,
refund, burn, treasury credit, or PoCO weight.

### G2E — consumption rollups and integrated private alpha

Current bounded tranche: `trnm-poco-consumption-settlement-v1` implements one
local provider/consumer, one asset, one final-valid result and one rollup.
Current-height bilateral Ed25519 signatures bind a gap-free receipt chain;
usage and cumulative charge are recomputed from a committed price table. One
atomic rollup assigns every receipt, sets a chain-derived challenge-close
height, and a later caller-amount-free trigger derives provider payment,
consumer refund and protocol fee while conserving the full escrow exactly
once. SQLite schema v2 provides immutable preflight, durable state/journal and
finalized-block roots, full deterministic replay, direct-successor empty-block
coverage, and exact source/target/fence crash outcomes.
All bootstrap identities, DA/result/order facts remain local trust inputs, so
this does not close G2E or integrated private alpha.

G2E's target is a canonical state transition, not a bilateral accounting
helper. A `SettlementIntentV1` may be admitted only after W1 authorization, a
W2 `BatchRef`/artifact reference, a W4 `ExecutionReceiptV1`, and a W5
`ResultFinal` decision whose profile hash and challenge maturity are exact. The
intent is immutable and carries task/lease/result IDs, payer/payee identities,
asset IDs, fee-schedule root, escrow/bond references, expiry, and an idempotent
nonce. `SettlementReceiptV1` is the only transition allowed to move economic
state and must be included in the application JMT with a verifiable proof.

The canonical transition must support a frozen multi-asset schedule and exact
conservation of provider payment, consumer refund, protocol fee, reward, burn,
treasury, escrow, challenge bond, slash, dust/rounding, and failed/expired
paths. Insolvency, stale price-table, duplicate receipt, related-party/Sybil,
MEV/reordering, griefing, and retry-after-commit vectors must fail closed.
Challenge maturity, appeal, refund and slash are forward transitions; no
settlement action rewrites an Order block or retroactively changes a result.
Settlement-derived reputation or PoCO economic weight remains ineligible until
G5 economics/governance activation, even when a private-alpha receipt verifies.

#### G2E exit (signed, independently reproducible)

The exit requires a W6 trace from every enabled task/result to exactly one
`SettlementIntentV1` and at most one terminal `SettlementReceiptV1`, with
global Agent/DA/Order/Execution/Verification facts rather than bootstrap trust
inputs. Two independent implementations must replay the same JMT root and
multi-asset conservation vector across success, rejection, challenge upheld,
challenge rejected, expiry, cancellation, retry, crash before commit, response
loss after commit, and duplicate submission. The fee-schedule/asset registry,
escrow-bond lifecycle, treasury/burn/reward accounting, maturity/appeal rules,
and PoCO-weight ineligibility proof must be signed. A local one-provider,
single-asset rollup is candidate evidence only and cannot satisfy this exit.

### G2F — cross-plane fresh-readback consistency

The first G2F candidate now joins all five local G2 kernels using two exact
fresh-reopen samples, typed lifecycle IDs, and each store identity, monotonic
position, state/metadata root, and journal tail. It deliberately has no write
path. The DA head and selected certificate share one SQLite read snapshot, and
each terminal receipt must match the sampled store identity, sequence/height,
Order head and state root. The Order-proof digest remains a trust input. A later
Node-owned whole-node CAS must consume these exact facts before cross-plane
authority or integrated private-alpha completion can move true.

A bounded follow-on candidate now demonstrates that consumption shape inside
the Node crate without activating it. It independently verifies one pinned raw
CEV1 FreshGenesis direct three-chain Order proof in Rust, consumes the G2F
carrier, reopens and rejoins the five sources, requires exact projection
stability, then advances a distinct predecessor-bound checkpoint with
successor-only CAS and mandatory fresh source/target confirmation. Existing
checkpoint files receive immutable read-only schema/metadata preflight,
sidecar rejection, and exact file-identity revalidation before mutable PRAGMAs
or transactions. The finalized Order header does not authenticate membership
of the five-plane projection in its `post_state_root`: the Order proof and
stable projection remain parallel local co-observations,
`order_finalized_cross_plane_authority=false`, and no proof-to-state
substitution boundary is closed. The source stores are not one atomic snapshot
or transaction; anti-whole-store rollback, Node process wiring,
Ordinary/TC/handoff trust progression and global G2 are still open.

An additional non-Node candidate now implements one bounded global pre-vote
runtime over those real local kernels. It requires a freshly authenticated
certificate and complete local DA retrieval, exactly one strictly decoded
bounded candidate item, and the exact same five-store parent cut before and
after Agent/Market, Verify/Challenge, MVCC/Fee and Consumption/Settlement
preview. It commits their candidate roots and receipts, the certified DA
obligation and retrieved bytes into a domain-separated **candidate composite
root**, then advances a separate validation sequence only through an exact
successor CAS with mandatory fresh source, target and prepared-row readback.
The resulting private carrier is non-cloneable and can exist only after the
target has been reauthenticated; reopen exercises the same generation,
checksum and prepared commitment.

A follow-on now also exercises the bounded normal-build source-apply cut. An
independently verified Order-finality carrier naming the exact prepared
candidate drives exact-replayable finalized application through all five
planes. Checksummed direct-successor finalized-block journals cover empty
blocks and same-block multi-operation execution, and fresh terminal readback
must match the prepared roots before the private, non-cloneable finalization
owner can exist. That owner binds the exact prepared generation/checksum,
candidate composite tip, five plane terminal receipt/root commitments and a
candidate-local final execution root. The history successor, finalized
evidence row and metadata CAS
commit in one SQLite transaction; exact retry, pre/post-commit response loss,
stale/fork/root substitution, reopen, partial/torn rows and logical metadata
rollback are executable controls. This is
`candidate_local_whole_node_finalization_cas=true`,
`candidate_local_normal_build_finalization_owner_issuer=true`, and
`candidate_local_source_plane_finalization_apply=true` for this bounded path.
These names are deliberately scoped and are not machine truth for a whole
Node. It does not
detect rollback of an entire database file without external anti-rollback
authority.

T0-C/T0-D separately carry the manifest-bound v2 path into a private Node data
journal. The only owner ingress consumes the exact non-Clone
`G2CandidateLocalFinalizeJoinV2`;
the journal never accepts a preview, raw request, root list, decoded snapshot,
or pin as an authority substitute. An anchor and its sole persisted successor
form a complete predecessor-bound history. `BEGIN IMMEDIATE` metadata CAS,
immutable source/target readback, path-level file/content identity checks and
external trusted-prefix pin data resolve exact retry and pre/post-commit
response loss. Receipt count is bounded before serialization; allocation-free
Borsh length counting and a hard-limited writer enforce the fixed snapshot
budget. A reopened target remains inert until a freshly regenerated typed join
encodes to the exact durable bytes.

The T0-E foundation first added the two authority-preserving prerequisites for
a real process tranche. Canonical Order-state now seals the manifest-bound
G2 block through a normal-build method that accepts its own non-forgeable
`RecoveredCanonicalOrderApplicationParentV1`, fresh-audits the complete store
and exact head pin before and after, and proves the seal is the unique direct
successor without exposing `OrderApplicationParentV1`. Separately, the
non-Clone T0-D owner retains its live SQLite journal and can crate-privately
rederive the full snapshot from the retained typed join across two fresh exact
journal audits.

The smallest normal-build process tranche is now statically wired behind
explicit candidate-only `prepare-g2-manifest-bound-candidate-v2` and
`run-g2-manifest-bound-candidate-v2` commands. It opens all five source stores
and canonical Order state through existing-only audited APIs, traverses the
normal input/preview/recovered-parent/seal/exact-join chain, consumes only that
typed join at T0-D, and holds the live stores, canonical store, T0-D journal,
independent process-pin CAS file and exclusive OS lock in one non-Clone owner.
The process-pin anchor seals the exact-join commitment produced during prepare;
prepare retries under the exact stable lock rerun the full issuer and reconcile
only the ordered durable prefix through that anchor. The run path requires
external manifest/process-pin checksums, rejects a fresh issuer mismatch before
T0-D consumption, permits an old external anchor only for the byte-exact unique
target reconstructed from the same issuer and T0-D successor, and reconciles
only an exact temporary target. The target schema binds journal ID, process
scope, generation, predecessor and direct canonical height. `READY` follows a
second fresh issuer/revalidation pass, after which control-stdin EOF performs a
final audit and clean shutdown. A normal-build integration target plus private
schema/temp/lock/rollback tests are present as source. Its feature-gated
fixture builder constructs real DA plus all five source stores, a canonical
Order parent and exact manifest, while exposing no typed join/owner input to
the unchanged normal CLI. The candidate-only feature integration target now
passes all 7/7
tests. Its real normal-binary matrix observes a byte-stable PREPARED retry, P1
READY, duplicate-lock refusal before READY, P1 SIGKILL (signal 9), and a
different-PID P2 launched with the saved old anchor recovering the same unique
target before READY and clean stdin-EOF shutdown. Five dynamic negative
classes—DA mode drift, canonical Order mode drift, malformed temporary target,
process-pin rollback after an externally observed target, and T0-D journal
rollback—each fail before READY. The candidate-only feature suite (74 unit, 7
process, 7 doc tests), strict all-target Clippy, the global boundary and
project preflight (`errors=0`) also pass in its recorded local run. This is not
production or release evidence; only the candidate-local process integration,
external-pin process persistence, and external-pin-authenticated process-owner
facts are true. Whole-Node, rollback, and G2 facts remain false.

These separate path/hash/rusqlite opens only narrow the replacement window.
They do not retain an `openat`/directory-descriptor identity, close a malicious
same-UID rename race, pin the namespace inode/effective-UID owner, or provide an
authenticated production anti-rollback root beyond the operator-retained
external checksum. The database-only rollback test therefore is not coherent
pin-plus-database rollback protection. This covers candidate-local normal Node
process reachability only, not whole-Node commissioning, vote eligibility,
whole-node rollback authority, or G2.

A further bounded path now exercises the local Order-state membership binding.
The independent Order-state writer consumes the real non-Clone linear terminal
owner into an exact-parent create-once permit, proves the derived tag-50 key
absent, commits its immutable version-zero value, and freshly reconstructs the
successor receipt and canonical 256-sibling proof. A typed receipt projection
can issue the non-Clone positive carrier only when separately verified later
Order finality names that exact height/root and proves the encoded candidate as
a strict certified ancestor. The global refinement seam then checks context,
candidate height/block, composite root, and final execution root against the
retained owner. Public terminal commitments, raw CEV1 claims, cloneable create
material, and fabricated receipt projections remain non-authority. The global
crate itself still has `order_binding_positive_carrier_issuer=false`, while the
cross-crate local path makes `order_state_membership_binding=true`.

This is `candidate_local_runtime_implemented=true`, not G2 completion. The item is
not the normative `AgentTransactionV1` wire, the composite root is not the
application JMT root, and there is still no multi-level overlay, canonical Node
Order-state commissioning, coherent whole-store rollback authority, Node
process owner for the global runtime, state sync, signing or broadcast. The
manifest-bound candidate-local persistence tranche has
`candidate_local_node_process_integration=true`, while the global execution
tranche and top level retain `node_process_integration=false`;
`g2_global_complete=false` remains fail-closed. Any candidate-local flag must
carry `scope=candidate-local` and `authority=false`; an unscoped
production-like `*_true` value is invalid evidence.

#### G2F hard authority exit: whole-node CAS and anti-rollback

The G2F exit is hard-fail, not a bounded-acceptance item. Before any private
alpha or validator process may consume a positive cross-plane result, a
Node-owned authority must:

1. read DA, Agent/Task, Verify/Challenge, MVCC/Fee, Settlement, and canonical
   Order state from one authenticated snapshot or an explicitly versioned
   atomic multi-store transaction;
2. derive the application JMT `post_state_root` from those exact bytes and bind
   it into the finalized Order header/proof, so a candidate composite root is
   never substituted for the application root;
3. commit a predecessor-bound whole-node checkpoint through a monotonic CAS
   whose anchor is outside the rollbackable database (HSM/KMS/remote signer or
   an equivalently authenticated operator quorum), with generation, height,
   epoch, validator-set hash, manifest hash, and file/namespace identity;
4. reject stale, forked, renamed, copied, same-UID, torn, sidecar, WAL, key,
   process-pin, and database-file rollback before signing, voting, GC, state
   sync, or settlement; and
5. prove normal-build process ownership, signer custody, broadcast, restart,
   catch-up, Ordinary/TC/handoff progression, and fresh post-commit readback
   in at least two independent implementations.

An operator-retained checksum or a path/hash/rusqlite reopen is useful negative
evidence but does not satisfy this authority. Any failure invalidates all
downstream G2F/G3/G4 evidence and leaves `node_support=false` and
`production_candidate=false`.

#### G2F light-client and proof-coverage exit

The independent v1 light client must verify, without trusting a full node, all
links needed by W3–W7:

| Proof family | Required statement | Negative coverage |
| --- | --- | --- |
| Order | Validator-set/epoch, proposal header, Vote/QC/TC, three-chain finality and handoff | Wrong domain/height, insufficient weight, equivocation, stale epoch, forged successor |
| DA | `BatchRef`, certificate/activated DAS proof, namespace, retention and repair status | Missing/withheld chunk, wrong range/root, committee substitution, sampling-only proof while DAS disabled |
| Execution | `AgentTransactionV1` authorization, receipt, read/write versions, resource fee and JMT inclusion to `post_state_root` | Root substitution, conflict/retry drift, duplicate nonce, malformed proof, composite-root substitution |
| Result | Profile hash, statement/evidence commitment, proof/quote/replay, challenge maturity and forward decision | Disabled profile, stale quote/key, duplicate verifier, invalid proof, expired/duplicate challenge |
| Settlement | `SettlementIntentV1`/`ReceiptV1`, fee schedule, conservation and exactly-once terminal state | Duplicate payment, insolvency, stale price, wrong asset, replay after commit, unauthorized PoCO weight |
| Upgrade/sync | Weak-subjectivity anchor, cross-version transition, snapshot/chunk root and validator membership | Downgrade, old WAL/key, anchor rollback, missing epoch, non-monotonic sync |

The client must pass multi-hop proofs (at least 64 epochs/10,000 headers), fresh
and anchored modes, malformed-proof fuzzing, proof-size/verification-time
budgets, and replay against two independent implementations. A subjective
profile may be displayed as subjective evidence but must be rejected by the
client as objective settlement or PoCO weight.

#### G2F exit (signed, independently reproducible)

G2F passes only when G2.0, G2A, G2B, G2C, G2D and G2E exit records are all
present and the whole-node authority, anti-rollback, process-owner, state-sync,
and light-client proof bundles above pass with zero open Critical or High
finding. The exit must include a complete W0→W7 trace for a real
`AgentTransactionV1`, cross-crash/restart/recovery and old-anchor negatives,
two independent light clients, and a clean-clone replay. Candidate-local
positive carriers remain evidence inputs; they never change global machine
flags. A missing proof family, unscoped positive flag, or accepted rollback
reopens G2F and invalidates all downstream evidence.

- Implement bilateral/versioned consumption receipts, cumulative roots and
  totals, artifact/measurement DA references, challenge windows, rollup
  resolution, settlement, relationship status and PoCO maturity eligibility.
  Sampling proofs are conditional on the separately activated `DA-DAS-V1`
  profile; the `DA-FULLREP-V1` baseline must not imply sampling.
- Integrate DA, Order, execution, task, verification, challenge and settlement
  into one native node while PoCO economic weight remains shadow-only.
- Complete v1 snapshot/state sync, cross-version transition proof, independent
  v1 light client/parser, remote signer/HSM interface, metrics and operator
  recovery tools. State sync must verify W3/W4 roots and validator membership
  before exposing a store to signing or voting; it cannot import a legacy WAL,
  key, or unverified application root.

Exit criterion (not current status): a private alpha **must pass** the complete
W0→W7 transaction/task/result/rollup lifecycle, G2.0–G2F signed exits,
cross-crash recovery and anti-rollback negatives, deterministic state sync,
two independent light clients, and shortened v0-to-v1 upgrade campaigns. The
current tree is not yet public-testnet ready; no G2 candidate result promotes
v1 implementation or production activation.

## 7. G3 — 7/31/100-validator WAN profiling and Order decision

The authorized six-host `192.168.0.0/24` fleet first closes a distinct LAN
campaign. Its frozen 7/31/100 placement, read-only readiness probe,
content-addressed raw-evidence acceptor, and private ephemeral-key material
generator exist, but no validator run is yet complete. Every validator must be
one independently observed OS process using a run-unique Ed25519 key with a
verified proof of possession. A LAN pass may set only the LAN evidence bit;
`g3_geo_wan_evidence` remains false until the same signed candidate is run
across controlled geographic regions.

### 7.1 Topology, identity, and decentralization claims

G3 separates four identities that are often accidentally conflated. The
topology manifest MUST carry all four for every validator and every run:

| Identity | Required meaning | What it may prove |
| --- | --- | --- |
| `process_id` | One independently observed OS process/container, with a run-unique validator key and proof of possession | Process-level safety, CPU/memory/disk/network measurements |
| `host_id` | One physical or virtual machine with a stable host attestation and resource inventory | Host-failure and resource-domain evidence; it does not prove operator independence |
| `operator_id` | One independently controlled organisation/key-custody domain, recorded with a signed operator declaration | Operator/failure-domain diversity only when distinct custody and control are evidenced |
| `region_id` | One controlled geographic/network failure domain with measured RTT, loss and partition schedule | WAN/region resilience; a label without measured links is not geographic evidence |

The manifest also records process-to-host, host-to-operator and host-to-region
mapping, validator-set membership, AS/ISP or equivalent network domain when
available, CPU/GPU/memory/disk/NIC inventory, container/image digest, clock
source, and all link characteristics. Multiple processes on one host count as
multiple `process_id` values but only one host failure domain and, unless
independently controlled, one operator. A six-host LAN with 100 processes is
therefore a **100-process** result, not a 100-operator or 100-region
decentralization result. Simulated or multiplexed validators MUST be labelled
`process_only=true` and are excluded from WAN/decentralization claims.

No G3 record may claim “100 validators” without reporting the process, host,
operator and region cardinalities separately. The minimum topology matrix is
7/31/100 processes, with the corresponding host/operator/region counts,
connectivity graph, and failure-domain coverage. A missing mapping is a failed
precondition, not an assumed one.

Run the same signed artifact, genesis, workload generator, fault schedule and
measurement contract at 7, 31 and 100 validators across controlled regions.
Matrices include:

- transaction and artifact size, batch size, worker count, conflict rate,
  read/write-set width, receipt/proof size and retention profile;
- normal, slow leader, leader crash, bandwidth-constrained leader, equivocation,
  selective omission/censorship, withholding, repair storms, DDoS, partition,
  heal, validator restart, state sync, epoch handoff and key rotation;
- committed goodput, finality tails, DA certify/retrieve/repair latency, MVCC
  abort/replay, proof/challenge/settlement latency, availability, state growth,
  recovery, CPU/GPU, memory, disk and network cost; and
- identical-hardware external baseline comparisons that do not enter the
  production dependency or release closure.

### 7.2 Signed benchmark-manifest-v1 and reproducibility

Every benchmark run is governed by a signed, content-addressed
`benchmark-manifest-v1`. The manifest is a release artifact (not an informal
spreadsheet) and binds at least:

- `manifest_id`, `run_id`, plan ID and plan SHA-256, source commit/tree hash,
  protocol/status/parameter manifest hashes, genesis/network ID, binary and
  container digests, toolchain/OS/kernel, SBOM and builder identity;
- the complete process/host/operator/region inventory and connectivity graph;
- workload grammar and exact operation mix for W0 (512-byte transfer), W1
  (2-KiB stateful), and each enabled AI profile, including canonical CEV1
  bytes, AgentTransaction/BatchRef/DA/receipt/proof/settlement schemas,
  batch/block/resource caps, read/write sets, artifact retention and result
  status distribution;
- deterministic seed, key-generation mode, warm-up, duration, sample count,
  replicate count, clock/measurement source, percentile denominator, dropped
  samples, confidence-interval method, and the complete fault/repair schedule;
- raw event/latency/resource traces, content roots, analysis version and
  comparator commit/container. A plotted percentile without its raw trace and
  denominator is not evidence; and
- Ed25519 signatures from the run owner, independent verifier and (for a
  surpass claim) a second independent builder/team. Signatures cover the
  manifest and every referenced content root.

The harness MUST expose one deterministic command that reconstructs the run
from a clean clone and MUST fail if any manifest field, byte limit, seed,
topology, fault schedule, comparator artifact or source hash differs. Raw
traces are retained long enough to reproduce the claim and are never replaced
by a summary. Cost is normalised by the declared hardware, power/hosting
assumptions and committed bytes; ingress/submitted TPS is never substituted
for committed goodput.

The current shadow profile's `p99_finality_max_ms = 5000` is a non-authoritative
shadow target. The §0.7 LAN release floor of p99 <= 2000 ms is a separate,
stricter release criterion. Before G3, the manifest MUST name which value is a
shadow target and which is a release floor; a numeric mismatch cannot be
resolved by silently editing a report or by selecting the more favourable
denominator.

### 7.3 Metric-to-gate binding (no orphan metrics)

Every number published by G3/G4/G5 is bound to one gate, one workload/profile,
one denominator and one evidence root. The minimum binding is:

| Metric family | Required source/evidence | Gate that may promote it |
| --- | --- | --- |
| Committed goodput and finality tails | Signed W0/W1/AI traces, finality event definition, raw percentile samples | G3; G4 confirms soak stability |
| DA certify/retrieve/repair and withholding detection | Certificate/BatchRef roots, retrieval/repair traces, fault schedule and negative vectors | G2/G3; G4 confirms adversarial availability |
| Execution speedup, abort/replay and state growth | Serial-equivalence roots, worker/conflict matrix, JMT/state-sync manifest | G2/G3 |
| Verification/challenge/settlement latency and correctness | Profile-specific proof/result/challenge/settlement IDs, outcome roots and conservation vectors | G2/G4; G5 economics |
| Recovery, custody and availability | Crash/power-loss/signer/HSM traces, incident timeline and SLO denominator | G1/G3/G4 |
| State-sync/light-client and API SLOs | Independent-client replay, proof timings, RPC/WS/indexer request matrix | G4/G5 |
| Per-resource cost and economic safety | Versioned fee schedule, resource meter, solvency/conservation simulation | G2/G5 |

The plan's §0.7 release and surpass bars MUST each point to a row, a
`benchmark-manifest-v1` field, a command, and a signed evidence index. A metric
without that mapping is `unbound` and cannot appear in a gate exit, release
manifest, or marketing statement. A changed schema, workload, topology,
comparator or denominator creates a new manifest ID and invalidates the old
result.

The profiler must attribute the dominant tail and resource bottleneck to DA,
Order, execution, state storage, signing, sync, proof verification, application
conflicts, or operations. A new Order mechanism is considered only if the
target hard requirement is formalized and DA/execution separation still leaves
Order as the measured blocker.

Decision routing:

- happy-path latency bottleneck: evaluate Jolteon/Fast-HotStuff style changes;
- long asynchronous/DDoS liveness bottleneck: evaluate a bounded fallback
  protocol;
- certified-DA leader censorship or residual bandwidth bottleneck: evaluate a
  multi-proposer DAG Order profile;
- formally prioritized tail-fork/MEV fault isolation: evaluate an explicitly
  specified tail-fork-resistant variant; and
- blob bandwidth/retention bottleneck: improve dissemination, erasure coding
  or sampling rather than changing BFT finality.

An Order replacement requires a new protocol version, safety model, liveness
model, negative mutants, independent proof review, two interoperable
implementations, migration/light-client rules, WAN fault evidence and an ADR.
Otherwise v1 retains weighted chained HotStuff.

### Exit gate

G3 may be signed only with a `G3ExitRecordV1` that binds the exact
`benchmark-manifest-v1` IDs and contains all of the following:

1. Signed, reproducible exits for G0, G1, G1.5, every G2A–G2F contract, and
   the clean source/tree/SBOM hashes used by the run. A local candidate or a
   fixture cannot satisfy this dependency.
2. The 7/31/100 process matrix with explicit host/operator/region cardinality,
   process-to-failure-domain mapping, validator key proof-of-possession and
   measured RTT/loss/partition evidence. Any missing topology field fails the
   record.
3. Complete W0/W1/AI workload, fault, repair, recovery, cost and availability
   traces, with raw content roots, percentile denominators, replicate counts,
   confidence intervals and the §0.7 threshold binding. No orphan metric or
   unbound “TPS” number may enter the record.
4. Zero conflicting finality, double-sign, unauthorized validator-set
   acceptance, or state/JMT/post-state-root divergence in the admitted fault
   model; all safety and custody negative mutants remain rejected after
   restart, sync, key rotation and epoch handoff.
5. An evidence-backed Order retain/amend/replace ADR. A replacement additionally
   requires the new protocol version, safety/liveness model, two independent
   interoperable implementations, migration and light-client proof rules,
   WAN fault evidence, and independent review. Without those artifacts v1
   retains weighted chained HotStuff.
6. A signed bottleneck attribution and cost report. Public or investor-facing
   language is limited to achieved committed-goodput, finality, availability,
   proof/DA latency and normalised cost; a target or shadow result is labelled
   as such.

G3 promotion does not set `production_candidate` or any activation flag. A
failed G3 invariant reopens G3 and invalidates all descendant performance
claims until the earliest affected manifest is rerun.

## 8. G4 — adversarial and public-testnet validation

### Required campaigns

- 72-hour continuous chaos followed by 7-day and 30-day multi-region soak;
- repeated process and host power loss at every Safety, signer, DA, execution,
  outbox, finalization, sync, migration and whole-node checkpoint boundary;
- database, WAL, snapshot, namespace and full-machine rollback; disk full,
  corruption, fsync uncertainty, clock skew, key loss/rotation, HSM/KMS outage,
  network eclipse, DDoS, censorship, withholding, repair and GC pressure;
- unequal PoCO weight in shadow across many epochs, related-party/Sybil and
  correlated-penalty simulations, challenge and settlement adversaries;
- reproducible builds, signed artifacts, SBOM/provenance, dependency/license
  review, secret scanning, fuzzing, supply-chain and disaster-recovery drills;
  and
- independent full-node/parser interoperability, independent light client,
  external consensus/cryptography/DA/application/economics/security audits,
  and a public bug-bounty process.

### AI-native threat and abuse campaign

G4 MUST exercise the AI-specific attack surface, not only generic consensus
chaos. The test register has one row per threat with the form
`threat -> invariant -> negative mutant -> owner -> evidence root -> severity`
and includes, at minimum:

- model/data provenance, license and version substitution; private-prompt or
  input leakage; low-entropy commitment inference; malicious tool calls,
  evaluator poisoning and nondeterministic runtime/image/precision drift;
- artifact decompression bombs, oversized/deeply nested values, retention/GC
  abuse, DA withholding and repair amplification;
- TEE quote/TCB expiry, rollback, side-channel and key-release failures; ZK
  setup/VK/soundness, malformed-proof and verifier-cost failures;
- stake-verifier collusion, related-party/Sybil concentration, optimistic
  challenge griefing/timeout races, duplicate settlement, replay and
  provider/consumer insolvency; and
- credential/session-key compromise, remote-signer/HSM failure, privacy-policy
  bypass and unsafe emergency/governance actions.

Each enabled verification profile must have a positive vector, malformed and
replay vectors, expiry/revocation behavior, resource/cost limits, and an
explicit fail-closed response. An unenabled profile MUST be rejected on the
canonical wire; it cannot silently downgrade to `subjective` or
`StakeQuorum`. Subjective evaluation may expose a user-facing opinion only and
can never create objective settlement, PoCO weight, or a consensus proof.

### Developer, RPC, and light-client interoperability

Before public-testnet sign-off, the release candidate supplies a typed
`AgentTransactionV1` builder/signing path, wallet and remote-signer/HSM
interfaces, canonical error-code registry, and version negotiation. It ships
at least two independently tested language SDKs, JSON-RPC and WS schemas with
request/response limits, an indexer replay schema, local devnet/genesis/faucet
fixtures, examples for every enabled operation kind, and a conformance CLI.

The full node, parser and light client are separate authorities. The light
client implementation MUST be independently authored (no shared parser,
signature verifier, upgrade verifier or state-transition code), verify the
committed validator set, complete three-chain/QC/TC finality, epoch and
version handoffs, state/JMT roots and the declared DA certificate boundary,
and persist its highest accepted checkpoint before reporting success. State
sync installs into a staging namespace, replays and recomputes the target root,
then swaps atomically without overwriting Safety, signer, DA or anti-rollback
watermarks. RPC/WS/indexer replay and light-client vectors must be reproduced
by two builders and recorded in the same signed evidence index.

### Rollback and recovery semantics

Rollback is defined per authority domain and is never an implicit database
restore:

1. Before the first finalized PoCO block, an isolated old chain may resume
   only under the old chain ID and old signer domain; its data is not a v1
   checkpoint.
2. After any PoCO finality, no finalized block, WAL, SafetyState, signer
   watermark, validator set or application root may be copied back to Comet or
   silently downgraded. A recovery is a forward, versioned migration/new
   genesis event with a new trust statement, not a rollback.
3. A process crash may replay the exact durable prefix. A snapshot/WAL restore
   is accepted only after external monotonic anti-rollback evidence, namespace
   identity checks, signer fencing and fresh state/JMT/root verification; a
   database checksum alone is insufficient.
4. A public-testnet reset uses a new chain/genesis/manifest ID and is labelled
   a new network. It cannot be used as continuity or uptime evidence for the
   previous history.
5. Emergency governance may pause admission or rotate keys, but cannot rewrite
   order-finalized blocks. Any post-activation recovery follows the explicit
   upgrade/cutover proof and light-client trust rules; there is no automatic
   fallback to an old protocol.

### Public-testnet gate

A public testnet is admitted only by a signed `G4ExitRecordV1` containing the
prior G0, G1, G1.5, G2.0, G2A–G2F, G3 and the C0-preparation migration rehearsal
IDs, the campaign/incident index, the
benchmark-manifest IDs, topology and validator inventory, independent client
and SDK/RPC conformance results, rollback/recovery drills, audit dispositions,
and operator runbooks. It MUST demonstrate operational RPC/read APIs,
monitoring/alerts, incident replay, documented upgrades, backups/restores,
validator onboarding/key management, state-sync capacity, published limits,
and the §0.7 custody/availability floors over the declared denominator.

Severity is explicit: every Critical finding blocks G4 and G5. A High finding
that touches consensus, finality, custody, migration, light-client acceptance,
DA availability, settlement conservation, or upgrade authority also blocks
G4. A bounded, time-limited acceptance may be recorded for a non-safety High
finding only when it has an owner, mitigation, expiry, residual-risk test and
no effect on those domains; it is **not closed** and automatically blocks C0
and mainnet activation. C0 (replacement complete) requires all Critical/High
findings closed, as does G5; “accepted” is never treated as “closed”. PoCO
economic influence remains capped or shadow until the separate G5 economic
gate passes.

The G4 record also MUST show the exact 72-hour chaos window, 7-day and 30-day
soak windows, validator/process/host/operator/region counts, fault injection
coverage, incident-response time, state-sync/light-client replay, and the
availability/finality/API denominators used. It must bind every applicable
§0.7 floor to a raw trace and signed verifier result, demonstrate zero
conflicting finality or state-root divergence, and list every finding that
still prevents C0. Before this record can be signed, `MIG-COMET-POCO` must have
an independently replayed C0-preparation rehearsal: finalized source export,
fresh target genesis, target-root recomputation, cross-peer GenesisQC, and old
WAL/key/data-directory rejection. The rehearsal is a prerequisite, not proof
of final mainnet activation; G5 consumes and re-verifies it. A testnet uptime
graph without these boundaries is not a G4 exit.

## 9. G5 — economic, security, governance, and mainnet activation

G5 is the final economic, security, governance and activation gate. It cannot
be entered because a date, benchmark, private alpha, or public-testnet uptime
target was reached. The dependency chain is explicit:

`G0 -> G1 -> G1.5 -> G2.0 -> G2A -> G2B -> G2D -> G2C -> G2E -> G2F -> G3 -> G4 -> G5`.

Every predecessor exit, including the separate G1.5 specification/baseline
record and each G2A–G2F record, must be signed, reproducible and bound to the
same source/protocol/parameter hashes. A changed predecessor invalidates G5's
prepared release until the affected range is rerun.

The cutover document's `C0-replacement-complete` predicate is distinct from
G5: C0 consumes the technical G0–G4 and migration evidence and requires all
Critical/High findings to be closed; G5 consumes a signed C0 record before
mainnet activation and closes the economic/governance/activation authority.
No bounded acceptance can satisfy C0.

### Scope

- Freeze staking, validator weight, issuance, fee and resource-meter
  schedules, consumption prices, escrow/bond/slash/reward/refund/treasury
  rules, privacy limits and upgrade constants as versioned parameter hashes.
  The canonical fee schedule and resource-price root are inputs to every
  `SettlementIntentV1` and `SettlementReceiptV1`; they are never selected by a
  provider, client or wall clock.
- Make settlement a canonical state transition: AgentTransaction admission,
  multi-asset conservation, escrow and challenge-bond lifecycle,
  exactly-once retry/expiry, slash/reward/refund/treasury accounting,
  dust/rounding rules, insolvency behavior, and PoCO-weight eligibility all
  require JMT inclusion and replay vectors. Run solvency, incentive,
  Sybil/related-party, correlation, MEV, griefing and fee-spam simulations;
  PoCO economic weight remains capped until this record passes.
- Implement governance as versioned protocol objects and wire, at minimum
  `GovernanceProposalV1`, `GovernanceVoteV1`, and `GovernanceDecisionV1`, with
  committed authority-set membership, threshold/weight rules, notice and
  timelock, emergency pause limits, veto/appeal, key rotation, upgrade and
  cutover proofs. A self-signed new set, operator-only file or uncommitted
  manifest is not governance authority. An independent client must verify the
  membership, decision and activation proof.
- Complete independent consensus, cryptography, runtime/contract, DA,
  economics, key-custody, AI-profile, supply-chain and operational reviews.
  Publish the threat-to-invariant register, SBOM/provenance, reproducible-build
  records, audit findings, bug-bounty scope, disclosure process, and every
  residual risk with owner, mitigation, expiry and severity. Critical and High
  findings must be closed for C0 and G5; bounded acceptance is never closure.
- Operate the public testnet through documented upgrade, incident,
  backup/restore, state-sync, validator onboarding, key rotation, rollback,
  and disaster-recovery drills. Require two independent builders, two
  interoperable consensus/light-client paths (or a reviewed independence
  plan), typed SDK/RPC/WS/indexer conformance, and an independently authored
  light client that verifies finality, validator-set handoff, state/JMT roots
  and DA boundaries.
- Consume and independently re-verify the G4 C0-preparation rehearsal for
  `MIG-COMET-POCO`, then perform the final cutover ceremony: finalized legacy
  export to a fresh PoCO genesis on independent nodes, independently
  recomputed target roots, validator and governance membership proof, and
  GenesisQC ceremony evidence. Prove that old Comet data, keys, WALs, signer
  watermarks and rollback paths cannot regain authority. This is separate from
  `UP-V0-V1`; neither path may be substituted for the other.
- Produce a machine-verified, signed release manifest binding the exact source
  commit and tree hash, canonical plan/plan-manifest hash, protocol/status/
  parameter manifests, toolchain, binaries/images, SBOM, benchmark-manifest
  IDs, telemetry, process/host/operator/region topology, fault schedule,
  audit disposition, genesis/migration proof, governance decision, rollback
  policy and activation parameters. The manifest must replay from a clean
  clone and fail closed on any hash or dependency drift.

### Exit gate

Mainnet activation requires a signed `G5ExitRecordV1` and an explicitly
finalized activation decision containing, at minimum:

1. G0, G1, G1.5, G2A–G2F, G3 and G4 exit IDs, the signed C0 replacement
   record, exact source/tree/plan/protocol/parameter hashes, and a clean-clone
   replay of the release manifest.
2. Frozen economics and governance objects/vectors: fee/resource schedule
   root, multi-asset conservation and solvency proofs, escrow/bond/slash/
   reward/refund/treasury accounting, challenge maturity, validator-weight
   eligibility, authority-set membership, threshold/timelock/emergency rules,
   and an independent client verification of the activation decision.
3. Consensus, cryptography, DA, AI-profile, key-custody, runtime, supply-chain,
   privacy and operational audit reports; the complete threat register;
   reproducible binaries/SBOM; bug-bounty disposition; incident-response and
   disclosure readiness; and no open Critical or High finding. Any residual
   risk must be explicitly outside the activation scope and cannot affect
   safety, finality, custody, migration, light-client acceptance, DA,
   settlement conservation or upgrade authority.
4. Public adversarial and multi-epoch upgrade evidence, including validator
   onboarding and key rotation, state-sync, independent light-client/full-node
   replay, rollback/recovery drills, and two-builder SDK/RPC/WS/indexer
   conformance. No benchmark-only or uptime-only result substitutes for this.
5. A completed `MIG-COMET-POCO` export/genesis/GenesisQC rehearsal and a
   separately completed `UP-V0-V1` transition proof where v1 activation is in
   scope. Old data, keys, WALs, signer state and downgrade paths must be
   cryptographically and operationally fenced.
6. A threshold-governance activation signature over the exact release
   manifest, chain/genesis ID, validator set, activation height/epoch,
   parameter roots and rollback policy. The first finalized block and its
   light-client proof must be reproducible by independent builders.

Flag semantics remain machine-owned and distinct:

- `zero_comet_production_dependency_achieved` (or its versioned successor
  `zero_comet_active_dependency`) describes only the normal Cargo/build
  dependency closure and may be true before cutover;
- `comet_replacement_complete` changes only after the signed C0 migration and
  cleanup predicate, including Critical/High closure;
- `production_candidate` changes only after the signed G5 release record; and
- `production_consensus_activation` changes only after the finalized
  governance decision and first authorized activation evidence.

The plan, a benchmark, or a manually edited TOML/JSON value can change none of
these flags. Mainnet activation is irreversible for the finalized history:
before the first PoCO finality, an isolated old chain may resume under its old
identity; after PoCO finality, recovery is only a forward governance-approved
migration/new-genesis event. A pause, key rotation or emergency repair cannot
rewrite a finalized block or silently downgrade the protocol.

## 10. Reporting cadence and stop conditions

### 10.1 Evidence index and reporting contract

Each gate publishes a signed evidence index with a unique `evidence_epoch` and
content-addressed records for source commit/tree, canonical plan and
plan-manifest hashes, protocol/status/parameter manifests, toolchain,
binaries/images, SBOM, topology, workload and fault manifests, raw traces,
formal/vector/test output, audit findings, known gaps, owner, and exact machine
flags proposed for change. The index names the gate, predecessor exit IDs,
metric bindings, commands, verifier identity and independent reproduction
result. A weekly report states only changed evidence, blockers and invalidated
records; it never turns a percentage, green unit test, or candidate-local flag
into readiness.

The index MUST distinguish `scope` (`crate`, `fixture`, `process`, `host`,
`network`, `production`) and `authority` (`candidate`, `simulation`,
`normative`, `production`). Any bounded fact currently written as an unscoped
positive (for example `whole_node_finalization_cas=true`,
`normal_build_finalization_owner_issuer=true`, `source_plane_finalization_apply=true`,
or `node_process_integration=true`) is historical candidate wording until
renamed to a scoped form such as
`candidate_local_<surface>_<fact>=true` with `authority=candidate`. Aggregate
and production readers MUST treat an unscoped candidate positive as false;
CI MUST reject a new unscoped production-like `*_true` field.

### 10.2 Downstream invalidation and deterministic re-run

Evidence is a dependency graph, not a checklist of independent green lights.
When a predicate changes, all descendants that consumed it become
`invalidated` and cannot be copied into a new release:

| Changed/failed authority | Records automatically invalidated | Required re-run boundary |
| --- | --- | --- |
| G0 native boundary, dependency, toolchain or source tree | G1 onward, all benchmark/client/release artifacts | G0 clean-clone and dependency/SBOM closure |
| G1 Core/Safety/Node/CAS or finality semantics | G1.5 onward, all v1 vectors, performance and migration evidence | G1 focused/crash/replay matrix, then downstream gates |
| G1.5 schema/domain/vector freeze or v0 baseline | G2 onward, wire/client/benchmark artifacts | G1.5 conformance and baseline, then G2 |
| Any G2A–G2F wire, root, execution, verification or settlement contract | G3 onward and every dependent SDK/light-client/release record | Affected G2 contract plus vertical traceability, then G3 |
| Validator set, topology, workload, comparator or benchmark denominator | G3 onward performance/surpass claims only | New `benchmark-manifest-v1` and complete affected runs |
| Migration/genesis/upgrade/governance/parameter root | G4/G5, C0/C1 and light-client/state-sync records | Migration and independent-client proof from the changed root |
| Critical/High security or custody finding | The affected gate and C0/G5 activation | Retained mutant, remediation, independent review and campaign rerun |

The earliest invalidated gate is the rerun start. A rerun increments
`evidence_epoch`, retains the failing mutant and prior report, regenerates all
hashes, and requires independent verification. No later gate may be “patched”
by editing its report, reusing an old denominator, or replacing a failed
artifact with a summary. A source/manifest change that does not identify its
invalidation set is itself a release-manifest failure.

### 10.3 Fail-closed stop conditions

Work stops immediately on conflicting finality, double-sign, unauthorized
validator-set acceptance, state/JMT/post-state-root divergence, lost durable
obligation, unavailable certified data inside its promise, nondeterministic
migration or MVCC result, settlement/asset imbalance, invalid proof/profile
downgrade, light-client acceptance of an unauthorized set, whole-node
checkpoint ambiguity, anti-rollback failure, unsafe key custody, or a
truth-manifest/release mismatch. The affected gate and every descendant are
reopened under §10.2 after root cause, retained regression mutant,
remediation, independent review and a fresh signed evidence index.

## 11. Current blocker board and immediate queue

The former five-file compile blocker is closed as a source defect by
`fcdc16104`; it is retained in the dated audit record for provenance. The
current cumulative source head is `236a7b50b`. Its candidate tranches have
reproducible local tests, but none of those tests is a signed gate exit. The
remaining blockers are concrete engineering boundaries:

1. **G1 authoritative host/Core/Safety/CAS:** the real-process host is a
   fixture-only composition. It does not drive the production Node effect
   loop, Core-owned Vote/Timeout authority, whole-node checkpoint CAS, or
   network broadcast. `G1-S01` through `G1-S03` remain open.
2. **G1 arbitrary corpus and fault closure:** required non-empty v0 corpus,
   physical power-loss campaign, signer/Safety rollback matrix, and independent
   whole-node crash/replay evidence are not complete. Genesis, H1 TrustedBase
   and finalized application commits now retry database-and-directory sync
   fail-closed under injected uncertainty. Separate-process SIGKILL matrices
   cover pre-commit, committed-before-fsync and post-fsync cuts for initialize,
   H1 TrustedBase and finalized application commit. That campaign exposed and
   closed the pre-genesis hot-journal bug: recovery accepts only an exact virgin
   schema with empty metadata/P/H1 inventory; any partial inventory fails
   closed. These are software/process results only;
   `power_loss_fsync_matrix` remains `NOT_EVALUATED`, the 100,000-block corpus
   has not run, and no whole-node anti-rollback assertion is promoted. The
   additional metadata-missing/P-or-H1-residual negative is now covered in
   both live initialize and reopen; a metadata-missing all-empty image remains
   indistinguishable from a genuinely virgin file without an external anchor.
3. **G2.0 authenticated nested transport:** semantic wire parsing checks
   scope/shape/bounds/roots, and P2P candidate verifies the outer session frame
   plus nested Vote/TimeoutVote/QC/TC signatures. An opt-in private anchor now
   rejects an exact old handshake after process restart and detects journal or
   retained-sidecar divergence, but both files can still be rolled back
   together without an external monotonic authority and the frame bitmap is
   session-object local. Socket/peer lease, a non-cloneable network owner,
   durable frame replay, Core integration and independent network replay remain
   open; P2P remains candidate-only.
4. **MIG-COMET-POCO provenance and cutover:** the offline exporter now rejects
   ambiguous duplicate-key/trailing/unknown-field JSON and zero-height source
   state; the rehearsal also requires canonical validator and QC signer order
   and remains deterministic/fail-closed. There is still no
   trusted Comet DB reader/finalized source anchor/real target JMT writer/dual
   quorum/old WAL-key-data-dir rejection/node-start cutover. MIG-ROOT/G4/C0
   remain open; caller-supplied witnesses cannot close them.
5. **G3/G4 release evidence:** seven/31/100-validator WAN fleet, independent
   full/light clients, interop, benchmark manifest, security campaign, public
   testnet ops have not run. Candidate-local metrics cannot be reported as
   surpassing a first-line chain.

Owner must next commit only independently tested source changes, rerun the
earliest affected gate from a clean clone, retain mutants/raw traces, and
update the signed evidence index. Source/protocol/validator/migration/
benchmark changes invalidate descendants under §10.2; no plan edit or local
fixture waives that rule. Production flags remain false until signed exits.
