# TRNM PoCO-BFT Delivery Plan — 2026-08-04

Status: **active engineering plan; no phase is complete**

Working branch: `feature/chain-poco-bft-v0`

This plan supersedes schedules that promote the CometBFT application fixture
to production consensus authority. CometBFT remains a differential oracle;
the existing deterministic runtime and JMT/ICS23 assets remain integration
targets.

## Execution boundary

- The development workstation may edit source, compile with Cargo, run unit,
  property, simulator, formal, and isolated integration tests, and build
  immutable release artifacts.
- It must not run persistent validator, node, signer, RPC, monitoring, fault,
  or soak services and must not hold live node state or validator keys.
- Deployment, LAN/public validation, fault campaigns, and soak run through
  ordinary OpenSSH on `p4-x230`, following
  `../runbooks/TRNM_POCO_BFT_X230_DEPLOYMENT_BOUNDARY.md`.

## Phase board

| Phase | Target window | Current state | Exit authority |
| --- | --- | --- | --- |
| P0 protocol freeze | 2–4 weeks | In progress | Normative spec, full vectors, required bounded/exhaustive formal evidence, independent consensus review |
| P1 deterministic core | 6–8 weeks | Prototype in progress | Pure core, crash journal model, verifier, fault simulator, trace/property/formal agreement |
| P2 real node | 6–10 weeks | Not started | Authenticated P2P, WAL/sign journal, sync, remote signer, runtime/JMT adapter, remote 4/7-node campaigns |
| P3 PoCO economic safety | 8–12 weeks | Spec/reference profile only | Certificate pipeline, bond/jail/slash, deterministic snapshots, anti-collusion simulation, staged observation/review |
| P4 public validation | after P3 gates | Not started | 7→20 nodes, multi-region attacks, 7–30 day soak, external audits, independent light client |

Windows are planning estimates, not readiness promises. A later phase may be
prototyped early, but it cannot inherit a completed label from partial work in
an earlier phase.

## P0 work packages

### Present in the branch

- PoCO-BFT v0 architecture decision, system/threat model, chained-QC rules,
  CEV0/domain separation, epochs/upgrades, PoCO/bond weights, light-client
  rules, conformance obligations, and reference parameters.
- Bounded protobuf transport projections. Protobuf bytes are never signing
  bytes; strict validation reconstructs CEV0.
- Normative Consumption Certificate v0 logical body.
- Bounded Quint kernels for three-chain/lock safety, persist-before-sign
  crashes, 4-/7-node weighted quorum, heterogeneous TC selection,
  partition/heal, joint handoff, light-client commitment/freshness,
  upgrade atomicity, deterministic PoCO weight snapshots, and synthetic-anchor
  first-leader view change, with retained negative mutants.
- Independent Python CEV0 parameter encoder and committed byte/digest vector.
- Independent foundational wire vectors for all frozen domains, common
  context, block ID, signing roots, and validator-set hash.
- Review-corrected exact synthetic-anchor, signed CertifiedHeader/finality,
  handoff-descriptor-domain, and first-leader view-change schemas; obsolete
  experimental proof/handoff digests are explicitly invalid.
- Bounded symbolic Apalache evidence for same-height finality safety through
  depth 10; the 20-step attempt is recorded as inconclusive rather than pass.
- `trnm-consensus-types` implementation scaffold and a pure core prototype
  with transactional steps, durable signing/finality outboxes, replay gates,
  validated ancestry, and persistent conflicting-QC fail-stop.
- `trnm-consensus-sim` now provides an epoch-0 deterministic scaffold with 11
  passing tests: 3 focused unit tests and 8 end-to-end scenarios. The suite
  covers complete per-node applied-finality prefix comparison,
  persistence-before-sign crash rollback, a running crash from nonzero durable
  state through safety replay, durable conflicting-QC halt and restart,
  4-/7-validator quorum-loss boundaries, 2+2 partition/heal, and consumed
  drop/duplicate/delay/reorder rules with repeat-stable traces.

### P0 blockers

- Resolve every remaining schema/spec/implementation mismatch and publish a
  machine-readable source of truth for all frozen logical objects.
- Add valid/invalid Ed25519 and full-object CEV0 vectors, parser rejection
  vectors, exact-threshold QC/TC vectors, epoch/upgrade/finality/evidence/light
  client vectors, and a second implementation independent of both the Rust
  node and the current Python foundation encoder.
- Deepen formal coverage from the present 4-/7-node weighted kernels,
  heterogeneous TC selection, one-shot partition/heal, persist-before-sign,
  joint handoff, upgrade atomicity, weight snapshots, and trusting-period
  boundary models to all persistence crash points, repeated/adversarial
  partitions, multiple skipped anchor views, weighted anchor timeouts, complete
  fallback construction, and multi-hop light-client transitions. Retain and
  expand the failing-mutant suite.
- Obtain independent consensus-engineer review. Economic constants and slash
  policy remain non-production and separately block P3 activation.

## P1 critical path

1. Align Rust protocol types and canonical digests byte-for-byte with P0.
2. Keep the core free of network, database, filesystem, clock, randomness, and
   signer side effects.
3. Enforce `PersistDecision -> StorageAck -> RequestSignature ->
   SignatureReady -> Broadcast`; no error path may skip the durable boundary.
4. Implement proposal validation, leader schedule, safe vote, weighted QC,
   heterogeneous-high-QC TC, monotonic lock/high-QC, direct three-chain commit,
   double-sign evidence, epoch checkpoint/seals/handoff, and crash recovery.
5. Expand the existing deterministic fault simulator into the complete
   canonical replay corpus. The current 11-test epoch-0 scaffold covers
   consumed loss/duplication/delay/reorder faults, quorum-loss stalls,
   partition/heal, equivocation evidence, durable conflicting-QC halt,
   pre-ack crash rollback, and one nonzero-state safety replay. P1 still
   requires a self-contained trace decoder/replay API, the remaining
   persist/sign/broadcast crash points, invalid and unavailable payloads,
   stale disk/signer disagreement, heterogeneous TC races, unequal weights,
   and epoch-transition scenarios.

P1 output is a library and simulator, not a locally running service.

## P2 remote validation ladder

P2 begins only after the safety types/core gates are green. Build immutable
artifacts locally, checksum them, transfer them to X230, and deploy remotely.

1. One-node storage/signer recovery fixture.
2. Four-node authenticated fixture: one crash/Byzantine-equivalent tolerance.
3. Seven-node fixture: two crash/offline/equivocating participants.
4. Partition campaigns: quorum/minority, non-quorum splits, delayed/reordered
   traffic, heal, catch-up, stale-state rejection, corrupt/incomplete chunks.
5. Runtime/JMT equivalence against the CometBFT oracle, including speculative
   overlays for multiple unfinalized blocks.

Every run records immutable evidence on the remote host. Expected stalls under
quorum loss are acceptable; conflicting finality, journal rollback, or root
divergence is a zero-tolerance failure.

## P3 staged activation

Consumption Certificates and weights enter `shadow` first. The reference
profile has `production_activation = false` and forbids leaving shadow.
Eligibility-only, capped-weight, and full-weight activation each require a
finalized epoch-boundary decision, the minimum observation window, deterministic
snapshot/fallback evidence, anti-reciprocal-consumption analysis, bond coverage,
and the applicable external review. Promotion is never automatic.

## P4 public gate

The public ladder expands 7→20 nodes across regions and providers. It includes
data-availability withholding, disk-full/slow disk, OOM/CPU/file-descriptor
pressure, network flood/delay/reorder/partition, signer outage/replay, sync
poisoning, and operator-error drills. The final gate requires a continuous
7–30 day soak, independent light-client implementation, and external consensus,
cryptography, and economic audits.

No throughput number, uptime percentage, or soak duration overrides a failed
safety invariant or unresolved protocol ambiguity.
