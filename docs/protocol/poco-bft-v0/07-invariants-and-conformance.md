# 07 — Invariants, Formal Obligations, and Definition of Done

## 1. Status

This document freezes what must be demonstrated; it does not claim that the demonstrations already exist. P0 is not complete merely because prose has been written.

## 2. Safety invariants

The following properties are normative and ordered by safety priority.

### S1. Finalized-prefix agreement

For any two correct validators `A` and `B`, their finalized block sequences are prefix-comparable. Equivalently, correct validators never finalize conflicting blocks. Same-height uniqueness follows as a corollary.

### S2. QC validity and weighted intersection

Every accepted QC contains unique valid votes from the exact active set with recomputed weight at least `floor(2W/3)+1`. Any two such quorums for the same set overlap in more than one third of total effective weight. Under the fault bound, that overlap includes correct weight.

### S3. Durable non-equivocation

A correct validator signs at most one normal vote digest for each `(genesis, chain, protocol_version, epoch, view)`, including across crashes, restores, signer retries, and node/signer restarts.

### S4. Lock monotonicity and safe vote

Within an epoch, a correct validator's locked-QC view never decreases. It votes only for a descendant of its lock or for a proposal justified by a strictly higher QC.

### S5. Three-chain finality soundness

Only a valid direct chain of three certified blocks can trigger ordinary
finality, and it finalizes exactly the oldest block plus its ancestors. Every
certified header retains a verifiable proposer signature over its exact
justify-QC and optional TC/handoff digests; b1 and b2 cannot substitute a
different valid QC signer-subset digest for q0 or q1. Views may skip only with
the exact preceding-view TC, must strictly increase, and heights/parent links
may not skip.

### S6. TC non-finality and non-unlock

A timeout certificate can advance a view and select its maximum referenced valid high QC. It cannot certify, finalize, lower a lock, clear a lock, or authorize a vote that fails the safe-vote rule.

### S7. Certified ancestry

Every correct vote and finalization decision is based on locally verified parent ancestry and the exact justify certificates. Height equality or peer assertion never substitutes for ancestry.

### S8. Epoch isolation and joint handoff

Ordinary QCs and finality do not mix validator sets or protocol versions. The old checkpoint is finalized under the old set; exactly one bridge descriptor obtains both an old-set and a new-set quorum; no new-epoch normal vote occurs before that joint certificate.

### S9. Crash-state monotonicity

Recovery never lowers epoch, view, lock, high QC, finalized height, or the set of durable signing decisions. Ambiguous or corrupt recovery fails closed.

### S10. Deterministic execution roots

Given the same finalized parent state, parameters, and ordered payload, correct validators compute identical validity, state root, receipts root, and evidence root. A validator obtains and executes the full payload before voting.

### S11. Light-client soundness

A light client starting from a recent correct trusted checkpoint accepts only descendants finalized according to the exact committed set sequence and joint transitions. It never accepts a set solely because that set signed itself.

### S12. Upgrade atomicity

At a height, all correct validators use the same protocol version and consensus parameters. A change occurs only at the committed epoch activation height through the joint handoff; unknown versions fail closed.

### S13. Canonical parsing and domain separation

Each accepted logical object has exactly one `CEV0` encoding. A valid signature or digest cannot be replayed across genesis, chain, protocol version, epoch, active set, view, message kind, or object domain.

### S14. Bond backing

For every non-shadow active validator, effective weight is no greater than raw PoCO capacity or bond capacity, and the counted bond remains slashable through the active/evidence windows.

### S15. Deterministic snapshot

All correct nodes given the same finalized snapshot state and parameters compute byte-identical next-set candidates, effective weights, fallback result, set hash, and epoch commitment.

### S16. Certificate uniqueness, maturity, decay, and caps

One certificate ID contributes at most once; immature, expired, revoked, challenged, or ineligible certificates contribute zero; hierarchical caps and decay are order-independent checked-integer functions.

### S17. Objective evidence idempotence

All correct nodes agree whether normalized double-vote evidence is cryptographically valid, and any disposition is applied at most once per evidence ID.

## 3. Conditional liveness properties

These properties are required only under the liveness assumptions in the threat model.

### L1. Post-GST view progress

After GST, timeout growth and valid QC/TC processing eventually place enough correct online weight in a common view with a correct leader.

### L2. Post-GST finalization

With a reachable correct quorum, available payload/state, compatible software, and recurring correct leaders, the protocol eventually forms direct three-chains and finalizes blocks.

### L3. Partition stall and heal

A partition lacking quorum may stall without violating safety. Once healed after GST, correct nodes converge on certified ancestry and resume without manual lock deletion.

### L4. Epoch-transition progress

If both the old set and committed new set have reachable correct quorums and
support the authorized versions, the checkpoint finalizes, the joint handoff
forms, and the new epoch progresses. Failure of the new epoch's initial
view-1 leader is recoverable by TC-driven view change while the authorized
view-0 epoch anchor remains the selected high QC.

No liveness property applies when a required new-set quorum is offline or the network remains asynchronous.

## 4. Formal-model obligations

P0 formal work MUST model the protocol independently of Rust implementation details. TLA+ and/or Quint models must cover at least:

- 4- and 7-validator configurations;
- equal and non-equal integer weights, including threshold boundaries;
- Byzantine proposals, votes, timeouts, withholding, and equivocation;
- message loss, duplication, reordering, partitions, and healing;
- crashes and recovery around every persist-before-sign boundary;
- high-QC and lock updates;
- TC construction with heterogeneous referenced high QCs;
- skipped views and non-consecutive certified views;
- epoch checkpoint, both seals, joint handoff, fallback set, and first new block;
- a failed initial genesis/epoch leader followed by TC-driven first-block
  progress from the context-authorized synthetic anchor;
- authorized, premature, unsupported, and conflicting upgrades;
- light-client transition verification at the trusting-period boundary.

The model checker must establish at minimum S1–S9 and S12. Arithmetic/snapshot properties S13–S17 require executable property tests or a separate bounded model where appropriate.

Required mutant checks must demonstrate that the suite finds intentional defects, including:

- changing the quorum to `floor(2W/3)`;
- counting duplicate signers;
- allowing a TC to clear a lock;
- allowing two post-crash votes in one view;
- omitting genesis, set hash, view, or message kind from a signing digest;
- activating a new set with only one handoff quorum;
- activating before checkpoint finality;
- rounding PoCO arithmetic upward or applying caps in iteration order;
- accepting a self-signed uncommitted light-client validator set.

Initial bounded Quint artifacts now live in `formal/quint/poco-bft-v0`. They
cover a four-validator equal-weight three-chain/lock safety kernel, an explicit
persist-before-sign crash boundary, and 4-/7-validator weighted-quorum
intersection (including non-equal weights). Small TC-lock and dual-quorum joint
handoff models plus retained negative mutants are also present. A dedicated TC
model now checks complete exact QC references, the
`(view, block_id, qc_digest)` tie-break, benign same-block QC variants, and
same-view/different-block fail-stop. A four-validator partition/heal model
checks safety under loss/delay/drop and includes a finite fair-heal progress
witness. A bounded light-client model rejects a self-signed uncommitted set and
checks the inclusive trusting-period/freshness boundary. The bounded upgrade
model covers finalized notice, checkpoint/two-seal order, both handoff
quorums, supported versions, activation height, and the first new block, with
a retained premature-activation mutant. A dedicated bounded anchor model covers
a failed view-1 leader, timeout quorum over the exact context-authorized anchor,
TC advance, and the view-2 first block at the unchanged activation height. Its
candidate-validation predicates reject a wrong selected anchor and attempts to
use an empty-signature anchor as a certifying/finality QC; this remains a model
of semantic acceptance, not a parser or cryptographic proof. These models do
**not** yet satisfy this section's complete obligation: deeper 7-node and
repeated/adversarial partitions, multiple skipped anchor views, weighted anchor
timeouts, full fallback construction, and multi-hop light-client sequences
remain required.

## 5. Wire and cryptographic conformance

Before a node claims protocol-v0 interoperability, the project MUST publish machine-readable golden vectors for:

- every `CEV0` primitive boundary and all frozen logical objects;
- all domain-separated digests and valid Ed25519 signatures;
- validator-set and parameter hashes;
- QC/TC exact-threshold and one-below-threshold cases;
- direct three-chain finality and malformed near-misses;
- checkpoint/seal/handoff/upgrade transitions;
- Consumption Certificate digest, ID, acceptance, maturity, decay, and caps;
- light-client same-epoch and cross-epoch proofs;
- wrong-chain/version/epoch/set/view/kind/domain replays;
- non-canonical, duplicate, overflow, unknown-enum, and trailing-byte rejection.

At least one implementation independent of the Rust node MUST reproduce the vectors.

## 6. Deterministic core conformance

The P1 core accepts explicit events and returns deterministic actions. Its trace corpus MUST include:

- proposal before/after lock changes;
- vote then timeout in one view;
- multiple timeout high QCs and deterministic TC selection;
- late QC after timeout;
- crash before persist, after persist, after sign, and before broadcast;
- stale disk/signer disagreement fail-stop;
- conflicting proposals and double-vote evidence;
- checkpoint, seals, handoff, first-new-block, and epoch-local reset;
- invalid execution roots and unavailable payload;
- parameter and arithmetic boundary failures.

Repeated runs with the same inputs must produce byte-identical logical outputs and final safety state.

## 7. P0 definition of done

P0 is complete only when all of the following are true:

1. The normative documents have no unresolved safety-affecting contradiction or implicit implementation choice.
2. Every `UNDECIDED` item is demonstrably outside the active safety path, causes fail-closed behavior, or is resolved before the phase that needs it.
3. `parameters.toml` parses and all documented cross-parameter inequalities hold.
4. Logical schemas, domains, canonical field order, thresholds, comparisons, and overflow behavior have golden vectors.
5. A TLA+/Quint model satisfies the required invariants and mutant checks in the bounded configurations above.
6. The threat model and safety/liveness assumptions are reviewed by a consensus engineer independent of the author.
7. The Consumption Certificate and weight formula are reviewed for deterministic behavior; no mainnet-economic claim is made.
8. Every normative conflict found by review is either repaired in this version or explicitly blocks P1 entry.

At the current P0 implementation point, the bounded Quint models and the
independent Python parameter and foundational-wire encoders/vectors exist.
Full-object/signature/rejection vectors, deeper bounded symbolic evidence, the
remaining formal scenarios, independent consensus-engineer review, and
complete implementation evidence do not. These gaps continue to block P0
completion and MUST remain visible in project status.

## 8. P1 definition of done

P1 requires a pure deterministic core, reference verifier, fault simulator, crash journal model, property tests, and formal-model agreement. It must have no network, database, system-clock, or signer side effects in the core and must pass all trace/golden-vector obligations relevant to it.

## 9. P2 definition of done

P2 requires authenticated P2P, WAL/sign journal, remote signer, catch-up/state sync, runtime/JMT integration, and reproducible 4-/7-node campaigns covering crash, equivocation, partition/heal, restart, disk-full, corrupt/stale state, invalid chunks, and unavailable payload. Safety violations are zero-tolerance; expected quorum-loss stalls are not failures if recovery is correct.

## 10. P3 and P4 gates

P3 must complete shadow observation, anti-collusion simulation, bond/unbond/jail/slash semantics, economic parameter freeze, and external economic review before staged activation. P4 must complete multi-region 7-to-20-node campaigns, resource/DA/network attacks, 7–30 day soak, independent light-client verification, and external consensus/cryptography/economic audits.

No soak duration or test count substitutes for a failed invariant or unresolved safety ambiguity.
