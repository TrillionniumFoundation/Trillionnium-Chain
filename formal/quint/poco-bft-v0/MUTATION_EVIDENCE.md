# PoCO-BFT v0 formal mutation evidence

Initial date: 2026-08-04
Last updated: 2026-08-05
Tool: `@informalsystems/quint@0.32.0`, Rust evaluator `0.6.0`

## Mutation-calibrated conflicting-finality kernel

The repaired `poco_bft.qnt` transition admits every nonempty vote batch,
including singleton batches, and forms a QC only after cumulative votes reach
the exact three-of-four quorum. A deterministic legal lane reaches ordinary
three-chain finality in four steps. The retained `unsafeForkStep` mutation
removes only the safe-vote/lock gate and reaches conflicting finality in eight
steps, with finalized set `{1, 2}`.

Using the same finite model, Apalache found the expected legal reachability
witness at depth 4 and the expected mutation counterexample at depth 8, while
the normal nondeterministic transition passed `noConflictingFinality` through
depth 10. This keeps the fine-grained singleton paths and demonstrates that
the symbolic bound is deep enough to expose the modeled failure when its
decisive safety gate is disabled. Exact tool versions, source and log hashes,
and the bounded-proof limits are recorded in
[`APALACHE_EVIDENCE_2026-08-05.md`](APALACHE_EVIDENCE_2026-08-05.md).

## Missing durable view monotonicity

The first bounded model enforced one honest vote per view and the locked-QC
safe-vote predicate, but did not persist a monotonic `lastVotedView`.

The seeded run found a counterexample to `noConflictingFinality`: honest
validators could sign the future conflicting branch while still unlocked,
then sign lower-view blocks on the first branch, acquire locks, and reuse the
already-signed future votes to build the second three-chain. Both height-one
blocks became finalized.

The repair adds `lastVotedView` to durable safety state, requires every new
honest vote to have a strictly higher view, and advances the journal value in
the same transition as the vote intent. The same 10,000-sample, 30-step seeded
run then reported no violation.

This is a protocol requirement, not merely a model convenience:

- `last_voted_view` must be fsynced before requesting a local or remote
  signature;
- recovery must reject a journal snapshot that moves it backwards;
- a timeout certificate never authorizes a lower-view vote;
- remote signers must enforce the same conflict key independently.

Random exploration is not exhaustive proof. The counterexample and repaired
run remain useful mutation evidence; the current bounded symbolic result is
recorded separately and does not constitute an unbounded proof.

## Signing before durable acknowledgement

`persist_before_sign.qnt` makes volatile requests, durable journal decisions,
released signatures, and process crashes separate transitions. The checked
model permits `sign` only for an exact decision already present in the durable
journal.

`mutants/sign_before_persist.qnt` intentionally changes that guard to accept a
volatile pending request. The CI script requires this mutant to violate
`signatureCoveredByJournal`; if it unexpectedly passes, the entire formal gate
fails. This retained negative control prevents a green run from merely showing
that the model never exercised the durability boundary.

## Duplicate signer weight

`weighted_quorum.qnt` stores votes as a set keyed by validator and branch. Its
four-validator mode uses weights `(3, 3, 2, 2)`, total weight `10`, Byzantine
weight `3`, and quorum `7`; its seven-validator mode uses unit weights, two
Byzantine validators, and quorum `5`.

`mutants/duplicate_signer_weight.qnt` deliberately adds validator 0's power a
second time whenever that signer is present. The seeded checker finds two
conflicting QCs without any honest validator voting on both branches. The CI
gate requires that violation, demonstrating why signer uniqueness must be
checked before summing weight.

## TC lock clearing

`tc_lock.qnt` changes only operational view and the learned high-QC watermark
when a valid timeout certificate is received. `mutants/tc_clears_lock.qnt`
instead sets every lock to genesis. The gate requires that mutant to violate
`tcDoesNotUnlock`, retaining a negative control for the normative rule that a
TC is neither a QC nor an unlock certificate.

## Heterogeneous TC references and deterministic high-QC selection

`tc_high_qc_selection.qnt` gives each timeout entry an exact opaque QC digest
and separately stores the de-duplicated referenced-QC table. The normal model
requires that table to equal the set of digests named by the entries. A valid
bounded witness carries digests for `(view, block_id, qc_digest)` values
`(1,10,11)`, `(2,20,22)`, and `(3,30,34)` and selects the last one. Selection
is checked by view, block id, and finally lexicographic canonical QC digest,
rather than by arrival order or an underspecified view-only comparison.

Another accepted witness carries digests 22 and 24 for the same view 2 and
block 20, representing distinct signer subsets over the same certified block.
This is not equivocation. The digest tie-break selects 24 uniquely. Digest
integers preserve byte ordering only as a bounded abstraction of the frozen
lexicographic digest comparison.

A second witness carries QCs for different blocks 20 and 21 in view 2. The
validator retains that conflict as a halted state, rejects the TC, selects no
high QC, and does not advance operational view.

`mutants/tc_omits_referenced_qc.qnt` deliberately builds three timeout entries
for digests 11, 22, and 34 while transporting only digests 11 and 34. The CI
gate requires a counterexample to `completeUniqueQcReferences`. This negative
control ensures the positive model cannot pass merely because it looks up QCs
from ambient state or silently discards a heterogeneous timeout entry.

The normal TC invariants use 10,000 traces of at most 20 steps with seed
`0x54524e4d`. Each dedicated acceptance/halt reachability check is a one-step
bounded trace from an explicit initializer. These checks do not cover
arbitrary certificate sizes, cryptographic digest collisions, decoding, or
unbounded view histories.

## Synthetic anchor used as a certifying/finality QC

`anchor_view_change.qnt` fixes four equal validators and quorum three. It has
separate trusted-genesis and authorized-epoch modes. In both modes the exact
anchor is view 0, carries zero signatures, and points to the height immediately
before the first block. Epoch authorization additionally requires terminal-old
finality plus independent old/new handoff authorization; the missing-new-quorum
mode cannot advance.

The two valid bounded traces deliberately fail the scheduled view-1 leader.
Three unique timeout signers reference the exact context anchor, an explicit TC
candidate selects that same anchor, and the shared TC acceptance relation lets
the pacemaker advance to view 2. Validator 1 is the scheduled view-2 leader and
proposes the first block at the unchanged genesis-first or epoch-activation
height. Three ordinary votes—not the empty anchor—then form the first ordinary
QC. Separate positive candidates demonstrate that the same certifying-QC and
finality predicates accept an ordinary QC and a direct three-ordinary-QC chain.

Dedicated reachability traces also retain the rejection paths for an
unauthorized empty QC, an exact epoch anchor missing one handoff quorum, a TC
that selects a different empty QC, use of the anchor as a certifying QC, and
use of the anchor in a finality proof. Each path must first present the concrete
malformed candidate, and its reject action uses the logical negation of the
same acceptance predicate used by the corresponding positive action. Peer
transport of the empty QC never creates context authority.

The former standalone anchor mutant was removed because it could fail without
exercising the positive model's validation relation. The retained mutation is
now the `syntheticAnchorHasPower` input to the exact parameterized acceptance
relations in `anchor_view_change.qnt`. Normal accept/reject actions always pass
`false`; the two mutation-only steps pass `true`, once for a candidate
certifying QC and once for a candidate direct-finality chain. CI requires both
two-transition lanes to violate `anchorHasNoCertificationOrFinalityPower`.

The normal anchor checks use 10,000 traces of at most 12 steps with seed
`0x54524e4d`; each valid view-change witness is seven transitions. This is not
a proof of unbounded pacemaker liveness, arbitrary skipped views, weighted
timeouts, cryptographic reconstruction, full header/QC linkage, or multi-epoch
histories.

## Partition, loss, delay, and healing

`partition_heal.qnt` fixes four validators, one Byzantine validator, quorum
three, and the two partitions `{0,1}` and `{2,3}`. A signed message can remain
delayed, be dropped, or be delivered only within its partition until the
monotonic heal transition. The normal aggregate gate checks 3,000 seeded
traces of at most 20 steps for conflicting finality, the inability of either
two-node partition to form a QC, vote provenance, drop/delivery disjointness,
no cross-partition delivery before healing, honest quorum intersection,
durable non-equivocation and view journaling, certified locks, and validity of
the progress-witness terminal state.

The separate `fairHealStep` trace is deliberately deterministic: one step
heals the network, then all three honest validators certify blocks 1, 3, and 5
in three increasing views and deliver their votes to honest validator 1. At
the fourth transition block 1 is finalized. CI proves this bounded state is
reachable by requiring a counterexample to `fairHealProgressNotReached`.

That trace demonstrates progress only under the encoded finite fair-delivery
schedule with an available honest quorum. The safety model permits arbitrary
stalling through delay or loss and makes no unconditional, probabilistic, or
unbounded liveness claim. It does not model dynamic membership, weighted
validators, retransmission timers, adaptive corruption, or more than one
heal cycle.

## Premature upgrade activation

`upgrade_atomicity.qnt` fixes one bounded upgrade lane at finalized heights 9
through 13. A finalized UpgradePlan notice at height 9 must be followed by a
plan-bound checkpoint at 10, seal 1 at 11, seal 2 at 12, and independent
three-of-four old/new handoff quorums. Honest handoff signers may authorize
only protocol versions in their advertised support sets. Activation occurs at
the declared height 13 in the same transition that finalizes the first block
under the new protocol and parameter hash.

Plans 1 and 2 both target supported protocol version 2 at height 13 but carry
different parameter hashes. Only the one finalized notice may advance; a
second conflicting finalized notice is retained as evidence and halts before
activation. Plan 3 targets unsupported version 3. Byzantine validators may
sign it, but one Byzantine vote in each set cannot form either quorum and the
local supported-version guard also rejects activation.

The `oneConfigurationPerHeight` invariant compares every pair of active
configuration records and rejects two different `(protocol_version,
parameter_hash)` pairs at one height. The remaining upgrade invariants require
the complete finalized milestone path, both handoff quorums, supported target
version, exact activation height, matching first new block, honest
non-equivocation, and a fail-closed halt on conflicting plans.

`mutants/premature_upgrade_activation.qnt` deliberately activates immediately
after the notice at height 9, with no checkpoint, seals, handoff quorum, or
first new block. CI requires a counterexample to
`activationRequiresAllPrerequisites` after one transition.

The normal upgrade checks use 10,000 seeded traces of at most 30 steps. A
separate seven-transition deterministic witness finalizes plan 1, both seals,
three honest votes from each validator set, and the first new-protocol block.
This is bounded reachability evidence, not unconditional liveness. The model
does not cover concurrent upgrade queues, rollback, dynamic weights, binary
decoding, cryptographic verification, or arbitrary activation distances.

## Duplicate certificate counted in a PoCO snapshot

`poco_weight_snapshot.qnt` instantiates the frozen P0 shadow parameters. Its
regular fixture represents four providers, eleven tasks per provider, six
consumers per task, and eleven distinct mature certificates per
provider/task/consumer group. Each raw certificate has two million units and
is first capped to one million. The resulting hierarchy deliberately reaches:

- 11,000,000 raw consumer/provider units, capped to 10,000,000;
- 60,000,000 task/provider units, capped to 50,000,000;
- 550,000,000 provider units, capped to 500,000,000.

The provider therefore has PoCO capacity 500. Active slashable bond is
400,000,000,000 atomic units, yielding bond capacity 400, so the final raw
candidate power is 400 and remains below the frozen validator maximum of
1,000,000. Four equal candidates produce total power 1,600 and maximum power
400: both `3*M < W` and the 250,000 ppm share bound hold, with the share bound
at exact equality. Total power remains below the frozen maximum.

Boundary certificates at snapshot epoch 30 check maturity epoch 2, age-zero
full contribution, age-10 50% decay, and age-20 expiry. Immature and expired
certificates contribute zero. Opposite group-enumeration orders reach the same
consumer, task, and provider totals; their candidate-power maps, fallback
flags, canonical provider order, and shadow-committed maps must be identical.
A separate sort fixture checks descending raw power followed by ascending raw
validator ID, then canonical ascending-ID snapshot encoding.

The frozen rollout phase is `shadow`: a valid candidate is retained only as
diagnostics and the committed next set remains the current set. Duplicate
certificate IDs are not silently de-duplicated or counted once; they invalidate
the complete candidate and invoke the same current-set fallback. Malformed
unsigned state and checked-arithmetic overflow do likewise. Dedicated
two-transition traces retain witnesses for the legal diagnostic snapshot and
for duplicate, malformed, and overflow fallback paths.

`mutants/duplicate_certificate_counted.qnt` presents two input slots with the
same certificate ID. The broken builder adds both million-unit contributions
instead of invalidating the candidate. CI requires a one-transition
counterexample to `duplicateCertificateFailsClosed`.

The normal weight checks use 10,000 traces of at most four steps with seed
`0x54524e4d`. Quint 0.32's Rust evaluator accepts only i64 literals, so the
model cannot represent `u128::MAX`; it uses the exact frozen
`max_total_voting_power` as a conservative overflow sentinel, while every
valid fixture intermediate is far below it. This is not exhaustive proof of
the full u128 domain, arbitrary certificate maps, more than four providers,
candidate truncation above 100 validators, cryptographic admission, related
party classification, or non-shadow rollout phases.

## One-sided epoch handoff

`joint_handoff.qnt` permits activation only after checkpoint finality and
quorums over one descriptor from both four-validator old and new sets.
`mutants/one_sided_handoff.qnt` deliberately removes the new-set quorum guard.
The gate requires a counterexample to `activationRequiresBothQuorums`.

## Self-signed but uncommitted light-client set

`light_client_handoff.qnt` gives the network enough freedom for either bounded
candidate validator set to sign and finalize its own epoch-local chain. The
client accepts a link only when the finalized old checkpoint committed that
exact `(target_epoch, set_id)`, both the old and new sets reached independent
handoff quorums for it, candidate-set finality is present, freshness is known,
and checked epoch distance is within the inclusive trusting period. Epoch 3 is
the exact `3 - 1 == 2` boundary and epoch 4 is rejected.

`mutants/self_signed_uncommitted_set.qnt` starts with a finalized epoch-1
checkpoint that commits set 2 and a valid-looking self-signed chain from set 3.
The broken verifier accepts set 3 using only its self signatures and local
finality, omitting both the checkpoint-commitment match and the old-set handoff
quorum. The CI gate requires a counterexample to
`acceptedOnlyCommittedJointTransition`.

This is a bounded negative control over two candidate sets and three target
epochs. It is not an exhaustive proof of arbitrary validator-set sequences,
multi-hop transitions, signature schemes, or weak-subjectivity recovery.
