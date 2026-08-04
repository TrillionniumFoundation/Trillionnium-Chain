# PoCO-BFT v0 Quint model

This directory contains bounded formal models for the protocol freeze. The
first model covers one Byzantine validator among four equal-power validators,
two conflicting branches, the safe-vote/lock rule, quorum formation, and the
direct three-chain finality rule. `persist_before_sign.qnt` separately models
volatile intent, durable journal acknowledgement, signature release, and
crashes. The deliberately broken `mutants/sign_before_persist.qnt` must produce
a counterexample and is retained to prove that the gate detects this failure.
`weighted_quorum.qnt` exercises both four-validator non-equal weights and
seven-validator equal weights at exact `floor(2W/3)+1` thresholds. Its
duplicate-signer mutant must demonstrate conflicting-QC failure.
`tc_lock.qnt` checks that a TC advances view/high-QC state without clearing a
lock. `tc_high_qc_selection.qnt` separately checks heterogeneous timeout
entries: every entry binds an exact QC digest, the de-duplicated reference
table is complete, the selected high QC is the deterministic maximum by
`(view, block_id, qc_digest)`, and same-view conflicting-block QCs halt and
reject the TC. Two QCs for the same view and block but different signer-subset
digests are allowed; digest order selects one uniquely. Dedicated reachability
traces exercise a valid heterogeneous selection, this equal-view/equal-block
digest tie, and the conflicting-block halt. The retained omitted-reference
mutant must fail.
`anchor_view_change.qnt` separates context-authorized synthetic anchors from
ordinary certifying QCs. Both trusted `GenesisQC` and joint-handoff-authorized
`EpochAnchorQC` are view 0 with no signatures and point to the height directly
before the first block. In separate seven-transition traces, the view-1 leader
fails, three of four validators time out over the exact anchor, an explicit TC
candidate is validated, the TC advances to view 2, the scheduled leader
proposes at the unchanged first/activation height, and three ordinary votes
form the first real QC. The model also presents explicit malformed TC,
certifying-QC, and direct-finality candidates. Acceptance and rejection use the
same predicates; rejection witnesses cannot be reached by merely recording a
reason with no candidate. Separate positive witnesses accept an ordinary
certifying QC and an all-ordinary direct finality chain. Two mutation lanes in
the same model flip the single `syntheticAnchorHasPower` validation input and
must violate the no-anchor-certification/finality invariant. This is bounded
relational evidence, not a parser or cryptographic proof.
`joint_handoff.qnt` requires checkpoint finality and independent old/new
quorums for exactly one descriptor. Both the lock and handoff kernels have
retained failing mutants.
`light_client_handoff.qnt` separately bounds trusted epoch 1, the inclusive
two-epoch trusting-period boundary, old-checkpoint next-set commitments,
independent old/new handoff quorums, candidate-set finality, and freshness
uncertainty. Its environment deliberately permits an uncommitted set to build
a self-signed chain; only the verifier is trusted to reject it. The retained
`mutants/self_signed_uncommitted_set.qnt` removes the commitment and old-quorum
checks and must produce a counterexample.

`partition_heal.qnt` models four validators with one Byzantine validator,
quorum three, two conflicting three-block branches, a two-by-two partition,
signed-but-delayed messages, explicit drops, constrained delivery, and
monotonic healing. Its aggregate safety predicate is explored over 3,000
seeded traces of up to 20 steps. A separate deterministic four-transition
witness heals the network and has all three honest validators certify a
three-chain, demonstrating bounded progress under that finite fair-delivery
schedule without Byzantine cooperation. This is a reachability witness, not
an unconditional liveness claim.

`upgrade_atomicity.qnt` binds one finalized UpgradePlan notice to checkpoint,
seal-1, and seal-2 finality; independent old/new handoff quorums; advertised
validator and local supported-version sets; the declared activation height;
and the first new-protocol block. Supported plans 1 and 2 intentionally carry
different parameter hashes at the same height, while plan 3 targets an
unsupported version. Activation is one atomic transition with the first new
block. Conflicting finalized plans fail closed, and the active-configuration
set cannot contain different `(protocol_version, parameter_hash)` pairs at one
height. A seven-transition reachability trace exercises a valid upgrade using
only honest quorum votes. The retained premature-activation mutant must fail.

`poco_weight_snapshot.qnt` uses the exact frozen P0 maturity, linear decay,
certificate/relationship/provider caps, power conversion, bond ceiling,
validator maximum, share limit, total-power bound, and shadow phase. A compact
certificate-family cardinality fixture hits every hierarchical cap without
materializing 2,904 records. Opposite aggregation orders produce identical
candidate diagnostics and canonical snapshots; a separate fixture exercises
raw-power-descending/validator-ID-ascending selection. Immature and expired
certificates contribute zero, while duplicate IDs, malformed state, and the
bounded overflow probe invalidate the whole candidate and carry the current
set. Valid shadow diagnostics reach power 400 per provider, but committed
power remains the current shadow set. The retained duplicate-counting mutant
must fail.

The model is intentionally smaller than the implementation. It establishes a
reviewable safety kernel before P2 networking and storage exist; it does not
claim unbounded proof, cryptographic security, data availability, or liveness
under an asynchronous scheduler.

Pinned tool version: `@informalsystems/quint@0.32.0`.

The first symbolic Apalache result is retained in
[`APALACHE_EVIDENCE_2026-08-04.md`](APALACHE_EVIDENCE_2026-08-04.md): the
`noConflictingFinality` invariant passed through depth 10, while the depth-20
attempt was stopped after 15 minutes and is explicitly recorded as
inconclusive.

Run the fast local checks with:

```sh
./scripts/ci/check_poco_bft_v0_formal.sh
```

The script typechecks the model and explores deterministic seeded traces while
checking all named invariants. Bounded symbolic Apalache verification is a
separate P0 gate because it requires Java 17+. Its evidence record must be
retained with the source commit and exact tool versions; a successful random
run is not accepted as symbolic evidence, and a bounded result is never
described as an unbounded proof.

Planned follow-on models cover larger and adversarial partition schedules and
multi-hop light-client checkpoint transitions. The current bounded models are
not an unbounded proof.
