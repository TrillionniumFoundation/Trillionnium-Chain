# Time, branch work and quantum credit continuation

Status: **HOLD_NO_GO**. This continuation extends the research source in PR #811.
It repairs current-clock checks on the existing Growth path, adds an incremental
full-work research context, and withdraws an unsupported external query-bound
citation. It does not install C1 or MU1 as the native consensus profile.

The [sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains authoritative. Existing failed acceptance observations remain in their
original evidence directories.

## 1. Three different kinds of time

Historical validity and credit use the selected native profile and the verified
parent branch. At the current-observed entry points, a receiving-clock check
determines whether an otherwise valid branch is eligible for the requested
processing or activation at that observation. The original business deadline,
cancellation token and paid CPU budget determine whether this request may
continue. Advancing one clock never resets either of the others.

A concrete legacy history illustrates why checking only the candidate is
insufficient. With genesis time 1000 and future skew 120, timestamps
1010, 1020, 1300, 1021, 1022 can satisfy the old MTP rule and be admitted when
the receiving clock is 1300. After the receiving clock moves back to 1023,
a candidate at 1023 can pass its own time check while the ancestor at 1300 is
still in the future. The entire ancestry is needed for current eligibility.
That observation does not retroactively invalidate or remove its historical
credit.

## 2. Existing native Growth behavior

The original generic observed-history interface now dispatches PGH2 through the
Growth owner's bounded header/trace reader and its storage-epoch guard. Checks
bind each header's actual ID, height and parent link; the original progress
callback stays active during the walk. A foreign write cannot turn a mixed
storage observation into either a successful current-time check or a trusted
historical fact.

The public Growth submit path checks parent-branch clock eligibility before
durable admission, including duplicate submissions and the stage after full W1
verification when it reacquires the original owner. These checks use the
request's original deadline and CPU checkpoints. The candidate's own timestamp
continues to use the existing native check.

The original postcommit activation contract is preserved. In particular, this
change does not rename or reuse a signed resource profile to claim a new
postcommit cancellation guarantee. A refused precommit time check is not
reported as successful admission or successful activation.

Current-clock CLI entry points use the same observed-history rule. Unless
an explicit logical time is selected, they sample the system clock again at
the admission and activation boundaries; mining also rechecks the parent after
its complete proof construction. These are discrete observations, not a promise
that physical time cannot change between them. A submit can durably admit a
historically valid packet before a later activation-time refusal.

Historical recovery remains a separate operation: cold opening a store can
reconstruct its historically best branch. A later current-clock refusal does
not roll that history, ledger credit, or operation history backwards and does
not imply that the whole CLI process made no storage change. A constructed
packet artifact is likewise retained when subsequent current admission is
deferred.

The ancestry walk reads headers and trace bindings; it does not replay every
ancestor's W1 proof. It is nevertheless linear in ancestry length. The walk preserves the
original request stop checkpoints, but this change does **not** certify
constant-time validation, an original-resource pressure campaign, or guaranteed
service for honest requests under hostile load.

Source owners:
[Node](../../../../trillionnium/crates/trnm-pon-node/src/store.rs),
[Growth recovery](../../../../trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs),
[public Growth](../../../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/growth.rs),
and [Growth CLI](../../../../trillionnium/crates/trnm-pon-node/src/growth_cli.rs).

## 3. Incremental full-work research context

The [research component](../../../../trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs)
adds a private incremental state that starts from the independently selected
profile's genesis. Only complete PNH1 or PGH2 packets can extend it. It cannot be
initialized from a caller-supplied arithmetic history, cumulative-work value or
anchor hint.

Each extension verifies the current packet in its actual wire challenge domain.
The complete proof, target, timestamp, linkage and transaction commitment must
pass before the new state is published. Cancellation, including a final
checkpoint after proof verification, leaves the previous context unchanged.
A failed or repeated candidate cannot add a second work contribution.

The state retains the checked branch points and a duplicate-ID set within the
existing 4096-height research horizon. It computes MTP from at most eleven
recent times, derives the anchor from the actual activation ancestor, and
carries checked accumulated work forward. A clone is an independent fork
context. It is not a database cache or a transferable native-admission token.

The terminal packet at height 4096 can be represented; requesting another
candidate context then refuses at the horizon. The full-height boundary control
uses a disclosed synthetic prefix and one real final W1 proof, not a claimed
4096-packet native campaign.

The maximum timestamp over the retained ancestry is exposed separately from
candidate-only eligibility. This is necessary because the preactivation legacy
history may be nonmonotone. Clock rollback changes current eligibility without
changing the profile, anchor, required target or credit.

This removes repeated genesis-to-parent proof replay from sequential **research
extensions**. An explicit cold bootstrap still has to validate its inputs.
Production reuse across Node transactions, reorganization and reopen requires
the original owner to publish the corresponding validated context at its actual
commit boundary. A generic cache keyed only by block ID is insufficient:
the existing block ID commits to the header and proof trace, not every proof
byte. A cache miss must not silently launch unbudgeted full-history replay.

See the [incremental contract](INCREMENTAL_WORK_SCHEDULE_RESEARCH_V1.md) for
construction, atomicity and proof scope, and the retained
[branch schedule contract](BRANCH_WORK_SCHEDULE_RESEARCH_V1.md) for C0/C1
arithmetic, activation, wire and storage boundaries.

## 4. Source-bound regression changes the quantum conclusion

The [exact source audit](../../../../formal/pon-nakamoto-v1/QUANTUM_BERNOULLI_SOURCE_AUDIT_V1.md)
reproduces a finite counterexample to the general Bernoulli bound printed in
arXiv:2012.15254v4 and the corresponding Quantum publication. At p=1/16, three
one-query Grover iterations on disjoint 16-point domains achieve success
2234219220017/35184372088832, approximately 0.063500329475. The printed general
bound at the same Boolean-query counts is approximately 0.053228884934.
The strict comparison uses integers.

Accordingly, the previously discussed base 0.9379882177048045 is retained only
as the algebraic value derived from that printed expression. It is not an
accepted chain-security certificate. The three-query counterexample does not
itself disprove the separate full-value-chain diagonal at the reduction's 2N
budget, and it is not an attack on W1 or MU1.

The independent conservative proof already in
[mandatory_units_query.py](../../../../formal/pon-nakamoto-v1/mandatory_units_query.py)
retains the full recording-transition and selected-coordinate projection
factors. At p=1/16, it covers the finite counterexample, and its bound at 64
Boolean queries and 64 outputs is nontrivial. At 2k Boolean queries and k outputs it returns
exactly one for every tested k from 1 through 64. Therefore this continuation
does not replace the rejected diagonal chain claim with an unsupported
nontrivial bound.

The source audit is wired into the existing repository-truth CI lane. A passing
regression means that the counterexample, arithmetic and rejection interface
behave as specified; its machine report still says
REJECT_PRINTED_SOURCE_BOUND and source_bound_usable=false.

## 5. Remaining qualification gates

| Obligation | What this continuation establishes | What is still required |
| --- | --- | --- |
| Current receiving clock | Existing Growth ancestry checks and precommit integration | Original-resource service, History and hostile-load acceptance |
| Branch work context | Incremental complete-W1 research extensions, explicit fork and clock state | Original Node commit/reorg/reopen context ownership and profile-bound migration |
| C1 versus MU1 | Their separate research identities and credit units remain explicit | A new native parameter/wire/storage transition with every ingress/miner/import path |
| Quantum source expression | Exact counterexample and refusal of unsupported source qualification | An independent valid chain bound or independently checked corrected theorem |
| Joint work-scale cost | No new minimum-cost claim | Bounds over all permitted classical/quantum algorithms, reuse and preprocessing |
| Lifecycle tail | Existing joint-state contract retained | Actual action operators, resource units, initial inventory, helper channels and network composition |
| Parallel difficulty adjustment | No protocol activation | Complete paper/proof mapping, resources and participation assumptions, then separate architecture evaluation |

Fixed probability removes one probability-scaling mismatch. It does not make
nominal mandatory units a linear cost lower bound. C1's target work and MU1's
research 16u credit remain different objects. No success in this continuation
changes unknown cost bounds into measured or proven minima.

## 6. Reproduction and evidence interpretation

Run the repository preflight before edits, builds or publication. The affected
native research, Growth, current-clock and retained consensus controls must run
on one frozen source with the pinned Cargo graph and provider. Exact-source
checks, strict workspace Clippy, formatting and local Markdown links retain
their original gates.

Run the source audit independently:

    python3 formal/pon-nakamoto-v1/test_quantum_bernoulli_source_audit.py -v
    python3 formal/pon-nakamoto-v1/quantum_bernoulli_source_audit.py

An old-source red test, when retained, is a distinct execution with the original
production source and only the added regression test. It is not combined with
the fixed-source native results. Test presence, a successful source check, and
a complete proof replay do not by themselves establish production admission or
mixed classical/quantum consensus security.
