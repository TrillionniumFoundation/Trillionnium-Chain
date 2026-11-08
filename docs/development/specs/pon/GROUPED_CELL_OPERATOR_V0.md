# Routed integer grouped operator v0

Profile: `pon-routed-int257-grouped-research-v0`. This is an implemented,
separately versioned **algebraic research relation**. It is not a PoW lottery,
succinct proof, registered chain work profile, proof of demand, model adoption
or permission to pay. The existing `pon-matmul-transcript-64-v1` relation and all
activation flags remain unchanged. This work continues the sole development plan
and existing integration candidate PR #688.

## Sources and owners

- [Native grouped operator and independent verifier](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs).
- [Persistent native research process](../../../../trillionnium/crates/trnm-crypto-primitives/examples/pon_routed_int257_grouped.rs).
- [Existing-model consumer and measurement supervisor](../../../../formal/pon-nakamoto-v1/experiments/grouped_cell_operator_v0.py).
- [Bounded request batch planner](../../../../formal/pon-nakamoto-v1/grouped_request_batch_v0.py).
- [Factor-preserving existing-adapter evaluator](../../../../formal/pon-nakamoto-v1/grouped_low_rank_v0.py).
- [Previous W1 experiment and negative result](SHARED_CELL_WORK_V1.md).

M01 owns the typed arithmetic verification boundary. The planner only records
caller-supplied arrival, cancellation and completion observations within a
bounded volatile session. Existing model, source-corpus and evaluation-bundle
loaders retain their original ownership. Neither the planner nor an arithmetic
commitment authenticates an external request, a current owner or a deadline.

## Exact numeric and routing contract

The fixture uses the existing public-source model: one base, one router and
three expert deltas, each with shape `3 x 257`. The number 257 is the feature
dimension, not a finite-field modulus. Every original coefficient is a signed
integer in `[-32767,32767]`. Every feature is in `[-8,8]`; feature 256 is the
fixed bias value 8. Products and sums use exact signed 64-bit arithmetic. There
is no floating-point conversion, rounding, modulo reduction or quantization
change. The model's existing scale and artifact version remain bound by its
validated model artifact.

Model preparation validates all original matrices, commits their original
bytes and caches each `base + delta[e]`. Merged coefficients can reach 65534 in
absolute value. The conservative full-logit bound is
`257 * 65534 * 8 = 134737904`; original router scores have half that bound.
Preparation is reusable only while those exact model bytes remain unchanged
and its cost is reported separately from warm inference.

For one to 64 supplied requests:

1. Calculate the router `3 x 257` by `257 x n`.
2. Select exactly one expert for every input, using lowest-index argmax ties.
3. Gather stable input-index groups from that same ordered input. Group sizes
   sum to `n`; an empty expert group has no contraction.
4. Multiply each selected cached expert `3 x 257` by its `257 x b_e` input
   matrix and scatter complete logits to the original input order.
5. Select predictions with the same lowest-index tie rule.

The required dense algebraic count is `2 * 3 * 257 * n`. At 64 requests it is
98,688 multiply-add positions, with zero padding and no unselected expert
outputs. This count describes this dense implementation. It is not a minimum
attacker cost, measured FLOPs, proof of business demand or reward entitlement.
Sparse, zero, repeated and low-rank inputs may admit cheaper lawful algorithms.

## Two lawful producers for the same relation

`observe` uses the compact grouped matrices described above. `observe_direct`
uses the existing direct selected-expert contraction, retains the same ordered
group/output statement, and avoids copying an expert-local activation matrix.
`nonempty_expert_groups` counts nonempty logical groups, not hardware kernel
launches. Both return exactly the same statement and product for the same model, context
and requests, and both go through the independent verifier. The numeric
relation does not require a needlessly expensive arithmetic implementation.

The ordinary control omits retained router/group diagnostics; direct selected
and packed grouped producers retain them. Their three hot kernels are measured
in all six execution orders. The current packed kernel also includes three
internal phase-clock probes that the ordinary/direct kernels do not have; the
reported ratio includes this instrumentation, not only activation packing.
Packed execution remains an explicit measured
option even when it loses on narrow three-row matrices. There is no automatic
calibration, hidden implementation switch or universal packed-kernel speedup
claim. A separate single-call selected-relation measurement includes fresh
request validation, input commitment, production, statement commitment and full
independent verification. Model initialization is reported outside that call.

## Canonical statement and verified handoff

The three fresh domain names are:

- `pon-routed-int257-grouped-model-v0`;
- `pon-routed-int257-grouped-input-v0`;
- `pon-routed-int257-grouped-statement-v0`.

They use the existing length-prefixed `hash_domain` SHA256 construction, with
the research profile and fixed numeric semantics bound explicitly. The typed
encoding has fixed hash fields, big-endian unsigned 64-bit counts/times and
signed 64-bit coefficients/results. JSON is a bounded research-process input
envelope; its textual layout is not the statement encoding.

The model commitment includes the supplied model version, dimensions and all
original base/router/delta coefficients. The input commitment includes the
model commitment; chain, parent, challenge and batch identities; the number of
requests; and each ordered request's ID, scope, original arrival/deadline and
all 257 features. The statement additionally binds every router score, route,
ordered group index, output logit, prediction and arithmetic count. Identical
activations with different request identities, contexts or deadlines therefore
produce different input statements.

The independent verifier receives its expected model, context, request list
and caller clock externally. It validates ranges/intervals/uniqueness and
recomputes router scores, selected base and selected delta directly from the
original matrices, without trusting the producer's gather or merged matrix. It
checks the complete group partition, ordering, exact outputs, counts and
commitments. Only this path constructs `VerifiedProduct`. A changed router,
wrong tie, omitted/duplicated/reordered request, altered result, inflated count,
changed context or expired request must be rejected.

This verifier performs full arithmetic recomputation. A hash is a binding
commitment, not a proof of correct computation or useful work. Its cost belongs
in every measured verification path. A future succinct or dispute-based
verifier needs its own protocol, trust assumptions, source version and cost
measurement. No current-parent or current-authority decision is supplied here.

## Batching, deadlines and shared execution

The planner admits only supplied request identities and immutable envelopes.
It bounds both batch capacity and total session intake, rejects reused request
IDs, and exposes the next required wake-up. Capacity, bounded waiting and the
earliest original deadline minus an explicitly supplied service allowance
control sealing. A scope or model change flushes pending work. Partial batches
are valid; missing requests are never manufactured to fill them.

The caller must actually wake the planner and submit completion observations.
A late wake-up records expiry; it never backdates dispatch. Cancellation remains
terminal even if an output later arrives. Completion rechecks the original
deadline and the request's model/scope/input identity; late output is recorded
without acceptance. The service allowance is a scheduling input, not a proved
worst-case runtime. The session is not a durable replay or payment owner.

A public-source corpus does not contain real arrival times, external request
authentication or service deadlines. Measurements without such a trace are
labelled retrospective arithmetic fixtures. Any logical times used to exercise
the relation are declared test inputs; no queue-latency distribution, deadline
benefit or public-service qualification is inferred from them.

Shared weights reduce residency. Reusing a single encoder result additionally
requires the same input, requested representation, model/generation and an
authorized compatible scope. Grouping different inputs changes scheduling; it
does not erase their encoder FLOPs. The current operator does not implement
an encoder cache or grant reuse across owners.

## Low-rank work and existing integration boundaries

The repository already has the [ILF2 factor codec](../../../../trillionnium/crates/trnm-protocol/src/integer_factor_v2.rs)
and the [exact integer insertion verifier](../../../../trillionnium/crates/trnm-verification-profiles/src/exact_integer_linear_v1.rs).
Their artifact/factor/scale and owner boundaries must be reused. Where an
adapter is represented as `B A`, inference should preserve `B (A x)` when that
is the lawful cheaper execution, charging the actual factor contractions.
Expanding `B A` for a validation comparison does not turn those expanded dense
positions into required inference work. Cached merged dense weights are also
a legitimate competitor; the small three-output fixture does not establish
that factor execution always wins.

Existing [Hepta handoff](../../../../trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs),
[Cell host supervisor](../../../../scripts/llm_cell_host_handoff.py) and resident
immutable tensor views remain the paths for future integration. This relation
does not replace their generation, withdrawal, original deadline, release,
CURRENT or FinalUse owners.

## Measurement interpretation

The native process prepares the model once and accepts multiple bounded batch
messages. Comparisons retain a direct cached selected-expert control with no
artificial proof or diagnostic duties. Report all three kernel arms, model preparation, input parsing,
validation/commitments, router/gather/expert/scatter, independent verification,
serialization/IPC, process startup and whole-supervisor cost in their actual
scopes. Kernel timings and full verified-process timings have different
denominators. Repeated warm samples over one batch do not create new demand.

The previous W1 child time includes proof generation/search and two verifiers.
A faster grouped arithmetic relation without a lottery cannot be advertised as
an equally secure PoW speedup over it. New results also cannot retroactively
change the prior `not_adopted`, zero-model-reward observation or its failed
independent future-evaluation gates.

## External research and remaining qualification

The [legal-work and lottery audit](GROUPED_WORK_FAIRNESS_AUDIT_V0.md) now fixes a
16-request candidate encoding and independently tests prechallenge binding,
canonical ticket identity, lawful factor/merged/sparse/repeated strategies and
all-query accounting. It confirms that this operator's arithmetic is challenge
invariant, so a cached correct product can generate additional hash-only audit
tickets. The audit grants zero chainwork; it is not a registered lottery and
does not establish a defect in native W1.

The subsequent [fresh-query floor research](GROUPED_FRESH_WORK_FLOOR_V0.md)
implements challenge-transform shortcuts and an explicitly additional fixed
security chain with native task/target binding and a bounded verification
journal. Its conditional oracle-query accounting is separate from neural or
physical hardness. Full local costs and exact authority checks are research
observations; real demand, global verification limits and production chainwork
remain unqualified.

[Komargodski and Weinstein, ESA 2026](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
report a GPU matrix path at large actual layer shapes. Their correlated
low-rank intermediate-work assumption, finite-field semantics and matrix-path
measurement scope do not qualify this signed integer research relation.
[Pearl PIP-2, fixed source](https://github.com/pearl-research-labs/pips/blob/0f45b124e9521c89d80755721ec3d90484a1731d/PIPS/pip-0002.md)
provides a useful organization of activation/weight/routing commitments and
authenticated gathers. It explicitly omits router computation verification;
its security, privacy, reference implementation and test-vector sections remain
TBD at that source. Here router correctness is checked explicitly.

Remaining gates include a registered challenge/lottery and minimum legal-cost
analysis across shapes, sparsity, ranks, repeated requests and hardware; full
proof/verification/availability/propagation costs; authenticated real demand
with deadlines; independently beneficial future model evaluation; ordinary
Hepta installation and consumption; original hostile-service budgets; and
funded effects under the original owners. None is closed by arithmetic equality
or by a faster local kernel.
