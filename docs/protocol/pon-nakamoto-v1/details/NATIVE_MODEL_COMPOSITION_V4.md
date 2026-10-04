# Native integer model composition V4

Status: an explicit development successor with executable bundle derivation and
measured leave-one-out allocation. It does not establish prospective model benefit,
training provenance, independent source controllers, Shapley fairness, demand, or
mining hardness. Production and public-reward acceptance remain false.

## Context and existing owners

`--model-profile linear-factor-composition-dev-v4` selects revision14 and requires
`--evaluation-policy native-public-evaluation-dev-v1`. It supports the legacy task
profile and `consensus-maintenance-continuity-dev-v1`. Model family, network label,
parameters, evaluation plan, genesis model material and state root bind this new
profile. It is a fresh context, not an in-place migration.

The [composition policy](../../../../config/pon/model-composition-v4.json) binds the
rules below. The exact [V3 empirical material](../../../../config/pon/model-evidence-v3.json)
is retained:25 public retrospective source-group rows and four historical integer
controls. Its policy/task hashes also enter the new context. No new data, independent
evaluation or positive external model qualification is claimed.

M06 [composition execution](../../../../trillionnium/crates/trnm-mvcc-fee/src/model_composition_v4.rs)
uses the existing full integer model, public evaluation, source allowance, release
and claim owners. Existing tag23 still submits ILF2, tags14/15 commit and reveal
the native empirical result, and tags8/9 publish and claim a funded release.
There is no new transaction tag, package, reward ledger, authority cache or SQL table.

The empirical arithmetic, control loading and source-map validation are shared with
[V3](NATIVE_MODEL_EVIDENCE_V3.md). V4 uses fresh `model-evidence-v4:` and
`model-source-v4:` state keys, `model_evidence_v4` contribution metadata, empirical
record/root-work domains and a composition record domain. Existing revision13 and
older profiles retain their rules, including V3's membership-only allocation and
standalone-positive component requirement.

## When composition becomes admissible

Tag23 does not carry a component-ID list. It admits a full, range-checked candidate
and computes its standalone empirical score, without certifying composition. A
producer can therefore store a candidate that later fails the composition gate.
Such storage consumes the existing source intake allowance. Tag8 is the first
operation carrying the complete signed ordered component/allocation list; native
execution checks composition there, before debiting the release budget or promoting
the bundle. An unrelated but accurate stored candidate cannot pass that gate.

A release must list2–4 distinct contribution IDs in strictly ascending byte order.
The bundle cannot list itself. Every component must use the bundle's actual current
parent reference, full parent artifact, family, submission round and expert slot.
No old archive or prior-parent component is substituted. Full component models are
loaded from their authenticated retained ILM2 bytes.

For common parent model `P` and complete component models `C[i]`, the one permitted
derivation is

    D = P + sum(C[i] - P).

This is a coordinate-wise exact integer operation over the complete model. It
counts a nonzero parent once. Accumulation uses checked wide integers; the final
coefficient of every full derived model must lie in[-32767,32767]. There is no
averaging, clipping, rounding, approximate reconstruction or acceptance based only
on equivalent predictions. The derived model must equal the complete submitted
bundle model in every coefficient and in its committed family.

Before accepting that derivation, execution enumerates every component subset with
at least two members and rejects it if `sum(C[i] - P)` is exactly zero in every
complete-model coefficient. There are at most11 such subsets for four components;
each checked `i64` sum contains at most four differences in[-65534,65534]. This
finite rule rejects exact cancelling groups, including a `Z` and `-Z` pair whose
individual omissions could misleadingly show positive leave-one-out gain. It does
not reject approximate cancellation or certify prediction equivalence or fairness.

The signed bundle still has to pass the existing ILF2 single-slot, rank1–2 and
checked-BA admission rules. A mathematical sum of admitted rank-two updates need
not itself be representable by that format. Such a sum has no admissible bundle
witness in this profile; native execution never silently approximates it. The
profile intentionally supports only the bounded representable subset.

## Full-bundle comparison and measured weights

The full bundle must have strictly more correct frozen rows than all of:

- Its actual current parent.
- Each of the four installed historical controls.
- Every included fresh component evaluated as its complete standalone model.

Every candidate's original native empirical digest/score is recomputed and checked
against its closed public evaluation. The normal roster, phase, conflict and timely
pre-adoption objection checks still apply. A component may have a complete native
standalone score of zero: it is only being used as a component, not independently
promoted. This exception applies only to V4 components. The complete bundle must
still pass all of the strict comparisons above.

For each listed component `i`, native execution constructs and evaluates the exact
leave-one-out full model

    D_without_i = P + sum(C[j] - P, for j != i).

Every such full model must satisfy the same ILM2 coefficient range, even when the
full bundle's coefficients fit. These are locally computed ablation models; no
producer-supplied prediction or omission score is trusted. They are not separately
admitted ILF2 candidates.

For `n` frozen rows and their exact correct counts, define

    weight[i] = floor((correct(D) - correct(D_without_i)) * 1000000 / n).

Each difference and resulting weight must be strictly positive. Here `n=25`, so a
one-row marginal is40000 without rounding loss. The supplied tag8 leaf weight must
equal the recomputed weight exactly. Standalone empirical scores are not allocation
weights. In particular, a bundle can beat every component and still be rejected if
one component has zero leave-one-out gain; this is possible with three or four
components.

This is a specified ablation rule on public frozen rows, not Shapley attribution or
a general fairness theorem. Interactions can make the sum of marginal weights differ
from the bundle's standalone or strongest-component improvement. Exact-zero subset
rejection does not prevent component splitting, coalitions, concealed common
controllers, general leave-one-out manipulation or public-data memorization.

## Funding, source caps, dust and retention

With `total = sum(weight[i])`, the existing funded ledger pays

    payout[i] = floor(budget * weight[i] / total).

Multiplication uses a wide integer before division. Tag8 commits the component ID,
payee and measured weight in each existing allocation leaf; tag9 proves that exact
leaf and records a single claim. No alternative claimant-supplied weight can change
the committed entitlement.

The unchanged installed author-to-source map and4-intake/100000-unit source-round
allowances apply in fresh V4 namespaces. Reservations aggregate the actual floored
payout amounts across all admitted aliases of a source, including earlier releases
in the same128-height round. Rejected releases do not publish partial reservations.
The funded budget may exceed the sum of floors by dust; that difference stays in the
same release, cannot be claimed through another leaf, and is refunded by the existing
deadline transition. These are development test units, not public monetary acceptance.

The existing release row embeds a `native-model-composition-record-v4` receipt with
context, parent/bundle identities, ordered component identities, complete-model
correct counts, leave-one-out artifact IDs/counts, measured weights, total,
`zero_subset_checks` and a
fresh-domain digest. It adds no separate state key or future mandatory insertion.
The4-component bound keeps the receipt and all claims within the existing value limit.
An overestimate using four claims, expired status and maximum `u64` values for every
numeric field, even the bounded counts, serializes to4057 bytes, below the4096-byte
value limit. This is a shape
bound, not an observation of successful four-component economic qualification.

The original20-height maturity,1000-height claim window, finite pre-adoption appeal
hold, candidate expiry, round-counter cleanup and256-height archive retention remain
in force. Archive/evidence cleanup can prune obsolete component model material; the
release receipt remains a commitment to the computation already checked at publication,
not a promise to retain every component forever. Historical transaction replay retains
the original admission path. Reorganization reverses composition receipts, model
promotion, reservations and claims with their branch.

When combined with revision12 continuity, normal signed admission charges all new
model/evidence/source/release keys to actual capacity. The existing archive reservation
covers each contribution's later mandatory closure. Composition adds no unreserved
mandatory state liability.

## Executable fixtures and limitations

The public positive fixture uses one perceptron pass in policy order and one pass
with that order rotated by one. Their full models score24/25 and23/25; their exact
sum scores25/25. The leave-one-out weights are80000 and40000, while their standalone
empirical scores are200000 and160000. A100001-unit release pays66667 and33333,
reserving100000 against their shared source and leaving one unit for deadline refund.
This fixture deliberately memorizes the public rows; it is evidence of the native
composition and payout rule, not prospective learning benefit.

A25/25 adopted parent saturates this fixed public metric. No later bundle can
strictly improve on it under this policy, so further model adoption stops; the
separate continuity maintenance task can still keep the ledger advancing. Testing
nonzero-parent improvement therefore requires a first genuinely adopted model with
less than25 correct rows, followed by a strictly better bundle. Changing stored
parent bytes or silently replacing the corpus is not a valid continuation.

The second native fixture first adopts an exact bundle from two21/25 components,
producing a24/25 parent. In the next submission round, two actual full components
each score23/25, so both have standalone native gain score zero against that parent.
Their exact parent-relative sum scores25/25 and each has leave-one-out weight80000.
The fixture uses the real first release as parent, closes the new signed evaluations,
adopts the second bundle, claims its funded rewards and reopens durable state.

The [native regression tests](../../../../trillionnium/crates/trnm-pon-node/tests/model_composition_v4.rs)
cover signed admission, composition/refusal, funding, claims and branch-state behavior.
The first lifecycle includes335 admitted PNW1 packets across the main and alternate
branches through main height306. A separate770-step contiguous M06 tail reaches the
claim deadline and verifies the one-unit dust refund; it does not claim770 more
mined packets. The two-generation fixture includes204 admitted PNW1 packets. Five
negative composition scenarios use signed submissions and evaluations through
contiguous M06 heights, rather than additional mined chains. Capacity assertions
check actual keys and future archive liabilities; this is not a full-capacity stress
measurement. Growing same-block prefixes also compare complete state, receipts and
roots with fresh full execution, including rollback of rejected composition suffixes.
The module's arithmetic tests additionally check a nonzero common parent, wide
cancellation, exact-zero subset refusal and out-of-range leave-one-out models.
The four-component cancellation regression has positive apparent marginals for
every member but is refused before funding by the exact-subset rule. Test observations must retain
their actual execution status; source presence alone is not a successful native run.

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test model_composition_v4
```

Public external model efficacy, rights/provenance, concealed-source identity,
prospective datasets, independent operators, poisoning/forgetting, deployment costs,
arbitrary model composition and mining-hardness qualification remain unaccepted.
