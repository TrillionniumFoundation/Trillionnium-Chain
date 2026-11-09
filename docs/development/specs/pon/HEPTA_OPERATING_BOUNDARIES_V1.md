# Hepta execution, learning and consensus boundaries V1

This continuation implements the user's preservation requirements on the
existing #821 candidate, starting at
`e798d7125724d4b9f98c24d00cc80031f2eab4a9`. It follows the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It grants no new work profile, production activation or model-use authority.

The paired learning work starts from Hepta #5393 at
[`bdf35d0991a02cdf201cc098257132fe3282f99f`](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/bdf35d0991a02cdf201cc098257132fe3282f99f).
The publication receipt must identify the tested successor in each repository.
Two source identities do not, by themselves, establish a joint execution.

## Preserve lawful shared and factored execution

The [Hepta neural-biomimicry specification](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/1eb72a1131285f5de98beeb7c95a27eab72d647e/docs/learning/NEURAL_BIOMIMICRY_SPEC.md)
describes compatible layers of the form
`W_i = W_base + B_organ A_organ + B_i A_i`, shared immutable tensors and
generation-bound private Cell state. The additive formula is valid only for
the named compatible layer and composition profile. It is not a universal
adapter-merge rule.

The [grouped operator](GROUPED_CELL_OPERATOR_V0.md) retains its direct and
packed producers and adds an explicit native factored producer for the same
bounded integer relation. Preparation validates every supplied factor product
against the original delta matrix using checked integer arithmetic. Warm
execution preserves `B(Ax)`. The existing independent verifier recomputes the
complete result from the original model matrices. An invalid factorization
cannot be accepted merely because its own producer and output agree.

Preparation and execution belong to different accounting scopes:

| Item | Required interpretation |
| --- | --- |
| Original model and factor preparation | Count and retain once for each actual prepared instance; reuse is legitimate only for its exact model identity. |
| Router, base and factor contractions | Report the contractions actually executed by the selected producer. |
| Dense relation count in the original statement | Preserve the original statement/verifier semantics; this is not a minimum execution cost or a bill for expanded factors. |
| Independent verification | Include its actual work in complete-path measurements, even if the producer is cheaper. |
| Shared activations or cached outputs | Require the original generation, representation, input and authorized scope; identical bytes alone do not authorize reuse across owners. |
| Shared preparation and failed attempts | Retain the original lifecycle and cost-deduplication obligations; multiple consumers do not multiply a shared preparation charge. |

For this three-output research fixture, factor execution need not outperform
a premerged dense matrix. A valid factorization and a lower arithmetic count
are neither a physical cost lower bound nor evidence of a speedup. Sparse
routing, repeated-input reuse, merged caches and batching remain lawful
competitors. No producer choice changes native chainwork.

The bounded grouped relation does not implement the complete Hepta
base/organ/Cell state owner or a cross-owner activation cache. Those integrations
retain their existing model, state, authority and resource checks. The new
producer does not serialize private working memory into a public work claim.

## Three separate rhythms

| Rhythm | Existing owner and admission | Boundary to preserve |
| --- | --- | --- |
| Fast: inference, local state, routing and STOP | Current local model, private state, budget and effect owners | No new consensus round or per-thought chain-finality wait. A local proposal does not change selected shared weights. |
| Medium: Cell or organ adaptation | Frozen learning request, trainer, independent evaluation, selection and durable adoption owners | Freeze the permitted update scope before dispatch; complete evaluation may select a candidate or retain the parent as `NoUpdate`. |
| Slow: base release, work relation, credit or consensus parameters | An explicitly versioned release or consensus owner | Cost qualification, activation, migration and recovery need their own admitted procedure. A learning result cannot supply that authority. |

The paired Hepta continuation adds an explicit scoped learning entry and
checkpoint identity to the real learning runner. Cell updates preserve shared
base/organ and representation components; organ updates preserve the Cell
adapter and shared representation components. The existing evaluator and
adoption owners still decide whether the permitted candidate may be used.
Base-release requests are refused by this medium-rate entry and require the
separate slow owner. An unchecked declaration of a base release is not an
upgrade permission.

Historical unscoped requests and checkpoints retain their original meaning.
They are not silently relabeled as scoped execution, and a scoped recovery
cannot accept a checkpoint under another scope. The exact paired implementation,
tests and limitations belong to its own immutable publication receipt.

Chain's [native Cell verifier](USEFUL_CELL_NATIVE_V1.md) and research work schedules
remain separate from ordinary fast inference and from the learning adoption
owner. The new factored arithmetic producer does not register a new lottery,
work tag, difficulty schedule or credit rule.

## Service fee, improvement bonus and work credit

| Object | What permits it | What does not permit it |
| --- | --- | --- |
| Base service fee | Original authorization, completed contracted service and the original delivery/payment owners | The mere existence of a new weight artifact. |
| Improvement bonus | Its separate frozen comparisons, retention, complete matched costs and independently admitted result | A training exit code, one exposed score, a quote or a vote. |
| Consensus credit | The existing admitted work relation and its original non-reusable work identity | Service price, model score, bonus amount or the number of new parameter bytes. |

A correctly completed evaluation may earn its contracted base fee when its
decision is `NoUpdate`. Incomplete evaluation, a failed process or an unknown
effect cannot be relabeled `NoUpdate`. Unknown retains the original operation
and reservation; recovery queries the original owner instead of executing again.
See the existing [service/work separation](SERVICE_WORK_SETTLEMENT_V1.md) and
[native task operation](NATIVE_TASK_OPERATION_V2.md) contracts.

The lower-level native `NoGain` resource outcome is compatible with a completed
paid service, but is not itself a verified independent `NoUpdate` decision.
Its source, delivery, resource and payment observations still need their
original owners. The retained research planner and controlled native fixtures
must not be described as independent customer demand or real-asset settlement.

## Current payment readback

V2 payment readback now validates the observed native anchor against the
complete persisted journal, including other tasks. It refuses an older
generation and inconsistent block, state-root or height values at the same
generation. A newer generation may report the same monetary effect after a
branch change without rewriting the original payment.

After the external owner callback, a fresh SQLite snapshot must retain the
same checked journal head. A concurrent WAL append produces a stale-observation
refusal. That refusal authorizes neither another dispatch nor another payment.
The historical record, retained costs and once-only operation fence remain.

Readback is deliberately read-only: it does not durably advance a fresh anchor,
make independent owners atomic, or defeat rollback of every local database.
An independent current recovery anchor and final effect reconciliation remain
separate acceptance obligations.

## Acceptance and evidence

Retain separate evidence for native arithmetic equality and malformed-factor
refusal; original protocol behavior; scoped learning and cold recovery; native
payment/NoGain behavior; and the raw source before and after each committed
campaign. The payment counterexamples must fail against the unchanged previous
implementation and pass after the fix. Source guards, required CI entrypoints,
locks, strict lint and original negative tests remain in force.

This continuation can establish implementation properties at the stated
boundaries. Qualification still requires the all-legal-algorithm lifecycle cost
argument, joint time/difficulty/credit security, a same-iteration independently
evaluated learning/payment/adoption/next-use record, and original public-service
and recovery evidence. The status remains **HOLD_NO_GO** until those obligations
have their own evidence.
