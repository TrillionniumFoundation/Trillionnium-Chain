# M1 — exact compatible model, evaluation and bounded commons settlement

Configuration: [`model-family-v1.json`](../../../../config/pon/model-family-v1.json).
FamilyId=H("family",canonical(configuration)). It binds features, shapes and integer
inference, not just a mutable model name. A change requires a different family/context.
The implemented experiment is public-source task routing, not a language-model quality
claim, an ordinary Hepta user workflow, or independently administered future evaluation.

## M1.1 Real task source, consent and partitions

The corpus consists of public Rust function/change snippets from the fixed repository
source commit recorded in each experiment. Labels are the real primary owners M00, M04,
M10 in the source inventory. It is a reproducible engineering task: route a change to
its owning subsystem. No email, private memory, user task or paid model API is consumed.
The repository license remains the source permission context; no legal inference is
made from a signature. Public-data provenance is recorded at file and content level.

Files within each class are sorted by SHA256(path). File rank modulo10 gives consumer=0,
evaluation A=1, evaluation B=2, calibration=3, remaining files=train. Exact normalized
content duplicates are globally removed. All snippets from a file use one partition;
path strings and explicit `trnm*`, m00/m04/m10 tokens do not enter model features.
This controls exact-content/file leakage, not every semantic near-duplicate.

The recorded first exploratory experiment failed. Its integer normalization erased
rare features and its class prior dominated. Its model, code digest and zero-reward
outcome are retained. The revised clipping/balanced-loss experiment reused partition
identities; consequently its scores are exploratory local evidence, NOT an untouched
holdout, independent audit, new future window or externally validated p-value claim.
The scripted statistical decision is still exact and reproducible; no thresholds were
changed to force a pass. Further acceptance requires new source/time windows and operators.

## M1.2 Fixed parameter and inference contract

Tokenize lowercased text with `[a-zA-Z_][a-zA-Z_0-9]*`, at most1024 retained tokens.
Hash each token with SHA256; bucket=LE16(first2bytes)%256; add +1 iff byte2&1 else -1.
Clip bucket counts to [-8,8], append bias8. Output dimension is257 integers.

Artifact is canonical JSON, <=65,536 bytes, exact allowed keys, no dynamic code or pickle.
`base` and `router` are3×257; `deltas` is3×3×257. Every weight is integer in[-32767,32767]
with scale1024. Unknown fields, shape/range/family/feature/class changes reject before use.
The full family identifier enters the ledger parameter commitment.

    route = lowest argmax(router * x)
    logits = (base + deltas[route]) * x
    prediction = lowest argmax(logits)

Inference is exact integer arithmetic. The base is counted once. The full model has771
base parameters,2313 delta parameters and771 router parameters. Selecting one expert
reduces active parameter use; it does not make total parameter count a quality metric.
An expert-free deployment and the full routed release are distinct declared profiles.

## M1.3 Learning and composition recipe

Float64 training uses deterministic full-batch softmax gradient descent, inverse-frequency
class weighting, learning rate0.3, L2 coefficient0.0005. This optimizer is an experimental
producer, not deterministic consensus. The shared seed trains8 steps on up to20 train
examples per class. Node i fine-tunes120 steps from that base using its class plus a
hash-assigned one-third of the other classes. Three subprocesses train three real deltas.
Round weight×1024 using ties-to-even and clip at export; parameters are not mock outputs.

Router targets come from the best expert's probability of the true label on calibration
only; router trains120 steps. Evaluations report base, every single expert, simple mean
delta, routed composition, and a pooled120-step control. Additional training and router
costs are disclosed. This is not an equal-total-compute proof of MoE superiority.
The calibration outcome can select a composition that later loses to a single expert;
all those results are retained, including the observed best-single advantage.

## M2.4 Frozen strongest baseline and clustered evaluation

The producer and evaluator now use [the immutable E3 bundle](EVALUATION_BUNDLE.md).
All four deployable control artifacts, the actual parent/candidate, task partitions,
calibration selection and policy are sealed before evaluation. The caller supplies the
expected bundle hash independently of downloaded bytes. Both best-single selection and
control selection use equal source-group weighting; a large correlated file is not
allowed to dominate selection merely by producing more snippets.

The paired source-group directional gate retains the four-comparison correction and
at least twenty groups, and now also requires positive average group improvement.
Input labels/predictions are strict bounded integers. Calibration, training and named
evaluation partitions cannot be relabelled or share exact content/groups. Legacy
unbound reference files reject. Candidate/control mutation after lock produces no score.

Before signing controlled settlement attestations, the existing settlement producer
recomputes the bound evaluation and checks predictions, controls and scores in both
report copies. No-update results still pay zero. This does not make development
attestors independent or replace the chain's explicit trust profile.

The current corpus is retrospective and has been observed; caller flags cannot create
future-window observation or authority. First-two ledger attestation arrival semantics,
public dispute policy, genuine Hepta owner integration and independent prospective
acceptance remain explicit work, not properties of this bundle.

## M1.5 Artifact identities and admission

Expert contribution ID binds sender, family, parent release, exact artifact hash and
components root. A composed bundle is a separate contribution whose components root binds
the bounded allocation list. The release transaction recomputes each scored leaf, total,
root and release ID from current evaluated state. It cannot assign arbitrary scores just
by supplying a Merkle root or a producer signature. The publisher prepays the budget.

The demonstration rewards only expert contributions with positive accepted marginal
scores on BOTH evaluation partitions and an adopted positive whole-model bundle. It does
not promise every locally trained expert a reward or pay by parameter count. Components
without credible local marginal evidence can be included in a research bundle without
being credited as independently valuable. General nonlinear complementary attribution
is a separate profile; this specific rule is bounded ablation, not exact Shapley fairness.

After20 blocks and before its1000-block claim window closes, a contributor claims floor(budget×score/total). The proof binds its
identity, contribution and accepted score; a root-relative nullifier forbids repeats.
A new nonce does not bypass the claim nullifier. Dust remains in the reserved pool.
Fork reorganization can remove the entitlement; actual prior service facts cannot vanish.

## M1.6 Author-offline use and free inference

Two local custodians store independently read-back copies of the exact public model.
During the test, the author's original file is renamed away and a separate consumer
process loads a custodian copy. This tests removal of one source path, not independent
geographic DA, legal erasure, anonymous-host trust or long-term retention availability.

A sponsor reserves quota for an unfunded consumer and specific provider. Consumer validates the closed model/request/input/output receipt, then signs
H("use",Network,Parameters,quota,provider,provider_tx_nonce,units,result). Provider submits the signed use;
prepaid budget covers execution fee and service amount. No account debit or training
consent is silently required from the consumer. Replays, mismatched provider/result,
expired quota and insufficient units reject. Consent to service never means consent to
export private training data. This public-source test requires no such private consent.

## M1.7 Hepta owner handoff, not a new global trainer

A production adapter must accept exact records from Hepta learning.operator, artifacts,
eval and plasticity owners, and submit through kernel.operations' intent/outbox identity.
Neuron/inference activates only a locally admitted new generation after drain/fencing.
The executable spec does not call that ordinary Hepta path; `ordinary_hepta_entry=false`
remains a required report field. Model release confirmation cannot issue a final-use token.
A fifth global NDU authority or a chain-owned duplicate learning database is not introduced.

Exact artifact manifests, failed experiment, two evaluation partitions, withheld consumer,
real work partial contraction,28-block release/claim flow and zero-cost consumer evidence
are collected separately. Native deployment, future efficacy, external data governance,
independent evaluators and public-network economics are still unaccepted.

Current native three-generation release tests use controlled signed scores and exercise retirement/claim semantics. They do not establish three improving learned generations. The ordinary Hepta path and prospective independent evaluation remain missing.

## Continuous attempts, including no-change outcomes

`learning_cycles.py` performs three actual local optimization/calibration/evaluation
attempts. Bootstrap source files are excluded from later partitions; the three cycles
use disjoint file groups. Candidate, strongest calibration-selected control and partitions
are fixed before evaluation. Each attempt starts from the actually admitted public
artifact, not from an unaccepted optimistic candidate. If independent owner/time evidence
is absent, public parameters remain unchanged and reward is zero even when an exploratory
score is positive. Retrospective file partitions are not new future user experience.

These experiments are not three improving public releases. The separate native ledger
regression exercises three signed controlled release generations for exact accounting.
Neither may be relabelled as three ordinary Hepta learning generations. A composition
losing to a stronger deployable single/merged control is not forced into adoption.

## Claim classes: no promotion from arithmetic to future benefit or optimality

These distinguish statement meaning inside the existing evaluation contract; they do
not add transaction tags, a new evaluator authority or an active revision3 wire field.

| Claim | Exact subject and verification obligation | Current acceptance boundary |
|---|---|---|
| Challenged arithmetic | Committed task/matrices, exact header challenge, canonical transcript/product and target; replay the W1 relation | Implemented experimental relation. Neither effort hardness nor useful model improvement follows. |
| Fixed-dataset marginal gain | Exact parent/candidate/control bytes, compatibility/composition recipe, dataset/groups, metric, budget and threshold; recompute predictions and the existing statistical gate | E3 controlled retrospective evaluation. It is not independent prospective benefit. |
| Prospective benefit | The fixed-dataset statement plus authenticated chronological collection, independently controlled untouched task windows, consent/withdrawal and preregistered stopping/multiplicity policy | Required but unaccepted; a caller timestamp, future flag or disjoint file names cannot supply it. |
| Bounded optimality | Exact feasible circuit/weight family, numeric domain, objective, resource budget, epsilon, candidate and checkable lower-bound certificate | The exact committed-dataset accuracy upper-bound certificate below is implemented. Arbitrary circuit/resource-constrained lower-bound certificates remain unimplemented; first place cannot fill them. |

For loss minimization, a valid feasible candidate with loss l and independently checked
lower bound L proves only the declared family's epsilon-optimality when l-L<=epsilon.
An arbitrary returned L, solver success string, training trace or signed score is not a
lower-bound certificate. The circuit family and objective must be fixed before search;
finite precision, allowed topology and resource limits are part of the statement.
No such statement certifies optimality over every possible future task or neural model.

Marginal evaluation must specify whether removing an expert freezes or retrains its
router; any retraining/composition budget is charged equally in compared cases. The
current bounded ablation recipe is not an exact Shapley or unrestricted optimality
algorithm. For a low-rank delta BA, BA=(BQ)(Q^-1 A) for invertible Q: different bytes
can represent the same update. Content hashes therefore establish exact identity,
not functional novelty, economic independence or immunity to attribution splitting.

### Executed empirical value and objective-bound statement

The existing evaluator now emits `pon-fixed-dataset-value-claim-v1`, binding the frozen
bundle, candidate, parent, strongest control and task digest. It recomputes reduced
rational candidate/control/marginal equal-source-group accuracy. The certificate
`zero-one-accuracy-upper-bound-v1` uses the universal upper bound 1 on this fixed labelled
dataset: gap=1-candidate_accuracy; exact empirical optimality is true only at gap zero.
A feasible model attaining this bound is optimal for that empirical objective. It is
NOT a minimum-size/minimum-cost circuit, a future distribution guarantee, a general
neural optimization certificate, original training provenance or fresh consensus work.
A nonzero gap is a valid bound, not a claim that the submitted model reaches the optimum.

Normal worker output carries this statement; settlement recomputes it and requires
canonical byte equality in both the worker and summary records. Relabelled future or
general-optimality claims, changed bounds and integer/Boolean aliases reject even when
both mutable reports are changed together. The prediction-row accounting names only
this evaluator (candidate, four controls, three fixed-router ablations, and four
calibration controls), not training, auxiliary worker metrics, wall time or GPU cost.
No revision3 transaction, signed parameter context or reward authority is changed.

## Explicit closed-round successor: all eligible attestations, not first arrivals

`config/pon/evaluation-round-v1.json` defines `closed-round-all-eligible-min-v1`.
The installed default remains revision3, including its retained first-two counterexample.
The successor is selected explicitly by the native CLI `--evaluation-policy` option,
`Settings::development_with_evaluation_policy` or, in a separately started Python oracle,
`TRNM_PON_EVALUATION_POLICY=closed-round-all-eligible-min-v1`. Unknown profiles reject.
Its revision4 network label, complete policy hash, parameter commitment and evaluation
plan differ. Existing databases and old signed transactions are not upgraded or relabelled.

For each candidate the roster is the genesis evaluator set minus the exact author, with
at least two eligible identities. Only those identities may attest once, to the fixed
plan/evidence/score. No prefix quorum can freeze a score. After ALL eligible identities
are present, the minimum of the complete set is the accepted score; before then status
remains submitted and no release can consume it. A complete round containing zero cannot
unlock model reward. Existing signed intake windows, expiry and retirement remain in
force: a missing evaluator can withhold this candidate's adoption, but cannot suspend
mining, fabricate a timeout vote or create an indefinite payout liability.

This deliberately trades evaluator availability for a complete, order-independent set.
Scores 10/100/100 yield 10 in all six orders. Scores 0/100/100 yield zero. An author in
the three-member roster is excluded, so both remaining members are required. Distinct
keys still do not establish independent administration. Signed false scores remain an
attested-trust risk; minimum aggregation is NOT objective model verification or arbitration.
A same-signer replacement rejects rather than silently replacing the first statement.
No slashing, appeal authority, retroactive block invalidation or consensus voting is added.
General nonlinear functional-copy/split attribution and independently governed objective
dispute resolution remain open. The exact integer-linear profile and signed bounded
policy below now execute narrower obligations.

The M11 `trnm-verification-profiles::closed_round::complete_score` procedure is consumed
by the existing M06 twelve-command executor. The Python `evaluation_round.complete_score`
is separately coded. `test_evaluation_round.py::ClosedRoundTests` runs signed transitions
at 1/2/4/8 workers, zero/missing/duplicate/wrong-context rejection, complete-budget
publication/maturity/claim, and the ordinary native CLI with real work, disk reopen and
heavier-fork replay. Positive scores in these tests are controlled fixtures, not a new
learned improvement or an independently authorized reward. Historical model observations
remain unchanged; fixed-data, prospective and optimum-certificate claims remain distinct.

## Executable integer-linear copy, complementarity and finite-set profile

[MODEL_ATTRIBUTION](MODEL_ATTRIBUTION.md) specifies fresh sidecar schemas for exact
BA normalization, parent/slot/numeric binding, admitted same-source caps, declared
bounded perturbations and all finite subset replays. Copying under another factorization
or identity cannot multiply the same effective update or its cap. Distinct components
may retain joint value even with zero standalone gain. Group-level Shapley and an
exhaustive finite-set optimum are replayed, never inferred from probe hashes or a
reported solver bound. This leaves general nonlinear equivalence, optimal circuit cost,
real independent source admission and target LLM prospective quality unqualified.

The same detail defines UniqueUsefulOutputAccounting: A/B relabelling, stale attempts,
reorg and output replay cannot erase incurred verifier costs or count one adopted
content output twice. Positive verification alone is not downstream adoption. The
real campaign uses existing training/inference owners and records actual versions;
retrospective source tasks remain exploratory, with no public reward authority.

[PUBLIC_EVALUATION_LIFECYCLE](PUBLIC_EVALUATION_LIFECYCLE.md) separates the bounded
off-chain policy from the explicitly selected `native-public-evaluation-dev-v1`
successor. The native successor freezes the candidate/context/roster, checks strict
commit/reveal and height phases, aborts missing reveals, records signature conflicts and
next-round key exclusions, and retains bounded record-only appeals. The historical
revision4 closed-round profile remains unchanged. Neither successor supplies public
roster governance, prospective independence, objective ML truth or funded appeal
adjudication; minimum scores cannot establish those facts.

## Joined reported model/operations acceptance

[MODEL_OPERATIONS_ACCEPTANCE_V1](MODEL_OPERATIONS_ACCEPTANCE_V1.md) joins the existing
target-decoder run replay to one externally pinned preregistration and receipt for
strong controls, poison/backdoor/forgetting probes, consumer observations and bounded
retention costs/material. It rejects contradictory or substituted records while
preserving failed gates and unknown GPU cost. This offline contract cannot certify
prospective independence, licensed provenance, authenticated consumer use or fulfilled
DA; all independent/public acceptance flags remain false even for a complete fixture.
