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

## M1.4 Exact evaluation and score rule

For each evaluation partition, compare composed prediction with base. Let w be composed
correct/base wrong cases, l be the reverse, m=w+l, n=number of examples. Require n>=20,
w>l and:

    20 * sum(binomial(m,k), k=w..m) <= 2^m

If true, score=floor((w-l)*1,000,000/n); otherwise score=0. The same rule measures each
expert's ablation (replace its delta with base only on requests routed to it). This rule
uses arbitrary-precision integers; timing floats never enter ledger decisions.
No-evidence, degradation or insufficient sample size yields zero, not a guessed utility.
Multiple testing and adaptive experiment reuse are additional scientific limitations;
external acceptance must prescribe family-wise/error and future-window controls.

Two separately executed evaluation partitions produce exact artifacts. In the devnet,
two distinct known, non-author Ed25519 identities attest the submitted bounded score and
evidence digest. Minimum score freezes when the threshold is reached. These identities
are under the same experiment operator; signatures do NOT establish operator independence.
Their attestations affect application adoption and reward only, never block work.

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

After20 blocks, a contributor claims floor(budget×score/total). The proof binds its
identity, contribution and accepted score; a root-relative nullifier forbids repeats.
A new nonce does not bypass the claim nullifier. Dust remains in the reserved pool.
Fork reorganization can remove the entitlement; actual prior service facts cannot vanish.

## M1.6 Author-offline use and free inference

Two local custodians store independently read-back copies of the exact public model.
During the test, the author's original file is renamed away and a separate consumer
process loads a custodian copy. This tests removal of one source path, not independent
geographic DA, legal erasure, anonymous-host trust or long-term retention availability.

A sponsor reserves quota for an unfunded consumer and specific provider. Consumer signs
H("use",quota,provider,provider_tx_nonce,units,result). Provider submits the signed use;
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
