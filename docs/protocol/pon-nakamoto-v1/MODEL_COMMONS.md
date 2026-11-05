# Public model commons and the real-task learning loop

Status: development contract, no empirical efficacy or current product activation.
Owners: M10 lifecycle, M11 evaluation, M09 artifacts, M12 allocation, M14 public use.
Hepta remains owner of training, runtime, local memory, artifacts and effect authority.

## L1. The required closed loop

Authorized real task -> local adaptation -> parameter publication -> independent
out-of-node evaluation -> composition/router adaptation -> whole-model evaluation
-> public release -> measured free consumption -> next authorized learning cycle.
A market which only uploads hashes, pays receipts or counts GPUs does not satisfy it.

The model has shared base theta, organ adapters phi, cell/expert adapters psi,
router rho and typed composition graph G. Compatible experts can form a sparse MoE
or adapter composition; periodically distill useful public behavior into a smaller
base/release. These are two reproducible artifacts, not arbitrary API routing hidden
behind the label "one large model". Base weights count once. Model-internal depth,
Cell activation depth and parameter count are not interchangeable measures of intelligence.

## L2. ParameterContribution

The versioned logical record binds contribution id, author/payout, parent release,
compatibility-family id, exact base/tokenizer/encoder/normalizer hashes, layer names,
shapes/ranks/scales/order, delta/head bytes and size, numeric/calibration/state schema,
permitted graph role, task/source lineage, authorized-use/export policy, training
configuration, resource observations, availability/retention and publication nonce.
Only canonical registered data formats are accepted; loading a contribution must not
execute a pickle, installer, dynamic import, shell command or arbitrary model plugin.

Artifact bytes are content addressed and actually retrievable from multiple independent
custodians before adoption. A signature attributes a claim; it does not prove ownership,
consent, training provenance or quality. The network checks the declared policy under
its trust model; it cannot infer legal rights or personal-data consent from a hash.
Private parameter contributions that cannot be redistributed are not advertised as
part of the freely downloadable public model.

Fine-tuning must respect the parent's compatible frozen bundle. For aligned linear
adapters, a permitted example is W=W_base+B_organ*A_organ+B_cell*A_cell, with exact
scales and order. It is not a merge law for arbitrary models. Different model families
use versioned ports or evaluated distillation; they cannot average tensor positions by
name alone. An old adapter is not silently rebased to a new tokenizer/base version.

## L3. EvaluationPlan and EvaluationReceipt

Before evaluation, lock candidate bytes, reference model, task strata and weighting,
metric arithmetic, quality/regression thresholds, uncertainty method, resource budget,
composition/retraining recipe, evaluator role, data-access/consent, anti-contamination
policy and appeal/retention schedule. Local training loss and self-reported NDU utility
are not globally comparable evaluation scores.

Use independent held-out tasks, cross-node tests and a future-time observation window.
Evaluate target gains, old-task retention, calibration/abstention, privacy/backdoor
probes and actual full serving cost. Feedback from free users is opt-in for learning;
service permission is not export or training consent. Publishing parameters is not
privacy proof. A revoked dataset cannot reenter via old checkpoints or cached views.

A receipt binds exact candidate/reference/plan/environment, data commitment, numeric
results and uncertainty, evaluated scope, cost, evaluator identity and complete evidence.
A publicly reproducible deterministic profile can be checked independently. A private
holdout or human assessment is an explicit attested trust class, not deterministic
on-chain truth. Commit-reveal can reduce direct score copying, not prove independence.
Evaluator count/stake, votes and scores do not contribute consensus chainwork.

### Preventing optimization of the evaluation process

The following six acceptance obligations apply to the existing evaluation, artifact,
selection and effect owners. They are not satisfied by a new report flag or another
evaluation implementation. A failed or unobserved obligation keeps adoption and
model-improvement reward unqualified.

| Attack | Required owner behavior | Evidence needed to close the obligation |
|---|---|---|
| Memorized tests and adaptive repeated submissions | Freeze the baseline, candidate, complete composition, metrics, thresholds and resource budget before disclosure. Consume the task exposure and a model-family trial allowance before returning prompts, labels or metrics. Retain failed, cancelled, incomplete and no-update attempts. | A durable, fenced owner spanning restarts, hosts and related author identities; untouched prospective cohorts; a declared family-wide multiplicity or sequential-testing policy. A new output directory, renamed candidate or new key cannot reset the allowance. |
| Author/evaluator collusion | Bind verified controller provenance and conflicts of interest; blind candidate/control labels where the metric permits; require independently operated cross-evaluation and a bounded dispute process. | Independent administration and data custody, exact signed input/output records, retained disagreement and appeal resolution. Distinct keys or controller strings generated by one host do not prove independence. |
| A better Cell makes the combined model worse | Bind the full release root: base, tokenizer, all active Cells, router, graph, loader/runtime and serving profile. Evaluate the complete composition against the actual admitted predecessor and frozen strong controls. | Separate measured channels and units for task quality, routing, old-task/rare-cohort noninferiority, calibration/rejection, latency and memory, including warm/cold loads. Renaming the same scalar estimator as several metrics is insufficient. |
| Rewards for tiny or costly versions | Require a preregistered minimum net utility over the declared horizon, with the no-update action available. Account for training/search, failed/retried evaluation, download, activation, serving, resident memory, storage/repair, rollback and future selection costs. | A conservative benefit bound after all applicable costs, enforced release-rate and retained-byte budgets, and an owner-accepted terminal no-update receipt when all observations complete without adoption. Missing RSS, failed execution or missing cost is an incomplete observation, not a legitimate successful no-update. |
| Backdoored or malicious weights | Run the actual candidate and full composition through clean tasks, trigger/poisoning probes and policy/tool-boundary checks in the admitted isolated loader; retain quarantine, revocation and rollback owners. | Real loaded-byte observations, held-out behavioral regressions, canary observations and withdrawal/rollback drills at a newly authorized generation. File integrity is not behavioral safety. |
| Code introduced through a weight update | Admit only the selected bounded data format and exact tensor inventory; check size, shape, dtype, offsets and numeric validity before copying any parameter. Use one verified byte snapshot. Code/runtime changes need their own release and capability authorization. | Actual loader refusal of executable formats, substituted files, dtype conversion, shape broadcasting, nonfinite values and undeclared tensors, followed by current-generation/FinalUse checks. A weight signature cannot authorize a plugin or executable replacement. |

The net-utility decision must keep hard safety, consent and resource constraints
separate from any weighted score. Cost terms need a frozen unit/tariff and horizon;
an omitted cost cannot become zero, and a high quality mean cannot offset a failed
mandatory cohort. A rejected update retains the actually admitted predecessor.
The statistical family must include the adaptive search that produced the proposed
version; a per-run comparison count alone does not bound repeated submissions.

The [reported-acceptance and exposure contracts](details/MODEL_OPERATIONS_ACCEPTANCE_V1.md)
already preserve pending/aborted windows and explicit no-update decision relations.
They remain offline relations whose returned pins require persistence by the actual
owner. Their hashes do not establish a global trial ledger, undisclosed-task custody,
independent administration, authenticated model execution or positive net utility.

At the inspected Hepta source
[`e0b4c82e`](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53),
the [study plan](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53/codex-rs/hepta-infer-worker-host/src/smollm_study_plan_tests.rs)
registers binary correctness, while the
[study evaluation](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53/codex-rs/hepta-infer-worker-host/src/smollm_study_evaluation_tests.rs)
creates its controlled holdout owner within the run directory. The existing
[fenced holdout owner](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53/codex-rs/hepta-intelligence-eval/src/fenced_holdout.rs)
and role-separation checks are reusable boundaries. This inspected study does not
close the cross-run family trial allowance or the full-composition resource and
net-utility requirements above. This is an exact-source observation, not a claim
about a later Hepta revision or a new authorized Chain/Hepta execution pair.

The chain verifies bounded registered statements and transitions. It does not run an
unbounded benchmark or call an LLM/web API inside block validity. Evidence unavailable
at admission rejects/defer under the profile, not a fabricated pass. Future evidence
can change adoption or escrow under the contract; it does not retroactively change
whether a formerly valid block contained a valid work proof.

## L4. CompositionCandidate

Local optima need not compose. Keep a candidate expert library; train/calibrate router,
connectors or allowed adapters with a frozen budget and compatibility contract. Compare
base only, best single expert, simple merge, routed experts, composition-adapted model
and distilled release under equal declared resources. Include interference, rare tasks,
non-IID data, cold loading and topology/rollback costs.

A candidate binds parent release, complete expert set, routing/graph, inheritance,
transforms, parameter manifests, serving profile and reproducible build procedure.
Quality must be measured on the WHOLE composition. Router and composition contributors
can earn credit. Test complementary pairs/bundles; purely greedy single-expert selection
can discard genuinely useful combinations. Omitted/private states cannot be recreated
by claiming that adding more cells recovers missing information.

## L5. GlobalModelRelease lifecycle

Proposed -> ParametersAvailable -> IndependentlyEvaluated -> CompositionEvaluated
-> Included -> PolicyConfirmed -> CanaryObserved -> FutureWindowObserved.
Any chain-derived stage can become Reorged; publication bytes remain historical facts.
A new release is an immutable manifest of base, experts, router, graph, interfaces,
calibration, evidence, serving profiles, attribution and use conditions. Peers reproduce
it without the author online. Duplicate release identities and missing dependencies fail.

Global publication does not compel local activation. A Hepta host checks current local
authority, selected artifacts, body/organ generation, resources and rollback admission.
It drains in-flight work and adopts a NEW generation; running tasks never mix releases.
Emergency local quarantine can stop a poisoned expert without waiting for a block.
A local stop cannot mint a replacement global release or broaden authority.

## L6. Rewards and public use

Evaluate marginal contribution to the locked public baseline and admitted composition,
not only a standalone score. State the counterfactual composition procedure and its
compute allowance. Use bounded leave-one-out/bundle ablations and sampled attribution,
with uncertainty and dependence disclosed; full exact Shapley computation is not required.
Duplicate/near-duplicate experts, identity splitting and copied public deltas are tested
as attacks, not solved by a content hash or an attribution formula alone.

Separate block-security reward, model-improvement reward and serving/storage/evaluation
payment. Non-miners can contribute parameters. Non-contributors can use a bounded free
basic tier. Downloadable parameters incur no model-use fee under the accepted public
license; local computation remains the user's resource cost. Hosted free inference is
budgeted and metered, with honest queues and limits; see ECONOMICS.

## L7. Cross-repository integration

Hepta learning.operator trains, learning.artifacts owns bytes/lineage, learning.eval
owns evaluation, learning.plasticity proposes next-generation changes, and Neuron/
Intuition/inference consume admitted bundles. kernel.operations owns intents/outboxes
and reconciliation; memory.federation stays read-only and is not a new export/training
owner. The chain adapter verifies PoN confirmation/inclusion and submits idempotent
business operations, not a second learning store or local capability issuer.

The existing Hepta four NDU subject classes remain System/Domain/Agent/Episode.
A global market/chain does not become a mandatory fifth central optimizer. Principals
keep distinct goals; public metrics do not override their hard constraints. Learned
routing and model parameters cannot become execution tokens or rewrite deterministic
reflex, truth, ownership, revocation or privacy boundaries.

## Executable bounded attribution and evaluation lifecycle

[Bounded linear attribution](details/MODEL_ATTRIBUTION.md) recomputes exact BA normal
forms, merges known-source/copy budgets, retains complementary components, exhausts
finite subsets and records downstream use and every reported verifier attempt cost.
Fingerprints and probes never become general functional-equivalence proofs. Optional
LLM metadata is unexecuted; independent prospective target-model acceptance remains
required. No chain reward authority is added.

[The frozen public-evaluation lifecycle](details/PUBLIC_EVALUATION_LIFECYCLE.md) seals
roster/lineage and task/model context, checks signed candidate/commit/reveal records,
enforces deterministic height deadlines and missing-evidence abort, retains signature
conflicts for next-round disqualification and records appeals without silent rescoring.
It is off-chain policy on existing owners; native revision4 and chainwork are unchanged.
Independent governance and truthful prospective measurement are not inferred from
distinct keys or signed minimum scores.

## Concrete compatible family and experiment

[M1](details/MODEL_EVALUATION.md) now defines exact features, tensor shapes, integer
inference, training recipe, evaluation rule, counters, artifacts and reward/free-use
transactions for a public-source routing task. It records a failed first run and all
stronger controls. This does not declare a universal large-model composition theorem
or an ordinary Hepta/future-window product acceptance.
