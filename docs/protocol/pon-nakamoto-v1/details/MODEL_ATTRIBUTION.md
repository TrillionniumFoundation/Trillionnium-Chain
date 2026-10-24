# Bounded linear adapter attribution and useful-output observation

This executable extension uses the existing learning/evaluation owners. It adds no
trainer, reward ledger or consensus profile. Implementation:
[`model_attribution.py`](../../../../formal/pon-nakamoto-v1/model_attribution.py);
attacks: [`test_model_attribution.py`](../../../../formal/pon-nakamoto-v1/test_model_attribution.py).
The E3 strongest-control gate and M10/M12 release authority remain necessary; positive
attribution cannot replace them.

## Exact adapter manifest

`pon-exact-integer-linear-insertion-v1` binds the existing family, parent artifact,
delta slot 0..2, rows=3, columns=257, scale=1024, rank 1..8, factor bound 32767 and
effective-update bound 32767. The router is frozen. Factor fields are exactly
`schema, contract, A, B`, with A rank×257 and B 3×rank. Verification recomputes every
entry of BA using exact integers, no rounding, and validates the entire normal form
and parent/slot/numeric context. Composed candidates still use the existing model loader.

Different factor bytes, zero-rank padding and changes of basis can yield the same BA.
Exact equivalence compares recomputed matrices, not only a hash. This proves equal
declared linear insertions for every input. It is not universal full-model equivalence:
unequal matrices can make identical argmax predictions. Equal probe predictions or
class labels do not prove equality or novelty over all inputs.

`freeze_adapter_manifest` returns canonical `pon-adapter-contribution-manifest-v1`
bytes and a separately retained digest. Closed fields are `schema, adapter_contract,
adapter, normalized_update, function_fingerprint, artifact, optional_llm_declaration,
scope`. `verify_adapter_manifest` reconstructs it and requires exact byte equality.
Existing v3 model artifacts still reject extra fields.

Optional `pon-llm-adapter-declaration-v1` binds base-model/tokenizer/architecture
digests, declared license reference and sorted target-module names with dimensions,
rank and scale. The numeric scope is exact linear BA only; `runtime_status` must be
`required-not-executed`. It supplies no LLM loader, floating-point LoRA proof, license
authority, training provenance or prospective acceptance. Qualified-runtime or unknown
fields reject.

## Source caps and declared duplicate perturbations

Before scores, `freeze_attribution_plan` seals parent, E3 bundle identity, partition
manifest, submissions, admitted source-lineage mapping, source caps and a declared
coordinate-wise L-infinity tolerance 0..8. At most 16 submissions yield at most 8 source
groups. Source admission comes from the existing owner, not a miner's asserted label.

1. Recompute matrices and sort by canonical normal form, then submission ID.
2. Assign each matrix to the first fixed representative within tolerance; otherwise
   create a representative. Tolerance zero is exact BA deduplication.
3. Collapse each cluster to its representative. Union clusters sharing an admitted
   lineage; retain distinct complementary components but one source budget.
4. Use the minimum admitted source cap per merged group, so an extra copy/key/source
   alias cannot raise it. Sum retained components; overflow rejects without clipping.

Positive tolerance is a conservative admission rule, not functional equivalence or
complete semantic-copy detection. It can discard a real small improvement; a changed
admitted set can change its representative. Freeze the full set before evaluation.
Poisoning, collusion, false source admissions and copies outside this finite threshold
remain unresolved. Distinct lineage strings/keys do not establish independent control.
Caps are diagnostic attribution units, not chain credits or balances.

## Complementarity and finite optimality

For n groups, run all 2^n subsets including the parent through existing `predict_rows`
and equal-source-group `macro_accuracy`. All subsets must remain feasible; total
additional inference is bounded to 1,048,576 prediction rows. Ties select highest
accuracy, fewest groups, then lowest mask. No router retraining occurs.

Report standalone gain, fixed-router leave-one-out gain and exact Shapley over these
admitted groups. This is finite group attribution, not unrestricted neuron Shapley or
fair economic allocation. Joint gain minus the sum of standalone gains measures
complementarity. Tests actually execute two zero-standalone updates with joint gain 1
and group Shapley 1/2 each. A copy cannot be summed twice to manufacture that threshold.

The certificate contains every subset mask/value, winner, maximum and candidate gap.
`verify_attribution_result` repeats all inference/metrics and checks canonical result
bytes. Its optimum is only within the frozen feasible subset set on this empirical
objective. It proves no optimal weights outside that set, minimum circuit cost,
general nonlinear equivalence, future utility, original training or fresh mining work.
Public reward, ordinary Hepta and independent acceptance remain false.

## Unique useful output and all reported verifier attempts

[`work_utility.py`](../../../../formal/pon-nakamoto-v1/work_utility.py) provides
`UniqueUsefulOutputAccounting`; regressions are in
[`test_work_utility.py`](../../../../formal/pon-nakamoto-v1/test_work_utility.py).
Each attempt binds branch, source, checked function, admitted task-content root and
normalized output-content root. The unique key excludes A/B labels, report wrappers,
signer, nonce and branch. Canonicalization belongs to the evaluator; hashes cannot
detect arbitrary semantic duplicates.

Record intake, normalization, proof/plan checks, quality replay, retries, rejections
and consumer checks. Fixed required stages must be present before adoption can count.
Every invocation counts; Boolean aliases and aggregate overflow reject. CPU/wall/
declared primitive operations/bytes/peak-memory records are observations, not hardware
cryptographic proofs. Unknown GPU time is null. Summed wall time is cumulative work,
not parallel elapsed; memory is maximum observed process peak, not simultaneous sum.

Verification creates no actual-use count. The existing inference/operation owner
acknowledges after bounded use with durable operation ID and observed output root.
Positive verified gain, complete costs, active branch and matching output are required.
Repeated A/B content or new-branch reexecution adds no historical unique output.
Reorg changes current validity but retains prior costs and physical-use observations.
Existing operations/outboxes own durable retention; this is no replacement DB, economic
ledger, revocation authority or independent signed-use oracle.

## Actual training campaign and remaining gates

[`model_attribution_campaign.py`](../../../../formal/pon-nakamoto-v1/experiments/model_attribution_campaign.py)
uses the existing trainer for three actual 120-step public-source shards, freezes fresh
plans before A/B replay, and runs the existing inference-worker subprocess for observed
use. It submits alternate BA factors, a one-coordinate copy, repeated A called B,
stale attempts and branch reexecution. Synthetic complementarity is clearly separate
controlled attack evidence; it is not real-world efficacy.

```bash
python3 formal/pon-nakamoto-v1/test_model_attribution.py
python3 formal/pon-nakamoto-v1/test_work_utility.py
python3 formal/pon-nakamoto-v1/experiments/model_attribution_campaign.py --inputs /path/to/existing/model-inputs --bundle-hash OWNER_RETAINED_DIGEST --out /tmp/new-attribution-run
```

Existing output directories reject. Reports bind actual runtime versions, source/input
hashes and clean/dirty source; preserve failed runs and rerun changes into new paths.
Historical public partitions remain retrospective. Required prospective gates include
authorized target-model/data/tokenizer/license, independent untouched chronological
windows, frozen metrics/stopping/multiplicity/budget, consent/withdrawal and appeal
owners, budget-matched strong controls, adversarial evaluation and actual target LLM/
GPU-memory/latency measurements. Metadata or a larger planned family satisfies none
of these gates and does not establish a production work-hardness primitive.
