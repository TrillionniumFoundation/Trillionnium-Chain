# Declared target decoder interface and larger-model run records

[`llm_adapter_contract.py`](../../../../formal/pon-nakamoto-v1/llm_adapter_contract.py)
implements closed, versioned target-model manifests, supplied tensor-byte binding,
typed decoder wrappers, a frozen comparison/cost plan and deterministic assessment
of reported outputs. It imports the existing wire/hash owner, requires no new
trainer or economic ledger, and changes no existing model artifact, native work
profile, evaluation/reward policy or Hepta release owner.

This is an executable interface contract, **not an executed target LLM**. No target
weights, real tokenizer, authorized future task release or deployment GPU have been
supplied. The test fixtures are fabricated: one tiny zero-byte tensor set and a
32-layer shape declaration with unavailable placeholder weight digests. Neither is
model efficacy evidence. The existing attribution campaign still runs the original
257-feature model through its actual learning/inference owners.

## Exact model, tokenizer and insertion context

`pon-target-decoder-adapter-contract-v1` binds network/parameters, a reference,
architecture, complete backbone tensor index/root, tokenizer index/root, numeric
operator contract, sorted targets, wrapped ports and external registration references.
`freeze_target_contract` returns canonical bytes and a separately retained domain
digest. `verify_target_contract` additionally requires the admitting owner's retained
backbone and tokenizer roots. Copying received hashes into those expected arguments
does not independently admit a model. Duplicate JSON keys, noncanonical bytes,
unknown fields and mismatched roots reject.

The supported architecture is explicitly a bias-free causal decoder with RMSNorm,
RoPE, grouped-query attention and SwiGLU. Fields freeze layer count, hidden/intermediate
width, query/KV head counts, vocabulary/context, rational RoPE base and norm epsilon,
and tied embedding behavior. Hidden width is divisible by the number of query heads;
the number of query heads is divisible by the number of KV heads; rotary head width
is even. For head dimension d and KV
heads k, K/V projections have output k*d, Q/O have hidden width, gate/up have
intermediate width and down projects to hidden width. The complete tensor inventory
includes both norms in every layer, seven projections, token embedding, final norm,
and a separate LM head only when embeddings are untied. Missing/extra tensors and
dimension, dtype or byte-length substitutions reject. This does not discover or
verify an arbitrary architecture from its name.

Tokenizer records bind exact file lengths/SHA-256, vocabulary and BOS/EOS/PAD IDs,
prefix/suffix behavior, chat-template commitment and a tokenization-behavior contract.
`verify_tensor_material` checks every supplied file/tensor byte against the retained
index. It does not download weights, validate licenses or prove provenance; an index
declaration without actual bytes remains a declaration.

The numeric profile supports little-endian BF16 or FP32 storage, declared FP32
accumulation, no quantization and insertion
`x W^T + (alpha/rank) ((x A^T) B^T)`. Every target names an existing layer projection
and freezes A rank×input, B output×rank, rank≤64 and a reduced positive rational
alpha. `pon-wrapped-decoder-lora-material-v1` binds exact factor tensor hashes,
shapes, rank, alpha and dropout=false to that contract. Actual supplied factor bytes
must match; IEEE NaN/infinity factors reject. An operator-contract digest still
requires a real reviewed runtime defining casts, rounding, ordering, kernels and
determinism. Byte equality and this FP interface do **not** extend the separate exact
integer-BA equivalence theorem to floating LoRA or nonlinear model behavior.

## Wrapped decoder ports

`pon-causal-decoder-token-and-logit-ports-v1` fixes eval mode, dropout=false,
int64 token IDs, Boolean masks, declared FP32 logits, left padding with an explicit
mask, rejected truncation and fixed-count greedy decoding with lowest-token-ID ties.
The contract bounds batch, input/output lengths and their sum within context.

`validate_decoder_request` requires rectangular batches, vocabulary-bounded integer
IDs, a nonempty left-pad mask per row, the declared pad token in masked positions
and the exact target contract. Boolean token aliases and oversized requests reject.
`validate_decoder_response` checks request identity, batch/token counts and vocabulary
bounds, and hashes exact UTF-8 decoded output bytes. It does not itself run forward
passes, inspect logits or verify that token IDs decode to the reported text. The
actual tokenizer/runtime owner must perform and retain those checks. Different
whitespace produces different output roots; this is not a semantic equivalence oracle.

## Frozen comparison, scoring and cost plan

`pon-target-decoder-evaluation-run-plan-v1` fixes target/weight/tokenizer roots,
candidate artifact, calibration/evaluation task records, source groups, expected
output-byte hashes, token limits, metric, repetitions/seeds, shared per-run resource
ceilings and stopping rule. Freeze and externally register it before candidates,
task revelation and scores; `freeze_run_plan` alone cannot establish that chronology.
`verify_run_plan` requires the retained plan and owner-registration identity.

Four mandatory control artifacts are distinct from the candidate:

1. Current immutable backbone with no adapter or training.
2. Fresh LoRA trained with the same declared resource ceiling.
3. Full tuning with the same declared resource ceiling.
4. Randomized LoRA with the same declared rank/interface.

The control IDs require their actual producer to retain the corresponding training,
initialization, rank and artifact evidence; names or different digests do not prove
that those controls were honestly produced. Shared ceilings bound reported spend;
they do not imply equal consumed CPU/GPU/FLOPs. All repeats and fixed seeds must be
reported; post hoc best-seed selection and early stopping reject. Tasks have unique
IDs and prompt-byte hashes across calibration and evaluation. This prevents exact
byte reuse, not semantic leakage, hidden common control or future-task knowledge.

The implemented metric is **equal-source-group exact-output-byte accuracy**. It is
appropriate only for tasks whose frozen target bytes define the objective, such as
a deterministic structured answer. It measures no general language quality, safety,
neural-circuit optimum or statistical significance. Source groups are externally
declared clusters and are not assumed independent.

`evaluate_run_record` requires every candidate/control, every frozen seed and every
task output. It recomputes grouped accuracy and averages all repeats. Calibration
selects the highest-scoring control using the frozen tie order. The assessment also
reports the candidate's gain against the **strongest control on evaluation**, so a
positive parent or calibration-selected gain cannot conceal a stronger held-out
baseline. This latter comparison is a conservative descriptive check, not an
independent new selection window or a replacement for E3's current strongest-control
acceptance gate, multiplicity policy and M10/M12 authority.

Each reported run retains all repeated cost entries, including failures, retries and
cache hits. Required stages are model load, tokenization, training, adapter-material
checks, calibration, evaluation, downstream use and retention/DA. Known CPU/GPU/wall
time and bytes are summed; peak memory is the maximum observed peak. Shared per-run
ceilings include training steps/FLOPs. Unknown GPU time remains null in the aggregate
and cannot establish a GPU budget bound. Summed wall time is cumulative reported
work, not parallel elapsed time; maximum process peaks do not establish simultaneous
VRAM occupancy. Missing stages, overflowing totals or exceeded reported ceilings
reject. No downstream-use count or unique-benefit reward is inferred from these
cost entries; the existing consumer/operation owner and useful-output observer
retain that separate responsibility.

Record roots bind declared runtime source/binary, hardware and observer references.
They do not authenticate physical execution, exhaustive costs or observations.
Recomputing byte-match scores proves arithmetic over the supplied output record;
it does not prove those outputs came from the declared LLM. Every assessment has
runtime/authenticated-inference/prospective/independent/public-reward acceptance
false. No self-published registration root can change those values.

## Invocation and remaining owner evidence

```bash
python3 formal/pon-nakamoto-v1/test_llm_adapter_contract.py
```

Public use still requires actual authorized backbone/tokenizer/adapter bytes,
reviewed architecture/operator/tokenizer execution, independently authenticated
output records, prospectively admitted untampered chronological tasks and custody,
budget-matched producer evidence, poisoning/backdoor/forgetting controls, all failed
and stale attempts, independently retained use receipts, and measured GPU/VRAM,
loading, inference, retention and DA costs. Those are required missing inputs;
manifest or scoring success cannot manufacture them. General functional equivalence,
arbitrary neural-circuit optimality and fresh consensus-work hardness remain open
research obligations described in [model attribution](MODEL_ATTRIBUTION.md) and
[public qualification gates](PUBLIC_READINESS.md).
