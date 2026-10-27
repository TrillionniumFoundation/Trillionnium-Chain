# Public neural tasks: bounded research contract

**Research only; no runtime implementation, new acceptance flag or activation.**
This note refines the gap in the [public bootstrap](PURE_PON_PUBLIC_BOOTSTRAP_V1.md),
not the development plan. The inspected Chain source is
[`9e05ad5d237660fb0ea8b40dd5c29af4225551d3`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/9e05ad5d237660fb0ea8b40dd5c29af4225551d3).
The Hepta public V2 profile was read locally at
`749699152b5f29840632c8a4d1c3a757ec119996`; the three inspected profile files are
byte-identical to local `d40231daabb39112e6de2e84a205f0a8d8cf25de`, whose complete
source tree is published as
[`f75bf1ac902ed73905e4daa49f9396df028a4254`](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/f75bf1ac902ed73905e4daa49f9396df028a4254).
This records inspection/publication provenance, not a new model execution. Its
exact numeric contract is recorded below. No new experiment is reported here.

The candidate keeps the existing pure PoN relation, target, validated cumulative
work, branch checks and single durable state owner. It adds no stake, committee,
hashcash threshold or model-quality contribution to chainwork. It would still
change task eligibility and state semantics, requiring an explicit new profile.
The existing W1 hardness and false-trace rejection vetoes remain open.

## Existing components and the two funding cases

The current `public_task_bootstrap` exposes the original genesis maintenance
matrices without a source private key, pre-existing balance or caller roster.
Its useful-output credit is zero. It cannot be relabelled as model learning.

M02 `QualifiedWorkTask`, `DemandLeaseV2` and M06
`qualified_task_lifecycle::{eligible_task,consume_output}` already exist.
The ordinary ledger path checks signatures, account nonce and fees before task
commands; tags 18 through 21 have base fee 100, tag 22 has base fee 200, plus
byte fees. Registration must be present in the parent before a task is mined.
The output owner records arithmetic identity; it issues no extra reward and
does not authorize a model effect or Hepta use.

* **No initial external funds:** a node can first mine maintenance, wait for its
  ordinary reward to mature, and pay the existing task fees. This addresses the
  initial balance only; a typed neural compiler and consumer are still needed.
* **The first neural task must need no balance or external order:** introduce a
  separate, deterministic endogenous task-eligibility profile. Its bounded
  ready queue is derived from the accepted parent program frontier and pinned
  public model/data/recipe. Any node reconstructs the same tasks. No fictitious
  requester/source lease, embedded fixture signature or implicit credit is used.

The second case is permissionless execution of a public generator, not unlimited
free admission of arbitrary caller programs. Task count, material size, dependency
depth, ready-set selection and per-parent preparation need explicit bounds.
The queue must not let a miner choose a cheaper labelled task or grind its
numeric semantics through nonce choices. A missing or invalid selected neural
task must fail as that task; it cannot silently become successful maintenance.

## The useful product survives blinding, but repeats across nonces

In `trnm-crypto-primitives/src/pon_work.rs`, let `E = EL ER`, `F = FL FR` and
`Cprime = (A + E)(B + F)`. The original correction computes

```text
C = Cprime - A F - E (B + F) = A B (mod q), q = 4294967291.
```

The final C is an unblinded, usable field product. The challenge changes noise
and the complete 512-tile transcript, not this product. `PreparedTask::new`
already computes C once and `product_bytes()` exposes the cached result;
new challenge proofs still require the original transcript relation. A cached
product or `PublicProduct` reject-only fact is never `VerifiedWork`.

Consequently, repeated nonce attempts and multiple miners can reuse the same
mathematical result, but do not produce a new neural result on each attempt.
The existing meter excludes mining nonce but includes `demand_id`; a new demand
ID alone must not manufacture a distinct useful computation. Keep three roles:

* A **result key** commits the numeric contract and exact A/B bytes; identical
  arithmetic can be cached across requests and consumers.
* A **semantic use key** commits program/compiler/model/tokenizer/data roots,
  generation, step, batch, operator, coordinates and predecessor-output roots.
  It binds where the result is actually consumed and excludes mining nonce,
  caller identity and a caller-chosen demand label.
* The existing **work identity** remains challenge, task and target bound.
  Neither cache reuse nor a new semantic use counts as a second fresh computation
  or establishes a model improvement. Utility is not an input to chainwork.

## Reuse the actual compiler, then complete one actual operator

`trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs` already independently replays
complete checkpoint bytes, a bounded safetensors header, original activation
bits and all derived A/B values. It uses exact integer IEEE decoding,
nearest/ties-even before clipping, and canonical field encoding. This is a
substantive reusable component, not a complete neural compiler.

Its fixed source is `model.layers.0.self_attn.q_proj.weight`, BF16, 576 by 576.
The current policy takes only output coordinates `[0,64)` and input coordinates
`[0,64)`. It quantizes weights by `2^14`, clipping to `[-32767,32767]`, and F32
activations by `2^4`, clipping to `[-128,128]`; unused token columns are zero.
Every nonfinite original activation rejects. Its actual prehook observation is
not an independent proof of the full token-to-activation forward relation.
`checkpoint_tile_policy_v1::check_manifest` expressly requires maintenance,
zero useful-output limit and unaccepted hardness.

For a first new contract, extend this exact construction to a complete linear
operator and a consumer. The following names are proposed private-constructor
types, **not existing APIs**:

| Proposed checked fact | Required binding and owner |
| --- | --- |
| `EndogenousNeuralProgramV1` | Pinned program/compiler, model, tokenizer and public-data roots; parent frontier; bounded deterministic ready set; existing M06 branch owner admits transitions. |
| `VerifiedNeuralOperandsV1` | Original tensor bytes/name/dtype/shape/offsets, all tile coordinates, tokens/mask/positions, predecessor outputs and their derivation, exact numeric contract, canonical A/B/task ID, and expected consumer input slot. Source replay constructs it; descriptor claims cannot. |
| `VerifiedNeuralContractionV1` | An actually verified W1 result plus matching operands; unique signed-integer decoding under a proved range bound; semantic use and dependency checks. Bare product bytes or a hash match cannot construct it. |
| `NeuralConsumptionRecordV1` | Actual consumer input/result roots, complete tile coverage and next operation; atomically deduplicated per branch. Validation, consumption and model efficacy remain different claims. |

Pin compiler semantics, not an arbitrary downloadable program. Provenance of B
requires a checked predecessor relation from the specified token/model state;
replaying a hook file's hash does not supply it. A bit-exact canonical prefix or
another separately qualified complete relation is still missing. Deterministic
integer nonlinear operations are needed if they enter this consensus-derived
program. A CPU floating-point hook is not silently promoted into that role.

### Exact range and coverage counterexample

For the existing quantization parameters, one 64-term tile output satisfies

```text
64 * 32767 * 128 = 268427264 < (q - 1)/2 = 2147483645.
```

It can therefore be uniquely decoded from the field into the signed interval.
But the complete 576-term sum has the conservative bound

```text
576 * 32767 * 128 = 2415845376 > (q - 1)/2.
```

Within those allowed operand ranges, an all-32767 weight row and an all-128
activation vector give positive `2415845376`; centered decoding of their field
sum instead gives `-1879121915`. This is a range counterexample, not an observed
row of the pinned checkpoint.

Decode each checked 64-term tile first, then accumulate nine terms in checked
i64. Summing all nine tiles modulo q and only then applying centered decoding
is wrong for allowed inputs. Requantization/dequantization has exact scale
`2^-18`; its rounding, saturation and downstream type must also be specified.

A complete 576 by 576 q_proj for at most 64 token columns requires
`(576/64) * (576/64) = 81` W1 tiles. The existing prefix is just one of them.
These are integer derivations, not throughput or quality measurements. A full
linear operator still does not establish RMSNorm, RoPE, attention/softmax,
SwiGLU, residual or adapter semantics; training additionally requires gradients,
optimizer state and the exact update relation.

## Hepta V2 is a different numeric contract

The inspected Hepta files are
`codex-rs/hepta-learning-artifacts/profiles/smollm2-public-initial-v2.{profile,target.json,plan.json}`.
Their target contract is
`c9b06f9a029a3257801844f89acb59b5f59f6a39087335af323f274e9152992f`:
storage and accumulation are `float32`, and quantization is `none`.
The public plan is
`4eb748aee63bb946b93c5df6780833691dc3a90e91dd1d8e6d29d1c93b9c7420`,
with 10 training steps and 20 public tasks (12 training, 4 calibration and
4 evaluation). The initial loader requires generation 1, no predecessor, and
the fixed 933664-byte zero-adapter artifact with SHA256
`1c5af7b5a7144a619dfac83b14bd83ae77f1e2227b18a6a9c5dcb214889a0cba`.
Its public reproducibility does not establish new learned value.

No inspected ordinary Hepta consumer accepts the integer tiles above. A new
numeric target and executable/profile digest are required before a consumer
can use their aggregate to continue a real forward pass. An integer result
cannot masquerade as c9b06 FP32 output, reuse the initial V2 qualification, or
alter CURRENT. Product qualification and installation retain their existing
owners; controlled positive results do not fabricate longitudinal credentials.

| Surface | Reuse or version requirement |
| --- | --- |
| PNW1 N64 field relation and original work verification | May be reused unchanged for an exactly matching contraction; this does not qualify hardness or the neural provenance. Changing its relation/fields requires a new work version. |
| Existing signed leases and fees | Preserve their current meanings. Fee-free endogenous eligibility needs its own profile/state namespace and explicit parameter/genesis binding, not a permissive QDL2 reinterpretation. |
| Checkpoint parser, integer quantizer and field codec | Reuse implementation after preserving old behavior. Generalized coordinates, prefix derivation and consumer semantics require a new descriptor/policy identity. |
| TCM1/TCR1 byte distribution | Reuse opaque transport with new exact family/layout/runtime/content IDs. They do not themselves express a complete dependency graph or grant model use. |
| Hepta c9b06 and initial V2 | Do not reuse their numeric/qualification identity. A new target, consumer profile and actual qualification are required; existing durable CURRENT/installer ownership is retained. |

## Acceptance obligations for an implementation

These are proposed tests, not tests executed by this note.

| Test | Required observation or rejection |
| --- | --- |
| Empty-account bootstrap | A fresh node without source/requester keys reconstructs the same real task; no hidden credit or fee exemption in the legacy namespace; wrong program/genesis rejects. |
| Numeric differential | All finite BF16 patterns and independent reference; F32 signed zero/subnormal/ties/clipping/nonfinite boundaries; canonical bytes agree across supported architectures. |
| Operand provenance | Changed checkpoint bytes, offsets, coordinates, tokens, mask, tokenizer, predecessor roots or compiler identity reject even when a new descriptor is self-consistent. |
| Full operator coverage | All 81 tiles match an independent implementation of the new integer semantics; missing/duplicate/wrong-k tiles and padding presented as real tokens reject. |
| Range checks | The 576-term counterexample, maximal positive/negative tiles, checked i64 aggregation and modular aliasing are covered. |
| Nonce and semantic reuse | C is identical across challenges; each fresh work claim still verifies; correct C plus forged trace fails; duplicate result/use keys cannot mint fresh computation credit. |
| Actual consumption | Disable the consumer's substitute GEMM/fallback, preserving original W1 verification; the real consumer uses the verified tile aggregate, continues to logits and matches the new numeric reference. A correct C for another input slot rejects. |
| Namespace refusal | Invalid neural material cannot retry as old maintenance, c9b06 FP32, a legacy lease, or a different numeric profile. Cache hits never bypass the checked constructors. |
| Reorg and crash | Frontier/output/use records commit atomically, survive reopen without double consumption, and respect branch rollback and predecessor identity. |
| Availability and budgets | Missing cells, stalled peers, hostile material and queue saturation preserve original deadlines/bounds and fail explicitly; no unavailable artifact is replaced with stale bytes. |
| Efficacy and installation | Compare actual outputs and downstream effects with the FP32 baseline under the new contract. No positive gain means hold; neither an enum nor zero-adapter bootstrap issues a product credential or changes CURRENT. |

Even a correct consumer does not guarantee indefinitely useful learning. Fixed
public samples can be exhausted or overfit; relabelling them creates no new
information. Missing useful tasks or nonpositive candidates may leave explicit
pure PoN maintenance running while learning remains on hold. Structured/low-rank
operands, output amortization, full-trace verification cost, data availability
and the security of the original work relation remain separate blockers.

## Primary numeric references

* [Google LiteRT quantization specification](https://developers.google.com/edge/litert/conversion/tensorflow/quantization/quantization_spec): scales/zero points and per-axis rules; the specification explicitly warns that hardware implementations may be non-bit-exact. It is not a consensus determinism guarantee.
* [ONNX QuantizeLinear](https://onnx.ai/onnx/operators/onnx__QuantizeLinear.html): nearest-even, saturation, quantization granularity and division precision. Pin the chosen operator version and types; merely saying "ONNX/int8" leaves semantics underspecified.
* [I-BERT original paper](https://arxiv.org/abs/2101.01321): integer Transformer inference also requires nonlinear approximations. Its BERT/RoBERTa results do not establish this SmolLM numeric profile, general training, or PoN security.

## Parent context is not an unbiased task-selection beacon

This is a design constraint for a future endogenous neural-task profile, not
an observed exploit of the fixed public maintenance task. At Chain source
`9e05ad5d237660fb0ea8b40dd5c29af4225551d3`,
`Settings::consensus_maintenance_material` in
`trillionnium/crates/trnm-pon-node/src/lib.rs:477–481` and
`Node::make_consensus_maintenance` in `src/store.rs:4270–4283` obtain the fixed
`continuity_v1::maintenance_matrices()`. The latter passes the parent into the
original block construction; it does not use a parent hash to draw a neural
task. No runtime or tested-source behavior changes in this paragraph.

A parent identity must remain bound to the chain context. That does not make
its hash an independent, unbiased source for choosing the next operands or
their reward. A producer can search its allowed nonce/header space and may
choose transaction contents, candidate valid parents and publication timing.
Deriving a task with `H(parent) % task_count` can therefore make favourable
future operands, structured low-cost work or output value part of the search
objective. Finding an alternative valid parent may itself require work; the
attack cost and benefit must be analyzed, not presumed free or impossible.
Using an older ancestor only changes the timing and cost of this strategy; it
does not by itself prove that selection is unbiased.

A proposed compiler/scheduler must freeze semantic task identity, eligibility,
output uniqueness, task ordering and the input commitment point. Its adversarial
analysis must include selectable headers and task descriptors, multiple valid
parent choices, adaptive withholding, predictable future jobs and differently
structured operand costs. Deterministic selection from committed state may
remove particular lottery knobs, but a mutable task set or manipulable ordering
introduces other choices that need the same analysis. This is not a reason to
weaken the original relation, count repeated C as fresh useful work, introduce
hashcash, or add stake/committee authority. It remains an unimplemented research
obligation under the original pure-PoN boundary.
