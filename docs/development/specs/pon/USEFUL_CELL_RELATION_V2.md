# Stateful useful-Cell reference relation V2

This increment belongs to the existing
[development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It adds `pon-useful-cell-stateful-int257-v2`, a fully replayed **bounded integer
source-router profile**. The original [V1 relation](USEFUL_CELL_RELATION_V1.md)
and its challenge domain, numerical rules, read-only state and evidence remain
unchanged. V2 is not an activated native Node work rule, ordinary Hepta Encoder
implementation, succinct proof, quality result or proof of work hardness.

## Executed surfaces

| Surface | V2 computation |
| --- | --- |
| Input | Replay the frozen Git source, inventory, snippet normalization, tokenizer, signed hashing and clipping. Compare every admitted source row, then actually apply the feature mask. |
| Model | Decode the complete integer base, router and three delta matrices; preserve the ordered bundle and use base plus the selected delta plus recurrent memory. |
| Route | Select only from the request's nonempty expert mask. Router ties choose the lowest legal index. |
| State | Recompute memory, remaining steps, sequence, RNG counter, optimizer moments and model artifact; generation and scope remain fixed. |
| Output | Execute emit, STOP, abstain or a typed tool proposal; reject a derived action outside the admitted legal action set. |
| Training | Recompute the loss, actual backward values, trainable mask, clipping, momentum and integer parameter update. |
| Segments | Replay actual values, link each segment to its contract, ordinal and predecessor, and compare the entire witness dataflow. |
| Time | Historical verification uses independently supplied parent state and protocol time. Live verification checks the consumer clock before and after complete replay. |

Implementation:

- [Execution semantics](../../../../formal/pon-nakamoto-v1/useful_cell_execution_v2.py)
- [Relation verifier](../../../../formal/pon-nakamoto-v1/useful_cell_relation_v2.py)
- [Execution controls](../../../../formal/pon-nakamoto-v1/test_useful_cell_execution_v2.py)
- [Relation controls](../../../../formal/pon-nakamoto-v1/test_useful_cell_relation_v2.py)
- [Task and segment attacks](../../../../formal/pon-nakamoto-v1/test_useful_cell_relation_v2_adversarial.py)
- [Executed source binding checks](../../../../formal/pon-nakamoto-v1/useful_cell_source_guard_v2.py)
- [Source binding attack controls](../../../../formal/pon-nakamoto-v1/test_useful_cell_source_guard_v2.py)
- [Fresh reproduction and cold reader](../../../../formal/pon-nakamoto-v1/experiments/useful_cell_relation_v2.py)

## Contract and independent context

The statement is still a computation relation

\[
R_v(T,s_{\mathrm{before}},y,s_{\mathrm{after}},w)=1.
\]

The canonical V2 contract includes task, parent context, before-state digest,
complete model identity, raw and masked source rows, executed policy, proof
identity and explicit research scope. The maximum contract is 128 KiB; the
witness is at most 4 MiB. A canonical object/receipt is at most 2 MiB. Extra
fields, unsupported modality/policy names, floating-point values, boolean
integer aliases and noncanonical JSON are refused.

Both verification APIs require independently retained `expected` with exactly:

```text
contract_id, program_sha256, parameters_sha256, before_state,
consumer, allowed_use, candidate_artifact, parent_context
```

`parent_context` contains `network`, `parent_id`, `parent_state_root`,
`block_height` and `consensus_time_ms`. The consumer must obtain it from its task
owner or already verified chain state. This research API **does not authenticate
a caller's parent context**. No helper reconstructs authoritative expected
context from a producer's returned contract. Matching internally consistent
hashes cannot establish an external admission.

The source guard retains V1's full loaded-source closure, adds the V2 relation,
execution and binding-guard modules and commits the executed profile and actual runtime
versions. Replacing loaded code or constants, or editing the source after
import, requires a restart and new admission. This is local source consistency,
not remote attestation of the interpreter or operating system.

The V2 guard checks source-defined names and imported repository aliases, not
only functions that report the expected `__module__`. The latter filter alone
could skip an externally rebound function while retaining the old program
digest. V2 checks the source closure before running V1's unchanged guard, with
function binding/code/default checks and the supported native cache wrapper.
An arbitrary writer inside the trusted Python process can also replace the
checker itself; these checks do not establish a sandbox or remote attestation.

## Preprocessing, model and W1 material

The input modality is precisely `public-git-rust-source`. This is the existing
source-token extractor, not an arbitrary tokenizer or trained multimodal
Encoder. Original source replay remains mandatory even when a masked feature
will later be zero. Unsupported audio/image/video inputs have no accepted
encoding in this profile.

All 257 mask coordinates are exact booleans. The final bias coordinate remains
enabled and has value 8; a disabled feature becomes integer zero. The source
rows, mask and resulting feature tensor are bound separately. W1 tiles are
built from the **masked** tensor actually consumed by the Cell.

The ordered matrices remain base, router, delta-0, delta-1 and delta-2. Every
coefficient is an integer in `[-32767,32767]`. All 15 output rows and all five
feature tiles of widths `64,64,64,64,1` undergo full W1 transcript, material,
product and target verification. Padding and signed decoding are checked.
Every product also matches the independent scalar integer implementation.

Each challenge includes the new domain, full V2 contract, complete before
state, tile material task, tile index and nonce. A valid old-domain proof is
not reusable. Source reconstruction, recurrence and training are verified by
complete replay; W1 has not become a succinct proof for those stages.

## Recurrent state and decisions

State contains exactly the versioned schema, Cell ID, generation, scope,
model artifact, three-element memory, RNG seed/counter, remaining step budget,
sequence and optional optimizer state. The complete before state matches the
independently retained state. There is no opaque replacement state root that
can conceal unexecuted transitions.

For each non-STOP row, choose the highest-scoring legal router expert, using
the lowest legal index on a tie. Let the base and selected-delta products be
\(b_c,d_c\), and the current memory be \(m_c\). Then

\[
z_c=b_c+d_c+m_c,
\qquad
m'_c=\left\lfloor\frac{3m_c+8192\,\operatorname{sgn}(z_c)}4\right\rfloor.
\]

Memory lies in `[-8192,8192]` and actually affects later rows. All calculations
are signed exact integers with explicit bounds. State generation and scope
cannot change within this relation; replacing a generation is an owner action.

The action rules are ordered:

1. If no steps remain, output STOP. That row changes neither memory, RNG nor
   remaining steps.
2. Otherwise compute route and logits. If the top-two logit margin is strictly
   below the admitted nonnegative threshold, abstain. Abstention consumes one
   step and updates memory but consumes no random draw.
3. Otherwise select a class using the admitted sampler. Emit the derived class
   content, or produce the class's admitted tool name and derived arguments.
4. Reject if that action is outside `allowed_actions`.

Every non-STOP row consumes one step. Every successful complete call advances
sequence once, including an all-STOP batch; overflow is rejected. This sequence
does not consume an external operation ID. Tool proposals never execute tools.
Derived delivery content is bound, but actual external delivery is unproved.

### Sampler

`argmax-lowest` is deterministic. `sha256-positive-shift-v1` assigns class
mass \(z_c-\min_j z_j+1\), draws a domain-separated SHA-256 value from the
before-state seed and little-endian u64 counter, and uses rejection sampling
before reducing modulo total mass. Every attempted draw advances the counter,
including rejected draws. There is a hard 64-draw limit per sampled row and no
counter wrap. The 256-bit rejection threshold is encoded as a fixed 65-digit
hex string in the trace, not an out-of-range JSON integer.

This proves reproducibility relative to the admitted seed, not seed entropy,
unbiasability, miner fairness or a model's sampling quality.

## Executed training profile

Training is either disabled or one explicitly admitted batch step. The whole
batch uses the frozen before-model; update happens after forward execution.
Every non-STOP row, including abstention, contributes supervised loss using
the actual source inventory label:

\[
L=\sum_{i,c}(z_{i,c}-8192\,1[c=\ell_i])^2,
\qquad
g_{i,c,j}=2(z_{i,c}-8192\,1[c=\ell_i])x_{i,j}.
\]

Base gradients sum all active rows. Each selected delta receives its routed
rows. Router parameters remain frozen. **Routing and the discrete recurrent
state have an explicit stop-gradient boundary**; this is an integer surrogate
training rule, not backpropagation through time or a differentiable router.
Source inventory labels are not newly established independent ground truth.

For each trainable parameter, componentwise clip the accumulated gradient and
apply the declared rational momentum/learning rate:

\[
\bar g=\operatorname{clip}(g,-C,C),\quad
v'=\operatorname{trunc}_0(\mu v)+\bar g,\quad
\theta'=\theta-\operatorname{trunc}_0(\eta v').
\]

The trace retains loss terms, backward values, masked/clipped gradients,
old/new moments and exact updates. Frozen parameters **and their existing
moments** remain unchanged, including nonzero old moments. A training-enabled
batch with no active rows does not initialize or advance the optimizer.
Out-of-range moments, weights or counters reject; weights are not silently
saturated. Reconstruct the full after-model and its artifact digest.

Computationally correct training does not imply a better model. Quality,
calibration, OOD, old-task retention, adoption and work-cost evidence remain
separate obligations.

## Segment composition

The witness includes actual stage inputs/outputs, not independently accepted
hash assertions. The verifier computes source features, masked features,
verified products, every execution trace and the final checkpoint itself.
It then compares the witness's whole sequence against those computed values.

Each segment is domain-separated and includes contract ID, ordinal, stage,
predecessor and complete stage values. The predecessor chain begins with the
contract ID. Even identical values from another task have distinct identities.
Changing every visible hash cannot hide an incorrect intermediate value
because the verifier reexecutes the producing and consuming stages.

This is a linear reference transcript for this fixed profile. It does not
qualify arbitrary tensor DAGs, distributed proof aggregation or every Hepta
backend's floating-point semantics.

## Historical validity and current use are separate

`verify_historical_relation` takes no wall-clock or current-revocation input.
It checks the agreed task window against the independently supplied protocol
time and binds the protocol parent state. Later revocation cannot change this
computation result for the same historical inputs.

`verify_live_relation` additionally requires

```text
issued_at_ms <= start_ms <= finish_ms <= deadline_ms
```

using the consumer's clock. It still does not check live owner authority.
A request may verify more than once; no pure computation result automatically
consumes an operation, commits a checkpoint, installs a model, grants FinalUse
or proves that the model was subsequently used.

The actual Hepta owner already has the relevant boundaries:

- `CellGenerationJournalV2`: durable admission, exact operation/request identity,
  one journal frame for successor/output/cost, external anchor CAS, and recovery.
- `NeuronGenerationCurrentOwnerV1`: current generation/writer ownership and
  publication CAS.
- `FinalUseAuthority`: current epoch/revocation/time checks and one-use claim at
  the local effect boundary.

A native integration must obtain expected state from these owners, keep the
verified computation separate from permission, recheck current owner context
at commit, and use their original consumption/checkpoint path. It must not
invent a second SQLite spent registry or promote a JSON `relation_valid` flag
into authority. A guarded owner context API is an integration seam; it is not
by itself a native implementation or acceptance of this Python relation.

## Reproduction and qualification

Run from the repository root with all frozen source objects available:

```bash
bash scripts/project-preflight.sh
PYTHONPATH=formal/pon-nakamoto-v1 python3 -m unittest -v \
  test_useful_cell_numeric_v1 test_useful_cell_relation_v1 \
  test_useful_cell_execution_v2 test_useful_cell_relation_v2 \
  test_useful_cell_relation_v2_adversarial test_useful_cell_source_guard_v2
python3 formal/pon-nakamoto-v1/experiments/useful_cell_relation_v2.py \
  --out /tmp/trnm-useful-cell-v2-fresh --batch-size 64
```

The driver retains seven cases: emit, masked sampling/training, tool proposal,
abstention, all-STOP, exhausted prefix and a subsequent task with disjoint source
rows that really uses the updated model and resulting state in the reference interpreter. Each case
retains independent admission context, all source/W1/state/model/segment bytes,
current and historical checks, a fresh-process historical readback, command
outcomes and elapsed/controller/child CPU observations. The maximal target is
a correctness control, not a mining cost or hardness measurement. Failures and
their observations are retained; use a new directory for every invocation.

The cold reader requires an explicit independent expected file:

```bash
python3 formal/pon-nakamoto-v1/experiments/useful_cell_relation_v2.py \
  --verify-dir /tmp/trnm-useful-cell-v2-fresh/emit \
  --expected /path/to/consumer-retained-expected.json
```

The local fixture is not independently administered admission. All success
reports retain false owner authorization, request consumption, checkpoint
commitment, FinalUse, ordinary Hepta use, native admission, tool execution,
external delivery, succinct proof, model quality, work security, production
qualification and public reward claims. Original negative usefulness/cost
results and the independent service, History, PQ and WAN gates remain intact.
