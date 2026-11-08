# Finite multimodal Cell computation V3

This increment follows the sole [development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Its namespace is `pon-useful-cell-multimodal-int-v3`. It implements actual
preprocessing, parameterized encoders, a residual MLP, routed low-rank adapters,
a head and stateful decisions. It preserves the frozen
[V1](USEFUL_CELL_RELATION_V1.md) and [V2](USEFUL_CELL_RELATION_V2.md) profiles.
It does not claim support for arbitrary encoders, arbitrary graphs, native
consensus admission, ordinary Hepta models or production quality.

## Inputs and the executed graph

Each call contains one to four independently admitted rows, with distinct row
IDs and one to three ordered modalities. The witness carries the original
bytes; the verifier reconstructs the values consumed by every stage.

| Input | Exact preprocessing and encoder |
| --- | --- |
| Text | Strict UTF-8, 1–64 original bytes, CRLF/CR normalization to LF, UTF-8 byte tokens, a complete 256×8 parameter table, explicit token mask and truncating masked mean. |
| Image | RGB8, 1–16 pixels on each axis, exact byte count, nearest-floor resize to 8×8, signed integer normalization, sixteen 2×2×3 patches, actual 8×12 projection plus bias, clamp and patch mask. |
| Audio | Mono signed PCM16LE at 8 or 16 kHz; 16 kHz uses truncating pair means; at most 64 resulting 8 kHz samples; signed normalization, four-sample frames, exact padding mask and actual 8×4 projection plus bias. |

Pooling and fusion use explicit integer truncation. An eight-coordinate feature
mask is applied to the fused tensor. The model then executes an 8→12→8 residual
MLP, the three-way router, all three rank-two adapters, selection of one legal
expert, and the three-class head. The full ordered bundle includes unselected
adapters and all encoder parameters. Missing, duplicated or reordered modalities,
incorrect lengths, padding admitted as audio, unsupported rates, floating-point
values and integer/boolean aliases are rejected.

These are parameterized encoders whose parameters can actually be updated by
the declared training rule. The retained arithmetic fixtures do not establish
pretrained semantic representations, recognition quality or generalization.

## What receives a proof

Every executed forward dense operator has its own complete W1 transcript.
The verifier first reexecutes the graph from the admitted model and raw bytes,
then constructs W1 material from the exact weights and intermediate tensor
that this execution consumed. It checks shape, dtype, signed bounds, every
padding coordinate, complete transcript and target, and compares every product
with scalar integer arithmetic. The challenge binds the contract, before state,
operation identity, ordinal, material task and nonce.

Text lookup, masks, rescaling, nonlinearities, means, routing, recurrent state,
sampling and backward/update operations are checked by full scalar replay.
They are not presented as succinct proofs or as W1-proven backward operators.
The mixed three-modality retained controls execute twelve dense operators per
call. They therefore require twelve separate complete proofs; the five V2
proofs cannot certify the different V3 graph.

Every trace segment includes its actual input and output tensors, contract ID,
ordinal and predecessor. The verifier recomputes the entire linked sequence.
A producer cannot repair a wrong tensor by rehashing the rest of the chain or
splice an otherwise valid segment from a different task.

## State, actions and training

The bounded state includes model identity, Cell ID, generation, scope, memory,
RNG seed/counter, sequence, step budget and optimizer state. Legal expert ties
choose the lowest index. The sampler is either lowest-index argmax or a
domain-separated SHA-256 counter sampler with positive-shift mass, rejection
sampling, a 64-draw cap and no wrap. Rejected draws consume counters.

STOP, abstention, emit and tool proposals are executed actions. Non-STOP rows
consume a step and update memory; abstention does not consume RNG. An all-STOP
call advances sequence but preserves memory, RNG, optimizer and model. The
fixed graph still runs and receives dense proofs before budget-controlled
decisions: STOP does not imply computational cost savings in this profile.
Tool proposals do not execute tools or prove external delivery.

The optional training step uses actual forward values and a squared-error
loss with target magnitude 64. Encoder, residual MLP, selected adapter and head
adjoints are recomputed. Quantization and mean adjoints have explicitly stated
integer truncation rules; clamp/ReLU gates use strict interiors. Routing and
recurrent state have stop-gradient boundaries. This is an integer surrogate,
not the derivative of a discontinuous integer function or backpropagation
through time. The trainable mask, component clipping, rational momentum,
rational learning rate and exact update are checked. Frozen weights and their
existing moments remain unchanged. Out-of-range parameters, moments and
counters reject; weights are not silently saturated.

## Independent admission and time

Both APIs require independently retained expected context containing the
contract, program and parameter identities; complete before state; consumer,
allowed use and request ID; model and input identities; and protocol parent
context. No producer-claim-to-expected helper is provided. Verification uses a
canonical snapshot of the owner's before state throughout the complete replay.
Matching source byte hashes does not authenticate a claimed source origin.

Historical verification uses the supplied protocol parent and consensus time
only. V3 parent and live-clock timestamps are UNIX milliseconds; this profile
performs no implicit conversion to native UNIX seconds or Hepta monotonic
microseconds. This reference API does not itself authenticate that parent. Live
verification additionally checks the consumer clock before and after the
whole replay. Later revocation must not change historical validity. A real
owner must separately recheck current generation, revocation and FinalUse and
atomically consume the operation at its actual commit boundary.

## Evidence and remaining gates

The [retained record](../../../../evidence/pon-useful-cell-multimodal-v3-20261107/README.md)
keeps source identities, arithmetic and adversarial tests, complete proofs,
all earlier observations, cold-process replay and per-file integrity checks.
The final eight four-row controls contain 96 distinct complete W1 transcripts,
including an updated-model call on a different input batch. The target is the
maximal correctness-control target, so these observations do not measure work
hardness or qualify an economic cost bound. Fixture labels are generated
arithmetic controls, not independent task-quality ground truth.

The separate [native profile](USEFUL_CELL_NATIVE_V1.md) implements a different
finite source-router graph. It does not consume V3 proof bytes. General
multimodal models, common graph semantics across runtimes, combined real-owner
effects, external delivery, production adoption, independent quality and
cheapest-legal-work qualification remain separate unfinished gates.

Implementation and controls:

- [Execution](../../../../formal/pon-nakamoto-v1/useful_cell_multimodal_execution_v3.py)
- [Relation](../../../../formal/pon-nakamoto-v1/useful_cell_multimodal_relation_v3.py)
- [Arithmetic and codec tests](../../../../formal/pon-nakamoto-v1/test_useful_cell_multimodal_execution_v3.py)
- [Full-proof and attack tests](../../../../formal/pon-nakamoto-v1/test_useful_cell_multimodal_relation_v3.py)
- [Reproduction driver](../../../../formal/pon-nakamoto-v1/experiments/useful_cell_multimodal_v3.py)
