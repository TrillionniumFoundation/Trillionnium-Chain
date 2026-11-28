# Synthetic CTRX-trained Model used by held routed arithmetic

This regression connects three published native kernels. It first supplies
`cell_held_train.hepta` with the `CTRX0001` product/feature fixture, once
with one remaining step and once with none. The training row is bias-only;
all corresponding original coefficients are zero, so all 15 input product
lanes are explicit inert zeros. This stage does not claim to produce its own
input products. The independently pinned original reference runs the full,
unchanged private Rust `execute` with training enabled on the same held data.
Its private fixture reports the actual synthetic router before and after.
There are no tools or stochastic sampling.

The test compares the entire original/native CTRX report and active rows.
The returned update weights begin at `30,848 + 80*active_count + 32`,
with one LE64 weight every 40 bytes. Only those actual native words, plus
the exact unchanged original router words, are used in the fixed
`CMCV0001` typed serializer input; training output is never substituted
with an independently generated candidate.

The bytes emitted by each native serializer match the genuine linked
original `cell_native_v1::canonical` call on the original updated Model.
The test decodes the actual emitted native bytes, verifies every LE64 word,
and uses only checked LE64-to-LE32 narrowing and a fixed router reordering
to form the Int257 input. This host bridge computes no dot products.
Exactly the same native-originating packet is consumed by both stock HIA
inference images and the frozen original `PreparedModel::ordinary`
using its original `new` and `prepare_batch` input adapters.

The one-step synthetic train changes class-1 bias in base and delta 0.
The three held rows are distinct from the bias-only training row. The
old, unchanged router selects routes 0/1/2; observed updated class-1
logits are 48/24/24 rather than zero, with the class-0 baseline
predictions changing to class 1. The dry run with one valid submitted
row but no remaining steps leaves the entire Model and held outputs
equal to the baseline. These are arithmetic observations, not model
quality or a future evaluation split.

This is not later full Cell execution: the held comparison is the
non-stateful ordinary routed numeric API, without recurrent memory,
expert eligibility masks, actions, actual dispatch, owner, proof,
adoption, or persistence.
