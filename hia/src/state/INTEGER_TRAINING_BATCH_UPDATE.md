# Frozen integer Cell batch optimizer update

This private native stage applies the original `train` integer optimizer
to already-produced loss/gradient values, without calling sampling,
inference, proofs, adoption, storage or the live Node. Its typed frame
does not establish where the gradients came from or confer authority.
The test also chains the exact native backward numeric output bytes
into this component and compares both stages to the unchanged original.
No code reads or alters the router, model identity/schema, or Cell state.

## Borrowed frame

Input `CTUP0001` is exactly 98,768 bytes. Its ten LE u64 words are
magic, active-row count (0–64), total squared loss, optimizer-presence
tag (0/1), old optimizer step, learning-rate numerator and denominator,
momentum numerator and denominator, and clipping magnitude. Policy
bounds equal those of the original validated Training. Absent optimizer
uses zero step and zero moments.

Four consecutive matrices follow, each with 3,084 LE words in exact
original group-major then class-major then coordinate-major order:
old weights, old moments, 0/1 mask words, and raw gradients. A matrix
here concatenates base and three 3×257 routed delta matrices; it does
not include the router. Weights are signed ±32,767; signed moments
exclude i64::MIN. Raw gradients are even and have absolute bound
`2 × 134,754,288 × 8 × count`; loss at most
`3 × 134,754,288² × count`. Empty input projections therefore have zero
gradient and loss. The frame does not assert an actual originating
`ActiveRow` preimage.

The 123,392-byte output begins with four LE u64 words: optimizer
presence, step, update-applied bit, parameters-changed bit. Each of
3,084 coordinate records has five LE i64 words: next weight, next
moment, masked gradient, clipped gradient, and applied weight change.
An absent optimizer uses zero moment words; a dry no-active return
emits original weight/optimizer values unchanged and zero trace words.
A nonempty batch initializes absent optimizer moments to zero, checks
one step increment before all coordinates, and visits coordinates in
original order. A false mask preserves old weight and old moment with
zero traces and no hidden decay. Parameters-changed describes only a
weight change, not a changed moment or step.

The original scalar f0 ABI and this batch share `opt_coordinate` for
clipping, signed truncation of optional momentum and learning-rate
fractions, and weight-range checks. Momentum bound failure remains
checked although unreachable within the validated policy and old moment
bounds; a successful resulting weight also bounds the returned change
to signed 65,534, so the later original i64 conversion cannot fail.

## Output and failures

Status 0 is success; 100 is malformed frame; 102 is insufficient
borrowed extent; 201 is original step overflow; 202 is the retained
original moment overflow check; 203 is original trained weight range.
The first arithmetic error returns without committing public output.
Malformed input and step overflow do not touch output or scratch. On
arithmetic or output-extent failure, staging scratch can contain a
prefix. The input and all output/scratch bytes beyond 123,392 are
unchanged. Scratch extent is checked before using the private staging
region; with enough scratch, arithmetic errors precede output extent.
A whole successful stage is copied to output only after every
coordinate has succeeded. This is not a transaction or state mutation
outside the caller's exclusively borrowed buffers.
