# Frozen-projection integer training loss and backward

The private `integer_training_backward.hepta` routine implements the
loss and backward portions of the unchanged integer cell Rust `train`.
It accepts only already-produced, immutable active rows. It does not run
cell sampling, route selection, optimizer masking/clipping/update, model
execution, deployment, or proof logic. No input is authenticated or
considered eligible for adoption.

Input starts with `CTRN0001` and one LE u64 active-row count (0–64).
Exactly that many 2,096-byte rows follow. Their original indices are
implicit contiguous indices starting at 0: `execute` only adds active
rows while the remaining-step counter is positive and does not replenish
it in that loop. A row contains LE u64 route and label (each 0–2), three
LE i64 logits in the original inclusive ±134,746,096 range, then 257
LE i64 features. The 256 token features are each in [-8, 8] and their
absolute sum is at most 1,024; the last (forced-enabled bias) is exactly
+8. These are the bounds implied by original source preprocessing and
the declared logit check. Supplying a projection does not prove a
particular input/model could have generated it.

Output is 30,848 bytes plus 80 per active row, in LE i64 words:
total loss, then five 3×257 row-major matrices (base, delta 0, delta 1,
delta 2, router). The row outputs follow, each three targets, three
errors, three derivatives, and a loss. The target is 8,192 at the label,
zero elsewhere. The output router matrix is exactly zero; the discrete
route and state stop-gradients are unchanged. A term is accumulated in
the base and only the chosen delta.

The derived conservative bounds are `|error| ≤ 134,754,288`,
`total squared loss ≤ 3,486,473,881,802,293,248` and
`|one gradient entry| ≤ 137,988,390,912`. They are all below i64
limits even before accounting for low token density. Two's-complement
operations therefore agree with the original typed arithmetic, and
original checked squared-loss overflow is unreachable on this frame.

Status 0 is success, 1 invalid frame, and 2 insufficient output for an
otherwise valid frame. The immutable input and unused arena do not
change. Validation finishes before any output write, and the output
tail remains untouched. Neither bare values nor a successful result
confer authority.

The test calls the exact full Rust `train` with inert synthetic rows and
a fully frozen trainable mask, extracts its original stages 0 and 1,
retains the original serialization code, and compares the complete
numeric projection to each stock HIA emitter. Synthetic weights and
optimizer state used by the witness are not part of this native ABI.
