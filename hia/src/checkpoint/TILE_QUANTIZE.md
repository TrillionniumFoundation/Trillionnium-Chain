# Private checkpoint-tile quantization value
This private native operation performs original numeric-only checkpoint
weight and activation quantization on immutable supplied bits. It
never opens a checkpoint, builds a checked material object, computes a
tile/task relationship, trains, enters W1/PoW, or grants any authority.

Input is eight bytes of magic (`TQ16\0\0\0\0` for BF16 weights or
`TQ32\0\0\0\0` for F32LE activations), a little-endian u64 count
(1 through 4,096), then exactly that many little-endian lanes. For each
lane the output is a little-endian i64 result and a little-endian u64
tag: 0 finite/not clipped, 1 finite/clipped, or 2 original NONFINITE
(with a zero placeholder result, not a valid quantized number).
Weights scale by 2^14 and clip to ±32,767; activations scale by 2^4
and clip to ±128. Integer-only IEEE decoding implements nearest-even
*before* clipping, including signed zeros, subnormals, and saturation
without invalid shifts. Scratch is unused.

Status 0 means every lane received a diagnostic result (including tags
for individual non-finite values). Status 100 refuses wire shape and 102
refuses output size before any write. The unused output suffix is
preserved. A test-only forwarding function in a temporary full copy of
the frozen original module invokes the existing private Rust function.
The audited source is otherwise byte-exact and its locked dependencies
are built by the original Cargo graph. Both pinned HIA backends compare
all 65,536 BF16 patterns and deterministic stratified F32 samples.
