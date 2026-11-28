# Private checkpoint tile numerical assembly
This operation consumes only caller-supplied inert BF16LE/F32LE spans.
It does not open or parse any checkpoint, derive checked material, call a
task or proof routine, train, use real model data, or establish authority.

Input is `TMA1\0\0\0\0`, a little-endian u64 token count from 1
through 64, exactly 4,096 already extracted row-major BF16LE weight
samples, then that many token-major F32LE rows of width 576. Every weight
and every activation lane is checked for a nonfinite exponent before
writing any output or scratch. Unselected activation columns are still
checked; they do not contribute to quantization or clip counts.

The previously qualified quantizer supplies signed intermediate values.
The output comprises the weight/activation clip counts (two little-endian
u64 words), then two 64×64 matrices of original **little-endian u32**
field residues `v.rem_euclid(4294967291)`. Matrix A preserves the weight
order; B uses coordinate-major `B[k*64 + token]` for the first 64 input
coordinates, filling absent token columns with zero. Output is 32,784
bytes; the disjoint scratch uses only 16 bytes for a single lane.
Status 1 reports original NONFINITE, 100 private frame, 102 arena
capacity. All refusals leave output and scratch unchanged.

The differential carries the entire original frozen source unchanged
into a private temp module. An appended test witness invokes the exact
original numerical loop block verbatim with inert observer/storage and
the original in-module quantization and encoding routines. It never
calls the later original material digest/task routine. Both stock
emitters compare full bytes, clips and original nonfinite refusal.
