# Bounded same-frame checkpoint and activation numeric pair

The private stock entry consumes one immutable input: TAR1 magic and the
32-byte expected activation SHA, the raw activation JSON, the entire raw
checkpoint, and a fixed footer of 32-byte expected checkpoint SHA, u64
little-endian expected checkpoint size, and u64 little-endian activation
JSON length. Exact range guards bound both spans and exclude the footer
from both digests. Only the native original-profile header chooses the
BF16 tensor, never an externally supplied offset or detached matrix.

The named/positional raw activation composition checks the activation pin,
concrete fields, pure profile fields and exact hidden bits first. The
checkpoint range then checks declared size, prefix, shared THV1 coverage and
target selection, and its complete independent pin. For numeric output
the original 64×64 BF16 slice is read at the original 1,152-byte stride.
All original activation lanes (including unused coordinates) must be
finite. A uses the existing native BF16 quantizer and B uses the existing
F32 quantizer, original transposition and zero tail. The original little-
endian residue and clip counts are identical to standalone TMA1: two u64
counts followed by two 16,384-byte matrices of u32 little-endian residues.

The complete input is limited to 1 MiB, including all framing. Ordinary
64-token synthetic input needs approximately 960,000 bytes. The existing
THV1 named-tensor header private bounds and activation bounded raw profile
also apply. The 500,000-byte scratch keeps hidden bytes and both matrices
private until every stage completes; any refusal leaves output intact.
Success writes only the 32,784-byte prefix. Original activation uses its
1–9 status range; checkpoint frozen statuses are the standalone code plus
20, nonfinite is 15, and unchanged private codes are 100–104.

The test-only Cursor executes the exact frozen original fragment from
activation through matrix encoding. No observer is called natively; no
matrix replay/adoption, task ID, training, proof, real source file or
runtime authority is involved.
