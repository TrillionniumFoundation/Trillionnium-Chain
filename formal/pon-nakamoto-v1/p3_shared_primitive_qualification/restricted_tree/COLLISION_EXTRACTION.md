# Ordinary binary Merkle paths: a deterministic full-hash collision extractor

## Status and scope

This is an elementary deterministic reduction with an executable checker. It
covers two **classically readable**, accepted openings at the same index under
one fixed binary-tree shape. Every sibling may be an arbitrary digest string.
No sibling preimage or legal subtree is assumed. It neither implements the P3
MMCS adapter nor proves the complete W1 proof system sound. The test hash is
intentionally broken; no test discovers a SHA3-512 collision.

The proposed new profile uses a complete hash output for a digest, canonically
serializes field elements, and uses distinct framed leaf, branch and transcript
roles. The checker uses explicitly local test tags and makes no change to an
existing protocol namespace.

## Definitions

Fix a deterministic function `H : {0,1}* -> {0,1}^n`. Fix the profile, the leaf
width `w`, the height `h`, and an index `0 <= i < 2^h`. The context is identical
for both verifications. Let `E_L` be an injective encoding of a width-`w` row and
let `E_B(a,b)` be an injective encoding of a pair of complete `n`-bit digests.
Their roles are disjoint by explicit framing. A suitable encoding is:

- Leaf: `leaf_tag || framed_profile || u32_le(w) || canonical_u64_le(row[0]) ...`.
- Branch: `branch_tag || framed_profile || left[n/8] || right[n/8]`.

For Goldilocks, canonical encoding means `0 <= x < p`, not reduction of arbitrary
u64 values modulo `p`. A length, height or role accepted from an attacker must be
validated against the verifier's fixed profile before using this lemma. Tags do
not replace this validation. The theorem only needs role-local injectivity
because both paths have the same shape; disjoint roles protect composition and
make cross-role statements unambiguous.

For an opening `(m, s_0,...,s_{h-1})`, define `d_0=H(E_L(m))`. For each level `j`,
let `b_j=(i >> j) & 1`, and define:

- `b_j=0`: `d_{j+1}=H(E_B(d_j,s_j))`;
- `b_j=1`: `d_{j+1}=H(E_B(s_j,d_j))`.

Accept if `d_h=R`. Every `s_j` is any correctly sized digest string.

## Extraction lemma

Given two accepted openings against the same `R`, context and index, with rows
`m != m'`, a deterministic procedure returns distinct byte strings `x != y`
such that `H(x)=H(y)`.

**Proof.** Evaluate both paths. Their final digests are equal. Let `k` be the
first level at which their running digests are equal. If `k=0`, the two distinct
rows have distinct canonical leaf encodings, so those encodings collide under
`H`. If `k>0`, their digests at level `k-1` differ. The same index places these
different digests in the same child position. Therefore the ordered branch
pairs differ regardless of the sibling values. Injectivity of `E_B` makes the
branch byte strings different, while the digests at level `k` are equal.
Those two byte strings collide under `H`. No further condition on siblings was
used. This also proves that the procedure always terminates. QED.

The procedure performs at most `2(h+1)` calls to `H`; repeated inputs can be
counted again. Independently rechecking its returned witness adds two calls.
For a sponge-based implementation, these are calls to the *complete hash*;
conversion to a primitive permutation-query budget must count every underlying
absorb, padding, squeeze and finalization call for the actual byte lengths.

### What truncation would change

If a Merkle digest is only a truncation or a noninjective conversion of `H`'s
output, the procedure returns a collision in that truncated/composed function.
It does not thereby return a collision in full `H`. The checker's declared
output-length check catches a caller supplying 32 bytes when 64 were required;
it cannot independently prove that an arbitrary callable is an honest hash
implementation. Source pinning and a known-answer test serve that purpose.

### Quantum-output and preprocessing qualifications

If a quantum adversary outputs the two accepted classical paths, this same
classical procedure can postprocess them into a collision for a quantum
*output-collision* experiment. It must account for its appended hash queries
or their permutation implementation costs. This deterministic observation does
not establish collapsing, does not rewind a quantum state, and does not extract
a witness from a single proof. It does not supply a Fiat-Shamir theorem.

The reduction can carry an adversary's auxiliary information unchanged; the
underlying collision assumption must then quantify over that same information
and preprocessing model. An assumption proved only with advice independent of
the sampled primitive cannot silently be used for advice correlated with it.

## Why this is not already the actual P3 MMCS theorem

The inspected `MerkleTreeMmcs::verify_batch` accepts sibling digest arrays
without recursively checking their subtree reachability. It also validates
matrix widths/heights, derives a dimension-dependent arity schedule, hashes
concatenated row groups, injects shorter-matrix row hashes at selected levels,
and selects a cap element. A complete adapter theorem must explicitly prove:

1. Both executions use the same verifier-fixed dimensions, validated row widths,
   matrix ordering, cap selection and admissible index.
2. The actual schedule and orientation match the abstract ordered children.
3. Every row group uses an injective canonical encoding with a fixed width.
4. Shorter-row injections retain the designated authenticated child positions;
   conflicting row groups lead either to a leaf collision or to a branch
   collision when the two derived children are compared.
5. Pruned/multiproof reconstruction, if admitted, preserves these properties and
   has a separate exact mapping; ordinary path code is not that mapping.
6. All returned digest bytes are the full hash output and all primitive work of
   the extractor is included in any quantitative reduction.

These are concrete implementation obligations. The executable checker below
establishes no claim that the adapter has discharged them.

## Executable evidence

`opening_collision_extractor.py` evaluates and extracts ordinary binary paths.
`test_opening_collision_extractor.py` uses deliberately colliding toy hashes
for first-leaf, first-branch and later-branch merges; exercises every orientation
for heights 1 through 3; passes arbitrary sibling byte strings; and has a real
SHA3-512 control that accepts a well-formed path and rejects a changed row.
The SHA3 control is a correctness check, not empirical collision resistance.

The tests also reject noncanonical field values, wrong leaf widths, wrong path
lengths, invalid indices, incomplete outputs, and observed nondeterminism.
Run:

```sh
python3 -m unittest -v test_opening_collision_extractor.py
```
