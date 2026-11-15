# Binary cap-zero P3 pruned openings: a two-opening collision reduction

Status: **HOLD_NO_GO**. This is a mathematical reduction argument with a native
implementation check. It does not grant concrete SHA3 security, PCS extraction,
Fiat–Shamir knowledge soundness, an actual-W1 forgery, or production admission.

## 1. Exact statement and scope

The baseline is PR #795 commit
`1fe2f31c70977a030aec73b63fe0617f34d15a77`. Its immutable R1 hash profile is
defined in [PROFILE.md](../PROFILE.md). The new executable is
[tagged_sha3_mmcs_binding.rs](../../w1_public_stark_research/examples/tagged_sha3_mmcs_binding.rs).
It uses the real locked `p3-merkle-tree = 0.8.0` verifier and the unchanged
R1 `LeafHasher` and `BranchCompressor` in its real-hash arm.

Fix all of the following externally, before accepting either opening:

- One R1 profile, one component (1 or 4), and one identical 64-byte context.
- One ordered, nonempty list of matrix dimensions `(height, width)`; all
  heights are positive powers of two and all widths are positive.
- Binary compression and cap height zero, so the commitment contains exactly
  one complete 512-bit digest.
- Two nonempty lists of verifier-selected global query indices, each in the
  tallest matrix's range. Their order, repetitions, and lengths may differ.
- Concrete canonical Goldilocks rows, one at the pinned width of every matrix
  for every query, and the actual P3 pruned frontier representation.

The executable restricts these inputs further to at most 64 matrices and
64 queries per opening, heights at most `2^20`, widths at most 8192, and at
most 1,048,576 opened base-field elements per opening. These bounds constrain
the offline audit helper. They do not qualify the production receiver's
resource contract.

If the tallest matrix has height `2^h` and matrix `m` has height `2^h_m`, then
global query `i` refers to matrix row

\[
  \operatorname{row}(i,m)=i\mathbin{\gg}(h-h_m).
\]

The shared coordinate is therefore `(m, row(i,m))`. It is not generally the
global query index. Distinct global indices can assert conflicting values
of the same shorter matrix row.

**Proposition.** Suppose both pruned openings are accepted by the actual
binary cap-zero P3 verifier for the same fixed parameters above. If they
give different row vectors at any shared matrix-row coordinate, the hash
queries made while verifying them contain two distinct complete R1 framed
messages with the same complete hash output.

Here all leaf and branch queries use one function `H`. The proposition does
not assume independence of roles, honest sibling subtrees, an ideal random
oracle, collision resistance, or that the two proofs came from the honest
constructor. Boundary siblings may be arbitrary 64-byte strings.

## 2. The actual verification computation

The relevant locked source interfaces are `Mmcs::verify_multi_batch`,
`MerkleTreeMmcs::verify_batch_pruned`, the shared `walk_pruned_frontier`,
`restore_and_recompute_paths`, and single-query `Mmcs::verify_batch`.
The source receipt records the archive checksums and source identities used
for the native run; the package version alone is not its provenance.

The frontier walk derives geometry from the supplied dimensions and index
lists. It sorts and deduplicates the latter, rejects inconsistent repetitions,
checks each row's matrix width, and requires the exact number of boundary
digests implied by the frontier. At every lower-height injection it also
compares the actual row vectors of all queries merged into that node. A hash
comparison is not substituted for that row-equality check.

At the starting layer the verifier hashes the rows of all tallest matrices
in their fixed matrix order. At each subsequent binary layer it compresses
the two children in their fixed left/right order. At a layer containing
shorter matrices it hashes that fixed group of rows and then compresses

\[
  (\text{structural parent digest},\ \text{injected-row digest}).
\]

The injection is an extra hash and compression. It is not one of the
authentication siblings and does not add a bit shift to the global index.
At cap zero every matrix-height group is consumed before the single root is
checked.

Pruning removes redundant transmitted siblings; it does not remove these
row dependencies. The shared frontier engine computes each required node
once. With recording enabled, the same engine scatters the other children
into every represented query's restored path. Recording never changes the
hash inputs or digests. Exact duplicate and injection-group row checks ensure
that the representative used for a merged group is valid for every query it
represents. Induction over the frontier layers therefore gives the same
root as separately verifying each restored path, with the same row
injections and fixed geometry.

This argument concerns the actual implementation's control flow. The native
tests check both ends: acceptance by the pruned verifier and independent
acceptance of every restored path by the unchanged R1 single-path verifier.
Finite tests support the implementation correspondence; they are not the
general mathematical proof.

## 3. Proof by following the shared coordinate

Assume no two recorded complete hash messages collide. Then whenever two
recorded calls return the same digest, their complete framed messages are
equal.

Take a shared matrix-row coordinate on which the accepted openings differ.
Both accepted computations contain the dependency from that row to the
fixed root. This remains true if the corresponding global indices differ:
the binary index shifts have already merged them by that matrix's injection
height. Because the cap is the same, the two root digests are equal.

Follow the two computations down from the root along the fixed dependency
to the selected row. At each structural compression, equality of outputs
and absence of a recorded collision imply equality of complete branch
frames. The encoding contains the left digest followed by the right digest,
without reduction modulo the field, so equality of frames implies equality
of both child digests. Follow the appropriate child in both computations.

At a shorter-row injection the same reasoning gives equality of its two
children. If the target row is in that injected group, follow the right
child. Otherwise follow the left child and continue down the structural
tree. The geometry and the ordered dimensions are pinned in both
computations, so these choices identify the same logical coordinate.

Both computations actually query every hash on this selected dependency.
A boundary sibling may lack a preimage, but the selected row is an opened
row on both sides; its dependency is computed rather than supplied as an
unopened sibling. No assumption about the other sibling's reachability is
needed.

At the selected leaf or injected-row hash, equal outputs therefore imply
equal complete leaf frames. A frame contains the canonical base-field
values in order and their full payload length. The externally fixed row
widths uniquely split that stream into its ordered matrix rows. Equality
of frames thus implies equality of the selected row vectors, contradicting
the chosen conflict.

Consequently, two distinct messages with equal complete hash output occur
among the verification calls. A recorder keyed by the complete output can
return such a pair directly. It may return an earlier collision unrelated
to the selected row; that is still a valid collision witness. The checker
re-evaluates both messages before reporting a witness.

The implementation retains every left-side value at a coordinate while
searching for a shared conflict. It does not use last-write-wins semantics
that could conceal a conflict if a future verifier regression admitted
inconsistent repeated rows.

## 4. Whole-hash call cost and quantum-produced outputs

Let `k` be the number of distinct matrix heights, including the tallest.
A full ordinary path makes one initial leaf call, `h` structural branch
calls, and two calls for each of the `k-1` lower-height injections. Thus

\[
 V_j\le q_j\,[1+h+2(k-1)]=q_j(h+2k-1).
\]

The actual pruned walk only saves calls by sharing nodes and eliminating
duplicate queries. It does not introduce new structural levels. The
executable records `V_0+V_1` separately from the two extra calls for its
independent collision-witness check. Its postprocessing bound is therefore

\[
 (q_0+q_1)(h+2k-1)+2.
\]

These are calls to the **same complete framed hash function**. They are not
counts of Keccak permutations, field operations, CPU cycles, wall time,
or an adversary's lifetime work. The native parity and path-restoration tests
perform additional checks outside the pair-audit call count.

The structural reduction also applies when a quantum algorithm outputs the
two classical openings. Run that algorithm with its original oracle access,
then perform the classical verification and collision search after its
output. There is no rewind or measurement of an intermediate quantum state.
If the original algorithm makes at most `Q` queries to the same abstract
whole-message oracle, this construction uses at most

\[
 Q+(q_0+q_1)(h+2k-1)+2
\]

such queries and outputs a collision whenever the accepted shared-row
binding event occurs. In a common oracle experiment this gives a reduction
of that event to the corresponding quantum collision experiment. It
provides no numeric bound until an applicable collision theorem and its
query/advice assumptions have separately been justified. The reduction
preserves the starting auxiliary-state experiment; it does not certify that
the state is independent of the public construction or charge unobserved
preprocessing for free.

In particular, producing two already available classical openings is not
the task of extracting committed data from one quantum prover. This result
does not establish collapsingness, a Merkle multi-opening extractor,
state-restoration/RBR knowledge soundness, FRI or PCS knowledge, or the
Fiat–Shamir theorem required for W1. It also does not change the original
public-inverse result for the old Poseidon2 compression profile.

## 5. Extension flattening and validation coverage

The candidate's `ExtensionMmcs` reduces extension-field rows to the ordered
base-field basis coefficients. For its degree-two extension, each matrix
width doubles and each original element contributes two ordered canonical
Goldilocks values. This representation is injective. The same proposition
therefore applies after that pinned flattening; a changed extension value
changes at least one coefficient. The native check uses the actual
`ExtensionMmcs` API, verifies its pruned proof, then verifies that exact proof
with explicitly flattened rows and doubled widths and restores every path.

The native campaign includes both R1 components, unordered and repeated
query indices, unequal matrix heights, repeated tallest-height matrices,
multiple injections, exact role-frame replay, and separate full-path checks.
Negative controls cover inconsistent duplicate queries, inconsistent shared
injected rows, modified committed rows, extra/missing/modified frontier
digests, wrong context, wrong component, substituted indices, width-boundary
redistribution preserving the flattened stream, and unsupported geometry.

Two explicitly artificial test oracles force leaf collisions or branch
collisions. They demonstrate the witness-extraction branch using the actual
P3 verifier. The branch-collision control also supplies arbitrary raw sibling
digests, including words outside the Goldilocks field. Neither test is a
collision in SHA3 or a false W1 proof.

The new result is a bounded structural sublemma for the tagged candidate.
Concrete shared-primitive security, a full commitment extraction theorem,
PCS/Fiat–Shamir composition, recursive verification, and lifetime budget
qualification remain open. All project-level security-bit fields stay null.
