# P3 0.8.0 shared-permutation model audit

## Result and scope

This increment constructs exact counterexamples to two primitive models that must not be used to close the full W1 noninteractive security gate. It uses the official Goldilocks Poseidon2 width-eight constants from the exact Plonky3 0.8.0 crates. The Python reference matches the upstream known-answer vector, verifies both inverse linear maps and the inverse S-box exponent, and produces concrete witnesses. A separate Rust program checks those witnesses using only the actual P3 forward APIs.

The findings do **not** constitute a Merkle binding attack or an accepted false W1 proof. No concrete ROM/QROM soundness bound, lifecycle budget, or PQ128 conclusion is established. Qualification remains **HOLD_NO_GO**.

The baseline is the full W1 two-PCS Plonky3 research associated with PR #783, published commit `3bbd072e4983eceee4531d7576d329da5b0d0900`. Application source and native-02 metadata were read from the recovered local materials and retained with SHA-256 pins. This audit independently verifies the exact crates against the recovered Cargo.lock; it does not claim to have independently fetched and compared the published application commit. The older RISC Zero research is outside this audit.

## Exact construction

Let F be Goldilocks with p = 18446744069414584321, and let Π: F⁸ → F⁸ be the public, invertible, official default Poseidon2 permutation. The fixed application config uses:

- `PaddingFreeSponge<Perm, 8, 4, 4>` for Merkle leaves;
- `TruncatedPermutation<Perm, 2, 4, 8>` for internal compression;
- `DuplexChallenger<Val, Perm, 8, 4>` for the transcript;
- clones of the same permutation parameters for those roles and both components.

The application prefixes its two transcripts with different component identifiers. This does not make the underlying permutation or the leaf/compression constructions independent.

### 1. Arbitrary-input compression collision: a universal construction

Write C(u,v) = first₄(Π(u ∥ v)), with u,v in F⁴. Choose any digest d in F⁴ and distinct tails r,s in F⁴. Let a = Π⁻¹(d ∥ r) and b = Π⁻¹(d ∥ s). Invertibility gives a ≠ b, while C(a₀…a₃,a₄…a₇) = d = C(b₀…b₃,b₄…b₇). This uses two inverse permutations and no search.

For d = (0,1,2,3), the generated report contains exact preimages with full outputs (0,1,2,3,4,5,6,7) and (0,1,2,3,4,5,6,8). The Python program verifies the forward equations. The Rust probe independently checks them through P3.

This behavior is consistent with the upstream contract: P3 implements **PseudoCompressionFunction**, whose documentation explicitly restricts the intended collision resistance to hash-tree-like settings. It does not implement a general collision-resistant compression function. The construction therefore rules out a reduction premise of unrestricted 128-bit collision resistance for C; it does not rule out a correctly specified restricted tree-binding theorem. The selected preimages have not been shown to be realizable as valid child digests in the W1 commitment trees.

### 2. Deterministic overlap between leaf and branch roles

For every x in F⁴, the four-field leaf hash is H₄(x) = first₄(Π(x ∥ 0⁴)) = C(x,0⁴). This equality is universal. A simulator that replaces H₄ and C with independent uniform functions gives equality with probability p⁻⁴ on those two queries. The equality test therefore distinguishes those independent-function models with advantage 1 − p⁻⁴. It does not distinguish the real construction from a single ideal permutation model.

Also, for every a,b in F, H₂(a,b) = H₄(a,b,0,0): both make the same first permutation call. Fixing each individual leaf width removes the single-role variable-length ambiguity, but it does not separate these two fixed roles.

These lengths actually occur in the baseline: the arithmetic quotient batch has one width-two base-field row, while a binary FRI leaf has two quadratic-extension elements, which `ExtensionMmcs` flattens to four base-field elements. The SHA quotient batch has two width-two rows at the same height, which are hashed together as width four. The table below describes those roles; it is not a claim that the witness rows in this audit satisfy a valid trace or quotient polynomial.

| Component and role | Base-field width presented to the leaf sponge | Permutation calls per leaf |
|---|---:|---:|
| SHA main trace | 7728 | 1932 |
| SHA preprocessing | 27 | 7 |
| SHA quotient batch | 4 | 1 |
| Arithmetic main trace | 516 | 129 |
| Arithmetic preprocessing | 18 | 5 |
| Arithmetic quotient batch | 2 | 1 |
| Either component, binary FRI | 4 | 1 |

For any nonempty leaf width, its final sponge call also lies in C's unrestricted input domain: if the last state before the permutation is (rate,capacity), the leaf output equals C(rate,capacity). This fact explains why a shared primitive model must retain interactions across roles. It does not establish that arbitrary internal child pairs can be generated as valid leaves.

## Consequence for the outstanding NI and lifecycle proof

The reported approximately 63.95384529640614 bits remain conditional RBR metadata. The application's `ASSUMED_HASH_COLLISION_BITS = 128` is explicitly labeled an assumption in its source. This audit narrows the acceptable interpretation: that parameter cannot stand for arbitrary-input collision resistance of the raw truncated permutation, nor justify substituting independent leaf/branch random functions.

A valid concrete closure must specify a restricted commitment/tree binding game, actual allowed matrix shapes, the same public permutation with forward and inverse evaluation available, and the interaction of both components and their transcripts. It must charge a single adversarial query budget across the shared primitive. Honest verifier permutation counts alone do not upper-bound offline adversarial evaluation. Component prefixes do not supply the missing reduction.

Once correct per-component noninteractive bounds are proved in a common adaptive game, ordinary union bounds can combine them without any independence assumption. This audit does **not** object to the union bound itself. It objects to importing component or role bounds proved for different, independent oracle models without a justified simulation or reduction. Merkle binding, sampling bias, Fiat–Shamir compilation and lifetime amplification remain unresolved together with the exact concrete constants and query model.

The next defensible proof target is therefore a concrete theorem for the actual restricted shared-permutation commitment/transcript construction, or an explicitly versioned redesign with a theorem that applies to its exact primitives. Changing widths, prefixes or the value 128 without that argument would not close the gate. This audit makes no production configuration change.

## Reproduction and evidence

The audit requires Python 3.8+ with only the standard library:

```sh
python3 -m unittest -v test_hash_role_audit.py
python3 hash_role_audit.py --out artifacts/hash_role_audit.json
```

Ten tests cover the official known-answer vector, algebraic inverse certificates on every basis vector, chosen-output collision witnesses, single-coordinate witness mutations, fixed-role overlaps, all mapped leaf widths, source tampering, and scope limitations. `artifacts/python_tests.txt` retains the actual test output. The current report binds `source_inputs/manifest.json` by SHA-256; that manifest pins each primary source file and the six exact source archives. Their archive hashes match the retained Cargo.lock.

For the independent native check, copy `hash_role_probe.rs` into the pinned W1 research crate as `examples/hash_role_probe.rs`, then run:

```sh
cargo run --locked --release --example hash_role_probe
```

The native probe has not been executed in this local environment, which has no Rust toolchain. Its source is a forward-only consumer of the independently generated exact witnesses. Native success must be recorded separately and must not be inferred from the Python tests.

## Primary sources

- [P3 symmetric compression contract and implementation, 0.8.0](https://docs.rs/crate/p3-symmetric/0.8.0/source/src/compression.rs).
- [P3 padding-free sponge implementation, 0.8.0](https://docs.rs/crate/p3-symmetric/0.8.0/source/src/sponge.rs).
- [Official Goldilocks Poseidon2 parameters and known-answer test, 0.8.0](https://docs.rs/crate/p3-goldilocks/0.8.0/source/src/poseidon2.rs).
- [Poseidon2 external linear layer, 0.8.0](https://docs.rs/crate/p3-poseidon2/0.8.0/source/src/external.rs).
- [Poseidon2 internal linear layer, 0.8.0](https://docs.rs/crate/p3-poseidon2/0.8.0/source/src/internal.rs).
- [Extension MMCS base-field row conversion, 0.8.0](https://docs.rs/crate/p3-commit/0.8.0/source/src/adapters/extension_mmcs.rs).
- [Uni-STARK opening order and quotient formation, 0.8.0](https://docs.rs/crate/p3-uni-stark/0.8.0/source/src/prover.rs).
- [FRI leaf formation and multiproof order, 0.8.0](https://docs.rs/crate/p3-fri/0.8.0/source/src/prover.rs).

The official `.crate` archive URLs and digests are recorded in the source manifest. Upstream source files are from Plonky3, licensed MIT OR Apache-2.0 according to the source package manifests; the downloaded archives are retained as provenance under `vendor_primary/`, not required for the small integration payload.
