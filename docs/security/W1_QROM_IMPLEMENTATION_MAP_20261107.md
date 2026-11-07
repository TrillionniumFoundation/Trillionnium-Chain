# W1 v2: concrete implementation mapping toward a QROM proof

Date: 2026-11-07. Status: **MAPPING REPRODUCED; COMPLETE SECURITY HOLD**.

This continuation fixes the implementation inputs behind the post-quantum proof
question. It independently reconstructs the default recursion control tree,
the saved v2 receipt's public bindings and seal geometry, and a limited set of
conditional theorem expressions. It does not certify a complete recursive
proof, establish a practical forgery, or authorize consensus admission.

The three conclusions remain independent:

> PQ signatures protect authorization. A complete proof protects the specified
> computation relation. Quantum-work analysis protects the relationship between
> resources and chain weight.

All three require their own argument before the system can claim complete
post-quantum PoN security. A correct proof of a cheaply computed relation would
not establish costly work, and valid authorization would not establish either
of the other properties.

## 1. Fixed scope and reproducible deliverables

This work continues `cb114b13bf848a77634e40a08b31b30c7c758e7b`, the head of the
existing W1 source-snapshot/actual-record candidate. The primary entry points
are the [fixed contract](../../config/pon/w1-qrom-implementation-v1.json),
[implementation audit](../../scripts/w1_qrom_implementation_audit.py),
[control-tree reconstruction](../../scripts/w1_control_tree_audit.py),
[transcript geometry audit](../../scripts/w1_fri_transcript_audit.py), and
[conditional calculator](../../scripts/w1_qrom_conditional_budget.py).
The [dated evidence](../../evidence/pon-w1-qrom-implementation-20261107/README.md)
retains their outputs and validation observations.

The contract pins selected local source files and lockfiles, six historical v2
artifacts, the upstream source snapshot, and the audit helpers. Hashing and
parsing use the same immutable input bytes. Helpers execute from their checked
repository source bytes; a different import-path copy or cached Python module
cannot silently replace the code whose digest is recorded. This is provenance
binding under the normal trusted Python runtime, not isolation from a hostile
interpreter. Upstream Rust text is parsed as data and is never executed.

The upstream snapshot identifies
`risc0/risc0@8c215e2f4ccdd935f0517bf05d90f1ae032840a9` by both source URL and
Git blob identity, and includes the upstream Apache-2.0 license. Its original
20 selected source files match the SHA-256 values in the earlier archive-backed
source map. Additional files needed for exact tree/tap geometry are identified
separately. This continuation does not claim a fresh verification of every
registry archive or every transitive source file.

| Boundary | Fixed value or observation | What remains outside this check |
|---|---|---|
| Native verifier packages | `risc0-zkvm 3.0.6`, `risc0-zkp 3.0.5`, `risc0-core 3.0.2` | Complete enabled-feature/build semantics |
| Circuit packages | recursion and RV32IM `4.0.5` | Generated circuit and compiler correctness |
| Historical prover/guest | zkVM/r0vm `3.0.3`; saved guest ELF | Reproducible ELF-to-image calculation and version bridge |
| Receipt profile | Succinct, Poseidon2, fixed final `join.zkr` | Every permitted inner program's relation and RBR proof |
| Node authority | Existing full native work checking | No new proof-based Node admission or current-parent authority |

Historical proof generation and the original real-positive/57-negative receipt
controls are separate records. The new Python checks inspect fixed bytes and
source identities; they are not fresh STARK verification trials.

## 2. Field, extension and FRI parameters

| Item | Frozen value |
|---|---|
| Native work modulus | `4294967291` |
| Proof base field | BabyBear, `p = 2013265921 = 15 * 2^27 + 1` |
| Proof extension | degree four, `F_p[X] / (X^4 + 11)` |
| FRI inverse rate | `4` |
| FRI folding factor | `16` |
| FRI queries | `50`, sampled with replacement |
| Terminal polynomial | at most `256` extension coefficients |
| Source global cycle constants | minimum `13`, maximum `24` |
| Allowed default lift names | ordinary and PoVW lift parameters `14..22` |
| Generic outer seal parser | explicit rejection above `po2=24`; no corresponding explicit lower check |
| Actual saved v2 | 43 historical RV32IM segments, segment limit `18`; outer recursion raw `po2=18` |

Three ranges must not be collapsed. The maximum lift parameter in a program
name is not a proof of the maximum trace size of every outer recursion seal.
The Succinct verifier's `check_code` closure ignores its `po2` argument and
checks the code/control identity and membership instead. Code-root constraints
may restrict feasible trace sizes, but this audit does not characterize that
set. It does not claim that every parser-level value from zero through 24 can
produce an accepting proof. The report provides arithmetic schedules over that
explicit parser range while marking reachability unresolved.

The seal's `po2` slot is also an encoding exception. The first 32 output words
are converted from Montgomery form by `as_u32()` during receipt interpretation;
the exponent slot is read using `to_u32_words()` and keeps its raw value. The
saved raw value is 18. Montgomery-decoding that slot would describe a different
protocol and is covered by a negative control.

## 3. Entire default control family

The independent Python implementation parses the fixed Poseidon2 constants,
works in ordinary field representation internally, and handles little-endian
Montgomery digest bytes at the boundaries. It matches upstream known-answer
vectors, reconstructs all 255 internal nodes of the depth-eight tree, and
checks every named inclusion path.

The tree has 256 leaves: 27 named control IDs followed by 229 zero-digest
padding leaves. The named IDs are sorted exactly as in the fixed implementation.

| Program family | Count | Named entries |
|---|---:|---|
| Identity | 1 | `identity.zkr` |
| Join | 3 | `join.zkr`, `join_povw.zkr`, `join_unwrap_povw.zkr` |
| Resolve | 3 | `resolve.zkr`, `resolve_povw.zkr`, `resolve_unwrap_povw.zkr` |
| Other recursion operations | 2 | `union.zkr`, `unwrap_povw.zkr` |
| Ordinary lift | 9 | `lift_rv32im_v2_14.zkr` through `lift_rv32im_v2_22.zkr` |
| PoVW lift | 9 | `lift_rv32im_v2_povw_14.zkr` through `lift_rv32im_v2_povw_22.zkr` |

The upstream catalog additionally contains the four lift variants at 23 and 24
and `test_recursion_circuit.zkr`; they are outside this default named family.
The computed identities are:

```text
control root
a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56

final join control ID, leaf index 1
7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e

Succinct verifier parameter digest
ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013
```

The parameter digest is independently recomputed from its tagged SHA-256
structure, both effective control roots, `RISC0_STARK:v1__`, and
`RECURSION:rev1v1`. The actual receipt's eight siblings match the reconstructed
join path; both inner and outer parameter fields match the fixed digest.

This proves the reconstruction agrees with the selected source catalog. It
does not rebuild `.zkr` programs from their generators, derive all control IDs
from bytecode, prove the absence of an accepting computation for a padding
digest, or establish any program's semantic relation. Those are separate
obligations. Restricting the final program to `join` does not remove the need to
analyze the complete permitted inner family.

## 4. Public relation and historical guest binding

The fixed v2 journal has 16,882 bytes. It binds the 318-byte header, trace
commitment, ticket, work ID, independent commitments to the original raw A/B
matrices, and all 4,096 public product words. Its domain is
`TRNM-W1-ZK-JOURNAL2\0`; the raw A and B commitments begin at offsets 434 and
466, and the public product begins at offset 498.

The audit rehashes the original matrices using the native framing and checks
the header task identity, target, trace/ticket/work identities, public product
bytes, saved guest bytes, image words and claim-output digest. The work hash
framing is `TRNM-PON1\0`, a little-endian 16-bit tag length, the tag, and each
part prefixed by a little-endian 32-bit length. This preserves the distinction
between the raw artifact relation and a transformed commitment relation.

The fixed image is:

```text
[1958252411, 3287394615, 1805488136, 1516578702,
 78549041, 790278610, 301018785, 4279049364]
```

The saved receipt is 257,014 bytes with SHA-256
`6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee`.
The saved guest ELF SHA-256 is
`25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f`.
Matching these values to a historical manifest is not an independent
ELF-to-image reconstruction. The mapping explicitly leaves that flag false,
along with fresh cryptographic verification and complete native replay.

## 5. Hash roles, Merkle typing and transcript

| Use | Actual encoding/primitive | QROM mapping obligation |
|---|---|---|
| Native work identity, artifacts and journal | SHA-256 with application tags and length prefixes | Model each use and quantum access in the whole reduction |
| Guest/receipt claims and verifier parameters | RISC Zero tagged SHA-256 structures | Prove the compiler and claim relation preserve the intended statement |
| STARK Merkle leaves | Poseidon2 over fixed circuit/phase field vectors | Preserve authenticated width, field representation and phase |
| STARK/control Merkle nodes | Two ordered eight-word digests, same Poseidon2 unpadded hash | Establish quantum binding/extraction for the actual typed construction |
| Transcript messages | Same suite's element/extension hash followed by RNG `mix` | Match this state machine to the selected compiler |
| Transcript RNG | Stateful Poseidon2 permutation; extension challenges use four base outputs | Joint quantum-oracle model and sampling analysis |

Poseidon2 has width 24, rate 16, capacity eight field elements, eight full
rounds, 21 partial rounds and an exponent-seven S-box. The stored digest is
32 bytes, but its support has size `p^8`, approximately 247.255 bits. Neither
the storage width nor this support calculation supplies the theorem's uniform
bit-oracle parameter or a quantum security estimate.

The suite's element, extension and pair hashes share `unpadded_hash`. Its
zero padding admits `H([1]) = H([1, 0])`; a regression control reproduces that
actual behavior. The upstream implementation restricts the intended
collision-resistance claim to equal-length inputs. A fixed-width tree node
does not create an arbitrary-length collision claim, but cross-type use still
requires a typed commitment argument. There are no explicit leaf/node/level/
index/purpose tags inside this raw hash interface.

Merkle sizes and positions are supplied by the fixed circuit, committed `po2`
and parser. A leaf contains exactly the expected number of canonical field
words. The index determines ordered left/right hashing and the correct cap
position; the expected depth determines the number of siblings. A raw root
does not independently encode all those auxiliary parameters. The extraction
proof must preserve them.

The standard native verifier commits proof and circuit context, outputs plus
raw `po2`, code root and data root; it samples 20 accumulation base challenges,
commits the accumulation root, samples a constraint-mixing extension challenge,
commits the check root, and samples the DEEP point. It then commits U
coefficients, checks the validity equation, samples the FRI batching challenge,
and for each FRI round commits its root before sampling its folding challenge.
It commits the final polynomial before drawing 50 query positions and requires
complete seal consumption. The machine-readable transcript records each event.

Root commit order is `code, data, accum, check`; opening order is
`accum, code, data, check`, followed by the FRI rounds. U coefficients are
adjacent four-component extension values. Final coefficients and the 16
extension values in each FRI leaf use component-major layout. A proof mapping
must preserve these distinctions.

The inspected standard verifier path has no explicit nonce/difficulty gate,
so this map assigns zero explicit Fiat-Shamir grinding credit. This scoped
observation does not rule out prover transcript search or other protocols.
PoN ticket difficulty is not automatically Fiat-Shamir grinding credit.

## 6. Actual v2 seal geometry

The recursion circuit has 32 outputs, 20 mix values, 643 taps, 163 registers,
and a check width of 16. U contains `643 + 16 = 659` extension values, or
2,636 base words. For the actual outer `po2=18`, the trace size is `2^18`,
the original domain is `2^20`, and three fold-by-16 rounds leave 64 terminal
extension coefficients.

| Tree | Leaves | Full depth | Cap digests | Siblings/opening | Base words/leaf |
|---|---:|---:|---:|---:|---:|
| Code | 1,048,576 | 20 | 32 | 15 | 23 |
| Data | 1,048,576 | 20 | 32 | 15 | 128 |
| Accumulation | 1,048,576 | 20 | 32 | 15 | 12 |
| Check | 1,048,576 | 20 | 32 | 15 | 16 |
| FRI round 0 | 65,536 | 16 | 32 | 11 | 64 |
| FRI round 1 | 4,096 | 12 | 32 | 7 | 64 |
| FRI round 2 | 256 | 8 | 32 | 3 | 64 |

The independent parser accounts for every seal word:

```text
4,717 words before queries + 50 * 1,019 words per query = 55,667 words
```

Every observed word is below the BabyBear modulus. The serialized receipt
prefix locates the seal at byte 12, and its 55,667 words occupy 222,668 bytes.
Geometry agreement checks encoding and parser expectations, not Merkle opening
hashes, polynomial equations, or the STARK's soundness.

`random_bits(k)` consumes four base samples, chooses the first nonzero
canonical value (or zero if all four are zero), and masks to the low `k` bits.
Under the explicitly conditional independent-uniform-base model and `k<=27`,
its total-variation distance from a uniform `k`-bit value is
`(1 - 2^-k) * p^-4`. A 50-query sampling-only union bound is at most `50*p^-4`.
This algebra does not prove that the real sponge supplies that model.

For `R` FRI rounds, this native transcript uses `232 + 4R` base squeezes and
`26 + 2R` RNG permutations: 244 and 32 respectively in the saved sample.
These counts exclude commitment hashing, nested verification and adversarial
attempts. They are not a lifetime quantum-oracle query budget.

## 7. Formal theorem bridge and conditional arithmetic

[Chiesa-Di-Hu-Zheng, 2025/2166](https://eprint.iacr.org/2025/2166) provides a
framework for succinct non-interactive reductions. This review checked selected
formal statements in the [January 1 manuscript](https://files01.core.ac.uk/download/690750245.pdf).
IACR metadata reports a March 2 revision; direct retrieval returned HTTP 403.
Equivalence to that latest full text and a full proof audit remain unverified.
The [Springer chapter](https://link.springer.com/chapter/10.1007/978-3-032-25336-1_14)
confirms formal publication on May 9, 2026, in LNCS 16547, pages 389-415. Its
accessible preview and the authors' ePrint links do not supply the full updated
theorem text. EPFL retrieval also failed in this session. None of those metadata
checks establishes formula or notation equivalence to the January manuscript.

The calculator implements only the January Theorem 6.10 expression

\[
80(t+k+1)(w+k)\kappa_{\rm RRBR}
+(t+k+1)k2^{-r_{\min}},
\]

and the four separately named Theorem 8.3 expressions

\[
\frac{240(t+1)}{2^\sigma},\qquad
\frac{8n\ell_{\max}}{2^\sigma},\qquad
\frac{160w_{\rm VC}t^2+16q_s\log_2\ell_{\max}}{2^\sigma},\qquad
\frac{240w_{\rm VC}t^2}{2^\sigma}.
\]

Theorem 11.3 additionally needs the specified knowledge-sound IOR, monotone
output relation, committed relations and multi-extractable commitments. Its
mass maximization, shifted query arguments, coefficients and commutator term
are not implemented here. Theorem 10.6's compatible-relation, same-oracle
sequential composition also remains uninstantiated. Summing the displayed
components is not either theorem. January notation differs in positional mass
argument order across statements; the calculator uses named arguments and
leaves revision reconciliation open.

The local calculator uses exact integers and rational numbers, rejects floats,
booleans, inconsistent mass bounds and unsupported schemas, and retains unknown
inputs as `null` even when another factor is zero. `k` is the complete IOR round
count, not the number of FRI folds. All project security-bit fields remain null
and all qualification fields remain false for every output.

The evidence includes one wholly hypothetical example using `t=w=2^64`,
`k=16`, `r_min=384`, `kappa_RRBR=2^-320`, `sigma=384`, `ell_max=2^20`, `n=8`,
`q_s=128`, and a component target of `2^-128`. A comparison changes only the
hypothetical ideal-oracle width to 256. These inputs are not adopted project
parameters. A failure to meet a target in an upper-bound expression is not a
lower bound on an attack or proof that the actual construction is insecure.

| Hypothetical ideal-oracle width | Offline component expression, approximate | Online component expression, approximate | Both at most `2^-128`? |
|---|---|---|---|
| 384 | `2^-184.678` | `2^-184.093` | Yes, for these hypothetical inputs only |
| 256 | `2^-56.678` | `2^-56.093` | No; this upper expression cannot certify that target |

These are the values of two separate expressions, not security-bit estimates
for W1. The table does not recommend a hash-width change or establish that
changing one parameter would close the complete theorem obligations.

## 8. Near-capacity assumptions and reference correction

[2023/1071](https://eprint.iacr.org/2023/1071) is Block-Garreta-Katz-Thaler-
Tiwari-Zajac's *Fiat-Shamir Security of FRI and Related SNARKs*. It belongs in
the RBR/Fiat-Shamir background, not as the reference for the later RS
counterexamples. Its discussion of RISC Zero does not instantiate this exact
selected implementation.

[Crites-Stewart, 2025/2046](https://eprint.iacr.org/2025/2046) disproves the
original up-to-capacity correlated-agreement, mutual-correlated-agreement and
DEEP-FRI list-decodability conjectures it specifies. The
[Fenzi-Sanso published paper](https://cic.iacr.org/p/3/3/44) analyzes a toy
protocol and small-base-field list-size obstructions relevant to conjectural
estimates. Neither result by itself constructs a forgery of this complete W1
receipt relation or invalidates every FRI parameter regime.

The earlier [dated STARK review](W1_STARK_REVIEW_20261106.md) and exact component
calculator remain intact. Their 144 arithmetic comparisons are equation
reproduction, not a proof that the conjectural expression bounds the allowed
recursive family. No replacement near-capacity conjecture, asymptotic positive
result, or Johnson/unique-decoding result is silently substituted for the
concrete required RBR bound.

## 9. Remaining acceptance obligations

| Obligation | Required evidence before closure | Current state |
|---|---|---|
| Latest theorem version | Authoritative full text and reconciliation of the selected statements | Open |
| Complete relation/compiler | RV32IM, recursion, guest compiler and public A/B/product relation correspondence | Open |
| All control programs | Generated bytecode/control identities and each allowed relation, including padding exclusion where needed | Open |
| RBR knowledge soundness | Explicit bounds for every relevant circuit, size, round and permitted statement | Open |
| Monotone/committed relations | Actual relation definitions and decider query bounds | Open |
| Vector commitment extraction | Quantum properties for the actual typed, capped, field-encoded Merkle construction | Open |
| Shared sponge and hash uses | Joint oracle model, domain/type handling and concrete-to-ideal reduction | Open |
| Fiat-Shamir/compiler match | Exact state machine, encoding, salt and challenge interfaces | Open |
| Sampling/randomness | Concrete conditional sampling bounds and minimum full-round randomness | Open |
| Recursive composition | Compatible relation chain, extractor costs, commutators and adaptive choices | Open |
| Lifetime budget | One system-wide quantum budget, accepted statements, recursion caps and total target | Open |
| Compiled feature scope | Exact builds and explicit exclusion of debug/dev or alternate proof paths | Open |
| Quantum work/chain weight | Resource lower/cost model, reuse, lottery, difficulty and fork-choice analysis | Independent, open |
| PQ authorization | Owner keys, transaction/transport/finality scopes and migration assumptions | Independent; not inferred here |

Lifetime values are deliberately unset in the contract. An operational policy
must cover failed proofs, offline transcript searches, every hash role, all
recursion nodes and all adversarial strategies over the system lifetime. A
per-proof allowance must not be reset after each accepted block. A final
composition bound must justify any conditional or adaptive union accounting;
neither `50` FRI queries nor 32 native RNG permutations supplies that bound.

## 10. Validation and disposition

The dedicated [CI workflow](../../.github/workflows/pon-w1-qrom-implementation.yml)
checks the exact candidate and prospective merge, fixes the complete named
test roster, retains logs and requires successful source checks before and
after execution. It emits unknown-input and explicitly hypothetical component
reports without granting security qualification. The dated evidence records
what actually ran locally; hosted CI is reported separately after readback.

New controls cover incorrect constants/catalog order, Montgomery encoding,
inclusion position/length, source and helper drift, import-cache substitution,
v2 identity substitutions, raw `po2`, seal geometry and noncanonical/trailing
data, and unknown or invalid conditional inputs. Existing real receipt
verification controls remain necessary and are not replaced by these checks.

The final new roster has 81 tests. Complete W1 discovery passes 209 tests;
43 separate source-integrity controls and 104 existing CI-contract controls
also pass. Fourteen new CI-gate regressions cover early `load_tests()` exit,
missing completion evidence, missing/altered budget components and false/null
type boundaries. These tests do not add 14 new cryptographic receipt trials.
Rust formatting and the repository/link check pass; locked native compilation
and strict Clippy remain blocked by the recorded incomplete offline dependency
cache. The evidence distinguishes candidate-worktree observations from the
required hosted checks of the exact published head and prospective merge.

The acceptance result remains `HOLD`: implementation mapping is more complete,
but the complete QROM proof, PQ authorization audit and quantum-work/chainweight
argument have independent unresolved obligations. Production activation,
ordinary-node proof admission and chain-level post-quantum acceptance remain
false.
