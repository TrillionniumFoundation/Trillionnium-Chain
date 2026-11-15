# W1 P3: pinned interfaces and exact query-expression feasibility

Date: 2026-11-08. Status: **ARITHMETIC AND SOURCE AUDIT; QROM HOLD**.

The external P3 candidate has a reproducible conditional query contribution
whose negative base-two logarithm is approximately **63.95384529640614**.
The exact calculation below identifies the expression, its source and its
parameter scope. It establishes neither an attack cost nor a complete
noninteractive, quantum, recursive or lifetime security bound. All such
qualification flags remain false and their project bit counts remain null.

## 1. Immutable profile and source provenance

This document refers only to the external Chain source revision
`cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`. It is not the RISC Zero source tree
and does not import that candidate's program catalog or theorem assumptions.
The [application manifest](../../evidence/pon-w1-qrom-proof-chain-20261108/p3-source-manifest.json)
pins the source revision, Git blobs and SHA-256 digests of five public files.
The [dependency manifest](../../evidence/pon-w1-qrom-proof-chain-20261108/p3-dependency-source-manifest.json)
records six official P3 0.8.0 archives, their agreement with the pinned
lockfile, the exact archive members used, and the separate estimator sources.

The actual [proof configuration][config] is:

| Parameter | Frozen P3 value |
|---|---|
| Base field | Goldilocks, `p = 18446744069414584321` |
| Challenge extension | Degree two, `X^2 - 7` |
| Estimator field size input | Conservative 127 bits |
| FRI rate | `rho = 1/4`, `log_blowup = 2` |
| Maximum folding arity | Two, `max_log_arity = 1` |
| Query draws | 64, with replacement |
| Terminal polynomial | `log_final_poly_len = 0`: one extension coefficient |
| Leaf hash | `PaddingFreeSponge<Perm, 8, 4, 4>` |
| Branch compressor | `TruncatedPermutation<Perm, 2, 4, 8>` |
| Merkle commitment | Binary tree, four field elements per digest, cap height zero |
| Challenger | `DuplexChallenger<Goldilocks, Perm, 8, 4>` |
| Shared permutation | The same default `Poseidon2Goldilocks<8>` in leaf, branch and challenger roles |
| Grinding parameters | Batch, commitment, query, OOD and lookup all zero |
| Zero knowledge | Disabled |
| Collision input to estimator | Assumed 128 bits; a conditional input, not a proved concrete compressor bound |

The [pinned Cargo.lock][lock] fixes the package checksums. The verified
archives declare Plonky3 source revision
`a21e3ed42905040ad49c519e402f018381c12d0c`. The estimator files
`security/src/{fri,proximity,stark,report,error}.rs` were independently obtained
as GitHub source at that immutable revision. **The p3-security archive itself
was not independently obtained.** Its expected lockfile checksum is recorded
in the dependency manifest; the source-to-archive correspondence for that
particular package remains unverified. The manifest does not describe the
GitHub fallback as archive-byte verification.

## 2. What the estimator actually composes

The [FRI implementation of the estimate][fri], [proximity definitions][proximity],
[composite orchestration][stark] and [report aggregation][report] implement
the following structure, writing each contribution as `b = -log2(epsilon)`:

\[
b_{\mathrm{report}}
=\max\!\left\{b_{\mathrm{UDR}},
\max_{m\in\mathcal M}\min\left(
b_{\mathrm{ALI}}(m),b_{\mathrm{DEEP}}(m),
b_{\mathrm{FRI,commit}}(m),b_{\mathrm{query}}(m),
b_{\mathrm{batch}}(m),b_{\mathrm{extra}},128\right)\right\}.
\]

Here `M` is the implementation's admissible integer range beginning at three,
capped by both `compute_upper_m` and 1000. The composite searches for the best
whole report, not just the best LDT term. The notation `extra` means any
additional terms passed by the caller; the frozen application supplies an
empty list. The FRI LDT already takes the minimum of its commitment and query
bit values. Taking minimum bits corresponds to a maximum of the represented
individual error contributions. Choosing maximum bits between admissible
regimes selects the tighter conditional RBR estimate.

This is **not** `-log2(sum epsilon_i)` for the failure probability of a complete
execution. It must not be inserted into a quantum state-restoration theorem as
an established full-protocol knowledge bound. The estimator source refers to
its own FRI/RBR and Johnson commit analyses; its computation is not an
implementation-to-CDHZ Theorem 6.10 or 11.3 mapping.

In the LDR query expression, with zero query grinding, the source sets

\[
\alpha_m=\left(1+\frac1{2m}\right)\sqrt\rho,
\qquad \epsilon_{\mathrm{query}}=\alpha_m^\ell.
\]

At the pinned rate `rho = 1/4`, fixed `m = 1000` and `ell = 64`,

\[
\alpha_{1000}=\frac{2001}{4000},\qquad
\epsilon_{\mathrm{query}}=\left(\frac{2001}{4000}\right)^{64},\qquad
-\log_2\epsilon_{\mathrm{query}}
=63.95384529640614\ldots.
\]

This reconstructs the cited numerical contribution. The equality is exact
before the displayed logarithm is approximated. The number does not measure a
known attack. The expression itself remains conditional on the hypotheses
that connect the implemented protocol and sampling law to the analysis.

Increasing the query count can move the bottleneck to batching, commitment,
ALI, DEEP or another contribution. A new complete report must reoptimize `m`
and recompute all terms. The helper below holds `m = 1000` fixed and does not
claim that increasing queries alone produces a stronger complete proof.

## 3. Bounded exact arithmetic for necessary query counts

The new [query-expression helper](../../scripts/w1_query_expression_feasibility.py)
computes the least nonnegative integer `ell` satisfying

\[
A\alpha^\ell\le 2^{-s}
\]

for explicitly supplied rational `alpha` in `(0,1)` and multiplier `A >= 1`.
It uses integer cross-products for every decision, including equality and
minimality. It does not establish the multiplier, the sampling premise,
extraction costs or a theorem mapping.

If a nonnegative sum or maximum contains this contribution, meeting this
inequality is necessary for that expression to reach the target. It is
sufficient for this one contribution only. This does not make `alpha^ell` a
lower bound on the protocol's actual failure probability.

For the fixed P3 expression `alpha = 2001/4000` and target exponent `s = 128`:

| Hypothetical multiplier `A` | Least `ell` for this single expression |
|---:|---:|
| `1` | 129 |
| `2^16` | 145 |
| `2^32` | 161 |
| `2^64` | 193 |
| `2^128` | 257 |
| `2^256` | 385 |

These multipliers are explicit hypotheses. No row is an adopted adversarial
budget, and no row assumes that CDHZ 6.10 or 11.3 has been mapped. Additional
additive errors would require their own allowance even if this contribution
met the full target. The output labels the approximate logarithm as the
negative logarithm of an expression, and keeps project security bits null.

There is also an abstract necessary condition at inverse rate four. If the
selected theorem requires `alpha > sqrt(rho) = 1/2`, `A = 2^a`, and `s,a`
are nonnegative integers, then for positive `ell`,

\[
A\alpha^\ell>2^{a-\ell}.
\]

Consequently a nontrivial target requires `ell >= s+a+1`. The exceptional
trivial case `s=a=0` admits `ell=0`. This condition supplies no sufficient
query count for an unspecified `alpha`. It explains why the corresponding
Johnson-regime expression with fifty queries cannot meet a target exponent
of fifty or more at `A=1`. It does not map RISC Zero's radix-16 protocol to
the P3 formula, establish a RISC Zero RRBR envelope, or prove an attack.

### Reproduction and refusal behavior

Run from the repository root:

```bash
python scripts/w1_query_expression_feasibility.py
python scripts/w1_query_expression_feasibility.py --alpha 2/3 --assumed-multiplier 3/2 --target-bits 128
python -m unittest discover -s scripts/ci -p test_w1_query_expression_feasibility.py -v
```

The default output includes the fixed P3 reconstruction, the six rows above,
the strict Johnson necessary condition and false/null qualification fields.
The optional custom expression requires both `--alpha` and
`--assumed-multiplier`. It is explicitly hypothetical and receives no protocol
identity. The reusable Python functions require a keyword-only `Fraction`
alpha; they have no P3 default that another profile could accidentally inherit.
Floats, booleans, missing explicit parameters, repeated numerical flags and
malformed fractions are refused; an invalid earlier option cannot be silently
discarded in favor of a repeated final value.

Resource limits are separate from cryptographic limits: at most 1024 bits per
input fraction component, target exponent 4096, 16384 queries and 262144 bits
per exact comparison operand. The permitted search endpoint is computed
before exponentiation. Bernoulli's inequality
`alpha^ell >= 1-ell*(1-alpha)` rejects parameters extremely close to one when
they cannot meet the target within that endpoint, without computing large
powers. Otherwise bounded doubling and binary search stop at the finite
endpoint. Resource refusals have a structured error, exit code two and
unchanged false/null qualification. They do not claim that no finite
mathematical solution exists.

The tests exercise exact equality and the immediately preceding failing
integer, non-power-of-two factors, missing/float/bool input, pre-power size
refusal, close-to-one refusal, bounded search exhaustion and CLI qualification.
They verify arithmetic and refusal behavior, not cryptographic soundness.

## 4. Remaining implementation-to-theorem interfaces

### Statement, relation and transcript

The application [public statement decoder and relation builder][public] and
[packed-carry runner][runner] matter to statement binding. The runner rebuilds
the AIRs and preprocessing commitments from independent expected headers and
artifacts, applies wire/degree admission, and invokes the native verifiers.
An empty `public_values` slice is therefore not by itself evidence that the
statement is unbound. A proof must establish completeness of this indirect
statement mapping for every accepted input and selected relation.

The [uni-STARK transcript][uni-transcript] absorbs the main trace commitment,
preprocessed commitment and public values before the alpha challenge, then
the quotient commitment before zeta. The PCS observes opening claims before
its batching challenge. The [FRI transcript][fri-transcript] observes round
commitments before folding challenges and the final polynomial before query
indices. Native verification checks final polynomial length and the canonical
zero-difficulty witness requirements. This source order is evidence for an
interface map, not a Fiat--Shamir knowledge theorem.

The shape fingerprint binds dimensions, **not the AIR constraint
polynomials**. A theorem application must bind the selected verifier relation
and code, not just its transcript shape. The typed pattern and algebra
fingerprints additionally use Keccak-256 in the [pattern sequence][pattern]
and [interaction descriptors][interaction]. These require explicit treatment
as fixed inputs or as a separate primitive family. Counts of the shared
Poseidon2 alone do not count these operations. Purpose labels do not turn
the same public permutation into independent random oracles.

### Query law and repeated positions

The actual chain is `FriVerifierTranscript::query_phase`, typed
`VerifierState::challenge_bits`, then [DuplexChallenger::sample_bits][challenger].
The last operation samples a base-field element, converts its canonical u64
and masks the requested low bits. This chain has no rejection sampler or
uniqueness enforcement. Authentication-path deduplication does not change
these draws into sampling without replacement.

Conditional on independent uniform base-field elements, let `N = 2^b` and
`p = kN+r`. Index masses are `k/p` or `(k+1)/p`, with heavy indices `0..r-1`.
For a set `S` fixed before sampling,

\[
\mu(S)=\frac{k|S|+|S\cap\{0,\ldots,r-1\}|}{p},
\qquad \Pr[\text{all }\ell\text{ draws in }S]=\mu(S)^\ell.
\]

For Goldilocks and `1 <= b <= 32`, `r=1`. The implementation does not establish
the independent-uniform premise or that an adaptive adversary's relevant
set is fixed in advance. The eventual theorem must handle the actual law and
adaptive conditions. Neither treating 64 draws as 64 distinct locations nor
subtracting a duplicate-count bit penalty supplies that proof.

The shared-permutation reduction, full relation-to-knowledge mapping,
quantum state restoration, actual vector-commitment extraction and lifecycle
composition remain open. This audit establishes no new false-proof acceptance
attack and supplies no permission to transfer the P3 number to RISC Zero.

[config]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/src/proof_config.rs
[lock]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/Cargo.lock
[public]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/src/public.rs
[runner]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/examples/packed_carry_backend.rs
[fri]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/security/src/fri.rs
[proximity]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/security/src/proximity.rs
[stark]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/security/src/stark.rs
[report]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/security/src/report.rs
[uni-transcript]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/uni-stark/src/transcript.rs
[fri-transcript]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/fri/src/transcript.rs
[pattern]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/challenger/src/fs/pattern/sequence.rs
[interaction]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/challenger/src/fs/pattern/step.rs
[challenger]: https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/challenger/src/duplex_challenger.rs
