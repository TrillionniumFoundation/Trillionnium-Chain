# W1: numerical AIR, DEEP and FRI replay for the fixed v2 seal

Date: 2026-11-08. Status: **FIXED-SEAL ALGEBRA REPLAY COMPLETE; END-TO-END QROM HOLD**.

This continuation starts at the exact published
[PR #792](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/792)
head `2e5150c41484a8b3196b33de2e997794145edd7c`. Its
[transcript and opening replay](W1_FRI_QUERY_REPLAY_20261108.md) explicitly
omitted the mixed AIR equation, the DEEP evaluation, the FRI folding equations
and the terminal polynomial equations. The new
[algebra replay](../../scripts/w1_fri_algebra_replay.py) evaluates those
previously omitted equations on the same complete, byte-pinned historical
receipt. The old replay and every historical observation remain unchanged.

The result closes that **fixed-input numerical replay** gap. It does not prove
the intended semantics of the guest, VM, generated AIR or all recursive
programs; it does not supply a round-by-round knowledge extractor. None of the
eight complete implementation proof interfaces in the
[QROM proof-chain disposition](../../evidence/pon-w1-qrom-proof-chain-20261108/proof-chain-status.json)
is relabeled closed. Complete W1/PQ qualification remains false, and the full
security bound and unconditional project security bits remain `null`.

## 1. Exact input and source identities

The input is still `evidence/pon-w1-full-v2-20261105/succinct.bin`, 257,014
bytes, SHA-256
`6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee`.
Its standard outer join seal has raw `po2=18`. The source profile remains
`trnm-w1-risc0-3.0.6-poseidon2-join-v2` and upstream commit remains
`8c215e2f4ccdd935f0517bf05d90f1ae032840a9`.

The driver first checks and executes the exact local historical replay helper,
SHA-256 `4a6a4f96baea59d5ff872d65ce9ba4f77eaf97306b97446442d5584369453b0f`.
That helper checks its own pinned helpers and complete 24-file upstream
snapshot, recomputes the live transcript and all Merkle openings, and checks the
whole input identity. A previously saved JSON report is not an accepted CLI
input. The algebra captures the actual opened words and challenge values from
this new execution, preserving their raw ranges and hashes.

The new [source supplement and provenance](../../evidence/pon-w1-fri-algebra-20261108/README.md)
add two complete upstream files as data:

| Source | Bytes | SHA-256 | Purpose |
|---|---:|---|---|
| [Recursion `poly_ext.rs`](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/circuit/recursion/src/poly_ext.rs) | 922,857 | `176f99041c0d3867ecd100b7292adbeb29294a0abe7a8f1f0a05807278da43b3` | Complete generated numerical constraint program |
| [`core/ntt.rs`](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/core/ntt.rs) | 14,765 | `5e363e48f97bbeb17642fa1829e56488747921cf5923c010ef533d2130b2cb1f` | Exact interpolation, normalization and bit-order convention |

Both were fetched at the exact VCS commit through the GitHub connector; their
Git blob identities and full content hashes are retained. The generated AIR
hash also matches the member hash in the earlier checksum-verified
`risc0-circuit-recursion-4.0.5` archive observation. That is an explicit
comparison with a historical observation, not a new archive download or a new
Cargo build. Apache-2.0 source notices and the repository's retained upstream
license remain attached to this source material. No upstream source is executed.

The existing snapshot supplies the exact
[field implementation](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/core/src/field/baby_bear.rs),
[tap table](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/circuit/recursion/src/taps.rs),
[constraint executor](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/adapter.rs),
[DEEP and validity verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/mod.rs),
and [FRI verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/fri.rs).

## 2. What was actually computed

| Check | Actual fixed-input coverage |
|---|---:|
| Fresh transcript replay | 69 ordered events; 244 base-field draws |
| Fresh Merkle opening checks | All 350 openings |
| Generated mixed AIR program | All 12,359 operations, 11,130 field registers and 1,229 mix registers |
| Tap interpolation values | All 643 taps, grouped into 163 registers |
| AIR validity equality | One actual mixed-constraint/check-polynomial equality |
| DEEP inputs | All 50 query points, all four opened row groups and all five tap combos |
| DEEP denominator checks | 1,050 nonzero factors, 300 nonzero divisor inversions |
| FRI incoming-value equalities | All 150 comparisons: 50 queries across three rounds |
| FRI interpolation | All 150 inverse transforms and subsequent evaluations |
| Final polynomial | All 64 extension coefficients; all 50 terminal equalities |

The 50 DEEP-to-first-FRI comparisons are **included** in the 150 incoming-value
equalities; they are not an additional 50 independent comparisons. There are
201 compared algebraic equalities in this replay: one AIR equality, 150 FRI
incoming-value equalities and 50 terminal equalities. Repeated later-round
positions remain repeated observations, rather than independent experiments.

The mixed AIR result and the separately reconstructed check expression both
equal, in normal extension coordinates:

```text
(890055781, 1976276683, 312542502, 1945752035)
```

Query zero begins at position `777360`. Its DEEP result is
`(1295369850, 707014057, 1267614, 1981086267)` and its final value is
`(1380940943, 1121887964, 585620636, 205243834)`. An independent numerical
review reproduced those values using an ungrouped per-register DEEP sum.
These deterministic values are checks on representation and equations, not
samples from an asserted random-oracle distribution.

## 3. Deterministic arithmetic correspondence

### 3.1 Field words and extension coordinates

Let `p=2013265921` and `R=2^32 mod p`. A canonical raw seal word `a` represents
the normal field value `a*R^-1 mod p`. All words are range-checked before that
conversion. Extension elements are polynomials in `T` modulo `T^4+11`.
Multiplication uses ordinary polynomial convolution followed by `T^4=-11`;
the regression suite independently checks a polynomial long-reduction form.

There are three different layouts to preserve. The U vector consists of
successive four-word extension elements. A FRI leaf contains 16 extension
elements in coordinate-major order, so element `i` has coordinates at
`j*16+i`. The terminal polynomial also uses coordinate-major order, with
coefficient `i` at `j*64+i`. Treating these layouts as interchangeable is
rejected by separate fault-injection controls.

The 28 forward and reverse root entries are read from the pinned field source
as normal values. Each is checked for its exact power-of-two order, the
nested-square relation and the forward/reverse inverse relation.

### 3.2 Numerical generated AIR

The interpreter has separate field and mix register banks, rejects unknown
opcodes and nonliteral arguments, and rejects forward, wrong-bank and
out-of-range references. Constants follow `from_u64` reduction. Each
`Get` uses a computed tap evaluation; `GetGlobal` uses the captured public
outputs or accumulation challenges. The two mixing rules are:

```text
AndEqz(chain, value):
  total = chain.total + chain.multiplier * value
  multiplier = chain.multiplier * constraint_mix

AndCond(chain, condition, inner):
  total = chain.total + condition * inner.total * chain.multiplier
  multiplier = chain.multiplier * inner.multiplier
```

For the permitted opcodes, induction in program order gives the same numerical
register values as the pinned `PolyExtExecutor`: the constant/read cases fix
the inputs and each arithmetic/mixing step applies the same field operation to
previously matched values. This deterministic correspondence does not establish
that the generated constraints encode the intended VM semantics.

The check side uses the exact quotient remapping `(0,2,1,3)`, the four
extension basis vectors and the zerofier `(3z)^(2^18)-1`. It is compared to
the returned mixed-constraint total; neither side is taken from an expected
fixture constant. The earlier degree bound alone did not perform this check.

### 3.3 DEEP batching and the first FRI equality

For register `r`, let `U_r(X)` be its sequential U coefficients, `C(r)` its
tap-combo set, `v_r(x)` its opened row value and `m^r` its batching weight.
The exponent advances once per **register**, not once per tap. With
`b=ROU_REV[18]`, the tap contribution is

\[
\sum_r m^r\frac{v_r(x)-U_r(x)}{\prod_{a\in C(r)}(x-zb^a)}.
\]

Registers with the same combo share a denominator. Distributivity groups the
numerator into the `combo_u` expression in the implementation. The 16 check
columns continue the batching powers after the 163 registers and contribute
through the additional denominator `x-z^4`. This is an algebraic grouping
identity for nonzero denominators; it does not assert uniform distribution of
`z` or a bound on the probability of a denominator event.

The actual `x` is `ROU_FWD[20]^index`. Every one of the 50 resulting DEEP values
is compared to the selected entry in the first FRI leaf. The first-round goal
is never initialized by simply trusting that selected entry.

### 3.4 Radix-16 interpolation and terminal verification

In a round with next-domain size `D`, write incoming position `p=Dq+g`,
where `q=p//D`, `g=p%D`. Let `d_0,...,d_15` be the opened extension
values and `w=ROU_FWD[4]`. The selected entry `d_q` must equal the incoming
goal. Natural-order interpolation coefficients are

\[
a_i=16^{-1}\sum_{j=0}^{15}d_j w^{-ij}.
\]

The pinned reverse butterfly computes the same inverse Fourier sums in
bit-reversed coefficient positions and then normalizes by `16^-1`.
The verifier's following `bit_reverse` restores the natural order above.
The replay deliberately computes the direct sums; a second regression
implementation uses the recursive reverse butterflies and bit reversal.
They agree on every basis position and on a nontrivial extension vector.

The outgoing goal is the polynomial with coefficients `a_i` evaluated at
`round_mix * ROU_REV[log2(16D)]^g`. The next position is `g`. The actual
three next-domain sizes are `2^16`, `2^12` and `2^8`; degree decreases from
`2^18` to `2^14`, `2^10` and finally `64`. The terminal evaluation therefore
uses the 64 supplied extension coefficients at `ROU_FWD[8]^g`. There is no
additional coset factor of three in these FRI evaluation points.

## 4. Validation and boundaries

The [regression suite](../../scripts/ci/test_w1_fri_algebra_replay.py) checks
independent field/transform identities and then changes captured values at
each algebra boundary. It rejects altered public outputs, U coefficients,
constraint/DEEP/batching challenges, each opened DEEP row group, selected and
unselected FRI components, every folding challenge, terminal coefficients,
wrong coordinate layouts and altered query positions. Source mutation,
symlinked helpers, stale capture identities and malformed generated programs
are rejected separately.

These controls isolate algebra errors **after** a correct cryptographic replay.
Their inputs are deliberately altered in memory without recomputing Merkle
commitments. A rejection in this fault-injection experiment is not evidence of
an accepted malformed receipt or an attack on W1.

The complete successful fixture has nonzero DEEP denominators. The upstream
base and extension implementations define inverse-of-zero as zero; this audit
instead refuses that case. That difference is explicit and prevents an
accepted-language-equivalence claim. A proof about all accepted transcripts
still needs to handle denominator events, every permitted statement/size and
the actual oracle/challenge distribution.

The outer receipt suffix, claim, journal, assumptions and their application
authorization are bound by the full input hash but are not semantically
interpreted here. No native Rust verifier, guest compiler, prover or production
node is run by this Python replay. A complete soundness or post-quantum claim
still requires the semantics, RRBR, quantum restoration, commitment, shared
primitive, Fiat-Shamir, recursion and lifetime arguments in the existing plan.

Reproduce without network access or a Rust build:

```sh
python scripts/w1_fri_algebra_replay.py --output /tmp/w1-fri-algebra-new.json
python -m unittest scripts.ci.test_w1_fri_algebra_replay -v
```

The output path must not already exist. The new report records the generator,
helper, input and source hashes, all per-query numerical values and explicit
qualification fields. A successful fixed-input replay does not alter any
production admission rule or historical HOLD decision.
