# A restricted FRI leaf lemma and exact lifecycle accounting

This successor proves a narrow classical ideal-permutation sublemma, and exact
counting statements about the pinned implementation. It does **not** prove
complete W1 noninteractive security or PQ128. The executable consequently keeps
actual W1 noninteractive, lifetime and quantum security fields `null`.

## 1. The actual four-element leaf

The fixed research profile uses a quadratic extension of Goldilocks, binary FRI
folding, `ExtensionMmcs`, and `PaddingFreeSponge<Perm,8,4,4>`. A binary FRI row
contains two extension elements. Flattening their two basis coefficients gives
four canonical base-field elements. The padding-free sponge absorbs those four
elements into a zero-initialized eight-element state, permutes once, and returns
the first four elements. Hence this exact leaf function is

\[
H_4(m)=\operatorname{left}_4\Pi(m\,\|\,0^4),\qquad m\in\mathbb F_p^4.
\]

Here `p = 18446744069414584321`. This identification is an implementation fact;
it makes no cryptographic claim about the fixed Poseidon2 permutation. Relevant
primary source locations are `p3-fri/src/prover.rs`,
`p3-commit/src/adapters/extension_mmcs.rs` and `p3-symmetric/src/sponge.rs`, all
at Cargo.lock-pinned version 0.8.0. The source contract records their full hashes.

This domain restriction is essential. The raw branch function accepts all
eight input elements, while the four-element leaf accepts only states whose
last four elements are zero. R3's two inverse-query collision for the raw
compressor therefore is not automatically a collision for this leaf. Nor does
this lemma establish security for a Merkle opening.

## 2. Explicit classical game

Let `X` be a finite set of cardinality `N >= 2` with a distinguished zero, and
sample a uniformly random permutation `Pi` on `X × X`. For this implementation
`X = F_p^4` and `N = p^4`. Define `S = {(m,0): m in X}` and
`H(m) = left(Pi(m,0))`.

A classical adversary adaptively queries both `Pi` and its inverse. All queries
to the same permutation count against a common lifetime budget `Q`, including
queries from other roles, components, protocol versions, honest subroutines,
precomputation and offline work included in the experiment. Repeated calls may
be counted again; this only makes the upper bound more conservative. After at
most `Q` calls, the adversary returns two **different** messages `m0,m1` in `X`.
The game checks whether `H(m0)=H(m1)`. These checks require at most two further
forward queries, so put `T=Q+2`.

The model does not grant a free description of a sampled ideal permutation.
Access to the actual, explicitly specified Poseidon2 algorithm is a separate
instantiation issue. In particular, no fixed-permutation security conclusion is
obtained merely by counting the algorithm's evaluations.

### Lemma

For `T <= N²`,

\[
\Pr[H(m_0)=H(m_1),\;m_0\ne m_1]
\le
\min\left(1,\frac{N T(T-1)}{2(N^2-T+1)}\right).
\]

For larger `T` use the trivial bound `1`. The lemma allows adaptive forward and
inverse queries and does not require independence among events or roles. It
does not apply to quantum oracle queries.

### Proof

Expose a consistent permutation table lazily. Repeated queries reveal no new
pair, so there are at most `T` fresh input/output pairs. Call an exposure bad if
it creates two distinct already exposed inputs in `S` with the same left output.
The first exposure cannot be bad.

At fresh exposure `j`, condition on its entire classical history and on no
earlier bad exposure. There are at most `j-1` exposed inputs in `S`.

For a forward query, its fresh output is uniform among `N²-j+1` unused outputs.
If the chosen input is outside `S`, this exposure cannot be bad. Otherwise the
outputs whose left half matches any earlier `S` output number at most
`(j-1)N`. Removing used outputs can only reduce this numerator. Its conditional
bad probability is therefore at most `(j-1)N/(N²-j+1)`.

For an inverse query, the adversary chooses an unused output and its preimage
is uniform among `N²-j+1` unused inputs. If that output's left half matches no
earlier `S` output, this exposure cannot be bad. If it does match, the preimage
must still land in `S` for a bad exposure, and there are at most `N` such inputs.
For `j >= 2`, `N <= (j-1)N`, giving the same upper bound. Thus inverse access is
charged explicitly; it is not silently removed from the experiment.

If the returned distinct messages collide, after the final two checks both
corresponding inputs in `S` occur in the table, so some exposure was bad. Sum
the conditional bounds over all possible exposures, including a stopped run's
unused opportunities with probability zero:

\[
\Pr[\mathrm{bad}]
\le\sum_{j=2}^{T}\frac{(j-1)N}{N^2-j+1}
\le\frac{N}{N^2-T+1}\sum_{j=2}^{T}(j-1).
\]

The sum is `T(T-1)/2`. Capping by one gives the lemma. This is an ordinary
conditional union argument, not an independence argument.

### Boundary checks and falsifying controls

With `Q=0`, two fixed different messages have exact collision probability
`(N-1)/(N²-1)=1/(N+1)`. The lemma gives `N/(N²-1)`, which is a valid slightly
larger bound. At `T=N²`, and beyond it, the returned result is the trivial one.
All computations use exact integer/rational arithmetic; displayed logarithms
are not used for decisions.

The tests enumerate all 24 permutations on `X×X` for `|X|=2`. Querying inverse
at two outputs with equal left half always produces a raw compression collision,
but both resulting inputs lie in `S` in only four of the 24 cases. This test
separates the two games; it is not empirical evidence for the asymptotic proof.
An additional negative control demonstrates that applying the restricted bound
to unrestricted branch compression would contradict its probability-one attack.

## 3. What remains outside this lemma

The bound does not cover variable or longer leaf inputs, all W1 input-commitment
leaves, raw branch collision resistance, authenticated paths, pruned multiproofs,
mixed-height tree geometry, position binding, vector extraction, or PCS
soundness. It does not extract a tree from an arbitrary branch preimage. It does
not establish that a malformed W1 statement can be proved, nor that one cannot.
The current shared leaf/branch/challenger permutation must still be analyzed
in the complete extraction game. The concrete Poseidon2 instantiation and the
quantum analogue also remain unproved here.

## 4. Exact transcript accounting

For the pinned P3 challenger, an observed base-field element discards pending
outputs and enters the input buffer. Filling four input slots permutes. Sampling
permutes exactly when input remains buffered or the output buffer is empty,
then removes one of four outputs. Consequently the number of calls is an exact
function of the observed absorb/squeeze lengths, independent of their values.

`lifecycle_probe.rs` wraps the actual native permutation with scalar-equivalent
counters and wraps the actual challenger with a diagnostic event log. It also
runs the original configuration on the same immutable proof. The independent
Python replay uses only the event lengths. It checks native/replayed counts,
the two extension coefficients of alpha/zeta/batching and every FRI beta,
exactly 64 index samples, and the fixed zero-grinding inventory. Exhaustive
short operation sequences test rate boundaries, discarded outputs and empty
operations. A fresh configuration and a reused configuration are budgeted
separately; identical replayed challenges do not become fresh entropy.

These receipts describe exact retained proofs. They are not a universal maximum
for arbitrary valid or malformed proofs. They count Poseidon2 evaluations,
including repeated inputs and SIMD padding, and do not count all CPU operations
or other hash functions. P3 also hashes fixed transcript patterns and algebra
identities with Keccak-256; that separate mechanism is not measured by these
Poseidon2 counters. For the fixed profile these patterns are selected by the
verifier, not from an attacker-supplied arbitrary protocol description.

## 5. Lifetime composition and conditional RBR

The common permutation query budget is the **sum** of calls from every role and
epoch, plus declared unmeasured honest and adversarial forward/inverse calls.
A new application tag or component number does not resample the permutation.
If a theorem contains a quadratic term, it must receive that combined query
count; squaring each role separately drops cross terms. The checker reports the
arithmetic difference but never calls it a valid raw-compressor collision bound.

Separately, suppose every bad-event opportunity, conditional on the entire
preceding history with no earlier bad event, has hazard at most `epsilon_i`,
and at most `q_i` opportunities of each class occur almost surely. Then
`Pr[any bad] <= min(1, sum_i q_i epsilon_i)`. The same conditional-indicator
argument proves this even for adaptive choices and stopping. A marginal error
estimate is insufficient: after learning a uniform value `Z`, an adversary can
choose the event `Z=i` with `i=Z`, obtaining probability one though every fixed
event has marginal probability `1/|Z|`.

The executable labels this as an **abstract adaptive game**. It does not claim
that the P3 63.95384529640614-bit conditional RBR estimator has been mapped to
these hazards or to a complete Fiat–Shamir compiler. Counts of received proofs
do not bound an adversary's offline challenges. No assumption checkbox, domain
tag, or supplied hash-bit value can enable a W1 NI/PQ result in this checker.
