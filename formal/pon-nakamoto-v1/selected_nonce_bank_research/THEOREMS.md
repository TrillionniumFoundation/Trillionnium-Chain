# Deferred nonce strategies and a smaller exact input compiler

This successor starts from published commit `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`. It preserves the earlier physical frontier package and its restricted online-policy claims. The relation here is the original **selected local product8** relation, with the same SHA domains, expected context, target, Merkle roots, nonce format and complete witness bytes. It is not the cumulative W1 relation, a STARK, or production Node admission.

The results below have three distinct meanings: an algebraic identity for recognized real input bytes; an exact optimality theorem in an explicitly priced auxiliary model; and actual deterministic SHA executions. None is a universal physical-work lower bound.

## 1. A legal action missing from the old online class

The frozen reference accepts any unsigned 64-bit nonce whose seed selects the witness coordinate and whose complete witness verifies. It does not require increasing nonce submission order, an immediate continuation after computing a selector, or destruction of a selector when its nonce is not immediately attempted. `seed`, `selected_coordinates`, `produce`, and `verify` in the [frozen reference](upstream/reference/selected_event_reference.py) make this boundary explicit. Input eligibility before a challenge and live chain authority are outside that reference.

A producer can therefore buy a finite bank of seed/coordinate pairs, retain them, reorder by coordinate, and only then evaluate nonce-dependent noise and ticket candidates. Every purchased gate is charged, including the gates of nonces never attempted after a winner is found. The context and target remain unchanged. Reordering cannot choose a different coordinate for a given nonce.

The round-3 online class allowed a drawn selector to be skipped forever or attempted immediately, with optional retention of the resulting useful product. It did not retain unattempted nonce records. Its Bellman bounds remain correct for that class; they do not extend automatically to the bank action.

## 2. Optimal scheduling of an already purchased finite bank

### Model and quantifiers

Fix the complete selector bank before ticket queries. Coordinate `i` occurs `n_i` times. No distributional assumption on these fixed counts is needed. Each of the `M = sum_i n_i` distinct ticket candidates has a fresh, independent Bernoulli success indicator of parameter `0 < p < 1`, independent of all selector information and private coins. Write `q = 1-p`.

An attempt costs a common nonnegative continuation price `c`. Its coordinate's useful result must be available. Acquiring that result costs a nonnegative fixed price `u_i`; a resident result can be reused without reacquisition. There is capacity for at least one complete useful result, in addition to the already purchased nonce bank. This is an atomic, additive acquisition model: it does not represent shared intermediate arithmetic between distinct coordinates, circuits exploiting ticket predicates, fractional computation, free historical advice, energy, latency, or a concrete processor.

Admit all history-dependent and randomized schedules of these `M` candidates, arbitrary whole-result precomputation, retention, eviction, recomputation and ordering. An outcome is observable only after paying the required attempt/acquisition costs. Require the maximum possible success probability for this bank, `1-q^M`. Early stopping after the first success is permitted. The already paid gate and bank-construction costs must be added to the theorem's value.

**Theorem.** There is an optimal policy using only one useful-result slot. It visits each nonempty coordinate in one contiguous bucket. It orders buckets by nondecreasing

\[
\rho_i=\frac{u_i}{1-q^{n_i}}.
\]

If this order is `pi`, and `L_t` is the number of tickets in earlier buckets, the exact expected continuation-plus-acquisition cost is

\[
C_* = c\frac{1-q^M}{p}+\sum_t u_{\pi_t}q^{L_t}.
\]

With a common setup price `u`, descending bucket occupancy is optimal. More useful-result cache slots cannot improve this optimum in the stated model. Additional bank memory is not thereby free: it was explicitly fixed and prepaid.

### Proof

1. With strictly positive `p` and `q`, attaining `1-q^M` requires attempting all `M` distinct tickets on every all-failure path of positive probability. Leaving a ticket unattempted on such a path loses a positive success probability. A policy may stop after its first success without increasing cost.

2. Condition on the policy's private coins. Along the only nonterminal outcome history, all earlier attempted tickets failed. Thus the policy specifies an all-failure order of attempts and acquisitions. Randomization is a mixture of such schedules and cannot beat their minimum expected cost.

3. Delay each precomputed result until its first use and omit unused or redundant acquisitions. An acquisition formerly made before an earlier success may disappear. Delaying costs cannot raise expected expenditure, and no more storage is needed. If later eviction would require recomputation, the grouping transformation below avoids it.

4. For any attempt order, the expected common continuation cost is `c sum_{j=0}^{M-1} q^j`, independent of that order. Consider the first remaining coordinate in an order. Move all its remaining copies to immediately after its first copy. This leaves its first-acquisition position unchanged, moves every other coordinate's first acquisition weakly later, and eliminates its reacquisitions. Every moved acquisition has nonnegative price and a weakly smaller survival weight `q^j`. Repeat on the remaining suffix. The resulting contiguous-bucket order costs no more and needs one useful-result slot.

5. A bucket of size `n_i` has failure probability `q^{n_i}` and expected cost `C_i = u_i + c(1-q^{n_i})/p`, conditional on reaching it. Comparing adjacent orders `i,j` and `j,i`, the former is no worse precisely when `C_i(1-q^{n_j}) <= C_j(1-q^{n_i})`. Dividing and cancelling the common `c/p` gives `rho_i <= rho_j`. Pairwise exchanges produce the stated order and value.

The independent state search in [bank_policy.py](bank_policy.py) does not assume contiguous buckets: it enumerates the next coordinate, all interleavings, every retained cache subset and every eviction. The test matrix checks 243 combinations of occupancies, nonuniform/zero acquisition prices, and capacities 1, 2 and 3 against the formula. That is an executable check of finite instances; the preceding argument supplies the general proof.

This theorem is conditional on an already acquired finite bank. It does not optimize how many selectors to buy, sequentially extend the bank, choose nonce values, trade success probability against cost, mix different input compilers, or share preparation across contexts. These remain admissible directions for a wider work model.

## 3. Strict counterexample to enlarging the old online lower bound

Use two uniformly and independently selected coordinates, one useful-result slot, at most three selector draws, independent ticket probability `p=1/2`, gate price `g=1`, continuation price `c=1`, and useful-result acquisition price `u=100`. Require success probability at least `3/4`.

**Bank policy.** Buy three gates, choose a most frequent coordinate (tie rule fixed in advance), and attempt its first two nonce records. Pigeonhole guarantees at least two records in that bucket. Acquire its useful result once. Ticket attempts have expected count `1 + 1/2 = 3/2`, so

\[
P_{\rm bank}=3/4,\qquad E[C_{\rm bank}]=3+100+3/2=209/2=104.5.
\]

This construction's success calculation only needs independent tickets; the pigeonhole statement holds for every three-selector realization.

**Old online class.** For penalty `lambda=202`, the exact minimum of `E[C]+lambda Pr[failure]` is `1281/8`. This is computed both by the preserved round-3 solver and an independent coordinate-identity Bellman tree. Bellman induction bounds all history-dependent and randomized policies in that specified irrevocable class, including its stop/skip/attempt/store actions. Therefore any such policy attaining success at least `3/4` satisfies

\[
E[C]\ge1281/8-202(1/4)=877/8=109.625.
\]

The gap is `41/8 = 5.125` with all prices strictly positive. All eight selector sequences and all four relevant two-ticket outcome sequences are also enumerated explicitly in the tests. The counterexample is finite, includes every paid gate and failure, and needs neither an infinite eventual-success assumption nor a physical pricing assertion.

This refutes a proposed **extension** of the old online-class bound to deferred nonce banks. It does not refute the carefully scoped round-3 theorem, prove the bank policy globally optimal for a success constraint, or establish an actual SHA probability law.

## 4. Global four-index structure of the original real inputs

Let each index range over `0..7`, and compute in `F_q`, `q=4294967291`. The new compiler accepts exactly matrices of the form

\[
A_{i,k,r,t}=a_0+a_I i+a_K k+a_R r+a_T t,
\]

\[
B_{k,j,t,c}=b_0+b_K k+b_J j+b_T t+b_C c.
\]

It reads and range-checks all 8,192 field words, derives the ten coefficients from fixed positions, then checks every value. There is no sampled recognition, approximation or fallback. A one-word corruption or a modification preserving each block's affine form but breaking the global structure is refused.

The exact original input bytes have coefficients

| Input | Origin | First block index | Second block index | Local row | Local column |
|---|---:|---:|---:|---:|---:|
| A | 0 | 136 | 17 | 104 | 13 |
| B | 0 | 88 | 11 | 56 | 7 |

These are nonzero structured matrices, not substituted zero-work fixtures. As full 64-by-64 matrices each has rank at most two, since every entry is a sum of one row function and one column function. Their first local 2-by-2 minors have determinants `-1352` and `-392`, nonzero modulo `q`, so these particular matrices have rank exactly two. This input structure is not imposed on arbitrary lawful task inputs by the reference relation.

### Identity and compilation

For fixed selected coordinate `(i,k,j)`, put `x=a_0+a_I i+a_K k+a_R r` and `y=b_0+b_K k+b_J j+b_C c`. Summing over the contraction index `t` gives the exact useful product

\[
U_{r,c}=8xy+28(b_Tx+a_Ty)+140a_Tb_T.
\]

The initial cell at `(r,c)=(0,0)` is a quadratic function of `(i,k,j)`. Write it as

\[
U_{0,0}=Z(k)+I(i,k)+J(j,k)+IJ(i,j).
\]

The compiler stores the eight values of the quadratic `Z` using its first and second finite differences, and three 8-by-8 tables for the other terms. It also stores one 8-by-8 row-step table, one 8-by-8 column-step table, and the constant mixed row/column increment `8 a_R b_C`. The explicit coefficients and recurrences are executable in [research_core.py](research_core.py).

This is `8 + 5*64 + 1 = 329` field words, or **1,316 bytes** of retained field payload. Source matrices, Merkle trees, interpreter objects, nonce-bank storage and transient compilation workspace are additional and are reported separately.

Recognition performs 8,192 field equalities and 8,198 additions/subtractions. Coefficient construction costs 26 multiplications and seven additions. Filling the retained tables costs 328 additions. The complete recognized-input setup is therefore **26 M + 8,533 A + 8,192 equality checks**, plus canonical field/range and shape checks. It is paid even if the first attempted nonce succeeds.

For an acquired product, three additions assemble `U_00` from four table values. The eight rows are generated by 56 within-row additions, seven row-start increments and seven column-step increments. The achieved product cost is **0 M + 73 A**, with seven compiled-field reads, and no retained cache of complete products is required for this formula.

The round-3 per-block compiler accepted a wider family and used `448 M + 8,512 A` setup, 2,048 bytes, and `5 M + 71 A` per product. For the recognized global family, this new representation saves `422+5K` field multiplications and 732 retained field bytes for `K` acquisitions, while adding `21+2K` field additions. These are exact achieved counts, not optimal arithmetic or physical bounds. The unchanged noisy part still uses three dense 8-by-8 contractions and two additions per attempt: `1536 M + 1472 A` in this schedule.

The tests compare every one of the 512 coordinate products against dense multiplication on the original inputs, a nontrivial wrapping coefficient family, zero input and constant input. The compiled family is strictly narrower than arbitrary per-block affine matrices. Its reduced representation cannot be assumed for unrecognized input.

## 5. Real SHA observations and where the theorems stop

[EXPERIMENT_PLAN.json](EXPERIMENT_PLAN.json) fixes the unchanged original context/input bytes, nonce interval `[512,1024)`, occupancy order, lexicographic ties, within-bucket nonce order and first-success stop rule. It was written before evaluating tickets in that interval. Each bank is serialized and its order sealed before its first continuation. The bank ordering function receives only nonce, seed and coordinate fields.

The actual execution performs no Bernoulli sampling. It evaluates the original SHA-256 messages and compares all 164 attempted strategy witnesses with the complete frozen original producer bytes. The independently billed full-range audit finds 13 actual hits. Fresh frozen native verification checks all 13 distinct accepted witnesses and each of the five strategy winners; its exact output is retained separately.

For the observed one-digest sampler rows, the executable bounded-prefix SHA schedule has whole-campaign compression count `904 + 3G + 44T`, where `G` is the total number of paid gates and `T` the number of continued candidates. The 904 includes task-tree and first-use prefix/context work. Every replayed digest is compared to `hashlib`. This formula is not substituted for sampler tails: actual `noise-eight` call counts are retained, and the source retains the original bounded rejection sampler. SHA-256 block/padding semantics are from [NIST FIPS 180-4, sections 5.1.1, 5.2.1 and 6.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

The live Python producer uses ordinary `hashlib` calls with an operation recorder. Its whole-message compression counts are **7,878 for the bank** and **5,946 for the sequential run**. The separately executed prefix-reuse schedule uses **2,748** and **3,254**, respectively. Prefix-replay counts must not be relabeled as the measured Python producer's implementation or timing.

Gate-bank storage, sorting, lookups, evictions, input recognition, setup, losing attempts and unattempted paid selectors are explicit. Field-operation and compression counts are vectors, not a common physical currency. CPython reachable-object sizes and instrumented phase times are observations; they omit neither a known native backend claim nor invent a universal resource conversion. There is no claim about all legal algorithms, favorable hardware, energy, useful demand, adversarially chosen inputs, all nonce schedules or production service.

The substantive consequence is narrower and concrete: a legal deferred-nonce policy invalidates extending the old online-policy lower certificate, and the original lawful input admits a smaller, cheaper exact useful-product representation than the round-3 compiler. A universal cheapest-lawful-work bound must account for both, as well as strategies beyond this successor's scoped models.
