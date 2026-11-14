# Exact affine construction and restricted cache-policy lower bounds

## Status and evidence boundary

These are local theorems with explicit domains. The algebraic identity is unconditional over the declared field. The strategy values are exact in the auxiliary stochastic resource model defined below. Neither establishes a minimum physical cost among all legal implementations of the selected-event protocol.

The protocol, source, task bytes and accepted witness are frozen in `UPSTREAM_SOURCE.json`. The snapshot is PR783's recovered selected-composition research edition. The original classical full-message-ROM theorem and its collision/backward-reference terms remain in `upstream/THEOREM.md`; they are not replaced or silently specialized by the iid model here. In particular, the latter has independent selector draws and Bernoulli tickets as hypotheses, not as a proof about concrete SHA-256.

## 1. Certified affine product compiler

Let q=4294967291, r,t,c in {0,...,7}, and

\[
 A_{rt}=a_0+a_r r+a_c t,\qquad B_{tc}=b_0+b_r t+b_c c
\]

in F_q. Define S0=8, S1=28 and S2=140, the sums of 1,t,t² on this range. Expansion of the exact matrix product gives

\[
 U_{rc}=(a_0+a_r r)(8b_0+28b_r+8b_c c)
             +a_c(28b_0+140b_r+28b_c c).
\]

For each A block compile T0=8a0+28ac, T1=28a0+140ac and R8=8ar, retaining (T0,T1,ar,R8). For each B compile Z0=8b0+28br, retaining (b0,br,bc,Z0). For one selected pair form

\[
 x=T0\,b0+T1\,br,\quad r_\Delta=ar\,Z0,\quad
 c_\Delta=bc\,T0,\quad m_\Delta=R8\,bc.
\]

Then U_rc=x+r rΔ+c cΔ+rc mΔ. The implementation synthesizes each row using seven column increments; between rows it increments the first value by rΔ and the column increment by mΔ. This is exactly 5 field multiplications and 1+8·7+7+7=71 additions per product. It neither rounds nor compares approximate ranks.

The generic recognizer reads origin=b00, row slope=b10−b00 and column slope=b01−b00, regenerates all64 entries with63 additions, and checks all64 equalities. It performs two additional subtractions. A block is accepted iff every equality holds. Canonical field encoding and exact block length are checked by the unchanged reference `words`. Therefore accepting a malformed block cannot cause the optimizer to substitute a different product. Invalid inputs are refused rather than silently approximated.

For64 A and64 B blocks, recognition costs128·65=8320 additions/subtractions and8192 equalities. A compilation uses5M+2A per block; B uses2M+1A. Total setup is448M+8512A and8192 equalities. Four field words per block occupy2048 bytes at four bytes per word. This counts logical field payload; language/container/allocator overhead is outside that representation count.

Every source block in the pinned nonzero fixture satisfies this identity. Its Rust generator sets A block i, flattened position j, to17i+13j and B to11i+7j. Thus ar=104,ac=13 and br=56,bc=7, while origins differ by block. No blocks or target were replaced. The executable test checks all512 possible coordinate products against the original dense operation, plus general affine samples with field wraparound and exact rejection cases.

This construction is an achieved arithmetic upper bound. The verifier still recomputes the original relation. The noisy products in the producer retain the original three dense8×8 multiplications, with1536M+1472A per nonce. Affine direct thus uses1541M+1543A per nonce plus the charged setup. It does not prove either1541 or5 is a lower bound; constants, alternative representations and larger algorithm classes may lower it further.

## 2. Pathwise lazy cache accounting

Fix one immutable pair of task matrices and any coordinate sequence i1,...,im; no probability assumption is needed. A full-capacity lazy dictionary calculates U_i only on its first visit and retains it. Its useful-product count is

\[
 d(i_1,...,i_m)=|\{i_1,...,i_m\}|.
\]

This follows by induction: an old coordinate causes one lookup and zero products; a new coordinate adds exactly one product and entry. All nonce-specific noise, event and ticket work remains unchanged. Thus dense useful work is512d multiplications and448d additions, versus512m/448m for direct and512·512/448·512 for an eager full table. Every observed miss is charged; a bounded no-eviction cache must recalculate an uncached coordinate even if it was seen previously, which the capacity16 experiment records explicitly.

On a fixed finite request sequence, full lazy uses no more useful arithmetic or peak result entries than eager, assuming the same entry/lookup representation and nonnegative preparation/insertion prices. This is not a latency dominance claim: eager moves expensive work before the first request, and different memory implementations can differ substantially. The original two-algorithm512-nonce break-even remains valid; it was never a lower bound over all legal cache schedules.

For m iid uniform draws from D coordinates, indicator linearity yields

\[
 \mathbb E[d_m]=D(1-(1-1/D)^m).
\]

No independence of occupancy indicators is required. If a separate independent Bernoulli(p) outcome is tested after every draw until the first success, then, for a fixed coordinate, its first visit occurs before termination with probability

\[
 \frac{1/D}{1-(1-1/D)(1-p)}=\frac1{1+(D-1)p}.
\]

Consequently E[d_N]=D/[1+(D−1)p]. For D512,p1/64 this is32768/575. This formula concerns always-attempt, unlimited auxiliary sampling and full lazy storage. It is not the optimum when skipping is permitted, nor a statement that a concrete64-bit nonce space contains a successful candidate.

## 3. Exact no-cache selector filtering

Suppose each independent selector draw costs g>0 and yields a uniform index i in {1,...,D}. Attempting index i costs c_i≥0 and succeeds independently with probability p>0; skipping returns to the identical state. Choices precede the ticket answer. Among all adaptive or randomized policies with finite expected cost until success, the optimum V satisfies

\[
 V=g+\frac1D\sum_i\min\{V,c_i+(1-p)V\},
 \qquad Dg=\sum_i(pV-c_i)_+.
\]

The right-hand side of the second equation is continuous, nondecreasing and strictly increasing after its first nonzero point, with range[0,∞). It has one solution. An optimal policy attempts exactly the coordinates with c_i≤pV; ties have equal value. For a nonempty accepted subset S its value is

\[
 V(S)=\frac{Dg+\sum_{i\in S}c_i}{p|S|}.
\]

Sorting c_i and enumerating its D nonempty prefixes therefore obtains the optimum. This includes paid skips and all losing attempts. The Bellman verification argument in section4 extends to history-dependent policies; randomization cannot improve the minimum of these affine conditional action values. Tests separately enumerate every nonempty subset for small cost lists.

## 4. Closed bounded-cache policy class

Fix integers1≤D≤4096 and0≤B≤D, p in(0,1], g>0, and c,u,l,s≥0. At an unfinished state k, a cache contains k distinct equal-cost useful products,0≤k≤B. A fresh iid uniform selector costs g+l, including lookup. Conditional on the selected coordinate:

- A cached coordinate permits skip, or attempt at cost c.
- A missing coordinate permits skip, attempt at c+u without retention, or, when k<B, attempt at c+u+s while retaining the product.
- An attempt succeeds with a fresh independent Bernoulli(p) answer. Success terminates. Failure returns to k or, for store, k+1. Insertion is charged even if that attempt succeeds.

Allowed policies can use arbitrary history and private randomness in choosing these actions, before each current ticket answer. The model excludes external advice, free initial cache, proactive prefetch, compute-without-attempt, new arithmetic algorithms, cache eviction, batching and oracle shortcuts. These are deliberate action boundaries, not impossibility claims about the actual protocol. A fresh campaign's preparation must be added separately, and any preexisting cache requires its actual lifecycle provenance/cost.

By exchangeability and constant cost, conditional future law depends only on k. Let V_k be the optimal expected post-setup cost until success. At each k,

\[
\begin{aligned}
 V_k=g+l&+\frac{k}{D}\min\{V_k,c+(1-p)V_k\}\\
 &+\left(1-\frac{k}{D}\right)
 \min\{V_k,c+u+(1-p)V_k,c+u+s+(1-p)V_{k+1}\}.
\end{aligned}
\]

The store term is absent at k=B. Solve downward in k. For each of at most six action pairs, isolate the self-loop: V=a+bV with0≤b≤1 and known V_{k+1}. If b=1, this pair pays positive gate cost forever and cannot finish; discard it. All remaining values are a/(1−b). The smallest satisfies the minimum equation; the code verifies its exact rational residual independently.

**Verification theorem.** The resulting finite vector lower-bounds the expected cost of every allowed adaptive/randomized policy that has finite expected total cost, and a stationary policy attains it.

For any conditional history at state k, the Bellman minimum is at most the policy's conditional immediate expected charge plus its expected residual V after a failed step. Averaging randomized actions preserves this inequality. Iterate for n selector draws or earlier termination to obtain V_k≤E[C_{≤n}]+E[1_unfinished V_{K_n}]. All V are bounded on the finite state set. Since every unfinished draw costs at least g>0, finite expected total cost implies finite expected draw count, hence probability of still being unfinished tends to zero. The last residual vanishes, proving the lower bound. Policies with infinite expected cost do not improve it.

A minimizing stationary action pair cannot remain in a positive-cost self-loop with coefficient1. At each fixed k it has positive probability of success or progressing to k+1. There are at mostB−k upward transitions, and at B its proper action has positive success probability. It terminates with finite expected cost, so its Bellman equations hold with equality and it attains V. This proves the claim for all policies in this explicitly closed class, rather than merely comparing some benchmarks.

The auxiliary unbounded model permits as many fresh independent draws as required. Actual nonce exhaustion, sampler failure, collisions and SHA correlations are not hidden inside that assumption; section5 supplies a finite-cap version.

## 5. Finite-cap cost and success lower certificate

With at most n remaining selector draws, allow immediate stopping and assign failure penalty λ≥0. Define

\[
 V^\lambda_{n,k}=\min_\pi\{\mathbb E[C_\pi]+\lambda\Pr[\text{no success}]\},
 \qquad V^\lambda_{0,k}=\lambda.
\]

Replace the self-loop future values in section4 by V_(n−1,k), and the store future by V_(n−1,k+1); then take the minimum withλ for stopping before the next gate. Exact backward induction proves optimality over all finite history-dependent/randomized policies in the class. `finite_penalty` also propagates cost and failure probability separately under an attaining policy; its scalar objective is never mislabeled success probability or protocol qualification.

If a policy succeeds with probability at leastα, weak duality gives

\[
 \mathbb E[C_\pi]\ge V^\lambda_{n,0}-\lambda\Pr[\text{failure}]
 \ge V^\lambda_{n,0}-\lambda(1-\alpha).
\]

The maximum of this expression with0 is a valid expected-cost lower bound. Optimizingλ would strengthen it. We provide declaredλ certificates, not a claim to have found every chance-constrained optimum or to make an infeasibleα feasible. Add any mandatory preparation cost to both the objective and bound.

A separately checked sharp example uses D2,B0,p1/2,g1,c1,u0,n2,α3/4,λ4. Its certificate is3. Attempting, then trying again only after failure, costs2+(1/2)·2=3 and succeeds with probability3/4. Achieving3/4 requires these two opportunities, so the certificate is attained. General small-state finite tests search actual coordinate-cache subsets rather than reusing the aggregated k implementation.

## 6. Declared tariff and actual-hash boundary

The numerical policy example assigns price1 each to field multiplication and SHA compression and price0 to additions, lookup, insertion, memory and all other resources. Its constants g3,c1580,u512 map the observed J=32 path into a fixed-work auxiliary profile: steady prefix SHA cost47 comprises3 gate+44 continuation compressions, and the unchanged nonce-specific matrices use1536 multiplications, so c=44+1536. This mapping is illustrative; the policy model does not contain real rejection-sampler tails or assert concrete SHA independence.

Initial dense setup adds894 tree compressions+10 first-nonce fixed-prefix/context overhead=904. The exact optimum with B16 is113205.562426... after setup, with a reachable policy storing until k15 and then skipping misses. The no-cache value is134080. Full new-campaign totals are therefore114109.562426... and134984, respectively. All unsuccessful/skipped draws are paid by their conditional action equations.

The affine producer changes u to5 and adds448 setup multiplications. Its simple no-cache new-campaign value in the same illustrative tariff is(3+1580+5)/p+904+448=102984. This is already below the dense-cache class optimum, so that optimum cannot be a lower bound across these legal implementations. The result is consistent because the two classes fix different available useful-product operations. Positive prices for recognition, additions, copying or memory could change this ordering, and must not be set to zero when answering a physical-cost question.

Replaying SHA-256 compression states merely checks digest equality with the actual hash implementation. NIST FIPS180-4 defines the padding/compression operation; it does not certify independent full-message random-oracle behavior or the physical indispensability of every reference call. Upstream's finite classical composition theorem supplies its own explicit assumptions and bad-event terms. Quantum, PCS, Fiat–Shamir, production resource and Node-qualification claims remain outside this increment.

## 7. Evidence and references

All algebra and optimization proofs are included above and implemented locally. New test and run evidence is in `checks_summary.json`, `tests.log`, `run.log` and `results/`. The canonical source/cost framing is the hash-pinned upstream snapshot. `SOURCE_NOTES.md` records the primary external checks: Bellman's own publisher abstract for dynamic programming as a method, and NIST's official SHA-256 standard. Neither external citation is used to claim our restricted-policy theorem has already been peer reviewed or that a universal physical-cost problem has been solved.
