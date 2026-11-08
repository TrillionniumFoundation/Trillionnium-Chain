# Actual selected-event hash composition: reconstructed classical-ROM derivation

**Recovery status, 2026-11-07.** The former round-2 local directory was lost. This document and its companion modules were reconstructed from retained conversation content. The original selected-event Python/Rust sources and the retained native fixtures were recovered from the saved round-1 bundle; their bytes are pinned in `provenance.json`. This is a newly hashed document. Historical round-2 hashes, test logs and review status are not represented as fresh evidence about this file. See `RECOVERY.md` and the newly executed `checks_summary.json`.

## 1. Claim and scope

The object is the existing selected-event v1 relation, including its actual framed domains, Merkle paths, context commitment, nonce seed, selector, noise sampler and the two layers

\[
H_{\rm ticket}\bigl(H_{\rm event}(\text{canonical event values})\bigr).
\]

The theorem idealizes **each complete SHA-256 message evaluation** as a query to a classical 256-bit random oracle. It does not prove that concrete SHA-256 has this behavior. It is not a STARK theorem, a QROM theorem, a consensus/authorization theorem or a universal physical minimum-work theorem.

Let q=4294967291, n=8 and

\[
\beta=1-(1-q^{-8})^4,\quad
K=\min\{M,\lfloor H/32\rfloor\},\quad
\delta=32MR\beta.
\]

Let all admissible targets have conditional success probability at most p before their ticket responses. For a fixed inclusive target T, `p=(T+1)/2^256`. Under the experiment and deterministic lifetime caps in §3, if W counts distinct accepted canonical events, then

\[
\boxed{\Pr[W\ge t]\le
\Pr[\operatorname{Bin}(K,p)\ge t]+\delta+\varepsilon_{\rm hash}.}
\]

Cap the right side at one. For one hit,

\[
\Pr[W\ge1]\le1-(1-p)^K+\delta+\varepsilon_{\rm hash}
\le Kp+\delta+\varepsilon_{\rm hash}.
\]

Write q_m=q_leaf+q_node and let Q be the total lifetime cap on distinct full-message oracle inputs, including inputs outside the protocol grammar. One conservative explicit composition bound is

\[
\begin{aligned}
2^{256}\varepsilon_{\rm hash}={}&\binom Q2
+q_m(2q_{\rm node}+2q_{\rm task})
+q_{\rm task}q_{\rm context}\\
&+q_{\rm context}(q_{\rm seed}+q_{\rm event})
+q_{\rm seed}(q_{\rm selector}+q_{\rm noise})
+q_{\rm event}q_{\rm ticket}.
\end{aligned}
\]

The bound may exceed one for enormous caps and then becomes vacuous. It intentionally includes harmless collisions. A simpler bound is `epsilon_hash < 5 Q^2 / 2^257`. `composition_budget.py` evaluates the displayed expression and exact binomial probabilities using rational arithmetic; the executable exact-tail implementation restricts K to at most 10,000 to control integer growth.

## 2. Pinned protocol and exact encodings

Recovered source pins, verified again in the fresh local checks:

| Source copy | SHA-256 |
|---|---|
| `reference/selected_event_reference.py` | `39575219c2adf0cf73bc58f58acf8ede934d073cbb0a02fc552d9dd4f5963357` |
| `reference/native_lib.rs` | `4cf25237ed76dcd9bc0a10f4d4e3875f1ed2d6af32a7af1dbae83ee64f840f07` |
| `reference/native_main.rs` | `3f14876f7f706149823fd686d868c9919e4ed571365a466fa6357c6fc6561431` |

The bytes hashed are

\[
\operatorname{enc}(t;p_1,\ldots,p_k)=
D\parallel\operatorname{u8}(|t|)\parallel t\parallel
\mathop{\|}_{i=1}^k(\operatorname{u32le}(|p_i|)\parallel p_i).
\]

The 36-byte D is `b'TRNM-PON-SELECTED-EVENT-RESEARCH-R1\x00'`. The 46-byte profile is `b'local-product8-fq4294967291-n64-r8-selected-v1'`. The tag has fewer than 256 bytes, and each part fewer than 2^32 bytes. The tag length and all subsequent part lengths make the encoding injective. Parsing proceeds to the end of the message. A final empty part differs from no part. There is no ambiguous concatenation of variable-length values. The ROM consequently gives independent entries to distinct tag/part tuples.

| Tag | Ordered parts | Input bytes | Ordinary SHA compressions |
|---|---|---:|---:|
| leaf | profile, A/B label, leaf index u8, 64 field words u32le | 361 | 6 |
| node | profile, label, level u8, left digest, right digest | 173 | 3 |
| task | profile, root A, root B | 163 | 3 |
| context | profile, chain, parent, header without work, task digest, target | 274 | 5 |
| noise-seed | context digest, nonce u64le | 95 | 2 |
| selected-coordinate | seed | 92 | 2 |
| noise-eight | seed, two bytes (label,index), counter u32le | 98 | 2 |
| event | context digest, nonce u64le, 3 coordinate bytes, noisy block, useful block | 617 | 10 |
| ticket | event digest | 79 | 2 |

Each block has 64 canonical field words, each in `[0,q)`. Merkle leaves include side label and index 0–63; six binary levels include label and level 0–5. The task binds both roots. The context binds the chain, parent, work-free header, task and target. Inputs retained as Expected are independent of the submitted witness at the caller boundary.

The selector returns `(digest[0]&7,digest[1]&7,digest[2]&7)`. Each of the 512 triples is uniform under a uniform selector digest. Repeated selected coordinates across different seeds are normal; they are not seed aliases. For selected coordinates (bi,bk,bj), the factors' row addresses are

\[
X:(0,8bi+i),\quad Y:(1,8i+bk),\quad
Z:(2,8bk+i),\quad T:(3,8i+bj),\quad0\le i<8.
\]

These are 32 distinct `(seed,label,index)` families. For each row the sampler reads counters 0–127, interpreting each digest as eight little-endian 32-bit candidates. Values at least q are rejected. It returns the first eight accepted values or refuses `NOISE_BUDGET`. There is no modulo-bias fallback.

The checked algebra is

\[
E=XY,\quad F=ZT,\quad D=(A+E)(B+F),\quad U=AB.
\]

Only the selected authenticated A and B blocks are involved. The canonical event contains the context digest, nonce, selected coordinate, D and U; Merkle paths and proof-encoding randomness do not enter it. Ticket comparison is lexicographic on 32-byte strings, equivalent to an inclusive big-endian integer threshold. A zero target is rejected; a maximum target has p=1 and is only an arithmetic correctness control for lottery purposes.

## 3. Experiment, lifetime state and budgets

The classical adversary may adaptively query the random oracle, prepare data, choose eligible candidate contexts, screen seeds/selectors, submit witnesses and receive the verifier's ordinary rejection results. Its initial coins and uncharged auxiliary advice are independent of the oracle. Any oracle-derived retained state must be accounted for over its **whole lifetime**, even before the reported mining interval or eventual parent. A coalition or outsourcing arrangement may be combined into one adversary; donated noise information is not silently free.

Trusted public setup may create Merkle trees, roots and contexts. Its queries are recorded in the global hash ledger and count toward Q and the domain caps. Setup must not give the adversary uncharged relevant noise information. If it gives such information, charge the corresponding row accesses. This distinguishes honest public input preparation from the miner's nonce work.

Expected contexts must be admitted by the experiment independently of the witness. They may be chosen adaptively, but every allowed target must be fixed before its ticket answer and obey the same declared p cap. Allowing a later larger target while analyzing a smaller p invalidates the bound. Determining which contexts are actually authorized by a live chain is outside the local relation.

For every submitted output, the exact verifier completes all needed oracle evaluations, including previously unqueried event/ticket/seed/noise entries. These completion entries count toward Q. **Verifier-internal noise computations never retroactively increase miner H.** The verifier may report its normal failure stage. Whole-D equality feedback is allowed, including the information that D was correct but U was not. No partial row/product leakage, hidden row dumps or timing side channel is included.

The following are deterministic caps valid on every execution, not estimates from successful samples:

* **Q and q_tag:** distinct full-message oracle inputs over public setup, adversary lifetime and verifier completion. Queries outside the canonical grammar enter Q as `other`. Counting every call is a looser safe cap; repeated queries do not create independent answers.
* **M:** all distinct `(context digest,nonce)` candidate pairs appearing in seed queries, structurally canonical event queries or submissions, including discarded candidates. A loose cap is `q_seed+q_event+number_of_submissions`. M is not merely the final winning nonce count.
* **H:** distinct `(seed,label,index)` row families accessed by the adversary or its coalition. The first query to any counter counts, including partial/rejected sampling and unused preprocessing. Charging counters outside 0–127 too is a safe weakening. Honest completion does not increase H.
* **R:** a per-candidate cap on event-message or submitted-D guesses made while some selected row remains adversarially untouched. It includes early event queries whose ticket is queried later, and early guesses followed by later row completion. Counting all event queries/submissions per pair is a safe simpler cap.

For the row prediction and paid-first analysis only, reveal the whole accepted row to the analyst at the first row touch. Giving all other rows to a predictor is a strengthening inside the independent-row comparison. This is **not a new actual random-oracle API**. It must not be used to assume unqueried raw noise digests were revealed to the real adversary while retaining the same fresh-output hazard proof.

One exact verification uses at most 4,120 full hash calls, of which at most 4,096 are noise digest calls. Per submitted witness, safe distinct-query completion caps are: leaf 2, node 12, task 1, context 1, seed 1, selector 1, noise 4096, event 1, ticket 1; total 4,116. The task and context recomputations are identical within one verification. These are relation call caps, not measured global worst-case receiver latency or network cost.

## 4. Collision and reverse-pointer composition

Output collisions alone miss a real ordering issue. Query `ticket(y)` at a guessed event digest y; suppose it produces a favorable z. Later query `event(m)` and obtain y. If z differs from y, these two outputs do not collide, but m inherits an already known ticket. The same backward direction is possible at guessed seed, context, task or Merkle digests.

Define the following failures on the **original** lazy-sampled full-message oracle transcript:

1. Two distinct oracle inputs have the same output, including cross-domain outputs.
2. A fresh producer output equals a value previously registered in a consumer's appropriate digest slot. Register consumer slots before sampling its answer. Repeated producer inputs do not trigger fresh predictions.

| Producer type | Earlier consumer pointer positions | Maximum pointer count |
|---|---|---:|
| leaf/node | two node children, two task roots | `2 q_node+2 q_task` |
| task | task argument of context | `q_context` |
| context | context argument of seed or event | `q_seed+q_event` |
| seed | seed argument of selector or noise | `q_selector+q_noise` |
| event | event argument of ticket | `q_ticket` |

The Merkle bound collapses labels/levels into a larger type for simplicity. Separating them could tighten the bound. A pointer can be any adversarially guessed bit string, not just a previously known hash output.

In the original transcript, a fresh oracle output is uniform conditional on the past; each existing set of s outputs/pointers is already fixed. Its hit probability is at most s/2^256. Summing all collision hazards yields `C(Q,2)/2^256`. Summing all producer × pointer caps yields the other five terms in epsilon. Completion queries are included in both sets of caps. The coarse bound follows because the pointer slots number at most 2Q, so their summed hazard numerator is at most 2Q^2.

This argument is made **before** the auxiliary whole-row revelations. Rejection sampling may use more than one digest; revealing the whole accepted row can disclose parts of later unqueried noise digests. Installing that stronger real interface and then blindly invoking the original fresh-output proof would mix filtrations. The actual adversary does not receive that extra interface.

The proof uses a common probability space and an identical-until-failure argument [S1]. It does not condition on the global event that no failure ever occurs and then claim independent oracle responses. `transcript_audit.py` implements the bookkeeping on finite observed transcripts, including examples with reverse event/seed pointers but no ordinary output collision. Such an audit does not certify unknown lifetime budgets.

## 5. Binding inputs and allocating independent row families

Before the first hash failure, an accepted opening's ancestry was fixed in the correct order. If its leaf or an internal node were first evaluated after a consumer already used its digest, that first output would trigger a reverse pointer. If another distinct producer input already yielded that digest, it would trigger an output collision. Recursing along the selected Merkle paths and then task→context→seed shows that the accepted A/B blocks were fixed before the seed output.

This does not demand all unopened leaves be evaluated. At seed birth, retain the map of already fixed, openable leaves under each committed root. If a later selected opening was not fixed then, later successful realization crosses one of the failure events. The selector is independent of factor streams; whichever eligible pair it selects has already fixed A/B. Roots without valid openings cannot create a cost-free accepted event.

A new seed cannot equal another earlier seed output without an output collision. It cannot equal a value used in an earlier selector/noise input without a reverse-pointer event. Thus its factor-stream addresses are fresh. Selecting later contexts based on earlier candidates is allowed: a fresh candidate's own factor streams remain independent of the past. Repeated 9-bit coordinates do not allow factor reuse because the 256-bit seed remains in every row address.

For the row analysis use an extended table: allocate independent accepted field rows and independent rejection patterns at each eligible fresh seed birth and couple their raw streams to the corresponding oracle inputs. The real transcript agrees with this view until a hash failure. The extended game can be continued with independent tables after failure solely for an upper-bound comparison. Do not condition row distributions on future failure avoidance.

A uniform 32-bit candidate is accepted with probability q/2^32. Conditional on acceptance its value is uniform in F_q; conditional on rejection it is uniform among the other five values. Acceptance indicators, accepted values and rejected values can therefore be sampled independently. The first eight accepted values are independent uniform field elements and independent of the rejection pattern. The 128-digest abort depends only on that pattern. Allowing an infinite stream is a stronger computation; the real abort can only prevent acceptance. Even revealing abort/rejection patterns does not bias an untouched accepted row. There is no additional modulo-uniformity or abort **security** error term; retry/abort still matters for availability and physical cost.

## 6. Four missing-row prediction bounds

This section reproduces the full algebra instead of depending on a lost earlier report. Let n=8, tau=q^-n and let X,Y,Z,T be independent uniform n×n field matrices. A,B are arbitrary matrices fixed before this family. Define `a_j=1−(1−tau)^j`.

For a uniform row v and independent uniform matrix V, vV has maximum point mass at most

\[
a_2=\tau+(1-\tau)\tau.
\]

The zero v event has probability tau; for nonzero v, vV is uniform. The same maximum atom holds after a fixed shift. For N=B+ZT,

\[
\mathbb E[q^{-\operatorname{rank}N}]
=\Pr[vN=0]\le\tau+(1-\tau)a_2=a_3.
\]

Indeed for nonzero v, vZ is uniform and `(vZ)T` has the a2 maximum atom, including the shift vB. Independently sampling Y gives

\[
\mathbb E[q^{-\operatorname{rank}(YN)}]
\le\tau+(1-\tau)a_3=a_4=\beta.
\]

Reveal all factor rows except one row u. Conditional on these revealed rows, the full noisy product D is uniform on an affine image of u. Let m be the maximum conditional atom. There are four cases:

* **X row absent:** u contributes `uYN` in its output row. The conditional atom is `q^−rank(YN)`, whose average is at most a4.
* **Y row absent:** the variable term is `(Xe_r)uN`. `Xe_r=0` with probability tau. Otherwise the image has rank rank(N). Hence E[m]≤tau+(1−tau)a3=a4.
* **Z row absent:** write C=A+XY. The term is `(Ce_r)uT`. The column Ce_r vanishes with probability at most a2, independently of T. Since E[q^−rank(T)]=a2, E[m]≤a2+(1−a2)a2=a4.
* **T row absent:** the term is `(CZe_r)u`. The coefficient column vanishes with probability at most a3. If nonzero, mapping u to that outer product is injective and its atom is tau. Thus E[m]≤a3+(1−a3)tau=a4.

The coefficient-zero and rank-deficient cases are included in the expectation. No invertibility or matrix-hardness conjecture is assumed. This is an **average maximum-atom** bound, not the false pointwise assertion that every revealed coefficient configuration has atom at most beta. The fresh tests exhaust all four missing-position cases over F_2 for scalar matrices; that checks a small analogue, not the general symbolic proof.

## 7. Adaptive guesses and feedback

Fix a candidate and one selected row which has not yet been adversarially touched. Reveal all other factor rows, fix independent oracle randomness and coins, and follow the branch on which every complete-D equality guess fails until that row is touched. This determines a list of at most R guessed D values without using the missing row.

If a first correct guess occurs, it lies in that list. Conditional on the other rows, list coverage has probability at most `min(1,Rm)`. Averaging gives at most R beta. This remains valid when later guesses depend on earlier equality failures. It does **not** assert that the posterior atom remains beta after each failure. For a four-point uniform secret, one failed guess changes the posterior largest atom from 1/4 to 1/3, while two-guess list coverage is still at most 2/4.

Guesses before seed evaluation are included: absent a reverse seed/context pointer, they do not know the eventual fresh factor family. Event/ticket answers are independent random-function information; rejection stages reveal whole-D equality or pre-noise checks. U failure after correct D already counts as a correct D guess. No partial-factor or timing oracle is added.

Candidate selection can depend on prior information, but each fresh eligible family has fixed A/B before its own factor sampling. The bound is uniform in those fixed matrices. Union over the 32 selected rows, all M lifetime candidates and the per-pair R cap gives

\[
\Pr[\text{early correct D before the first hash failure}]
\le32MR\beta.
\]

M must include every candidate inspected in preprocessing or filtering; this factor pays for searching for easy revealed coefficients. R includes all relevant early guesses even if the missing rows are later queried before publication. One cannot replace these caps by final successful outputs or a post-setup nonce count.

## 8. Unconditional paid-first sequence and binomial tail

Use the extended analysis history and stop after the first hash failure. A ticket response can be an adversarial query or an internal first response in honest verifier completion. Just before such a response, include a candidate if:

1. no earlier hash failure has happened;
2. its seed derivation and event producer are already present;
3. its structural, Merkle, selector and algebraic relation is correct **excluding the ticket threshold**, its target is fixed, and all 32 selected rows were already adversarially touched;
4. this canonical event has not already supplied a ticket response.

Correct but subsequently losing candidates are included. The predicate is predictable from the past: row-touch auxiliary information fixes D, fixed ancestry fixes A/B and U, and the independent selector may be placed in the analysis history at seed birth. A missing producer later realized in an accepted event is paid for by a reverse-pointer exception or an early D guess. The real adversary gets no new row interface.

Before the first failure, a canonical event has one digest and its first ticket input is unqueried. Otherwise a reverse event pointer or an output collision would have occurred. Thus its fresh ticket answer is independent of the enhanced row/selector history. With fixed T the hit indicator is Bernoulli(p); for predictable smaller targets its conditional hit probability is at most p.

**Include the current ticket before reading its answer, even if that answer itself causes the first collision failure. Stop afterwards.** Excluding the current answer based on whether it causes a failure would filter the random trial using its own outcome.

Each included event uses a distinct seed and 32 distinct adversarial row accesses; there is at most one canonical algebraically correct event per context/nonce. Every execution contains at most `K=min(M,floor(H/32))` such trials. A predictable stopped sequence of fresh Bernoulli(p) trials, padded with independent unused trials to K, is dominated by Bin(K,p). For variable conditional probabilities at most p, use the same coupling with fresh uniforms.

Every distinct accepted event not counted by this sequence either crosses a hash failure or had an early correct D guess. Completing rows only after testing the correct ticket does not retroactively make that event paid-first. Add the two unconditional exception bounds to the binomial tail. This proves §1 without asserting independence after conditioning on absence of future exceptions.

Repeated presentations of the same valid event count once in W. The source verifier itself has no durable payment or replay-state authority; this theorem does not supply one.

## 9. Numerical use and practical boundaries

For this field beta≈3.454467454210013×10^-77. The composite hash term can dominate the row-guess term and must not be omitted. Query caps in `budget_example_*.json` are assumed limits, not measurements proving limits for all miners.

For p=1/64, 44 paid trial slots give probability 0.499890250976003… and 45 give 0.507704465804503…. With the supplied small exception budget, H=1408 is insufficient for one-half success, so H≥1440 is necessary inside this model. In general, when alpha>delta+epsilon and 0<p<1,

\[
H\ge32\left\lceil
\frac{\log(1-\alpha+\delta+\varepsilon)}{\log(1-p)}
\right\rceil
\]

is necessary, subject to the same assumptions and enough candidates. This is a bound on row accesses, not on physical hashes, matrix multiplications, useful demand, money or elapsed time.

The adversary may cache original U products across nonces/contexts, share SHA prefix states, use exact fast matrix multiplication, exploit zero/low-rank/repeated input structure, batch work and reuse public preparation. `PRICING.md` gives explicit achieved algorithms. No universal arithmetic lower bound follows from giving arithmetic away in the query model.

The proof is classical: a quantum superposition query does not yield the same transcript of untouched rows and guessed pointers. Its collision, preimage and query accounting needs a separate QROM argument. Quantum search already changes generic oracle-query scaling [S3]. Nor does a full-message random-oracle proof automatically become a proof for SHA-256's concrete iterated compression structure. Exact standard SHA computation is a different claim [S2].

The targeted earlier search found the ESA 2026 matrix-PoUW invited paper [S4], which explicitly bases optimal cheating resistance on a correlated low-rank hardness conjecture. That result does not certify this local 8×8 relation or a universal physical-work minimum. The row lemma here avoids that conjecture while proving a narrower query statement. The recovery does not claim a new exhaustive literature search.

## Primary sources retained with the derivation

**[S1]** Victor Shoup, *Sequences of Games: A Tool for Taming Complexity in Security Proofs*, January 18, 2006 version, difference lemma. https://shoup.net/papers/games.pdf . Used for failure-event methodology, not as attribution for this original selected-event derivation.

**[S2]** NIST, *FIPS PUB 180-4, Secure Hash Standard*, August 2015, §§5.1.1, 5.2.1, 6.2. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf ; publication page https://csrc.nist.gov/pubs/fips/180-4/upd1/final . Defines SHA-256 blocks, padding and compression.

**[S3]** Christof Zalka, *Grover's quantum searching algorithm is optimal*, Physical Review A 60, 2746 (1999), author preprint https://arxiv.org/abs/quant-ph/9711070 . Used only for the classical-versus-quantum boundary.

**[S4]** Ilan Komargodski and Omri Weinstein, *Proofs of Useful Work from Arbitrary Matrix Multiplication (Invited Talk)*, ESA 2026, published August 25, 2026. https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2 . Its conjecture does not instantiate the present theorem.

Historical internal review checked the same typed graph and identified the threshold/predictability and filtration distinctions now explicitly retained. This reconstructed text is not thereby machine-checked, externally audited, or certified for SHA/QROM/production use. **HOLD_NO_GO remains unchanged.**
