# W1 rooted canonical paths with charged bidirectional ideal-cipher queries

Date: 2026-10-26. Status: finite classical conditional theorem, with a complete proof and a separate-agent static review. The reviewed v2 proof body below is unchanged from the retained research note (SHA-256 `92b47396ba1b410e5899fe0f1c37780f74e5633340918a6065f644e896607c45`). This document adds no experiment, physical-cost or production-qualification claim.

## 1. Exact outcome and scope

A finite lemma survives the arbitrary-CV fixed-point counterexample **in a different, explicit model**. The adversary gets both directions of independently sampled permutations, and inverse queries producing isolated compression fixed points are allowed. The exceptional event concerns a newly exposed edge joining an older exposed vertex or an earlier digest reference. It does not forbid a new inverse-query self-loop.

Outside that bounded event, the component reachable from the fixed standard IV is an outward tree whose edges were first exposed by forward queries. Consequently, different canonical W1 challenges require disjoint 2,049-edge paths. With all preprocessing recorded and bounded terminal checking, those paths must have been exposed before their respective full digest references. Terminal checking contributes to the failure probability but not to the miner's query allowance.

This is a theorem about a classical ideal-cipher query model. It is not an assertion that the SHA-256 round family is a collection of independent random permutations, a lower bound on matrix arithmetic, a CPU/time/energy bound, or a fresh-ticket/binomial theorem.

## 2. Experiment and resources

Let `X = (Z/(2^32)Z)^8`, with componentwise addition `boxplus`, identity 0, and size `N = 2^256`. The reasoning works for any finite group with bijective translations. For every 512-bit message block b, independently sample a uniform permutation `P_b:X -> X`. Define the compression edge

`D_b(h) = h boxplus P_b(h)`.

The IV `r` is fixed independently of every permutation and of oracle-dependent advice. All domains (trace, challenge, noise, ticket, and any other accessed hashes) share this one permutation family. The adversary can query either `P_b(h)` or `P_b^{-1}(y)` for any b and any state, interleave them, reuse entries, batch queries, choose all its tasks/challenges/forks adaptively, and perform arbitrary finite oracle-independent computation. A serialized adaptive interaction contains any classical batch schedule.

A fresh table entry is a previously unknown pair `P_b(h)=y`; a later query in either direction that retrieves that same entry is a repeat. Every call is charged, in either direction. Charging calls is conservative relative to counting fresh entries. In particular, obtaining `P_b^{-1}(0)` is charged and its resulting self-loop is retained in the exposed graph. The primitive cannot be evaluated by any other uncharged interface or by a publicly available implementation inside this experiment.

All caps below are fixed before sampling the permutations and hold uniformly on every possible execution:

- `Q_P`: all charged preprocessing calls, including rejected/discarded trials, public or outsourced preprocessing made available to the attacker, and all domains. This is an exposure allowance; public parties' costs are not thereby reclassified as costs actually paid by this miner.
- `Q_A`: all charged calls after the online boundary and before the miner seals its references.
- `R`: all full 256-bit trace-digest references made before that seal, including misses, wrong candidates, early guesses, repeated references and unqueried final submissions. Counting multiplicity gives a valid, possibly loose cap.
- `G`: at most G referenced openings examined after the seal. To cover every potentially valid opportunity, G must cover every such reference, including nonwinning references. Examining only published winners proves only the corresponding published-reference bound.
- `V`: all additional primitive calls made by a bounded terminal checker of those openings. These calls are not charged as miner work. They are included when bounding exceptional joins.
- `C = Q_P + Q_A + V`. The nontrivial formula below assumes `C <= N`; otherwise use failure probability 1.

The initial oracle tables are empty. A retained list of favorable pairs is **not** an adequate account of earlier preprocessing: the entire search which selected it must be included in Q_P. A hidden, unbounded search is oracle-dependent advice, handled separately in section 8. Fixed public input independent of the sampled permutations is harmless. Oracle-dependent public input requires captured generation calls or an explicit advice/initial-table model; it cannot silently enter as free independent data.

The checker receives bounded openings sufficient to determine the exact canonical trace message and evaluates all missing primitive calls needed for checking it. Reference values are committed to the analysis before the answer they are intended to use. Openings may be selected adaptively, but the checker cannot create new miner references after the seal. Its work and outputs do not add miner credit.

## 3. The incremental join event

Maintain the directed labeled graph of **all exposed compression edges**, not just rooted edges. An exposed permutation entry `(b,h,y)` contributes the edge `(h,b,h boxplus y)`.

Before the j-th fresh permutation entry, let

`S_j = {r} union {origins and endpoints of all earlier exposed edges} union {all prior full trace-digest references}`.

A reference is inserted when its complete digest is first used as a reference; insertion itself is not a failure, even if the value equals an old vertex. Duplicates do not enlarge the set. With at most R references,

`|S_j| <= 1 + 2(j-1) + R = 2j-1+R`.

For a **fresh forward query** `(b,h)`, write `y=P_b(h)` and `z=h boxplus y`. Declare `Join_j` if

`z in S_j union {h}`.

For a **fresh inverse query** `(b,y)`, write `h=P_b^{-1}(y)` and `z=h boxplus y`. Declare `Join_j` if

`h in S_j OR z in S_j`.

Importantly, the inverse event does **not** include `z=h`. For `y=0`, the new edge is a self-loop at a newly sampled h; that is allowed unless h already belongs to S_j. A repeated forward query of this already known entry is also allowed. Thus the fixed-point construction does not make Join inevitable.

Let Join be the union of these events over preprocessing, online work, and terminal checking. It is a deliberately conservative sufficient event: some joins between unrooted components are also counted, though they need not help the attacker. No soundness claim requires every Join to be useful.

### Lemma 1: probability of Join

For oracle-independent initial advice,

`Pr[Join] <= delta_IC(C,R)`

where, for `0 <= C <= N`,

`delta_IC(C,R) = min(1, sum_(j=1)^C (4j-2+2R)/(N-j+1))`

and hence

`delta_IC(C,R) <= min(1, 2C(C+R)/(N-C+1))`.

**Proof.** Fix the complete transcript immediately before a fresh query and its chosen direction, b, and input. If the table for b already has k entries, then `k <= j-1`. Lazy sampling makes a fresh forward response uniform over exactly `N-k` unused outputs, and a fresh inverse response uniform over exactly `N-k` unused inputs. This statement is about the actual revealed transcript, without conditioning on a future good event.

For a forward query, translation by h is a bijection. At most `|S_j|+1 <= 2j+R` possible responses put z in the forbidden set. For an inverse query, the two conditions are `h in S_j` and `h in S_j boxminus y`. Their union has size at most `2|S_j| <= 4j-2+2R`; for y=0 the two sets coincide, which only improves the bound. For all j>=1 and R>=0, the inverse bound also bounds the forward case. Removing previously used permutation values can only reduce the number of forbidden choices, and leaves at least `N-j+1` choices.

Summing conditional first-failure bounds over at most C fresh entries proves the sum. The numerator sums to `2C(C+R)` and every denominator is at least `N-C+1`, proving the simpler bound. Repeated calls expose no new edge and require no new probability term. An adversarial stopping time is permitted as long as the predeclared caps hold. One must not substitute favorable realized C or R into this tail probability after observing the run without an additional anytime argument. QED.

## 4. Rooted graph and reference-time extraction

### Lemma 2: the standard-IV reachable component is an outward tree

On the event that no Join occurs, the graph reachable from r is an outward tree. Every reachable edge was first exposed by a forward query. Every new reachable edge adds a previously unseen endpoint. Inverse-created self-loops remain outside the reachable component.

**Proof.** Start with r and no edges. A fresh inverse query adds an origin and endpoint outside every earlier graph vertex and r; they may equal each other only in the allowed self-loop case. Thus it creates a new unrooted component. A fresh forward query has a chosen origin h and an endpoint outside all earlier vertices, r, and h. If h is already reachable, the edge attaches one new vertex to the rooted tree. If h is not reachable, it cannot connect its old/new unrooted component to the rooted component because its endpoint is new. Repeated queries do not change the graph. These rules also prevent later attachment of an old inverse component to the rooted component. Reference insertion does not add graph edges. Induction proves the claim. QED.

### Lemma 3: a valid referenced digest's whole path was already exposed

Consider a reference `(c,t)` made at time tau, later opened as a canonical message of L blocks whose hash starts at r and ends at t. On no Join, all L path entries were already exposed before the reference at tau. They therefore belong to captured preprocessing or online calls, rather than to terminal checker calls.

**Proof.** The checker eventually exposes all entries of that canonical path. Suppose at least one entry was missing at tau, and choose the **last** missing edge in path order. If it is the final edge, its endpoint t is a prior protected reference when that entry is first exposed. If it is not final, the next edge was already exposed at tau by the choice of the last missing edge, so its origin, equal to the missing edge's endpoint, is already an older exposed vertex. In either case, the newly exposed endpoint is in S_j. Both the forward and the inverse rule classify this as Join. Contradiction. QED.

This argument does not demand a materialized output transcript, does not charge the auditor's reading or arithmetic to the miner, and does not assume that only correct candidate messages were queried. It is a statement about table entries and chronological full-digest references. A wrong message whose digest happens to equal the canonical digest is also covered by the same event.

## 5. Canonical W1 corollary

Use the frozen source's exact canonical trace grammar: `TRNM-PON-TRACE1\0`, the full 32-byte challenge, then all 32,768 canonical little-endian field-prefix words, followed by standard SHA-256 padding. This is 131,120 bytes before padding and exactly `L=2049` blocks. The first 64-byte block contains the entire challenge. Consequently, distinct challenges have different first blocks, regardless of their prefix-word values. This source geometry is the same in the scalar reference and producer implementations in `trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs`.

Only legal, exact canonical messages count; no arbitrary IV, inserted block, variable length, omitted prefix, or alternative padding is made valid. Inputs and challenges may otherwise be chosen adaptively. Algebraic computation of their prefix values can be arbitrarily fast in this model.

Let m be the number of **distinct challenges** among valid referenced openings. By Lemma 3 their paths were exposed before their references. By Lemma 2 each path has L distinct edges. Since their first edges differ in an outward rooted tree, the paths are pairwise edge-disjoint. Therefore, except with probability delta_IC,

`L*m <= Q_P + Q_A`,  with `L=2049`.

A sharper but less convenient right-hand side counts only fresh forward entries exposed during those two phases. The displayed bound charges all calls in both directions and is sufficient. The auditor's V is absent from this right-hand side.

This proves a count of distinct canonical trace instances. It does not prove that each proof encoding, signature, transcript wrapper, reused trace, or alternate task alias creates another independent opportunity. A separate semantic identity and pre-answer ticket-binding rule is still required.

### Previously exposed and prepared-but-unrevealed instances

Retirement has an additional coverage requirement. An old instance can be retired only if its exact canonical path was already exposed by the captured Q_P calls, or if its earlier full reference is included among the same G bounded terminal openings and all calls needed to check it fit inside the same V. In the second case, G and V must cover the union of old retired openings and new openings, not each subset separately. An unexamined digest reference which merely happens to be canonical does not establish that its path entries are in the captured table on the stated no-Join event.

Let D0 be distinct-challenge canonical paths meeting that coverage requirement whose lottery answers have already been revealed before the online boundary. They may include winners and misses. The paths must be canonical, not merely old arbitrary trace candidates. For n additional distinct challenges, on no Join,

`n <= floor((Q_P - L*D0 + Q_A)/L)`.

For these covered old paths, the same event supplies `L*D0 <= Q_P`: a terminally checked old reference invokes Lemma 3 at its original pre-online reference time. Complete prepared paths with as-yet unrevealed lottery answers remain in Q_P and may yield immediate online openings; do not add them again as a free bank. This is a cumulative capacity statement, not a minimum incremental online cost for each individual ticket. Public preprocessing included in Q_P stays an explicit initial resource/exposure allowance rather than a miner expense inferred from the theorem.

## 6. Shared primitive and complete ticket references

The canonical ticket hash is exactly two blocks. Its first block contains c and the first six bytes of t; its second contains the remaining 26 bytes plus fixed padding. A wrapper which registers t only at publication would therefore be insufficient.

For a genuine rooted ticket path, Lemma 2 gives the needed causal fact: when its second entry is first exposed, that query is forward and its input vertex is already reachable through its unique first edge. If the second edge had instead been exposed before its first edge, later connecting the first edge to that old vertex would be Join. An inverse-created second edge also cannot become rooted on no Join. The known first edge's block and the chosen second block can therefore be parsed and canonically re-encoded, recovering all of c and t **before the second forward response**. Register that complete t then. Repeated queries of the second entry do not create new opportunities.

The instrumented reference extractor may conservatively register every exact two-block ticket-shaped query whose first edge is already exposed from r, even when its proposed trace is invalid. All of those references, including misses and wrong guesses, belong in R. Final submissions that did not make such a query also require an explicit earlier reference event. Requests for an unresolved second edge, partial-byte candidates, or a future late first-block opening cannot be silently omitted from the model; the latter is covered by Join.

This causal parsing observation is not a claim that the shared ideal-cipher ticket is an independent random oracle. Predictability of canonical validity, correct instance binding, and conditional lottery distributions remain separate obligations. In particular, an outcome-selected set of eventually valid references cannot simply be treated as that many independent Bernoulli trials.

## 7. A finite extension for an explicitly fixed initial table

There is also a useful, distinct model which permits k arbitrary, consistent initial permutation entries. For each key, the rest of its permutation must be sampled uniformly from the remaining inputs and outputs, independently of other keys. The adversary's initial data may depend only on this fixed table, not on its random completion. This is a bit-fixing model, not unrestricted advice.

Include all initial edge origins/endpoints in S. The initial rooted component may contain cycles and joins; do not classify those deterministic entries as improbable. For C additional fresh entries and `k+C<=N`, the same sampling argument gives

`delta_seed <= min(1, 2C(2k+C+R)/(N-k-C+1))`.

Let H be the number of distinct challenge strings appearing in an initial-table edge from r whose block is syntactically a W1 first block. This is an upper bound on potentially relevant seeded first blocks, so `H<=k`; counting even noncanonical ones only weakens the bound. For a canonical trace with a challenge outside that set, its first edge cannot be an initial entry. On no new Join, that edge introduces a new vertex, and its entire L-edge path consists of distinct new forward entries. Such paths cannot enter the initial graph or join one another. The reference-time argument still excludes new auditor entries. Hence

`L * max(0,m-H) <= Q_P+Q_A`.

This extension deliberately does **not** assert `L*m <= k+Q_P+Q_A`: an arbitrary fixed table can seed reachable cycles and shared paths. The whole challenge associated with a seeded first edge must be reserved as a potential exception, rather than pricing each fixed pair as only one ordinary path edge. For retirement, split previously exposed canonical challenges into `D_seed` within that H-set and `D_fresh` outside it. A safe remaining capacity is

`(H-D_seed) + floor((Q_P-L*D_fresh+Q_A)/L)`.

Here D_seed is a count of actual distinct already-exposed canonical challenges in the seeded set, not the count of invalid guesses. For every retired D_fresh instance, its canonical path must either be exposed in captured Q_P or its old full reference must be included in the same G/V bounded terminal coverage, exactly as in section 5. Any terminal checks needed to establish retirement of D_seed also belong to that same coverage. A bare unexamined old digest does not justify the Q_P subtraction. This bound is conservative when some seeded first blocks can never be canonical.

The unique-first-edge ticket parser of section 6 is **not** transferred to this seeded model. The initial table may contain two distinct ticket first blocks from r to the same state u. A later second-block query from u can then have two different complete `(c,t)` interpretations before its response. For this model, references must be explicit, or an extractor must enumerate and charge to R all applicable complete pre-answer interpretations (and G/V must cover the needed openings). The simple unique parser and any one-reference-per-second-query inference are unavailable without an additional initial-table restriction. This is a concrete limitation of the extension, not an assumed improbable event. The explicit-reference path-count lemma itself does not need uniqueness of those ticket interpretations.

The extension is not automatically an auxiliary-input theorem. A preprocessing search that chooses a favorable table by inspecting its would-be random completion violates this model unless its entire search is captured. Auxiliary-input pre-sampling reductions have additional parameters and losses; this note does not import one without proving its precise event mapping.

## 8. Non-uniform advice and concrete failure cases

For unrecorded oracle-dependent advice of at most s bits, a general but weak corollary is

`Pr[violation] <= min(1, 2^s * delta_IC(C,R))`.

For each fixed advice string a, analyze the corresponding adversary without conditioning on the event that the oracle's advice function outputs a. The joint event for the actually selected string is contained in the union of the violation events for all at most `2^s` fixed-string adversaries. All caps and checker bounds must hold uniformly for every string. This is a union bound, not a tight non-uniform security result, and is often vacuous. Oracle-independent non-uniform code does not incur this loss. An unbounded amount of oracle-dependent advice admits no nontrivial bound from this lemma.

Concrete checks on the assumptions:

1. **Free inverse calls break the intended resource meaning.** Inverses can expose arbitrary many edges without paying the stated resource. The theorem counts both directions, although its no-Join rooted paths ultimately consist of forward-created edges.
2. **An attacker-chosen IV breaks the rooted-tree conclusion.** Query `P_b^{-1}(0)=h*`, choose r=h*, and repeat b. One stored self-loop supports paths of any length. This is why r must be fixed before the sampled family; it is not a valid W1 message attack.
3. **Binding the challenge only in a last block breaks the Lm corollary.** One common `(L-1)`-edge prefix and m different final blocks cost `L-1+m` exposed entries without any join. W1 puts the complete c in its first block, so this countermodel does not fit the actual trace grammar.
4. **Ignoring prior searches breaks the online-only bound.** Fully prepare m canonical paths offline and reveal them with zero online queries. Q_P must remain in the capacity formula.
5. **An opaque digest advice string breaks unconditioned lazy sampling after advice selection.** Advice may be the correct digest for a fixed canonical instance. A first online reference then succeeds with no prior online trace calls. The auditor's eventual endpoint hits the prior reference with probability one conditional on that advice. This is consistent with the explicit advice loss, and inconsistent with pretending advice is independent.
6. **Retiring arbitrary invalid paths as D0 remains invalid.** An invalid path can share an already paid prefix with a later canonical path. Only distinct canonical instances whose lottery answers were exposed may be removed from future capacity.
7. **Independent permutations are a substantive assumption.** Invertibility of each round mapping alone does not imply this theorem: a publicly specified family can have deliberately engineered rooted fixed points or cross-key relations. The actual SHA-256 mapping is known code with structured message schedules. The theorem supplies no bound on its deviation from this experiment and no physical cost of one oracle call.

## 9. What is proved; what is still open

Proved within the stated classical random-family experiment: the finite Join bound, the rooted-tree property despite freely chosen charged inverse queries, reference-time extraction with an explicitly paid audit allowance, distinct-challenge W1 path disjointness, and the two bank-accounting corollaries. The model covers adaptive choices and finite batches without a direct-product matrix assumption. It requires neither full-transcript materialization nor independent ticket random oracles.

Still open for production use: a defensible relationship between actual SHA-256 algorithms and this ideal-cipher model; nonvacuous treatment of unrestricted favorable oracle-dependent advice for the required experiment; a physical resource conversion for all allowed implementations; canonical-validity/ticket process composition; and global semantic consumption/uniqueness. The lemma does not close O01/O05/O07 and does not furnish a universal kappa. It repairs one mathematically well-defined target after the arbitrary-CV fixed-point model failure.

## 10. Primary-source checks and applicability

- Dodis and Puniya, *On the Relation Between the Ideal Cipher and the Random Oracle Models*, author-hosted full paper, definitions around pp.1 and4: https://cs.nyu.edu/~dodis/ps/ic-ro.pdf . Used only to check the ordinary ideal-cipher interface includes forward and inverse access. No indifferentiability theorem is transferred to W1.
- Carolan and Majenz, *Compressed Permutation Oracles Revisited*, 2026-09-23, sections3.2 and5.5 read: https://arxiv.org/html/2609.28469v1 . Confirms independent keyed permutations with both directions and distinguishes ideal-model preimage/collision statements from actual permutation instantiation. Its quantum results do not prove this classical chronological path lemma or extend it to quantum miners.
- Bhaumik and Huang, *Indistinguishability Lifting for Keyed Oracles, Compressed Ideal Cipher, and More Applications*, 2026-10-03, introduction and classical-model discussion read: https://arxiv.org/html/2610.04674v1 . The bidirectional interface and lazy sampling of only accessed keys support the model choice. No lifting loss or quantum theorem is imported.
- Coretti, Dodis and Guo, *Non-Uniform Bounds in the Random-Permutation, Ideal-Cipher, and Generic-Group Models*, CRYPTO2018; author-hosted full version dated2023-02-02, introduction/auxiliary-input and pre-sampling discussion read: https://cs.nyu.edu/~dodis/ps/ai-perms.pdf . It explicitly models bounded advice depending on the full oracle and explains why conditioned lazy sampling fails. Its bit-fixing methodology motivates section7, but no numerical pre-sampling theorem is asserted here. This note's s-bit union bound is proved directly.

Retrieval failures retained in this note: NSF mirror https://par.nsf.gov/servlets/purl/10208485 timed out; ePrint https://eprint.iacr.org/2018/226.pdf returned403. The linked author-hosted full version was successfully opened instead. These failures do not affect the self-contained proof.

## Revision and independent review record

This v2 preserves v1 as a separate file. The independent chain-security reviewer found no counterexample to the probability bounds, rooted graph induction, last-missing-edge proof, 2049-edge count, or seeded-table capacity. Two boundary conditions were tightened here: retired old paths need captured-query or the same bounded audit coverage; the empty-table unique ticket parser does not automatically extend to a seeded table with multiple first-edge interpretations. Review was read-only and did not execute code. No source or measured result was changed.
