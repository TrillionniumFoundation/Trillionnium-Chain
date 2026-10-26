# W1 ticket composition from literal shared-primitive inputs

Date: 2026-10-26. Baseline: `6488894f9f0bb2779a9aa75a4ae79a3c5d06977c`.
Status: a source-bound, finite **conditional ideal-cipher composition theorem** and executable negative controls. This is an additional result inside an explicit classical model; **O01 and O02 remain OPEN under their original standards**.

This document supplies the canonical-validity and lottery-process step left separate in [the rooted-path theorem](W1_ROOTED_CIPHER_PATHS_V1.md). It does not assume a separate ticket random oracle. The new ingredient is an exact separation between the message-block keys used by W1 noise expansion and those used by a ticket's final compression. Together with a chronological header/material/trace binding argument, this permits a predictable validity marker in an enlarged *analysis* filtration. A shared key's remaining permutation outputs give a probability **interval**, rather than independent Bernoulli equality.

The scope excludes actual-SHA instantiation, unrecorded favorable oracle-dependent advice, arbitrary seeded tables, physical cost conversion, production settlement and external reward consumption. No production consensus or qualification rule changes here.

## 1. Source binding and the identity being counted

The source facts below bind the listed identity, encoding and verification rules, which are unchanged from the baseline. Other helpers in these files may change in the concurrent task; this is not a whole-file immutability claim:

- [pon_work.rs](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs): `hash`, `task_id`, `expand_with_progress`, `checked_proof_inputs`, `verify_with_kernel`.
- [pon_wire.rs](../../../../trillionnium/crates/trnm-protocol/src/pon_wire.rs): exact 318-byte `Header` encoding, `challenge` and `block_id`.
- [node lib.rs](../../../../trillionnium/crates/trnm-pon-node/src/lib.rs): `Packet::id` takes the final 32 proof bytes as the trace digest and calls the header's block identity.
- [store.rs](../../../../trillionnium/crates/trnm-pon-node/src/store.rs): `blocks.id` is a primary key; `check_admission_header_context` returns an existing exact packet's ID, and rejects differing bytes under that ID with `DUPLICATE_CONTENT`.
- [consensus.rs](../../../../trillionnium/crates/trnm-pon-node/src/consensus.rs): `required_work(T)=floor(2^256/(T+1))`, with zero target rejected.
- [pon_executor.rs](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs): `block_reward_updates` uses a reward key derived from parent ID, height and miner, and writes branch state.

Write `h` for the complete encoded header, `d` for its work-task digest, `c=H_challenge(h)`, and `t` for the canonical trace digest. A valid W1 proof has exactly `PNW1 || A || B || C || t`, 49,188 bytes, with fixed-width canonical field encodings. Full verification checks `H_task(A,B)=d`, the ticket threshold, the complete canonical prefix hash and the exact useful product. The inexpensive ticket filter alone proves none of the latter checks.

The object bounded below is a **distinct native block candidate identity**, not an actual subsidy transfer. With one header and one trace, the native identity is the deterministic `H_block(h,t)`. Re-encoding, replaying or attaching an alternative invalid C does not change that pair. Under the binding established in the ideal experiment, one c fixes h, d, A/B, the canonical prefix sequence and t. Thus one valid first lottery answer has fanout at most one into distinct such identities. A collision of block IDs can only reduce this count.

This does not prove global realized-money consumption across reorganizations, another external reward service, or a future randomized proof backend. The existing store duplicate rule is local persistence behavior. Same-parent/height/miner sibling reward keys also must not be added as independent realized payments.

## 2. A literal byte separation, and its exact limitation

PON1 hashes use the unchanged message grammar:

```
TRNM-PON1\0 || u16LE(len(tag)) || tag
             || u32LE(len(part_1)) || part_1 || ...
```

SHA-256 padding follows FIPS 180-4: one 1 bit, zero padding and a 64-bit big-endian message-bit length [1]. The relevant exact lengths are:

| Hash message | Unpadded bytes | Padded 64-byte blocks |
| --- | ---: | ---: |
| Task, two 16,384-byte operands | 32,792 | 513 |
| Challenge, one 318-byte header | 343 | 6 |
| Noise, c / one-byte label / four-byte counter | 66 | 2 |
| Ticket, c / t | 90 | 2 |
| Canonical trace | 131,120 | 2,049 |

For every legal c, label and counter, the noise first block has **byte 53 equal to 1**, the first byte of the one-byte label's length. Every ticket final block has **byte 53 equal to 0**. The noise final block has padding at byte 2 and bit length 528; the ticket final block has padding at byte 26 and bit length 720. In particular their bytes 26 and 63 differ. These are contradictions at fixed positions, not tests of sampled challenges.

Let `Nkeys` be the union of all compression message blocks occurring in legal W1 noise hashes, across all c, labels 0..3 and counters 0..127. Let `Tkeys` be all ticket-final message blocks across all c,t. The byte contradictions prove

\[
\mathcal N\cap\mathcal T=\varnothing .
\]

This is an unconditional fact about the source's encodings. It is **not** statistical independence of actual SHA computations or a separation of all trace/material/header keys from ticket keys.

The new executable control constructs a stronger counterexample to that broader separation: for a fixed external c, choose perturbed A'=I and a suitable B', then subtract the exact four ordinary noise factors to obtain canonical A and B. Prefix words 4..19 are chosen to equal the 16 legal field words in a ticket-final block for t=0. The actual scalar W1 relation produces that exact block as its second trace block, and its digest is checked against the independent scalar oracle. This is a legal relation-level prefix overlap. It neither finds a self-consistent header/task fixed point nor claims that the overlapping ticket is this trace's own winning ticket.

Consequently, earlier trace and other-domain queries may deplete the very same permutation used by a later ticket. Section 6 accounts for that depletion; distinct top-level tags alone would not.

## 3. Experiment, references and captured resources

Use the empty-table experiment of the rooted-path theorem. For every 512-bit block b, independently sample a uniform permutation `P_b` on `X=(Z/(2^32)Z)^8`, with size `M=2^256`. Compression is `h boxplus P_b(h)`, with the fixed standard IV r. All hash domains share this family. The adversary has both forward and inverse query interfaces at arbitrary chaining values; free arithmetic, arbitrary classical batching, adaptive input/header/fork choice and storage are allowed. All primitive access is through charged queries. A known implementation which evaluates the family without queries is not an extra interface.

Capture all preprocessing `Q_P`, including public/outsourced information made available to the adversary and unsuccessful selection attempts, then at most `Q_A` additional calls before a seal. These are exposure allowances, not an assertion that public work was paid by this miner. The captured table freezes at the seal. The auditor may perform at most V additional calls to check at most G sealed openings, without adding miner credit. Let

\[
C_{\rm all}=Q_P+Q_A+V.
\]

All these caps, and the full-reference cap R below, are fixed before the sampled family, and hold on every run. Use only the trivial failure bound 1 if a proposed cap is outside the nontrivial range. Initial advice and public fixed inputs must be independent of the family, unless their entire oracle-dependent generation is captured. Arbitrary seed tables and arbitrary oracle-dependent advice are not silently allowed.

### 3.1 Full references before the relevant responses

Augment the rooted theorem's protected-reference set with **all** full c, d and t references from these source-specific extractors:

1. **c.** Before answering any primitive request whose chosen block is syntactically a canonical trace first block or ticket first block, insert its complete c. This includes arbitrary-CV requests, inverse requests, bad candidates and misses. The entire c lies in either first block.
2. **d.** Before a forward response, if an already exposed rooted five-block path to the query's input CV plus the chosen block exactly re-encodes a challenge/header message, insert that header's complete work-task d. The d spans the fifth/sixth challenge blocks, so registering only an early partial prefix would be insufficient.
3. **t.** Before a forward response, if an already exposed rooted first ticket block plus the chosen second block exactly re-encodes a ticket message, insert the complete t. The first block carries only its first six bytes; the remaining 26 bytes are in the query block.
4. **Sealed submissions.** As one seal action, register the full t and d for **all** submitted header/proof openings, then freeze the captured table, **before the first V query for any opening**. Registering the next opening only immediately before its individual check is insufficient: an earlier audit could otherwise create its path first. Any other explicit complete early guess also belongs to R. The complete sealed list and subsequent audit cannot create a new miner claim.

The parser consults only already exposed ordinary history. It uses exact re-encoding, including length fields and padding, rather than accepting a tag match alone. If several rooted interpretations exist, use a fixed deterministic choice or decline to parse: outside Join the empty-table rooted graph has a unique path, so this ambiguity only matters inside the exceptional event. No seeded-table unique-parser claim is made.

R counts all emitted references, including repeats and wrong values, throughout captured work and bounded checking. Allowing checker-time protected references only enlarges the conservative failure event; it does not retroactively change when a sealed miner t was first inserted. Reference extraction never consults the hidden noise information introduced in section 5. Thus the ordinary lazy-sampling Join bound remains applicable. Extending its protected set from trace digests to arbitrary complete state strings changes only R, not its proof.

A conservative declared bound for this particular deterministic extractor is
`R <= 3*C_all + 2*G + R_explicit`: at most one c, one d and one t per primitive call, two full references per sealed opening, plus every additional explicit complete guess/reference. The parser does not enumerate multiple interpretations after a Join, so this bound holds on all executions, not only good ones. The constants may be loose. All terms must be capped in advance; unbounded free submitted guesses cannot be hidden in an omitted `R_explicit`. Private ideas never used or submitted as references do not add a new claim.

G bounds the complete sealed submission list, including failed submissions, rather than only its accepted subset. V includes all checker calls, including rejection paths. G/V must cover every published identity claimed in the theorem and any retired old opening not already established by captured paths. For an assertion about all opened opportunities, they must cover that larger union, including nonwinners. They are not separate fresh allowances for each subset. A simple maximum for one header/material/relation/ticket opening is

\[
6+513+1024+2049+2=3594
\]

primitive calls: at most four labels times 128 two-block noise hashes. The auditor can deliberately check a rejected candidate completely. This maximum is not a charge to the miner, a source-runtime timing estimate or a requirement that actual receiver code hash in that order.

### 3.2 The same finite Join event

Use the previous forward/inverse Join rules with all protected c,d,t strings. Before fresh entry j, old origins/endpoints, r and prior references form a set of size at most `2j-1+R`. A forward endpoint entering that set or its own origin is Join. An inverse origin or endpoint entering the old set is Join. A new isolated inverse-created fixed point remains allowed.

For `C_all<=M`,

\[
\Pr[J]\le\delta
=\min\!\left(1,\frac{2C_{\rm all}(C_{\rm all}+R)}
                         {M-C_{\rm all}+1}\right).
\]

This is an unconditional failure probability in the **ordinary** revealed-history experiment. The tighter summed bound in the rooted theorem is also available. Never condition on future no-Join and then retain an unconditioned uniform-response assertion.

## 4. Binding and freshness before the lottery answer

### Lemma A: every ultimately opened valid candidate was already bound

Outside J, for an opened valid candidate, its canonical header, material and trace paths were exposed before the first relevant complete reference, and hence before its first fresh ticket-final response. For an unqueried sealed submission, all three paths were already in the captured table at the seal.

**Proof.** The previous last-missing-edge argument applies to every protected full state string. A canonical path ending at a previously referenced value cannot acquire a missing last edge later without a Join: its endpoint is the prior reference, or its next already present edge supplies an older origin.

Apply it first to t. A queried ticket registers t before the last response; a submission registers t before checking. Validity supplies the exact 2,049-block canonical opening, so its whole path already existed. Its first block contains c and caused a c reference before that trace-first response. Apply the same argument to the six-block canonical header ending at c. The header path already existed before that c reference. Its final request registered the exact d before the header-final response. Apply the argument again to the 513-block canonical material message ending at d.

The rooted graph is an outward tree on no-Join. Consequently the paths at c,d,t are unique: another header, another A/B message or another full trace ending at one of those vertices would create a join. Exact parsing fixes the target, parent, task, all header fields and material bytes. No future response is used to choose them. For sealed submissions the original t reference occurred before the seal, so the same chain puts these entries in captured work, not in V. QED.

This argument also covers an early guessed ticket which is made valid only by a later favorable header/task opening: such an opening is precisely a late path into an already protected c or d. The initial five-block challenge prefix may be reused across nonces; that legitimate reuse does not remove the c reference or the 2,049 trace blocks for a different c.

### Lemma B: one genuine first ticket answer is a fresh forward entry

Outside J, a new canonical ticket's second edge is first exposed by a forward query after its first edge is exposed. The already exposed first edge uniquely supplies the missing six trace bytes, so the complete c,t is parsed before the final response. A second edge exposed in advance at an arbitrary CV, or produced by inversion, cannot later become rooted without a Join. Repeating an already exposed full ticket entry repeats the same answer.

A canonical trace/header/material path cannot have exposed **that identical primitive entry** earlier: their first domain blocks differ from the ticket's, and the outward tree cannot merge different root branches. This excludes identical entries, not identical message-block keys. Other inputs under the same key remain permitted and are counted by `k_b` below.

A first ticket answer may occur during terminal checking when the miner submitted without querying it. It is then a virtual fresh lottery observation for the analysis. Its auditor calls belong to V, while Lemma A puts its trace path in captured work. Publishing without a ticket call is therefore not incorrectly forced to pay a miner-side ticket hash, nor is it given a new trace for free.

## 5. A predictable validity marker without a separate ticket oracle

Let `F_j` be the ordinary history before primitive response j, including query choice and previously captured entries. Define the enlarged analysis filtration

\[
\mathcal F^\nu_j
=\sigma\bigl(\mathcal F_j,\{P_b:b\in\mathcal N\}\bigr).
\]

The entire noise subfamily is revealed **only to the mathematical observer**. This changes neither the adversary's information nor Q_P, Q_A or V. It is not a free miner oracle, uncharged advice, an extraction algorithm's performance claim, or a live audit which feeds new results back to the miner.

Given this filtration and a newly queried `b in Tkeys`, the remaining entries of P_b are still a uniform completion of its ordinary already exposed table. The proof is elementary: Nkeys and Tkeys are disjoint fixed key sets; initially their permutation families are independent. Conditional on the complete noise family, an adaptive query transcript for every other key restricts that key only by its revealed pairs. Ordinary query selection can depend on past answers but not on its unseen permutation completion. Induction over the actual queries preserves this statement. This argument fails for arbitrary oracle-dependent advice, which is why it is excluded.

Before a fresh forward ticket-final response define a marker using only:

- the unique already exposed two-block ticket interpretation;
- complete header, task and trace paths **already in the captured table available at that time**;
- exact header/material/trace grammar and nonzero target;
- comparison of the decoded prefix words with the literal W1 arithmetic under the noise family;
- first use of that canonical challenge as a marked opportunity.

During terminal checking the guard uses the frozen **seal-time captured table** for header/task/trace paths, not paths created by the auditor. It may use a just exposed ticket first edge to interpret the virtual ticket-final request. The marker also respects a predeclared opportunity cap by stopping the comparison process before any excess marker.

All marker inputs are measurable before the ticket-final response in `F^nu`. The arithmetic requires only fixed A/B,c and noise queries, whose keys all belong to Nkeys. It does not recompute a trace digest through new, possibly overlapping ticket-key entries: the candidate trace path and every prefix byte were already exposed. Full noise-budget failure makes the marker false.

This is why the two ingredients are both needed. Noise-key separation alone would not reveal material or target chosen later. Rooted trace counting alone would not make a later noise-dependent validity test predictable. The c/d/t binding chain, captured-only guard and hidden disjoint noise family together resolve those issues in this experiment.

For every actually accepted opened native identity, Lemmas A/B imply that its first ticket response has this marker on no-Join, unless it belongs to the already revealed initial bank. Node task eligibility, parent validity, state execution and eventual canonical selection may reject additional candidates. They need not be predicted by this marker: it deliberately describes a superset used for an adversarial **upper** bound. No lower bound on accepted honest service follows from being marked.

The ordinary miner filtration need not itself decide validity at that time. Using a richer analysis filtration is sufficient for the conditional probability argument, provided the marker is predictable there and unseen ticket entries retain the stated conditional law. No step selects only eventual valid winners and retrospectively calls them independent trials.

## 6. The exact conditional lottery envelope

Suppose the fresh final entry uses key b at input chaining state u, and that b already has `k_b` exposed permutation pairs. Conditional on `F^nu`, the new permutation value Y is uniform over its `M-k_b` unused outputs. The ticket digest is `u boxplus Y`. Translation is a bijection; the native lexicographic threshold set has exactly `a=T+1` elements.

Therefore, without conditioning on no-Join,

\[
\max\!\left(0,\frac{T+1-k_b}{M-k_b}\right)
\le \Pr[\mathrm{hit}\mid\mathcal F^\nu]
\le \min\!\left(1,\frac{T+1}{M-k_b}\right).
\]

These are bounds, not generally equalities. Every previous exposure under b counts, including inverse queries, rejected candidates, preprocessing and other hash domains. For a predeclared total cap `C_all>=1`, `k_b<=C_all-1` gives the uniform upper envelope

\[
\bar p_T=\min\!\left(1,\frac{T+1}{M-C_{\rm all}+1}\right).
\]

The analogous conservative lower envelope is `max(0,(T+2-C_all)/(M-C_all+1))`. Its use for honest chain growth additionally requires a real canonical attempt, completed service, admissible parent/task and visibility assumptions; this note supplies none of those guarantees.

The four-state exact control shows why nominal `p=(T+1)/M` cannot replace this interval. With T=1 and u=0, removing one previously exposed miss output leaves probability 2/3; removing one hit leaves 1/3. The nominal value is 1/2. Native-style weight w=2 then has mean 4/3 in the first case, so an exact mean-one claim would already be false in this finite model.

For adaptive legal targets, with `w(T)=floor(M/(T+1))`,

\[
\mathbb E[w(T)\,\mathrm{hit}\mid\mathcal F^\nu]
\le \frac{M}{M-k_b}
\le \rho=\frac{M}{M-C_{\rm all}+1}.
\]

A stronger predictable process can retain the exact upper factor
`w(T) min(1,(T+1)/(M-k_b))`. Subtracting these predictable upper compensators gives a supermartingale for the marked process. It is not legitimate to transfer the earlier exact-uniform mean-one interface unchanged. Variable targets and weights also do not become equal-weight Poisson events.

## 7. Capacity, old winners and a finite fixed-target reward bound

On no-Join, distinct canonical c values yield disjoint 2,049-edge trace paths. Every marked path used by the comparison process is already captured, including the terminal guard. Thus

\[
2049\,m\le Q_P+Q_A.
\]

For an old canonical instance to be retired, its path must already be exposed in Q_P, or its original pre-online full reference must be covered by the same bounded audit as the new openings. Its first lottery answer must already have been revealed at the online boundary. Retire both winners and misses. Never retire arbitrary old invalid candidates: their prefixes can later be reused by a different, truly canonical path.

Let D_0 count those distinct retired canonical challenges, and K_0 count their distinct winning native candidate identities. K_0 is an initial bank, not new online production. Prepared but as-yet unqueried instances remain in Q_P; they are not another free additive bank. Outside J,

\[
n_{\rm new}
\le \left\lfloor\frac{Q_P-2049D_0+Q_A}{2049}\right\rfloor.
\]

D_0/K_0 may be random and depend on the captured past. Do not substitute an outcome-selected realized query total or condition away J. One clean finite probability statement uses **fixed** predeclared integers d,k with `0<=2049d<=Q_P`, k>=1. Set

\[
n_d=\left\lfloor\frac{Q_P-2049d+Q_A}{2049}\right\rfloor .
\]

For a fixed target T for the new opportunities, let W be the number of distinct opened native winner identities, including old bank entries. Then

\[
\Pr[\,W\ge K_0+k\ \land\ D_0\ge d\,]
\le
\Pr[\operatorname{Binomial}(n_d,\bar p_T)\ge k]+\delta .
\]

For d=0 this requires no favorable retirement observation. A sharper history-dependent confidence threshold requires its own conditional/anytime construction; it is not obtained by reporting the best realized cap after the experiment.

**Proof of the comparison step.** At the online boundary, use the pre-answer, captured-path marker of section 5 to identify the old canonical exposed bank. This is measurable in the enlarged filtration; on no-Join it coincides with the covered old instances just described. If this old count is below d, set the comparison process to zero. Otherwise retain at most n_d future pre-answer markers and stop before further marks. Each retained response has conditional hit probability at most bar p, by section 6, even on histories which will eventually experience Join. The elementary conditional Bernoulli coupling, or induction on the number of remaining marks, stochastically dominates their sum by Binomial(n_d,bar p); missing marks can be padded with independent dominating Bernoulli variables.

On no-Join, binding gives fanout one, repeated answers add no identity, the initial bank is separate, and trace disjointness prevents stopping before any relevant new genuine identity. Hence the original event outside J is contained in the comparison tail event. Add Pr[J] **after** bounding that tail. This never conditions the lottery law on a future global good event. QED.

This covers arbitrary classical adaptive strategies **within the finite captured-query model**, including many headers, forks, tasks, inverse queries, prefix caching and joint matrix algorithms. It does not convert an observed average CPU ratio into kappa or constrain every algorithm for actual SHA.

## 8. Executable controls and concrete failure modes

The dedicated [model](../../../../formal/pon-nakamoto-v1/experiments/w1_ticket_composition_v3.py) and [tests](../../../../formal/pon-nakamoto-v1/experiments/test_w1_ticket_composition_v3.py) contain:

| Control | What it checks |
| --- | --- |
| Byte-pattern contradiction | Universal mask conflicts for both noise-block families against ticket-final keys; exact native framing and padding |
| Legal relation-level overlap | A/B chosen after a fixed external c produce a real canonical trace interior block in the ticket-final key family; independent scalar digest comparison |
| Reference chronology | Complete task/header/trace before ticket; late c/d/t openings; second ticket entry exposed before its first; inverse fixed-point attachment; two-header challenge fanout |
| Seal and captured-path guard | All submission t/d references registered before any audit call; an immutable copied path table; one seal only; even a valid auditor-created path present in the live table cannot pass the captured-only extractor |
| Exact permutation enumeration | All small conditional partial-table laws fit the interval; one exposed miss can raise the hit probability and native-style weighted mean |
| Adaptive predictable marking | Exhaustive two independent five-state permutation families, adaptive shared-key query inputs and pre-answer marks, with comparison against a conservative binomial tail |
| Invalid retrospective selection | If the same hidden response both defines validity and determines winning, the valid subset can win with probability 1; conditioning on one realized stop-after-success trial similarly gives probability 1 |
| Initial accounting | Prepared unseen paths remain in Q_P; old winners/misses are retired once; arithmetic rejects subtracting more path cost than captured preprocessing |

The chronology oracle checks consistency of scripted forward/inverse permutation entries over a finite additive-group representation. Its examples are deliberately chosen controls, not sampled attacks, actual SHA traces, numerical security estimates or native block-admission demonstrations. The actual scalar arithmetic overlap control is separately identified. `seal_openings` copies the rooted parent table into a read-only mapping; `extract_candidate` automatically uses that fixed snapshot after sealing. This is an implemented data boundary, not a fixture flag claiming that later auditor work was prepaid.

Neither exact enumeration of a small process nor these unit tests constitutes a proof for the 256-bit model; the lemmas above provide that argument under the stated assumptions. No benchmark or production performance sample is added by this task.

## 9. Limits which remain open

1. **Actual SHA.** Independent per-message-block permutations are a substantive idealization. Literal byte disjointness does not make SHA round mappings independent. The previous arbitrary-CV SHA fixed-point control still rules out the older global ideal-F route. This note proves no bound on an actual-SHA rooted/composition failure term.
2. **Oracle-dependent advice.** Fully captured finite preprocessing is included. Unbounded favorable advice, secret prior searches or oracle-dependent public state cannot be priced by the remaining online queries. Even a tiny advice string can correlate a hidden family with a ticket response, breaking the conditional completion argument. The auxiliary-input literature explicitly treats this problem [3].
3. **Seeded tables.** The rooted theorem's weaker seeded path-count extension does not automatically inherit this composition. Its initial graph may admit several ticket-first interpretations, header/material aliases or reachable cycles. Additional explicit bank/fanout and advice restrictions would be needed.
4. **Physical and matrix cost.** A query is not a fixed quantity of CPU, energy, bandwidth or field multiplication. The model permits free arithmetic, so fast matrix, low-rank, multi-instance and precision shortcuts do not contradict it. A 2,049-query statement does not establish a matrix-work floor or useful training cost.
5. **Whole protocol.** This is an adversarial native-candidate upper interface. Honest visible service, DAA/fork settlement, eligibility, global reward consumption, Hepta quality and future ZK/mixed-work backends retain their own original obligations.

The substantive closure is narrow: **inside the empty-table captured classical ideal-cipher model**, source-specific references plus the disjoint-noise analysis filtration establish a predictable marked opportunity process with a finite shared-permutation envelope and native candidate fanout one. The actual project-level blockers keep their original standards and remain open.

## 10. Primary literature and use

[1] NIST, *FIPS 180-4, Secure Hash Standard*, sections 5.1.1, 5.2.1 and 6.2: https://doi.org/10.6028/NIST.FIPS.180-4 . Used for the literal padding/block/chaining geometry. It supplies no cost or independence theorem.

[2] Joseph Carolan and Christian Majenz, *Compressed Permutation Oracles Revisited*, 2026-09-23, section 3.2 and the Davies–Meyer discussion: https://arxiv.org/html/2609.28469v1 . Its ideal-cipher interface has independent keyed permutations and both directions. Its quantum results are not imported as a proof of this classical composition or of SHA instantiation. The derivation here uses elementary classical conditional completion.

[3] Sandro Coretti, Yevgeniy Dodis and Siyao Guo, *Non-Uniform Bounds in the Random-Permutation, Ideal-Cipher, and Generic-Group Models*, CRYPTO 2018; author full version dated 2023-02-02, introduction and auxiliary-input/lazy-sampling discussion: https://cs.nyu.edu/~dodis/ps/ai-perms.pdf . It explains why oracle-dependent leakage invalidates unconditioned lazy sampling. No auxiliary-input reduction or its numerical constants are claimed here.

These primary sources were opened directly; current discovery used the stronger search engine. The composition lemmas and finite controls are new explicit derivations for the source layout, not conclusions attributed to those papers.


## Independent review and revision record

The first complete draft and its genuine first 18-test PASS are retained separately. A read-only reviewer found that the intended seal-time timing was not explicit enough: per-opening registration just before each check does not imply registration before all audit work. This revision makes simultaneous pre-audit registration part of the experiment and adds an actual immutable captured-path snapshot plus targeted negative controls. The same review had not found an arithmetic error in the noise-key separation, conditional permutation envelope or fixed-d/k comparison. The final static review and executed test receipt are retained with the research evidence; no native timing or production closure follows from them.
