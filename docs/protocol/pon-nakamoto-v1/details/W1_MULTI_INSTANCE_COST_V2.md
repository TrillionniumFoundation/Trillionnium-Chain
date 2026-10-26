# W1 multi-instance cost research v2

Status: bounded algorithm and conditional query-model result, 2026-10-26.
Baseline before these new files: `635734087e505e065243f6464342e41c48f20f21`.
This supplements [the cost game](W1_COST_SECURITY_GAME.md) and
[the v1 resource reduction](W1_RESOURCE_REDUCTION_V1.md). It does not close
O01, O05 or O07, qualify SHA-256 as a physical work meter, or change any
production relation, authority, difficulty, reward or mining default.

The increment has two substantive results:

1. A new **complete zero-task producer** combines shared Strassen transforms
   with integer-paired leaves. Its proof is byte-for-byte ordinary W1. Its
   explicit scalar-product schedule is smaller than the previously retained
   blocked-zero-paired schedule, while additions and reductions increase.
2. A **compression-query theorem** derives a per-trace query requirement in a
   stated ideal-compression model from the actual 2,049-block message layout.
   It avoids assuming a materialized transcript output and avoids using a
   verifier's work as miner work. Instantiating its primitive with actual
   SHA-256, or converting its queries into a physical resource, remains open.

## 1. Source geometry and available reuse

The unchanged relation is in
[`pon_work.rs`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs).
Noise, trace and PON1 identities use SHA-256, with their literal existing
framing. The following lengths include domain and length framing but exclude
SHA padding; the block counts include padding.

| Message | Bytes | SHA-256 blocks | Relevant dependence |
| --- | ---: | ---: | --- |
| `H_challenge(PNH1 header)` | 343 | 6 | Header nonce is at message offsets 335–342 |
| One noise expansion hash | 66 | 2 | Label at offset 57; little-endian counter at 62–65 |
| `H_ticket(challenge, trace)` | 90 | 2 | Both complete 32-byte values are included |
| Canonical trace | 131,120 | 2,049 | 16-byte domain, 32-byte challenge, 32,768 four-byte prefix words |

The prefix words are not truncated field elements. They are canonical little-
endian values in `F_q`, `q=2^32-5`, after inner-prefix boundaries of eight
coordinates. The digest is the full 256-bit SHA-256 output. The native PNW1
proof has 49,188 bytes and carries the operands, useful product and final
trace digest; it does not carry the 131,072 bytes of prefix words.

**Actual, exact hashing reuse.** For a fixed header except its nonce, the first
five challenge-hash blocks are identical. A cached SHA state after those 320
bytes produces the same challenge as hashing all 343 bytes. This is tested
against the independent wire oracle. Changing a parent, task, target or another
header field requires validating the prefix again; a nonce cache is not a
parent-independence claim.

Every admitted noise counter lies in `0..127`. Its upper two bytes, the only
message bytes entering the second SHA block, are zero. That entire second
block, including padding and length, is identical across challenges, labels and
counters. Its message schedule can be prepared once; its compression **state**
continues to depend on the first block. For one challenge, the first 14 input
words of block one are shared across labels/counters. For one challenge and
label, the first 15 are shared across counters. A conventional SHA round
implementation can reuse those corresponding initial round states. These are
exact implementation opportunities, not a claim that the current hash backend
fails to exploit them or that compressions have constant physical cost.

A trace's challenge is already in its first block. Equal matrix-prefix suffix
blocks under different challenges therefore do not supply equal chaining
states. The executable geometry control verifies this distinction. FIPS 180-4
specifies the padding, message expansion and chaining computation; it provides
no work-cost or temporal-extractability theorem [1].

## 2. A new exact zero-task schedule

The prior
[`blocked_zero_paired.rs`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs)
uses the zero operands `A=B=0` and four independently expanded noise factors
`EL,ER,FL,FR` of shapes `64x8,8x64,64x8,8x64`. For inner boundary `k=0..7`,
write

\[
 S_k=ER[:,0:8(k+1)]\,FL[0:8(k+1),:],\qquad
 L_{i,k}=EL[8i:8(i+1),:]\,S_k,
\]

and `F_j=FR[:,8j:8(j+1)]`. The next canonical prefix tile is exactly
`L_(i,k) F_j`. Emit its 64 entries in row-major order, with outer order
`i,j,k`, which is the unchanged W1 order. This identity holds for every
expanded noise value, including rank-deficient factors; it assumes no
probability or hardness property of the noise.

There are 64 distinct left tiles `L_(i,k)`, eight distinct right tiles `F_j`,
and their complete Cartesian set of 512 products. This is a useful sharing
structure **inside one challenge**. No reuse of random factors between fresh
challenges is assumed.

For an `8x8` tile product, use one or two ordinary seven-product Strassen
levels. Reduce each linear addition/subtraction canonically modulo `q`.
At each even-sized leaf, apply the exact integer identity

\[
 a_0b_0+a_1b_1=(a_0+b_1)(a_1+b_0)-a_0a_1-b_0b_1.
\]

Left-leaf row factors depend only on the left tile and right-leaf column
factors only on the right tile. Prepare the former once per `(i,k)` and the
latter once per `j`; reuse them across all Cartesian products. Strassen's
recombination restores each exact prefix tile. This is a field-exact
composition of established identities, not a new fast-matrix-multiplication
asymptotic theorem [2,3].

Let `d` be the Strassen depth, `s=8/2^d`, and `h=7^d`. The output-stage scalar
product count, including the reusable factors, is

\[
 512h\frac{s^3}{2}+64h\frac{s^2}{2}+8h\frac{s^2}{2}.
\]

| Schedule | Middle `S_k` | Lifted `L_(i,k)` | Output cross-products | Left factors | Right factors | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Existing paired output, `d=0` | 2,560 | 16,896 | 131,072 | 2,048 | 256 | 152,832 |
| One Strassen level, `d=1` | 2,560 | 16,896 | 114,688 | 3,584 | 448 | 138,176 |
| Two levels, `d=2` | 2,560 | 16,896 | 100,352 | 6,272 | 784 | 126,864 |

Depth two saves exactly 25,968 of these scalar products, or
`541/3184` (about 16.9912%). This is an **algorithmic upper-bound improvement
in the declared product metric**, not an adversary lower bound, speedup in
seconds or a 16.99% reduction in total work. Additions, subtractions, modular
reductions, buffers and loads matter. The executable test specifically checks
that the new schedule increases additions, reductions and the sum of all three
counts if their unit prices are equal. Noise hashing, SHA trace work, proof
assembly, validation, transmission and unsuccessful candidates are additional
costs. A native timing experiment must retain slow results too.

The new isolated native helper is
[`w1_zero_strassen.rs`](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_zero_strassen.rs).
Its constructor checks **both complete operands**, rejects malformed lengths
and noncanonical field values, and returns `None` for canonical nonzero work.
It expands all four ordinary noise arrays, obeys the original 128-counter
budget, and streams every prefix tile to ordinary SHA-256. It keeps only one
row-tile's eight left preparations and the eight right preparations; it does
not materialize the complete prefix transcript. A completed generation is
atomic to its caller, whose resource harness must count late work correctly.

This produces valid zero-task *relation* proofs. The caller still needs actual
current-parent eligibility for that task. It is not evidence that arbitrary
miners may authorize zero tasks, that zero work trains a model, or that this
algorithm is fastest among all legal algorithms.

## 3. The precise ideal-compression experiment

Replace **the SHA-256 compression function**, not each whole-message hash, by
one random function

\[
 F:\{0,1\}^{\lambda}\times\{0,1\}^{512}\longrightarrow\{0,1\}^{\lambda},
 \qquad \lambda=256.
\]

SHA padding and iterative message layout remain literal. All domains share
this same `F`. An adversary may query arbitrary chaining values and arbitrary
blocks, not only execute honest SHA calls. It may choose headers/tasks
adaptively, process multiple parents, batch its computations, store arbitrary
query results, start from intermediate states, and perform unlimited free
arithmetic. Such free arithmetic deliberately allows any low-rank or joint
matrix shortcut; **only distinct `F` queries are the resource**.

This is a classical black-box model. Actual SHA-256 is a known, fixed circuit;
its round scheduling, instructions, circuits, ASICs and non-black-box shortcuts
are not made into black-box queries by this definition. Nor is a random
compression function the same object as a whole-message random oracle or an
ideal cipher with Davies–Meyer feed-forward. None of those model changes is
silently granted.

### 3.1 Captured history, references and audit caps

Before sampling `F`, fix deterministic worst-case caps and the adversary class:

| Symbol | Meaning |
| --- | --- |
| `Q_P` | All distinct preprocessing/helper/public `F` queries available to the adversary |
| `Q_A` | Further distinct online queries, across all domains and instances |
| `Q=Q_P+Q_A` | Captured producer-accessible query cap; a repeated input is counted only once |
| `R_d` | Complete 256-bit trace-digest references, including fabricated guesses and losing lottery queries, plus any final submission with no earlier reference |
| `G` | Number of references receiving canonical message openings in the analysis; for an all-opportunities bound, cover every reference that could be valid, not just winning publications |
| `V` | All additional distinct oracle queries needed by that terminal canonical audit, including any missing task/header/noise/trace computations |
| `C=Q+V` | Global query cap used only in the probability error bound |
| `D_0` | Distinct-challenge **canonical** full trace paths captured in preprocessing whose lottery answers were exposed before online mining, including both winners and misses |
| `U_0` | Complete prepared trace paths with lottery answers still unseen; these consume `2,049 U_0` captured preprocessing queries on the good event |

A reference records a full digest value and its time in the captured history.
For the actual two-block PON1 ticket message, a structural observer can record
it **before the second compression response**. The first block has challenge
bytes at offsets 22–53, its trace-length field at 54–57, and the first six
trace bytes at 58–63. The second block has the remaining 26 trace bytes,
followed by fixed padding and the bit length 720. The executable parser
reconstructs and compares both exact padded blocks; partial-prefix matches
or permissive length parsing are not accepted.

At the earliest query of the second block, look up its input CV as a prior
response to `(IV, first_block)`. Outside output-collision `Bad` there is at
most one such first block. If the canonical first block has not yet been
queried, its later response must hit the second query's already registered
CV, itself causing `Bad`. Thus on the good event a later valid ticket-final
query has a unique complete `(challenge, trace)` interpretation available
before that query's response. Count every such candidate query in preparation
and online operation, including misses and wrong trace guesses, and final
submissions lacking a queried ticket. A cap on these observations provides
`R_d`; it is not merely the number of winning publications. The mathematical
observer records intermediate CVs and block bytes; ordinary timing logs do
not automatically expose that history. This parser establishes reference
timing, not the independent predictable-lottery premises discussed below.

Canonical openings use the actual task material and fixed prefix relation.
The audit may compute that material's complete transcript after the producer
stops; that work increases `V` and **never** increases `Q_P` or `Q_A`.
If an audit supplies only `G` final winners, the conclusion concerns those
opened claims. To cap *all* fresh lottery opportunities, set a sufficient `G`
and `V` for all possibly valid references. For example, auditing all `R_d`
references requires accounting for up to `2,049 R_d` trace queries, as well as
any other missing domains. Invalid/unopened references are not automatically
free valid opportunities.

Default advice is independent of the random function, or is a function of
this captured preprocessing transcript. Unlimited hidden oracle-dependent
preprocessing is not captured by an advertised online budget. Section 5 gives
a deliberately weak alternative for a bounded opaque advice string.

### 3.2 The bad event and its probability

For each **fresh distinct** query `(v,b)` at position `j`, register its input
chaining value `v` before returning the new response. Mark `Bad` if the new
response equals any of:

- an earlier fresh compression response;
- an earlier or current query's input chaining value;
- the fixed IV;
- a full digest reference already made before this response.

This includes output collisions, cycles, attempted joins into previously
queried suffixes, and delayed matches to previously guessed trace digests.
A repeated query's unchanged response is not a fresh random draw and does
not create a new bad event merely by repetition.

Conditioned on **each past transcript**, the fresh response is uniform over
`2^lambda` states. The forbidden sets have at most `(j-1)+j+1+R_d=2j+R_d`
elements. Summing through `C` yields the unconditional bound

\[
 \Pr[\mathrm{Bad}]\leq
 \delta_F:=\min\left\{1,\frac{C(C+1+R_d)}{2^\lambda}\right\}.
\]

It is conservative: sets overlap, and many queries/references need not be
relevant. The probability is sampled **before preprocessing**. It is not a
bound conditioned on an adversary-selected favorable initial table, or on
the future event that every later query avoids `Bad`.

### 3.3 Temporal coverage lemma

Consider an opened canonical message and the first time its correct full
digest was referenced. On `not Bad`, every edge of its padded compression
path was queried in captured producer-accessible history before that reference.

**Proof.** Suppose otherwise. On the final canonical path choose its *last*
edge not yet queried at reference time. Its first response occurs afterwards,
either in a later producer query or in the terminal audit. If it is the last
path edge, that response equals the earlier digest reference. Otherwise its
response is the input chaining value of the next path edge, which by choice
of the last missing edge was already queried before the reference. Both
cases cause `Bad`. This argument permits later selection of a canonical
opening and arbitrary earlier wrong guesses. It does not count a terminal
verifier's path construction as producer work. QED.

### 3.4 Disjoint paths and the resource theorem

For distinct challenges the first trace blocks are distinct because they
contain all 32 challenge bytes. On `not Bad`, fresh response values are
injective across distinct inputs, never equal the IV and never close a cycle.
Consequently those complete 2,049-edge paths are simple and edge-disjoint.
If two paths met after different prefixes, their previous distinct edges
would have equal responses; meeting the first edge would require returning
to the IV. Both are excluded. Identical suffix message bytes do not alter
this argument.

Together with temporal coverage, for `m` distinct-challenge valid trace
references in the declared audit set,

\[
 2,049m\leq Q_P+Q_A\qquad\text{outside Bad}.
\]

If `D_0` distinct-challenge **canonical** full paths were already completed
and had exposed lottery answers before the online interval, their edges
cannot serve fresh canonical paths with different challenges.
For `n` distinct new valid trace references in the interval,

\[
 n\leq
 \left\lfloor\frac{Q_P-2,049D_0+Q_A}{2,049}\right\rfloor,
 \qquad 2,049D_0\leq Q_P.
\]

The right side may also be capped by the number of online distinct lottery
references. Pre-exposed winning native work remains a separate initial bank;
pre-exposed misses are not new opportunities. Do not add `U_0` again when its
complete paths are already present in `Q_P`. Different headers that collide
in the challenge hash need a separate binding failure analysis; under the
shared ideal primitive and canonical fixed-length messages, such path
reconvergence is already within the collision/cycle bad event. Actual-SHA
binding remains an assumption outside this ideal experiment.

**No automatic Bernoulli conclusion.** The inequality bounds the number of
opened canonical valid references. A probability bound on mining wins also
requires a predictable valid-opportunity class, task/header binding before
the answer, and fresh conditional-uniform ticket responses. A posthoc
outcome-selected set of `n` valid references is not `n` independent trials.
The two-block parser supplies the pre-answer full-reference condition only;
this document does not prove all remaining lottery premises for the shared
compression primitive, nor replace it with an independent whole-message
ticket oracle. Use the v1 conditional lottery interface only with those
premises explicitly supplied. In particular, do not multiply this count by
`p` or infer a Poisson block-arrival process from the query theorem alone.

This result does **not** lower-bound prefix arithmetic. It proves a query
bound even if a magical free arithmetic algorithm supplied every correct
prefix. There is no materialized-output lower bound, no per-word copying
charge, and no use of an extractor's posthoc computation to pay the miner's
bill. This is the narrow strengthening over the v1 resource interface.

## 4. Partial preprocessing and exact boundary controls

A fully prepared but lottery-unseen path costs no *new* compression query.
A path with 2,048 prepared steps requires only one more. Reporting only a
count of fully prepared proofs loses this distinction.

For an explicitly exposed disjoint bank with prefix lengths `s_j` in
`0..2,049`, its residual completion costs are `2,049-s_j`. Retire previously
exposed lottery paths first. With online budget `B_q`, complete the cheapest
remaining paths, then spend any residual budget on fresh paths of cost
2,049. This is optimal for this specified prefix-completion game because
all completions have equal value one and there is no suffix sharing.
The finite exact implementation is checked against every subset for small
banks. Two prepared lengths `2,048` and `2,047` plus three new queries suffice
for two complete paths; calling this two proofs from three lifetime queries
would be false.

`D_0` cannot retire an arbitrary invalid trace path merely because it was
queried and its lottery was exposed. In the exact control with path length
three, preparation queries two common prefix edges and an invalid final
edge, then observes that invalid trace's lottery. One online query replaces
only the final edge with the canonical one. There is no collision or forward
state guess. The new canonical opportunity exists, while incorrectly retiring
three old queries would report `floor((3-3+1)/3)=0`. The correct canonical
retirement count is zero, giving `floor((3+1)/3)=1`. The code's integer cap
function requires this semantic precondition; it cannot infer canonical
status from a numerical `D_0` alone.

The model includes concrete negative controls:

| Omitted requirement | Counterexample/control |
| --- | --- |
| Different first blocks | Two four-block messages with a three-block common prefix need five distinct queries, not eight |
| No merging collision | Different first blocks that return the same state share the remaining suffix |
| No forward chaining guesses | Query a suffix at a guessed chaining state, then make a missing prefix reach it; the latter response hits a prior query address |
| Temporal full-digest references | Guess a digest before a later audit computes the matching path; audit work is not producer work |
| Full digest equality | A blind one-bit truncated digest has success `1/2`, not the `1/16` success of a full four-bit digest |
| Captured preparation | Initial completed and partial paths can make the online requirement zero or one |
| Actual reference records | A fabricated reference time is rejected by the executable graph observer |

The same-salt and truncated-digest cases describe changes to the declared
model, not vulnerabilities demonstrated in current W1. Current W1 retains
the complete challenge at the beginning of the trace and a full trace digest.

## 5. Oracle-dependent advice and SHA-256 instantiation

If an adversary additionally receives an arbitrary `s`-bit oracle-dependent
advice string whose origins are not captured, a coarse union bound can be
stated. For each fixed advice string, require the same uniform query and audit
caps for the resulting adversary. Union over at most `2^s` fixed strings:

\[
 \Pr[\mathrm{Bad\ with\ selected\ advice}]
 \leq\min\{1,2^s\delta_F\}.
\]

This is not a tight auxiliary-input random-oracle theorem. In particular,
256 advice bits already make ordinary small examples vacuous. It does not
license deleting preprocessing costs from a practical adversary model.
A 256-bit advice value chosen as a target instance's final digest illustrates
why a zero-online-query claim can otherwise evade the intended accounting.
The time at which the instance/salt becomes known is essential.

The literature treats oracle-dependent advice separately because ordinary
lazy sampling cannot simply be conditioned on such advice [4]. A May 2026
revision of Dodis et al. reports an efficient AI-ROM simulation theorem;
only its official abstract/metadata were accessible during this increment,
so no uninspected quantitative theorem is imported [5].

### 5.1 Concrete obstruction to the global Bad-event instantiation

**The global arbitrary-CV Bad bound above is already false as a literal
SHA-256 claim, not merely unproved.** For any 512-bit block `b`, let `E_b`
be SHA-256's 64-round transformation of its eight-word working state before
feed-forward. Each round is reversible using its updated words and the known
message schedule, so `E_b` is a permutation. SHA-256 compression is
`C(h,b)=h + E_b(h)`, with addition independently modulo `2^32` in each word.
Compute `h=E_b^{-1}(0^256)`. Then `C(h,b)=h`. This takes 64 known inverse
rounds, not a `2^256` search. It immediately triggers the global event
“response equals the current query CV.” Even a perfect ideal cipher with
an inverse interface permits the analogous construction in one inverse query.
The same global Bad event therefore cannot be assumed negligible for actual
SHA-256. This known distinction appears explicitly in the NIST authors'
SHA-256 SPHINCS+ analysis, footnote 11, and the earlier fixed-point literature
[12,13].

The independent executable
[`w1_sha256_model_boundary.py`](../../../../formal/pon-nakamoto-v1/experiments/w1_sha256_model_boundary.py)
implements literal forward/inverse rounds and feed-forward. Its
[focused controls](../../../../formal/pon-nakamoto-v1/experiments/test_w1_sha256_model_boundary.py)
compare standard-IV multi-block digests with `hashlib`, check both directions
of every round and the complete permutation, and construct explicit arbitrary-
IV fixed points. It changes neither the ideal-F lemma nor a W1 producer.

**This is not a demonstrated valid W1 shortcut.** W1 starts from SHA-256's
fixed standard IV, includes a bound challenge, uses exact canonical matrix-
prefix blocks and fixes the message length/padding. The chosen `h` has not
been reached along such a legal path. One cannot insert it as W1's IV,
substitute freely chosen message blocks, or charge an invalid path as work.

The next precise target is a **rooted canonical-path** game in a forward-and-
inverse ideal-cipher model. Give each block `b` a random permutation `P_b`;
permit and charge both `P_b(h)` and `P_b^{-1}(z)` queries. Either exposes
compression edge `h -> h+z`. Capture all preprocessing, advice and forks;
count only standard-IV paths obeying actual W1 framing, canonical prefixes
and fixed padding. Bound shortcuts that affect these reachable paths while
allowing unreachable fixed-point edges. An argument must account for inverse
queries exposing an edge without a further forward query, joins into prepared
graphs, and pre-answer lottery interpretation. No usable temporal coverage or
multi-instance lower bound for this revised game is proved here. Excluding
attacker-chosen fixed points by definition would not solve it.

### 5.2 Remaining actual-SHA obligations

For actual SHA-256, the following are still missing:

- A construction-specific **rooted-path** argument preserving temporal
  coverage against the declared non-black-box, preprocessed, multi-instance
  attacker class; the unrestricted global Bad bound is ruled out above.
- A justified conversion from compression-query resources to CPU, hardware
  area-time, memory, bandwidth, energy, or another declared physical resource.
- A bound for adversaries able to exploit simultaneous operations, batching,
  specialized circuits or algorithmic structure inside the fixed compression
  function. Counting a standard compressor's 64 rounds does not prove this.

Recent work on compressed permutation oracles gives results for ideal
permutations/ciphers, including Davies–Meyer preimage and collision games
[6]. Those results do not by themselves prove W1's temporal multi-message
coverage, its canonical-prefix cost, or concrete SHA-256 expenditure.
Thus the new theorem closes a **declared ideal query-model sub-obligation**;
it cannot mark global O01 closed.

## 6. Composition with compressed proofs and useful-work claims

The query theorem can support a future proof layer without pretending that
proof-generation time is an unavoidable charge on losing lotteries. The
necessary composition conditions are concrete:

1. The lottery remains a function of the canonically bound `(challenge,
   full trace digest)`. Proof randomness, encodings and fresh proof nonces
   cannot create extra valid lottery inputs for the same relation instance.
2. Acceptance implies that this digest is the ordinary canonical trace.
   A new succinct proof requires soundness in the joint oracle/adaptive
   environment, with a failure bound for **all** adversarial attempts, not
   only published winners.
3. The canonical task material must remain available for the bounded terminal
   audit. If a zero-knowledge statement hides it and only asserts an opening
   exists, bounded access to an opening must be supplied by a separate
   argument; an unlimited search for a witness can destroy the `V` bound.
4. Economic consumption and block identity must identify the same semantic
   opportunity and enforce their intended scope. A compression-query theorem
   alone cannot prevent paying several proof variants or renewing credit
   across unrelated consumption scopes.

Under these conditions, add the proof system's joint soundness failure to
`delta_F`; no extra per-lottery prover cost is inferred. There is no need for
a costly knowledge extractor solely to recover *publicly available* task
material, but hidden material cannot be declared publicly available by a
soundness claim. This is a limited O05/O07 composition rule, not an installed
ZK backend, consumption mechanism or Hepta quality rule.

The ordinary prepared W1 producers already calculate `A*B` in preparation.
Their remaining proof delivery clones the canonical operand/product prefix
and appends the trace. A producer may compute trace and ticket first, assemble
and publish full PNW1 only on a hit, and retain no full losing proof. Parent
research owns the separate late-assembly implementation; its misses must keep
original trace/ticket evidence, and any later proof reconstruction gets no new
credit. That actual path is stronger evidence than charging a hypothetical
proof to every unsuccessful lottery. The expected cost identity
`trace_cost + p*winner_delivery_cost` requires the stated fresh lottery model;
a complete measured pipeline must include its real finite budget behavior.

PoML's October 2026 preprint formalizes computational-independence assumptions,
but its depth formulation and Appendix F's completed-pair accounting do not
establish W1's resource direct sum. Publishing a proof after a lottery win
cannot make proof generation compulsory for losses. Its separate prover
independence assumption also needs its own support [7].

## 7. Primary research and applicability

| Source examined | What informs this increment | What is not imported |
| --- | --- | --- |
| Komargodski–Weinstein matrix PoUW, v4 / ESA 2026 [8] | Correlated low-rank transcript problem; field and oracle work counted separately | Its construction-specific hardness conjecture is not a proof for this fixed W1 implementation |
| Ball–Rosen–Sabin–Vasudevan, CRYPTO 2018 [9] | A direct-sum theorem is a substantive construction result | Hardness of their low-degree polynomial evaluations does not transfer to arbitrary matrix prefixes |
| Anand–van den Brand–McCarty, 2025 [10] | Structured matrix queries can have different preprocessing/query costs | Worst-case linear-algebra bounds do not prove every miner-selected structured task expensive |
| Solomonik–Blaeser, 19 Oct 2026 [11] | Explicit simultaneous-product algorithms; distinct outputs do not entail independent cost | Their complex-field centering and border-rank approximations are not bit-exact W1 algorithms |

For a concrete finite-size check on [11], its advertised exact-rank construction
for fourteen independent `n^3 x n^3` products has count `(n+1)^9`. At `n=2`,
this is 19,683 for fourteen `8x8` products, compared with 7,168 classical scalar
products. The displayed construction is therefore not an immediate improvement
for W1's `8x8` tile core. Its centering uses real orthonormal embeddings extended
to complex-linear maps; applying it over `F_(2^32-5)` needs an explicit valid
field construction. Approximate border rank additionally needs an exact
recovery argument. Neither finite operation counts nor asymptotic exponent
improvements establish native CPU benefit by themselves.

## 8. Executable evidence and completion boundaries

The independent finite implementation is
[`w1_multi_instance_cost_v2.py`](../../../../formal/pon-nakamoto-v1/experiments/w1_multi_instance_cost_v2.py),
with [focused tests](../../../../formal/pon-nakamoto-v1/experiments/test_w1_multi_instance_cost_v2.py).
It validates every small-instance prefix in original order, complete deployed
W1 proof bytes against the existing scalar oracle, actual executed product
counts at depths zero/one/two, strict invalid inputs, SHA geometry/cache reuse,
and exact query-graph/preprocessing counterexamples. The native helper's own
tests compare all 32,768 prefixes, three complete native proofs and ordinary
verification, plus boundary tiles and strict zero-only construction.

| Sub-obligation | Completion evidence | Remaining boundary |
| --- | --- | --- |
| New relation-preserving algorithm | Independent Python and native full-prefix/full-proof equivalence tests | CPU/energy advantage is unknown until measured under a frozen comparison |
| Scalar-product schedule | Formula equals executed counters, including shared factors | Other costs are larger; no universal fastest algorithm claim |
| Compression-query path theorem | Explicit model, proof, caps and negative controls | Actual SHA instantiation and physical conversion remain open |
| Initial path bank | Exact remaining-cost scheduler and exhaustive small-bank check | Real opportunity/authority lifetimes still require native state semantics |
| Succinct-proof composition | Public material, joint soundness, stable lottery and credit conditions | No new production proof backend, quality rule or consumption authority |

Raw records for this increment live outside the repository in
`w1-cost-raw/next-multi-math-v2`. Failed discovery and tooling observations are
retained. The initial `rustfmt` PATH failure was corrected using the specified
absolute toolchain; no failed build or test is represented as a success.
This work does not investigate hosted CI or activate a deployed network.

## References

1. NIST, [FIPS 180-4, Secure Hash Standard](https://doi.org/10.6028/NIST.FIPS.180-4), 2015; sections 5.1 and 6.2.
2. V. Strassen, [Gaussian Elimination is not Optimal](https://eudml.org/doc/131927), 1969. The executable seven-product identities are stated and verified directly here.
3. R. P. Brent, [Algorithms for Matrix Multiplication, author-hosted abstract and bibliography](https://maths-people.anu.edu.au/~brent/pd/rpb002a.pdf), 1970; cites S. Winograd, *A New Algorithm for Inner Product*, 1968. Only the abstract/bibliography is available at this URL; no full-report theorem is imported.
4. D. Unruh, [Random Oracles and Auxiliary Input](https://eprint.iacr.org/2007/168), CRYPTO 2007; official abstract/metadata.
5. Y. Dodis et al., [How to Simulate Random Oracles with Auxiliary Input](https://eprint.iacr.org/2026/854), received 1 May 2026, major revision of FOCS 2024. Official abstract/metadata only in this review; PDF access failed.
6. J. Carolan and C. Majenz, [Compressed Permutation Oracles Revisited](https://arxiv.org/html/2609.28469v1), 23 Sep 2026; introduction and section 5 model/application scope examined.
7. W. K. Wong, M. Ciampi and R. Sarkar, [Proof-of-Machine-Learning-Inference: Mining Knowledge, Not Hashes](https://arxiv.org/html/2610.26713v1), 19 Oct 2026; Definitions 1/11 and Appendix F examined.
8. I. Komargodski and O. Weinstein, [Proofs of Useful Work from Arbitrary Matrix Multiplication](https://arxiv.org/html/2504.09971v4), v4 13 Nov 2025; [ESA 2026 version](https://doi.org/10.4230/LIPIcs.ESA.2026.2). Model and transcript/noise assumptions examined.
9. M. Ball et al., [Proofs of Work From Worst-Case Assumptions](https://msabin.github.io/files/papers/BRSV18.pdf), CRYPTO 2018; author-hosted full paper used after ePrint PDF returned 403.
10. E. Anand, J. van den Brand and R. McCarty, [The Structural Complexity of Matrix-Vector Multiplication](https://arxiv.org/html/2502.21240v2), 6 Mar 2025; model, Theorem 3 and scope examined.
11. E. Solomonik and M. Blaeser, [Simultaneous Matrix Multiplication by Tensor Contraction Aggregation](https://arxiv.org/html/2610.26563v1), 19 Oct 2026; sections 5.5, 8 and Appendix C examined.
12. R. Perlner, J. Kelsey and D. Cooper, [Breaking Category Five SPHINCS+ with SHA-256](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=935143), NIST-hosted full paper; section 6, footnote 11 explicitly discusses the compression-random-oracle/fixed-point limitation. Its SPHINCS+ attack is not imported as a W1 attack.
13. J. Kelsey and B. Schneier, [Second Preimages on n-bit Hash Functions for Much Less than 2^n Work](https://www.schneier.com/academic/paperfiles/paper-preimages.pdf), EUROCRYPT 2005; author-hosted full paper used after IACR archive returned 403. Fixed-point/expandable-message scope only; no claim of a feasible standard-IV W1 forgery.
