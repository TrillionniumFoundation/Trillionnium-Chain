# Native DAA: adaptive opportunities to weighted work

Status: **conditional resource interface plus native-rule adversarial controls**.
Source baseline: `635734087e505e065243f6464342e41c48f20f21`.
O03 remains open. This refinement changes no consensus, target, clock, work
identity, difficulty parameter, production flag or owner authority. It belongs
to the [sole plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It extends the [chain envelope](W1_CHAIN_SECURITY_ENVELOPE_V1.md) beyond its
fixed-target examples; it does not re-prove a common-prefix theorem.

## 1. The actual rule and the predictable interface

The unchanged [native arithmetic](../../../../trillionnium/crates/trnm-pon-node/src/consensus.rs)
and [Node ancestry/admission owner](../../../../trillionnium/crates/trnm-pon-node/src/store.rs)
use the following rules. The growth backend follows the same parent-first
window and adjustment arithmetic in
[its owner](../../../../trillionnium/crates/trnm-pon-node/src/store/growth.rs).

| Rule | Actual development profile |
| --- | --- |
| Digest space | `M=2^256`; nonzero target `T<=2^255-1` |
| Success and chainweight | Inclusive `digest<=T`; `w(T)=floor(M/(T+1))` |
| Adjustment | Child height divisible by 16; its parent's target times observed/150, floored, then clamped to `[1,pow_limit]` |
| Observed span | Parent timestamp minus the timestamp 15 ancestors behind it, saturating at zero; `max(1,span)` clamped to `[38,600]` |
| Valid timestamp | Strictly above the upper median of at most 11 parent-first timestamps; at most caller-observed `now+120` using wide addition |
| Fork choice | Greater fully validated cumulative work; equal work keeps the current active tip |

For each newly inspected lottery, the complete header, target and validity
instance must be fixed **before its first answer**. The conditional-uniform
lottery assumption, distinct semantic identity bound, and temporal/captured
preprocessing conditions remain obligations of the
[resource reduction](W1_RESOURCE_REDUCTION_V1.md). Different epochs need not
be independent. Parent selection, timestamps, tasks, abortion and withholding
may adapt to every previous answer. All workers and branches share the same
opportunity accounting; an easier branch never resets a budget.

## 2. A theorem for an entire adaptively mined forest

Let the filtration begin before captured preparation, or include an initial
state whose supplied origin and conditional lottery guarantees are justified.
Let `T_i` be predictable, and let `I_i` be the hit indicator of the i-th distinct
fresh opportunity. Assume `Pr[I_i=1 | past]=(T_i+1)/M`. Define

`X_i=w(T_i)*I_i`, `A_k=sum_{i<=k} X_i`,
`eta_i=(T_i+1)*floor(M/(T_i+1))/M`.

The native floor immediately gives `0<eta_i<=1`. Consequently

`E[X_i | past]=eta_i<=1`,

and `A_k-sum_{i<=k}eta_i` is a martingale. This statement allows the actual DAA,
any legal timestamp choices and every adaptive parent or task policy. It also
allows counting complete winners that are later rejected or never activated:
that only makes the bound more conservative than native accepted weight. Each
successful lottery must supply at most one distinct credited native identity;
replays are not additional `X_i`.

**The finite-budget theorem.** Suppose at most `N` fresh opportunities are
available outside a named failure event, including prepared-but-unseen `U0` and
terminal completions. For the capped comparison process,

`Z_k=A_{k wedge N} + N-(k wedge N)`

is a nonnegative supermartingale starting at `N`. For any `d>0`,

`Pr[exists k<=N: A_k>=d] <= min(1,N/d)`.

Indeed a crossing has `Z_k>=d`, so the maximal inequality for a nonnegative
supermartingale applies. Equivalently, monotonicity gives the same bound from
`E[A_N]<=N`. A producer's adaptive stopping does not create another budget.
Add the actual-to-ideal coupling/cap failure probability **outside** this
comparison, never by conditioning the distribution on a future good event.

Let `W0` bound all remaining **weighted** credit of distinct already-revealed
winning identities. Then, for `D>W0`,

`Pr[exists k<=N: W0+A_k>=D] <= min(1,N/(D-W0)+epsilon)`.

A count `K0` alone is insufficient without the weights of its initial winners.
An initial hard winner cannot be replaced with `K0` unit work. Duplicate known
winners are counted once; prepared unseen outcomes belong to `N`, not `W0`.
Initial shared public ancestry may be subtracted when measuring a fork's
extension, but its acquisition cost does not disappear from the lifetime game.
The same distinction applies to a withheld chain that is published all at once.

This bounds **total newly successful work over the whole forest**. Any one
branch composed of those identities has no more new weight. It does not say
that summing several sibling branches manufactures one heaviest branch, that
a block is admitted within the producer deadline, or that honest nodes agree.

## 3. Bounded jumps from actual DAA and initial ancestry

A stronger tail needs a jump bound. Define the exact one-adjustment floor

`g(T)=max(1,floor(38*T/150))`.

If every eligible ancestor descends from an explicitly included initial parent
of height `h` and target `T`, and at most `N` newly generated blocks plus `E`
externally supplied blocks may extend that ancestry, the number of adjustments
up to any queried child is at most

`r=floor((h+N+E)/16)-floor(h/16)`.

Every queried target is at least `g^r(T)`; hence
`Wmax=floor(M/(g^r(T)+1))` safely bounds each new increment. For a forest, take
the smallest floor over all initial parents. The bound is conservative: it
does not claim every timestamp realizing an extreme is reachable on every
history, and it does not charge the caller for nonexistent successes.

**External ancestry is a separate premise.** Attackers may switch to a newly
observed honest parent without paying for all its ancestors. Their own query
budget therefore cannot bound that parent's height or difficulty. If `E` or
the initial eligible-parent bank is unbounded/unavailable, only the global
native bound `Wmax=2^255` is supplied. A useful concentration claim must not
silently substitute the smaller attacker-only depth bound. An old prepared
fork can also begin near an adjustment boundary or already at a tiny target.

For any rational `z>1`, convexity and `0<=X_i<=Wmax` imply

`E[z^X_i | past] <= beta=1+(z^Wmax-1)/Wmax`.

Thus `z^A_k/beta^k` is a nonnegative supermartingale, and

`Pr[exists k<=N: W0+A_k>=D] <= min(1,beta^N/z^(D-W0)+epsilon)`.

The exact target-normalized process

`z^A_k / product_{i<=k}(1+p_i*(z^w_i-1))`

is a martingale when fresh conditional success probabilities equal `p_i`.
Its predictable denominator is path dependent: replacing it with one realized
favorable path's denominator is not an unconditional probability bound. The
uniform `beta` envelope above avoids that error. The Python helper declines
materializing astronomically large exact powers rather than fabricating a
numerical exponential bound. The all-weight `N/d` theorem remains available.

## 4. Legal bookends under MTP11 and skew120

The new [native example](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_daa_resource_research.rs)
is a bounded source-level legality experiment. Its planned history has exactly
36 non-genesis blocks: a common height-30 path and three height-31 siblings,
each with a height-32 child. It uses actual W1 generation, Node admission and
activation, and the original native arithmetic. It does not construct a fake
winning proof or rewrite targets. The caller's observed clock is read from the
system for admission. Through the existing `Settings::development` API it uses
a new valueless genesis 1,200 seconds before startup; this is an explicit new
namespace, not an amendment of a deployed chain. No DAA/time limit is changed.

Relative to genesis `g`, common headers 1..30 use timestamp `g+height`, except
height 16 uses `g+11`. This backdate is legal because the rule compares the
median, not the immediate parent. Height 16's target is determined by height
15's earlier timestamp and the clamp floor; its work is 7. At the next boundary:

| Height-31 choice | Height-16 first timestamp | Raw span | Height-32 work | Total chainwork through 32 |
| --- | ---: | ---: | ---: | ---: |
| `g+31` | `g+11` | 20 -> clamped to 38 | 31 | 173 |
| `g+161` | `g+11` | 150 | 7 | 149 |
| `g+611` | `g+11` | 600 | 2 | 144 |

All three height-32 timestamps are `g+32`, and all are legal under the original
median and future bound at this observation time. The common path has work
135; the three complete branches add a total forest weight 61, producing total
forest weight 196, while the heaviest single branch has 173. These arithmetic
values are predicted by the exact rule model; a raw native execution receipt
must separately establish that the built implementation admits these packets.

The example activates successively the easier, unchanged and tightened branch,
checks actual chainweight/tip readback, and checks replay does not create a new
stored block or work. It retains complete accepted packet bytes and the native
search nonce-derived attempt counts; unsuccessful native proof bytes are not
retained, so this is not a complete producer-cost campaign. A bounded-search
failure aborts and preserves the already emitted prefix, not a successful stub.
The next frozen campaign is responsible for source-bound execution evidence.
The independent `scripts/read_w1_daa_resource_research.py` additionally replays
all 36 retained W1 proofs and reconstructs every target, median/time check,
parent link and weight from the original packet bytes. Node State execution and
the physical clock remain source-bound observations. Its native fixture and
negative controls live in `scripts/ci/test_w1_daa_resource_reader.py`.

The result demonstrates legally different second-epoch weights and allowed
backdates. It does **not** demonstrate a profitable attack, a real-network
reorg, a guaranteed wall-clock production rate, or a violation of the mean-work
bound. Long gaps in publication or historical timestamps are compatible with
these rules; target adjustment alone cannot certify physical task availability
or validated propagation latency.

## 5. Exact finite adaptive policy control

The [Python model](../../../../formal/pon-nakamoto-v1/experiments/w1_native_daa_resource_v2.py)
uses exact native 256-bit targets and rational probabilities. A separate
Bellman control starts after the declared height-30 history. That initial
history is supplied and excluded from the new query count, so its lifetime
cost must be covered by preparation. At height 31 the allowed timestamp alphabet
is exactly `{g+31,g+161,g+611}`; heights 32..34 use `g+height`. Every known parent
remains eligible and every attempt consumes one fresh lottery, including misses.
The model maximizes the tail over this finite policy class only.

For two additional opportunities, reaching 38 new work requires a successful
height-31 block and then the tightened weight-31 child. Its exact probability
is `p31*p32_tight>0`. A fixed-weight-7 binomial calculation would incorrectly
assign zero probability to 38 work. For threshold 9, the optimal second target
is the eased one, with exact probability `p31*p32_easy`. Optimizing one tail is
not the same as maximizing expected work or optimizing a physical algorithm.
An independent two-hit calculation checks both Bellman outcomes. Small-digest
exhaustive controls are labeled arithmetic controls and never native execution.

## 6. Honest service, propagation and settlement remain explicit

A supplied physical resource theorem may map `P,B,advice` into `N(t)` and `W0`;
this document does not prove that map for SHA-256/W1. Fresh conditional-uniform
lottery answers also remain an explicit assumption. Raw CPU ratios do not
supply either assumption or the time profile of adversarial opportunity bursts.

For a private branch containing no new honest blocks, a separately justified
honest visible-work floor `H(t)` and propagation/service lag can turn an excess
work threshold into a necessary private-overtake condition. The error in that
honest floor and the resource/lottery coupling must be added. Applying a bound
at many deadlines requires a time-uniform argument or a declared union budget.
This is not a generic common-prefix proof: general attacks can obtain honest
work on competing branches, alter observed tips and delay publication. Total
honest successful work is not automatically common honest progress.

Closing O03 still needs the actual task availability and verification-service
process, bounded publication/availability delay, honest participation bounds,
all-fork settlement coupling under the native tie rule, and an explicit lifetime
error budget. A safe mean-work envelope alone does not select production kappa,
confirmation depth, a work multiplier, or a protocol emergency policy.

## 7. Primary research and what was actually used

[Wang et al., Securing Parallel-chain Protocols under Variable Mining Power,
v2](https://arxiv.org/html/2105.02927v2), Appendix A and C.1, explicitly studies
difficulty-raising variance and query-indexed weighted martingales. Its chain
results additionally require controlled participation changes and protocol-
specific structure. This motivates using weighted increments and retaining
jump/ancestry bounds here; no Prism, OHIE or Bitcoin settlement theorem is
imported. Our floor arithmetic and budget supermartingale are proved above
for this interface.

[Garay, Kiayias and Shen, Fast Difficulty Adjustment, revised 2026-09-10](https://eprint.iacr.org/2026/1116)
uses parallel chains and approximate agreement according to its official
abstract. The full PDF was inaccessible in this increment; no theorem from it
is imported, and merely shortening this chain's epoch to 16 is not its design.

[Hu, Ruan and Duan, Timestamp Manipulation, v6, 2026-09-11](https://arxiv.org/html/2505.05328v6)
explicitly distinguishes per-block Ethereum-style DAA from periodic epoch
retargeting in section 9.6. Its incentive-attack figures therefore do not
establish an attack on this native periodic DAA. Our bookend vectors are checked
against this repository's rules instead.

The new [exact controls](../../../../formal/pon-nakamoto-v1/experiments/test_w1_native_daa_resource_v2.py)
cover native integer bounds, MTP/future edges, supplied-ancestor counterexamples,
known-bank replay, adaptive capital, two-query DAA tails and the distinction
between total forest weight and heaviest extension. Native execution and
physical lower bounds have separate verdicts; global O03 remains open.
