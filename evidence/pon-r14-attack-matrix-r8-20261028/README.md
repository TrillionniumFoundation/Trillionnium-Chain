# Original r14 attack paths and paid-credit geometry: read-only diagnosis

## Decision

WP2B remains **HOLD**. The original 131f campaign failed all nine service phases:
0/27 planned honest rounds confirmed, including all three attack-free baselines.
The six attack phases did not deplete the receiver's actual paid account.
This directory adds a reproducible analysis of those same bytes; it does not
contain a new native attack, a new profile, a repaired campaign result or a
release qualification. Pure PoN, W1, chain weight, input set, deadlines and CPU
accounting are unchanged.

The additional result is stronger than absence of a sampled depletion: using
every original cumulative debit/refill snapshot, the full-burst constructor and
the settled final snapshot, the **already-debited scalar paid balance** in each
attack phase has a conservative lower bound above 1.959763023 CPU seconds. The
original depletion threshold is 0.1 CPU seconds. This is a bound on the original
accounting trajectory, not on unsampled physical CPU or every possible input.

## Provenance and reproduction

Original native source: `131f673d9563e72aca7139f3239856957d118d49`, tree
`b8bdd87dca3cd6288c38f63848b24b1a2df6a09d`. Original GitHub run:
[40620917256](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40620917256),
job `122594446727`, artifact `12787328109`.

The original artifact is 50,535,162 bytes, SHA-256
`2882b94bb4edc617ecee45b65fe4e3ad9607a8330505e1ccc38ec13933e680f5`.
The three complete reports, every actor attempt and failure, and all receiver
observations remain in that original artifact. See the prior
[original readback](../pon-131f-native-and-pq-readback-20261028/README.md).
The script checks the archive size/hash and each complete report hash before
reading any measurement. It does not execute archive contents or fetch data.

Analysis was executed at `56462db5fae46830581a01a52deaca1e40ba8203`, tree
`2ade68d837ca664a384b283ae83c419e28be0d04` with only this evidence directory
untracked. [Source bindings](source-binding.json) compare the relevant current
source bytes with 131f. The campaign, attack construction, W1, scalar accounting,
public dispatch, admission and Host implementation files used here are equal.
The separately committed History checkpoint optimization is not projected onto
these old runtime measurements.

```sh
python3 -B evidence/pon-r14-attack-matrix-r8-20261028/analyze.py \
  --archive /absolute/path/to/chain-131f-native-12787328109.zip \
  --out /absolute/path/to/new-readback-directory
R14_ORIGINAL_ARCHIVE=/absolute/path/to/chain-131f-native-12787328109.zip \
  python3 -B evidence/pon-r14-attack-matrix-r8-20261028/test_analyze.py -v
```

[matrix.json](matrix.json) preserves each phase, each acquired hostile body
digest, all counts, CPU scopes, honest import records and final flows.
[flow-intervals.jsonl.gz](flow-intervals.jsonl.gz) contains every bound interval
with its original report/phase/sample pointer, exact delta and time bracket.
[Commands and receipts](commands.json) retain argv, exit codes, actual runtime
and both output streams, including the initial wrapper argument-order failure.
That wrapper exited before starting the analyzer; no native work was attempted.
The successful readback took 1.086 seconds wall, 1.044863 seconds child CPU and
145,268 KiB peak child RSS. The 11 parser/accounting controls passed in 0.685
seconds wall and 0.619689 seconds child CPU. Injected records in these controls
are explicitly diagnostic negatives, not malicious network execution.

## 1. All original calls and stage boundaries

Each attack phase had 24 external actor processes. Each actor acquired one
body, retained all actual construction attempts and costs, then repeatedly sent
that body using development identities. Across six phases there are 144 actor
acquisitions, 11,216 client attempts, 11,072 signed relation refusals and 144
client errors. All actors exited normally; zero reached the 480-attempt cap and
zero were killed. These runs therefore provide no kill-cut coverage.

Client refusals are 5,846 `WORK:Transcript` and 5,226 `WORK:Product`. Errors are
125 IO EAGAIN, 18 `FRAME_DEADLINE` and one `PUBLIC_CLIENT_DEADLINE`; all 144
returned after the original window. Every failure stays in the denominator.

Digest matching the acquired request bodies to the receiver observer gives:

| Original path | Attempts / receiver records |
| --- | ---: |
| Client attempt without a matched receiver record | 1 |
| Connection before task: hello / solution / body | 3 / 85 / 14 |
| Task before paid worker dispatch: queue / work terminal phase | 15 / 5 |
| Paid worker dispatch began, complete W1 did not begin | 5 |
| Complete W1 rejected, response frame did not complete | 7 |
| Complete W1 rejected, response frame completed | 11,081 |
| Total client attempts | 11,216 |

There are 11,093 paid worker dispatches, 11,092 native decode starts and
11,088 complete W1 starts/rejections. **Zero matched hostile requests began
Admission/M06.** The server completed 11,081 response frames for W1 refusals,
while clients recorded 11,072 signed refusals. The difference is retained as
late/incomplete client/server observation, not assigned a fabricated one-to-one
pairing. Digest matching identifies a repeated body cohort; it does not create
a unique request identity for every repetition.

The actual constructors and verifier establish why:

- `from_zero()` constructs the correct maintenance matrices, task and encoding,
  but uses zero product and searches a cheap claimed trace/ticket. The complete
  verifier still recomputes the transcript before `Transcript` rejection. This
  is not a header-only refusal, and the resulting W1 relation is invalid.
- `corrupt_product()` starts with genuinely acquired work, preserves its valid
  transcript and changes the **first** product cell. The verifier computes the
  complete product and then returns `Product`. The label `late-product` refers
  to W1's product check; it does not mean a later M06 failure. Moving corruption
  to the last cell only extends the final comparison, not admission execution.

These statements are bound to
[multiprocess_work.rs](../../trillionnium/crates/trnm-pon-node/tests/support/multiprocess_work.rs),
`from_zero` / `corrupt_product`, and
[pon_work.rs](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs),
`verify_with_kernel`.

## 2. Measured CPU and the complete honest denominator

All numbers below are from the original reports. W1 CPU is the inner
`full_work_thread_cpu_ns`; dispatch includes it. The separate Submit `work`
phase brackets are slightly wider and are also retained in the matrix. Do not
add nested intervals. Final paid CPU includes honest and hostile mutation
body/decode/dispatch/response work and final settlement. It is not attack-only
CPU or an exact in-window rate.

| Run / mode | Calls | Full W1 starts | W1 CPU seconds | Hostile dispatch CPU seconds | Final receiver paid CPU seconds | Final paid balance seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 / from-zero | 1,958 | 1,936 | 2.067087411 | 3.643692791 | 4.111180881 | 1.999567925 |
| 1 / late-product | 1,796 | 1,774 | 2.297271970 | 3.809102629 | 4.242366695 | 1.997247186 |
| 2 / from-zero | 1,992 | 1,971 | 2.103670764 | 3.692842657 | 4.141152923 | 1.998667039 |
| 2 / late-product | 1,738 | 1,719 | 2.249696896 | 3.750730568 | 4.188798636 | 1.993800319 |
| 3 / from-zero | 1,968 | 1,947 | 2.069474263 | 3.627595267 | 4.065892561 | 1.998094811 |
| 3 / late-product | 1,764 | 1,741 | 2.260371373 | 3.774042509 | 4.220796110 | 1.999380818 |

The independent History verifier has a separate cold CPU account but shares
the same physical 0.25-core public Host. Reactor, authentication and other
non-mutation work also use that physical Host. Whole-parent CPU must not be
debited to the receiver account, and receiver plus History account balances
must not be merged. No callback count is interpreted as CPU.

| Original honest requirement, all nine phases | Observed denominator and result |
| --- | --- |
| Three signed rounds per phase, scheduled at 1 / 5 / 9 seconds | 0 / 27 confirmed; nine first-round failures, 18 unobserved later rounds |
| 21 business packets per phase | 63 / 189 submitted; all 63 got timely signed responses |
| Every actual History network request | 24 / 24 timely responses |
| Every actual local History import | 15 / 24 succeeded; nine `PUBLIC_REQUEST_DEADLINE` failures |
| Complete History before confirmation | Every returned page held one packet and `complete=false` |
| Actual confirmation calls after complete import | Zero |

Each original phase uses one 30-second deadline, including History replay.
It is not renewed on each page. After the first failed confirmation the
campaign stops issuing later rounds, which remain unobserved planned work.
The three baselines each imported three of four returned pages successfully;
the six attack phases each imported one of two. Timely network response or
timely Submit acceptance is not confirmed business completion. None of this
is evidence of service success during depletion.

## 3. Exact scalar-account argument

Let `B=2,000,000,000 ns` be the fresh campaign credit, `R=100,000,000 ns` the
owner start reserve, `F` cumulative **credited** refill, `D` cumulative actual
CPU debit and `S` cumulative settlement discard. Let `P` be remaining paid
credit and `U` booked start/termination principal. The implementation requires:

```text
P = B + F - D - S
stored_credit = P - U
D = live_debited_cpu + settlement_residual_cpu
```

The original `paid_depletion()` additionally requires a known available account,
zero clock failures, `P < R`, `D > B-R` and original full-burst initialization.
Here every settlement discard is zero, so genuine depletion would need
`D-F > 1,900,000,000 ns`, not simply cumulative CPU above two seconds.
Reservation principal is not CPU. `discarded_refill_ns` was never credited and
must not be subtracted from `F` a second time.

For consecutive exact flow snapshots `i,j`, cumulative `F,D,S` are monotone.
At any intermediate **accounting** state:

```text
P(t) >= P_i - (D_j - D_i) - (S_j - S_i)
```

The script validates every identity, monotone counter, ordered nonoverlapping
sample time bracket, known clock and account. The source's fresh `new()` and
recorded initial meter establish the prefix; `final_actual_flow` follows
sampler join and `service.finish()` and has zero owners, reservations and
unsettled known CPU. Its paid debit equals both settled full CPU and the final
service metric, closing the tail. Missing/unknown/contradictory records fail
the readback rather than being dropped. Neither uniform sample intervals nor
a continuous physical CPU bound is assumed.

| Run / mode | Original samples | Worst original sample pair | Minimum conservative paid-balance bound, CPU seconds |
| --- | ---: | --- | ---: |
| 1 / from-zero | 373 | 51 → 52 | 1.960984060 |
| 1 / late-product | 345 | 67 → 68 | 1.961936241 |
| 2 / from-zero | 357 | 2 → 3 | 1.960639215 |
| 2 / late-product | 364 | 13 → 14 | 1.962404262 |
| 3 / from-zero | 363 | 54 → 55 | 1.960025650 |
| 3 / late-product | 356 | 53 → 54 | 1.959763023 |

This excludes a hidden dip below the original paid threshold **in these
recorded, known-accounting runs**. It does not bound CPU not yet sampled or
prove the implementation cannot exhaust with a different legal input. An old
meter snapshot also does not predict a later `reserve()` result, which first
refills at its current time.

## 4. Why the current geometry does not give a sustained drain

The fixed parent provides `25000/100000` CPU, with `cpu.max.burst=0`, and the
mutation account refills at 0.25 CPU seconds per wall second. In an ideal
timely-accounted model the receiver's paid subset cannot sustain a rate above
the entire Host's 0.25 CPU/s supply. Other public work uses some of that supply.
Adding actors or making W1 more expensive alone does not create a sustained
`paid_rate - refill_rate > 0` advantage. Service can still fail from physical
CPU, owner, queue or History work while the bucket stays nearly full.

This is **not an impossibility theorem** for actual depletion:

1. `charge_live` refills/clamps before debiting a measured interval. A long
   nonpreemptive interval may discard refill while the balance appears full,
   then deliver a large real debit. A reachable original input and real CPU
   measurement are required to establish such an attack.
2. Quota applies by periods, not every arbitrarily aligned short interval.
   Two ideal edge periods alone permit a 50 ms allowance; actual scheduling
   overshoot and clock errors have not been bounded for all executions.
3. Scoped-worker CPU arrives through actual joins and settlement. Delayed
   debit, distinct clock boundaries and owner termination must stay accounted.
4. Integer refill truncates less than one ns per update. Equal nominal rates
   are not a proof of zero cumulative rounding loss. Call counts may bound that
   rounding error; they do not measure completed work.
5. A fresh full receiver bucket differs from a cold zero-credit History epoch.
   The latter cannot replace the original full-burst acceptance condition or
   establish restart invariance of the former.

See the existing, unchanged
[Host applicability analysis](../pon-history-owner-next-20261027/HOST_BUDGET_APPLICABILITY.md)
and [scalar_cpu.rs](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs).

## 5. Next reachable loads, with their evidence requirements

The first useful candidate is **complete valid W1 followed by a deliberately
wrong state or receipt root**. Use a legal parent, target, timestamp,
transaction-root and transactions. Modify the claimed state/receipt root
before acquiring W1 so that the entire work statement still passes. The public
path performs paid canonical decode and context checks, complete W1, then
`admit_shared_checked`; detached admission executes M06 and compares output
roots before persistence. A correct observation must show full Work accepted,
Admission refused, real signed `ROOT` responses, exact owner/child CPU and no
hostile durable packet after live inspection and cold reopen. A parser failure,
old-parent rejection, cancellation or W1 refusal does not satisfy this cohort.

There is already a `valid-work-root` constructor and separate supplement in
[public_v3_multiprocess.rs](../../trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs).
It changes `state[0]` before fresh work acquisition. **Its current supplement
calls `phase()` directly, rather than the original campaign's
`phase_host::run()` launcher.** It cannot silently inherit the fixed-Host claim.
A new explicit selector must preserve actual external actor acquisition,
receiver/History Host placement, full original deadlines and all honest rounds.
No such native rerun is performed here.

The prior actual ROOT supplement at source
`96a98a635def8c13b2d4f234aa1daee59c57afa0` did demonstrate real depletion on its
different 4-core / 16 GiB common-controller environment: 9.399693107 CPU seconds
paid, 7.468604691 credited, final paid balance 0.068911584; 23 signed ROOT
responses inside the first round; 0/3 planned honest confirmations. Hostile
packets were absent after live inspection and cold reopen. Its
[original retained summary](../pon-upgrade-implementation-20261018/native-rounds/pn-convergence-20261023/closure-receipts/pn1-root-final-readback-summary.json)
keeps `original_campaign_qualified=false`. This establishes reachability in
that older environment; it is not evidence of depletion or restored service
on r14's 0.25-core Host or the present source.

Additional distinct cohorts may use a maximum legal transaction batch with a
valid prefix and a last invalid business transition, or a wrong final root
after all valid transitions. Actual rejection order must be observed: parallel
validation may discover a purportedly late defect earlier. Complete valid
side branches are a separate ledger-growth threat and can be admitted; they
are not malformed rejection tests. Replaying one cached acquired body and
churning distinct valid W1 identities are also different cohorts. Retain each
producer's actual preparation/search CPU and memory, all attempts, work IDs,
replay-priority behavior and all server responses. No artificial CPU burn,
credit write or callback counter can replace any stage.

## 6. Resource-profile proposal for review only

Keep the original r14 inputs, all its failures and its profile ID. A separately
named research profile may put receiver refill below the physical Host quota.
This changes the declared service allocation and requires a fresh profile /
domain; it is not a retroactive repair of the old measurement. The receiver and
History account bindings must be explicit because refill is a common source
constant today. No constant or profile is changed in this directory.

With the same `B=2`, `R=0.1`, a sustained actual paid rate `a` and new refill
`r`, the ideal drain time would exceed `1.9/(a-r)` seconds, for `a>r`. Choosing
`r=0.125` and assuming all Host CPU is paid gives an optimistic 15.2 seconds.
The old whole-receiver paid totals divided by 30 seconds are only about
0.1355–0.1414 CPU/s, and include honest work and settlement after the window.
Those are not observed pure attacker rates. Substituting them gives roughly
116–181 seconds at refill 0.125, outside the original window.

An explicitly reviewable research point is refill 0.05 CPU/s with the same
Host, burst, reserve, workers, original honest workload and deadlines. The same
counterfactual rate substitution gives about 20.8–22.2 seconds; this is
arithmetic, **not an observed feasible attack or a selected production rate**.
It may still miss the predeclared honest/depletion overlap, and lowering a
budget does not reserve physical CPU or provide fairness. A front-loaded
pressure phase, if studied, must have a fixed preregistered schedule and retain
all later planned honest work, not start the measured window opportunistically
when depletion happens. A larger-Host budget-stress profile has different
physical threat assumptions and cannot qualify the original Host either.

The next decision therefore needs two separate facts: whether full valid W1
and later M06 work can sustain the declared attack under its real producer
cost, and whether all original honest work succeeds during **measured** paid
depletion under an explicitly frozen resource allocation. Neither is replaced
by this diagnostic. Independent operators, multi-day WAN, all kill cuts and
restart-without-new-credit evidence also remain outside this readback.
