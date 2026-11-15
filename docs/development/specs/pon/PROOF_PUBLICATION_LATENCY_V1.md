# Full W1 proof publication latency V1

Status: **research measurement and screening contract; HOLD / NO-GO**.
Reviewed on the existing integration candidate
`3d1b6507671ec694ce58e86d4063a125c8deeb66`, 2026-11-07 America/New_York.
This implements evidence readers and finite screening, not a new consensus
profile, proof-admission path, prover or asynchronous worker. The sole plan is
[the development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## 1. Preserve the statement and distinguish the clocks

[Full W1 v2](../../../../evidence/pon-w1-full-v2-20261105/README.md) includes the
complete W1 relation and independently supplied expected-artifact commitments.
The older v1 external-binding objection does not describe this v2 observation.
It does not prove a complete raw-text encoder, training run or Cell transition.

The pinned observation records `fresh_proof_pipeline_seconds =
6248.484106799`. This starts after the input fixture is available and includes
preparation/full guest execution, all segment proofs, recursion, source and
checkpoint checks, controller overhead and fresh independent verification.
Build/setup and fixture construction are outside that declared budget.

The same record explicitly has null `post_find_publish_seconds`,
`real_network_propagation_seconds`, `node_admission_seconds`,
`confirmation_seconds` and `stale_block_rate`. It contains one independently
generated successful proof, a separate retained deadline failure, and an older
interrupted UNKNOWN. One hundred replays of the same receipt are verifier
measurements, not one hundred proof-generation trials. There is no complete
attempt-population denominator or prover p99.

Consequently the fresh pipeline fails the original four-second **necessary
on-demand service screen**. It is not itself a measured winner-to-publication
latency, fork loss rate or proof-generation lower bound. The original four-second
confirmation contract is distinct from the experimental ten-second target
spacing in [CONSENSUS C5](../../../protocol/pon-nakamoto-v1/CONSENSUS.md).
Neither quantity is changed here.

## 2. Reproduce the actual stage decomposition

Run from the repository root:

```bash
python3 scripts/read_w1_proof_latency.py
python3 scripts/ci/test_w1_proof_latency_readback.py
```

The new reader first invokes the existing
[retained-proof reader](../../../../scripts/read_w1_full_v2_disposition.py).
Its fixed declaration binds all 13 historical inputs, including the raw archive,
full receipt, expected commitments, failures and UNKNOWN. The new structural
checks also bind each process result to its raw stdout/stderr hashes, require
ordered nonoverlapping monotonic intervals within the original deadline, and
reconcile the endpoint and every interval. Historical byte authentication is
not new cryptographic verification.

| Exclusive part of the recorded fresh pipeline | Seconds |
| --- | ---: |
| Full execution/preparation process | 16.238464345 |
| Initial `reverify-existing-prefix` process | 10.414869301 |
| 43 segment proof processes | 3958.660546294 |
| Complete recursive compression process | 2257.781606805 |
| Fresh verifier process | 0.053977281 |
| Controller and interstage gaps through verified endpoint | 5.334642773 |
| Total | 6248.484106799 |

The initial prefix stage contains zero retained segment receipts. Its name
must not turn its whole 10.415 seconds into prefix cryptographic verification.
The actual later prefix replays are counted separately below.

Segment processes account for 63.3539% of the pipeline and the compression
process for 36.1333%. Nested clocks explain parts of these same intervals; they
are not extra costs to add to the table:

| Nested observation | Count | Seconds |
| --- | ---: | ---: |
| Segment proving API calls | 43 | 3795.495161914 |
| Newly produced segment verification | 43 | 1.067630576 |
| Reverification of existing segment prefixes | 903 | 21.996080820 |
| Recursive lift API calls | 43 | 1138.946912063 |
| Recursive join API calls | 42 | 1112.044486135 |
| Lift/join verification | 85 | 1.913855753 |

The recursive loop enclosing the last three rows is 2253.372330696 seconds.
The inner API clocks include their subprocess/initialization costs; this record
does not isolate pure cryptographic arithmetic, process startup, device loading
or GPU transfer. The 140.101672984-second segment remainder is unattributed,
not proven removable overhead. The CPU of an entire process tree and its peak
aggregate memory remain separately unqualified.

The reader also reports explicit fixed-schedule counterfactuals:

- Setting the recorded segment-process intervals to zero, leaving all other
  intervals fixed, leaves 2289.823560505 seconds.
- Setting only the compression process to zero leaves 3990.702499994 seconds.
- Setting both to zero leaves 32.041953700 seconds.

These are accounting identities, not hardware forecasts, measured speedups or
lower bounds for another implementation. They show why optimizing one dominant
stage alone does not establish a critical-path result.

The old cost vetoes remain: decode/verify median 28,882,359.5 ns versus matched
native median 954,983.5 ns (30.2438 times), and local envelopes 257,429 versus
49,603 bytes (5.1898 times). The envelope is experimental local transport, not
a measured WAN cost. The full report is linked in
[the execution record](../../../../evidence/pon-proof-publication-latency-20261107/README.md).

## 3. Invert the conditional no-competitor model

Let lambda_c denote the explicitly assumed competing eligible-candidate arrival
rate. Under homogeneous independent Poisson arrivals, a fixed complete latency
L has no competing arrival with probability:

\[
P_0(L)=\exp(-\lambda_c L).
\]

For an allowed competing-arrival probability epsilon, the latency screen is:

\[
L\le B=-\log(1-\epsilon)/\lambda_c.
\]

If ten seconds means the competing process's mean interval, lambda_c = 0.1/s.
If it means a total discovery interval and a miner has fixed effective fraction
q, lambda_c = (1-q)/tau additionally needs independent Poisson thinning. An
observed main-chain interval distorted by withholding, proving and discarded
branches cannot silently substitute for raw competitor intensity.

| Competing-arrival budget | Complete latency budget at 0.1/s |
| --- | ---: |
| 0.1% | 10.005 ms |
| 1% | 100.503 ms |
| 5% | 512.933 ms |
| 10% | 1053.605 ms |

At fixed latencies 0.1, 1 and 10 seconds, the corresponding no-competitor
probabilities are 99.005%, 90.484% and 36.788%. These are conditional scenario
calculations. They are not measured stale probabilities, security bounds or
claims that a candidate on an old parent becomes invalid after another block.
The [original cumulative-work rule](../../../protocol/pon-nakamoto-v1/CONSENSUS.md)
still selects only fully validated branches.

Reproduce the illustration without interpreting it as a measurement:

```bash
python3 scripts/pon_proof_latency.py model \
  --competitor-rate-per-second 0.1 \
  --max-competition-probability 0.01 \
  --latency-seconds 0.1 1 10
```

For independent random latency D the exact model expression is
E[exp(-lambda_c D)], not exp(-lambda_c median(D)). Jensen gives
E[exp(-lambda_c D)] >= exp(-lambda_c E[D]) when the finite mean and independence
assumptions hold. This mean-based lower bound does not establish tail latency.

If P(D <= B) >= 1-delta has independently been established, then:

\[
P_0\ge(1-\delta)e^{-\lambda_c B},\qquad
B\le\frac{-\log((1-\epsilon)/(1-\delta))}{\lambda_c},\quad\delta<\epsilon.
\]

For epsilon=1%, delta=0.1%, lambda_c=0.1/s, this gives 90.498 ms. Merely
having p99 <= 100 ms does not establish a total 1% competing-arrival budget:
the unconstrained tail alone can consume that budget. Individual stage p99s
also cannot be summed and called an end-to-end p99. Measure the whole endpoint,
or explicitly allocate tail budgets and apply a union bound.

Under independent representative Bernoulli trials, n zero-exceedance trials
give the exact one-sided upper exceedance bound 1-alpha^(1/n) at confidence
1-alpha. At 95% confidence, 299 zero-exceedance trials are needed for a 1%
bound and 2995 for a 0.1% bound. These calculations do not establish independence
or representativeness. The finite reader deliberately issues no population
confidence or population p99 claim.

## 4. Executable finite campaign contract

[pon_proof_latency.py](../../../../scripts/pon_proof_latency.py) provides a
strict `evaluate` command:

```bash
python3 scripts/pon_proof_latency.py evaluate \
  --policy /path/to/policy.json \
  --observations /path/to/observations.json \
  --expected-policy-sha256 INDEPENDENTLY_RETAINED_SHA256
```

The independently retained policy digest fixes the exact source, relation/profile,
campaign, endpoint, complete trial roster, per-trial header/expected-material
identities, competitor-rate assumption, risk budget and original timeout. A
record cannot quietly widen the threshold, change its statement or drop a
failed trial. Independently retaining a digest is a procedural prerequisite;
this reader cannot prove when a human chose that digest or authenticate clocks.

The two endpoints are `winner-to-publish-ready` and
`winner-to-receiver-validated`. Their ordered phase partition is queue, witness,
prove, compress, local verification, package; the second adds propagation,
receiver queue and receiver verification. Each interval has bounded integer
nanoseconds in one observer monotonic clock domain. Gaps, overlaps, missing
phases, cross-host clock subtraction and restarted deadlines are rejected.
For a remote endpoint, timestamp the authenticated completion acknowledgement
at the original observer; its return transit remains charged. A raw message
saying success is not authenticated measurement. Intervals between observer
notifications do not isolate the receiver's internal phase durations; retain
remote internal clocks separately and never subtract clock origins across hosts.

This phase partition allocates elapsed wall time, not every overlapping CPU
operation. Streaming/parallel work needs a separately retained dependency graph
and resource ledger; end-to-end time remains the authority. No phase may be
declared zero merely because its work ran on another host or before a local
measurement window.

All predeclared success/failure/timeout/canceled/unknown outcomes are retained.
A proof success with no winner event can be recorded as success with null
timing and a reason; it remains UNKNOWN for the latency gate. Only a fully
observed endpoint can pass a finite screen. Any missing or interrupted trial
prevents reporting a success-filtered empirical p99 or mean no-competitor
probability. Late success retains its actual outcome and time but fails its
original deadline. A four-second necessary screen never proves confirmation.

Fixed headers make this schema appropriate for controlled fixed-statement proof
campaigns or an independently closed roster of actual winners. It is not a
live-miner admission policy that knows future winning headers. Live collection
needs a precommitted attempt/entropy schedule and a non-filterable discovery log
to establish that its final winner roster is complete. Starting a stopwatch
on a known fixture does not create a measured mining win. Repeated receipt or
statement trials do not establish independent proof generations.
The roster row count is not an authenticated count of fresh proofs. Identical
observations are retained rather than deduplicated into a smaller denominator;
different receipt bytes also do not by themselves prove independent generation.

Every report retains `disposition=HOLD_NO_GO`, `production_activation=false`,
`consensus_admission=false`, null population p99/stale rate, and explicit false
measurement/cryptographic-authentication flags. Synthetic tests exercise this
contract only; none is entered into historical performance evidence.

## 5. Amortization, queues and batching are separate obligations

C_attempt + p*C_proof describes expected resource cost per attempted lottery
under a declared charging model. It leaves winner critical-path time unchanged.
Costs must include failed proofs, restarts, stale jobs, loading, queue ownership,
and any pre-win speculative proving. Work moved before a win enters attempt
cost; it cannot continue to be charged only on the p fraction of winners.

For proof arrivals lambda_p, m equal servers and service time S, the necessary
capacity condition is rho=lambda_p E[S]/m < 1. It is not a tail bound. Under the
additional M/G/1 FCFS Poisson/IID/finite-second-moment assumptions, residual
service plus work arriving while waiting gives
E[Wq]=lambda_p E[S^2]/(2(1-rho)). One historical fresh pipeline does not identify
either moment or a production capacity requirement.

Waiting for exactly b arrivals without a flush timer gives expected oldest-job
waiting (b-1)/lambda_p and per-job average waiting (b-1)/(2 lambda_p) for Poisson
arrivals. Low winner frequency can make amortized compute inexpensive while
making a batch intolerably slow. Use a bounded queue, absolute oldest-job
deadline, explicit flush and cancellation accounting; do not turn throughput
of large completed batches into a latency claim.

## 6. What the current code suggests optimizing

The current [staged prover](../../../../formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1-staged-prover.rs)
executes 43 lifts and a left fold of 42 joins. Balanced joins could reduce the
join dependency depth from 42 to ceil(log2(43))=6; they still require 42 joins
and 43 lifts. More independent workers need paid CPU/GPU/memory/IO. Single-task
timings observed with eight Rayon threads are not multiworker timings under an
unchanged total resource cap.

A relation-preserving prototype must join only adjacent nonoverlapping ranges,
retain complete segment verification and state continuity, carry pre/input
from the left endpoint and post/exit/output from the right, and finish with the
original full claim, empty assumptions, expected journal and independent v2
artifact commitments. Intermediate receipts never authorize admission. The
same fixed independent verifier must accept new actual proofs and reject
missing, duplicate, reordered and cross-session pieces. A changed control root,
proof kind or verifier parameter set needs a separately reviewed profile.

Persistent process/setup reuse and overlapping execution/proving may help, but
the old API intervals do not isolate removable setup. Source/checkpoint guards
cannot simply be deleted. First measure the relevant intervals under the same
complete relation and fixed resource budget; then compare every attempt and
the whole receiver endpoint. Dedicated trace/hash AIR or another zkVM remains
a separate backend-equivalence and soundness exercise.

The host client is pinned to SDK 3.0.3. Its official
[API client](https://github.com/risc0/risc0/blob/v3.0.3/risc0/zkvm/src/host/api/client.rs)
calls `self.connect()` on each lift/join, and the
[parent process connector](https://github.com/risc0/risc0/blob/v3.0.3/risc0/zkvm/src/host/api/mod.rs)
spawns a backend and waits for its exit for each connection. Thus constructing
one client outside the loop does not itself establish persistent backend reuse.
This identifies a concrete profiling target, not a measured startup saving.

## 7. Asynchronous placement and current research

The [asynchronous settlement boundary](ASYNC_PROOF_SETTLEMENT_BOUNDARY_V1.md)
maps the real M06/Node funding, evaluation, consumption and effect owners.
Native full W1 still gates blocks. Slow computation/proof generation may be
separate jobs; canonical proof-dependent state still requires every validator
to perform the bounded proof checks. A sponsor's signed acceptance is an
explicit owner-authorized trust model, not independent canonical verification.

Primary references checked on 2026-11-07:

- [RISC Zero proof system](https://dev.risczero.com/proof-system/) distinguishes
  composite segment proofs from recursive succinct completion.
- [RISC Zero composition](https://dev.risczero.com/api/zkvm/composition) requires
  conditional-receipt assumptions to be resolved; composition is not free
  completion or independent authorization.
- [Ethereum Foundation security milestones](https://blog.ethereum.org/2025/12/18/zkevm-security-foundations)
  keep real-time execution proving, final proof size and recursion soundness as
  separate targets. Its Ethereum latency definition is not this PoN competitor
  hazard budget.
- [Brevis Pico 3.1 release, 2026-11-05](https://blog.brevis.network/2026/11/05/pico-3-1-128-bit-provable-security-still-real-time-on-4-gpus-now-fully-open-source/)
  reports 99% of its 7200 specified Ethereum blocks proved within 8.73 seconds
  on four RTX 5090s. This is the developer's workload/hardware result, not a W1
  experiment or whole-chain PQ128 qualification. Its CPU/GPU preparation and
  scheduling work informs a comparison plan; its numbers cannot replace ours.

The open scientific/engineering gate is a newly executed, independently bound
complete-W1 backend with measured winner/receiver clocks, acceptable tail and
capacity, and a net verification/transport benefit under the original budgets.
This continuation makes that gate reproducible; it does not mark it closed.
