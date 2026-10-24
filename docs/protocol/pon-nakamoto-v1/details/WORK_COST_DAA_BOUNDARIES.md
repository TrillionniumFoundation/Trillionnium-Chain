# Work cost and DAA boundary evidence

This increment makes two existing experimental obligations directly reproducible:
complete cost of the implemented W1 strategies on the same mathematical cases,
and actual native admission of legal timestamp schedules at the current DAA
boundaries. It changes no W1 relation, lottery domain, target rule, default
profile, request budget, timeout or confirmation rule. Cost hardness, an
attacker work fraction, timestamp attack profitability and public network
qualification remain unestablished.

## Complete costs on two retained hosts

Use the existing
[`pon_w1_budget_report`](../../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_budget_report.rs)
native example. Its `pon-w1-same-target-budget-v1` JSONL records actual calling
thread CPU, wall time, public task construction, each producer setup, every
attempt, complete search and total producer time. A missing CPU clock stays
unknown. Setup, search and attempts are nested in the complete total and must
not be added to that total again.

The finite grid retains dense, zero, rank-one and sparse public A/B matrices.
It runs the generic, structured and blocked-zero legal implementations where
supported, and a separate from-zero false-trace producer. Unsupported arms and
finite-budget exhaustion remain in the record. Successful legal arms for a
case must use the same task, target, challenge/nonce stream and exact winning
proof bytes. The false-trace producer starts from public material and does not
first acquire a valid proof. The original complete production, scalar-reference
and limb verifiers observe both legal and false candidates.

The reproducible four-file campaign uses the following existing example flags.
The two native hosts must use the same exact source commit/tree, release
profile, toolchain and declared outer resource constraints. Retain each full
command, exit code, stdout, stderr, binary digest and hardware observation;
building a binary is a separate step from its measured work spans.

| Retained stdout | Samples | Attempts per arm | Receiver replays | Target | Seed |
| --- | ---: | ---: | ---: | --- | ---: |
| `w1-seed1.jsonl` | 3 | 32 | 1 | `7f` followed by 31 `ff` bytes | 1 |
| `w1-seed2.jsonl` | 3 | 32 | 1 | `7f` followed by 31 `ff` bytes | 2 |
| `w1-exhausted.jsonl` | 1 | 2 | 1 | 32 zero bytes | 1 |
| `w1-receiver-budget.jsonl` | 1 | 1 | 1024 | 32 `ff` bytes | 1 |

The zero-target case is a deliberately impossible-hit boundary. The all-`ff`
receiver campaign is a bounded diagnostic of the original service CPU domain,
not a valid new chain target. Its repeated requests are not new proof
production or unique business confirmations. These profiles preserve the
existing cost campaign; they do not alter the separate chain-494 authenticated
multiprocess workload.

The fixed runner
[`run_pon_w1_native_campaign.py`](../../../../scripts/run_pon_w1_native_campaign.py)
requires a clean exact source commit/tree, Rust 1.95.0, offline locked release
compilation and fresh output outside the source and build directories. It
checks the inherited actual CPU quota, memory limit, ancestor restrictions and
nice value before execution. Compiler overrides, including `RUSTC`, Rust flags
and wrappers, are refused. The runner preserves source and hardware observations,
every child command/exit/stdout/stderr, all four raw JSONL files, and a hashed
copy of the binary it actually executes. A compile-only result, missing native
child, output truncation or nonzero exit cannot become successful W1 evidence.
The 600-second build and 120-second per-cost-process caps are outer collection
limits; they do not alter chain service deadlines or grant mutation CPU credit.

```sh
python3 scripts/run_pon_w1_native_campaign.py \
  --out /absolute/new-main-cost-report --target-dir /absolute/build-target \
  --cargo /absolute/cargo/bin/cargo --host-label main --expected-nice 10 \
  --expected-head FULL_SOURCE_COMMIT --expected-tree FULL_SOURCE_TREE
```

Run the same command on `rog` with that host label and its own new output path,
under the same observed 400% CPU quota and 16 GiB memory ceiling. A successful
wrapper does not itself attest host independence or public-network readiness.

[`pon_w1_budget_derive.py`](../../../../scripts/pon_w1_budget_derive.py)
first uses the existing strict raw reader, checks the same raw bytes again,
and binds `results.json` to explicitly supplied source head/tree. Version
`pon-w1-derived-costs-v2` adds the following costs without rewriting historical
raw evidence:

- Each complete legal winner retains actual full CPU, setup, search, attempted
  proof count, per-attempt CPU including unknown samples, proof identity and
  production verifier CPU. A sample minimum is explicitly descriptive.
- Each **fixed implementation** retains every declared seed/sample in its
  class, including all misses, exhausted searches and unsupported setup.
  Aggregate full CPU per attempt and per winner retain their integer
  numerators and denominators. Zero winners produce a null per-winner ratio;
  unsupported cases prevent selection as a complete fixed implementation.
- The lowest observed fixed implementation per class is selected over that
  complete cohort. The report never sums a different fastest implementation
  from each sample into a supposed executable strategy. This observation does
  not add an automatic mining dispatcher or establish the fastest adversary.
- False-trace costs retain full actual setup plus every attempted construction,
  complete production rejection CPU and cooperative receiver settlement. A
  last winning hash trial cannot replace the producer denominator.

Preparation is really reused across attempts within each search. Reusing one
setup across separate searches is **not measured by this campaign**. The
separate setup/search fields expose that remaining amortization question;
they do not turn a projected steady state into a native observation. Common
public-material construction is also reported separately. Full packet/M06/
SQLite admission, socket transport and business confirmations are outside
these raw W1 timing spans.

The optional `--peer-raw-dir` and `--host-labels main rog` comparison revalidates
both raw directories with the same reader. It requires identical source
head/tree, complete declared campaign grids, tasks, targets, methods, attempted
streams and exact winning proof bytes. Missing or exhausted cases cannot be
dropped to improve a host ratio. It pairs actual full CPU/setup/search and
false producer/receiver costs. The hardware and host labels remain external
runner observations; they do not establish different operators, GPU/ASIC
lower bounds, a universal hardware speedup or public mining fairness.

```sh
python3 scripts/pon_w1_budget_derive.py \
  --raw-dir /absolute/main-cost-report \
  --peer-raw-dir /absolute/rog-cost-report --host-labels main rog \
  --expected-head FULL_SOURCE_COMMIT --expected-tree FULL_SOURCE_TREE
python3 scripts/ci/test_pon_w1_budget_readers.py \
  --raw-dir /absolute/main-cost-report
```

The reader counterexamples mutate supplied records only in memory and verify
that the retained native files have not changed. Old v1 derived reports remain
historical observations. Fresh native observations are needed before making a
claim about the current source on either host.

## Original service campaign: complete same-target costs

The original multiprocess service campaign also measures eight legal producer
implementations on its actual first business packet's task, parent and target.
The existing [original campaign reader](../../../../scripts/read_original_native_campaign.py)
now derives `pon-original-native-campaign-work-costs-v1` inside readback-v2.
Raw campaign and phase schemas remain unchanged. The reader binds the original
header, transactions, nonce stream, target misses, winning proof digest and
complete encoded packet digest; it does not independently replay W1 transcripts.

Each implementation retains both cold preparation and **actual four-search
preparation reuse**, with three samples per mode. A complete cohort has twelve
winning searches and nineteen complete legal attempts. The process CPU interval
includes preparation, all misses and winners, allocation, packet encoding and
diagnostic recording. Nested setup/search clocks describe that inclusive total;
adding them again would double count. Independent verification is a separate
interval. The common public workload is fixed; full block preparation, durable
admission, transport and business confirmation are outside these acquisition
intervals. A missing subclock remains unknown and never becomes free work.

The retained [native campaign run 39980481947](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39980481947)
measured source `4e49725f1b457a422dbb12f620101903c21599d7`, tree
`0c2c1cfddc42b23b6f45ad6b4e75bb3dd486d7e6`. Its file-list SHA-256 is
`e75a2d89978341bcae2498ceb7a3930d24d0398771535321aba9b831efcb75c8`;
all 910 listed files / 312,805,891 bytes and the retained binary digest were
checked. The new reader's derivation of those old bytes is not a native run of
the reader's newer source or of subsequent consensus changes.

| Run | Cold generic CPU, 12 winners | Lowest complete fixed cold method | Its CPU, 12 winners | Lowest complete four-search-reuse method | Its CPU, 12 winners |
| --- | ---: | --- | ---: | --- | ---: |
| 1 | 12,548,383 ns | maintenance-limb | 8,147,915 ns | maintenance-limb | 8,127,559 ns |
| 2 | 11,908,507 ns | maintenance-limb | 8,246,068 ns | maintenance-periodic | 8,813,768 ns |
| 3 | 12,130,782 ns | maintenance-limb | 8,285,211 ns | maintenance-limb | 8,174,315 ns |

Selection compares each fixed implementation over its whole twelve-winner
cohort. It never combines the fastest individual samples into a fictitious
strategy. Repeating the same deterministic stream across methods does not
create additional independent work samples. These observations cover a small
development target and one maintenance material; they do not measure a
64-winner reuse horizon, production difficulty, all selectable tasks, GPU/ASIC
implementations, energy or the globally cheapest valid producer.

The separate from-zero arm starts with public A/B and a claimed zero C, then
searches fake transcripts without first acquiring a genuine proof. Each actor
retains 29 hash trials, twelve target hits, complete construction CPU and
separate full rejection CPU. All full relation diagnostics report `Transcript`.
Across these retained cohorts, rejection CPU divided by **complete** false
construction CPU is 5.177922–5.644848. These target hits contribute zero valid
chainwork. This receiver amplification is a service attack cost, not a faster
valid mining strategy.

The original three-run service verdict remains PASS on that exact measured
source and envelope. The independent readback retains 189 submission
observations and 27 confirmation rounds. Eleven of eighteen hostile rounds
overlap observed depletion; it does not relabel all eighteen as continuously
depleted. Earlier failed campaigns remain failed. None of these finite local
results establishes sustainable WAN TPS or independently operated service.

### Effective-work adversary model

For a declared same-hardware CPU budget fraction `q`, and a fixed legal
implementation advantage `s = baseline_complete_cost / alternative_complete_cost`,
the conditional model is:

`q_effective = q * s / (1 - q + q * s)`.

Its half-work budget boundary is `q = 1 / (1 + s)`. This calculation assumes
linear throughput in allocated CPU, the same task and target distribution,
equal availability and no unmodeled network or hardware advantage. Neither
`q` nor network adversarial share was measured. The reader preserves exact
integer ratios and labels these outputs as assumptions. It excludes invalid
from-zero target hits from both valid-work numerators.

| Adversary capability | Relevant authority and cost | Remaining qualification |
| --- | --- | --- |
| Faster legal structure, product reuse or hardware | Full verifier validity and target-derived cumulative work remain required; compare complete fixed producer strategies | Lowest valid cost over all selectable tasks, realistic reuse horizons, accelerators and task-selection incentives |
| Cheap fabricated trace or malformed packet flood | Bounded framing and original admission/CPU owners may reject or cancel; cancellation is not a completed invalidity verdict | Whole request cost, sustained depletion, caller fairness and independent WAN service |
| Valid-work flood with deliberately failing application roots | Valid W1 alone cannot authorize M06 state mutation; original owner still checks parent, context, state and receipt roots | Combined verification/execution cost and honest-service performance on the exact current source |
| Timestamp manipulation or branch withholding | Actual expected target, median-time rules and cumulative verified work select the branch | Effective-work share, legal timing schedules, propagation and confirmation risk; useful-looking output supplies no extra finality |
| Reused or stale task/model material | Exact signed task window, parent, output and consumption owners govern usefulness separately from W1 | Actual installed-parent training, evaluation, release closure and next-task use; mining parity does not establish model gain |

This separates statement correctness, computational qualification and honest
service. The new reader closes complete-denominator and same-input accounting
gaps for retained observations; cryptographic hardness and public qualification
remain open until their own evidence exists. No reward, consensus or activation
flag follows from the sensitivity model.

## Actual PNW1 timestamp and chainwork boundaries

The existing
[`daa_adversarial_schedule`](../../../../trillionnium/crates/trnm-pon-node/tests/daa_adversarial_schedule.rs)
test retains its original endpoint schedule. The additional test opens the
authenticated native state backend and mines two short periods, then three
real branches and their next blocks. Every packet has a complete PNW1 proof,
passes full native work verification and goes through ordinary Node admission.
The original per-packet search limit stays 4096 complete attempts.

All offsets below are seconds after the fixed genesis timestamp. Heights
1–31 on the common branch use timestamp `height` and explicit logical
validation clock `10 × height`. Two short periods put the later branch target
far enough below `pow_limit` that the upper factor-four boundary is visible.

| Branch | Timestamp at height 32 | Timestamp at height 47 | Raw endpoint span | Bounded span | Next target relative to the branch period |
| --- | ---: | ---: | ---: | ---: | --- |
| Ordinary | 320 | 470 | 150 | 150 | unchanged |
| Lower clamp | 32 | 47 | 15 | 38 | floor of `parent × 38 / 150` |
| Upper clamp | 27 | 627 | 600 | 600 | `parent × 4`, below `pow_limit` |

The upper branch's first timestamp is lower than its parent's timestamp 31,
but exceeds the actual preceding median 26. The existing rule constrains the
median of up to eleven ancestors; it does not require every adjacent timestamp
to increase. Its last timestamp 627 is accepted with logical clock 507,
exactly at the original 120-second future tolerance. The next timestamp 628
uses clock 508. These supplied clocks describe a legal finite validation
schedule; the test does not claim elapsed wall time, a live ten-second cadence
or that an attacker can obtain those blocks at a specified work fraction.

At height 48 the independent integer work formula gives, respectively,
31, 123 and 7 required-work units for the ordinary, lower and upper targets.
The test actually activates upper, ordinary and lower branches in increasing
accumulated-work order. The easier upper branch cannot replace the heavier
lower branch. Each branch target comes from its actual retained ancestors,
and work is calculated from the expected target, not the lucky ticket value.

Two additional packets acquire fresh valid PNW1 proofs after timestamp
mutation. A timestamp equal to the parent median fails with `TIME`; one second
beyond the future tolerance fails with `TIME_DEFERRED`. Neither rejection
changes the stored-block count or active state. The exact future packet is
then admitted when the logical clock advances one second and still cannot
replace the higher-work branch. Finally the authenticated database is closed
and reopened; exact retained packet bytes, active state/root, generation and
accumulated work must agree.

## Retention and independent replay

Set `TRNM_DAA_EVIDENCE_DIR` to a **new, nonexistent** directory beneath the
runner's already-created report directory. The native test creates that
directory, writes complete encoded packets and `daa-bounds.json` with
create-only file operations, and emits the same structured observation on
stderr. Existing evidence cannot be replaced. The native temporary database
is not exported. There are 85 admission observations, 84 distinct retained
proof packets and 83 distinct admitted non-genesis packets; the exact future
proof occurs in both its rejection and retry observations.

Each row's `attempts = nonce + 1` is derived from the native producer's bounded
search starting at nonce zero. The retry carries the same value for the same
packet; summing every observation would count that producer search twice.
The Python reader fully replays the retained winning proofs, and does not
recreate every unsuccessful nonce search. Use the separate W1 cost campaign
for actual attempt-by-attempt timing and complete search-cost accounting.

```sh
TRNM_DAA_EVIDENCE_DIR=/absolute/report/daa-native \
  cargo +1.95.0 test --release --offline --locked \
  --manifest-path trillionnium/Cargo.toml --jobs 2 -p trnm-pon-node \
  --test daa_adversarial_schedule -- --test-threads=1 --nocapture
sha256sum /absolute/report/daa-native/daa-bounds.json
python3 scripts/pon_daa_schedule_reader.py \
  --raw-dir /absolute/report/daa-native \
  --expected-report-sha256 RECORDED_NATIVE_REPORT_SHA256
python3 scripts/ci/test_pon_daa_schedule_reader.py \
  --raw-dir /absolute/report/daa-native
```

[`pon_daa_schedule_reader.py`](../../../../scripts/pon_daa_schedule_reader.py)
uses the existing separately implemented Python
[`work_oracle`](../../../../formal/pon-nakamoto-v1/work_oracle.py),
[`contract_wire`](../../../../formal/pon-nakamoto-v1/contract_wire.py) and
[`reference`](../../../../formal/pon-nakamoto-v1/reference.py). It checks the
externally recorded report digest, complete bounded packet inventory, exact
header/proof bytes, original target/median/future rules, chainwork arithmetic,
activation order and reported reopen identity. It then independently recomputes
every retained PNW1 transcript and matrix product. The cheap task/ticket filter
alone cannot satisfy this replay.

The reader has no Node or SQLite admission authority. It does not itself
reopen the database, authenticate a native host, prove source provenance or
measure proof-production hardness. The native runner must bind source,
compiler/binary and raw output identities separately. Counterexamples include
dropped rejections, changed bytes/ancestry/work, edited reopen identity,
mislabelled future admission and a freshly fabricated ticket-valid false
trace. All counterexample changes stay in memory; original native evidence
remains unchanged.

These observations make the current timestamp control range reviewable. A
production DAA replacement still needs an explicit protocol version, time
and network assumptions, oscillation and partition analysis, adversarial work
share simulations and independently reproduced native campaigns. This test
does not switch an existing namespace to a new rule.
