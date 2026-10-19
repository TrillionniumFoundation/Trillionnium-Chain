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
