# W1 frozen legal strategy and actual reuse V1

This finite experiment extends the existing PN1 work-cost obligation. It does
not replace W1, the mining dispatcher, admission, target arithmetic, receiver
budgets or the default verifier. Two samples per class are below the unchanged
eight-sample acceptance policy. Passing capture checks cannot qualify the work
profile, economic hardness, independent hardware or public service.

## Frozen executable strategies

The native example compares `prepared-generic` with one fixed
`frozen-public-dispatch-v1`. The second strategy tests these constructors in this
exact order and uses the first supported result:

1. `maintenance-limb` for the exact public maintenance material;
2. `blocked-zero-integer-paired` for zero/zero material;
3. `blocked-one-zero-rank-one` for supported one-zero/rank-one material;
4. `paired-product` as its complete generic implementation.

All structural recognition, unsuccessful constructor probes and selected
preparation execute inside the setup timer. Selection uses public A/B only. No
timing probe, per-sample fastest implementation, hindsight kernel selection or
unrecorded preparation is used. This is an executable comparison strategy,
not a claim that it is optimal. The two strategies must produce identical
challenge, trace, ticket and full proof digest on **every attempt**, including
misses, and identical complete winning bytes.

The fixed grid has five material classes: full-rank field, zero, continuity
maintenance, left-zero/right-rank-one and right-zero/left-rank-one. Targets are
`7f` followed by 31 `ff` bytes and `07` followed by 31 `ff` bytes. Under an ideal
uniform lottery these have success probabilities 1/2 and 1/32 respectively;
that model is not established by this measurement. Actual reuse horizons are
1, 8 and 64 searches, matching the existing policy's requested horizon values.
Every search has at most 4,096 complete attempts. Exhaustion retains every miss
and its cost; it supplies no invented winner, mutation or verifier result.

For each sample/target/horizon, one actual prepared object remains alive through
all searches. A new setup occurs for the other strategy and other horizon.
Within each cohort, search indices have distinct challenge domains. Across
horizons the same search-index prefix is intentionally repeated, enabling
matched comparisons. Those repeated observations are not additional distinct
blocks or independent mining samples. The challenge also binds task, target,
seed zero, sample and nonce. These primitive challenges are not live PNH1
parent/task-window/beneficiary admission evidence.

## Complete measured intervals

Producer cohort CPU/wall includes one real setup, every complete attempted
proof, every ticket calculation, failed searches, binary trial retention and
SHA-256 of every full attempted proof. Trial digest capture is evidence overhead
that a miner need not incur. Hex/JSON serialization, later destruction of retained
buffers, native verification and output I/O are outside that interval. Common
public material construction is recorded separately and never silently charged
once per winner or omitted from the report's scope description.

Every winning proof is verified through four complete entrypoints: production,
independent scalar reference, limb and experimental full-limb. `production` means
the exact measured source's default: after the draft full-limb switch, production
and explicit full-limb use the same arithmetic and are not independent kernels.
Archived transposed-default captures retain their original meaning. Call order rotates
by sample, strategy invocation and search. Returned challenge, task, ticket and
full product must match the exact statement. The reader preserves unexpected
outcomes as semantic alerts and suppresses corresponding cost ratios.

A separate measured diagnostic clones each winner and increments the final
canonical product word modulo q. The trace, task and challenge remain unchanged.
All four kernels must reach `Product` rejection. Each mutation records its
source/destination proof digest, exact offset, old/new canonical word and actual
clone/mutation interval. This interval is separate from original legal mining
and receiver verification; it is not new accepted work. The false-trace campaign
continues to measure its own distinct rejection path.

The reader checks exact field sets, bounded complete framing, all fixed cases,
first-hit stopping, every failed nonce, canonical material/product bytes,
complete proof digests, one real setup, nested timings, strategy probes, all
verifier cases, actual mutation construction and matched cross-horizon streams.
It reports ratios of complete fixed-strategy CPU sums. It never chooses a new
strategy from individual fastest samples, imputes an exhausted winner or divides
a single setup measurement to simulate reuse.

Positive/nested CPU and wall readings are consistency checks only. The existing
clock's sampling endpoints differ slightly, so this reader imposes no invented
strict `CPU <= wall` nanosecond rule. Source/binary provenance, real execution,
clock truth and hardware identity require the enclosing capture receipt. The
reader does not rerun W1; synthetic reader tests deliberately use invented clocks
and native verdicts and are not execution evidence.

## Fixed sharded execution

The exact native invocation is:

```sh
pon_w1_legal_strategy_v1 --legal-strategy-v1 \
  --class full-rank-field --target-index 0 --reuse-winners 64
```

There are 30 shards: five classes, two target indices and three horizons. The
existing runner's explicit `--legal-strategy` mode retains the existing source,
compiler and binary checks, with the original 300-second campaign cap applied
to each fixed shard. Failed shards remain failures while the runner captures
the others. Complete-grid readback requires every shard exactly once; no failed
or inconvenient class/target/horizon may be dropped. The existing false-trace
mode remains separate.

```sh
bash scripts/project-preflight.sh
python3 -B scripts/ci/test_pon_w1_legal_strategy_reader_v1.py
python3 scripts/ci/run_w1_false_trace_reuse_v1.py --legal-strategy --arch x64 --local
python3 scripts/pon_w1_legal_strategy_reader_v1.py /absolute/capture/shard-*.stdout
```

The last command illustrates the complete JSONL input set; use the actual
capture filenames recorded by the runner. A single-shard readback is only a
partial observation. Full grid consistency still leaves two-sample coverage,
unmeasured task families and targets, accelerators, task-selection/funding,
physical energy, quantum costs and live service qualification open. All
qualification and activation flags remain false.
