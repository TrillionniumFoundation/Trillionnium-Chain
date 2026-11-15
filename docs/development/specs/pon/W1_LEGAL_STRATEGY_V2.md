# W1 eight-sample legal strategy observation V2

This is a separately versioned continuation of the existing PN1 cost experiment
in the sole development plan. It changes no work relation, block or proof format,
mining dispatcher, task authority, target, CPU admission policy, service deadline
or activation flag. Implementation and reader tests do not constitute a native
cost result. Each reported collection must bind its actual complete source,
compiler, locked graph, executable and retained streams.

## Preserve V1 and freeze V2 before collecting costs

The [V1 experiment](W1_LEGAL_STRATEGY_V1.md) remains available with its original
two-sample contract. Its old observations remain two-sample observations. The
same native example now accepts a second exact selector with this fixed mapping:

| Contract | Retained V1 | New V2 |
| --- | --- | --- |
| Native selector | `--legal-strategy-v1` | `--legal-strategy-v2` |
| JSONL schema | `pon-w1-legal-strategy-v1` | `pon-w1-legal-strategy-v2` |
| Samples per class / target / horizon | 2, indexed 0–1 | 8, indexed 0–7 |
| Challenge domain | `pon-w1-legal-strategy-challenge-v1` | `pon-w1-legal-strategy-challenge-v2` |
| Runner mode | `--legal-strategy` | `--legal-strategy-v2` |
| Execution receipt schema | `trnm-w1-legal-strategy-execution-v1` | `trnm-w1-legal-strategy-execution-v2` |
| Complete readback schema | `pon-w1-legal-strategy-readback-v1` | `pon-w1-legal-strategy-readback-v2` |
| Per-shard evidence file limit | 512 MiB | 2 GiB |

All eight V2 sample streams must actually execute. No V1 sample, repeated
verifier call, repeated architecture run or copied output counts as a V2 sample.
The challenge domain is new; task, target, fixed seed zero, sample, search and
nonce remain explicitly bound. Across the 1/8/64 reuse horizons, the same V2
search-index prefix is deliberately reused. Those overlapping searches are not
extra independent samples or issued chainwork. Eight distinct deterministic
sample domains do not prove independent or ideal-uniform SHA-256 lotteries.

Both versions use immutable profiles in the native example and the shared
reader engine. The V1 CLI defaults to V1 and rejects V2 records; the V2 wrapper
accepts only V2 records. There is no mutable module-global version switching,
record-driven auto-detection or relaxed historical parser. Mixed schemas,
relabelled V1 challenge streams, omitted samples and shortened exhaustion fail.

## Unchanged executable strategy and complete accounting

The two strategies remain `prepared-generic` and the existing
`frozen-public-dispatch-v1`, including that dispatcher's existing fixed probe
order and complete generic fallback. Its name does not change merely because
its new observation has eight samples. Recognition, every unsupported probe,
preparation, all attempted proofs and every target miss remain inside the
original strategy cohort timer. The actual prepared object survives all searches
in its frozen reuse horizon. No historical timing result selects a new kernel.

The original five material families, two targets and 1/8/64 horizons give exactly
30 shards. Every sample executes both strategies. Every winner retains complete
proof bytes, all four complete verifier entrypoints and its separately paid
last-product-word mutation. Semantic disagreements remain explicit alerts and
suppress associated cost ratios. All qualification flags stay false.

For a complete no-exhaustion V2 grid, there are 480 actual strategy setups,
11,680 executed strategy searches, 5,840 retained candidate records, 11,680
separately timed mutations and 93,440 native verifier calls. Repeated proof
identities across strategies and horizons are deliberate controls. They are not
93,440 independently mined blocks. The unique search-stream count after matching
overlapping horizons is 5,120. Actual attempts and exhaustion outcomes come only
from captured records; no expected attempt count is substituted for them.

Producer timing still includes binary trial retention and complete proof hashing,
which a miner could avoid. It excludes later hex/JSON output, verification and
retained-buffer destruction. Common public material generation is reported
separately. These scoped intervals are not a physical cost floor, complete process
CPU or the cost of the globally cheapest legal producer.

## Original time and execution budgets

V2 uses the same command owner and exact original limits:

| Boundary | Limit retained |
| --- | --- |
| Identity command | 30 seconds |
| Native release build | 900 seconds |
| Complete native shard | 300 seconds |
| Termination grace | 5 seconds |
| Complete attempts per search | 4,096 |
| Hosted legal lane | 180 minutes |
| Single JSONL record | 8 MiB |

The 2 GiB V2 evidence-file bound is four times the V1 bound because the maximum
complete eight-sample exhaustion stream is four times as large. Parsing remains
line based and bounded; this is not a 2 GiB allocation request. The enlarged raw
evidence envelope is an explicit new research-format limit. It grants no extra
Node memory, Host CPU, service time, attempt budget or receiver credit. The V1
512 MiB bound is unchanged. A timed-out, truncated or oversized observation fails
and remains retained; the runner still attempts the remaining fixed shards.

Neither a successful subset nor an edited last sample can satisfy the complete
grid reader. The original first/middle/last-failure, source mismatch, changed
binary, missing retained binary, compiler override and Cargo configuration checks
apply to V2 as well. Hosted x64 and ARM64 head/actual-merge lanes retain separate
source identities, Cargo graphs and raw artifacts. The original V1 artifact
names remain available; V2 uses a separate `w1-legal-strategy-v2-` artifact prefix.

## Execute and inspect

Freeze the complete committed-clean source before the new native collection.
The original source and compiler checks remain required. For actual local x64:

```sh
bash scripts/project-preflight.sh
python3 -B scripts/ci/test_pon_w1_legal_strategy_reader_v1.py
python3 -B scripts/ci/test_pon_w1_legal_strategy_reader_v2.py
python3 -B scripts/ci/test_run_w1_false_trace_reuse_v1.py
python3 scripts/ci/run_w1_false_trace_reuse_v1.py --legal-strategy-v2 --arch x64 --local
python3 scripts/pon_w1_legal_strategy_reader_v2.py /absolute/capture/campaign-*.stdout
```

Use the actual capture directory and filenames, an explicit external receipt
directory and `CARGO_TARGET_DIR`, as required by the original runner. Native ARM
uses `--arch arm64`. Local runs cannot claim GitHub-hosted context. Hosted runs
require exact `TRNM_EXPECTED_SOURCE_SHA`; both source and binary are checked
before and after execution, including the retained executable copy.

Reader unit fixtures use invented timings and native verdicts. The new suite
checks all 30 complete synthetic byte streams, version/domain isolation, all eight
samples, the eighth sample's full exhaustion, omitted misses, separately charged
mutations, mixed records and interleaved V1/V2 readers. These are parser controls,
not new W1 execution evidence or authentication of clocks.

## Acceptance boundary

A complete eight-sample collection can set only
`policy_sample_count_satisfied=true` for the unchanged minimum of eight. The
acceptance profile bytes and hash stay fixed. It cannot set
`work_profile_qualified`, `hardness_accepted`, `resource_fairness_qualified`,
`public_service_measured`, `independent_hardware_qualified`,
`public_network_ready` or `production_activation` to true.

The five classes and two easy targets are still not all selectable tasks or
production difficulty. Accelerators, wider preprocessing/reuse, task selection,
physical energy, quantum costs, actual public service and model utility remain
separate obligations. A frozen strategy that is slower remains a negative
result. Additional samples do not establish that the compared generic producer
is optimal or that a new consensus-security premise has been proved.
