# W1 preparation V4: complete paid search observations, WP2 HOLD

**The complete capture and its strict readback pass. The cheapest-legal-strategy
work package remains HOLD.** This experiment measures dense/sparse fixed-product
preparation and eager/lazy proof materialization while keeping the complete
FullLimb transcript kernel fixed. It does not qualify an ordinary Hepta Cell,
work hardness, a globally cheapest algorithm, hardware fairness or public service.
It continues the [canonical development plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Delivered implementation and validation

The separate native
[V4 example](../../../trillionnium/crates/trnm-pon-node/examples/pon_w1_preparation_strategy_v4.rs)
uses the existing `legal_attempt::Task::with_preparation` and original PNW1
wire relation. The
[reader](../../../scripts/pon_w1_preparation_strategy_reader_v4.py)
reconstructs the canonical fixed product, binds every challenge, trace digest,
ticket and retained attempt, and requires the complete matched search streams,
original cost denominators, winner bytes and native verifier observations. It
does not itself replay the W1 transcript or authenticate a clock.

The four fixed cells are:

| Cell | Fixed AB preparation | Transcript arithmetic | Proof bytes |
| --- | --- | --- | --- |
| dense-eager-full-limb | Dense | FullLimb | Every attempt |
| dense-lazy-full-limb | Dense | FullLimb | Target hit only |
| sparse-eager-full-limb | Sparse | FullLimb | Every attempt |
| sparse-lazy-full-limb | Sparse | FullLimb | Target hit only |

Every actual attempt computes the entire original transcript and ticket. A lazy
miss omits the 49,188-byte proof buffer; it omits no transcript work. All successful
proofs undergo both production and independently implemented scalar arithmetic
verification. Their separately measured canonical last-product mutations must
return `Product`. Scalar-verifier timings are never used as the producer baseline.

Validation retained in this directory:

- [Nine native tests](native-tests.log.gz) pass, including all six material classes,
  complete proof equality, independent scalar replay, three real misses, first-hit
  stopping, exact external bytes and noncanonical words hidden by a zero product.
- [Twenty-four reader controls](python-controls-final.log.gz) pass. They reject
  removed misses, fabricated setup totals, missing verifiers, altered byte
  digests, false provenance, partial grids, changed shared prefixes and truncated
  archives. These tests use explicitly synthetic timing/verdict fixtures.
- [Release build](native-build.log.gz), [strict release Clippy](native-clippy.log.gz)
  and [format check](native-format.log.gz) pass for this example. These are selected
  component checks, not a full-workspace or hosted-CI result.
- The [initial formatting failure](initial-format-failure.log.gz) remains visible.
  Native build output retains the SQLite boundary warning from the shared build
  cache. No SQLite I/O-boundary qualification is inferred from this W1 experiment.
  Earlier test reruns are not counted as extra independent controls or cost trials.

## One complete 36-shard cost grid and 12 separate controls

The fixed cost grid is six material classes, two targets and reuse horizons
1/8/64. Each shard contains eight sample identifiers and all four cells, with
call order rotated. Every search permits 4,096 complete attempts and stops at
its first hit; actual misses and any full exhaustion remain in its cost.

The materials are full-rank field inputs, zero, rank one, sparse diagonal,
sparse full-field values and the maximum canonical field value. The last class
sets every input word to `q-1`, with `q = 4294967291`; its exact product has every
word equal to 64. Sparse full-field inputs retain every 17th A word and every
19th B word from the checked full-rank recipe. All six classes are diagnostic
fixtures. None supplies an attested encoder-to-feature lineage.

[The execution declaration](v4-cpu-1/declaration.json) records all 48 commands
before execution. [The final manifest](v4-cpu-1/manifest.json) retains their
individual exit, timeout, CPU, RSS and artifact observations. All 48 processes
returned zero without a timeout, all 48 individual readbacks passed, and the
[36-shard aggregate](v4-cpu-1/grid-readback.json) passed exact grid and shared-prefix
checks. No command was unobserved. The per-command limit stayed at 300 seconds.

| Cost-grid denominator | Actual recorded total |
| --- | ---: |
| Actual preparations | 1,152 |
| Searches | 28,032 |
| Complete attempts, including misses | 464,320 |
| Losing attempts | 436,288 |
| Target hits | 28,032 |
| Exhausted cost searches | 0 |
| Native legal `Accepted` calls, both verifiers combined | 56,064 |
| Separate native `Product` refusals, both verifiers combined | 56,064 |
| Proof buffers actually materialized | 246,176 |
| Cumulative PNW1 bytes materialized | 12,108,905,088 |

The byte total measures buffer creation/copying across all actual attempts. It is
neither retained disk bytes nor network traffic. Repeated cells and horizon
prefixes remain real paid invocations, but are not new independent challenges or
credited chainwork. After strategy/horizon deduplication there are **6,144 indexed
search streams**. Eight sample identifiers do not establish confidence bounds or
an adversarial cost lower bound.

The twelve separate controls have a distinct declared purpose and a fixed
three-attempt cap: six near-zero-target exhaustion controls and six maximum-target
first-hit controls. They execute 384 actual preparations, 384 searches and 768
complete attempts: 192 searches exhaust all three attempts, and 192 stop after
one winning attempt. All twelve expected outcomes occur. The reader refuses to
substitute these controls for a cost-grid shard. An unrun opportunity after a
first hit is never fabricated as a failed attempt.

## Observed costs and rankings

[cost-summary.json](cost-summary.json) preserves all 36 per-shard rankings,
integer ratios, paid totals, separate controls and input hashes. The
[summary script](summarize_costs.py) reproduces it from the retained readbacks.
Each ranking sums all eight samples for one fixed strategy. Rankings are
descriptive and selected after observation; no fastest-per-sample oracle or
adaptive best-of-strategies miner was executed.

| Fixed cell | Paid attempts | Producer CPU (s) | Included setup CPU (s) | Materialized PNW1 bytes |
| --- | ---: | ---: | ---: | ---: |
| dense-eager-full-limb | 116,080 | 43.227771 | 0.098380 | 5,709,743,040 |
| dense-lazy-full-limb | 116,080 | 42.291755 | 0.092771 | 344,709,504 |
| sparse-eager-full-limb | 116,080 | 44.521567 | 0.064461 | 5,709,743,040 |
| sparse-lazy-full-limb | 116,080 | 42.146360 | 0.061913 | 344,709,504 |

These are physical sums of paid observations, including repeated horizon
prefixes. They must not be treated as pooled independent statistical trials or
a universally profitable policy. Sparse preparation reduces the aggregate setup
subtotal in this capture; it does not produce a consistent total-CPU improvement.
Lazy proof materialization greatly reduces copied bytes, but its CPU ordering
also varies by class and horizon.

The following endpoints use the fixed target with ideal uniform-ticket probability
1/32. A ratio below one means the indicated sparse cell used less measured producer
CPU than its corresponding dense cell. All intermediate horizons and both targets
remain in the complete summary; these endpoints do not replace them.

| Material | Reuse searches | Sparse eager / dense eager | Sparse lazy / dense lazy |
| --- | ---: | ---: | ---: |
| full-rank-field | 1 | 1.135 | 1.018 |
| full-rank-field | 64 | 1.120 | 0.959 |
| zero | 1 | 0.993 | 0.973 |
| zero | 64 | 0.907 | 1.031 |
| rank-one | 1 | 0.991 | 0.939 |
| rank-one | 64 | 1.049 | 0.943 |
| sparse-diagonal | 1 | 0.974 | 1.058 |
| sparse-diagonal | 64 | 1.050 | 1.012 |
| sparse-field | 1 | 0.981 | 1.028 |
| sparse-field | 64 | 1.087 | 1.007 |
| maximum-field | 1 | 0.924 | 1.005 |
| maximum-field | 64 | 1.040 | 1.039 |

Producer CPU includes the actual preparation, every complete attempt and ticket,
winning proof materialization, eager losing-buffer destruction and retained
binary trial recording. Attempt-digest/JSON-value construction, native validation
and product mutations have separate measured intervals. JSON output, the fixture
generator and retained-buffer destruction are outside the producer interval.
The direct-process `wait4` totals include these native-process costs: the 36 cost
commands used **266.496296 CPU seconds** and **267.946116 observed wall seconds**.
The six exhaustion controls used 0.266300 CPU seconds, and the six first-hit
controls used 0.712819 CPU seconds. Observer compression/readback CPU is outside
those native-process totals. No unknown CPU observation is converted to zero.

The largest recorded direct-process peak RSS is 19,832,832 bytes, including the
spawned process lifetime. This is not aggregate host or process-tree memory, an
application-only allocation measurement, or an original-resource service result.

## WP2 coverage, security assumptions and remaining gates

| Requested dimension | Scope of the new evidence | Remaining obligation |
| --- | --- | --- |
| Preprocessing | Actual dense/sparse fixed AB and prefix preparation, paid once per cohort | Full cost across all legal task-selection policies |
| Reuse across challenges | One real prepared object through 1/8/64 complete searches | Cross-run/persistent-cache attacks and wider preprocessing tradeoffs were not run |
| Low rank | A rank-one input class is included in the four FullLimb cells | No low-rank-specialized producer is timed by V4; an input label is not an implementation comparison |
| Sparsity | Exact sparse fixed-product preparation, including canonical validation and actual index construction | Sparse/structured transcript shortcuts across all eligible materials |
| Batching | No V4 batch producer or complete Cell batching result | Shared-material/grouped implementation costs and service effects |
| Early stopping | Stop after the first ticket hit or complete attempt exhaustion; lazy misses omit only proof-byte materialization | No predictor or partial-transcript shortcut is measured |
| Hardware | One x86_64 native environment; software clocks and executable identity retained | ARM and GPU **NOT_RUN**; no physical energy, ASIC/FPGA or independent hardware comparison |
| Provenance | External exact 16,384-byte canonical A and B files are supported and SHA-256 bound | No ordinary Hepta-origin material campaign was executed; encoder/task eligibility is unproved here |

The existing
[structured producers](../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs)
include checked rank-one, zero, diagonal and tiled implementations, and
[blocked zero paired arithmetic](../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs)
and the [registered producer set](../../../trillionnium/crates/trnm-pon-node/examples/support/w1_cost_producers.rs)
remain available. V4 does not supersede or silently count their observations.
The [historical V3 factorial capture](../../pon-w1-factorial-v3-20261102/README.md)
retains its own measured source and original failures. The separate
[historical grouped-delivery experiment at 3e78206](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3e78206a33c134d9ba5ade143b900e325f6ec37b/evidence/pon-six-experiments-20261105/grouped-delivery/README.md)
belongs to its own source and scope; no result is transferred to these new bytes.

The 1/2 and 1/32 probabilities are the ideal uniform-ticket assumptions for the
two fixed targets. This experiment supplies no proof of uniformity, fastest
classical/quantum algorithm, universal lower bound or live-chain difficulty
security. It evaluates fixed primitive challenges, not current-parent task
eligibility. The original complete PNW1 relation is required for every native
winner. Invalid-input rejection economics remain a separate experiment.

The observed host has `cpu.max = 800000 100000` and `memory.max = 8589934592`:
eight CPU equivalents and 8 GiB. **This microbenchmark does not exercise the
original 0.25-CPU / 2-GiB public-service contract, four-second confirmation SLO
or sixteen-hostile-producer criterion.** No acceptance flag is promoted.

## Source and lossless raw evidence

The execution started from base commit
`b173c1f52d927522af67df30dd08ecfb2e3a1bb0` with working-tree changes. The declaration
hashes 95 explicit inputs: the sampler/readers and complete crypto/protocol Rust
sources with manifests and lockfile. Those bytes and the copied native executable
remain unchanged through the run. This is not a clean-commit or whole-workspace
reproducible-build attestation. Later registration or commits must be checked
against these actual input hashes and must not relabel this as another trial.

The executed native ELF SHA-256 is
`9bf4706966ece8bb5762ef8afe333f076f8c2c160a4917261ad0d81911027beb`.

The lossless archive contains **197 members / 954,889,727 raw bytes**: all 48
original stdout streams and stderr streams, 48 process receipts, 48 readbacks,
the declaration, final manifest, full-grid readback, preflight output and pinned
executable. The [archive index](raw-archive-index.json) binds every member's raw
size and SHA-256. [Independent round-trip verification](raw-archive-verification.json)
checks all members and the complete archive. The 24,549,060-byte compressed stream
is split into sixteen parts, starting at
[part 000](raw-observations.tar.zst.part-000), with a 1.5-MiB per-part cap. The index
preserves their exact order, individual hashes and assembled-stream hash. The original
gzip bytes remain retained in the workspace; historical gzip hashes in the
manifest are transport observations. The published tar preserves the original
uncompressed native bytes, not regenerated equivalent JSON.

Verify without extracting or executing any member:

```sh
python3 evidence/pon-six-workpackages-20261106/strategy/package_raw.py --verify \
  evidence/pon-six-workpackages-20261106/strategy/raw-archive-index.json
```

After extracting the verified archive into a new directory, the reader accepts
the original uncompressed JSONL directly:

```sh
python3 scripts/pon_w1_preparation_strategy_reader_v4.py \
  /new/extraction/v4-cpu-1/*-t[01]-h*/stdout.jsonl
python3 scripts/pon_w1_preparation_strategy_reader_v4.py --single-shard \
  /new/extraction/v4-cpu-1/zero-control-t2/stdout.jsonl
```

Build a new explicitly sourced native executable using Rust 1.95.0 and the
unchanged locked graph, then use [run_campaign.py](run_campaign.py) with an empty
output path for an additional campaign. It preserves the complete plan and every
failed or interrupted process. A further campaign is a new observation, not a
replacement for this retained one.

For external public material, the native selector is:

```sh
pon_w1_preparation_strategy_v4 --preparation-strategy-v4 \
  --class supplied-material --target-index 1 --reuse-winners 64 \
  --model /exact/public-a.u32le --input /exact/public-b.u32le
```

The reader labels these inputs `caller-supplied-provenance-not-verified` and
requires `provenance_verified=false`; an external name, file path or digest
cannot turn this into authenticated Hepta evidence.

Original command logs are stored losslessly as `.log.gz`; their native whitespace and failure output are unchanged. Decompress to the original `.log` names when checking historical command-record paths. The shared [log storage index](../validation/lossless-log-storage.json) binds the original and compressed bytes.
