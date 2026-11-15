# PoN fact reuse and honest-rate continuation — 2026-11-03

Status: **HOLD / NO-GO**. This increment continues the composed PR #688 source
`e1a41026a1b93a6cd3926a60e8af3d97f713ebb6`. It removes redundant input decoding
from existing fact reuse and adds conditional DAA arithmetic observations.
It does not qualify the W1 primitive or public service.

Before publication, the existing branch advanced to
`c39c65b15cde72c30d69dec62ae630a7ebffa3da` with Cell cache-deadline and CI-guard
repairs. This increment preserves that exact parent and all ten concurrent
files. The source-pin manifest combines both reviewed sets of changed pins.
The primitive, lockfile and model input bytes used for the observations are
unchanged by that integration. Combined-source Clippy and source/CI checks are
recorded separately in [integration.json](integration.json).

## Implementation and preserved boundaries

The private borrowed `CheckedProofStatement` checks the current wire length,
version, zero target, canonical C/A/B fields, task and ticket/target in their
original order. Only an invocation that needs actual arithmetic replay decodes
the owned 32-KiB A/B buffer. The independent scalar reference retains its
original three-matrix decode and field re-encoding.

`WorkFactCache` and `ArithmeticFactCache` retain their exact existing keys and
capacity/locking behavior. A hit rechecks the current claim and all required
cancellation points. A different challenge with the same A/B/task requires full
replay. A trace-only fact cannot supply a product, lock contention follows the
original complete verifier, and cancellation cannot publish a new completed
fact. Neither a cheap statement nor a fact is execution authority. This change
does not enable either cache in a configuration that did not already use it.

The new unit controls use real legal proofs, the independent scalar oracle,
callback order and a test-only thread-local count of actual input decoding.
They cover cold/hot reuse, same-task/new-challenge replay, cancellation, waiter
isolation, trace-only upgrades and contention. The count is not a CPU metric.

## Executed local allocation observation

The same [observer](valid_cache_allocation_observation.rs) was separately linked
against the clean baseline and candidate release libraries in **different Cargo
target directories**. Both are Rust 1.95.0, the unchanged locked workspace graph,
default primitive features, and the same observer compile flags. The selected
compiler artifacts, all primitive source hashes, library hashes, observer hash
and executable hashes are retained in [allocation-artifacts.json](allocation-artifacts.json).
The two libraries and two executables have distinct hashes.

Each variant performs 24 measured successful calls over three A/B classes and
two challenges per task. Six independent scalar reference calls, fixture/proof
generation, cache construction, twelve cache-seeding calls, comparisons and
output are outside each allocation interval. Every measured result matches
the scalar challenge/task/ticket/product, and challenge changes perform replay.
The six legal proof fingerprints and all replay decisions match between variants.

| Path | Calls per variant | Baseline requests / bytes per call | Candidate requests / bytes per call |
| --- | ---: | ---: | ---: |
| Raw complete verification | 6 | 15 / 104,448 | 15 / 104,448 |
| Work fact, cold | 3 | 17 / 153,600 | 16 / 120,832 |
| Work fact, warm | 3 | 2 / 49,152 | 1 / 16,384 |
| Work fact, different challenge | 3 | 17 / 153,600 | 16 / 120,832 |
| Arithmetic fact, cold | 3 | 15 / 104,448 | 15 / 104,448 |
| Arithmetic fact, warm | 3 | 2 / 49,152 | 1 / 16,384 |
| Arithmetic fact, different challenge | 3 | 15 / 104,448 | 15 / 104,448 |

All three class observations agree on each listed count. Each affected call
eliminates one 32,768-byte allocation. A warm call's cumulative requested bytes
fall by two thirds. These are successful `alloc`, `alloc_zeroed` and `realloc`
requests; realloc counts its entire new request size. They are **not peak RSS,
retained cache size, CPU savings, throughput or statistical confidence bounds**.
The wrapper's process elapsed/CPU fields include setup and instrumentation;
they are retained execution metadata and are not a per-verification comparison.

Raw rows: [baseline](baseline-allocation.jsonl), [candidate](candidate-allocation.jsonl).
Machine comparison: [allocation-summary.json](allocation-summary.json).

## Honest work-rate arithmetic on one time horizon

The [new model](../../formal/pon-nakamoto-v1/honest_rate_model.py) reuses
`reference.py` for exact target, work and timestamp rules. The installed
16-block/10-second/11-timestamp development configuration and both confirmation
thresholds are unchanged. Exact `Fraction` arithmetic carries incomplete work
through rate changes and outages, and charges the unfinished tail at the horizon.
An observation uses one unit of integrated assumed success hazard per event.

This is a deterministic fluid path, **not a random mining sample and not the
expected trajectory of a nonlinear stochastic process**. All participants being
honest, equal-cost complete legal attempts, uniform independent target hits and
the input attempt rates are assumptions. No actual W1, network, partition,
validation queue, clock anomaly, quantum computation or learned model is run.

The [full 7,200-second record](honest-rate-campaign.json) retains all 2,649 modeled
events, source hashes, incomplete markers, targets and work. The cases share a
time horizon but deliberately have different assumed total attempt budgets:

| Case | Modeled events | Assumed complete-attempt budget | Cumulative required work |
| --- | ---: | ---: | ---: |
| Steady | 720 | 1,440 | 1,440 |
| Fourfold supply, then restore | 699 | 2,880 | 2,854 |
| Quarter supply, then restore | 540 | 1,080 | 1,080 |
| 300-second outage, then restore | 690 | 1,380 | 1,380 |

The initial development target is already at `pow_limit`; the quarter-rate
period therefore cannot regain the nominal spacing by reducing difficulty.
Its conditional event spacing is 40 seconds. In the fourfold-then-restore case,
the marker requested at 4,800 seconds is included at approximately 4,823.151;
the depth threshold is reached at 5,012.952 and the work threshold at 5,082.732.
Both are required, for a modeled confirmation wait of approximately 259.581
seconds after inclusion. The higher attempt budget produces more chainwork
while difficulty recovery changes the block count. Block counts, machine counts
and nominal FLOPs therefore cannot replace the modeled work quantities.

These are conditional arithmetic observations, not network latency measurements
or parameter recommendations. Nanosecond fields are presentation floors of exact
fractions, not measurement precision. Every `finalized`, `execution_authority`,
work-hardness, public-network and activation qualification remains false.

## Validation and evidence scope

Executed on the candidate source bytes:

| Check | Result |
| --- | --- |
| Complete native W1 unit module, all primitive features | 118 passed; 0 failed; 0 ignored; 12 non-W1 tests filtered |
| Existing Python reference | 29 passed |
| New honest-rate controls | 12 passed |
| Existing source-integrity controls | 34 passed |
| Existing PQ source-pin controls | 34 passed |
| Workspace/all-target/all-feature strict Clippy | Passed with `-D warnings`, Rust 1.95.0 and pinned OpenSSL 3.5.9 |
| Workspace formatting | Passed |
| Locked offline Linux all-feature graph | 26 workspace packages; 138 resolved nodes |
| Embedded source inventory | Passed |
| Current source pins | All 372 checked; only the changed primitive and CI entrypoint pins refreshed |
| Existing CI contract | Passed; original head/merge lanes preserved |
| Separate release observer builds and execution | Both completed; all 48 measured calls match scalar results |

The model test is added to the existing `fuzz-smoke` reference lane used for
head and prospective-merge sources; no workflow or resource gate is replaced.
Full workspace test execution, fresh hosted head/merge acceptance, original
four-second service acceptance and an invalid-rejection CPU experiment are not
claimed by this table. Documentation and evidence were finalized after the code
measurements; the precise primitive and model source hashes bind the observations.
Software source/artifact/PID records are not authenticated execution attestation.

The [validation summary](validation.json) and [raw manifest](raw-manifest.json)
preserve commands, successful and failed return codes, logs and hashes. Decode
the [archive](raw-validation.tar.gz.base64) using [restore.py](restore.py) into a
new directory to inspect the exact original streams. Initial sparse-checkout
missing-evidence and stale CI-pin refusals remain failed records; they were
resolved by materializing the existing source and refreshing the one changed
CI pin, then rerunning the unchanged check. The first model-control fixture
selected a marker outside the retarget interval; its marker was corrected,
with no DAA algorithm or threshold change. The initial full local checkout
exhausted disk space; compilation proceeded after space was available again.
No interrupted readback or prepared remote directory is counted as execution.

## Reproduction

Run the repository preflight, then use the pinned toolchain and provider:

```sh
bash scripts/project-preflight.sh
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --lib --all-features pon_work:: -- --test-threads=1
python3 -B formal/pon-nakamoto-v1/test_honest_rate_model.py -v
python3 -B formal/pon-nakamoto-v1/experiments/honest_rate_campaign.py \
  --include-events --output /tmp/new-pon-honest-rate-observation.json
```

For the allocation comparison, use separate clean baseline/candidate checkouts
and `CARGO_TARGET_DIR` values. Build each locked default-feature primitive in
release mode with `--message-format=json`, select its actual library artifact,
then compile the same observer with Rust 1.95.0, `--edition=2021 -C opt-level=3`,
`--extern trnm_crypto_primitives=ACTUAL_RLIB`, and the corresponding release
dependency directory. Inspect each artifact and binary hash before execution.
The raw build/compile records contain the exact observed arguments.

## Remaining acceptance obligations

The prior approximately 20.73 rejection-CPU ratio is not remeasured or closed.
The original failed honest-service outcomes remain failed. Raw fresh complete
verification retains the same allocation count in this observation. No work-
hardness lower bound, cheapest legal implementation, hardware/quantum share
bound, independent operator/evaluator, prospective learning benefit, persistent
external effect, long-term storage funding or public economics is established.
The same [public-readiness requirements](../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md)
continue to apply. No qualification, activation, work credit or confirmation
parameter is promoted by this increment.
