# Future-tip scheduling: actual native counterexample and repair

A valid future-dated tip could stop the ordinary wall-clock miner even when the
original consensus median already allowed a successor at the real current time.
The old scheduler required `now > parent.timestamp`; admission requires
`candidate > upper_median(first 11 parent-first timestamps)`. Those conditions
are different. This lane retains an actual failing native execution before the
repair and the same unchanged regression passing after it.

This is a local honest-work/liveness defect. The ancestor packets were genuinely
valid W1 packets, not false traces that acquired work authority. An actor that
mines a permitted future tip can potentially suppress an affected honest
scheduler while continuing with a different legal scheduler. The experiment
establishes the bounded local suppression below; it does not measure a public
network attack, a 60-second outage, attack profitability or an effective-work
majority.

## Actual native observations

Both programs use the existing development Node, real SQLite stores, ordinary
full W1 verification/admission/activation and a signed queued PNX1 transfer.
They use the real local clock, not `--logical-now`. The regression itself is
byte-identical between baseline and fixed execution.

Let `w` be each test's actually observed starting wall time. Genesis is `w-100`.
The first case builds three admitted ancestors at `w-80`, `w-70`, `w+60`; the
four-entry upper median is `w-70`. The second builds them at `w+60`, `w+61`,
`w+62`; its upper median is `w+61`.

| Case | Configured miner runtime | Baseline observation | Fixed observation |
| --- | --- | --- | --- |
| Valid future tip, past upper median | 2 seconds | 0 searches, 0 work trials, 0 activations; runtime stop; required activation assertion failed | 1 search, 2 complete work trials, 1 admitted/activated block, 1 included signed transfer; block-limit stop |
| Genuinely future upper median | 150 milliseconds | 0 searches/trials/activations; queued transfer retained | 0 searches/trials/activations; queued transfer retained |

The baseline command exited **101**, with **1 passed / 1 failed**. The fixed
command exited **0**, with **2 passed / 0 failed**. The positive fixed case also
asserted that the winning header timestamp equalled the recorded real wall
seconds, was below its immediate future parent's timestamp, and was above the
median. It independently verified the complete winning W1 proof, observed the
pool row as `SequenceConsumed`, closed the Node, reopened it and compared exact
active packet bytes. The negative case rejected any attempt to enter search.

The actual old positive report retained `actual_elapsed_ns=2000089548`. The new
positive report retained `actual_elapsed_ns=16135773`. These are descriptions of
two different real-clock runs and challenges on a shared host, **not a throughput
or computational speedup comparison**. The fixed program stopped after one
block under the unchanged two-second configuration. No deadline, attempt limit,
work relation or target was relaxed.

The complete raw observations include all ancestor packet bytes, the positive
queued transaction, the active packet, reports and events:
All stdout/stderr logs are stored losslessly as gzip, preserving original blank
lines and avoiding the generic generated-log ignore. Process receipts retain the
actual uncompressed execution paths; archived payloads are the same exact bytes.

- [Baseline stdout](capture/before-native-run.stdout.log.gz), [complete stderr](capture/before-native-run.stderr.log.gz) and [actual process receipt](capture/before-native-run.process.json).
- [Fixed stdout](capture/after-native-run.stdout.log.gz), [complete stderr](capture/after-native-run.stderr.log.gz) and [actual process receipt](capture/after-native-run.process.json).
- [Observation index](observation-summary.json) derives a readable subset and packet hashes from those exact stderr records. It is not an independent native replay or replacement receipt.

## Narrow production change

The existing upper-median operation was factored into one crate-local helper.
`check_time` still checks an unknown parent first, then the same strict upper
median, then the same `u128` future-skew bound. The first eleven timestamps,
genesis inclusion by the caller, upper median for an even-length window and
`UNKNOWN_PARENT` / `TIME` / `TIME_DEFERRED` order are preserved.

The miner now asks the Node whether its actual wall timestamp exceeds that
median on the actual selected parent branch. The Node reads ancestry afresh
under the existing owner lock. Readiness does not grant admission, execution,
state or work authority. Parent/generation fencing after search and complete
ordinary verification/admission/activation remain in place. A genuinely future
median still waits; the scheduler does not advance a logical clock.

The current helper reuses ordinary `recent()`, whose read bound is
`max(retarget_interval, 11)`, before taking the first eleven timestamps. These
fresh reads are additional local readiness work, not an asserted throughput
improvement. This does not add permanent-account-growth mining support; the
existing ordinary pool miner still has its existing complete-State dependencies.

The [existing continuous-mining specification](../../../docs/protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md)
now states this scheduling rule. No alternate plan, new work primitive,
Hashcash gate, stake weight, evaluator weight or consensus profile was added.

## Source and executable binding

| Role | Actual measured source commit | Tree |
| --- | --- | --- |
| Supplied production base | `7da4964d02b42076996e89a78d13f68572d33be5` | `c7609a5502641739505862f2e4cd3c1e06ce1041` |
| Baseline with corrected test fixture only | `c69749680d7fd8dd2334d284f0e9a6823cf38a18` | `5321fe46bc7b0e7d589e402c92e1b403d825da93` |
| Fixed native/control execution | `298ecbaf08db571f98253e38fb6aed9c18146006` | `054cd8338c9df2f530cdeefa3f9543b15876d75a` |

[Base-to-baseline patch](source/base-to-baseline.patch.gz) changes **only the new
integration test**. Production code is unchanged at the baseline. The
[baseline-to-fixed patch](source/baseline-to-fixed.patch.gz) contains the narrow
median/readiness repair, added timestamp assertions in the existing consensus
test, and the CI registration/negative control. [Source comparison](source/identity.json)
binds both trees, the identical regression file, unchanged Cargo manifests and
lock, unchanged crypto subtree, unchanged header/work identity source, unchanged
consensus arithmetic prefix and preservation of every original CI selector.
The supplied base is an input identity, not a native execution by this lane.

Both integration executables were copied to frozen paths before execution and
hashed before and after execution. The exact frozen bytes are retained as gzip:

| Executable | Raw bytes | Raw SHA-256 | Retained object |
| --- | --- | --- | --- |
| Baseline | 11,359,024 | `bb3eccd67c1866bef617079310f6e5c2ea93a8ef744e09480df9e61f2b107db5` | [before-native.gz](objects/before-native.gz) |
| Fixed | 11,358,016 | `bd6e4d90003c273d29e3f18ef944d2b3b3e1399520a00bd8c8ae19c569a24194` | [after-native.gz](objects/after-native.gz) |

Each compressed file is below 4 MB. The gzip payload hashes were verified before
removing the redundant uncompressed copies. No executable was substituted after
measurement. [Binary metadata before](capture/before-native.binary.json) and
[after](capture/after-native.binary.json) retain their actual build/frozen paths.
Those transient execution paths are not claims that the old raw files still
exist. The larger existing unit/control and CLI binaries have exact
[before](capture/existing-native-controls.binaries-before.json) and
[after](capture/existing-native-controls.binaries-after.json) digests, but their
bytes are not archived here.

The actual capture helper is [capture_process.py](capture_process.py). Each
successful build and each native execution after the initial setup attempts
retains before/after hashes for **1,267 tracked inputs**: the native workspace,
`config`, and three CI contract files. Every listed file was present, scope diffs
were empty, and these input records were identical before/after each recorded
process. The full records are in `capture/*.source-before.json.gz` and
`capture/*.source-after.json.gz`; they retain commit/tree as well as file hashes.

This was an explicitly **sparse checkout**. Historical evidence outside the
selected paths was omitted to conserve shared disk. These bindings are not a
full repository inventory, an entire build-input/host attestation, a remote
merge-head guard or a full Markdown-link verdict. The retained test depfiles
are not represented as a complete dependency closure. In v1 capture records,
`binary_unchanged` compares optional before/after records; for Cargo/Python/shell
commands both records are null, so that field alone attests no executable.
The native execution records have actual non-null binary records and matching
hashes. Resource fields do not establish exclusive-host or deployment limits.

## Failed setup attempts remain visible

| Retained attempt | Actual outcome | Scope |
| --- | --- | --- |
| [Initial offline stderr](capture/before-build.stderr.log.gz) | Missing `risc0-zkvm` index/package information; exit 101 observed | No native execution; no full process/source receipt was retained for this first shell attempt, and none is reconstructed |
| [Initial online build](capture/before-online-build.process.json), [stderr](capture/before-online-build.stderr.log.gz) | Source `fdb8b2b4346d18a19db6d875a6eba0a76bd1715b`; four private `Settings::encode_packet` compile errors | Test setup failure, not the production liveness counterexample |
| [Corrected offline build](capture/before-corrected-build.process.json), [stderr](capture/before-corrected-build.stderr.log.gz) | Source `c69749680d7fd8dd2334d284f0e9a6823cf38a18`; unavailable `anyhow 1.0.103` archive | No native execution; same locked dependencies, no lock mutation |
| [Corrected online build](capture/before-online-corrected-build.process.json) | Exit 0 | Produced the actual baseline executable that subsequently failed the activation assertion |

The fixture had pre-run corrections for retained pool-row semantics and exact
packet-byte comparison. The observed private-encoder compile errors were then
corrected by calling the existing public legacy `Packet::encode`. Those are
fixture corrections, not fixes to production behavior. After the actual failing
baseline execution, the integration test remained byte-identical through the
fixed execution. No failed setup or failing native assertion was turned into a
successful receipt.

## Completed validation on the fixed native source

| Check | Actual result |
| --- | --- |
| Unchanged timestamp liveness integration target | 2 passed, 0 failed |
| Existing `pool_mining` integration target | 8 passed, 0 failed |
| Existing consensus unit tests, with added literal median/order boundaries | 6 passed, 0 failed; unrelated unit tests explicitly filtered |
| Existing `recent_batch` branch/reopen/corruption controls | 3 passed, 0 failed; unrelated unit tests explicitly filtered |
| CI contract controls | 97 passed: original 96 retained plus one added target-mutation test |
| Existing source-integrity mutation controls | 34 passed in their temporary Git fixtures; not a full-source guard of this sparse checkout |
| Workspace `cargo fmt --all -- --check` | Exit 0 |
| Targeted Clippy: node library plus `mining_timestamp_liveness` and `pool_mining`, `-D warnings` | Exit 0; no all-workspace/all-feature lint claim |

Full command/exit/stdout/stderr records are retained under `capture/`, including
[pool controls](capture/pool-mining-controls.process.json),
[consensus controls](capture/consensus-controls.process.json),
[ancestry controls](capture/recent-ancestry-controls.process.json),
[CI controls](capture/ci-contract-controls.process.json),
[source-integrity controls](capture/source-integrity-controls.process.json),
[formatting](capture/workspace-format.process.json) and
[Clippy](capture/targeted-strict-clippy.process.json).
The existing ancestry test emits its own scoped local timing diagnostic; it does
not qualify whole-service History cost or confirmed-transaction throughput.

The recorded toolchain is Rust/Cargo **1.95.0** on x86_64 Linux. Native builds used
`CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_TEST_DEBUG=0` with
unoptimized test executables. The Clippy invocation additionally set
`CARGO_PROFILE_DEV_DEBUG=0`; the capture helper's environment allowlist does not
include that variable. No compiler wrapper or Rust flags were supplied by this
lane. The successful fixed builds were offline and locked. Earlier necessary
public dependency retrieval used the inherited proxy and kept the lock unchanged.

The CI protocol lane adds `--test mining_timestamp_liveness` alongside all its
old targets. Its separate frozen command contract was updated, and the new
negative control refuses omission, duplication, substitution with `pool_mining`
or insertion of a skip for the actual counterexample. This changes no old
selector, old acceptance threshold, workflow budget or source pin.

## Reproduce the native regression

Use the baseline or fixed source identity above, Rust 1.95.0 and its locked
dependencies. Run the same fixture without changing its runtime or assertions:

```sh
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test mining_timestamp_liveness -- --test-threads=1 --nocapture
```

The baseline is expected to fail the positive activation assertion while passing
the future-median control. The fixed source should pass both. Actual new clock,
nonce and packet values must be retained as a new observation; do not copy this
run's receipts or infer a comparable computational cost from elapsed time.

## Remaining boundaries

This repair does not establish the cheapest legal W1 solver, a universal resource
lower bound, GPU/ASIC or quantum advantage bounds, cheap rejection of fresh fake
traces, Sybil-resistant honest service, DAA/time-warp profitability, WAN behavior,
model efficacy, PQ migration or production readiness. A truly future median still
halts this real-wall scheduler by design; that remaining timestamp envelope
requires its own security analysis and native network evidence.

The [recovered original V5 data](../../pon-postpublish-recovery-20261030/cost/README.md)
remain their original scoped observations and readback, with their unrecovered
outer provenance and original CI failure. They were inspected as prior evidence,
not rerun or re-certified by this lane. No measured timing here replaces their
cost denominators or turns those historical sibling observations into chainwork.

[files.json](files.json) hashes every retained file except itself and records
both compressed and decompressed hashes for every gzip object. Later documentation
and evidence packaging do not change which source/binary these actual executions
measured. Integration into a new combined head needs that head's own required CI.
