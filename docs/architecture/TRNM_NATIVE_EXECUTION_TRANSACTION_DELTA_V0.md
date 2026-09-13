# Native v0 transaction-local mutation staging

Status: implementation contract; source qualification pending; not an activation record.
Primary module: M06. Consumers: the ordinary native block candidate and complete
native application execution paths. Development sequencing remains in the
[canonical plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Contract and authority

`stage_runtime_mutations_v0` validates one transaction against its immutable
parent view plus the accumulated in-block overlay. Its returned map contains
only that transaction's writes, never untouched entries from earlier
transactions. Both runtime consumers merge the returned delta with `extend`
only after the function succeeds. Replacing the entire block overlay with a
transaction delta is invalid.

An in-block entry takes precedence over the authenticated parent. A key absent
from the overlay requires the same fallible authenticated parent lookup as
before; an unavailable lookup is not absence. Duplicate mutation keys, stale
expected versions, object-type changes, exhausted/skipped successor versions,
noncanonical values and mismatched canonical keys retain their rejection rules.
The function stages every mutation before returning. A later failed mutation
cannot expose an earlier mutation, alter the borrowed overlay or mutate parent
state. A transaction with no writes returns an empty delta and leaves the block
overlay unchanged.

This is an internal execution change. It does not change the v0 wire format,
canonical order, transaction authorization, gas, fees, receipts, JMT derivation,
execution roots, persistence barriers, signing authority or activation flags.

## Resource behavior

The former assembly copied the entire accumulated overlay before each
transaction. With independent writes growing that overlay, cumulative copied
entries grow as a sum of prefixes. Transaction-local staging constructs only
this transaction's changed entries. Merging them into the ordered block map
still has map-insertion cost; parent verification, execution, final state
assembly and JMT work retain their separate costs.

The regression checks a linear *staged item count*, preservation of an
untouched value allocation, and equality with the previous clone-based overlay
assembly. These are structural complexity and semantic checks, not a measured
TPS result, allocation benchmark, whole-node speedup or independent protocol
implementation. Real workload/hardware latency, allocation and throughput
measurement remains necessary before a performance claim.

## Verification and consumer replay

The crate's `overlay_delta_tests` module retains twelve regressions covering
empty deltas, untouched allocation preservation, prior-overlay precedence,
authenticated parent reads, duplicate/stale/type/version/value/key rejection,
late read failure, mixed create/hot-update differential replay and scaling
across 1/2/4/8/64/256 independent writes. Existing runtime/JMT differential and
complete durable four-root vectors remain unchanged and must also pass.

```bash
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-execution-v0 --lib overlay_delta_tests --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-execution-v0 --all-targets --locked
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

Run with the repository-pinned toolchain and the applicable existing CI cache
policy. The shared complete-execution consumer and durable restart/finality
paths require their existing exact-source regression gates. A successful local
model, source inspection or uncompiled Rust test is not Rust execution evidence.
Independent M06 producer and M07/M08 consumer review remains required before
acceptance; public-testnet, production, release and activation remain false.
