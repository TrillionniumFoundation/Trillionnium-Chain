# Conservative cache capacity estimates

The two scalar exports port the original
[`CellCacheConfigV4`](../../../trillionnium/crates/trnm-data-availability/src/cell/cache_budget.rs)
sizing methods. Each accepts the four original limits in order: database bytes,
logical bytes, chunk rows, and manifest rows. Each returns a positive estimate
in bytes, or zero for the original invalid-configuration error. Zero is an
internal scalar ABI convention, not a new wire encoding or a change in the
legacy error. The shared index and WAL estimates are separate, not a total
disk reservation.

The configuration range and page alignment are validated before arithmetic.
Database sizes are at most 2 TiB and are multiples of 4,096 bytes, so the
quotient is exactly a 12-bit shift. The WAL bound adds 16 frames for padding.
The index bound rounds that frame count up to 4,096-frame regions and includes
one extra region for the shorter first region. None of the checked operations
can overflow on the admitted domain.

The original SQLite cache, Rust callers, ownership, application wire, and
runtime admission are unchanged. This port is not a storage or Node cutover.
Run the focused check with the repository's pinned HIA compiler environment and
Rust 1.95.0 on `PATH`:

```sh
python3 -B -m unittest hia.tests.test_cache_capacity -v
```

The check compiles the original struct, complete implementation and validation
helper directly from their existing Rust source files. A small std-only
adapter supplies the used error variant and reports the two estimates or their
invalid sentinel; it neither rewrites the methods nor builds the SQLite
crate. Both native backend artifacts are executed in isolated test processes.
