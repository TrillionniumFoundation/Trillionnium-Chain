# Grouped unsigned executor settings

[`config_grouped_u64.hepta`](config_grouped_u64.hepta) ports the value parser
in [`trnm-executor/src/env_config.rs`](../../../trillionnium/crates/trnm-executor/src/env_config.rs)
for the supported 64-bit target. The Rust function currently supplies
`TRNM_AGGR_SCAN_WINDOW`, `TRNM_AGGR_SCAN_RR_SEED`, `TRNM_AUTO_MIN_BATCH_LEN`,
and `TRNM_AUTO_SAMPLE_LEN`. This kernel does not read the environment, apply
the callers' defaults or bounds, or replace any scheduler call site.

The borrowed `f0(readbuf, mutbuf, mutbuf) -> u32` ABI takes the value
bytes and leaves scratch untouched. With an output capacity of at least eight
bytes, a valid input returns 0 and writes an unsigned 64-bit little-endian
integer, preserving the output tail. An invalid input returns 1, even if
capacity is short. A valid input with short capacity returns 2. Neither
failure writes to output. The foreign buffer bridge separately rejects
invalid pointers or extents; this is not a Chain wire or storage format.

The parser uses Rust's Unicode whitespace at the two outer ends, removes a
matched pair of outer quotes, trims again inside that pair, and ignores
underscores before evaluating decimal syntax. Commas permit any nonempty
first digit group and require exactly three digits in each later group.
Without commas, two leading plus signs are accepted after underscore
removal: the wrapper strips the first and Rust's unsigned parser accepts
the second. With commas, the grouping test disallows that second plus sign.
Overflow refuses before multiplication and addition. Only recognized
whitespace is removed; malformed UTF-8 and non-ASCII core bytes refuse.
Missing environment variables remain the host owner's concern.

Run the exact Rust comparison and the two machine backends with the pinned
Hepta checkout, pinned self-host compiler and Rust 1.95.0:

```sh
python3 -B -m unittest hia.tests.test_executor_config_grouped_u64
```

The reference compiles the original `env_config.rs` unchanged and calls
the real Rust parser, setting an isolated key in one reference process.
The test does not build the full executor crate or run a production node.
