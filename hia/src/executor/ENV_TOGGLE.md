# Executor environment toggle

[`env_toggle.hepta`](env_toggle.hepta) implements the value decision made by
`env_toggle_enabled` in the [active Executor source](../../../trillionnium/crates/trnm-executor/src/lib.rs).
The three active callers are:

| Environment variable | Default |
| --- | --- |
| `TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS` | true |
| `TRNM_AGGR_DEEP_SCAN` | false |
| `TRNM_AGGR_SCAN_ROUND_ROBIN` | true |

Missing or invalid UTF-8 values return the supplied default, like Rust
`std::env::var`. For valid UTF-8, the kernel trims Rust Unicode whitespace,
removes at most one pair of matching ASCII single or double quotes, and
trims the enclosed text again. Empty text and strings composed entirely of
underscores and commas return the default. Only exact `0`, `false`, `off`
and `no` return false after ASCII case folding. Mixed quotes, repeated quote
layers, internal whitespace, separator suffixes and Unicode lookalikes are
not rewritten. All other values return true.

## Private three-buffer ABI

Input buffer: two one-byte booleans, **present** followed by **default**,
then the value bytes. An absent frame has no value bytes. A present frame can
contain invalid UTF-8, which is explicitly mapped to the default after
native validation. The complete frame is at most 1 MiB. The return is
`0` or `1` for the decision, or `100` when framing is invalid. Neither mutable
buffer is used or written. The borrowed entry `f0` delegates to `et_toggle`;
the pinned self-hosted compiler requires that external entry name.

The framing is for private qualification rather than an environment, protocol
or storage schema. No environment acquisition or scheduling is performed by
this component, and no production invocation, default, or dispatch changed.
OS environment values cannot contain NUL; extended private-frame tests also
check that adding NUL to a false-token prefix cannot produce false by
truncation.

## Reproduction

After normal project preflight and locked HIA compiler bootstrap:

```sh
python3 -B -m unittest -v hia.tests.test_executor_env_toggle
```

The test checks the exact, hash-bound active Rust function and all three caller
definitions, plus the equivalent definitions from the complete
[retained configuration module](../../../trillionnium/crates/trnm-executor/src/env_config.rs).
One compiled oracle sets the three original environment keys in its own
single-threaded process and observes both implementations with pinned
Rust 1.95.0, including missing, valid and invalid-UTF-8 values. The native
candidate executes separately on explicitly framed inputs, with an
independent expected-byte model, malformed controls, and 1 MiB boundary
checks. This is not a claim of full Executor equivalence or Rust retirement.
