# History cancellation and durable worker settlement

This scoped continuation starts at original PR #498,
`4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251`, preserving its 25-package Cargo
graph, lockfile, original W1 semantics and local operation owner. The
[sole plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains authoritative. **Full durable continuous History import remains OPEN.**

## Actual changes and results

History completion now carries its original CPU and physical resource callbacks
inside ancestor traversal and activation. Existing continuous packet context and
activation also carry their original permit and CPU checkpoints internally. No
late accounting failure retracts an already durable native result.

The new History regression admits three real W1 blocks on an inactive branch,
cancels at the seventh resource checkpoint inside activation, and verifies
unchanged active state and zero outstanding CPU operations. A subsequent real
completion uses the same owner and activates the branch. Cold reopen preserves
the new tip. This internal native test does not qualify a public Host parent.

The new journal regression joins two actual scoped Rust workers, including one
that deliberately panics after paid work. Both worker starts/completions and
nonzero child CPU remain charged once through the original settlement owner.
Cold reopen retains usage, the receipt and spent operation without a fresh burst.

On final formatted Rust source, six CPU-owner tests and three exact History
tests passed: nine distinct executed tests, zero failures or ignored tests in
these selected runs. The binary listed 724 tests; this does not mean all 724 ran.
Strict Clippy passed for `trnm-pon-node` and `trnm-crypto-primitives`, all targets,
with warnings denied. The exact original lockfile and offline vendor graph were
used with Rust 1.95. Test debug information was disabled to bound disk usage;
original package optimization settings were retained.

The same execution hashed all Rust/Cargo inputs before and after Cargo, required
the actual new test names and nonzero pass counts, executed the exact binary,
and checked its hash again. The final binary SHA-256 is
`ce6e82f30af1a9cc7bf05ddd8ae0b7a686e73ad9c85c90290bf89956b5ebaf99`.
See [summary.json](summary.json) and [final-native.json](final-native.json).

## Failures retained and compatibility repaired

The base still had callers of a now-private History API and constructors missing
the rejection-cache field. The failed compilations are retained. Internal unit
callers use the existing source-aware internal entry. External tests and the
distributed example pass their actual source address to the existing
`receive_public_page_from`; this retains its fixed Host parent requirement,
including loopback. No weaker public parser was introduced. Those external tests
compiled; their complete runtime success without the Host environment is not
claimed.

Rustfmt repaired nine existing affected files. An unused initial assignment in
the retained rejection-cache test was removed. The source inventory now includes
the previously omitted rejection-cache module and the new test. The original CI
reader quartet had been split by a cookie study; moving that study immediately
after the quartet retains every command and restores the existing order gate.
No gate or negative test was removed.

One intermediate build log reported a new test while a subsequent read of the
same-name binary still lacked it; an exact rerun selected zero tests. That result
was rejected. The new-directory successful run and final formatted-source run
both bind actual nonzero selections to stable source and binary bytes. Earlier
observations are not upgraded into final acceptance.

[manifest.json](manifest.json) maps all retained logs and source snapshots to
deterministic gzip objects with original/stored sizes and SHA-256. Decompression
restores their exact observed bytes. Expected panic output and failed commands
remain visible; use the named final scope when interpreting results.

## Unclosed acceptance

`begin_remote_history_cpu_epoch` still refuses a continuous Node whose generic
History import lacks an authenticated durable operation scope. Preserving that
refusal prevents unjournaled debit, but is **not** completion of the user's P0.
Page decode, W1/M06 admission, activation and real child workers must share
authorized durable identities; propagate cancellation internally; settle or
retain unknown debt on every error/panic/crash; and demonstrate successful
authorized restart and import. Permanently disabling import cannot pass.

No full workspace run, public-WAN throughput, complete process-kill recovery
campaign, independent operator run or production qualification is claimed.

## Reproduction

Use the repository's declared toolchain and locked dependencies:

```sh
bash scripts/project-preflight.sh
cargo fmt --all --manifest-path trillionnium/Cargo.toml -- --check
cargo clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node -p trnm-crypto-primitives --all-targets -- -D warnings
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib operator_continuous_cpu::tests:: -- --test-threads=1
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib ingress::history_activation_tests::complete_history_checks_resources_inside_activation_and_can_retry -- --exact
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib ingress::tests::history_paid_epoch_crash_cut_refuses_new_cold_credit -- --exact
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib ingress::tests::malformed_paid_history_rejection_closes_known_epoch_without_poisoning_cold_reopen -- --exact
```

A zero-test exit code or an older green artifact never qualifies a new source.
