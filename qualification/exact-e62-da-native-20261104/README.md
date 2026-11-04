# Exact e62 DA native qualification

This independent recipe executes the published production source `e62eb3a4f35cf9fc5bf7f3092f86d441d0c4cd29`, tree `e61e1542d983e780c96a39e5785d3b4efc46ed60`, without applying any Rust diagnostic overlay. The recipe has its own commit and checkout. Both complete tracked trees are checked before and after the commands.

## Narrow question and required result

The previous diagnostic registered 174 DA library cases. The frozen e62 source adds six acknowledgement-retention controls. This recipe requires exactly 180 unique names from the actual compiled library's `--list` output, including the original two-bootstrap case, the readiness-handshake control and all six new acknowledgement cases. It runs the entire binary once with `--test-threads=1`, requires all 180 names to succeed exactly once, and requires one complete summary with zero failures, ignored cases, measured cases or filtered cases.

The former child-process libtest transcript interleaving is recognized only in the same four-line shape reviewed for the earlier diagnostic. The old 16 synthetic parser controls are retained; three additional controls bind the 180-case positive result and reject a short count or missing case. These are parser controls, not native tests.

The package-selected all-feature build and Clippy commands use exact Rust 1.95.0 and the unchanged checked-in workspace lock. The library execution keeps the original diagnostic's 300-second module ceiling. Build and Clippy have separate 600-second command ceilings; formatting has 120 seconds. The 45-minute workflow ceiling accommodates both fresh checkouts, toolchain installation and all commands; it changes no production request, Host, fixture, performance or original workflow budget.

## Exact commands

```text
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-features --lib --no-run --message-format=json
<actual single trnm_data_availability test executable> --list --format terse
<same executable> --test-threads=1
cargo +1.95.0 clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-targets --all-features -- -D warnings
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

The actual executable and immutable source inputs are hashed before and after. Every command's argv, cwd, exit status, timeout status and complete log hash are retained. Output lives outside both checkouts; compiled binaries are not uploaded. The 16 MiB log limit is a parser read limit, not a disk-write, RSS or native-output guarantee.

This result covers the package-selected all-feature test profile. It does **not** reproduce full-workspace feature unification or substitute for the original full-workspace runtime, protocol, Host, ARM or business-performance gates. The published e62 ref and all original CI runs remain unchanged. No prior diagnostic result is transferred to this source.

There is no local Python/native/preflight execution in this publication environment. The hosted workflow must establish the actual result. DRAFT / SHADOW_ONLY / DENY_ALL / HOLD_NO_GO remains in force.
