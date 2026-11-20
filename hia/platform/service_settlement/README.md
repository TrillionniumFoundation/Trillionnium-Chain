# Native SettlementEngine

This directory builds and qualifies the finite Service SettlementEngine public owner. The implementation is HIA. The hosted Python files orchestrate compilation and test execution; they do not execute Settlement business decisions for the public library.

The owned interface is declared in `engine_owned.h` and has 21 exact exports. Constructors and successful operations mint independent immutable owners. Borrowed views remain valid while their owner is alive. Callers must pass live handles created by this library and honor the C pointer, length, and ownership contract.

## Rebuild and qualify

Use the repository's pinned Hepta revision and native compiler. Set `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER`, and `HIA_NATIVE_COMPILER_SHA256` according to `hia/toolchain.lock.json` and the compiler binding. Rust qualification uses the unchanged locked original source with Rust 1.95.0, offline Cargo dependency resolution, and an empty target in the new output.

```sh
bash scripts/project-preflight.sh
python3 -B -m hia.platform.service_settlement.build --output /new/out/build
python3 -B -m hia.platform.service_settlement.qualify run --output /new/out/qualification --rust-bin /path/to/1.95.0-x86_64-unknown-linux-gnu/bin
python3 -B -m hia.platform.service_settlement.readback --input /new/out/qualification --output /new/out/independent-readback
```

Attached development checkouts run the normal project preflight before qualification. Detached read-only CI uses the existing audit mode and still binds the exact source, HEAD, tree, project boundary, and remote identity. The audit mode does not alter staged or push rules.

Every output must be new and outside the repository. The independent reader writes only its separate output. A complete gate requires both the fresh qualifier and independent reader to succeed.

The gate retains all eight native compiler inputs and outputs, the actual HIA ownership emitter buffers, exact public link, current source and tool identities, original Cargo events and feature graph, all process stdout and stderr, and complete observed response bytes. It preserves the original 30-second compiler limit and 128-function, 8192-operation budgets. The full qualification has a 1200-second deadline. Native observations and allocation controls retain their 240-second deadlines; the original generator retains 120 seconds. Owned commands use one independent three-second cleanup deadline.

The finite required roster is 137 original registered tests: 136 outer tests and the original child fixture explicitly exercised by its parent in both crash phases. The two original compile-fail documentation tests, formatting and strict Clippy are mandatory. Native comparison covers all 320 fixtures and 2636 operations, including 16066 native calls and 1754 independently recorded FFI height values. Allocation coverage requires 162 controls with 136 actual calloc refusals and eight concurrent readers producing 256 independent owners. The fixed 68 integrity controls are named in `qualification/integrity_roster.py`; a partial or failed result cannot become a successful report.

## Scope

This is the Engine owner qualification. It does not qualify a native SQLite Store, Node integration, the original service resource budget, other targets, production activation, a complete host dependency closure, package retirement, or whole-chain native completion. Original Rust remains the mandatory comparison implementation. The public runtime does not fall back to Rust or a Python interpreter. The allocator observer is test-only C and is linked only into the separate test image; the production library is not changed by those controls.

All failures and partial captures remain in their original output. Repeating qualification creates a new output and new execution identity.
