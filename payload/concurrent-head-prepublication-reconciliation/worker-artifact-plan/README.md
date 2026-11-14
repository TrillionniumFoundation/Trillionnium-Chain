# Worker artifact verification plan — prepared only

## Current result and source boundary

No Cargo metadata command, test, native workload, benchmark, Host command, or source/ref change has been run by this preparation. The final merged HEAD and tree have not yet been supplied. Root must bind both before authorizing an actual run.

The immutable N and M6 Cargo/module captures are byte-identical for the workspace manifest, worker manifest, main module and audit module. The worker package is the ordinary binary target `trnm-worker-agent` (no `src/lib.rs` in the captured target tree). `src/main.rs:16` declares `mod audit`; `audit.rs:1–2` loads `artifact` under `cfg(unix)`. Audit query reads the export and the index through `artifact::read` at audit.rs:544 and 550. The proposed test entry therefore exercises the selected production module.

The selected artifact source is blob `f021a33e2969305241099998f703172d29b15251`, 12,283 bytes, SHA256 `12396ec45e2b059d588f7d00feb9f19cc557389e37be0053d9ff5f344825f3cc`. It preserves initially validated metadata through lock acquisition. The two new tests perform controlled permission and hardlink changes in that interval, require that the mutation actually occurred, and require the original identity-change error.

## One future component run

Prefer the existing ROG Linux component runner. Linux compiles all ten methods: the original eight and the new two. macOS compiles nine because the original FIFO method is gated by `cfg(target_os = "linux")`; a nine-test Mac result cannot establish the complete ten-test requirement.

Use the existing root-approved source-before/source-after, toolchain, owned Cargo target/cache, bounded capture and terminal-receipt machinery. Only the selected binary/module command needs a new entry; no general-purpose framework is required. Proposed ordinary Cargo unit command, from the exact final repository root:

```text
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-worker-agent --bin trnm-worker-agent audit::artifact::tests:: -- --nocapture
```

This is a proposal, not a previously executed command or an inherited timing budget. It uses the normal test profile and default test threading, with no `--ignored`, `--skip`, `--exact`, new cfg, flags, test-body changes or profile override. Root selects and records the future component timeout. If the existing owned environment cannot satisfy the locked offline build, retain that failure; do not change dependencies to make this plan pass.

Before execution, verify the root-provided exact HEAD/tree and clean worktree, the selected artifact identity, and the module/manifest identity. Bind the source record to the actual command and process. After every outcome, independently verify the source again. A list-only test inventory can supplement the actual run but cannot replace it.

## Required actual outcomes

The full ten-name roster is frozen in `validation-plan.json`. Every name must occur exactly once as an executed `ok`; require ten passed, zero failed, zero ignored, complete stdout/stderr, and a zero authoritative process exit. Both of these names are mandatory:

- `audit::artifact::tests::validation_to_lock_permission_change_is_refused`
- `audit::artifact::tests::validation_to_lock_hardlink_change_is_refused`

A missing, duplicated, ignored, filtered required name, truncated log or unknown process result is not acceptance. Harness filtering of unrelated module tests is expected and does not count as skipping a required control. Preserve any failure and do not silently rerun or modify the tests.

These are ordinary local-filesystem Rust unit tests. They do not invoke `run_from_zero_host`, a Host controller or simulation, or a benchmark. A future pass makes no claim that the independent 4-second/16-worker confirmation gate, public activation, custody, consensus, or whole-repository semantic qualification has passed.

## Provenance

`source-target-review.json` binds the immutable source captures and exact module roster. `source-read-terminal.json` preserves the complete tool receipt for the read-only source capture. `EVIDENCE_INDEX.json` and `seal.json` bind these preparation files. The already closed production audit and its stage prefix remain unchanged; this plan has not been added to the execution stage.
