# Cell repair writer deadline

The existing ACK and retirement fixes capped their SQLite writer waits, but three repair transaction boundaries still inherited the owner's two-second busy timeout. With a 100-ms operation deadline and another IMMEDIATE writer held, new intent, zero-byte reconciliation, lost-completion retry, and lost-completion reconciliation all waited about 632 ms until the regression controller released its lock. They returned failure after that wait; this is a deadline-overrun defect, not an observed late successful charge or write.

All repair transactions now acquire and commit their writer using the remaining duration of the original absolute deadline, capped by the owner's configured timeout. The original owner timeout is restored on success and failure. Existing schema, prior-row, whole-charge, complete-payload and post-commit readback checks remain. A control refusal after commit leaves the durable intent/completion for exact retry.

Four native SQLite contention controls fail on the unmodified base and pass after the fix. Each preserves the complete obligation, repair identity, byte charge and physical payload, verifies reopening, and recovers valid pending completion without a second charge. The complete M09 library has 183 passing tests; strict all-target Clippy also passes. Exact source hashes and observed wall times are in `report.json`; the 600-ms lock-release detector is a regression-test controller, not a new operation budget or a service SLO. Publication retains the code and this small reproduction manifest; local validation keeps the original compressed success and failure logs separately.

A subsequent independent review added three controls for cancellation observed
immediately after a real repair COMMIT. A separate SQLite connection observes
the committed intent, zero-byte reconciliation or completion row; callback
counts do not select the boundary. Reopening preserves the original charge and
operation identity. Exact retry cannot copy or charge again, checked with an
empty source cache, complete payload bytes and a file-mtime sentinel. The new
full M09 run passes **186/186**, with strict all-target Clippy. The initial
183-test source and observations remain in `report.json`; the subsequent exact
source and coverage are in `postcommit.json`. These added controls pass on the
reviewed fix and do not claim another baseline runtime defect.

## Reproduction

Use Rust 1.95.0 and the existing locked Cargo graph. In a complete clean integration checkout run:

```sh
bash scripts/project-preflight.sh
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib repair_ -- --test-threads=1 --nocapture
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib -- --test-threads=1
cargo clippy --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-targets -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
```

For the red control, use a separate checkout of the `base_commit` in the report, retain its original `retention.rs`, and apply only the four added tests and their helper. Run the first command's `repair_` test filter; exactly the four writer-wait controls must fail while the pre-existing 12 filtered tests pass. Do not alter the original 100-ms operation deadlines.

## Remaining acceptance

This closes a local repair-wait regression. Independent provider administration, geographic/fault-domain separation, enduring storage obligations, and a real heldout prospective model cohort remain separate open acceptance conditions. The currently installed model-evolution profiles explicitly retain `prospective_accepted=false`; this source change does not alter model eligibility, authority roots, wire namespaces, schema versions or production activation.
