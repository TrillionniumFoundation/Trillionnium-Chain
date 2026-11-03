# Cell rendezvous fixture readiness — original-budget candidate

This candidate composes owner `9f04640877078204d367f753eba684d94e705a74`
and fixed-Host candidate `4204c4b0b1300cbb5d5325d9915a161173983491`.
It adds a real worker-initialization handshake to the existing test fixture.
The only other Rust edit is two formatting-only line wraps in the owner's
new History deadline regression. Both parent histories and their entire
development-plan additions are preserved.

## Observed failure and repair

The original [required runtime job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41685898301/job/126091416148)
at `4204c4b0` ran 173 DA tests: 172 passed and one failed at the original
`announce_cell_provider(...).unwrap()` with `cell absolute deadline`.
It stopped before architecture-delivery tests. The exact decoded job log
and its byte/hash binding are retained here.

The old rendezvous constructor returned after spawning its thread, before
the serving thread had validated its real limits and addresses and made its
listener nonblocking. The new capacity-one channel reports that actual
initialization result before returning the fixture. It does not open a probe
connection, consume a signed record, change production server code, or alter
any of the 16 existing test bodies.

The original request allowance remains **200 ms**, server request allowance
**250 ms**, caller overall allowance **10 s**, server lifetime **30 s**, and
connection limit **64**. Only the readiness wait uses the existing 10-second
setup allowance. Existing shutdown and join remain synchronous: this is not
a hard cancellation guarantee for an arbitrarily stuck initializer.

Readiness proves initialization ran; subsequent worker scheduling can still
miss a 200 ms request deadline. The original selector passed locally before
the change. Therefore this evidence establishes a real startup-order defect
and a controlled repair, but does not prove startup was the sole cause of the
historical hosted timeout. Original hosted runtime qualification remains due.

## Actual local results

The original Rust 1.95 default test profile and locked graph were used, with
one build job, incremental compilation off, and one test thread. No test
profile, timeout, CPU limit, or performance acceptance was relaxed.

| Check | Actual result |
| --- | --- |
| Original selector on `116a3caf` | 1 passed; 172 filtered; historical hosted failure remains retained |
| First readiness candidate discovery module | 17 passed; 157 filtered |
| Real removal mutant: remove only readiness receive | Expected Cargo exit 101; 0 passed, 1 failed, 173 filtered; `fixture exposed its endpoint before real initialization` |
| Final fixture on `116a3caf` | DA 174 passed, 0 failed, 0 ignored, 0 filtered; 20.18 s |
| Composed `9f046408` + `4204c4b0` | DA 174 passed, 0 failed, 0 ignored, 0 filtered; 21.51 s |
| Strict DA Clippy, all targets, `-D warnings` | Exit 0 |
| Locked full workspace metadata | Exit 0; 174 packages, 26 workspace members, 174 resolve nodes; lock unchanged |
| Existing Host/architecture/shard controls | 35 + 9 + 9 passed |
| Source-integrity negative controls | 34 passed |
| Project-boundary controls | 16 passed |
| Original CI contract | 20 inline source pins; five head jobs and five prospective lanes preserved |
| Workspace format check | Original owner failed two assertion line wraps; exact format-only fix; final exit 0 |

The executed DA binary SHA-256 was
`a5451fbcabbc0f7a519ad273f6c56b152250fe5ba325e8f00ba6c93799eb80e9`.
The final fixture file SHA-256 is
`016f15c41972bfa560383de9876d79b3964ec41776220c1d7f2f376525e51ab9`.
All 1,189 captured native source inputs were checked around execution.
The only later input change is the exact two assertion wraps in `trnm-pon-node`,
outside the entire DA local dependency closure; this is explicitly recorded.
No local native qualification of the History test or whole workspace is claimed.

## Reproduce the positive and negative

From this candidate checkout, with Rust 1.95 on PATH and independent Cargo
home/target directories:

```sh
bash scripts/project-preflight.sh
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib -- --nocapture --test-threads=1
cargo clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-targets -- -D warnings
cargo metadata --locked --manifest-path trillionnium/Cargo.toml --format-version 1
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
python3 scripts/ci/test_architecture_delivery_host.py -v
python3 scripts/ci/test_rust_baseline_shards.py -v
python3 scripts/ci/test_from_zero_host_ci.py -v
python3 scripts/ci/test_ci_source_integrity.py -v
python3 scripts/ci/test_project_boundary.py -v
python3 scripts/ci/check_ci_contract.py
```

For the exact recorded negative, use a separate detached worktree at
`116a3caf6046dd0db3caf1d0797e636c35c877b8`, copy the retained
`negative-mutant.rs.txt` onto
`trillionnium/crates/trnm-data-availability/src/cell/discovery/tests.rs`,
and run the same locked DA library command with this exact selector and
`--exact --nocapture --test-threads=1`:

```text
cell::discovery::tests::rendezvous_fixture_waits_for_initialization_before_starting_request_budget
```

The negative must fail. Do not apply or publish that mutant as production
source. `candidate-before-comment.rs.txt` preserves the exact first positive
source; its sole difference from the final fixture is a comment clarifying
the synchronous join boundary.

## Evidence boundaries

`LOCAL_COMMANDS.json` retains every local receipt and small original output,
including the missing sparse vector/fuzz inputs, original formatting failure,
and the explicitly corrected first discovery receipt field. Verbose Cargo
metadata is reproducible; its exact stdout hash and complete normalized
resolved graph are retained without the large repeated raw listing.

The existing fixed-Host source from #697 is unchanged. Its resource limits,
source/binary/environment binding, actual controller readback, two original
tests and 18 business records remain required. This local DA result does not
qualify that original hosted architecture run.

Original **4 s / 16 hostile**, ARM CPU, and **30 s campaign** gates remain
independent and open. No workload denominators are combined and no previous
performance failure is promoted. Status remains **DRAFT / SHADOW_ONLY /
DENY_ALL / HOLD_NO_GO** with no production activation, model efficacy,
security, or consensus authority inferred.

The inherited #697 `cargo-invocation-control/command.log` contains an original
blank final line. Its exact historical bytes are preserved. Whole-composition
`git diff --check` reports that retained-log whitespace; the separate check
excluding only this unchanged historical log passes. The formatting-only
patch is retained as a JSON string so patch context spaces remain exact data.
