# Cell rendezvous fixture readiness — original-budget candidate

The current composition adopts owner
`12171edc890df1611bf68503038bfad3d66a5a88`, including its complete current-ELF
fixed-Host framework. The only workspace Rust difference from that owner is the Cell
rendezvous readiness fixture. See **Current Host framework supersession** below
for the current commands and source-bound control results. The earlier sections
retain the initial candidate's exact results, not qualification of this later
composition.

The initial candidate composes owner `9f04640877078204d367f753eba684d94e705a74`
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

For these exact historical receipts, use a separate checkout of
`801bc063d64eff483cbd52804debfa6638cf96dd`, with Rust 1.95 on PATH and
independent Cargo home/target directories. Its old architecture-only helper
has been superseded in the current composition; use the current commands below
when validating the current source.

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

In that initial candidate, the fixed-Host source from #697 was unchanged. Its resource limits,
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


## Source-pin correction after the first publication

The actual corpus check on `801bc063d64eff483cbd52804debfa6638cf96dd`
failed on the changed fixed-Host CI workflow. A complete comparison of all
376 pins found exactly two stale entries: that workflow inherited from #697
and the formatting-only History deadline test change in this composition.
The earlier source-integrity unit controls did not replace this actual
manifest check. Its negative output remains in `PIN_CORRECTION.json`.

The correction updates only those two blob values. The other 374 pins and
all manifest fields remain identical. The real corpus check now exits zero
with its original `HOLD_NO_GO` result; the original 34 corpus controls and
22 claim-guard controls also pass. No Rust, Cargo, workflow, deadline,
workload or assertion changes accompany this correction, and no additional
native run is claimed. Original hosted runtime qualification remains pending.

Separately, the original release and workspace-profile CPU matrices on the
earlier exact `116a3caf` source have now been independently verified across
x64/ARM and head/prospective merge. Their [source-bound proof](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/adb90322aee5675fdd410bc813a9782e881f0024/evidence/pon-original-cpu-independent-20261103/README.md)
does not qualify this later composition or the still-failing 4-second and
30-second service gates.


## Concurrent owner integration

GitHub reported the corrected Draft as conflicting after its base advanced.
The next merge retains both exact parents: `368b39cdf37868b7e16d9b04e8451177386433cc`
and owner `8a74a9e42a9efbc52d83e861f64f03efd40f1406`, with common ancestor
`9f04640877078204d367f753eba684d94e705a74`. The only content conflict was
parallel appends to the sole development plan; both complete additions remain.
The owner's PQ test correction, bounded architecture failure diagnostics and
proof-scope documents retain their exact bytes. Its 376-entry corpus is kept,
with only the already-validated fixed-Host workflow pin from this Draft.

`OWNER_8A74_MERGE.json` records the exact equality checks and current controls:
original 376-pin checker and CI contract, 9 architecture controls, 9 shard
controls, 34 source-integrity controls and 16 project-boundary controls all
pass. No second large local Node build was started while the shared host was
already compiling the owner's native tests near its resource limit. The three
History completion controls, PQ refusal regression and original hosted runtime
must actually execute on the combined source; their status remains pending.
The DA library/dependency sources, fixed-Host workflow and runner inputs are
unchanged from the previous qualified source. This merge does not close the
original service or performance gates.

## Current Host framework supersession

The target branch subsequently introduced its own complete current-ELF Host
adapter in `b28098c092dca72165c0d26054fce95a8636d777`, retained by
`af570eaef44870ba3ec1f3d5be2cbdde2981931d` and the evidence-only
`12171edc890df1611bf68503038bfad3d66a5a88`. That implementation covers nine
exact public fixture selectors, including the architecture comparison. Keeping
the earlier Cargo runner active would leave two overlapping provisioning modes;
its old path also refuses the sealed parent created by the new fixture path.

The new merge therefore retains the complete owner implementation and retires
the earlier architecture-only runner and its hook. The original workflow,
History helper, shard driver/control and all 376 corpus entries now exactly
match the owner. All old source remains reachable in first parent
`4a32fe3418ea9b6eb18a44c93d8a282fa83fb426`; the original failure, nine earlier
adapter controls and historical qualification files remain retained. Removing
a superseded active helper is not evidence that its native gate passed.

The adopted path launches the already compiled current test ELF, binds the
actual source/job/process/cwd/binary and original compiled CLI, checks the real
kernel Host, and revalidates a root-sealed fixed-parent lease. A generic marker
cannot authorize execution. The full original signed-DAG test still produces
18 samples and runs its original business reader; its other original test
remains in the full workspace command. No new Cargo invocation, native retry,
larger Host allocation, confirmation window or request deadline is introduced.

The actual current controls pass: **78 Host adapter/controller/lease/process,
104 native driver, 8 shard, 34 source integrity, 16 project boundary, 34 corpus
and 22 claim controls**. The actual 376-pin checker, original CI contract,
preflight and complete workspace formatting also pass. Two earlier import
failures are retained: this sparse checkout initially lacked the owner's
`architecture_compare.py`, then its synthetic control module. Both were
restored byte-for-byte from the same Git index; only the affected Host suite
was rerun. No production source or test expectation was edited to fix imports.

`OWNER_12171_MERGE.json`, `OWNER_12171_CONTROLS.json` and
`OWNER_12171_HOST_CONTROLS.json` bind these observations. The control scripts
are retained under `owner-12171-controls/`; their recorded absolute scratch
paths describe the actual invocation, while the commands below reproduce the
checks from a current complete checkout:

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/test_from_zero_host_ci.py -v
python3 scripts/ci/test_run_from_zero_native.py -v
python3 scripts/ci/test_rust_baseline_shards.py -v
python3 scripts/ci/test_ci_source_integrity.py -v
python3 scripts/ci/test_project_boundary.py -v
python3 scripts/ci/test_pq_research_integration.py -v
python3 scripts/ci/test_pq_chain_claim_guard.py -v
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/check_ci_contract.py
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

This merge preserves the owner's committed-CAS production correction and new
native regressions unchanged. Their fresh original hosted execution is still
required. The earlier 174-test DA receipt is not relabeled as this merged
binary. All original service, work-cost, 4-second/16-hostile, 30-second and
activation gates retain their original status and acceptance conditions.
