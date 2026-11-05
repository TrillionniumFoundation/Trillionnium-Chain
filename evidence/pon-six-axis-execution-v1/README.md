# Six-axis native execution continuation

Status: component correctness checks completed; Node runtime and cost observations
remain blocked by compilation resources. **HOLD / NO PRODUCTION ACTIVATION**.
Native code anchor: `23a56123e3112de06d7c684ef2057578759176ff`
(existing Draft PR #688). Delivery also preserves the concurrent documentation and
evidence at `67097f5add069c49788fc5ba21c35d1db07167c4`; its native code, scripts,
config and toolchain bytes are unchanged from that anchor.
This evidence follow-up changes no native implementation.
The original implementation checkpoint is `95d37c7c31c601fb6ee319bc965a5956c7250f68`.
The four-second / sixteen-hostile-W1 confirmation requirement and 4,105-block
history requirement are unchanged. No old result is a result for this source.

## Executed results and source boundaries

| Scope | Actual result | Source boundary |
| --- | --- | --- |
| M09 all-feature library | 302 passed, 0 failed, 0 ignored | Integrated implementation equivalent to `38cf428103f48879fcc6b7dc0fc523d5c58ff2e0` |
| M09 persistent module | 17 passed, 0 failed | A subset of the 302; do not add it to that count |
| M06 all-feature library | 126 passed, 0 failed; original 7 ignored retained | Same integrated source scope as M09 |
| M09 and M06 strict Clippy | Both passed, all targets/features, `-D warnings` | Same integrated source scope |
| Node strict Clippy | Passed after correcting the native prefix test's `sequence_root` import | Worktree bytes equivalent to `2d529aa0a1c65df9c43a5fd278c72ab0c0be3814`; launch HEAD was still `38cf4281` |
| Node runtime regressions | No tests executed | Unit and production-library compilation attempts failed before running tests |
| Parser ABBA and native account/history matrix | No samples started | Registered plan unchanged; no performance result or slope inferred |

The [component validation record](component-validation.json) retains exact commands,
exit codes, source digests, original ignored counts, log hashes and successful ELF
hashes. The earlier checkpoint-95 negative control remains separate: the original
implementation plus the same final tests produced 10 passes and 5 failures; the
paired fix produced 15 passes and no failures. The later 302-pass result has its own
source identity and is not substituted into that older comparison.
The [original checkpoint record](implementation-checkpoint-reproduction.json)
is preserved byte-for-byte, including its then-pending status, earlier failures
and historical reader controls. The current index is `reproduction.json` v2.

The [Node execution ledger](node-validation.json) retains all seven attempts:
Clippy first hit ENOSPC, then found the incorrect test import, and then passed after
the fix. Two unit-test builds hit ENOSPC; a third unit-test build and the subsequent
`public_v3_request_accounting` production-library build ended in rustc SIGKILL.
No Node test ELF completed and no request observation reports were produced.
Shared cgroup OOM counters increased around the SIGKILL attempts, but those cumulative
counters do not identify which process caused every event.

The failed builds did not lower optimization, debug information, assertions,
overflow checks, native CPU budgets, deadlines or sample counts. Later Node attempts
explicitly used the original CI setting `CARGO_INCREMENTAL=0`; earlier default
incremental-context attempts remain separate. The unsuccessful incremental-cache
symlink attempt did not relocate the database or produce any native measurement.
Only this session's reproducible inactive compiler intermediates were reclaimed;
successful test ELF bytes, source, failure logs and receipts were retained.
The [ELF preservation receipt](elf-preservation.json) records subsequent lossless
gzip archives and complete decompressed hash/length checks before removing the two
original executable paths. These archives are external evidence, not committed
binaries, and no native test or database was moved to a RAM filesystem.
The remaining inactive compiler cache was also archived and verified before
reclamation; its [completion receipt](build-cache-preservation.json) records the
separate cache operation. No subsequent native test or measurement used that cache.

The final code composition additionally preserves the concurrent cache-constructor,
source-integrity and research changes from `d9954903` / `963f2119`. The tested `38cf`
and `2d529` results do not qualify that complete composition. See
[reproduction.json](reproduction.json) for the exact source scopes and
[final static checks](final-static-validation.json) for checks on the delivered code.

## Actual implementation paths

1. Public paid mutation requests now observe their existing CPU settlement,
   including actual live settlement, original budget return and continuous journal
   completion. The existing `cpu_settle` slot distinguishes a known owner clock
   from successful settlement. A versioned optional diagnostic retains missing
   clocks, budget failure and journal failure without changing the native result,
   signed ACK or charged amounts. It overlaps part of the existing dispatch CPU
   interval; the two intervals must not be added. Historical reports without this
   extension retain their original reader derivation; they remain unknown here.
2. The account parser visits the exact `account:` ordered-map range. It preserves
   the complete parser, canonical key checks, malformed-prefix rejection, error
   order and account graph checks. Native Growth keeps both successor calculations,
   all proof/cancellation boundaries and the final independent readback. This
   removes unrelated working rows from this parser, not from every Node operation.
3. The native Growth writer and existing public serve path accept a bounded local
   preparation count of 1/2/4/8, default 1. Each actual preparation worker receives
   the original scoped CPU meter and must be joined before canonical application.
   Only transaction preparation/signature checks run concurrently. Account witness
   access, nonce, balances, debts, fees, rewards, state changes and durable commit
   remain with the original single owner. Cold replay remains the independent
   serial path. The change does not aggregate or batch PQ signatures, grant any
   new resource credit, or create another SQL writer. Workers are a scheduling
   choice; no throughput improvement is inferred from their count.
4. The TCQ2 client rechecks the original shared response-byte budget after waiting
   for its per-peer connection slot, preserving quarantine error precedence and
   already charged requests. Exhausted actual egress stops new server accepts and
   frame admission; already admitted workers are still joined. Temporary reserved
   bytes are not treated as permanently consumed. Original deadlines, retries,
   frame counters and response budgets remain unchanged.

## Reproduction

Use the committed Rust 1.95.0 toolchain and Cargo.lock. Prepare the repository's
pinned OpenSSL 3.5.9 provider using `scripts/ci/prepare_pq_provider.sh` for all-feature builds; do not substitute the host's
OpenSSL 3.0 for PQ validation. Start with `bash scripts/project-preflight.sh`.
A private offline Cargo cache and one compiler job avoid cross-session cache
contention; neither is a performance acceptance resource claim.
Keep the committed per-package test profiles, debug assertions and overflow checks.
For subsequent Node commands use the original CI's `CARGO_INCREMENTAL=0`, with
`CARGO_BUILD_JOBS=1`; do not reinterpret Cargo's aggregate profile label as the
optimization level of every package.

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-features --lib -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib account_prefix_tests -- --nocapture --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib current_accounts_tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib parallel_preparation -- --nocapture --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib growth_paid_dispatch_charges_joined_preparation_workers_and_fences_unknown_cpu -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib paid_settlement_consistency_tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib cpu_budget_signed_native_success_survives_clock_failure_and_reads_survive_debt -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --test native_growth_public_cli -- --test-threads=1
```

For the actual request observations, create a new output parent and retain stdout
as well as the two depletion reports. Existing output directories must not be reused:

```sh
request_receipts=/absolute/new/public-request-run
mkdir -- "$request_receipts" &&
TRNM_CI_RECEIPT_DIR="$request_receipts" CARGO_INCREMENTAL=0 cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --test public_v3_request_accounting -- --nocapture --test-threads=1 > "$request_receipts/cargo.log" 2>&1
```

Keep the real exit status and original log even if compilation or a test fails.
The observer snapshot is printed to stdout; `actual-cpu-depletion/report.json` and
`depleted-public-overlap/report.json` are written below that output parent when the
corresponding tests reach their report stage. Their absence is not a passing result.

The registered account-parser ABBA cost run is:

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib prefix_range_component_cost_abba -- --ignored --nocapture --test-threads=1
```

Its fixed-account/variable-working-state component samples include matching
instrumentation in both arms. They do not measure process RSS, full replay,
commit fsync, network or independently confirmed business latency. All cohort
failures and nonregressions must be retained; no best-sample selection is allowed.
The TCP baseline comparison adds only the same seven new assertions to the
original implementation; it never changes a production budget to make a test pass.

The [measurement plan](measurement-plan.json) was frozen before these new local
cost observations. Its parser gate uses all 320 planned ABBA sample returns,
paired round ratios and declared component improvement/nonregression limits.
The original fixed-touched-set native matrix remains 64/1,024/16,384 accounts by
0/16/128 warmup history blocks, eight measured signed blocks per cohort, with
full W1, complete-State reference roots, cancellation rollback and cold reopen.
It is a direct Node scaling observation; 72 measured blocks do not establish p99.
The [measurement status](measurement-status.json) records zero started samples for
both planned runs and preserves the execution declaration. Build failures are not
zero-cost request samples and missing samples cannot pass either measurement gate.

```sh
TRNM_GROWTH_SCALE_OBSERVATION_DIR=/absolute/new/run-directory cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib native_growth_v2_fixed_owner_account_history_scale_observation -- --ignored --nocapture --test-threads=1
```

See [reproduction.json](reproduction.json) for actual executed checks, interrupted
attempts, exact source digests and limitations. A listed command above is a recipe,
not a pass.

[parse_measurements.py](parse_measurements.py) checks the fixed plan hash, every
expected sample/event, ABBA order, fixture digest, returned stages and journal/log
agreement. Its output is create-only and incomplete input fails closed.
[observe_resources.py](observe_resources.py) records whole-command wall time,
waited-child user/system CPU and maximum RSS without modifying the command or
environment. That scope includes setup, warmup, journal output and any compilation;
it is neither per-stage CPU nor simultaneous aggregate process memory. These helpers
were prepared before measurements; no unexecuted helper output is presented as a
native result. Raw logs, output journals, command receipts and source/build identity
must accompany an actual run.

## Cache and authorization review boundary

This increment does not change existing cache implementations. Growth's checked
packet remains private and exact, and the public Growth entry performs full W1.
The ordinary arithmetic cache retains complete canonical A/B inputs and challenge;
current proof syntax, task/target and trace/product claims are checked on every use.
The separate rejection cache binds its versioned domain, profile, challenge, task,
target and complete proof, and stores only completed mathematical rejections.

Authorization retains independent current policy epoch, revocation and time checks,
plus exact packet/operation and durable journal/anchor checks at commit. The policy
epoch is distinct from the ledger's active-generation CAS. The arithmetic cache's
per-entry profile/version identity and cross-upgrade semantics remain an explicit
open acceptance item; current version isolation relies on the compiled profile,
current wire checks and a fresh volatile owner. This audit does not qualify a
cross-process authorization cache or automatic external revocation propagation.
The preserved concurrent constructor guards reject combining the arithmetic and
rejection-cache owners in either order, and reject replacing a rejection-cache
owner through a second builder call. They do not change the default disabled
configuration, cache algorithms, current authorization checks or paid dispatch.
Their separate constructor-control evidence does not replace this increment's
pending paid runtime and parallel Growth regressions.

## Remaining original gates

- Full working-state cloning/root work and legacy complete-state/history paths.
- Original fixed-hardware four-second/16-producer independent six-deep confirmation,
  with failed/cancelled/unknown requests in the denominator and confirmation drain.
- Original 4,105-block History recovery and complete exact-source Node/workspace
  regression, Clippy and prospective-merge acceptance.
- Complete ingress-to-client-confirmation p99, rather than cumulative waiter times.
- Node validation of 1/2/4/8-worker atomicity, joined cancellation/panic, exact CPU
  accounting and equivalent roots, plus separate preparation-scaling observations.
- Group-commit cost, head-of-line blocking, failed-batch retry and independently
  confirmed drain under the original workload; TCQ2 correctness is not that result.
- Cross-process CPU/RAM/network isolation between ledger, query, repair and Cell
  transfer, and production host/model/PQ independent qualification.

No activation, public-network, absolute work-cost or whole-chain PQ claim is made.
