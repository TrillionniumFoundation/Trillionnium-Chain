# Six-axis native execution continuation

Status: implementation and local conformance work; **HOLD / NO PRODUCTION ACTIVATION**.
Integration parent: `44ebe1ae95bd27cfc9eee3a9be27f0e06a084771` (existing Draft PR #688).
Implementation checkpoint: `95d37c7c31c601fb6ee319bc965a5956c7250f68`.
The four-second / sixteen-hostile-W1 confirmation requirement and 4,105-block
history requirement are unchanged. No old result is a result for this source.

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

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-features --lib -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib account_prefix_tests -- --nocapture --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib current_accounts_tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib parallel_preparation -- --nocapture --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib growth_paid_dispatch_charges_joined_preparation_workers_and_fences_unknown_cpu -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib paid_settlement_consistency_tests -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib cpu_budget_signed_native_success_survives_clock_failure_and_reads_survive_debt -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --test public_v3_request_accounting -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --test native_growth_public_cli -- --test-threads=1
```

The optional account-parser ABBA cost run is:

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

```sh
TRNM_GROWTH_SCALE_OBSERVATION_DIR=/absolute/new/run-directory cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib native_growth_v2_fixed_owner_account_history_scale_observation -- --ignored --nocapture --test-threads=1
```

See [reproduction.json](reproduction.json) for actual executed checks, interrupted
attempts, exact source digests and limitations. A listed command above is a recipe,
not a pass.

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

## Remaining original gates

- Full working-state cloning/root work and legacy complete-state/history paths.
- Original fixed-hardware four-second/16-producer independent six-deep confirmation,
  with failed/cancelled/unknown requests in the denominator and confirmation drain.
- Original 4,105-block History recovery and complete exact-source Node/workspace
  regression, Clippy and prospective-merge acceptance.
- Complete ingress-to-client-confirmation p99, rather than cumulative waiter times.
- Cross-process CPU/RAM/network isolation between ledger, query, repair and Cell
  transfer, and production host/model/PQ independent qualification.

No activation, public-network, absolute work-cost or whole-chain PQ claim is made.
