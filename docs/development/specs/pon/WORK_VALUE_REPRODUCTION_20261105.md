# Separate service, research and improvement value: reproduction

Date: 2026-11-05 America/New_York. Scope: local accounting/observation repair.
No deployment, real payment, model-efficacy or consensus-security acceptance.

## Source composition

The first inspected integration source was PR #688 at
`dda4cc47362065819e9591f11f713933e7a853bf`, tree
`95fc95096e795e8f7a63d5d8a31e77b43af2e399`. The initial verified candidate is stacked on
the subsequent six commits through
`2a8fee974b41fab6e2c4e662dcce1807fcd19bdd`, tree
`b9627a51026e8d16a206b3952c3cda1d058d40ec`.
The latter's Growth payment epoch, timestamp, preparation, public-cost and
runtime-release changes are retained. Plan text was combined; the then-current
492-entry PQ source manifest was preserved with only the three changed Rust
file hashes refreshed. No lockfile or consensus profile changed.

That initial validation applies to tree
`efffe58265aaf46269c46426c89f03ae8e5f6244`, committed locally as
`2075893eadb11a819fad615d88dfbd2ec9e9040c` and published without content changes
as `5ce402bfca2a7c35a16a13a53bd7dab58c96d6d1`. The fixed-base merge validation
below retains this earlier receipt rather than attributing it to later sources.

The original negative control, with the new M12 regression and old production
source, ran one test and failed with `BUDGET_NATIVE_SOURCE_LANE`. The old
payment transition also required `Positive` for every funding source. Thus a
commissioned training task could not reserve training resources, and a completed
negative experiment could not record its already executed contract fee.

## Resulting boundary

The [existing M12 adapter](NATIVE_BUDGET_ADAPTER_V1.md) now admits
`Task/Contribution` for separately commissioned training. A `NoGain` result
qualifies only for observing an already executed `Task/Contribution`,
`Task/Evaluation` or `Quota/Serving` fee, after local effect completion and
resource recording. The original Node must still reexecute the exact signed
native payment, binding source, subject, beneficiary and gross/net amounts.
Release/mining rewards, invalid/unknown/cancelled work, and incomplete effects
do not acquire that eligibility. Original prepaid ceilings, whole-task amounts,
source/lane pins, operation deduplication and non-rewinding history remain.

The [usefulness observer](../../../../formal/pon-nakamoto-v1/work_utility.py)
uses a fresh V2 report and event-root domain. It separates correct on-time
service, completed planned research and legacy positive-gain output use.
The declared service clock/window and research plan must precede the observed
attempt. Changed output, stale branch, missing costs, changed plan/clock and
cross-channel operation replay refuse. Repeated outputs remain deduplicated;
distinct task-content count is reported separately and independent sample count
is explicitly unknown. This observer does not authenticate actual chronology,
independent controllers, social value, model adoption, funding or payment.

## Reproduction commands

Use the repository-pinned Rust 1.95.0 with its normal Cargo/rustup environment.
The container run used the installed compiler's absolute `RUSTC` path, an
isolated target directory, offline cached dependencies and four build jobs.
Run from the repository root:

```bash
bash scripts/project-preflight.sh
cargo metadata --offline --locked --manifest-path trillionnium/Cargo.toml --format-version 1
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-service-settlement --all-targets --all-features
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib store::funding::tests:: -- --test-threads=1
cargo clippy --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-service-settlement -p trnm-pon-node --all-targets --all-features -- -D warnings
python3 -B formal/pon-nakamoto-v1/test_work_utility.py -v
python3 -B scripts/ci/test_ci_source_integrity.py
python3 -B scripts/ci/test_pq_research_integration.py
python3 -B scripts/ci/check_pq_research_integration.py
```

The graph contains 26 workspace members and 175 resolved packages. The unchanged
`trillionnium/Cargo.lock` SHA-256 is
`39ab5baeecb55c5445e6bbbbb359cb4ddcddd75a237e19ec243dc2f0f92849be`.

## Initial observations

| Check | Observed result |
| --- | --- |
| Initial native funding-source regression | FAIL, one test; retained above |
| M12 full crate, all targets/features, initial composition | PASS, 48 tests |
| Native funding/payment bridge, initial composition | PASS, 6 tests |
| Whole-workspace formatting | PASS |
| M12/Node strict Clippy, all targets/features | PASS with `-D warnings` |
| Utility V2, including retained V1 behavior | PASS, 19 tests |
| Raw-source integrity negative controls | PASS, 43 tests |
| PQ source-integrity negative controls | PASS, 35 tests |
| Initial source-pin contract | PASS, 492 pins; status remains `HOLD_NO_GO` |
| Changed Markdown references | 271 local references resolve in the exact base tree or candidate files |

The first all-feature Clippy attempt stopped because the offline cache lacked
`foreign-types 0.3.2`. The five existing locked OpenSSL/foreign-types dependencies
were fetched without changing the lockfile, then the complete strict all-target,
all-feature command passed. The earlier partial/offline attempt is not counted
as a pass. This dependency acquisition did not change the tested runtime source.

The new native test covers three real Node storage backends (Legacy,
AuthenticatedV1, PermanentAccountGrowthV2) and both commissioned training and
evaluation. It executes native signed test-unit task reservation, receipt and
settlement; checks the exact sponsor debit/provider credit; rejects same-byte
Release/Reward/Quota namespace substitution and duplicate budgets; compares
same-height paid/unpaid blocks' equal chainwork; and preserves historical local
observations through reorg and restart without another native credit or effect.
These are controlled integration tests, not real research payments or independent
scientific observations. Existing task/quota/reward/recipient regression coverage
is retained in the same funding test module.

The complete repository checker was not claimed green: the sparse local clone
does not materialize all historical binary evidence linked from unchanged
Markdown files. Changed links were checked against the exact Git tree instead;
no placeholder evidence was created. Native component tests do not upgrade the
separate SQLite I/O-boundary qualification or full release/host acceptance.

## Fixed-base merge continuation

The published candidate was then merged normally with the fixed concurrent
PR #688 source `1d6a9f9b5e8abd9e86457f45199a4922f9376360`, tree
`4a0314e72ebc45659986d03e7ca2f96cab9399ea`. The merge's ordered parents are
`5ce402bfca2a7c35a16a13a53bd7dab58c96d6d1` and
`1d6a9f9b5e8abd9e86457f45199a4922f9376360`; their common ancestor is the
initial `2a8fee974b41fab6e2c4e662dcce1807fcd19bdd` source. No rebase, force
update, boundary change or later upstream snapshot is part of this composition.

Only adjacent entries in the source manifest conflicted. Its resolved bytes
are exactly the fixed upstream manifest with this candidate's three Rust pins
substituted: funding tests, M12 native budget and M12 native budget tests. All
502 source pins and the upstream 420 required paths are retained. The plan's
independent 14-line work-value and 17-line architecture additions both survive.
The eight other candidate files and 35 other upstream files were independently
checked against their respective parent blobs before this note was extended.
Historical binary evidence uses its existing upstream blobs without modification.

The upstream Growth materialization progress checks are on the native funding
test's Growth backend path. Its mining change uses the actual wall clock with
the native MTP11 window. In addition to the commands above, the following seven
tests directly cover those merged changes:

```bash
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib native_growth_v2_materialization_controls_preserve_state_and_original_errors \
  -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib ordered_growth_difference_control_checks_unchanged_keys_and_final_boundary \
  -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib store::error_boundary_tests::mining_wall_time \
  -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test pool_mining wall_clock_miner_ -- --test-threads=1
```

The merged executable source, configuration and tests remain byte-identical
through finalization; only this reproduction note was extended after testing.

| Fixed-merge check | Observed result |
| --- | --- |
| Original development preflight | PASS, 26 packages; no remote-policy mutation |
| Cargo graph and original lockfile | PASS, 26 members / 175 packages; same lock SHA-256 |
| Whole-workspace formatting | PASS |
| M12 full crate, all targets/features | PASS, 48 tests |
| Native funding/payment bridge | PASS, 6 tests |
| Growth materialization and delta-comparison controls | PASS, 1 + 1 tests |
| Native MTP11 and pool wall-clock regressions | PASS, 3 + 2 tests |
| M12/Node strict Clippy, all targets/features | PASS with `-D warnings` |
| Utility V2 and retained behavior | PASS, 19 tests |
| Raw-source integrity negative controls | PASS, 43 tests |
| PQ source-integrity negative controls | PASS, 35 tests |
| Merged source-pin contract | PASS, 502 pins; status remains `HOLD_NO_GO` |
| Changed Markdown references | PASS, 298 local references in 8 changed files resolve in the merged Git tree |

The Node test build retained its separate warning, `trnm SQLite I/O boundary
UNQUALIFIED: normal Cargo loader directory set incomplete`. Passing the component
tests and strict Clippy does not convert that observation into an I/O-boundary
qualification. The whole repository checker remains outside the claimed passes
for the historical sparse-evidence reason recorded above.

These scoped regressions do not rerun the upstream architecture/GHOSTDAG/OHIE
campaigns or the whole workspace test suite. Their retained historical receipts
are not reclassified as measurements of this merge. Growth callbacks do not
claim interruption inside bulk map construction, serde or hashing; no public
CPU/SLO, SQLite I/O qualification, model efficacy or release gate is promoted.
Any subsequent movement of the PR base is outside this fixed validation scope.

## Remaining acceptance requirements

Independent future-window benefit, training/calibration/selection/evaluation
isolation, equally informed cheap baselines, full lifecycle costs and multiple-
candidate statistical control remain obligations of the existing model owner.
Actual commission/plan authorization, consumer use/deadline observation, funded
production service, independent evaluator custody and economic externalities
also require their own evidence. Local `Positive`, a signature, an on-chain fee,
or passing these tests establishes none of those claims. Model improvement and
application payments remain outside target-derived chainwork.
