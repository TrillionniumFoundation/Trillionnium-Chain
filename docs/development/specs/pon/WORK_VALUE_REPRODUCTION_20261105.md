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

## First fixed-base merge: owner controls

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

This first merge was committed locally as
`c06d6b192f809c51789a4eb69bb5037a7c52c93f` and published as
`1af1085db98a85ac1a191e5de370c49ac7d9b26d`, with the identical content tree
`b0c64bd2ad908f586780fc979574b3c6e2ff4af0` and the ordered parents recorded above.

## Second fixed-base merge: crypto and CI research inputs

A subsequent actual manifest conflict required another normal merge, now with
ordered parents `1af1085db98a85ac1a191e5de370c49ac7d9b26d` and
`f3a597f274833121d5ec408cb6a1cad83996d7f2`. The fixed second parent has tree
`86ca08c321e0866d2f49811c74e77c9dedb0c06a`; the common ancestor is the first
fixed source `1d6a9f9b5e8abd9e86457f45199a4922f9376360`. Both prior validation
receipts above remain historical observations of their own exact compositions.

The resolved manifest again preserves the fixed upstream's complete bytes,
substituting only this candidate's three Rust source pins. It retains all 505
pins and 423 required paths, including the newly required Growth observation
and account multiproof dependencies. The plan merges both independent additions.
Before extending this note, all eight other candidate files and 64 other
upstream files were checked against their exact parent blobs.

Upstream adds a separately named routed grouped integer research module and an
explicit sparse preparation option for legal-work experiments. The original
`Task::new` remains dense; the native producer, verifier, Node mining/store,
funding/payment and M12 source are unchanged by this upstream delta. The Python
useful-relation verifier does not create native adoption or payment authority.
The native funding tests are rebuilt against the new crypto dependency. Small
crypto unit controls and the changed source/CI contracts are checked with:

```bash
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --lib pon_work::legal_attempt::tests:: -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --lib pon_routed_int257_grouped::tests:: -- --test-threads=1
cargo clippy --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-service-settlement -p trnm-pon-node -p trnm-crypto-primitives \
  --all-targets --all-features -- -D warnings
python3 -B scripts/ci/check_ci_contract.py
python3 -B scripts/ci/test_ci_contract.py \
  EvaluationQuorumLaneTests.test_actual_lane_preserves_quorum_reference_and_retained_vector_checks \
  EvaluationQuorumLaneTests.test_useful_cell_relation_controls_cannot_be_removed_skipped_duplicated_or_moved
```

| Second fixed-merge check | Observed result |
| --- | --- |
| Original development preflight | PASS, 26 packages; no remote-policy mutation |
| Native funding/payment, rebuilt with merged crypto dependency | PASS, 6 tests |
| M12 full crate, all targets/features | PASS, 48 tests |
| Legal-attempt Dense/Sparse and transcript controls | PASS, 9 tests |
| Grouped integer research-profile unit controls | PASS, 11 tests |
| Whole-workspace formatting | PASS |
| M12/Node/crypto strict Clippy, all targets/features | PASS with `-D warnings` |
| Cargo graph and original lockfile | PASS, 26 members / 175 packages; same lock SHA-256 |
| Upgraded PQ source-integrity negative controls | PASS, 37 tests |
| Merged source-pin contract | PASS, 505 pins; status remains `HOLD_NO_GO` |
| Actual CI contract and selected protocol/relation controls | PASS, contract check and 2 test methods; no CI campaign execution claimed |
| Changed Markdown references | PASS, 368 local references in 18 changed files resolve in the merged Git tree |

The executable source, configuration and tests remain byte-identical to this
validated composition; finalization extends only this note. The native test
build again reports the separate SQLite I/O loader-directory `UNQUALIFIED`
observation. The component passes do not supersede it, the sparse-evidence
limitation of the whole repository checker, or any release/host acceptance gate.

This continuation does not rerun shared-material/grouped/useful-relation research
campaigns, external proving, architecture campaigns or the whole workspace test
suite. Previous utility, raw-source and Growth/mining results are retained above,
not relabeled as fresh measurements of this second merge. No later upstream
movement, model improvement, deployment, real payment or acceptance promotion is
included in this fixed-source scope.

This second merge was committed locally as
`a5937a3c5bf8399fe36bae4f830a71196eb8cc93` and published as
`674b1340fd30b33b63de5fdc4ddbc5af6b2a6252`, both with tree
`333f253cd74f506354283321d320c4c8f480c90a` and the ordered parents above.

## Final fixed-base merge: source preservation and static checks only

The final normal merge uses ordered parents
`674b1340fd30b33b63de5fdc4ddbc5af6b2a6252` and
`cbead1508ce8b6d9deb2a86b4bc3181da09694e7`. The fixed upstream tree is
`624c8aad419ee05dc71a4aac507abea429018289`, and the common ancestor is
`f3a597f274833121d5ec408cb6a1cad83996d7f2`. No later base is part of this scope.

Only the manifest conflicted. Its resolved bytes preserve the entire fixed
upstream manifest, replacing the same three work-value Rust pins. All 521 pins
and 440 required paths survive. Before this note was extended, eight candidate
files and 108 other upstream files were checked against their parent blobs; the
plan retains both additions. Historical evidence remains byte-for-byte upstream.

The added DA Cell work changes delta cancellation/deadline propagation and
discovery-directory owner/SQLite waiting. Source-level call inspection finds no
calls to those delta/discovery entry points in Node or M12 production source.
M12 does not depend on the DA crate, and the native funding/payment state,
transition and original work-verification paths are unchanged. The newer Python
runtime handoff also does not introduce authority into this fee observer.

This final composition receives source-preservation and static contract checks
only. No Cargo test, native rebuild, Clippy or Rust formatting run is attributed
to it. The native results in the second-merge table remain measurements of tree
`333f253cd74f506354283321d320c4c8f480c90a`, not of this newer composition.

The static reproduction adds these checks to the original preflight, source-pin
checker and PQ negative controls:

```bash
python3 -B scripts/ci/check_ci_contract.py
python3 -B scripts/ci/test_ci_contract.py \
  EvaluationQuorumLaneTests.test_actual_lane_preserves_quorum_reference_and_retained_vector_checks \
  EvaluationQuorumLaneTests.test_current_readers_and_runtime_controls_cannot_be_missing_duplicated_stubbed_or_moved \
  EvaluationQuorumLaneTests.test_current_runtime_controls_must_follow_pilot_and_parent_material \
  EvaluationQuorumLaneTests.test_current_runtime_controls_cannot_split_parent_material_and_parent_step
git diff --check cbead1508ce8b6d9deb2a86b4bc3181da09694e7 HEAD
```

| Final fixed-source static check | Observed result |
| --- | --- |
| Original development preflight | PASS, 26 packages; no remote-policy mutation |
| Independent source preservation | PASS, 8 candidate / 108 upstream files, plus exact manifest and plan composition |
| Upgraded PQ source-integrity negative controls | PASS, 37 tests |
| Merged source-pin contract | PASS, 521 pins / 440 required paths; `HOLD_NO_GO` retained |
| Actual CI contract and selected runtime-command controls | PASS, contract check and 4 test methods; no CI campaign execution claimed |
| Candidate diff relative to fixed upstream | PASS, ten work-value files |
| Whole upstream-import whitespace check | Exit 2; unchanged upstream observations retained below |
| Changed Markdown references | PASS, 440 local references in 29 changed files resolve in the merged Git tree |
| Native tests, rebuild, Clippy and Rust formatter on this composition | Not run; prior native receipts keep their original tree identities |

The whole import's `git diff --check` reports existing upstream raw-log trailing
spaces/EOF blank lines and an EOF blank line in
`scripts/llm_python_runtime_contract.py`. This failed observation is retained;
upstream evidence and source were not reformatted. The separate diff check of
the ten work-value files relative to the fixed upstream passes. No check or
qualification gate was altered to suppress the whole-import observation.

## Remaining acceptance requirements

Independent future-window benefit, training/calibration/selection/evaluation
isolation, equally informed cheap baselines, full lifecycle costs and multiple-
candidate statistical control remain obligations of the existing model owner.
Actual commission/plan authorization, consumer use/deadline observation, funded
production service, independent evaluator custody and economic externalities
also require their own evidence. Local `Positive`, a signature, an on-chain fee,
or passing these tests establishes none of those claims. Model improvement and
application payments remain outside target-derived chainwork.

## PR 717 conflict reconciliation, 2026-11-05 UTC

The original owner completed the fixed `96b8e81e2d25be7004a1e4a3b39d04a60dcadf0d`
publication. Subsequent base advancement to
`b9f339011886b7323f36825b2e79f7ecc7beea1f` made the stacked PR conflict again.
This continuation uses a normal two-parent merge, with original candidate head
first and that fixed integration base second. No rebase or force update is used.

The only textual conflict was between adjacent independent additions to the
canonical development plan. Both complete sections are retained: the upstream
execution/request-accounting evidence, followed by service/research value
separation. The source manifest merged automatically and retains the three
candidate Rust pins plus all upstream pins and required paths. Original raw
logs, failures, timelines, source receipts and authority restrictions are preserved.

Checks on this composition: utility controls 19/19, raw-source negative controls
43/43, PQ integration negative controls 37/37, source-pin checker (521 exact
source blobs, HOLD_NO_GO), CI contract checker, and four selected runtime CI
controls. Independent tree review checks preservation against both parents.
The candidate-only whitespace check passes. The full imported-upstream check
returns exit 2 for preexisting evidence-log whitespace; those bytes are retained.

No Rust compiler/Cargo toolchain is available in this continuation environment.
Native tests, Cargo metadata, Rust formatting and Clippy were not rerun, and no
earlier native receipt is attributed to this merged tree. This is conflict
reconciliation and source/Python validation, not a whole-workspace, hosted-CI,
model-efficacy, economic-value or activation qualification. The full repository
checker is not claimed green. Later base changes are outside this fixed merge.

### Publication-time base advancement

Before the PR ref was updated, upstream advanced once more to
`7ae0d1b227853fc75e02334b497f69dd52d50235`, preserving `b9f3390` and adding
the corrected fuzz-lock dependency graph, its CI contract control and original
evidence. That exact base is merged normally after the preceding composition.
All 14 upstream changed paths survive; the candidate's source files remain
unchanged, and the manifest combines both sets of pins. This second merge has
no textual conflict.

On this latest composition the 19 utility, 43 raw-source and 37 PQ controls were
rerun, together with both source/CI checkers and the four selected runtime CI
controls. The new fuzz serialization-edge negative control also passes. The
521-pin HOLD_NO_GO result remains. The added fuzz Cargo.lock is preserved as
upstream supplied it; no Cargo metadata, native tests, Clippy or Rust formatting
was run here. Earlier native receipts remain scoped to their original commits.
