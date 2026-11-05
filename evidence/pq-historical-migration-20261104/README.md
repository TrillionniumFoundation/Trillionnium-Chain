# Historical-account migration continuation

This is source, small regression inputs and a reproduction manifest with exact commands.
It preserves the existing #688 integration candidate and keeps qualification and
activation on HOLD. The full [technical contract](../../docs/security/PQ_HISTORICAL_ACCOUNT_MIGRATION_V1.md)
describes all three cases and their remaining external obligations.

## Reproduce the native and public-input controls

Use the repository's pinned Rust 1.95.0 toolchain, the composed Cargo lockfile and
the existing pinned OpenSSL 3.5.9 provider for the optional native feature.
The normal ML-DSA provider and all existing byte/resource limits are unchanged.

```bash
bash scripts/project-preflight.sh
cargo metadata --locked --offline --all-features --format-version 1 \
  --manifest-path trillionnium/Cargo.toml
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-mvcc-fee --all-targets --all-features -- --test-threads=1
CARGO_BUILD_JOBS=1 cargo \
  --config profile.test.package.trnm-pon-node.debug=0 \
  --config profile.test.package.trnm-pon-node.opt-level=0 \
  test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --all-features --test pq_migration_inventory \
  -- --test-threads=1
python3 -m unittest discover -s formal/pon-nakamoto-v1 \
  -p test_pq_seed_recovery_v1.py -v
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-mvcc-fee --all-targets --all-features -- -D warnings
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --all-features --lib --test pq_migration_inventory -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/test_ci_source_integrity.py
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/test_pq_chain_claim_guard.py
python3 scripts/ci/test_ci_contract.py
python3 scripts/ci/check_repository.py
git diff --check
```

The Python public-input controls are also registered in the existing
`repository-truth` entrypoint. Their diagnostic is explicitly unverified; a
passing input test is not a successful seed recovery or cryptographic proof.
The Rust inventory report can be obtained from
`Node::inspect_pq_migration_checkpoint(SourcePins { network, genesis, checkpoint })`.
Supply independently selected pins; the report never chooses or retires a source
or publishes a destination. Its actual header/packet/State reads share one
SQLite read transaction. A retained side branch is intentionally queryable.

## Red-before / green-after nonce repair

Baseline: #688 `5c070abeb61d0ea8702fa94fffe9330d1699119c`.
Separately inspected #706: `c09e681b043cad8141a659ca40a9b19a2eca9d5e`.
Their source histories are divergent, not interchangeable runtime evidence.

The first red input uses the baseline runtime and the inspected #706 test file
(Git blob `be78290a1d2b1d5cf2551cd264c202666a38b32d`), not the later expanded
REGISTER tests. Apply that exact test blob to the baseline and run:

```bash
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-mvcc-fee --features pq-native-openssl --lib \
  pon_executor::pq_accounts_v2::tests:: -- --nocapture
```

The old runtime actually returned exit 101: one original group passed and three
groups failed because inconsistent nonce/authority states were accepted. The
new runtime rejects retained CLAIM authority with a nonce at/below the source
floor, retained genesis rotations below `generation - 1`, and imported rotations
below `source_nonce + generation`, including checked-add overflow. Real ML-DSA
CLAIM and rotation operations create the valid parent states used by the tests.

The first green PQ-module run passed all 22 groups, including seven inventory
and nine Application V6 controls, without ignored or failed groups. The complete
retained M06 targets, final Node inventory controls and strict checks have their
separate exact commands/outcomes in [reproduction.json](reproduction.json).
Historical failure digests and outcomes remain recorded. The original local raw
logs became unavailable after a transient workspace reset; they are not reconstructed
or rewritten as passes.
Do not replace the whole Application V6 implementation with #706.

A second independent native counterexample starts with actual funding and
REGISTER, then retains generation-1 authority while changing nonce 1 to 0. The
intermediate runtime incorrectly accepted both complete-state validation and an
empty-block execution: the selected test failed with exit 101. Registered
accounts now require `nonce >= generation`; only descriptor-bound genesis
accounts use `generation - 1`. A real second rotation tests generation 2 with
nonce 2 and refuses a rewind to 1. The first full M06 library run after that
repair passed 120 cases, with seven original explicit resource experiments
ignored; it precedes the d073 source composition.

The small [reverse patch](registered-nonce-green-to-red.patch) reconstructs the
exact intermediate runtime and red-test bytes from this continuation. Apply it
with `git apply --unidiff-zero` only in a disposable checkout and select
`pon_executor::pq_accounts_v2::tests::real_pq_positive_funding_registration_state_resolved_transfer_and_zero_credit`.
The manifest retains both reconstructed SHA-256 values and the original failure.
The final combined source additionally preserves all 14 files changed by
`d0737cf5434894ce47fad8082376fc417313c2cb` relative to the initial baseline;
the plan combines both increments and the generated inventory is refreshed.
It also preserves the subsequent ten-file Legacy reorg observation/source-pin
increment `bd2777f9cc74df10ba07ae8202584ed0fb90a519`. Its original diagnostics,
validation, resource limits and historical observation records are retained.
The subsequent checkpoint/release/transport increment
`245146c7d2e6f7dfcda463f6a7dd342d4d7ca818` is also preserved, including
its Cargo.lock dependency-edge additions; this continuation does not undo them.
The later `c156c2310346d1367b8f9b1111171f412b5ffce2` quantum research and
bounded admission composition is preserved as well. It changes Node admission,
but leaves M06, Cargo.lock and every M06 workspace dependency source unchanged.

## What the evidence does and does not establish

| Case | Delivered evidence | Still required |
| --- | --- | --- |
| A: fresh PQ genesis | Complete selected-state inventory, including zero accounts/nonce floors/monetary rows/unknown records; actual Node read-only checks | Real deployed ledger and external obligations inventory; source write retirement; independently agreed archive/genesis selection |
| B: precommitted migration | Actual partial-nonce-rollback counterexamples and rejection, retained real PQ transitions | Authentic pre-compromise registration, complete unsupported-state preservation, coherent old-store rollback protection, source retirement and in-place activation/reorg semantics |
| C: original seed | Versioned public statement, exact research source/parameter pins, strict public request/context/size controls | Reviewed ZK proof and PQ signature verification, target-host measurements, separate bounded execution owner, durable one-use/current-authority integration |

No production network was reset, no account or key was retired, and no current
execution authority was granted. The source snapshot of a still-valid earlier
branch remains valid; the nonce repair adds no node-local irreversible fork rule.
The Node inventory checks retained identity, complete state root and original
state/conservation rules; it does not rerun W1 or prove global source finality.
An empty ledger report leaves external scopes unresolved.

The source manifest includes only this continuation's changed inputs and exact
commands. Full workspace/business/independent-platform acceptance remains
separate. No remote CI result is used as a substitute for these local controls.

## Restored source composition

The transient local workspace was reset before the integration ref was updated.
All 19 changed files had already been uploaded as Git objects. Their exact tree
`0c12f5df05653df71cc34c202c84c7dca43fbeab` is preserved in recovery commit
`9d8193ee7b12ee38ab754d85a27b8dadc682b588`, with the authenticated noreply identity.
This source was reapplied to integration head
`a9b8602706b66adba82655c3c2ce90bde88620a2`, preserving every concurrent change.
The account runtime, native regressions, inventory modules and public target retain
their uploaded bytes. The Node registration is merged with the latest store owner;
workflow source pins, the complete 460-blob corpus and generated inventory are refreshed.

The earlier 227-case M06 and five-case public Node runs below remain historical
measurements. Later upstream M06/Node/dependency changes are not covered by a claim
of whole-workspace byte equivalence. Fresh restored-source checks are recorded
separately in the reproduction manifest as they complete. The original unit-build
and all-target lint failures remain explicit; no missing raw log is invented.

## Restored-source native verification

The actual published candidate `7a88207db3c50d2789787ff3af6f3b8ff7620ac5` has tree `7ba537d62dbbd81966c0db19b6ff0942fc5fb738`.
The restored-source Python checks ran on local commit `3e683e515afe4065218f2e3c96fa285965416d70`
with this exact same tree. All native checks below then executed on the published
commit itself, with clean unchanged source before and after every command.
Final evidence packaging changes only this README and the reproduction manifest,
on top of preserved integration parent `44ebe1ae95bd27cfc9eee3a9be27f0e06a084771`.
Later concurrent M09, Node, CI and research changes are preserved. The results in
this table belong to `7a88207db3c50d2789787ff3af6f3b8ff7620ac5`; they do not certify the later whole workspace.
The manifest includes the complete wrapper script and its explicit environment values,
so the recorded commands do not depend on an omitted local wrapper. It records
these overrides separately from the inherited process environment. Original
`source_inputs` remain an immutable snapshot at the tested commit, including the
old README; updated evidence-file identities are listed separately.

| Executed control | Actual restored-source result |
| --- | --- |
| M06 all targets / all features | 236 passed, 7 original explicit experiments ignored, 0 failed |
| Public Node inventory target / all features | 5 passed, 0 ignored, 0 failed |
| Strict Clippy | M06 all targets/all features and Node library/public inventory target/all features: both exit 0 with `-D warnings` |
| Python source and request controls | 208 passed, 0 failed, 0 errors, 0 skipped |
| Locked offline Cargo graph | 26 workspace members, 180 resolved packages |
| Source inventory and repository check | 460 exact pins; 2,641 local links checked; formatting and diff checks passed |

The fixed Rust compiler is 1.95.0 (`59807616e1fa2540724bfbac14d7976d7e4a3860`).
The restored OpenSSL 3.5.9 CLI has SHA-256
`08e4988f44357113a30082b8b37b368c722dc6be82d07a8e3c3585b75e301955`;
its header/static-library identity and an actual ML-DSA-65 sign/verify/refuse
control were checked. This is a different local provider build from the earlier
recorded CLI, and its hashes are kept separately. The independent Cargo cache
uses the original locked archive checksums. The initial shared-cache waiting
attempt was cancelled with exit 130 before any test executed and remains recorded.
The first restored Node run lost its execution session while the retained log
still showed dependency compilation. Its exit code is unknown and no completed
test result was observed. After reconnection, the original process was absent;
its log was preserved separately, preflight passed again, and the five Node tests
and the subsequent lint/format checks were executed successfully. The 236-test
M06 run was not repeated. Original source receipts and logs survived this later
connection interruption, and their recorded byte lengths and hashes were checked.
Wall times in the manifest include compilation and are not throughput benchmarks.

The public Node target keeps the explicit local opt-level 0/debug 0 compile
overrides above, with debug assertions and overflow checks retained. No repository
profile or production threshold was changed. These results do not turn the older
full Node unit-build or full Node all-target lint failures into passes. Those
broader gates, deployed-state obligations, source retirement, activation/reorg
semantics and reviewed seed-proof execution remain open.

## Recorded scoped local results before workspace reset

The local commit used for the recorded pre-reset runtime/source validation is
`2d6b02ecc7b78d3fbd9047592a8972cdd28d1e6c`, tree
`63ca4f6103f601c24c590b1a8ebc8ddee9a63643`. That evidence package also preserved the
subsequent isolated W1 research/workflow increment
`03163dcb849a15cd267fcaf704a533a88cd54131`; its entire production workspace,
main lockfile and CI job entrypoint are byte-identical to the validated inputs.
The updated plan combines both increments. The manifest binds each command to its
actual committed input, includes file digests, and retains the failed attempts.

| Executed control | Result and scope |
| --- | --- |
| M06 all targets / all features | 227 passed, 7 original explicit experiments ignored, 0 failed on `0723b501`; this is the earlier measured source, not an execution of the later restored composition |
| Final native PQ account module | 22 passed, 0 ignored, 0 failed on `2d6b02ec` |
| Public Node inventory target | 5 passed, 0 ignored, 0 failed; actual public methods and real SQLite state on ordinary/authenticated backends |
| Seed public-input controls | 19 passed; no ZK or PQ signature verification |
| Source integrity / corpus / claim guard / CI contract | 34 / 35 / 22 / 98 passed; 208 Python tests including the seed controls |
| Strict Clippy | M06 all targets/all features, plus Node library and the public inventory target/all features, `-D warnings`: exit 0; full Node all-target attempt was terminated |
| Cargo graph / format / source inventory / repository links | Passed; 26 workspace members, 180 packages, 419 pinned source blobs on `2d6b02ec` |

The full Node unit-test harness was **not successfully executed**. Its first
compile found an E0283 test-only type ambiguity, which was fixed. Later original
and reduced-symbol/optimization compile attempts were terminated by SIGKILL,
before tests ran. The full Node all-target Clippy attempt was also terminated
by SIGKILL; that broader lint gate is not claimed as passed. High shared memory
pressure was observed; the precise cause
of each termination is not asserted. Those observations remain failures, not
passing runs. No production source or test selection rule was removed to hide
them, and the five stricter internal unit tests remain in the original suite.

The independent public target uses the explicit local compile overrides shown
above, with one build job. It preserves debug assertions and overflow checks;
no repository profile, runtime budget or production configuration is changed.
Its separate observer compares committed rows, `data_version` and public active
state. It does not claim to observe the private Node connection's autocommit or
`total_changes`; the internal guard and retained unit tests cover those checks.
This is functional evidence, not a performance or full-Node qualification.

The preserved `245146c7` changes three release-bundle dependency edges in
Cargo.lock. The final lockfile is bound by its new digest. Complete lock-record
closures remain identical for M06 (138 packages) and Node (149 packages);
release-bundle is unreachable from both. This source comparison does not count
as an additional native test run. The final native module and public Node target
were also run with the composed lockfile.

## Seed research provenance

- [Paper abstract](https://eprint.iacr.org/2025/1368): 6.2 s proving, 2.3 s
  verification, 5.4 MB proof; FC 2026 full version, revised 2026-03-20.
- [Official source README](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/README.md):
  5.4 s proving, 2.3 s verification, 5.4 MB proof, 100-run average on a 12-core
  M4/24 GB system. This is distinct author-reported evidence and a WIP project.
- Circuit/verifier/parameter source SHA-256 values are pinned in
  [the public-input component](../../formal/pon-nakamoto-v1/pq_seed_recovery_v1.py).
  They do not attest to an installed binary or establish quantum security.

Neither the cited proving numbers nor the README memory figure is a measurement
performed by this continuation. No seed, real asset or private-key material is
used in these source and request-format controls.
