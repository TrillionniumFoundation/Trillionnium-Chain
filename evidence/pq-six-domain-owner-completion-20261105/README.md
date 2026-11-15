# Six-domain PQ continuation: source changes, retained observations, and open acceptance gates

**Status: all six system-level acceptance domains remain HOLD.** This round
adds bounded source repairs and stronger recovery controls. It does not qualify
whole-chain post-quantum security, original hostile service capacity, complete
non-resurrection, independent deployment, or activation.

> Evidence prepared 2026-11-05 for
> `evidence/pq-six-domain-owner-completion-20261105/`. Both fixed-source Chain
> native commands finished with exit 101; their passing, failing and ignored
> cases are retained below. Build-only execution contributes zero tests.
> Original receipt/log bytes remain unchanged. Private Runtime raw evidence
> stays in `hepta-private-ci`; this public bundle contains summaries and
> immutable private links only. Evidence publication is separate from tested
> source and system acceptance.

The governing requirements remain in the
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the [whole-chain PQ claim guard](../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md).
Earlier evidence remains attached to its own measured source, configuration,
executable and execution conditions.

## 1. Exact identities and the boundary of each observation

| Object | Identity | Meaning in this document |
| --- | --- | --- |
| Frozen Chain native source | Commit `1d6a9f9b5e8abd9e86457f45199a4922f9376360`; tree `4a0314e72ebc45659986d03e7ca2f96cab9399ea` | Previously published to the existing [PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688), with ref readback confirmed by the publication owner. Source contracts and strict Clippy passed; library/pool and architecture commands each exited 101. Full outcomes appear below. A later publication base does not inherit these results. |
| Earlier integrated Chain source | Commit `bbc940cbdbdd6092158f735565004812ee834281`; tree `591ebbaef4bde2344d2117bc87759a0ab85d0a25` | Completed 258 static tests and strict workspace Clippy belong to this source. Its native invocation was interrupted during compilation. |
| Earlier initial Chain source | Commit `5642591d89f1e0938ade32a5e2abe57504cb63ca`; tree `b3fbdc280fb0df800e2126539bbcbf926cb0ebd3` | The historical 198 static tests and first interrupted native attempt retain this identity. |
| Published Hepta source before fixture repair | Commit `97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f`; tree `fdce3b8e854629315cea088f5d549aed3f8b2021`; parent `7530e4bc7aa61a0c23a5933fef4a65d86a586cf8` | Published to the existing [PR #4812](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4812), with ref readback confirmed by the publication owner. Its separate completed and incomplete observations appear below. |
| Published intermediate Hepta fixture-repair source | Commit `ff19c86b7190204e9172a1595a58d8eb9f897c6d`; tree `1c34e75019730bfdd238ebc612701d9f9583759d`; parent `c90d13228514440e82d4bbb0da2bdaf13d145c8a` | Published to the existing private PR, locally aligned to exact source/tree and read back by the publication owner. Its 120 static and 17 owner results passed; its dispatcher selection failed to compile. Every result retains this source identity. |
| Final frozen Hepta repair source | Commit `9438a6c27a5e2f25169445f39499631db4e00529`; tree `a9cba014de26164f0285c6c886fb071b19a04845`; parent `ff19c86b7190204e9172a1595a58d8eb9f897c6d` | One test import deletion; exact local import, push and remote ref readback confirmed. Its own 120 static, 17 owner, 14 dispatcher and 11 signed controls passed. Full library: 155 passed, one existing ignored fixture. Original process group: 0 passed / 3 failed; recovery process group: 2 passed / 2 failed. Hosted acceptance remains HOLD. |
| Chain observed test executables | Three logged ELF paths have equal pre/post SHA-256 and length; see the binary observations below | Local debug test artifacts observed at actual Cargo build/run paths. This is not exec-time attestation, a release build or independent deployment. |
| Hepta execution-bound executable identity | **HOLD** | Private local debug-artifact hashes were observed after execution. The retained logs do not name a `Running` binary path that binds those later hashes to the executed artifact; no release/deployment identity is supplied. |
| Required hosted source-head/prospective-merge observations | **HOLD** | The required fixed-source hosted architecture/merge receipts are not supplied by these local observations. |
| Chain evidence publication identity | The actual Git commit containing `evidence/pq-six-domain-owner-completion-20261105/` will pin publication once created | This later documentation/receipt identity is separate from every tested source above. It does not require an invented or self-referential commit SHA inside its own README. |
| Selected Chain publication base | Commit `a16a89f92a0db5ff6af9c1d7790f201841f079aa`; tree `1bd822500863b843d7625402258c49c52a529e69` | Preserves the earlier 549 preparation and one subsequent concurrent ingress commit. The first-parent change is this evidence directory plus the sole-plan append. No native execution on this later base is claimed. |
| Published private Runtime evidence | Commit `1556a4df6e279055fd8196f81a4ca2fe0f19384a`; tree `9675a9e62a1fbbdaed3248eb239bb2036d79feba`; [immutable private README](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/1556a4df6e279055fd8196f81a4ca2fe0f19384a/evidence/pq-invocation-recovery-20261105/README.md) | Published, read back and imported clean by the publication owner. The first-parent diff contains only 62 evidence files; concurrent peer source remains preserved. Final native results retain source `9438…`; earlier results retain their original sources. No private raw files are included in this Chain bundle. |

The frozen Chain execution source `1d6a9f9…` preserves prior peer histories and
their own source identities. That source's registry contains **502 pinned
blobs and 420 required paths**. Its 203 Node paths (202 files under `src`, plus
`tests/pool_mining.rs`) are byte/mode equivalent to `bbc940c…`. This establishes
the stated source subset's continuity, not whole-tree equivalence: later
research, source-registration and CI changes still require their own final
source checks. Existing ELF release controls were added to the
`repository-truth` invocation, and nine added research inputs were registered.
Registration and invocation are not proof or runtime-release acceptance.

The [final local alignment record](chain-final-local-alignment-20261105.json)
retains the exact source/tree and 203-path byte/mode comparison. A later,
separate [remote peer observation](remote-observation/chain-remote-cbead-summary.md)
captured `cbead1508ce8b6d9deb2a86b4bc3181da09694e7` /
`624c8aad419ee05dc71a4aac507abea429018289` once at 10:29:36 UTC. Its
168-path delta includes additional crypto and data-availability source.
The native source remains frozen at `1d6a9f9…`; preserved Node files do not
justify transferring execution credit across changed dependencies. The peer
snapshot and its source registrations are retained under their own identity.

The initial evidence preparation selected 549, later than the cbead snapshot.
The [fixed 549 object/path audit](remote-observation/chain-remote-549-object-finalization.json)
records 90 changed paths from cbead and a complete fixed 549 snapshot; it does not
claim complete historical-object closure. The
[publication-base alignment](chain-publication-base-alignment.json) occurred
after fixed 1d native/post observations ended. The initial Git merge attempt
failed on absent historical objects without changing HEAD; the later alignment
used verified raw ancestry, guarded tree application and an expected-old ref
update. No native tests ran on 549. The publication's first-parent diff must
keep this round's evidence/plan append separate from preserved peer source.
Results stay with `1d6a9f9…`; the publication tree is not thereby qualified.

Before publication, the remote advanced to `a16a89f…`, whose single parent is
549. The [concurrent composition record](chain-concurrent-a16-composition.json)
binds its 11 changed paths, including the ingress canonical-hex implementation
and its peer evidence. None overlaps the 55 prepared evidence/plan paths; all
prepared and peer bytes were verified during composition. Final publication
metadata now names this later base. The peer source and its separately reported
tests do not inherit or enlarge the fixed `1d6a9f9…` execution results.


Source and evidence publication identities must remain separate. If a later
commit only adds evidence, its diff must demonstrate that no executable source,
lockfile, security policy or runtime configuration changed. Even then each raw
receipt continues to name its original tested commit/tree. If implementation
bytes change, fresh source checks and relevant execution are required. A
source-equivalent merge is not a new native execution or an independently
administered deployment. Preserve earlier peer evidence byte-for-byte rather
than relabelling it with the new HEAD.

The Runtime repair source is not merely the old `97ae5b4…` with two lines
changed. Its parent `c90d132…` adds 27 concurrently published sealed
qualification paths relative to `97ae5b4…` (24 source and three evidence paths),
retained byte-for-byte by the repair owner. `ff19c86…` changes only the two
fixture modules relative to that parent. These additional source dependencies
are another reason the old 120 static and 14 dispatcher results cannot be
transferred to the new candidate. The new-source 120 static and exact 17 owner
results below have their own `ff19c86…` receipts. Its subsequent dispatcher
compile failure and the final repair's outcomes also keep their own identities.

The signed recovery frontier's source commit/tree fields also do not pin the
running binary by themselves. Their syntax and signature checks must not be
reported as a comparison against an installed executable.

The Runtime evidence publication has first parent
`96af771bda36fd4bc12125d4eded5322ae8a7cbe` and second parent
`796b622634ae46d2d344024dbc713f4993539e60`. Its first-parent diff contains only the
62 files under `evidence/pq-invocation-recovery-20261105/`, while preserving the
72 concurrent peer Cell paths already present in `96af…`. Local Git review confirms
that exact evidence-only first-parent delta. This does not make the published
`1556…` tree equivalent to the tested `9438…` tree: **no native result is
transferred to `96af…` or `1556…`**. Final Runtime test receipts retain `9438…`;
earlier results retain their original sources.
Publication/readback and the private composition proof remain separate. The
private package is retained unchanged; only its identity, scope and immutable
link are summarized here.

## 2. Completed, interrupted and failed observations

### Completed source-bound checks

| Source | Executed scope | Recorded result |
| --- | --- | --- |
| Chain `5642591…` | Source integrity 43; PQ integration 35; CI contract 98; PQ claim guard 22 | **198 static tests passed**, followed by repository/inventory/format PASS. Before/after commit and tree match. |
| Chain `bbc940c…` | The preceding four suites plus native-roster negatives 9 and public-phase-reader negatives 51 | **258 static tests passed**; repository/inventory/format PASS. Before/after commit and tree match. |
| Chain `1d6a9f9…` | The same six static suites 258; changed formal suites 36/29/22; existing ELF release module 20 | **365 Python-reported tests passed** across these distinct scopes, no reported skips; repository/inventory/format PASS, compound command exit 0 and exact clean before/after source. The formal and ELF fixture results do not qualify Node native or independent installation. |
| Chain `bbc940c…` | `cargo +1.95.0 clippy --locked --offline --workspace --all-targets --all-features -- -D warnings`, with the recorded manifest path | **Exit 0**. This is strict compile/lint evidence, not execution of the retained native tests. |
| Chain `1d6a9f9…` | A new final-source invocation of the same strict workspace/all-target/all-feature Clippy command with `-D warnings` | **Exit 0**, 286.538-second total invocation; Cargo reports 4m33s. Exact clean before/after source matches. Compilation/lint success supplies no native-test execution credit. |
| Chain `1d6a9f9…` | Separate three-target test precompilation with `--all-features --no-run`: library, pool and architecture | **Exit 0**, 1,458.423-second total invocation; Cargo reports 24m08s. **Zero tests executed.** Three actual `Executable` paths are recorded; this is compilation only, not a native test pass. |
| Chain `1d6a9f9…` | Complete Node library and pool target, all features, `--no-fail-fast`, one test thread | **FAILED, exit 101**, 1,655.770 seconds. Library: **1090 passed / 3 failed / 28 ignored / 0 filtered**. Pool: **10 passed / 0 failed / 0 ignored**. All three library failures retain the real independent-witness Unix bind EPERM. |
| Chain `1d6a9f9…` | Complete 13-case architecture delivery target, all features, `--no-fail-fast`, one test thread | **FAILED, exit 101**, 16.213 seconds; **12 passed / 1 failed / 0 ignored**. The signed-DAG business comparison failed with fixed-Host parent rejection in all 18 retained diagnostic rows. |
| Hepta `97ae5b4…` | Lane-A verify/self-test, recovery document/roster checker, implementation-map tests 86, source-observation tests 19, CI-exec tests 15 | **120 static tests passed** and the other named gates passed. Before/after source is clean and identical. |
| Hepta `97ae5b4…` | Original dispatcher selection, minimum 14, 3,600-second budget, `--retries 0 --test-threads=1` | **14 named native tests passed once**, exit 0; completed at 09:46:58 UTC in 1,515.256 seconds. Exact names, no selected skips, original log hash and clean before/after source were checked. This remains a local observation. |
| Hepta `ff19c86…` | New source-contract invocation, including 86 implementation-map, 19 source-observation and 15 CI-exec tests | **120 static tests passed**, exit 0, 26.398 seconds; clean exact before/after source. This is a new receipt, not a transfer of the old 120. |
| Hepta `ff19c86…` | Exact 17 recovery-owner names under the original 600-second budget, zero retries, one test thread | **17 tests passed exactly once**, exit 0; 27.102-second invocation / 6.715-second test summary. The 139 tests outside this exact filter were not selected controls. Signed/process/hosted gates remain separate. |
| Hepta `9438a6c…` | New final-source contracts | **120 static tests passed**, exit 0, 20.791 seconds; exact clean final-source identity. |
| Hepta `9438a6c…` | Exact 17 owner selection and original 14 dispatcher selection, separately executed | **17 / 14 passed**, both exit 0; 11.596 / 81.902-second invocations. Required names each ran once. They are separate source-bound selections, not a whole-library or hosted result. |
| Hepta `9438a6c…` | Exact 11 signed-frontier names, original 600-second budget, zero retries, one thread | **11 passed exactly once**, exit 0; 8.256-second invocation / 3.208-second test summary. The 241 cases outside the filter are not selected skips. Local 17/11 roster inspection passed; hosted qualification remains false. |
| Hepta `9438a6c…` | Complete eligible evidence-library regression, original 600-second budget and minimum17 | **155 passed / 0 failed**, exit 0; 78.994-second invocation / 72.761-second test summary. Of 156 discovered cases, one existing ignored subprocess fixture remains excluded. The 155 include the owner controls and are not added to those 17. |
| Hepta `9438a6c…` | Original scoped `just fix`, 1,200-second budget | **Exit 0 with warnings**, 778.748-second invocation; Cargo reports 12m50s. Before/after source remains clean and unchanged. Project lint warnings and dependency deprecations remain in the private original log; this is not strict zero-warning acceptance or test execution. |
| Hepta `9438a6c…` | Original `just fmt` | **Exit 0**, 3.732 seconds, with no changed files needing formatting. Clean unchanged source, zero tests; this was not a full-repository `--all` format check. |

The final Chain [receipt](chain-final-source-contracts.json) and
[raw log](chain-final-source-contracts.log) record 43,302 bytes and SHA-256
`efdcb3d41ebdeb3522534762d52e450165088066d5647a14dbed0ed33441b4c8`.
Its before/after checks both bind `1d6a9f9…` / `4a0314e…`, 10,025 tracked
entries and 965,395,071 tracked bytes. This is the final-source observation;
the following earlier receipts keep their own identities.

The final strict Clippy [receipt](chain-final-workspace-clippy.json) and
[6,341-byte log](chain-final-workspace-clippy.log) have SHA-256
`f19c456cc2f6f8910cdd74d28ff41fc4cdbc0394c96997b4f66f07faed91cba8`.
The receipt records `elapsed_ns=286537970821`, exit 0 and identical verified
`1d6a9f9…` / `4a0314e…` before/after identities. Cargo's 4m33s line is its
compile interval, not the full wrapper duration. This is a fresh final-source
lint result; the historical bbc Clippy result below is retained separately.

The separate test-build-only [receipt](chain-final-test-build-only.json) and
[3,530-byte log](chain-final-test-build-only.log) have SHA-256
`868292cabbae114adee081cece1bf1c9fc2ae78b1da7a36e919db03a58086a38`.
The command completed with exit 0, `elapsed_ns=1458422675765`, and identical
verified `1d6a9f9…` / `4a0314e…` before/after identities. Cargo reports
24m08s and the actual library, architecture and pool executable paths. The
original `--no-run` command executes zero test bodies; pre/post executable
hashes and actual native execution remain separate observations.

The Chain 258-count receipt is
[chain-integrated-source-contracts.json](chain-integrated-source-contracts.json),
with [its raw log](chain-integrated-source-contracts.log): 24,966 bytes,
SHA-256 `b6ec0ffb1579db89d665e99fdc6181adc7b0614d22664837cb3c8f03ba9d7e52`.
The repository result records 26 workspace packages, 1,150 Rust files and
3,022 local links. The separate strict lint result is
[chain-integrated-workspace-clippy.json](chain-integrated-workspace-clippy.json),
with [its raw log](chain-integrated-workspace-clippy.log): 5,505 bytes,
SHA-256 `72864193091e5fc0da791bc057766713dbabb9346e4bad1f921b911d12065fcf`.

Retain the preceding [198-count receipt](chain-source-contracts.json) and
[log](chain-source-contracts.log) as historical observations: 23,814 log bytes,
SHA-256 `6d3911a059686489fd9ccc5c4ef87169211bed5f037fe010c6f33a85198527ee`.
These counts describe separate source-bound invocations; adding them together
would not describe distinct tests executed on the final candidate.

The Runtime results in the table are cross-repository summaries. Their raw
receipts, native compilation logs, environment record and helper programs stay
in the published private Runtime evidence bundle at
[private Runtime evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/1556a4df6e279055fd8196f81a4ca2fe0f19384a/evidence/pq-invocation-recovery-20261105/README.md). Source identities and the
[private workflow][hepta-workflow] are linked for authorized reviewers.
These local results do not establish independent custody, hostile capacity,
a complete PQ effect path, or final hosted validation.

### Completed Chain native invocations retain their failures

The library/pool [receipt](chain-final-node-and-mining.json) and
[146,066-byte log](chain-final-node-and-mining.log) record exit 101,
1,655.770283795 seconds, and SHA-256
`5f30d2dd4db337c3b5d948ef005b07501be129b60a35defe21f2da94e094d223`.
The terminal library summary is **1090 passed / 3 failed / 28 ignored /
0 filtered**, and the pool summary is **10 passed / 0 failed / 0 ignored**.
The log also includes two nested one-test subprocess summaries; they are not
added again to the primary harness counts. `--no-fail-fast` preserved the pool
execution after the library failure; it did not turn the command into a pass.

All three library failures belong to `store::pq_rollback_witness::combined_tests`:

- `guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart`
- `guarded_npq6_valid_submit_cleanup_preserves_primary_error_and_child_diagnostics`
- `guarded_npq6_valid_submit_exact_replay_and_independent_process_restart`

Each independent witness subprocess failed at the real `witness.sock` bind
with EPERM, in the [fixed-source witness fixture](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1d6a9f9b5e8abd9e86457f45199a4922f9376360/trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/combined_tests.rs).
The failures and all28 original ignored cases remain in the denominator;
neither a skip conversion nor a permission workaround is credited.

The architecture [receipt](chain-final-architecture-delivery.json) and
[7,563-byte log](chain-final-architecture-delivery.log) record exit 101,
16.212758079 seconds, and SHA-256
`f42afc0a08c95bb37370560b08a28ec204b3ba351ede9259adde02fffa11ae30`.
The complete target ended **12 passed / 1 failed / 0 ignored / 0 filtered**.
Its only failed case is
`signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract`.
All18 retained business diagnostic rows report `PUBLIC_HOST_KERNEL_PARENT`,
`native_state_equal=false` and `cold_reopen_equal=true`. This is a fixed-Host
execution-position rejection through
[`KernelBudget::open`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1d6a9f9b5e8abd9e86457f45199a4922f9376360/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs),
whose required parent is `/sys/fs/cgroup/trnmponpublic.slice`. It is distinct
from the Unix socket failures and supplies no native capacity or DAA algorithm
conclusion. A later Host inspection found the fixed parent absent; the record
labels that environment observation as post-run, not captured execution-time
environment.

The [failure-boundary observation](chain-final-native-failure-boundaries.json)
retains the original4 failed and28 ignored names/log lines, three Unix failure
sections and all18 bounded diagnostic rows. **The full architecture report is
NOT_RETAINED.** The path announced by the test no longer existed at the later
inspection. The original receipt does not record the optional report-copy variable;
the surviving raw log is a bounded projection. No full report was
reconstructed from the console, and no retry or substitute campaign was run.

The complete commands and source checks remain bound to fixed 1d. Passing
individual controls, local byte equality or the successful cold-reopen flag
does not override either command failure or qualify the original4s/16-hostile
and4,105-block campaigns.

### Preserve both interrupted Chain native attempts

The original Node command was:

```sh
cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --all-features -- --test-threads=1
```

The first attempt targeted `5642591…`; the second integrated Node/mining
attempt targeted `bbc940c…`. Both were still compiling when concurrent source
advanced. Each session was deliberately stopped through supported session
`write_stdin` Ctrl-C before retargeting. Each termination observation records
**exit 130 and zero completed tests observed**. Neither is a test pass, a
completed native test failure oracle, or a run on `1d6a9f9…`.

Retain these pairs without rewriting their original unfinished command JSON:

- [chain-node-all-lib.json](chain-node-all-lib.json),
  [log](chain-node-all-lib.log), and the later
  [first retarget observation](chain-native-retarget-observation.json).
- [chain-integrated-node-and-mining.json](chain-integrated-node-and-mining.json),
  [log](chain-integrated-node-and-mining.log), and the later
  [integrated retarget observation](chain-integrated-native-retarget-observation.json).

Those command records may retain `running` and null terminal fields. The later
termination records explain the actual end. The first retarget record's generic
`signal` label is not evidence that individual rustc processes received that
signal; use its concrete stop method and session exit.

### Retained private Runtime failures

Two distinct Runtime attempts on `97ae5b4…` remain failed. The initial full
`codex-hepta-evidence --lib` attempt used the original 600-second budget,
minimum 17, zero retries and one test thread. It timed out: wrapper exit
**124**, child exit **-9**, **zero completed tests**, 608.895 seconds including
termination handling. The later exact 17-name owner selection failed during
compilation: **exit 101**, **15 E0277**, **zero executed tests**, 147.701 seconds,
with no timeout. Clean before/after observations bind both attempts to the
original `97ae5b4…` / `fdce3b8…` source. The private Runtime bundle retains each
original JSON and raw log unchanged.

The fixture repair is the separately published and locally aligned `ff19c86…`
source. Its 120 static and 17 selected-owner tests have successful new-source
receipts; its subsequent dispatcher failure is recorded separately below.
Those successes do not rewrite either old-source failure. The old source's 120 static and 14
dispatcher successes retain their original identity, too. Subsequent source
and native commands need new receipts; they cannot erase the timeout or the
selected-owner compile failure. No private compiler output, fixture source
snippet or patch is copied into this public Chain evidence.

The `ff19c86…` dispatcher selection then also failed to compile: **exit 101**,
**one E0432 unresolved test import**, **zero executed tests**, 74.852 seconds,
with no timeout under its original 3,600-second budget. Its private raw receipt
and log remain bound to clean `ff19c86…` / `1c34e75…` source observations.
The 17 owner and 120 static successes on that source remain factual, but do not
satisfy this separate Agentd library compilation gate. The one-line fixture repair is published as final frozen source `9438a6c…`,
tree `a9cba01…`, parent `ff19c86…`. Its own source/owner/dispatcher/signed
invocations passed with 120 / 17 / 14 / 11 tests. The full-library regression
passed 155 eligible cases with one existing ignored fixture. These new
receipts do not relabel the intermediate source or erase its compile failure.

The final source's process outcomes are also terminal failures. The three
original AuthBus/Agentd controls finished with **0 passed / 3 failed**, exit
**100**, 40.827 seconds. The four recovery process controls finished with
**2 passed / 2 failed**, exit **100**, 15.868 seconds. Both retained their
original 1,800-second budgets, zero retries and one test thread. Agentd's real
Unix control-socket bind returned **EPERM** in each failed case. The two
successful recovery controls rejected a valid older database image and an
effect-only rollback; the startup and exact-current-database positive paths
failed. No failure is rewritten as a skip or an environment-adjusted pass.

### Native gate results and remaining holds

| Required observation | Recorded status |
| --- | --- |
| Chain complete library/pool invocation | **FAILED**, exit 101; library1090/3/28 and pool10/0/0. Original witness bind failures and ignored cases remain. |
| Chain complete architecture invocation | **FAILED**, exit 101;12 passed /1 failed /0 ignored. All18 retained rows report fixed-Host parent rejection; full report is NOT_RETAINED. |
| Final Hepta four real evidence recovery product controls | **FAILED**, exit100; 2 passed / 2 failed. Real Agentd startup/current-image positive paths hit Unix bind EPERM; original 1,800 seconds and zero retries retained. |
| Final Hepta three original AuthBus/Agentd product controls | **FAILED**, exit100; 0 passed / 3 failed, all with real Unix control-socket bind EPERM. Original 1,800 seconds and zero retries retained. |
| All required hosted architecture/source-head/prospective-merge lanes | **HOLD**; no local receipt supplies these required lanes. |

These are complete terminal observations. A successful case inside a failed
command does not change the command exit or the required gate result. Earlier
unfinished receipts retain their later stop sidecars, and hosted/independent
acceptance remains HOLD.

The completed test-build-only invocation is a separate
`chain-final-test-build-only` observation on fixed `1d6a9f9…`, under the same
recorded environment. It began preparing executables while Runtime scoped
lint was checking. It executed zero native tests. The later library, pool and
complete13-case architecture executions have their own terminal receipts and
actual `Running` paths. Their pre/post byte observations are retained separately.

### Added controls and local executable observations

The [final native observation](chain-final-native-observation.json) records all
**37 enumerated added controls as observed passes**: 24 library, 2 pool and 11
architecture. These are subsets of the complete target counts above, not 37
additional tests. They do not erase four failures or28 ignored cases.

The [corrected roster](chain-observation-roster-corrected.json) changes only one
module qualifier in the original [roster](chain-observation-roster.json): the
same public-v3 test belongs to `paid_settlement_consistency_tests`, rather than
the older `tests` qualifier. The [correction record](chain-observation-roster-correction.json)
retains the original observation and proves the 37 function/source/blob/target
entries were not added, removed or substituted. The
[actual final reader](chain-observation-final-native.py) binds the corrected
roster; its [new review](chain-native-reader-corrected-roster-review-20261105.txt)
is separate from the [preserved earlier reader](chain-observation-final-native-before-roster-correction.py)
and [earlier review](chain-native-reader-review-20261105.txt). No native test
was rerun for this metadata correction.

The [pre-execution observation](chain-final-pre-execution-observation.json)
uses actual Cargo `Executable` paths; the
[post-execution observation](chain-final-post-execution-observation.json)
uses actual `Running` paths. All three paths, SHA-256 values and lengths match
across the observations:

| Local debug test artifact | Bytes | Observed pre/post SHA-256 |
| --- | ---: | --- |
| `trnm_pon_node-411f55f039b2c3b6` | 436,666,472 | `a2c70e8508ced69c6fdde88bc915dc9d7224ddd429ba27b0e812109aca5c375c` |
| `pool_mining-cc0741c5553beb4a` | 198,028,432 | `c79be812dc1015ba4d6e70b2fefe364c00e5847d3cb51a4fdfc33cfc0ae92329` |
| `architecture_delivery_compare-4678277dbc448539` | 202,422,880 | `5947b15474a1a2aa77e4b6285505aa8f00386ca855d81ad7d689cd1f974c6678` |

These are local observations before and after execution. The records explicitly
retain `exec_time_attestation=false`, independent deployment false and
whole-chain qualification false. Matching debug artifacts are not an
independent release build or proof that no file changed between observations.

### Local environment and execution boundaries

Chain used Rust/Cargo 1.95.0 and the recorded OpenSSL 3.5.9 provider executable
SHA-256 `35f28c82e7e4fdcd06b0a42062efd224a5fd5d32d5cc9894252f8206219d496e`.
[Earlier native environment](native-env.json), the source-bound
[final native environment](chain-final-native-environment.json) and individual
command receipts retain provider paths, build settings and source identities.
The final environment names `1d6a9f9…` / `4a0314e…`; its
[preflight log](chain-final-native-preflight.log) passed and has SHA-256
`1620576ebd51d7de5281b6cdbc4ffa3b6bc1a2f67653c0d26055ed2d1cf8a9af`.
Preflight and the provider executable hash do not identify or execute a Node
test binary.

The private Runtime environment record reports Rust/Cargo 1.96.0,
**just 1.59.0 and cargo-nextest 0.9.151**. The pinned workflow instead requests
**just 1.51.0 and nextest 0.9.103**. Local `CARGO_BUILD_JOBS=1` also differs from
the workflow's 2. These local runs use the repository's `just test` path, but
are not exact reproductions of the pinned hosted environment. The tool observations remain attached to the recorded `97ae5b4…` attempts;
separate ff19 and final9438 environment records now retain their own identities.
Final9438 keeps the same local/hosted tool differences. Source-head labels
without hosted run/job IDs are local provenance, not hosted execution.

The private Runtime bundle also retains a later stable hash observation for
two local unit-test artifacts and a byte-verified cache backup record for five
completed local debug artifacts. These observations preserve actual local
bytes. They do not attest the binaries' hashes at test execution, an independent
build, or a deployment release. The missing execution-path binding remains
explicit; artifact hashing does not resolve the failed process gates.

The shared filesystem exhausted available capacity during concurrent heavy
builds. Heavy native test execution was serialized and the superseded Chain
compilation cache was reclaimed; source and raw logs were retained. After
that cleanup, final Chain test precompilation overlapped Runtime scoped lint;
actual native test execution remains sequential. This changes local
build/cache conditions and supplies no capacity result. The existing container
observation that Unix-domain socket bind fails with **EPERM** was reproduced
by the final process tests above. Earlier TCP bind success does not remove
it. No test skip, permission workaround or relaxed product gate is credited
here; the failed process receipts remain in the private Runtime bundle.

## 3. Source changes present in the fixed candidates

### Chain mining: use the existing native time rule

The pool miner now asks the original consensus time predicate whether the
actual wall clock is admissible above the current branch's parent-first
MTP11. A legal future-dated immediate parent need not stall a child whose real
wall time already exceeds that median. The miner does not manufacture a
future timestamp or change DAA parameters.

The added median read is bounded to eleven headers, with the original
short-chain/genesis behavior. It preserves the pre-existing immediate-parent
record check and full packet decode. A header projection alone is insufficient:
a packet with an invalid transaction count can retain a plausible header, and
a genesis shortcut must not bypass malformed record fields. New source
regressions cover those boundaries, an admissible future tip and a median that
itself remains in the future. Their named native outcomes are included in the
37-control observation, while the complete target failures above remain binding.

See [mining.rs](../../trillionnium/crates/trnm-pon-node/src/mining.rs),
[store.rs](../../trillionnium/crates/trnm-pon-node/src/store.rs),
[pool_mining.rs](../../trillionnium/crates/trnm-pon-node/tests/pool_mining.rs), and
the [continuous-mining contract](../../docs/protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md).
This local liveness repair supplies no cheapest-work theorem, private-fork
bound, propagation qualification or confirmation improvement measurement.

### Chain Growth: retain the original request control before persistence

Growth materialization carries the caller's original cancellation/CPU control
through working-set copying, witness-account materialization, ordered delta
comparison, and the boundaries before and after canonical delta encoding.
Unchanged keys and final boundaries remain observable. Cancellation, budget
errors and original local storage errors retain their identity and occur before
publication of the admission result.

The working copy first builds a fallible vector of cloned pairs, then uses the
standard bulk State construction. This avoids continuing bulk construction on
a successful prefix after the control has already returned an error. It also
introduces a temporary pair buffer. Bulk map construction and an individual
encoding/provider/SQLite operation remain nonpreemptive; checkpoints do not
make every internal instruction interruptible. Existing bounded-working-set
limits remain. There is no measured speedup, lower peak RSS, removal of all
full-state work, or end-to-end deadline claim.

The source controls exercise cancellation and original-error preservation,
unchanged persistent state, legal retry/reopen, and comparison with an
independent ordered-difference oracle. See
[growth.rs](../../trillionnium/crates/trnm-pon-node/src/store/growth.rs),
[progress points](../../trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs),
[materialization controls](../../trillionnium/crates/trnm-pon-node/src/store/growth/tests/materialization_control.rs),
and [difference controls](../../trillionnium/crates/trnm-pon-node/src/store/growth/difference_tests.rs).
Their presence is not a native RED/GREEN receipt.

### Concurrent Chain changes retained by the integration

The merge also retains History/schema readback and private ancestry-spool
changes, Growth post-snapshot epoch checks, explicit header time at the M06
input, ordered prepared execution controls, and actual per-request CPU
settlement fields. Source review confirmed that the new epoch checks remain
after SQLite read-snapshot release; reusing a checked multiproof is limited to
that same read operation. Admission still performs its independent parent-proof
verification and rebinds current parent, time and state inside the original
write transaction.

The header-time regressions exercise real PQ transaction expiry at the M06
input boundary and classic Growth admission/replay compatibility. They do not
show a PQ Growth wire profile: the complete Growth packet path retains its
existing profile boundary. Parallel preparation still joins scoped workers
before canonical ordered application and durable commit. Its 30-second
condition-variable timeout bounds test coordination; public service budgets
are unchanged. New request-cost fields expose the original settlement values,
including canceled work and unknown clocks, without adding CPU credit.

The frozen integration's controls and concurrent additions were checked by
read-only Git object comparison. That review is not an executed native test.
See [read-epoch controls](../../trillionnium/crates/trnm-pon-node/src/store/growth/tests/read_epoch.rs),
[header-time controls](../../trillionnium/crates/trnm-pon-node/src/store/growth/tests/header_timestamp.rs),
[ordered preparation](../../trillionnium/crates/trnm-pon-node/src/store/growth/tests/parallel_preparation.rs),
and [actual request observations](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs).

### Private Runtime recovery and gate maintenance: cross-repository summary

The Runtime candidate advances the recovery contract to an ML-DSA-65 frontier
V4 and snapshot V3 with existing trust V2. It adds ordinary governance
invocation history, including pending and indeterminate outcomes, to the
signed recovery commitment. A narrow guard checks actual SQLite pagination
keys; typed decoding is intended to reject damaged projections without a
panic. Ordinary startup retains read-only preflight and repeated current
snapshot admission. The exact owner selection failed to compile on the
original source; after the separate `ff19c86…` repair, all 17 selected owner
controls passed once. The ff19 dispatcher selection subsequently failed at
Agentd test compilation. Final9438 independently passed its 120 static, 17
owner, 14 dispatcher and 11 signed selections, plus 155 eligible evidence-library
cases with one existing ignored fixture. Its original process group recorded
0 passed / 3 failed and its recovery process group 2 passed / 2 failed. Hosted validation remains
HOLD; local selection success does not qualify system recovery.

The selected workflow preserves all original seven owner and nine signed
controls, expanding to exact 17/11 rosters without changing 600-second recovery
budgets, zero retries, the 90-minute job, or required architecture/merge lanes.
Static maintenance aligns current migration labels through 0016, canonical
module/capability ordering and actual current callsite/test anchors. It retains
false acceptance states and historical source-observation provenance. The
original 120 static results and 14 dispatcher successes belong to `97ae5b4…`.
The final source's scoped `just fix` completed with exit 0 and unchanged
source, while retaining project and dependency warnings. Its detailed warning
categories and raw output stay in the private Runtime evidence. No claim that
all lint issues were automatically repaired follows from this command.
The following original `just fmt` exited 0 with no changed files and no source
diff; it did not perform a whole-repository `--all` formatting audit.

Full contract, fixture, source-binding and raw validation details remain in
[the private Runtime source index](#hepta-source-index) and its private evidence
follow-up ([private Runtime evidence](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/1556a4df6e279055fd8196f81a4ca2fe0f19384a/evidence/pq-invocation-recovery-20261105/README.md)). The recovery checkpoint does
not implement independent external freshness, consume/checkpoint atomicity or
a complete CURRENT-to-FinalUse effect transaction. Those obligations and the
old-Q0 whole-machine restore case remain HOLD.

## 4. All six system properties remain HOLD

| Domain | Required system property | Current blocker and required evidence | Verdict |
| --- | --- | --- | --- |
| Every authorization entry | Accounts, governance, publication, recovery, CURRENT and FinalUse must constrain real effects under the current PQ root. | Complete ordinary-entry/effect trace; current-root, revoked/retired-key and downgrade negatives; cross-owner CURRENT-to-FinalUse execution under the same frozen profile. Recovery startup and signed metadata do not demonstrate the final effect. | **HOLD** |
| Work and proof | The complete native relation and every candidate proof backend must satisfy an explicit cryptographic objective. | Exact statement/`IMAGE_ID` and current-parent/A/B artifact equivalence across the accepted-program set, concrete quantum/QROM assumptions and losses, and full proving-to-confirmation cost. Later peer complete-proof and receipt observations require their own source and image attribution; their existence alone does not close these system obligations. | **HOLD** |
| Mining and fork choice | Cheapest legal work, DAA, timestamps, private forks and propagation must hold together. | Adversarial cheapest-work/preprocessing/hardware bounds; joint DAA/time/private-branch analysis; actual propagation, stale-block and confirmation observations. MTP11 consistency fixes one owner rule and proves none of those joint properties. | **HOLD** |
| Historical migration | Old rights, nonces, debts, retired keys and executed effects must not resurrect after migration or recovery. | Independent freshness and the old-Q0 whole-machine restore case; durable consumption/effect reconciliation across owner boundaries; original migration/reorg/reopen checks. A matching older local database plus an older valid frontier is not evidence of freshness. | **HOLD** |
| Hostile capacity | Real PQ wire verification, memory, tail latency, History and recovery must stay within the original limits. | The unchanged four-second / 16-hostile-W1-producer campaign, all original confirmation/service subconditions, and the 4,105-block recovery campaign with its original Host, renewal, state-equality and reopen conditions. No new measurements here establish those outcomes. | **HOLD** |
| Independent deployment acceptance | Fixed source and binaries must be reproducible under separate administration and failure domains. | Exact source/lock/config/binary pins, independent replay/review, at least three genuinely independent administrators/failure domains, and the preregistered at-least-72-hour WAN/fault campaign with each cohort's objectives met. Local agents and repository-authored tests are not independent operators. | **HOLD** |

### Q0 whole-machine restore remains an explicit open window

Consider retained checkpoint Q0 matching state S0. A permission is then consumed
or an external effect occurs, advancing only local state to S1. Before a truly
independent owner publishes and retains Q1, restoration of the old machine
image can restore S0 together with Q0 and its trust files. The signed-file
admission can still see a matching, validly signed old pair. Rejecting S0
against a separately retained fresh Q1 is useful but does not close this Q0
window. A canonical path outside the Agent-owned directories is not proof of
an independent rollback domain.

The invocation commitment enlarges the history compared with that fresh
frontier. It does not establish external consume/checkpoint atomicity,
provider-owned idempotency/reconciliation, budget/FinalUse coordination, or
non-resurrection when every relevant local witness is rolled back together.
No Q0 acceptance upgrade is claimed.

### W1 scientific and image obligations remain explicit

The [statement-v2 record](../pon-w1-statement-v2-20261105/README.md) and
[component/QROM budget record](../pon-w1-qrom-budget-20261105/README.md) are
historical research evidence with their own identities. The latter uses an
explicit research failure-probability budget of `2^-128`; that is neither an
adopted protocol guarantee nor a quantum work factor. Its fixed component
terms do not certify that budget, and increasing queries alone does not repair
all terms. A complete instantiated recursive QROM argument and quantum query
budget remain missing. This failure to certify is not itself a matching attack.

The concurrently added [W1 v2 complete-proof record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/549c5a26616113c6aeee76a62f34dd780d729b75/evidence/pon-w1-full-v2-20261105/README.md)
reports **one fresh complete v2 proof** and **58 real receipt controls**. Its
executed clean source is `2810f7c2b1b5e549302b3fdb2cf41b2a6ee19bff`; the
record identifies `a635200956843f0d2f335f929977d602b48b36ec` as the published
commit with the same source tree. These are separate peer observations,
not executions within this round's frozen `1d6a9f9…` native invocation.

| Peer observation | Original budget | Recorded outcome |
| --- | --- | --- |
| One fresh complete v2 proof | 7,200 seconds | 6,253.711474144 seconds total; 6,248.484106799-second fresh proof pipeline; all 52 stages passed, including 43 segment proofs, recursion and independently built fixed-image verification |
| Real receipt controls | 120-second common budget | All 58 passed in 4.629197061 seconds: 1 positive and 57 negative, with zero unexpected acceptances, timeouts or panics |

The recorded verifier SHA-256 is
`9c3e3f321a24e1acb66638058fd77f67906824593422692f9e296e70a688fe65`.
The [fixed-peer integrity observation](remote-observation/chain-remote-549-w1-integrity-observation.json)
matched all13 retained assets' byte lengths/SHA-256 and checked the52-stage
and58-control report shapes. It did not run a prover or verifier and adds zero
proof trials.
Build/setup and input fixture construction were outside the declared proof
budget. The 100 saved-receipt replays and 1,000 native replays are not new
independent proof trials. Transfers were on single-host TCP loopback. The
earlier deadline failure and initial pre-test control failure, 0/58, remain
in the peer record. The negative-control rejection contexts include
construction and full receipt checks; the record does not assert that every
rejection traversed every STARK check.

This supplies a complete proof for that fixed v2 observation. It does not
establish complete-proof coverage of every later grouped or useful-cell
statement, PQ128, prover p99, complete process-tree memory, admission, parent
eligibility, real WAN propagation, confirmation or production activation.
Each candidate still needs exact statement/source/`IMAGE_ID` attribution and
accepted-program coverage. Preparation, complete execution, all
segments/recursion, verification, serialization, transmission, post-find
propagation and confirmation belong in the end-to-end cost. Private-fork and
cheapest-work findings must be assessed against that full cost. All six
system-domain verdicts remain HOLD.

## 5. Original denominators and acceptance conditions are retained

The original **four-second / 16-hostile-W1** gate and the **4,105-block/packet**
History gate remain the acceptance targets. The History obligations also retain
four renewals, independent full synchronization, state equality and reopen,
including the fixed Host/resource and original deadline conditions. Shorter
histories, alternative wire profiles, a no-attack subset or longer observation
time cannot replace them.

All planned cohorts, requests, confirmations, failures, deadline refusals,
resource aborts, cancellations and incomplete observations remain visible in
their original denominators. A command's zero exit is insufficient when its
business reader fails. A confirmation that was never observed remains missing,
not an infinite/zero latency value or a removed row. Server and client counters
retain their different observation boundaries; nested CPU intervals are not
added as independent costs.

The [retained native-liveness observation](../pon-native-liveness-20261104/README.md)
and [earlier fixed-pair ledger](../pq-workflow-continuation-20261105/frozen-b5bb-367e/README.md)
remain historical evidence. Their failed campaigns, incomplete native attempts
and source-specific limits are not overwritten by the new source repairs.
No public capacity, custody, economics, model utility or activation flag is
advanced by this README.

## 6. Reproduction and follow-up commands

Commands are instructions, not additional observations. Select the exact
source first and retain commit/tree, locks, environment, executable hashes,
stdout/stderr, terminal status, elapsed/resource observations, and before/after
source checks. Do not run from a moving or mixed checkout. Run heavy native
commands sequentially under the retained original limits.

### Final Chain static and changed-module scope

From the Chain repository root, with the intended source already selected:

```sh
set -euo pipefail
export GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1
chain_tested_commit=1d6a9f9b5e8abd9e86457f45199a4922f9376360
test "$(git rev-parse HEAD)" = "$chain_tested_commit"
bash scripts/project-preflight.sh
python3 -B scripts/ci/verify_ci_source.py \
  --kind head --expected-head "$chain_tested_commit"
python3 -B scripts/ci/test_ci_source_integrity.py
python3 -B scripts/ci/test_pq_research_integration.py
python3 -B scripts/ci/test_ci_contract.py
python3 -B scripts/ci/test_pq_chain_claim_guard.py
python3 -B scripts/ci/test_native_constants_roster.py
python3 -B scripts/ci/test_pon_public_v3_phase_read.py
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 \
  -p test_parallel_variable_ohie.py -v
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 \
  -p test_ghostdag_order_reference.py -v
python3 -B -m unittest discover -s formal/pon-nakamoto-v1/experiments \
  -p test_architecture_compare.py -v
python3 -B scripts/test_llm_runtime_release.py
python3 -B scripts/ci/check_repository.py
python3 -B scripts/refresh_distributed_source_inventory.py --check
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check
python3 -B scripts/ci/verify_ci_source.py \
  --kind head --expected-head "$chain_tested_commit"
```

The existing ELF module is also called by
[`repository-truth`](../../scripts/ci/ci_job.sh). A platform skip in that module
must remain a skip, not cold-runtime or installation acceptance. Formal
architecture tests remain model-specific research checks, not proof of the
full cheapest-work/private-fork/propagation system property.

### Native execution remains separate

The [corrected native roster](chain-observation-roster-corrected.json) and
[observation checklist](chain-observation-checklist.md) describe the relevant
retained/new controls. The [binary observer](chain-observation-binaries.py)
does not execute tests. Its [historical Clippy observation](chain-observation-historical-clippy.json)
belongs to `bbc940c…` and observes zero test executables; it is not a final-source
native result.

The separately prepared [pre-execution observer](chain-observation-pre-execution.py)
and [required ordering](chain-observation-pre-execution.md) are tools only.
They do not themselves establish that the build completed or that an ELF file
was observed; actual records must follow the completed original command.

The separate build-only command prepared all three targets without executing
tests. Its recorded terminal compile outcome is exit 0:

```sh
cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --test pool_mining \
  --test architecture_delivery_compare --all-features --no-run
```

The successful `--no-run` command establishes compilation only. The following
actual execution commands and the complete architecture target
remain separate observations.

The recorded library/pool invocation covered the complete targets, all features
and `--no-fail-fast`. It ended with exit 101 and the retained outcomes above:

```sh
cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --test pool_mining --all-features \
  --no-fail-fast -- --test-threads=1
```

The separate complete architecture target also ended with exit 101:

```sh
cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test architecture_delivery_compare --all-features \
  --no-fail-fast -- --test-threads=1
```

Use the existing fixed-Host campaign machinery for service and History
acceptance; unit/integration commands do not substitute. See the
[public campaign reader](../../scripts/ci/check_public_v3_service_campaign.py),
[History native runner](../../scripts/ci/run_history_native.py), and
[public-readiness contract](../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md).

The additional full Runtime evidence-library regression uses the original
600-second command budget and minimum17 as a separate local observation.
Its 156 discovered cases include one pre-existing subprocess crash fixture
that is not selected for ordinary execution. The final receipt records 155
passed and zero failed. Keep the one excluded fixture visible, do not add the
library total to its contained 17 controls, and do not use it as a hosted
selected-gate result. The original 97ae full-library timeout remains in the
private history.

Runtime reproduction and exact original selections belong to the
[private PQ workflow][hepta-workflow] and private Runtime evidence follow-up.
Its obligations retain 14 dispatcher / 3 original product / 17 owner / 11
signed / 4 recovery-product controls, exact-name/no-skip auditing,
3,600/1,800/600/600/1,800-second budgets, zero retries, one test thread and the
90-minute job. All four PR architecture/source-head/merge lanes remain required.
Run each repair-source invocation under its own explicit source/tree and
preserve both failed old-source attempts privately.

## 7. Publication boundary and retained holds

The actual Git commit containing this directory pins the evidence publication;
it does not need to contain its own hash. The selected base is `a16a89f…`, and the
intended first-parent change is this new evidence directory plus the sole-plan
append. The actual diff remains authoritative. Frozen `1d6a9f9…` native results do
not transfer to that later tree, and private Runtime publication `1556…` does not
inherit `9438…` native qualification.

All local commands in this record have terminal outcomes or explicit historical
stop observations. The original Chain command failures, 28 ignored cases,
missing full architecture report, both stopped earlier builds, Runtime
timeout/compile/process failures and remaining lint warnings remain visible.
The 37 added-control passes are a subset; matching local debug binaries and
one peer complete v2 proof do not override those boundaries.

Required hosted lanes, independent administration/failure domains, Q0 freshness,
real CURRENT-to-FinalUse effects, instantiated quantum security, combined
mining/fork-choice guarantees and original hostile capacity/History acceptance
remain **HOLD**. No production activation, deployment qualification or six-domain
closure is granted by publishing these observations.

### Hepta source index

All links below name source commit
`97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f`; these describe the original
source, including the fixture version that failed to compile. Repair-source
identity is `ff19c86b7190204e9172a1595a58d8eb9f897c6d`; compare the two
[repaired invocation fixtures][hepta-repaired-invocation-tests] and
[repaired schema fixtures][hepta-repaired-schema-tests] separately. None of
these source links is an execution receipt.

- [Invocation commitment][hepta-invocation] and [its seven control bodies][hepta-invocation-tests].
- [Actual SQLite key guard][hepta-schema] and [its three control bodies][hepta-schema-tests].
- [Fallible shared invocation decoder][hepta-record].
- [PQ recovery frontier/preflight/admission][hepta-frontier].
- [Recovery contract and external-consume boundary][hepta-recovery-doc].
- [PQ workflow selectors, budgets and exact-roster audit][hepta-workflow].
- [Module truth matrix][hepta-matrix], [capability map][hepta-map] and
  [current-source/historical-provenance manifest][hepta-native-binding].

[hepta-invocation]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/codex-rs/hepta-evidence/src/recovery_invocation_frontier.rs
[hepta-invocation-tests]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/codex-rs/hepta-evidence/src/recovery_invocation_frontier_tests.rs
[hepta-schema]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/codex-rs/hepta-evidence/src/recovery_invocation_schema.rs
[hepta-schema-tests]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/codex-rs/hepta-evidence/src/recovery_invocation_schema_tests.rs
[hepta-record]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/codex-rs/hepta-evidence/src/provider_record.rs
[hepta-frontier]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/codex-rs/hepta-agentd/src/evidence_frontier.rs
[hepta-recovery-doc]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/docs/lane-a-foundation/kernel.evidence/RECOVERY_FRONTIER_V1.md
[hepta-workflow]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/.github/workflows/hepta-pq-policy-renewal.yml
[hepta-matrix]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/docs/lane-a-foundation/MODULE_TRUTH_MATRIX.json
[hepta-map]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/docs/lane-a-foundation/CAPABILITY_EVIDENCE_MAP.json
[hepta-native-binding]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/97ae5b4bf5e5f0d0589c1c653f1861e1d9c1242f/qualification/module-execution-dossiers/NATIVE_BINDINGS_LANE_A.json

[hepta-repaired-invocation-tests]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/ff19c86b7190204e9172a1595a58d8eb9f897c6d/codex-rs/hepta-evidence/src/recovery_invocation_frontier_tests.rs
[hepta-repaired-schema-tests]: https://github.com/TrillionniumFoundation/hepta-private-ci/blob/ff19c86b7190204e9172a1595a58d8eb9f897c6d/codex-rs/hepta-evidence/src/recovery_invocation_schema_tests.rs
