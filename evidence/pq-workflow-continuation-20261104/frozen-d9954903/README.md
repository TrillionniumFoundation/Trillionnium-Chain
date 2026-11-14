# Final scoped validation of the frozen Chain / Hepta runtime pair

Status: **HOLD — the scoped checks below passed; whole-chain acceptance and activation remain open.**

## Immutable source identities

| Component | Code commit | Tree | Review |
| --- | --- | --- | --- |
| Trillionnium-Chain | `d9954903ef9239f71aa575ec3e6f4fdaa88f2d35` | `54442c70933c1ea37ebfe725628cbdd8685b746e` | [Draft #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688) |
| hepta-private-ci, the Hepta runtime | `484ce165522026d915c4cf526cd7df2effab632c` | `87608a9448e8cbb90c448bf82a495db1dfd32a45` | [Draft #4812](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4812) |

This record is an **evidence-only follow-up**. Its containing commit, a later PR head, and a GitHub prospective merge are not replacements for the selected code pair. The final tests below were executed against the immutable Chain commit above. Runtime source and formatter checks bind the runtime candidate above; they do not constitute a combined task or multi-node run.

The Chain code preserves the incoming Cell, metered Growth preparation, account-prefix ranges, persistent byte-budget rechecks, migration, W1 v2 and QROM work. Results from the earlier `38543c96` composition remain historical and were not transferred to this code. The source pair is suitable for review; the complete deployment profile, authority/custody map, and ordinary-path acceptance are still incomplete. [P0_BASELINE.md](../P0_BASELINE.md) records the partial inventory and existing performance owner.

## Four bounded repairs

1. **Reproduce prospective merge contents independently.** Correct parent SHAs alone cannot establish a merge's tree. The source guard independently constructs the canonical merge tree, with an isolated empty-template bare repository, object alternates, and sanitized Git configuration/environment for the divergent case. It refuses injected/omitted content and unknown or conflicting compositions. Controls cover configuration, attributes and merge-driver interference. The synthetic controls passed; an actual GitHub prospective merge was not executed here.
2. **Give the public server one cache owner.** Rejection-cache setup now rejects either an existing rejection cache or an arithmetic-facts cache. Arithmetic-facts setup rejects an existing rejection cache. Native tests exercise both mixed orders, repeated rejection-cache replacement, and preservation of the original cold CPU budget/profile with either cache alone.
3. **Use exact boundaries for quantum candidate-check accounting.** The upward clock uses rational boundaries consistently when accounting for elapsed checking stages. Six new controls cover started/in-progress checks at the affected boundaries; the combined candidate/network/resource-clock suites passed. This repairs model accounting and does not establish a quantum work factor or deployment threshold.
4. **Refuse a shared runtime clock/frontier endpoint path early.** The PQ authorizer compares the resolved clock and frontier paths before opening trust clients or creating its authority directory. Source tests cover both path-assignment directions and the exact early constructor error. Native execution of those runtime tests remains NOT_RUN. Distinct paths alone do not prove independent administrators, custody, every possible alias exclusion, or effect atomicity.

See the immutable [Chain code](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/d9954903ef9239f71aa575ec3e6f4fdaa88f2d35) and the [runtime repair and checks](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/484ce165522026d915c4cf526cd7df2effab632c/evidence/pq-final-use-endpoint-separation-20261104/README.md).

## Final checks actually executed

| Check | Result | Exact scope / receipt |
| --- | --- | --- |
| CI source integrity + command recorder | **47 passed** | 43 source controls + 4 recorder controls; [log](source-integrity.log) |
| Quantum candidate, network and resource clocks | **63 passed** | Model implementation controls; [log](quantum-clock.log) |
| PQ research integration + claim guard | **57 passed** | Source/claim controls; [log](pq-controls.log) |
| Native public-cache modes | **4 passed**, 0 failed / ignored / filtered | Actual Rust constructor integration tests; [result](native-cache-modes/result.json), [Cargo log](native-cache-modes/cargo.log) |
| CI structural contract | PASS | The checker explicitly says `tests_executed: false`; [log](ci-contract.log) |
| Generated source inventory | PASS | Repository generator `--check`; [log](source-inventory.log) |
| Shell syntax | PASS | `bash -n scripts/ci/ci_job.sh` |
| Rust workspace formatting | PASS | `cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check` |
| Complete tracked-source identity before and after all tests | PASS | **9,197 entries / 948,887,514 bytes**; [before](raw-source/head-source-identity.json), [after](raw-source/head-source-identity-after-tests.json) |
| Exact source-corpus contract | PASS; **HOLD_NO_GO** | **464 pinned source blobs / 6 upstreams**; [receipt](raw-source/pq-research-integration.json) |

The four test groups total **171 scoped passing tests**. They are not 171 newly added tests, a complete native workspace suite, or ordinary PQ end-to-end acceptance. Identity, formatting and structural checks are not additional native test cases. [checks.json](checks.json) contains exact commands, environment overrides, return codes, durations and log hashes.

The complete source checks use **head mode**, with the expected commit and tree above. They verify all tracked bytes and clean worktree state, and explicitly do not execute tests themselves. Setup receipts retain the earlier `81da33e6` checkout and the subsequent transition to the corrected commit; only the final `d9954903` checks establish the selected result.

### Native execution conditions

The cache suite used Rust/Cargo 1.95.0, default features, `--locked --offline`, one build/test thread, no incremental compilation, and explicit debug/optimization settings suitable for this bounded correctness run. The command took **98.183603 seconds including compilation**. That duration is unrelated to the original 4-second business gate.

Before and after execution, HEAD, tree and clean worktree remained identical. All **1,245 Git-tracked files under `trillionnium` and `config`** matched the frozen commit, with aggregate SHA-256 `2f96825a93f5db926dd310f0412e455f9b5c684ef43773f882ef29debdefaf75`. The more restricted 1,213-file native/config manifest and all ten publication-manifest entries also matched. The [before](native-cache-modes/native-config-manifest-before.json) and [after](native-cache-modes/native-config-manifest-after.json) manifests preserve the actual inputs.

The build emitted **`trnm SQLite I/O boundary UNQUALIFIED: RUSTC must be absolute`**. This warning is retained. The constructor suite therefore establishes neither the SQLite boundary's qualification nor Host/business performance. No timeout, resource abort or storage abort occurred in the final run.

Two preflight-only attempts are retained: missing local origin metadata, then detached local branch metadata. Neither launched Cargo. The metadata repairs preserved the same commit and source tree; [origin repair](native-cache-modes/checkout-origin-repair.json) and [branch repair](native-cache-modes/checkout-branch-repair.json) explain the changes. Earlier blocked attempts are not counted as test passes.

### Runtime execution conditions

The runtime's exact source identities, direct formatter, repository `just fmt --base 5bf9e9eb7dc49ef56caf5143531f3a705fcd0e52`, and `git diff --check` passed. Its host package suite and new/expanded endpoint native controls are **NOT_RUN**. The current environment refuses `socket(AF_UNIX, SOCK_STREAM)` with EPERM. The [runtime record](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/484ce165522026d915c4cf526cd7df2effab632c/evidence/pq-final-use-endpoint-separation-20261104/README.md) preserves the probe, an initial clone failure, exact format receipts, and the repository-native continuation command.

## Integration failure retained and corrected

The initial publication checkpoint `81da33e609cb64b319e8cfcca7059e5c30d39044` contained an API-side edit error in the generated distributed source inventory: inserting the new test entry omitted the opening/path of the existing `public_cli.rs` entry. The repository generator and workspace formatter rejected it. The four native cache tests alone did not compile that examples surface and could not establish its correctness.

The real generator repaired the inventory, the affected corpus blob pin was refreshed, and the correction was published as the selected `d9954903ef9239f71aa575ec3e6f4fdaa88f2d35`. The initial failures, regenerated checks and correction are preserved in [inventory-correction](../inventory-correction/README.md). **All final groups in the table above were then executed again on the corrected immutable commit.**

## Roadmap status

| Workstream | What this receipt establishes | Acceptance still required |
| --- | --- | --- |
| P0 | One explicit code pair; exact complete Chain source identity; scoped command and input manifests | Complete deployment profile, cryptographic-asset and authority/custody/call inventory; old-configuration conclusions remain separately scoped |
| A1 | Early runtime clock/frontier path refusal; source/claim controls | All ordinary task, payment, CURRENT and FinalUse PQ paths; missing/wrong authorization refusal in real runtime execution. Native Growth currently refuses PQ identity |
| A2 | Concurrent migration work preserved | Conservation, debt, nonce, tasks, key generations, CLAIM/retirement, cross-activation reorg and non-resurrection acceptance |
| A3 | No closure claimed | Stable effect IDs, consumption and independent witnesses coordinated through rollback, clone, crash and reorg; provider-effect atomicity |
| B1 | Cache-owner composition repaired and natively tested; concurrent Growth work preserved | Actual no-attack business baseline, real GrowthV2 hotpath integration and explainable scale costs |
| B2 | No threshold changed | Original **4 seconds / 16 hostile producers**, every existing subcondition, budgets, real cancellation, Cell/sync isolation |
| C1 | Existing work-cost records retained | Fastest legal solver set, selection/reuse analysis, actual-parameter attacker-cost assumptions; honest FLOPs are not a lower-bound argument |
| C2 | Candidate-check clock accounting repaired | Best legal quantum model, marked domain and physical cost, private branches/DAA, deployment thresholds, chain growth and reorg conclusions |
| D | Existing W1 v2/QROM candidate evidence retained | Complete new W1 proof, instantiated security composition, actual parameters and end-to-end benefit before any main-path admission |
| E | Reviewable fixed source pair and local scoped logs | Real Hepta task and multi-node campaign on this pair, engineering gates and independent acceptance |

The retained [W1 v2 record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/d9954903ef9239f71aa575ec3e6f4fdaa88f2d35/evidence/pon-w1-statement-v2-20261105/README.md) binds the fuller statement, but does not contain a completed accepted new v2 proof. The retained [QROM budget record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/d9954903ef9239f71aa575ec3e6f4fdaa88f2d35/evidence/pon-w1-qrom-budget-20261105/README.md) exposes unresolved parameter/composition terms; it is not a mining/DAA security theorem or a measured quantum attack.

The historical V8 result belongs to Chain `73ab6e9a83bcc836e261d93f9bb23ceafe556758`; it does not qualify this pair. Full workspace native tests, strict workspace Clippy, actual GitHub prospective-merge execution, the original performance campaign, runtime native acceptance, complete proof benefit and independent acceptance were not completed by this continuation.

No production activation or whole-chain security gate is closed. The sole [development plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) and existing Draft PRs remain the acceptance owners.

## Evidence index and publication checks

- [Machine-readable summary](summary.json)
- [Exact commands and return codes](checks.json)
- [Native runner and result](native-cache-modes/result.json)
- [Complete post-test source check command](raw-source/after-tests-command.json)
- [Artifact hashes](artifact-manifest.json)

All code changes and final receipts are published through the existing Draft PRs with expected-head, non-forcing ref updates and the configured GitHub noreply identity. The evidence commit adds receipts and documentation; the tested source pair above remains fixed.
