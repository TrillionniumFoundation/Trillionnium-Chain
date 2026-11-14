# Follow-up 666-control migration preparation

Prepared only. No control suite, Cargo command, native test, benchmark, source verifier, or preflight command was executed for this preparation. The only Python source inspection was AST parsing of the current 819 test files. The original 819 full native package is still running; wait for its authoritative terminal state and source-after, then for root's explicit new committed worktree, H, tree and launch window.

## Preserved identities and current static roster

Original runner: /home/qian-qi/chain-throughput-local-admin-20261107/final-source-validation-20261107/run-final-controls-v3.py
SHA256: 27bde97006593d37a7fbae3b93d10d81c0178c9342659e8671f585c4c3b09c81
Original roster: /home/qian-qi/chain-throughput-local-admin-20261107/final-source-validation-20261107/prepared-test-roster-v3.json
SHA256: 950e9ceff839a8c599f4ebdb4a1b6d72bd7719f48557c76c832b74b8518aed72; 225337 bytes.

All 17 suite source hashes, imported-class source hashes and sorted test identities currently match this roster on 819309fd312298e099642e1253b1d4ba07113e98. Static method total: 666. This is a name/hash check, not execution, and does not establish the count or outcome for a future commit.

The roster retains historical preparation fields (including its earlier observed, not-frozen source head). Do not rewrite them to make them look newly observed. Actual execution identity comes from the new invocation, original full-source verifier and per-suite source hash checks.

## Minimum adaptation after the new source is frozen

Copy the original runner to a new external filename tied to the new H; preserve the original file. Change only its ROOT assignment to root's actual new isolated worktree. BASE, PREP, ROSTER, the roster SHA, source verifier SHA, EXPECTED_TOTAL, functions, command arrays, parsers and timeouts remain unchanged.

Keeping PREP at final-source-validation-20261107 is sufficient: output is already a new directory named by the complete new H, must lie beneath PREP and outside ROOT, and mkdir(exist_ok=False) refuses reuse. This also leaves Cargo's metadata-only target outside the source and separate from native targets. No runtime source-root override or global monkeypatch is needed.

Before launching, inspect the copied runner's AST and require every function body and execution/parser definition to equal original v3; the only permitted AST difference is the ROOT assignment. Record both runner hashes and a short exact diff. Do not create or launch a placeholder executable now.

The unchanged CLI requires --expected-head with a complete lowercase 40-hex H, --output under PREP, and --execute. Independently compare HEAD and HEAD^{tree} with root's frozen H/tree before the one launch. The original source verifier then verifies the whole tracked worktree against that immutable H; its emitted tested_tree must equal the supplied tree. H binds its tree without changing the original verifier or synthesizing a merge identity.

Repeat the static roster/hash/imported-class comparison on the actual NEW worktree before launch. Any changed Python test source or changed set of names is a stop-and-review condition, not a reason to weaken the old roster. The present Rust-only proposal suggests 17/666 remains correct; only the new bytes can establish that.

## Unchanged validation contract

- 17 original unittest CLI commands, each using the actual /usr/bin/python3 and -v.
- Expected suite counts: 37, 43, 13, 149, 29, 79, 7, 4, 103, 20, 47, 34, 11, 11, 20, 34, 25 = 666. Cell remains 8 suites / 202; Host includes its four imported test classes and is 79.
- Every verbose expected name must appear once, one matching Ran summary, exactly OK, no skip/expected-failure success, real process exit 0 and no timeout.
- Static/original checks: preflight --audit; check_ci_contract.py; check_pq_research_integration.py; refresh_distributed_source_inventory.py --check; check_repository.py; git diff --check; actual Cargo/rustc versions; cargo +1.95.0 fmt --all -- --check; locked/offline/all-features cargo metadata.
- Existing driver command timeout defaults 600 s; every suite has 1800 s supervisor bound. Genuine Cell child timeout remains 30 s. Do not change a child timeout, CPU/Host configuration or runtime identity.
- Actual Python must remain the prepared 3.12.3 / NumPy 1.26.4 / cryptography 41.0.7; discovery records actual installed files. If different, stop rather than spoof.
- Preserve GIT_NO_LAZY_FETCH=1, GIT_NO_REPLACE_OBJECTS=1, GIT_OPTIONAL_LOCKS=0, offline Cargo, no source-local output/bytecode, no native builds or benchmarks.
- Every failure stays in its original log and record; the driver continues through remaining suites and performs full source-after in finally. It must not restart failed suites.
- Full source-before and source-after must be verified and byte-identical. One stable launch idempotency key belongs to the exact H/runner; collect authoritative terminal state and durable, complete output before reporting.
- These controls do not qualify the four-second/16-worker service, 4105 History, fixed-resource Actions, model efficacy or release. state_growth independently owns the 16 targeted native commands.

## Source pin and inventory changes owned by integration, before freeze

The proposed edits are store.rs, legacy_reorg_root_tests.rs (helper-reference rename only), and the new store/legacy_admission_root_tests.rs module. After final formatting:

1. Regenerate trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs using the existing refresh script. It enumerates filenames and embeds include_bytes; the new Rust module must be included. The validation driver only runs --check and will never repair it.
2. In config/pon/pq-cross-branch-corpus-v1.json, update pinned_blobs for store.rs, legacy_reorg_root_tests.rs and the regenerated inventory; add the new test module's real Git blob ID and corresponding required_paths entry. Preserve existing test names, historical source inputs and evidence. These are Git blob SHA-1 object IDs, not file SHA256.
3. Update only the existing store.rs Git-blob literal in .github/workflows/pon-recent-batch-acceptance.yml:76 to the final actual store.rs bytes. Its original value on 819 is 6769b89e1544d82fb41d418adf11d6b26ef01cc3. Do not alter triggers, matrix, resources, command selectors or gates.
4. Final helper rename changes file blobs but does not change original Python cases or old Rust test selectors. The new Rust test is outside the 666 Python-method denominator. Do not increment the Python total for it.
5. Finish root-owned evidence and the sole plan, then commit and freeze. Do not add or edit tracked documentation/evidence during source-before/after validation.

The new worktree must have the full tracked tree and the existing Cell model fixtures. If it shares repo.git, the prepared 9fedf7ecbbe07177069c030592b4e03dcffebb81 object closure should be shared, but verify availability with lazy fetching disabled instead of assuming it. Preserve the real 415-object preparation and fixture evidence; do not fetch implicitly, synthesize historical objects, or change model inputs to make a missing-input test pass.

## Awaiting root

Required before any execution: new isolated absolute worktree path; committed clean H and tree after all evidence/sole-plan/pins/inventory updates; confirmation that original 819 full native/source-after is terminal; an explicit launch window coordinated with the targeted native owner. No future source-control result is claimed.
