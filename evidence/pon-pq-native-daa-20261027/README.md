# Scoped native PQ and conditional DAA evidence, 2026-10-27

## Source and verdict boundaries

The executed native code is local commit
`99be553ea80bee137b0bcc3b67d8786348547256`, tree
`08b3b7d9dab4b767a0629cecd0dc6855cb3232e9`. Its real parents are
`8dc693f085e40553c12a90d5f7ffccd03638c761` and upstream integration
`21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59`; the original PQ integration
base is `5e797326b9c7635e43b93f97c65a309e51eafb46`. The only later native file
change is the two size-bound test assertions
converted to equivalent compile-time assertions in
`215fc89386a6375e8a2663774085c3a11b24e24e`. The retained scoped binary tests
were executed at 99be; strict Clippy and one exact copied-binary size-bound test
were executed at 215f. The following archive commit changes only documentation
and evidence.

The strict atomic native wrapper **failed its final source guard**. It had
compiled and run the scoped Cargo tests, copied four unique test executables,
checked their hashes and required new test names, and replayed those copies.
All 1,675 tracked non-evidence files matched the frozen Git blobs again, but
the post-check found old self-generated hex fixtures as untracked files. The
wrapper did not write a successful result JSON. Its earlier attempt refused
before Cargo on the same extra-file condition. The files' repeated appearance
has no established cause. No ignore rule, source-check exclusion, or rewritten
successful receipt was added to suppress it.

`atomic-source-guard-observation.json` separates the recorded original tool
observation from a later actual rerun of the same refusing guard.
`frozen-native-diagnostic-manifest.json` is an explicitly diagnostic
reconstruction from the retained unique executables and raw logs, not a
successful atomic-wrapper receipt. Historical upstream evidence is sparse in
the local checkout, so a complete repository source guard is also not claimed.
The clean published checkout must execute the repository's original gates.

## Actual test observations

| Scope | Observation | Raw evidence |
| --- | --- | --- |
| Original local PQ owner plus three regressions | 5 pass, 3 fail; successful records could lack durable rows or sequence advancement | `logs/base5e-pq-baseline.log`, `logs/pq-owner-baseline-red-tests.log` |
| Hardened actual local owner | 12 pass, including a real SQLite `SQLITE_FULL` rollback and successful capacity-restored retry | `logs/merged-native-86b3bead680b-trnm_pon_node-frozen-tests.log` |
| Native M01 selected PQ tests | 5 pass, including the full pinned 210-case Wycheproof corpus | `logs/merged-native-86b3bead680b-trnm_crypto_primitives-frozen-tests.log` |
| Full M00 lib suite in copied binary | 39 pass, 2 original ignored tests remain ignored | `logs/merged-native-86b3bead680b-trnm_protocol-frozen-tests.log` |
| Full M06 lib suite in copied binary | 78 pass, 6 original ignored tests remain ignored | `logs/merged-native-86b3bead680b-trnm_mvcc_fee-frozen-tests.log` |
| Independent real ML-DSA fixture check | 7 cryptographically valid vectors; malformed duplicate hint refused | `logs/qtx-raw-real-crypto.log` |
| DAA/native arithmetic | 7 tests pass; 1,079 comparisons with directly included original M02 source | `logs/quantum-daa-final-tests.log` |
| CI contract after retaining upstream 21e | 95 pass | `logs/ci-contract-merged-tests.log` |
| Negative source-integrity controls | 34 pass | `logs/source-integrity-negatives.log` |
| Original project boundary regressions | 16 pass | `logs/project-boundary-tests.log` |
| Workspace formatting | exit 0, no output | `logs/merged-cargo-fmt.log` |
| Strict workspace/all-target/all-feature Clippy | exit 0 with original `-D warnings`; one build job; all 1,675 tracked non-evidence blobs match before/after | `logs/final-clippy-result.json`, `logs/final-clippy.log` |

The final Node selector ran only the 12 PQ-owner tests, leaving 723 other tests
filtered. The M01 selector left 108 tests filtered. This archive does not claim
the complete Node, M01 or workspace test roster ran. The four executables total
roughly 427 MB; only their complete hashes, byte lengths and raw results are
committed. The recorded runner copied each binary to a unique path in the same
process immediately after Cargo completed and rehashed it after execution.

The first SQLite capacity test did not actually exhaust its pages and failed.
Its log and JSON remain under `pq-owner-hardened-complete-*`. The corrected
setup materialized 512-byte pages with `VACUUM`, asserted their size, and reached
the real storage failure before observing rollback. The original 5e CI-contract
test run also retains its 94-pass/one-error result for native/fuzz `typenum`
lock drift. The already published upstream 21e lock correction was retained as
a real merge parent; the contract was not relaxed to accept the mismatch.

## Commands and reproduction

Use the repository-declared Rust 1.95 toolchain and exact locked Cargo graph.
The original run used the verified offline vendor input for the integration
base; it added no native dependency. Every separate scope retains its own
meaning:

```bash
bash scripts/project-preflight.sh
python3 scripts/pon_pq_native_fixtures.py --check trillionnium/crates/trnm-protocol/tests/fixtures/pq_transfer
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-mvcc-fee -p trnm-crypto-primitives -p trnm-pon-node --all-features --lib pq_
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-mvcc-fee --all-features --lib
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_daa.py -v
python3 formal/pon-nakamoto-v1/quantum_daa.py --output /tmp/pon-quantum-daa.json
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The `.py.txt` files in `recorded-runners/` preserve the exact local recording
scripts, including local paths and the strict wrapper that refused. They are
records, not installed CI or portable successful-receipt generators.

`reproduce-original-owner-red.patch` is a reviewable reproduction prepared from
the current three regression functions. Apply it only to a fresh separate
development worktree at 5e and run `cargo test --locked --manifest-path
trillionnium/Cargo.toml -p trnm-pon-node --lib pq_authority`. It retains the
original five tests and appends three tests expected to fail against the
original owner. This post-run reproduction patch is not claimed byte-identical
to the first red-run test file. The original owner source has SHA-256
`eea7ab0d099dfd485491a81da4d172336a70ae98b89b85b0715e77e9736c5648`.

## Interpretation and remaining obligations

The QTX1 route is an explicit fresh-network **component preview** using actual
M01 verification and shared M06 nonce, fee, balance and root arithmetic. It
does not install normal Node admission, mempool reservation, durable account
commit, migration or Hepta final-use authority. The hardened local PQ owner
does not resist a consistent rollback of the entire SQLite file or qualify
physical power-loss behavior.

`logs/quantum-daa-final.json` assumes valid W1 for synthetic headers and an
isolated quantum search rate. It produces no W1 proof and no reversible W1
circuit. `w1-static-ledger.json` and the component contract enumerate complete
source-level work, including cached setup, every prefix, bounded noise, streaming
hashes and verifier-only costs. Those counts are neither quantum gate estimates
nor lower bounds against the existing paired/structured producers. The assumed
`r=0.25` is not derived from that ledger. Fixed-p0/fresh-m remains unproven.

Production activation, whole-node PQ integration, whole-chain PQ security,
physical rollback resistance, quantum PoN hardness, independent-operator and
public-WAN qualification remain false or open. No consensus fallback, pairing
proof, independent hash grinding or validator committee was introduced.

The first exact-source strict Clippy run at 99be failed on the inherited
`pq_frame.rs` constant assertions. Its original log and both complete source
snapshots remain in `logs/strict-clippy-99be-red/`. Commit 215f retains both
size bounds in a `const` block without lint suppression or test removal. The
exact size-bound test was compiled, copied to a fresh executable, hashed and
executed at 215f; `logs/const-assert-result.json` records the nonzero one-test
selector. No full suite was rerun or claimed at 215f.

The Clippy build retained the original SQLite I/O-boundary **UNQUALIFIED**
build-script warning. Passing static lint does not qualify that physical I/O
boundary. See the [component contract](../../docs/security/PQ_NATIVE_TRANSFER_AND_QUANTUM_DAA_V1.md)
for the precise implementation and W1 oracle ledger.
