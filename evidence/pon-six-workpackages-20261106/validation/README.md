# Local validation scope

The local working candidate starts at
`b173c1f52d927522af67df30dd08ecfb2e3a1bb0`. The native campaign and storage
repair records contain their own pre/post source hashes and command receipts.
Those are observations of the recorded bytes, not an assertion that an
uncommitted worktree was already a clean final publication commit. Final
publication requires byte comparison, source-pin verification and a separate
readback of the remote head. CI at an earlier head does not qualify a later one.

## Commands observed locally

| Command or suite | Result | Scope |
| --- | --- | --- |
| `cargo metadata --locked --offline --all-features` | 26 workspace members; 180 resolved packages/nodes | Exact existing lock; dependency metadata, no tests |
| `cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings` | Exit 0 | Whole Chain workspace, including optional provider and new native controls |
| `cargo fmt --all -- --check` | Exit 0 | Rust formatting |
| `test_ci_contract.py` | 101 passed after a retained harness-authoring failure | Real workflow/lane refusal controls |
| `test_ci_source_integrity.py` | 43 passed | Git/raw-byte/mode/source-substitution controls |
| `test_pq_research_integration.py` | 37 passed | Source pins, missing dependencies and unsupported activation refusals |
| `test_six_workpackage_native_rosters.py` | 6 passed | Original registry artifact and workflow roster mutation controls |
| `test_w1_full_v2_disposition.py` | 11 passed | Real retained proof input plus altered/missing/failure-erasure refusals |
| `test_pon_w1_preparation_strategy_reader_v4.py` | 24 passed | Complete-grid, attempt and cost-accounting controls |
| Native V4 example | 9 passed | Actual sampler semantics; see its separate source record |
| Native `storage_service::tests::` with all features | 20 passed, 0 failed, 0 ignored | Original 15 plus 5 new controls; 1,152 unrelated library tests filtered |

The native commands use their original Cargo profiles. The storage command
includes initial compilation and waiting for another Cargo lock in its
655.953-second wall interval; the test harness itself reports 11.72 seconds.
Neither number is a four-second public-service qualification. No build-only
command is counted as a test pass, and counts from nested or repeated runs are
not combined into a new acceptance population.

The first local CI-contract attempt executed 101 tests and had one error in
the newly authored mutation test: it used a fixture attribute belonging to a
different test class. The correction uses this class's actual root and refusal
helper. Both the original failure and the successful rerun are retained; the
failure is not silently reclassified as a passed command. Separate native RED
and missing-dependency observations remain in the settlement record.

## Runtime and verification limits

Rust/rustc 1.95.0 and matching official rustfmt/Clippy packages are used. The
optional OpenSSL provider was built by the unchanged repository preparation
script from the pinned 3.5.9 source archive. Its ML-DSA-65 sign/verify and
wrong-message-refusal smoke completed. The exact provider/tool download hashes
and source command logs are retained beside this note. No Cargo.lock edit,
fallback crypto provider, reduced test profile or changed service budget was
used to obtain these observations.

The V4 performance run has its own eight-CPU/8-GiB host declaration. It is not
the quarter-CPU/2-GiB original service campaign. Initial source-specific
SQLite-boundary qualification warnings, where present in earlier commands,
remain in those logs; later source checking cannot retrospectively qualify an
earlier executable. No independently operated host, physical rollback
resistance, energy measurement or complete-system release qualification is
claimed by this local validation.

Logs are losslessly compressed; the observation index records original byte
lengths and hashes. `committed-source-verification` receipts, when present,
record a separate final-source check rather than rewriting an earlier command's
identity. The two actual original CI roster failures and original service /
History failures remain in the main evidence record.
