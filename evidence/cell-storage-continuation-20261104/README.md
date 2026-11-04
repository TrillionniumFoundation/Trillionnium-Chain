# Model storage continuation — source and observations

This record belongs to the existing Chain integration candidate and the
[sole plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The implemented contracts and their remaining gates are in
[CELL_MODEL_STORAGE_V1](../../docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md).
It is a local source/runtime observation, not production, model-efficacy,
funded independent custody, WAN performance or CURRENT/FinalUse acceptance.

## Preserved source and failures

[source-provenance.json](source-provenance.json) identifies the exact
`93e207c8d2ccb8509f78566223abc371b9d8118b` integration base and archival
`d48c8070f1dfe406a7405fd875909b68db0e6b9a` input. All 27 restored reference blobs
were checked independently against their recorded SHA256, Git blob SHA1 and
size. The historical generated native inventory was not copied; the current
inventory is regenerated from the actual source tree. New TCA2, tensor and
persistent-transfer code is not attributed to the historical archive.

The original [M09 baseline](baseline-m09-lib.log) executes **186 passed,
0 failed, 0 ignored** tests on the unchanged integration base. The first
[retirement selector](retention-red-empty-selector.log) accidentally matches
zero tests and supplies no PASS evidence. The corrected
[exact regression](retention-red-exact.log) executes one real test and fails:
the old physical owner returns `retired: true` while an interrupted repair
remains unsettled. The new writer guard and release catalog preserve the
obligation until exact repair reconciliation.

The [initial compiler diagnostic](initial-compile-diagnostic.log) retains the
missing in-progress persistent-test module and the `Vec<i32>` SQL fixture error.
Both are actual development failures; neither is omitted or represented as a
runtime result. The [intermediate library run](intermediate-m09-lib.log) then
passes 254/0/0 and the [intermediate full M09 test invocation](intermediate-m09-tests.log)
passes the same 254 native tests plus 26 CLI integration tests. These precede
the final typed-plan cold recovery and release-wide connection-pool additions,
so they are not a substitute for those additions' final-source checks.

## Reproduction requirements

Run `bash scripts/project-preflight.sh` before edits/builds. Use the repository's
locked Rust toolchain and original pinned PQ provider setup where required.
The source has 26 workspace members and the unchanged 180-package lockfile;
the actual selected-platform Cargo metadata resolves 175 packages. Moving the
existing serde/serde_json versions into M09's ordinary dependency graph enables
typed tensor parsing. The original `arbitrary_precision` feature remains a
dev dependency, preserving its existing scope instead of widening ordinary
number semantics. The lockfile SHA256 remains
`773cd1364a02cc70b017412350e2343172ae4f2a8770b044a5a307e33a638d0a`.

The native regression and CLI entrypoints are ordinary retained Cargo targets:

```sh
bash scripts/project-preflight.sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --all-targets
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib store::storage_service
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --all-targets -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/check_repository.py
```

From `formal/pon-nakamoto-v1`, run
`python3 -m unittest -v test_model_release_root` for the independent TMR1
oracle and fixed vector. Source integrity also requires the retained negative
CI/source/claim tests; deleting a newly required file and its pin together or
reusing an old pin after mutation must fail. All activation/qualification
flags retain their previous false values.

## Interpretation

The tests use synthetic canonical payloads and real local TCP, SQLite, files
and CLI processes. They prove the stated pin, byte, parser, resume, deadline,
retention and collection behaviors within their declared profiles. They do
not prove release-owner completeness for a real architecture, numerical model
safety, Expert ABI, arbitrary codec support, independent remote copies,
automatic funded renewal, current chain-height truth or actual authorization
at use. Those owners and the original WAN/product-loop gates remain required.
