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

The later [release CLI compiler diagnostic](release-cli-compile-diagnostic.log)
retains a missing import used by `prepare-release`; the original import was
restored. The [strict Clippy diagnostic](persistent-clippy-diagnostic.log)
retains one unnecessary unit expression in a test; it was removed without a
lint allowance. Both are followed by the committed-source checks below.

## Exact committed-source results

The implementation commit is
[`3e866c637197339700c93a6b716d20a3968291f1`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/3e866c637197339700c93a6b716d20a3968291f1),
tree `38fd2b903c276d3d53e44a0e2fbd7ef3373681f1`. The existing source recorder
checks all **8,796 tracked entries / 941,172,912 bytes** before and after each
command. Both receipts finish `command_succeeded`, exit 0, with identical
before/after source identities. The first evidence follow-up, `f6941358`, adds
evidence only; its implementation, configuration, source pins and protocol
documents retain the tested commit's exact bytes. Later concurrent composition
is recorded separately below; these original receipts are not relabeled.

| Actual check | Result |
| --- | --- |
| M09 library | 261 passed, 0 failed, 0 ignored |
| M09 CLI integration | 29 passed, 0 failed, 0 ignored |
| Selected M12 native paid-storage controls | 7 passed, 0 failed, 0 ignored; 994 other Node tests filtered |
| Raw CI source-integrity negative tests | 34 passed |
| PQ source-integrity negative tests | 34 passed |
| Claim-guard negative tests | 22 passed |
| Authority-surface negative tests | 11 passed |
| Independent TMR1 Python vector/oracle | 4 passed |
| Whole-workspace, all-targets strict Clippy | PASS, default features, `-D warnings` |
| Workspace formatting and embedded source inventory | PASS |
| Exact source pins and repository checks | 421 pinned blobs; 2,474 local links; qualification flags remain false |

The [main receipt](exact-source/cell-storage-exact-source.json) and its
[complete log](exact-source/cell-storage-exact-source.log) bind M09, the
workspace static checks and all five Python suites. The
[paid-storage receipt](exact-source/native-paid-storage-exact-source.json) and
[complete selected-test log](exact-source/native-paid-storage-exact-source.log)
bind the seven neighboring storage controls. These are **297 distinct native
and CLI test executions plus 105 Python tests** in the stated final set;
earlier repeats are not added. This is not a full Node-suite execution.

[Retained-test coverage](retained-test-coverage.json) matches every original
186 baseline name against the final 261 library names. All original archived
archive/model-root/delta/delta-network controls remain: 15 + 4 + 4 + 2 = 25.
The process-death parent test's output is interrupted by inherited child stdout;
its result is established by the full name set and successful terminal count.
The child name is not counted twice. Printed `FAIL` receipts inside source
negative fixtures are expected rejection controls, not additional failed
native invocations.

The [first Node compilation](node-initial-sigkill.log) was killed with SIGKILL
before executing any tests, exit 101. The container's 8 GiB memory limit and
cgroup observations are consistent with resource exhaustion; no source
diagnostic was emitted. The [single-job retry](node-single-job-retry.log)
changes only `CARGO_BUILD_JOBS` to 1, preserving the original package
optimization, test assertions and timeouts, and executes all seven selected
tests successfully. Its later committed-source rerun also passes. Command
wall time includes shared build-directory waiting; none of these durations
is a performance comparison.

## Concurrent integration composition

Before moving PR #688, its head advanced from `93e207c8` to
`d0737cf5434894ce47fad8082376fc417313c2cb` through the Cell residency,
generated-inventory and evaluation/weight-loading commits. The integration
preserves all three commits and both continuation sections in the sole plan.
The M06 evaluation and Python weight-loading source files retain their exact
concurrent bytes.

`release.rs` composes the concurrent marker-free `fetch_closure` with the
shared network session. Both marker and no-marker paths retain full manifest,
aggregate-budget, payload and final deadline checks. TMA still runs the actual
tensor reader before publication. The new real-TCP composition control covers
all four marker formats and marker-free prefetch under both insufficient
payload and chunk budgets: only manifests may be fetched, no payload row or
marker may appear. Residency slots/bytes/references keep their separate
original owner and are not redefined as disk-cache capacity reservations.

Required-path and blob-pin sets retain the union of both inputs; all three
residency entrypoints also become mandatory in the source-integrity checker.
The native inventory is regenerated from the actual combined source. Current
composition observations belong in their own receipts; the 7 selected Node
results above remain bound specifically to `3e866c6`.

### Exact composed-source results

The composed implementation is
[`b110ba5bc1f755e5988c1b1f710243677976bcc8`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b110ba5bc1f755e5988c1b1f710243677976bcc8),
tree `20d41d881353ae7f66f1d15f326274ee811f7c65`, with ordered parents
`d0737cf5` and `f6941358`. The [main composition receipt](composition/cell-storage-composition-exact-source.json)
and [complete log](composition/cell-storage-composition-exact-source.log), plus
the [selected owner/documentation receipt](composition/cell-storage-composition-owner-doc-controls.json)
and [complete log](composition/cell-storage-composition-owner-doc-controls.log),
all finish successfully with exact before/after identities. Each source check
verifies **8,811 tracked entries / 941,457,721 bytes**. The first composition evidence follow-up, `ea3fed76`,
does not change implementation, configuration, source pins or the lockfile.

| Actual composed-source check | Result |
| --- | --- |
| M09 complete library | 281 passed, 0 failed, 0 ignored |
| M09 CLI integration | 29 passed, 0 failed, 0 ignored |
| M06 `evaluation_quorum_v2` integration target | 3 passed, 0 failed, 0 ignored |
| Exact original PQ evaluation/claim owner case | 1 passed; 119 other M06 library tests filtered |
| M09 compile-fail documentation controls | 8 passed, 0 failed, 0 ignored |
| Source/claim/authority negatives and TMR1 oracle | 105 passed |
| Incoming weight-loading and parent-material Python controls | 17 + 11 passed |
| Whole-workspace, all-targets strict Clippy | PASS, default features, `-D warnings` |
| Formatting, native inventory, exact pins and repository links | PASS; 424 pins; 2,490 local links |

This set contains **314 native/CLI tests**, **8 compile-fail controls** and
**133 Python tests**. The added rejection assertions inside the selected PQ
owner case are not counted as separate tests. The 28 weight-loading Python
controls use NumPy-backed test doubles; they do not run Torch/Safetensors or
an actual LLM forward. The seven selected Node storage tests above are not
rerun or relabeled as composition results.

The [composition audit](composition/source-composition-audit.json) verifies
that all 338 required paths and 424 pinned paths are exactly the union of both
parents, with no missing or mismatched blob. Twelve incoming source/test/doc
files, including the ten evaluator/weight-loader source and test files, are
byte-identical to `d0737cf5`; the entire M06 directory and lockfile are unchanged.
The sole plan intentionally preserves both continuation sections. The
[composed test coverage](composition/retained-test-coverage.json) retains all
186 original baseline names and all 261 names from the first implementation;
the combined library adds 20 names and passes all 281. The
[composed results](composition/results.json) record exact counts, executable
hashes, graph identity and the limits of these local observations.

### Subsequent Node-observation integration

A final expected-head read found the concurrent Node Legacy-observation commit
`bd2777f9cc74df10ba07ae8202584ed0fb90a519`. It is preserved as a parent alongside
`ea3fed76`. The [late composition source audit](late-node-composition/source-composition-audit.json)
checks that the entire M09, M06 and M12 service-settlement scopes, the weight
loading source/tests, and all Cargo manifests/lockfiles retain the tested
storage composition's exact bytes. The Node source/tests and the incoming
workflows retain the concurrent parent's exact bytes. Only the shared source
corpus and generated native inventory need composition: all **343 required
paths / 429 pins** are retained and checked against actual blobs.

The incoming Legacy reorganization observer defaults off. Its clocks and
counters surround the original validation/commit calls; the original physical
storage, funding, retirement and current-height owners are unchanged. Explicitly
enabled diagnostics add measurement overhead and grant no authority. The C
receipts above remain bound to C, and A's seven selected Node tests remain
bound to A. Any selected Node execution on this later combination is recorded
separately, without treating those earlier receipts as the later commit's runs.

The original [A results](results.json) record the counts, command scopes, lockfile
identity, source bounds and SHA256/size observations for the original M09 library,
Node library and `trnm-cell` executables. These local observations do not
replace independent operators, the remote required-check matrix or actual
prospective-merge qualification.

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

The exact final recorder runs strict Clippy with `--workspace --all-targets`;
the M09-only command above remains a smaller diagnostic entrypoint. Its full
argv and pinned-provider environment are retained in the main receipt.

## Interpretation

The tests use synthetic canonical payloads and real local TCP, SQLite, files
and CLI processes. They prove the stated pin, byte, parser, resume, deadline,
retention and collection behaviors within their declared profiles. They do
not prove release-owner completeness for a real architecture, numerical model
safety, Expert ABI, arbitrary codec support, independent remote copies,
automatic funded renewal, current chain-height truth or actual authorization
at use. Those owners and the original WAN/product-loop gates remain required.

TCA2's wrapper owns the private `objects` arena and holds its original physical
exclusive lock. Ordinary M12 calls pointed at the outer TCA2 directory refuse;
the wrapper's public physical-retirement path goes through the catalog audit.
The internal `objects` directory must not be registered as a separate M12
store. Same-permission reconfiguration after the wrapper closes, direct arena
access and administrator deletion remain outside this local owner boundary.
