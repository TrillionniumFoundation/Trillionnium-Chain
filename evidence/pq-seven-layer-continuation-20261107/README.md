# Seven-layer PQ continuation — 2026-11-07

**HOLD / NO-GO. All recorded native commands are terminal; the native phase
and its independent readback failed. Original failures remain retained.**

This report records source repairs, exact-source checks and bounded research
observations. It does not qualify whole-chain PQ-128, quantum mining security,
public-WAN operation, complete rollback resistance or production activation.
The [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the plan; this directory is an evidence record.

## Source identity and observation scopes

| Scope | Exact identity and disposition |
| --- | --- |
| Frozen validation source | Commit `e36cfb88956a0e35e53d74c5ab71c94c628439d9`, tree `b2586f06e82de55484a2e5752563e8b669c3ea17`. This is the source exercised by the completed source, quantum and native phases. |
| Frozen source corpus | 713 pinned source blobs and 632 required paths at e36. Passing this contract establishes checked source identity/coverage, not native or cryptographic acceptance. |
| Pre-fix reader counterexample | Exact reader bytes from `79075c36cb8a9d27f922920c1f4958895efc32b5`, exercised against the same adversarial controls as the repaired snapshot. |
| Concurrent integration target | `3d1b6507671ec694ce58e86d4063a125c8deeb66` advances the reviewed `271a87f831aa7e08f3c2024f738504c1422122dd` by adding a CodeQL worktree-observation block and three historical evidence files, with no runtime-source change in that advance. Neither target is the frozen e36 validation source. |
| Reviewed CodeQL compositions | The first two-file candidate and its 11-control result remain immutable evidence. The second candidate preserves the new target's exact observation block and adds one real-Git dirty-path control, for 12 controls. Both are separate from the four CodeQL controls included in the e36 source phase. |
| CI policy and evidence merge | `d1e6e279593b63049f538af081b0c0757a4f4506` composes e36 with `3d1b6507671ec694ce58e86d4063a125c8deeb66`. Its Rust and formal subtrees remain byte-identical to e36. |
| Subsequent analysis-input composition | `276a1e26f1989aef4b3d75263ff5b55e073b46e9` / tree `d2a3d83d2800c8e0829e3a951cb2f0f6aa233e56` additionally preserves `adebe0bd78e6e1bdb55a599179ffe2313997170e`. Its 13 source commands / 270 cases and two supplementary metadata commands pass; the separate Clippy attempt fails with compiler SIGKILL. Rust/formal subtrees remain identical to e36; no native execution is relabelled. |

## Updated seven-layer audit

| Layer | Actual progress at the frozen source | Boundary that remains open |
| --- | --- | --- |
| Transaction and identity signatures | Real ML-DSA-65 verification and profile-specific native authorization paths are present. | A primitive or selected profile does not establish every account, migration, governance or effect path. The native failures below prevent full acceptance of the composition. |
| Network transport | The PNQ2 signed-plaintext development profile remains distinct from the explicit ordinary TLS route. The TLS source connects hybrid exchange, ML-DSA mutual identity, inner admission and an explicit witnessed-owner mode. | These are selected loopback/development compositions. They do not establish all-listener/private-task confidentiality, independent PKI custody, sustained public-WAN service or deployment acceptance. |
| Release and governance | The Node now has explicit M15 installation/launch and configuration-consumer source, retained owner state, replay and independent frontier/time contracts. The earlier blanket absence finding must retain its historical source scope. | All installation entrances, general Cell activation/CURRENT, ordinary isolated-consumer execution, external-effect recovery and independent recovery custody are not established by source presence. |
| Rollback protection | Under the independent-witness premise, the [native witness](../../docs/security/PQ_NETWORK_DURABLE_WITNESS_V1.md) binds the PNQ2 resource, peer and request tables to a configured Current/CAS authority. | Account/ledger state, blocks, History, Cell, CURRENT, Hepta FinalUse and external effects are outside that three-table root. A fresh reply is not an exclusive execution lease or proof that the service itself never rolled back. |
| PoN work and fork choice | Constructive fixed-context oracle resource accounting and restricted-domain observations now have recorded executions and independent output readback. | They do not determine the cheapest legal quantum attack, prove a lower bound, calibrate hardware, characterize the full nonce space, or establish DAA/fork-choice safety and liveness under mixed resources. |
| Proof backend | The [native work relation](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs) retains complete PNW1 verification. | zkVM research has not become the qualified consensus backend. A proof-system name or experimental proof result supplies no whole-chain PQ-128 qualification. |
| Independent end-to-end qualification | The [claim guard](../../scripts/ci/pq_chain_claim_guard.py) still reports HOLD and keeps acceptance/activation flags false. | The native phase finished with failed commands and failed readback checks. No independent deployed end-to-end qualification, whole-chain PQ-128 claim or production activation follows. |

### M15 source exists; execution acceptance is separate

The dated absence statements in the
[authority-surface audit](../../docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md)
refer to their named earlier candidates. At e36, the Node depends on
`trnm-release-bundle`; `m15-release-owner-install-v1` calls the actual
[installation owner](../../trillionnium/crates/trnm-pon-node/src/release_owner/catalog.rs),
and the explicit launch route reaches `operator-continuous-m15-v1` and
[`Session::consume`](../../trillionnium/crates/trnm-pon-node/src/release_owner/consumer.rs).
The selected profile binds actual image/configuration, current authority and
durable claim consumption. This does not complete general Cell activation or
Hepta FinalUse integration. Owner current-time observations also must not be
described as persisting a new floor on every read.

The [isolated ordinary-M15 consumer control](../../trillionnium/crates/trnm-pon-node/src/release_owner/native_consumer_tests.rs)
requires reviewed static artifacts and a fresh rootless user/mount/PID namespace
and is explicitly ignored by the default library run. Its separate fixture
helper is also ignored. Those controls were not executed in this recorded
e36 phase; compilation, registration and older-source
receipts do not substitute for their execution.

## Completed exact-source checks

The source phase completed 13/13 recorded commands successfully, including
formatting, repository/inventory checks, locked graph inspection, the source
corpus and the HOLD guard. Its seven Python suites contain 262 passing cases:

| Suite | Cases |
| --- | ---: |
| CI contract | 104 |
| Raw source integrity | 43 |
| PQ source integration | 55 |
| Whole-chain claim guard | 37 |
| Authority source scanner | 15 |
| CodeQL retention at e36 | 4 |
| Native-command recorder | 4 |

These source-only controls do not run or qualify the native Node. Expected
failure fixtures inside successful test suites remain negative controls, not
additional successful product operations.

The default-feature locked graph contains 176 nodes; supplementary all-features
metadata contains 181. Both have 26 workspace members. These are distinct graph
observations, not interchangeable feature configurations.

## Reader TOCTOU repair and retained counterexamples

The old claim/corpus readers checked a pathname and then reopened it with
`read_bytes()`. Equal-length replacement, symlink redirection, ancestor changes
and in-place rewrites could therefore be accepted after the checked identity
changed. FIFO substitution could block the read, and file growth could exceed
the intended read bound.

The [shared reader](../../scripts/ci/pq_source_reader.py) now opens each directory
from `/` through held `dir_fd` descriptors with no-follow checks, binds the leaf
to its descriptor, limits reads to `cap + 1`, and rechecks file metadata and
every directory entry. Nonblocking open prevents the raced FIFO hang. The
negative controls use real renames, hardlinks, symlinks, writes, mmap and FIFO
creation; scheduling hooks do not fabricate data or stat results.

The same 28 controls produced **24 failures, one error and three passes** on the
frozen old readers, then **28 passes** on the repaired snapshot. The complete
claim/corpus suites subsequently passed 92 cases and are included in the 262
e36 source cases above; these overlapping executions must not be summed as
independent qualification. Exact old/new source hashes and raw outputs are
retained. This repair protects the observed read boundaries; it is not an
immutable whole-checkout snapshot or a chain rollback proof.

## Quantum research: completed, bounded observations

The quantum phase completed 13/13 recorded commands: nine suites with **182
distinct passing tests**, plus constructive/restricted campaign observation and
replay. Independent readback checked recorded commands, output hashes, declared
source bindings, case counts and resource arithmetic. It did not rerun the
campaigns or independently prove the circuits.

- **Four constructive cases:** PNH1 and PGH2 at native dimensions executed
  scalar macro semantics; two reduced cases executed reversible leaf gates in
  a classical basis interpreter, covering success and noise exhaustion.
  Native-sized gate execution, quantum hardware and native Node admission were
  not performed by this campaign.
- **Five restricted cases / 60 literal nonce observations:** the three
  native-shaped cases enumerate four candidates each, leaving 62 nonce bits
  unsearched. Three winning PNW1 proofs were checked by the separate Python
  scalar relation, not by native Node parent/task/time/target admission.
  The reduced prefix-loss case discards 25 of 32 full-relation winners; the
  restricted predicate must use its own marked count. Two reduced gate controls
  and a zero-marked case retain their own narrower scope.
- The resource figures are constructive upper bounds for declared, deliberately
  nonoptimal fixed contexts. They do not prove a minimum attack cost, uniform
  tickets, prefix/ticket independence, measured quantum advantage or a complete
  machine-failure bound. Full-nonce64 resource census is not full-domain search.
  These campaigns do not execute the broad network/adversarial/DAA campaigns;
  classical observer wall time is not a quantum mining clock.

All mining, whole-chain and production qualification flags remain false.

## Native terminal results — failed

All 13 planned native commands reached terminal receipts: **10 succeeded and
three failed**, with no command left unexecuted. The failed commands are the
full Node library, TLS CLI/witness combination, and checkpoint/release
combination. Independent transcript/source/ELF readback reports **FAIL: 14
passing checks and seven failing checks**, with no pending check. Those are
readback checks, not additional test cases.

The complete e36 Node library registry contains 1285 tests: **1217 passed /
35 failed / 33 ignored**, with harness duration **1405.00 seconds** and command
exit **101**, before the unchanged 1500-second ceiling. Earlier counts of 31
and 35 FAILED rows were intermediate observations, not separate executions.

| Node failure group | Observed cause and scope |
| --- | --- |
| 23 failures: six recovery and 17 journal controls | ENOENT during `Journal::initialize → Epoch::new → stamp` in the [PQ submission journal](../../trillionnium/crates/trnm-pon-node/src/public_submit/pq/journal.rs), whose `stamp` reads metadata for the unavailable `/proc/self/ns/time` interface. |
| 12 failures: eight release fixtures, one existing-owner fixture and three witness children | `UnixListener::bind` returned EPERM. The eight release fixtures did **not** reach the clock stamp; these failures must not be attributed to the time-namespace check. |

The ENOENT attribution combines the original panics, the unchanged journal
initialization path and an independent observation that the exact namespace
path is missing. No diagnostic rerun or backtrace was produced. Recovery
fixture readiness had already succeeded; initialization failed before journal
acquire, prepare or publish. The EPERM observations do not identify a specific
kernel, sandbox or filesystem policy as their cause.

| Separate scope | Recorded result |
| --- | --- |
| Required core/TLS library rosters, already within the Node library | Core 51/52 passed; TLS library 13/13 passed. These are subsets, not extra tests to add to 1217. |
| Ordinary TLS CLI | 4 passed / 0 failed. |
| Witness CLI | 0 passed / 5 failed in fixture setup, before the intended target CLI assertions; the combined TLS/witness command exited 101. |
| Default-feature NPQ6 migration / TLS feature-off | Migration 3/3 passed; feature-off 1/1 passed, in separate harnesses. |
| Checkpoint library / binary | Library 11 passed / 7 failed; binary harness 15/15 passed. |
| Checkpoint cold recovery / cross-process / socket ownership | Cold recovery 15/15 passed; cross-process 3 passed / 3 failed; socket ownership 0 passed / 2 failed. |
| Checkpoint example | Zero tests executed; this is not a product-control pass. |
| Release-bundle library | 43/43 passed; the overall checkpoint/release command still exited 101. |
| Strict Clippy | Whole workspace, all targets, all features, `-D warnings`: exit 0. |

No doc-test command ran in this phase; `--all-targets` does not establish
doc-test execution. Harness results are kept separate, and nested child output
does not inflate parent pass counts. Environment-related failure does not
become acceptance. The original errors and command ceilings remain intact;
ignored ordinary-consumer controls were not counted as run.

SQLite requalification executed four real Cargo commands against the same
uncleaned target. **All four Cargo commands exited 0**; the recorded cfg sequence
was **false / true / false / true**. These are actual build-output/guard
observations, not four Cargo exit-code refusals. They do not qualify all SQLite
deployment configurations or erase the native socket/time-namespace failures.

Host disk exhaustion was also observed. The completed Node harness ELF was
retired only after its identity was recorded and its result checked. All logs
and receipts were retained. The sealed raw archives contain evidence and
binary identity records, not a promised archive of executable payloads.

The receipts retain source-before/source-after verification and execution-bound
ELF identities. They are local evidence, not independent hardware attestation.
The terminal failed disposition must survive later evidence publication or
CI-only source composition.

## Concurrent CodeQL composition and historical CI outcomes

The historical e70 PQ CI job `128343245485` in run `42352433649` refused a changed
`check_sqlite_build_requalification.py` source pin; its native suite did not
execute. The reviewed repair updates the exact pin without weakening the
original native resource fence or source checks.

CodeQL job `128343245440` in run `42352433630` generated local Python SARIF, then
failed because default setup rejected advanced-configuration uploads. Its
readback/retention steps were skipped. Keep that real failure and its historical
repair advice attached to that observation; do not rewrite it as a remote pass.

The later concurrent `271a87f8` policy keeps default setup and sets the local
exact-source lane to `upload: never`. The reviewed two-file composition retains
the pinned real query actions, Rust/Python/Actions and both PR head/merge lanes
(six combinations). Successful SARIF readback gates the main artifact containing
original SARIF plus source-before/source-after records, logs and step outcomes.
Identity JSON alone cannot satisfy it. Missing/invalid SARIF instead permits only
an explicitly named diagnostics artifact. Source verification and `cmp` failures
remain fatal, including through `tee`; no step failure is converted to success.

The first composition's **11 local controls passed** and remain retained under
their original artifact hashes. The `3d1b6507` advance adds the exact
post-analysis worktree observation block: NUL-delimited status/diff names and a
diff-stat record before the after-source check. The second composition's **12
local controls passed**, including a real-Git tracked/untracked dirty-path
control; a newline-containing path remains unambiguous and the after-source
check still fails. Real temporary Git repositories exercise
the workflow shell's deterministic receipt comparison, changed-source and
changed-receipt refusal, and ordered-merge checks. This was not a new CodeQL or
GitHub Actions execution. Default setup settings were not changed, and a later
CI-only composition cannot relabel e36 native receipts as fresh final-source
execution. The source comparison checks two observations, not continuous
immutability throughout extraction and query execution.

The retained M09 history also remains mixed: job `128251866889` in run
`42323049446`, on `1c14fab4`, recorded 352 passes and one announcement-budget
failure; later job `128344391177` in run `42352433711` recorded 353 passes and
zero failures. The sequence test source was unchanged, so the later pass is not
evidence of a causal fix for the earlier failure. The
[historical M15 follow-through](../pq-m15-native-followthrough-20261107/README.md)
likewise keeps its `1c14fab4` library result of 1249 passes / zero failures / 33
ignored; that result does not transfer to e36 or the future publication source.

### Subsequent standalone analysis input

The concurrent target then advanced to `adebe0bd78e6e1bdb55a599179ffe2313997170e`.
Its [retained analysis binding](../codeql-standalone-lock-20261107/README.md)
adds a standalone primitive-harness Cargo lock and two evidence files. The
historical five-file harness manifest and campaign archive remain unchanged;
the new lock is subsequent analysis input, not recovered historical CI output.
This composition preserves those exact files without changing the CodeQL source
guard or any runtime/formal source. The final composition separately executed the twelve-package locked/offline
metadata check and preserved its own before/after source records.

## Final composition source checks

The [final source/static receipt](publication-source/README.md) binds the exact
`276a1e26f1989aef4b3d75263ff5b55e073b46e9` composition: **13/13 source commands,
270 Python cases, and 2/2 supplementary graph commands passed**. The additional
strict Clippy command failed with Cargo exit 101 after compiler SIGKILL 9, cause
unattributed; it was not retried. Every command, including that failed attempt,
retained identical before/after source records. The new CodeQL suite has
twelve cases; the earlier e36 262-case result keeps its separate source identity.
The full Node result above remains e36 execution and FAIL. The containing
evidence-only publication adds no native execution or security qualification.

## Sealed evidence and readback

- [publication-source/receipt.json](publication-source/receipt.json) and its
  [independent readback](publication-source/independent-readback.json) retain the
  final source/static checks and exact source composition. Its separate archive
  leaves the original four sealed archives below unchanged.

- [qualification.json](qualification.json) records the source-scoped HOLD,
  exact command outcomes, failure/ignored boundaries and publication mapping.
- [native-readback.json](native-readback.json) binds the actual registry and
  parent rosters, the separate CLI/default-feature/component harnesses and
  before/after source and ELF records. Its result is FAIL.
- [failure-readback.md](failure-readback.md) and
  [failure-readback.json](failure-readback.json) retain the full Node and TLS
  witness failures, exact error locations and historical blob comparisons.
- [quantum-readback.json](quantum-readback.json) records all 182 distinct tests,
  actual cases, recorded arithmetic and the unchanged research limitations.
- [component-readback.json](component-readback.json) retains both selected
  dependency graphs, all four SQLite build-output observations and strict Clippy.
- [m15-entrypoints.md](m15-entrypoints.md) and
  [m15-entrypoints.json](m15-entrypoints.json) preserve the source inventory.
  Their 31-failure prefix is explicitly an earlier partial observation; the
  final 35-failure result above supersedes that count without changing its bytes.
- [initial-composition-pins.json](initial-composition-pins.json),
  [reader-security-pins.json](reader-security-pins.json) and
  [publication-composition-pins.json](publication-composition-pins.json) explain
  each reviewed source rebinding and preserve both source-path sets.
- [historical-ci.json](historical-ci.json) and
  [historical-pressure-readback.json](historical-pressure-readback.json) retain
  earlier CI findings, including the original confirmation failure. Their
  contemporaneous CodeQL repair advice is historical; the later reviewed
  default-setup policy is described above.
- [raw/archives.json](raw/archives.json) indexes four archives with per-file
  SHA-256 inventories. Every archived member was read back after creation.
  All original source/quantum/native outputs, supplementary all-features metadata,
  pre/post reader counterexamples, historical CI and both CodeQL composition
  controls are retained. The independent-reader 36-control transcript is an
  explicitly new recording of parser controls, not original product execution.

The raw archives are ordinary gzip tar files containing only relative regular
files. Extract them into a fresh review directory and verify the adjacent
`*-index.json` hashes before using the included readers. The frozen validation
archive includes the runner and independent readback scripts. The reader-race
archive includes exact old/new source snapshots and its replay script. Native
readers retain the original execution-path checks; records must not be rewritten
to make a relocated checkout appear to be the original execution environment.

No native executable bodies or build caches are included. The completed Node
ELF's separate [retirement record](completed-node-elf-retirement.json) explains
its rehash and removal after the completed failed run when disk space was
exhausted. The underlying logs, source receipts and before/after identities were
retained. Archive hashes establish byte identity, not deployment or security
qualification.

GitHub documents the
[default-setup upload restriction](https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/code-scanning/sarif-files/troubleshoot-sarif-uploads/default-setup-enabled).
The pinned action's
[query implementation](https://github.com/github/codeql-action/blob/1fc58d04a4d4374f921bdac573c3811c240f9c26/src/analyze-action.ts)
and [upload selection](https://github.com/github/codeql-action/blob/1fc58d04a4d4374f921bdac573c3811c240f9c26/src/upload-sarif.ts)
were reviewed separately. Local SARIF retention is not a new Code Scanning
server acceptance or an independent end-to-end PQ qualification.
