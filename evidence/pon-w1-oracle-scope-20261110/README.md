# W1 construction scope and native-packet differential

**The fixed-context W1 reversible oracle exists. Quantum mining security and production qualification remain HOLD / NO-GO.**

The source change separates construction, software execution, submitted-proof validity and native admission. It adds a versioned scope reader and a read-only packet bridge, wires both control suites into the required repository-truth sequence, and preserves historical V1 source/report identities. See the [scope contract](../../docs/research/W1_ORACLE_EVIDENCE_SCOPE_V1.md).

## Exact source and delivery state

| Identity | Value |
| --- | --- |
| Tested implementation commit | `6e39f27357ce7c030f5662ada3d524fecb58d63e` |
| Tested tree | `f36683afd74fa9811bddf21787ab2386900ea70b` |
| Original native input commit | `e4abb172147e941b62483652b0ceabaae4317624` |
| Original native input tree | `016ebf3deeac88d6d7a782edf563f2291ebe17f5` |
| Local task branch | `fix/chain-w1-oracle-evidence-20261110-0776` |
| Intended draft base | `fix/chain-pon-native-boundaries-20261110-02769a` (#876) |

This evidence-only continuation records executions of the implementation commit; it does not rename those executions as tests of the later evidence commit. Complete source guards bracket both Python groups and the Rust metadata/format group, and agree on unchanged source. Each guard covers 27,892 tracked entries and 2,553,814,149 bytes; the identity checker itself explicitly reports `tests_executed_by_identity_check=false`.

**The selected Python checks and recovered desktop static checks passed on the implementation commit. Security and production qualification remain HOLD.** After the recorded HeptaRuntime outage, a fresh read-only probe confirmed ProfHepta and the exact retained runner. The source bundle was transferred in five create-only chunks and independently verified by complete size and SHA-256. An isolated desktop checkout then passed default/all-features/fuzz locked offline Cargo metadata, workspace formatting and the original strict Clippy command. Its complete source guards match the implementation identity above, and its five installed provider inputs remain unchanged. See the [original desktop summary](desktop-validation.json) and [desktop records](desktop-records.tar.gz).

The earlier transport Unknown/error observations, cloud offline cache refusals and interrupted provider build remain preserved in the unchanged [original execution archive](execution-records.tar.gz). Recovery adds a distinct observation; it does not rewrite those attempts. The [recovery records](recovery-records.tar.gz) retain transport reconciliation and the actual historical-report verification executed from evidence child `8dc625abe7116c75223a95f9be5931ca6075bf89`. That verifier rebuilt the original report byte for byte while preserving its `6e39f273` source identity.

Publication fields in this evidence snapshot describe the moment before this update is committed and published. A branch push and draft PR require their own subsequent remote-head and PR readback; no hosted CI pass is claimed by the local observations.

## Construction already retained

The [original construction record](../pon-quantum-construction-20261104/README.md) retains 17 construction controls and five cases: three native-sized macro executions and two reduced-shape leaf-gate executions. The nonce, bounded noise branches, ordered transcript, ticket/target, phase and inverse are included. Those original records retain their original source and execution modes.

The new scope reader rebuilds the selected program and census. It distinguishes the complete fixed-context predicate, a legal restricted subset, reduced controls and caller-only budgets. A caller-supplied `constructed-w1/` label cannot certify a circuit. The [seven preserved V1 sources](source-change-review.json) are byte-identical to the base. In the V1 accounting/model outputs, the local `full_W1_oracle_constructed=false` describes those invocations, not a repository-wide absence of a construction.

Three saved scope reports passed CLI reconstruction: [full PGH2](reports/full-native-scope.json), [restricted PGH2](reports/restricted-native-scope.json), and [generic accounting](reports/generic-accounting-scope.json). Their [request](reports/illustrative-resource-request.json) uses synthetic accounting premises and no physical model. These reports reconstruct schedules; their own execution flags remain false.

| PGH2 logical construction | Logical qubits | Compute-Z-uncompute gates | Serial depth upper bound |
| --- | ---: | ---: | ---: |
| Full fixed-context | 22,253,429 | 17,718,795,839 | 1,969,864,925 |
| Legal restricted subset | 22,030,197 | 15,992,948,079 | 1,102,062,749 |

These are constructive upper bounds for particular logical circuits, not physical costs or lower bounds on the cheapest legal attacker. The restricted oracle can discard full-predicate winners; fewer gates do not establish a cheaper campaign at matched success probability. Marked probability, preprocessing, reuse, all attempts, scheduling and fault-tolerant implementation still need separate evidence. The PNH1 census in the research note has different framing and must not be substituted for this PGH2 table.

## Original native input and new differential

The [artifact provenance](native-artifact.json) binds the original [ZIP](native-fullpath-e4abb172.zip), GitHub Actions [run 42830743579](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743579), job `129927393431`, artifact `13785762485`. The 129,999-byte ZIP has SHA-256 `d9ce3ead97f87759707829220525f50420126fa0347cbd64ec46aeb69bbd57c9`. Its original preregistration is `9ba442904cc481e8371ff90bef97908dd1f0dcf59ce442375b18d0fd8a10f443`; its native binary is `fe18172189e555693c701d0d6b686c519e2a4c5d7a55ecdf999cb7c4e77db7b7`.

The original source guards agree. Nine native processes supply four scheduled observations: valid accepted, exact duplicate, corrupt product rejected as `WORK:Product`, and cancellation before `VerifiedWork`. They record one new local block, depth zero and zero timely accepted progress under the original service contract. The original successful component workflow retains `overall_gate=security_gate=HOLD` and `performance_gate=COMPONENT_OBSERVATION_ONLY`.

The [new bridge report](reports/bridge-result.json) reparses both PNP2 packets, replays the complete scalar W1 relation and compares the valid PGH2 input with one native-sized reversible **macro interpreter** execution. It agrees on challenge, transcript, ticket, winner and phase `-1`, preserves nonce zero, and observes inverse execution and clean ancillas. The report records **5,543,958 macro calls**, not leaf-gate or quantum-hardware execution.

The late-product control changes C[4095] from 949175 to 949176. The header, A/B matrices, nonce and transcript remain identical, so the same oracle observation still marks the nonce as a winner. The complete submitted-proof replay rejects `PRODUCT`; the original native process rejects `WORK:Product`. The late-product comparison reuses the same fixed-template/nonce observation; it is not counted as a second oracle execution. **A winning nonce does not authorize a corrupt submitted proof.**

The bridge CLI then independently rebuilds the complete saved report from the same externally pinned archive. [Original](reports/bridge-result.json) and [replayed](reports/bridge-rebuilt.json) reports are byte-identical: 30,141 bytes, SHA-256 `24cb1149f8dc19f8da6e73de4a2761b5da7bd0e95db59c1b88f55abdc0618046`. These two CLI invocations are separate software replays of the same case, not additional native observations or independent quantum security evidence. No new native node process ran in this continuation. The original reader's `native_relation_replayed_by_reader=false` is retained; this continuation's scalar replay is recorded separately.

## Executed checks

All **599 selected top-level unittest methods** in the 16 named suites passed, with zero skips. The two new suites contribute 37; the existing suites contribute 562, including one newly added CI omission-control method. By method origin, that is 38 added methods and 561 pre-existing methods. Nested subprocess controls, historical construction cases and native wrong-context cases are not added to this count. This is the stated selected Python scope, not the complete repository or Rust suite.

| Suite | Outer methods | Result |
| --- | ---: | --- |
| native-bridge | 25 | PASS |
| evidence-scope | 12 | PASS |
| reversible-components | 17 | PASS |
| w1-oracle | 17 | PASS |
| w1-restricted | 12 | PASS |
| resources | 25 | PASS |
| clock | 18 | PASS |
| candidate-clock | 6 | PASS |
| adversarial | 12 | PASS |
| network | 39 | PASS |
| daa | 19 | PASS |
| pq-daa | 6 | PASS |
| native-reader | 109 | PASS |
| ci-contract | 180 | PASS |
| source-integrity | 43 | PASS |
| corpus-controls | 59 | PASS |

The actual repository/link checker, corpus inspector, CI-contract inspector and source inventory also passed on the implementation commit. A separate `git diff --check e4abb172... 6e39f273...` checks the actual committed 13-file patch; its receipt is retained in `final-source-review/`. The supplemental worktree-only whitespace check ran on a clean checkout and is not used as a substitute for that committed-range check. Static inspector success is not test execution or security qualification. The corpus retains 1,086 pinned blobs and 994 required paths. The CI omission controls reject missing, duplicate, reordered, backgrounded and failure-suppressed new commands. Archive controls include NUL-truncated ZIP names, traversal, symlinks, duplicate paths, file/parent conflicts, substituted source and altered packets. Recomputed report hashes cannot upgrade unsupported qualification flags.

The separate Rust metadata/format group used an external toolchain prefix, Cargo home and target directory, one build job and disabled incremental compilation. Its nine metadata command observations remain distinct: each profile's first offline command failed with exit 101, its locked retrieval succeeded, and its final locked offline command succeeded. Formatting passed with `--all -- --check`. The full source guard took 867.49 seconds before that group and 63.47 seconds after it; both actually exited zero and matched. No timeout occurred in those guards. Full command streams, toolchain archive and executable hashes, and lockfile identities are under `cloud-rust/` in the execution archive. No native node build/run or fuzz execution is claimed by metadata.

## Earlier bounded cloud provider attempt

A subsequent actual attempt retained the required `cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings` scope. The fixed OpenSSL 3.5.9 prerequisite entered GCC compilation under the original maintained preparation script. The process supervisor imposed a 2 GiB per-process address limit and watched the owned group's RSS and shared resource low watermarks. This executor exposes no delegated cgroup; the RSS watchdog is not a hard kernel group-memory limit or an adversarial process jail. Small capability probes, including the initially overconservative exit-drain observation and corrected recheck, are retained separately from repository tests.

After **246.81 seconds**, shared free disk was observed at **2,147,143,680 bytes**, below the declared **2,147,483,648-byte (2 GiB)** floor. The supervisor sent SIGKILL only to its owned build group. The provider exited **-9**, with `stop_reason=shared_disk_free_low_watermark`; no live group members remained. This is a controlled disk-budget interruption, not an observed OOM or a source compilation error. The provider's success receipt was not produced because the killed shell could not complete its exit handler. The supervisor receipt, original build log and resource samples are preserved in `bounded-clippy/`.

**Cloud strict Clippy was not started**, because provider preparation did not complete. Its flags were not relaxed and no pass is inferred from metadata, formatting or compiler startup. The final full source guard passed in 14.65 seconds and matched the previously completed same-source anchor; the earlier anchor retains its original execution time rather than being relabelled as a new guard. A read-only capacity review found that reclaiming all measured task-owned regenerable caches would still not meet the original 4 GiB start requirement. Other task files were not removed. At the end of that cloud attempt, the prepared desktop route was still blocked by the recorded HeptaRuntime errors. The later recovery and static validation below retain their own execution identity and timestamps.

## Recovered desktop static validation

The [desktop summary](desktop-validation.json) records `VALIDATION_PASSED` for implementation commit `6e39f27357ce7c030f5662ada3d524fecb58d63e`, with no errors or skips. The original command group finished at `2026-11-11T02:06:28Z` (2026-11-10 in the record timezone). It used Rust/Cargo 1.95.0, the pinned existing OpenSSL 3.5.9 installation, two build jobs, disabled incremental compilation and a new external target directory. All three metadata commands passed on their first offline attempt; the desktop run did not fetch missing Cargo dependencies or rebuild the provider.

| Desktop check | Exit | Actual elapsed seconds |
| --- | ---: | ---: |
| Locked/offline default metadata | 0 | 0.219 |
| Locked/offline all-features metadata | 0 | 0.220 |
| Locked/offline fuzz metadata | 0 | 0.219 |
| Workspace format, `--all -- --check` | 0 | 21.941 |
| Strict Clippy, workspace/all-targets/all-features, `-D warnings` | 0 | 181.250 |

Both preflights and complete source guards passed. The before/after guards took 7.252 and 6.259 seconds and have the same SHA-256 `d676544a479331025cae9e6055d55629514489b223db3a4cc5125aa059468c1b`. The provider binary, two headers and two static libraries also match before and after. The retained archive has 67 members and 20 command receipts, with all 40 stdout/stderr bindings independently verified. The setup branch-absence probe intentionally returns exit 1; its receipt records that expected result. It is not a failed compiler check.

The original Clippy stderr contains a build-script warning that the SQLite I/O boundary is **UNQUALIFIED** because the provider's `LD_LIBRARY_PATH` introduces an additional loader directory. The warning and environment are retained. Clippy exit zero establishes the recorded static-command result and does not qualify that boundary. `--all-targets` does not execute the Rust tests; this group adds zero native tests, native node admission runs or quantum hardware executions, and does not increase the 599 Python-method count.

The [desktop manifest](desktop-records-manifest.json) binds the original 211,590-byte archive, SHA-256 `5dd560fc76bc667160a7dd32cc7a7fc3625a46b6a5d68eb40804794f0658091a`. Recovery protocol observations, the original full PTY output and local receipt verification are separately retained in the [recovery archive](recovery-records.tar.gz) and [its manifest](recovery-records-manifest.json). The earlier 276-member execution archive remains byte-identical.

## Preserved failures and remaining gates

At original source `e4abb172`, the [repository-truth job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743518/job/129995452145) ran 58 methods in `test_pq_lifetime_budget.py` with one error: `source lock hash mismatch: trillionnium/crates/trnm-pon-node/src/consensus.rs`. The quantum suites occur later in that lane and were not executed there. Its original log is retained in the execution archive. This source-identity refusal remains unresolved in this branch; no historical pin was weakened to hide it. A successful native component or local Python subset does not erase that failure.

Preparation observations are also retained, including the initially rejected scope label, corrected missing plan pin, ZIP-name review finding, unsuccessful unnamed-head bundle attempt and remote transfer failure. Session observations without copied raw logs are explicitly labelled, and are not counted as final-source tests.

The following remain unqualified: quantum hardware execution, physical cost calibration, attacker optimality, quantum work lower bounds, whole-campaign quantum mining security, and full current native/public-network admission and recovery. Test totals and large circuit counts do not close those obligations. All production and security qualification flags remain false or HOLD.

## Review and reproduce

The [summary](summary.json), [execution archive](execution-records.tar.gz), [archive member manifest](execution-records-manifest.json) and [file manifest](member-manifest.json) retain command arguments, original outputs, exit codes, times, input/source hashes and transport state. Extract the archive outside a clean checkout; its command paths identify the original execution workspace.

At the recorded source, the two new suites can be run with Python unittest discovery under `formal/pon-nakamoto-v1`, using `test_w1_quantum_evidence_scope.py` and `test_w1_quantum_native_bridge.py`. Replay a scope with `w1_quantum_evidence_scope.py --verify REPORT`. Replay the bridge with `w1_quantum_native_bridge.py --verify REPORT`, the retained ZIP, and all five independently supplied pins from `native-artifact.json`; the exact argv is in `bridge-cli/verify.receipt.json` inside the archive. Historical report verification on a later evidence-only commit also validates the original commit/tree/blob identities before accepting unchanged reader inputs.

The original execution archive contains the 150,042-byte incremental `transport/source-6e39f27357ce.bundle`, SHA-256 `961b7e0f160218613fe37b95f12d686b9a6dcceade2492904d00e8ca68fdf73a`; it requires base `e4abb172` in the receiving Git repository. The recovered desktop run actually consumed an independently verified copy of those bytes. Its retained runner fixes source and toolchain, checks ProfHepta, uses an isolated worktree and target, and records locked metadata, formatting, strict Clippy and source guards. The previous uncertain upload remains a historical observation; the successful create-only transfer and immutable readback are recorded separately.
