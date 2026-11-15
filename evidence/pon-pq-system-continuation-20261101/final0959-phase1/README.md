# Frozen native PQ continuation evidence — phase 1

Status: **HOLD / whole-chain UNQUALIFIED**.

This evidence-only package preserves successes and failures from two precisely identified Chain candidates. It does not change application code, budgets, test selectors, consensus configuration, or activation flags. A repository commit that publishes this archive is an evidence commit; its tree is not the source tree from which any recorded binary was built.

## Source identities

| Cohort | Candidate | Actual prospective merge | Tested tree |
| --- | --- | --- | --- |
| Original failure cohort | `d2fabdd3757b89db84763d632aeedfe84f9fce4f` | `66a0a0e9f7679bcbdef0aab5c111ef0bdde6a927` | `b4d4cca6da8244cf9c7d479eca0974559f4a1005` |
| Corrected candidate | `0959b694539b2e6427c6bfc2422b45c23b63cde4` | `2c1235118b4962c00efc7a774dbb0532cf46cf24` | `49ffbac079b5c549050b5e876b02f70ce5b37d14` |

Both merge cohorts above used base `64cb26b53ed82be14049000387040ba119f00e1e`. The corrected merge has parents `64cb26b5…` and `0959b694…`. A later base, including `456d23a778d91b6f3cfee60ee997f8f51d3216bc`, is outside these execution receipts. Neither a current PR badge nor a later merge ref can substitute for these identities.

The corrected source is [commit 0959b694](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/0959b694539b2e6427c6bfc2422b45c23b63cde4). Its actual Git commit metadata and raw object are included under `local-0959/helpers/`. A small source capsule contains the exact `0959` readers, relevant workflows, Cargo profile and lockfile; every capsule entry records its Git blob and SHA256.

Earlier compact hosted evidence, including the first readiness-reader failure and earlier original workspace/from-zero observations, remains at [immutable evidence commit b3704e49](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/b3704e49f6ed43f84b4f0a0bc3dfb56240d1937a/evidence/pon-pq-system-continuation-20261101/hosted-initial). This package does not copy that earlier 324-entry publication.

## What was actually observed

| Scope | Actual observation | Qualification boundary |
| --- | --- | --- |
| Old `d2` dedicated PQ controls, x64/ARM × head/actual merge | Each lane: **36/37** meaningful exact tests passed. The unchanged slow-drip write test failed. | The failure is retained, not replaced by the later success. |
| Old `d2` complete Node library regression | Each lane: **878 passed, 3 failed, 22 ignored**; process exit `101`. Failures were slow-drip write and the two original large-parent CPU selectors. | Earlier child-harness `1 passed` summaries are not the final suite outcome. |
| Old `d2` strict Clippy | All four dedicated PQ lanes passed. | Static lint success does not repair failed native tests. |
| Corrected `0959` local exact controls | **37/37**, no child harness counted. The same recorded Node test ELF SHA256 is present before and after the sequence. | This is an exact-control run, not the full Node suite. |
| Corrected `0959` hosted dedicated controls | **37/37 in each of four lanes**, 148 executions of 37 distinct controls. Slow-drip write completes within the original test's bound. | These early artifacts do not contain the subsequent complete Node regression. |
| Corrected `0959` additional local checks | Exact M06 callback control, strict Node Clippy, formatting, locked dependency graph, and **55 public-readiness reader tests** passed. All 43 command records bind unchanged actual `0959` source before/after. | The M06 control remains distinct from the 37 PQ controls. Python reader tests are not counted as native tests. |
| Corrected `0959` hosted external-evidence contract | Head and actual merge completed successfully; their readiness-reader suites each executed **55 tests**. | This repairs the new backend-enumeration/source-contract omission. It grants no whole-database or production qualification. |
| Corrected `0959` original workspace CPU workflow | All four complete workspace builds succeeded. The eight original capacity executions failed with `PUBLIC_MUTATION_CPU_BUDGET`; all eight reactor-exit controls passed. | **Capacity HOLD remains.** |
| Corrected `0959` from-zero protocol/cost runs | Four cohorts each executed all five exact native tests successfully. Every aggregate business gate failed `CONFIRMATION_TARGET`: original four-second pressure window confirmed **0/1** required transactions. | **Business confirmation, History/WAN and work-hardness qualification remain open.** |

The corrected complete Node regression is deliberately outside this phase. Its actual final results are collected separately. This package makes no claim that the corrected full Node suite or the entire required baseline is green.

### Compilation and executable identity

The local corrected Node test artifact has SHA256 `428d91424bfaf99eb32945e82299852837bf5690c32b1671f34fc59ad4c5c773`, size `342054176` bytes. Its actual Cargo compiler artifact records Node `opt_level=3`, `debug_assertions=true`, `overflow_checks=true`, features `default,pq-native-openssl`, and `fresh=false`. The original hosted workspace runs use the same original Node test profile and the ordinary M06 dependency profile at `opt_level=1`, with debug assertions and overflow checks enabled.

The original workspace build command is retained verbatim:

```text
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features --no-run --message-format=json
```

The from-zero protocol/cost executables were built in their separate `--release` profile, as recorded by their build/controller JSON. They are not used to substitute for the original workspace test-profile capacity result. Their downloaded ELF bytes were independently checked against the controller SHA256 and ELF machine type during collection. The workspace artifacts contain runner-side ELF identity checks and before/after hashes, not ELF bodies; the packager did not independently re-read those absent ELF bodies.

No ELF, original ZIP, build target tree, fixture SQLite database, or fixture owner-lock body is included. These exclusions preserve the raw logs, source/build receipts and business reports while avoiding redundant executable and database copies. Original ZIP IDs and SHA256 digests remain in the verification indexes.

### Original capacity results on `0959`

The two capacity selectors and budgets are unchanged. Actual paid CPU totals are observations under the recorded refill/accounting policy, not an invented universal two-second acceptance limit.

| Lane | Ordinary parent paid CPU, ns | Authenticated parent paid CPU, ns | Native capacity exits | Reactor-exit controls |
| --- | ---: | ---: | --- | --- |
| x64 head | 2569687019 | 3042670752 | `101`, `101` | `0`, `0` |
| x64 actual merge | 2854479516 | 2796405802 | `101`, `101` | `0`, `0` |
| ARM head | 2867827616 | 3501657096 | `101`, `101` | `0`, `0` |
| ARM actual merge | 2866739664 | 3515738160 | `101`, `101` | `0`, `0` |

The exact selectors are:

```text
store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner
store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator
ingress::public_v2::tests::public_loop_exit_records_lifetime_before_internal_stop
ingress::public_v2::tests::public_loop_exit_records_external_stop_after_signed_read
```

### Original business window on `0959`

The attack-free baseline confirmed one required transaction in each run. Baseline latencies were 2606523243 ns (protocol head), 3395880528 ns (protocol actual merge), 2389817808 ns (cost x64), and 2110910999 ns (cost ARM). Every corresponding 16-worker pressure phase confirmed zero required transactions in the original `4000000000` ns window. No post-window drain credit or changed deadline is used. These are finite individual observations, not latency percentiles or an independent WAN benchmark.

The protocol head/merge and cost x64 reports record `PUBLIC_REQUEST_DEADLINE` in pressure verification errors; the ARM cost report has no such verification error but still fails the same confirmation target. Native host readiness reports contain no host error, and native builds exited zero. The business failure therefore remains visible separately from environment readiness and five successful exact native test invocations.

## Contents after restoration

| Restored directory | Contents |
| --- | --- |
| `local-0959/records/` | The final local build, per-test commands/logs/readers, binary/profile identity, M06, Clippy, format, graph and readiness records. |
| `local-0959/helpers/` | Exact local invocation helpers, provider observation and actual corrected Git commit object/metadata. |
| `hosted-d2/pq/` | Four original dedicated-PQ artifacts' raw files, including final full Node and Clippy outcomes, plus their verified four-lane index. |
| `hosted-0959/pq-controls/` | Four early dedicated-control artifacts' raw files and verified indexes. |
| `hosted-0959/baseline/` | Corrected from-zero reports/logs/build receipts, contract job logs, all four original workspace artifact files, collection verification scripts/indexes and the frozen source capsule. |

`RAW_FILES.json` is a complete inventory of every retained raw file, its source path, byte length and SHA256. Raw whitespace, empty files and failed-test logs are preserved. JSON wrappers named `*.job-log.json` preserve the exact GitHub tool's retrieved job-log string in `raw_log`; the wrapper identifies its source job. No Hepta private source or private raw runtime material is included.

## Verify and restore

Only Python's standard library is required. Choose a destination that does not already exist:

```sh
python3 restore.py --output /tmp/chain-pq-phase1-restored
```

The tool validates support-file hashes, each encoded and decoded part, contiguous gzip segments, complete gzip and tar sizes/hashes, the embedded raw manifest, canonical relative paths, unique regular tar members, per-file lengths and SHA256. It rejects symlinks, traversal paths, duplicate members and unexpected files. It writes into temporary staging and publishes the destination only after validation succeeds. It does not execute archived native code, scripts, tests or SQL.

The archive uses sorted PAX tar entries with `mtime=0`, `uid=gid=0`, empty owner names and mode `0644`; gzip uses an empty filename, `mtime=0`, level 9. Consecutive gzip segments are independently encoded as Base64, each part at most 160000 bytes including its final LF. The exact gzip/zlib parameters and all digests are in `manifest.json`. Two builds from the frozen plan are compared during collection, and every restored file is compared against its original bytes.

To reproduce the encoding from an already restored raw set, retaining the original manifest's provenance paths:

```sh
python3 build_archive.py \
  --plan /tmp/chain-pq-phase1-restored/RAW_FILES.json \
  --source-root /tmp/chain-pq-phase1-restored \
  --output /tmp/chain-pq-phase1-reencoded \
  --work /tmp/chain-pq-phase1-reencoded-work
```

Hashes establish byte identity for the retained evidence. They do not by themselves authenticate an independent operator, establish a secure deployment, or attest that a consensus or product security goal has been met.

## Qualification remains unchanged

The exact `0959` cross-branch corpus retains all eight assertions as `false`:

```json
{
  "allow_legacy_fallback": false,
  "hepta_final_use_integrated": false,
  "independent_accepted": false,
  "native_pq_node_integrated": false,
  "physical_rollback_resistant": false,
  "production_activation": false,
  "public_wan_accepted": false,
  "quantum_pon_hardness_qualified": false
}
```

The witness controls concern the explicitly guarded PNQ2 request, resource and revocation state. They do not establish rollback resistance for every account, History, CURRENT or FinalUse path. The witness must retain independent protected state; Current is not a distributed lease; same-writer clones are not shown to provide exactly-once business effects. Unknown CAS outcomes remain fail-closed. Neither local/hosted component tests nor the encoded archive substitute for independent deployment, normal legacy-asset migration, quantum work/fork-choice analysis, production transport confidentiality, or complete Hepta integration. All six whole-chain qualification gates remain open.
