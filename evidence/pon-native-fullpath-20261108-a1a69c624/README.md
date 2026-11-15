# Native full relation and complete-path observation — 2026-11-08

**Component controls passed; performance remains COMPONENT_OBSERVATION_ONLY and security/overall gates remain HOLD.**

The one new development candidate took **7.322108454 seconds** from its frozen scheduled start through independent acceptance readback. Its first canonical snapshot was at **7.213319303 seconds**, with depth **0**. It exceeded the original four-second deadline and never reached six successors. Required-depth timely accepted progress is **0**.

This is a single same-host development control set, not a throughput distribution, WAN campaign, original constrained Host run, or quantum work-cost proof. No compressed proof path or real chain-reorganization experiment was run. Negative absence records mean the rejected/cancelled packet was never stored in its private receiver.

## Exact measured source

- Source commit: a1a69c624db33205a69973b98a6db0f7d22e0782
- Source tree: 8b1759580bad0c260f692ca3405ba7d856cd6bd5
- Base integration commit: 62d2d90c9e1f4c8450c89843f1e08360a24283ce
- Release binary SHA-256: 5ca41198209fe21b6d4f3557879c69847d37802c4aad67f962dd695bdd7f634e
- Original preregistration SHA-256: e7687531f92da803ae0f5dd3d02cb25271ef7d1d09dbe371e9808b9fddc4117e
- Original observations SHA-256: 88a362570bd09dc9e7117048fff4c4767c19867dd5d6dc0274014c4cd063e591

The later publication commit adds these observations and their plan link. It does not replace the measured source identity. Runtime, test, collector, reader and CI source bytes are identical to the measured commit. The independent source checks before/after validation and after collection verified all 14,998 tracked entries (1,652,446,053 bytes) against that exact Git tree. These external observations do not give the Python reader an authentication or consensus authority.

## Actual native outcomes

| Frozen start | Replay / tiles / product / final callback | Process result | Independent native readback |
| --- | --- | --- | --- |
| valid | 1 / 512 / 1 / 1 | exit 0; complete admission and activation | exact packet stored, canonical depth 0 |
| duplicate | 0 / 0 / 0 / 0 | exit 0; existing admission reused | same block, no new progress |
| late_product | 1 / 512 / 1 / 0 | exit 2; WORK:Product | absent, active tip remains genesis |
| cancelled | 1 / 512 / 1 / 1 | exit 2; PUBLIC_REQUEST_CANCELLED | absent, no successful admission return |

All **4/4** frozen starts and all **9** actual processes are retained. There were no collection errors, timeouts, unresolved process groups or unresolved pipes. The original negative exit codes remain failures; the component-control result checks their intended refusal behavior. One new block was locally accepted; the original business progress remains zero.

## Complete-path observed intervals

The parent monotonic clock timestamps when it observes flushed events. Intervals include reader scheduling, cold opens, persistence and process lifetime; they are not isolated kernel execution times. Child-local durations are not added again.

| Interval | Seconds |
| --- | ---: |
| Native generation / search | 2.394345806 |
| Native winner packet preparation | 0.876685725 |
| Same-host complete packet delivery | 0.042120643 |
| Cold receiver, full W1, execution and SQL admission | 2.576483899 |
| Activation, close and independent readback | 1.082870444 |
| Queue and interstage gaps | 0.349601937 |
| **End-to-end for the valid candidate** | **7.322108454** |

The complete four-start observation lasted 13.706487952 seconds. Its common observation window exceeded four seconds, but the valid candidate never reached the required depth. Sequential control samples are not a miner-success distribution.

| Full control-set resource | Recorded value |
| --- | ---: |
| Parent plus children CPU | 618,446,000 ns |
| Sum of nine process CPU intervals | 607,399,000 ns |
| Additional parent accounting retained | 11,047,000 ns |
| Conservative parent-plus-child RSS peak upper bound | 54,403,072 bytes |
| Actual stdin delivery | 4 × 50,010 = 200,040 bytes |

The host was a shared, unqualified x86_64 development machine with 48 reported logical CPUs. RSS is a sum of separately observed maxima, not an instantaneous measurement. These observations do not enforce or qualify the original 0.25-CPU, 2-GiB, zero-swap, 256-PID, 16-hostile-worker contract.

## Exact-source validation

All 13 recorded command steps passed on the measured source. The scope was:

| Check | Result |
| --- | --- |
| New collector / adapter / reader controls | 52 tests passed |
| Existing source-integrity negative controls | 43 tests passed |
| Existing repository negative controls | 50 tests passed |
| Node retained regression selection | 10 tests passed, including the new 16-context matrix |
| PoN work kernel selection | 135 tests passed; 23 unrelated crypto tests filtered out |
| Default and all-feature Cargo graphs | locked, offline resolution passed |
| Full workspace formatting | passed |
| Strict Clippy on the new Rust test and example | passed with warnings denied |
| Repository/Markdown check | passed; 3,739 local links |
| Release example build | passed |
| Source-byte checks before/after validation and after measurement | passed |

That is **290 named tests in the selected scope**, with 16 freshly sealed wrong-context cases inside one Node test. It is not a claim that every workspace test or release gate was executed.

## Retained evidence and reproduction

- [Command identities, actual exit codes and durations](validation/commands.json)
- [Complete original validation outputs](complete-validation.tar.gz)
- [Measurement command records](measurement-commands.json)
- [Component-control summary](component-summary.json)
- [Original frozen plan](processes/preregistration.json)
- [Original process observations](processes/process-observations.json)
- [Normalized component readback](processes/gate-readback.json)
- [Original valid PNP2 packet](processes/candidate.pnp2)
- [Original last-C-word mutation](processes/late-product.pnp2)
- [Complete raw process directory, including private development SQLite stores](complete-processes.tar.gz)
- [Native scope and integer correspondence](../../docs/development/specs/pon/NATIVE_FULL_RELATION_QUALIFICATION_V1.md)
- [Collector and reader usage](../../formal/pon-native-fullpath-v1/README.md)

The SQLite stores contain only this explicit deterministic development fixture. The archive is retained for independent local replay; no running or deployed store was copied.

Run adapt_native.py against the retained processes directory with the original preregistration digest above. It deterministically reproduces the existing normalized files and returns **1**, meaning valid component evidence / HOLD. Exit **2** means malformed or inconsistent evidence and must not be accepted as an expected HOLD. The complete record hashes are in [artifact-index.json](artifact-index.json).

Full native relation correctness does not prove the physical or quantum cost of discovering a winner. Compression still needs the complete, instance-specific cryptographic argument and an end-to-end performance/availability campaign. This record authorizes neither public-network readiness nor production activation.

The two Cargo stdout logs are also stored as lossless .gz files because their exact original bytes include trailing blank lines. No original output bytes were edited. The full validation archive retains every original filename and byte; artifact-index.json records the uncompressed identities as well.
