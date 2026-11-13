# Final source-bound readbacks, 2026-10-27 — all acceptance HOLD

This is a **time-bound evidence snapshot**, appended only to `docs/chain-pure-pon-readback-20261027`. It records exact published successors and their pending CI, and preserves newly retrieved original failures. It does not change runtime files, workflows, branch heads, PR pins, model adoption, or M06 integration.

## Exact successor identities

| Repository / PR | Published head | Tree | Actual GitHub prospective merge | Original base |
| --- | --- | --- | --- | --- |
| Chain / [#506](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/506) | `ac469237422d43805845e8b9a6839ad14e1028e7` | `aa000d8883cbffdf0ac4fbfb57b63394693c99c6` | `47727c4f8335427710b4f3608768b4e9cc7c2a64` | `57c1ed545d067937cbd7aaa7570d5f22123265e6` |
| Hepta / [#4080](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4080) | `1d9f262f9965d30105ee58d4218cd6e27ef7a431` | `3c8a7f5f18325de728b2fc08d5b7bac2e499bfae` | `7cdbb08558b899e23fe029423ef9a762d424e95e` | `3e9efb15faa261a4dc3ffc3205cd259aaee41a3f` |

Both actual merge objects have the original ordered `[base, head]` parents and the canonical merge tree recorded by the native pair checks. The new Hepta commit retains original parent `2bfceaa3226611a72f43d24e67d13e30091c7449` and pins the Chain head and actual merge above. The initial Chain PR GET that briefly returned the previous source after ref update is retained unchanged; the later API bracket and native tuple checks are separate records. Six limited original correction commits and their mapped remote raw commit payloads are included without rewriting original IDs. No full source bundle or old Git history is duplicated.

The docs parent is `163832173a36ceae3f6d8ffd29c1c7ac0ea92c76`, tree `b0b13a564778f80dde42c5c5d413d5a6c1873ccb`, parent `36cf6cc7a0ac3cfd9ace44d254bee0c266d3e7eb`. An initial missing local tree/lazy-fetch failure is retained. The parent subsequently fetched the published docs branch, and this packager verified the actual local commit and tree; no virtual parent is claimed.

## Frozen successor CI, not a pass

Run/check lists were read at **2026-10-27 11:29:56 UTC**. The 16 run-job collections were acquired by **2026-10-27 11:30:30 UTC**. The snapshot retains all four list responses, all 16 job responses, the clock record and summaries. These are different read times, not an assertion of one atomic live state.

| Exact head | Workflow run denominator | Registered check denominator at list time | Acceptance |
| --- | --- | --- | --- |
| Chain `ac46923` | 12: 10 queued, 2 pending | 35: all queued | HOLD |
| Hepta `1d9f262` | 4: 2 queued, 2 pending | 7: 6 queued, 1 in progress | HOLD |

Queued, pending, running, skipped, and not-yet-registered work receives no passing credit. No successful model/training/FinalUse/adoption gate is observed in this successor snapshot. The retained nine local Hepta static checks are **static checks only**; Hepta Rust, Cargo, Bazel, the original training generations and the model gates were not executed locally. Publication identity and native merge pairing are not CI acceptance.

## Original failures remain separate evidence

### Hepta original pair

Original run [40491440610](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40491440610) uses Hepta `2bfceaa3226611a72f43d24e67d13e30091c7449` and Chain `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34`. All four Linux jobs failed step 28: 86 tests, 83 passed and three failed fixture expectations after the named-test list grew from four to five. Model steps 49–52 were skipped in all four jobs. Two Windows ledger jobs succeeded according to the retained jobs API; their complete logs were not collected in this set. All four complete decoded Linux logs and original runs/jobs envelopes are retained byte-for-byte. They are connector-decoded UTF-8 records, not native GitHub ZIP bytes. The seven original files do not record a separate acquisition timestamp; their job/log times are preserved and packaging time is not substituted.

The successor fixture correction is a different source and cannot rewrite that failure. Its original before/after evidence lives at the immutable successor source; this package preserves the limited raw commit mapping, publication receipt, and new pending CI.

### Original Chain late CI and A03 / History

The retained later original `0c804` check list has 64 checks: 37 successes, 21 failures and six in progress; it does not describe the new `ac46923` head. Five representative decoded job logs retain the original History, service-model, protocol-contract, repository-truth and campaign failures. A rejected annotation lookup is also retained.

Read [A03-history-diagnosis.md](A03-history-diagnosis.md) for the full source-bound diagnosis. Original hosted A03 ran three real attempts, all failing within the unchanged 600-second outer limits: **0/3 runs, 0/9 phases, 0/27 planned confirmation rounds**. Nine first rounds were observed and 18 later rounds were not. **63/189 planned business blocks** were attempted and ACKed; 126 were not attempted. **576/576 History network responses succeeded but all 576 native imports failed `PUBLIC_HOST_KERNEL_PARENT`**. All 144 pressure actor instances completed normally. Of 22,881 attack calls, 22,737 were refused and 144 errored; none succeeded. There were 5,337 valid budget samples, zero observed genuine depletion and zero mutation CPU refusals. This hosted evidence is distinct from the earlier local profile-precheck refusal of 0/3.

The representative History artifact contains 4,105 original packet files; its last periodic progress log is 4,000. The test failed after 378.88 seconds at strict public import. Only one of the four failed History lanes' artifacts was downloaded here. Its before-binary hash is retained; the executable bytes are absent from that original History artifact, and the workflow's after-hash check was not reached.

The in-process A03 verifier cannot simultaneously satisfy the original 400% CPU / 16 GiB current-and-ancestor contract and membership in the fixed public parent capped at 25% CPU / 2 GiB. The new from-zero-only wrapper does not automatically solve this conflict. No limits, deadlines or native predicates were weakened. A different importer-process topology requires its own explicit resource/accounting proof and versioned experiment; it cannot be relabeled as the old A03 passing. Priority History has a narrower exact-binary Host wiring option. The broad protocol command names `ancestry_long_sync` without `--ignored`, so it does not itself execute the 4,105-block ignored test; the entire protocol script must not be moved into the smaller resource domain.

All **three complete original campaign total reports** are included in the archive, with their original attempt stdout/stderr, source/resource/binary metadata, selected History records and complete member-hash manifests. The selected original records are 66 files / 144,165,873 bytes. The original campaign ZIP (64,330,038 bytes) and History ZIP (38,101,611 bytes) are **not** embedded here. Their exact original GitHub digests and all 5,034 member hashes are included; all member CRC/size/SHA checks and 913/913 original campaign manifest hashes were verified. The large campaign executable, History SQLite/packet bytes and separately duplicated phase/actor sidecars remain in the original artifacts/local byte-preserved ZIPs, not in this selected-records archive. The manifest enumerates exactly what is present.

### CodeQL: nine reviewed, original gate still failure

Read [codeql-review.md](codeql-review.md), copied byte-for-byte from the completed same-operator review. The original `0c804` check `122144152932` remains **failure**, with nine reported critical/high annotations (five critical, four high). The review uniquely maps 9/9 original annotations to the API-exposed Rust SARIF subset and examines their real code/type/fixture semantics. It does not establish a production secret leak or signing/cipher-nonce misuse at those nine selected sinks; it also does not dismiss alerts or clear the gate. Eight selected sink lines predate the PR; the additional selected literal is a new regression-test fixture.

The exposed Rust analysis contains 316 results. **The other 307 have not received individual semantic audits in the nine-alert review.** The separate [additional scope inventory](codeql-additional-scope.md) enumerates all 316 by source context: 279 unit-test, 23 integration-test, eight fuzz-target, five example, and one production-or-unknown result. These classifications do not clear the alerts. The production candidate, alert 1024 at `main.rs:2641`, remains **OPEN**: its 12 reported source relations include three real `secret_identity` calls, but only four complete API flow paths were available. The bounded inspection did not establish actual private-key disclosure and did not resolve the unavailable relations; the `DevelopmentIdentity` type name is not evidence that an owner-controlled secret file is a public fixture. The additional JSON and Markdown are preserved separately, without rewriting the frozen nine-alert review.

API-provided SARIF is not claimed to be the original full upload or complete historical branch alerts; the prospective merge was not scanned by that head analysis. The original CodeQL review archive is preserved as the exact 722,798-byte `codeql/review.tar.gz` member, SHA-256 `f5a980c68af9173c5b4162ed2e257be1ca5957e7c5a1316670cc4e54d2226637`; it is not reconstructed. No new CodeQL execution was performed by this packager.

## Preservation, layout and extraction

The archive uses **one tar.xz encoding with Python lzma preset 6**; raw members are unchanged. Existing compressed review evidence is itself retained as original bytes. The archive has **145 members**, **161,759,808 raw member bytes**, and **4,404,916 compressed bytes**. It is distributed as **1 blob(s)**, each at most 6 MiB. `manifest.json` binds member hashes, part order/offsets, every part hash and the complete reconstructed archive hash.

Full archive SHA-256:

```text
9147ddbbd64751f2a50850e5f073ecea88664338038e0058c4252cdbb52c3525
```

The archive is a single file; no reassembly is required.

```sh
printf '%s  %s\n' '9147ddbbd64751f2a50850e5f073ecea88664338038e0058c4252cdbb52c3525' 'readbacks.tar.xz' | sha256sum -c -
tar -xJf readbacks.tar.xz
```

Key archive paths: `successor-ci/`, `publication/`, `raw-commits/`, `hepta-local-static/`, `original-hepta-ci/`, `original-chain-late-ci/`, `native-host/selected/`, `native-host/diagnosis.json`, and `codeql/`. Every input was rehashed before and after packaging. Previously content-screened large original records were reused only with identical hashes; new inputs and nested CodeQL review members were screened without printing potential values. No recognized non-test credentials were found. Scope and limitations are retained in `verification/credential-screen-final-append.json`.

Previous immutable evidence remains at [docs commit 36cf6cc](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/36cf6cc7a0ac3cfd9ace44d254bee0c266d3e7eb) and [docs commit 1638321](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/163832173a36ceae3f6d8ffd29c1c7ac0ea92c76). The earlier complete x64/arm64 from-zero ZIPs are already preserved there and are not duplicated. Historical M06 source/evidence and same-operator review remain on their isolated branch and prior evidence paths; no M06 implementation is added or merged here.

**All overall acceptance remains HOLD:** full successor CI, original public service/depletion/confirmation gates, independent WAN qualification, whole-chain post-quantum security, work hardness, model improvement/adoption and production readiness are not established. This metadata append performs no source edits, native build/test, CI rerun/dispatch/cancel, commit, ref update or remote write.
