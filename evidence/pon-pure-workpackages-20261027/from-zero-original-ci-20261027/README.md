# Original cross-architecture CI artifacts: failed confirmation gate

This package preserves both complete original GitHub Actions ZIPs byte-for-byte. It records a **failed** integration at source [`0c804e9f5bcf6e972bbb4524c744d4b3c8801c34`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34), tree `ebd3545aac5815260ec1f94a2b9a2f383e8dd051`, in [workflow run 40490734526](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734526). It does not accept a source successor, change a native acceptance predicate, or claim that CI passed.

The original artifact list was read at `2026-10-27T10:57:02.354Z`; the two download receipts end at `2026-10-27T10:57:07.636Z`. The forensic diagnosis is dated `2026-10-27T10:59:38.877001+00:00`. This is later evidence for the same completed original jobs, separate from the previously frozen 10:51 CI status snapshot. Future source changes or CI results do not rewrite either snapshot.

## Actual result and denominator

Both architectures ran the five named native tests and their original manifests record `all_named_tests_passed: true`. Their harness nevertheless records `passed: false`, `execution_finished: false`, and `failures: ["CONFIRMATION_TARGET"]`. The failed required report flag is `finite_target_met`; passing `invariant_target_met` and `same_packet_sequence_in_both_runs` do not establish business confirmation.

| Architecture | Original phase | Attacker workers | Signed submits OK | History network OK | Native History imports OK | Business confirmation |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| x64 | attack-free-baseline | 0 | 7/7 | 16/16 | 0/16 | 0/1 |
| x64 | from-zero-pressure | 16 | 7/7 | 16/16 | 0/16 | 0/1 |
| arm64 | attack-free-baseline | 0 | 7/7 | 16/16 | 0/16 | 0/1 |
| arm64 | from-zero-pressure | 16 | 7/7 | 16/16 | 0/16 | 0/1 |

Across the four phases, **28/28 signed submissions succeeded and 64/64 History network responses succeeded; all 64 local imports returned `PUBLIC_HOST_KERNEL_PARENT`, and business confirmations were 0/4**. The independent client stayed at its genesis cursor. The original four-second business windows, two-second call budgets, and 16 pressure workers remain unchanged in the retained reports.

The original `receive_public_page_from_before` path invokes `require_host_kernel_budget(source, Some(FIXED_PUBLIC_KERNEL_PARENT))`, including for loopback. The fixed parent is `/sys/fs/cgroup/trnmponpublic.slice`. The old CI call did not provision or enter that required administrator-owned Host scope. The observed error covers parent canonicalization, ownership and path eligibility checks. Without the original host cgroup capture, these reports cannot establish which specific parent condition was absent. This is evidence of an integration/environment contract mismatch at a retained fail-closed guard, **not a measurement proving CPU saturation, a throughput ceiling, or an unavoidable consensus bottleneck**.

A wrapper repair on a newer source has not been accepted by this package. It needs its own exact-source execution and unchanged confirmation gate. No new CI is awaited or folded into this archive; public Host checks have not been removed or weakened to turn this failure into a pass.

## Preserved bytes and source identities

`x64-original.zip` and `arm64-original.zip` are the original complete archives, with **123/123 members each**. Their GitHub artifact digests, CRCs, sizes, compressed member sizes and member SHA-256 hashes were rechecked. Both original from-zero manifests' **47/47 hashed files** were also rechecked against their corresponding ZIP members. Binaries, SQLite state, all logs and full reports remain in the ZIPs. No members were filtered, rewritten or repacked.

| Architecture | ZIP bytes | Original GitHub ZIP SHA-256 | Actual native binary SHA-256, before = after |
| --- | ---: | --- | --- |
| x64 | 7406718 | `a0d4851c857d8d816d66942ee51ce351bb63d37d955f73e91750892b291c16cd` | `a75e3fcd1e6fd9dcdc1ca7a0b45895d794e74f55f3e6e94db325e700fac170ef` |
| arm64 | 7155919 | `b14bbb55e2678a0f9a4b0446dc6bc0ebb4fc5218f9017c3ba60cef1ed1c6326b` | `829f7586331b0e334292733d8339bb473bbd55e12efb6e9567a1cfae82a9e8ec` |

Both native manifests bind the same commit `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34` and tree `ebd3545aac5815260ec1f94a2b9a2f383e8dd051` before and after execution; their tracked source identity records agree with original `source.json`. The native test source SHA-256 is `d10a3871e19ae2479c9eb3420ddf0bc47e89a1ef72d34ac5be5b82fad99eb023` on both architectures. These were checked against the original Git objects. Archive integrity and source identity are distinct from CI success.

`metadata.tar.gz` contains the original artifact list, download receipts, all-member hash manifests, original from-zero manifests, source records, the later diagnosis and exact source excerpts, plus this packaging operation's validation and credential-screen receipts. Its original small files are byte-preserved. It does not redundantly embed the two complete ZIPs or the extracted 9 MB confirmation report copies. The full reports are already present at `from-zero-native/confirmation/report.json` inside each original ZIP; their exact byte counts and hashes are in `manifest.json` and `verification/original-report-references.json` inside the metadata tar.

All 246 ZIP members (100193257 uncompressed bytes), including binaries and SQLite, and the original loose metadata/report copies were screened for recognized credential formats, credential-named files, private-key envelopes, token literals and signed download URLs. No recognized non-test credentials or credential-named paths were found. An initial broad `sk-` search matched 50 substrings inside `task-`/`mask-` identifier strings in the native executables; none were token-boundary credential matches. Temporary signed download URLs were already omitted by the original collector; its public GitHub API endpoints are preserved. Screening rules and scope are recorded without reproducing candidate values. This check is not semantic decompilation of arbitrary opaque key material.

## Publication scope and limits

These five files append only to the separate documentation branch, based on published docs commit `36cf6cc7a0ac3cfd9ace44d254bee0c266d3e7eb` and tree `6a5a5805970809b019b78c8b5e12ee14819346a3`. This package does not change runtime files, workflows, PR506 or PR4080 source pins, main heads, model adoption or the isolated M06 branch. It performs no native build/test, CI dispatch, Git commit, ref update or network mutation.

The package does **not** establish full CI acceptance, an independent WAN run, public service qualification, useful-work hardness, whole-chain post-quantum security, or production readiness. The original failure remains a failure. `manifest.json` hashes this README, both original ZIPs, the metadata tar and every tar member; the external publication plan hashes all five repository blobs, including the manifest itself.
