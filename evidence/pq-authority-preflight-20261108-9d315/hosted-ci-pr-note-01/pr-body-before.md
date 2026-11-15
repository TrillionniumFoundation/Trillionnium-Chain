## Why

The release owner could perform earlier signature verification before rejecting a later malformed signer entry, or verify the old root before discovering a malformed successor quorum. Those quorums were already rejected: this fixes rejection-cost ordering, without claiming an authority bypass.

## Changes

- Preflight the complete bounded signer set before signature mathematics. Root rotation prepares both old and successor quorums first. Every supplied signature still must verify; signed encodings, current-state checks and owner transitions retain their existing semantics.
- Add nine regressions: the original kernel recorded **6 failures / 3 passes**, and the repaired kernel recorded **9 passes**. Preserve the exact **37 original + 6 initial-root + 9 quorum-preflight** release registry.
- Preserve concurrent migration qualification through `8d8f05566b2a1612a3bf4a6c6c71635df454d397` in a real merge. The main Cargo lock is unchanged; the fuzz lock adds only the local release-bundle → protocol dependency edge.
- Separate Node regression setup from post-admission expiry after a real trusted-time-window failure. The [failed first integrated run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/527e2e58db6d7c1fd84ba88c3131289edea86b1d/evidence/pq-authority-preflight-20261108-9d315/integrated-source-01/summary.json) remains recorded as FAIL.
- Retain the report, failed attempts and raw captures. Lossless gzip preserves large research records and validation captures with Git-sensitive whitespace; the artifact index binds stored and original bytes. Failed commands remain failures in the evidence.

## Validation

All **31 command gates** passed in `integrated-source-02` on tested source `a14b7e2b51af9772210e5114945dfa7e309bf97b`. Delivery `527e2e58db6d7c1fd84ba88c3131289edea86b1d` changes only paths under the evidence directory. [Full retained summary](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/527e2e58db6d7c1fd84ba88c3131289edea86b1d/evidence/pq-authority-preflight-20261108-9d315/integrated-source-02/summary.json) · [Execution record](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/527e2e58db6d7c1fd84ba88c3131289edea86b1d/evidence/pq-authority-preflight-20261108-9d315/README.md).

| Actual test scope | Observed result |
| --- | --- |
| Release bundle, all targets/features | 52 passed, exact 37+6+9 names; no ignored tests |
| Other five selected packages, all targets/features | 442 passed; 2 existing ignored observations |
| Six-package doctests | 4 passed |
| Node `release_owner::` module | 40 passed; 1 existing ignored control; 1,244 unrelated tests filtered |
| CI contract tests | 116 passed |
| Pure root-research harness tests | 18 passed |
| Preserved migration signature / journal / public-seed controls | 7 / 13 / 21 passed |

The run includes strict workspace Clippy across all targets/features, formatting, locked/offline default/all-feature/fuzz graphs, non-test release-library checking, source guards before and after execution, CI/PQ/claim/authority/source-integrity checks and negatives, the canonical plan and repository links. Source/provider identities were unchanged and retained SQLite native build outputs were qualified. The tests above do not constitute all-workspace tests or full Node/Host acceptance. Hosted CI results are reported separately; this PR does not claim a green hosted run.

## Retained Node timing failure and fixture correction

The first integrated run on `af6b06fa1cb944e639148b58e9765fe2bb0065ab` failed in `admitted_completion_after_expiry_lost_reply_is_exact_and_cold_does_not_redispatch`: it expected `lost after durable completion` but admission returned `M15 conservative trusted time interval is outside the exact window`. This was a real failing run, retained with its original receipts and raw captures; the later successful run is credited only to its own tested source.

The [corrected regression](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/a14b7e2b51af9772210e5114945dfa7e309bf97b/trillionnium/crates/trnm-pon-node/src/release_owner/service_tests.rs) changes the signed validity window from **2 to 30 trusted seconds** and deliberately waits past the former two-second setup boundary before sending the request. The request still receives the existing fresh **two-second service deadline**. At the actual `Admitted` point, the test asserts exactly one admission and verifies that the signed window has not expired; it then waits for the real elapsed fixture clock, at its unchanged declared 2× rate, to reach that **same signed expiry**. The lost-reply injection, durable-completion assertions and cold no-redispatch checks remain exercised.

Only regression setup and synchronization change; production clock, deadline, wire and cryptographic paths remain unchanged. [Corrected tested commit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a14b7e2b51af9772210e5114945dfa7e309bf97b) · [Source correction identities](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/527e2e58db6d7c1fd84ba88c3131289edea86b1d/evidence/pq-authority-preflight-20261108-9d315/source-correction.json) · [Exact retained correction patch](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/527e2e58db6d7c1fd84ba88c3131289edea86b1d/evidence/pq-authority-preflight-20261108-9d315/source-correction.patch.gz).

## Root-signature research

The pinned OpenSSL 3.5.9 experiment completed **64 paired proposals**, all **9 legal signer combinations** and **12 refusal controls**.

| Command-cold candidate path | Signing + encoding median | Frame verification median | Complete frame |
| --- | ---: | ---: | ---: |
| ML-DSA-87 component | 20.468 ms | 16.539 ms | 15,484 bytes |
| Fixed ML-DSA-87 AND SLH-DSA-SHA2-256s | 4,120.412 ms | 36.787 ms | 75,378 bytes |

The trusted configuration is separately encoded at **8,717 bytes**. These shared-host, command-cold measurements include process/file overhead and fixed current views; they grant no durable effect. They do not establish independent custody or historical enforcement of requested resource limits. See the [full report](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/527e2e58db6d7c1fd84ba88c3131289edea86b1d/docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md) for protocol scope, controls and raw observations.

## Qualification

Production activation, whole-chain PQ qualification, physical rollback acceptance, WAN acceptance, Hepta CURRENT/FinalUse acceptance and PoN quantum-security claims remain **HOLD**. This is a draft for review; no deployed service, key, root or execution permission is changed.
