# Original CodeQL evidence review: F and G

This directory records a manual context review of all **322 original Rust results** and the actual four-language publication outcome. It grants no security, coverage, supply-chain or publication qualification. No query, model, SARIF result, official alert state, coverage condition or repository setting was changed by this review.

The reviewed sources are F `7d54a36c9e760f8edab6544c69c153dad2626eab` and G `c96c2b3e24ba354b4abcb842ca6a6a019c442b73`. The original runs are [F 40877800722](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40877800722) and [G 40984057072](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40984057072). All result references below are zero-based SARIF result indices, **not GitHub alert numbers**.

## Complete result identity and context

[rust-triage-322.json](rust-triage-322.json) preserves the original F index, rule, message, partial fingerprints, canonical result digest, source path and line, source digest and reason for each result. It adds a pinned source URI and the corresponding G index/digest. Every row retains `security_gate_pass=false` and `official_alert_state_changed=false`.

[F-to-G-findings-map.json](F-to-G-findings-map.json) maps all 322 F/G results. Every `artifactLocation.index` was checked against its own run's artifact URI before the index alone was omitted from comparison copies. The complete result multisets then matched. Original SARIF bytes remain unchanged; matching does not establish project security or complete source coverage.

| Manual context group | Count | Finding and retained limitation |
| --- | ---: | --- |
| Fixed test-fixture nonce/salt | 297 | Locations belong to `cfg(test)` modules or Cargo integration-test targets, including replay, malformed-input and known-answer controls. Context is recorded per result; original alerts remain. |
| Adversarial research work nonce | 1 | F result 195 uses the public zero challenge nonce in a false-trace research branch; it is not an encryption nonce. |
| Entropy buffer initialization | 1 | F result 297 initializes a 32-byte buffer, then fills all bytes using `/dev/urandom` and `read_exact` before use. The `?` path returns on failure. No runtime entropy-failure qualification is claimed. |
| Vector-operation sink model | 15 | F results 299–313 report `Vec::insert/remove`. Successful mutation does not print elements. A bounds panic may disclose index/length; that behavior must be distinguished from element disclosure. Inspected inputs are public test/fuzz/research state. |
| Public test diagnostics | 7 | F results 314 and 316–321 print numeric capacity/length information or a certificate-verification result for public fixtures. Inspected output types have no raw signing-seed field. |
| Mixed CLI data flow | 1 | F result 315 requires a separate finite runtime canary check; no universal information-flow conclusion is claimed. |

The 299 hard-coded-value results comprise 294 nonce and five salt reports. The 23 logging results comprise the last three groups. The [pinned upstream model](https://github.com/github/codeql/blob/codeql-cli/v2.27.3/rust/ql/lib/ext/generated/modelgenerator/rust.model.yml#L8758-L8767) marks vector self/index arguments as `log-injection`. Its exact raw bytes were checked against the Git blob identity; [review-provenance.json](review-provenance.json) records the SHA-256 and source lines. This is an upstream-model false-positive candidate review, not a dismissal or an allowlist.

The CLI result names **13 sources**, including three `secret_identity` calls. The original SARIF contains **four expanded code flows**, all through public account paths. Manual inspection additionally follows `DevelopmentIdentity`: private secret/public fields, `Clone` without a serialization or debug implementation, raw-secret use by signing, and return of public keys or signatures. No raw-secret serialization path was found in those inspected paths. A finite canary exercise is still pending and would cover only its stated commands, branches and output files; it would not prove noninterference for arbitrary executions.

## Actual G analysis and publication

[codeql-G-publication-receipt.json](codeql-G-publication-receipt.json) identifies the original run, job and artifact IDs, archive/member digests, source capture, phase exit codes, preservation checks and official failure. All downloaded artifact archives and members were verified; temporary download URLs are excluded.

| Language | Selected queries | Findings | Extraction warnings | Local analysis gate | Metric number normalizations | Official publication |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| Rust | 37 | 322 | 85 | Fail | 14 | Fail |
| C/C++ | 61 | 0 | 0 | Pass | 15 | Fail |
| Python | 45 | 0 | 0 | Pass | 0 | Fail |
| Actions | 18 | 0 | 0 | Pass | 0 | Fail |

All four preservation checks report `all_results_rules_diagnostics_and_invocations_preserved=true`. G therefore provides actual CI evidence for the metric fidelity repair. The official upload action in each publisher job reports: “CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled”. The following verification step also exits unsuccessfully because its explicit upload-outcome check sees failure. A verified metric transformation is not a successful official upload.

The separate [G exact-source export run 40984057251](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40984057251) also failed: its original log records that analyses/checks did not complete and stabilize before the deadline. This review did not inspect or change administrator settings and does not reinterpret the failed export as complete.

## Extraction coverage remains open

[rust-diagnostic-review.json](rust-diagnostic-review.json) retains the original 85-warning denominator and the reason each group remains open:

| Group | Count | Evidence boundary |
| --- | ---: | --- |
| Literal macro expansion | 74 | 37 `expected expression` plus 37 `to_sign_and_limbs` expression-expansion warnings. A separately staged narrow `ark-ff-macros 0.5.0` parser compatibility backport is a candidate; no reduced CodeQL count has been observed. |
| Archived source manifest context | 8 | Four unavailable-manifest and four missing-manifest warnings concern retained standalone original source without its full original compilation context. No deletion, rename or exclusion was used to hide them. |
| Retained assembly macro | 1 | `ark_std::arch::asm` extraction support remains incomplete in the report. A native build cannot establish semantic extraction coverage. |
| Internal Phi invariants | 2 | The diagnostics have no actionable source location. A precise extractor reproducer or upstream correction is required before claiming resolution. |

This is an evidence report. Development acceptance and remaining work remain governed by the repository's [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
