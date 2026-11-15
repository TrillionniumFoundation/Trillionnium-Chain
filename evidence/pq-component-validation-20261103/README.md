# PQ component validation — 2026-11-03

**Whole-chain status: HOLD / UNQUALIFIED.** This directory records bounded component work and its exact source identities. It does not authorize production activation, change consensus, provide all-state rollback protection, or attest whole-system PQ-128.

## Published changes and exact validation scope

| Change | Commit | Scope |
| --- | --- | --- |
| Witness client pre-CAS consistency guard | `45962558a7133375b16c0ac2600f2edb4a115585` | Refuse arguments contradicted by the last authenticated checkpoint before signing or transport; keep exact retries and unobserved legitimate writer progress. |
| Native versus succinct-proof scope correction | `1c18878c42727e5261c7706d996fbfb672a8dc3c` | Current Node validates complete native PNW1. The isolated RISC Zero experiment is not a Node backend. All six qualification gates remain unqualified. |
| Original witness regression repair | `8a74a9e42a9efbc52d83e861f64f03efd40f1406` | Test both the known client's local refusal and a fresh client's real-owner CAS refusal, retaining the original exact retries, skip, wrap and unchanged-head checks. |

Final native validation binds **`8a74a9e42a9efbc52d83e861f64f03efd40f1406`**, tree **`3d3ab7ff49c7f0b9109ba9e5ede1362cf6b290e7`**. It preserves concurrent History, architecture-fixture, plan and proof-scope changes. Before and after every recorded command, all **7,536 tracked entries / 872,317,779 bytes** matched that source. Evidence publication is a later documentation-only commit and does not assign these results to another source tree.

Evidence publication preserves later commits `b28098c092dca72165c0d26054fce95a8636d777` and `af570eaef44870ba3ec1f3d5be2cbdde2981931d`, including additional committed-CAS, fixed-Host fixture and History evidence work. The 45-entry native result above belongs to `8a74a9e4`; it was not rerun against those later changes. The exact publication parent `af570eae` passed project preflight in a separate clean worktree; that preflight executes no native tests.

## Actual results

| Observation | Recorded result and limit |
| --- | --- |
| Original hosted run `41691371037`, four x64/ARM × HEAD/merge lanes | Every lane: original controls **42 passed / 1 failed**; complete Node **940 passed / 1 failed / 23 ignored**; build and strict Clippy exit 0. Both new witness functions passed. **All four full runs remain failures.** |
| Original separate X230 continuation at `45962558` | Original locked graph, formatting, no-run build and strict Clippy passed. Pinned OpenSSL 3.5.9 build and real ML-DSA-65 smoke passed; this is not the full upstream OpenSSL suite. No runtime result is assigned to this continuation. |
| Proof-scope edit at exact `9f046408 + published 1c18878c overlay` | Original qualification-guard tests **22/22**, source-corpus tests **34/34**, preflight, guard and all 376 source pins passed. Guard success preserves HOLD; it does not prove PQ-128. |
| Initial regression composition | Formatter exit 1 on two concurrent History assertion wraps; original failure output retained. The correction and subsequent exact `3898f6a6 + repair` composition passed the original full formatter, preflight, guards, pins and whitespace. |
| Final frozen `8a74a9e4` | Compiler identity, Linux locked graph, original formatter, no-run build, strict Clippy, witness inventory, witness runtime and postflight all exit 0. |
| Final complete `pq_rollback_witness` selector | **45 passed / 0 failed / 0 ignored / 922 filtered out.** The 45 include one child-process harness entry; 44 entries remain after excluding that helper. All 38 original required witness controls, the two added controls and the repaired original CAS regression are present and pass. |

Final command:

```text
cargo +1.95.0 test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --all-features pq_rollback_witness -- --show-output --test-threads=1
```

The original provider, project test profile, one build job and selected single-thread execution are recorded with every command. No business deadline or assertion was relaxed. The fresh final test executable is 363,681,632 bytes, SHA-256 `1a592635ce27a99b0d34177a992a559c81d5da11bd564557186a05efdeca6fec`; its identity is retained, not the large executable itself.

Durable final job `1a1a2e9ee80-96a-7564` completed with exit 0, no cancellation or timeout, and complete output. Intermittent result-read timeouts delayed observing that terminal state. They were not converted into a failed or successful execution claim.

The final selector is not the full Node library, a fresh four-lane hosted acceptance, a throughput benchmark, or a composed Chain/Hepta deployment. The later hosted run [41704279631](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41704279631) is a separate observation; its queued state when checked supplies no pass. No old failing result is relabelled.

## Evidence layout

- [hosted-41691371037](hosted-41691371037/README.md): all 652 original full-artifact members, 40,861,110 uncompressed bytes, preserved in a compact TAR/XZ with per-member hashes. All eight original ZIP identities and both original summaries are retained. The TAR/XZ hash identifies the repack, not an original GitHub ZIP. Its historical statement that final native verification was pending describes that package's capture time; the separate final results above supersede that pending observation without changing any original bytes.
- [x230-45962558](x230-45962558/archive-members.json): original X230 command receipts, provider metadata and complete raw-log archive.
- [proof-scope](proof-scope/checks.json): exact edit, raw 22/34 test outputs, guards and source-corpus records.
- [repair-initial](repair-initial/checks.json): original formatter failure and complete formatter output.
- [repair-composition](repair-composition/composed-checks.json): successful exact final composition and preceding formatting follow-up.
- [x230-8a74a9e4](x230-8a74a9e4/witness-scope-execution.json): final source-bound command receipts, complete test inventory, terminal status and raw-log archive.
- [publication-parent](publication-parent/checks.json): exact later publication parent, clean worktree and project preflight; no new native test claim.
- [validation-summary.json](validation-summary.json): machine-readable scope and results.
- [evidence-manifest.json](evidence-manifest.json): exact published file lengths, SHA-256 and Git blob identities, excluding the manifest itself.

Paired Hepta authority evidence is maintained in its own repository; no private Hepta raw logs are included here.

## Remaining qualification boundaries

The witness still covers only the three PNQ2 tables under an independent external-witness-state assumption. A whole-SQLite restore test detects changes to that protected root; it does not put balances, History, CURRENT, installation, FinalUse, settlement or governance into the root.

The current native PNW1 relation, actual verifier and each hash purpose still need the stated security argument and independent review. Any future accepted succinct backend adds its own concrete commitment, FRI, Fiat–Shamir, recursion, guest/compiler and final-verifier obligations. RISC Zero component estimates do not assign a bit level to the current native Node.

The complete authorization inventory, historical ownership/nonce/revocation migration, quantum work and fork-choice model, original-capacity acceptance, independent WAN/fault/recovery deployment and activation process remain open. Successful component tests do not close any of the six whole-chain gates.
