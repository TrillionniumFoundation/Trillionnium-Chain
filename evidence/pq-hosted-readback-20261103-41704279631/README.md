# Frozen 8a hosted PQ readback — partial result and retained ARM failure

This evidence-only supplement records [run 41704279631](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41704279631). **Whole-chain qualification remains HOLD / UNQUALIFIED.** It adds no source change, rerun, timeout increase, assertion waiver or CI exception.

## Observed result and source boundary

Candidate HEAD is `8a74a9e42a9efbc52d83e861f64f03efd40f1406`; the actual prospective merge is `6ab5906347c148ca2def1c0bb02a187ece51c77f`. Both recorded tree `3d3ab7ff49c7f0b9109ba9e5ede1362cf6b290e7`, with identical before/after tracked-source observations.

| Captured lane | Original controls | Complete Node library | Build / strict Clippy |
| --- | --- | --- | --- |
| x64 HEAD | 43 passed / 0 failed | 944 passed / 0 failed / 23 ignored | exit 0 / exit 0 |
| x64 prospective merge | 43 passed / 0 failed | 944 passed / 0 failed / 23 ignored | exit 0 / exit 0 |
| ARM64 HEAD | 42 passed / 1 failed | Not included in this artifact capture | exit 0 / not included |

At the separate [job observation](job-observation.json), completed at **2026-11-03 20:48:38 UTC**, both x64 jobs were successful. ARM64 HEAD and prospective-merge full regressions were still running. ARM64 HEAD's original-control step had failed. These are point-in-time observations, not a later all-matrix conclusion.

The [unaltered capture](capture/README.md) preserves all 487 original members from three official artifacts, plus their source identities and original summary. The archive is a new TAR/XZ container, with original member bytes preserved; its hash must not be confused with any original ZIP hash. Root review independently rechecked all 487 members against the original ZIPs, the three metadata copies, all five outer hashes and the unchanged summary.

## ARM64 failure: observed phase, not speculation

The failed selector is `store::pq_rollback_witness::tests::guarded_charge_pending_revocation_survive_service_cold_restart`. The [original command receipt](arm64-head-native-11.json) records exit **101**, source `8a74a9e4`, and a single failed test. The [unaltered log](arm64-head-native-11.log) is **18,375 bytes**, SHA-256 `6fe8a52d5537e4d4b8970c86d1b54738dfb8b6cb41839e9fa59791d7938a7d3e`.

The panic at [tests.rs:225](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8a74a9e42a9efbc52d83e861f64f03efd40f1406/trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/tests.rs#L219-L242) is the unwrap of `begin_pq_network_request`. The pending-request CAS failed before the test reached peer revocation, service restart or reopen.

| Original observer record | Actual observation |
| --- | --- |
| 26, service_cas | `last_phase=service_final`; CAS commit attempted and committed; `PQ_WITNESS_DEADLINE` |
| 24, client_cas | Transport entered; `last_phase=transport`; no authenticated matching CAS receipt |
| 22, mutation_commit | `last_phase=advance_cas`; local commit neither attempted nor completed |

The service entered with **241.382315 ms** remaining. Its `service_commit` phase consumed **262.156783 ms wall time / 0.667432 ms calling-thread CPU**. Receipt signing subsequently completed, then the final service deadline check returned the error. The diagnostic reported zero measurement failures, no fixture delay and no TCP failure. Nested interval durations are not additive.

These records locate a committed-external-CAS / unavailable-receipt outcome. They do not identify storage, scheduling or any other environmental root cause, do not establish an adversarial exploit, and do not justify calling the test flaky.

## Relationship to later b28098c

The existing later [b28098c change](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b28098c092dca72165c0d26054fce95a8636d777) directly changes this `ServiceFinal` check: an already completed CAS retains its signed receipt for the client's existing authenticated reconciliation path, while `Current` retains the deadline check. Earlier deadline checks, the socket write deadline and late-live-use refusal remain distinct. The failing fixture invokes `DurableWitness::handle` directly, so this is an exact source-path correspondence.

**That correspondence is not a same-configuration ARM pass for b28098c.** This capture tests 8a only. The later source is not assigned the x64, X230 or Hepta results from earlier revisions. The 8a ARM failure remains a failure.

The earlier [69-file component evidence](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/12171edc890df1611bf68503038bfad3d66a5a88/evidence/pq-component-validation-20261103), including all four original failed 45962558 hosted lanes, is unchanged. The 8a X230 45-entry witness scope and the two successful x64 full runs do not waive this ARM failure or close capacity, recovery, whole-state rollback or whole-system PQ-128 qualification.
