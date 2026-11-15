# PR #782 fresh challenge service: retained remote failure

Source: C2 `cc4dd8bdd89309c635831db30b508af2f89419d7`; run `42422952132`, head job `128555111370`.

The actual fresh test panicked at `trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/fresh_challenge.rs:244`: the unchanged four-second/six-depth business target was not met. The process returned 101; it was not marked timed out. The fresh report had already been written. The wrapper's `FRESH_NATIVE_PROCESS_REQUIRED` is its nonzero-process refusal, not a missing binary or build failure.

The attack-free phase confirmed one transaction at depth six in 2.894233678 seconds. Under the 16-worker fresh-challenge pressure, the independent client confirmed zero transactions. History replay 0 was accepted; replay 1 ran from 3.386899779 to 4.085282455 seconds and was rejected with `PUBLIC_REQUEST_DEADLINE`. No final independent confirmation observation exists. Both invariant targets remained true, no attack was accepted, and the receiver matched the valid honest prefix. The pressure finite business target is the false term in the fixed source's top-level assertion.

The original retained-packet test returned 0 but also reported `finite_target_met=false`. Its strict wrapper rejected that observation as `CONFIRMATION_TARGET`; the retained manifest records the last pressure replay at index 3 with `PUBLIC_REQUEST_DEADLINE`. The full original report was not decompressed for this triage.

The host contract was observed as `cpu.max=25000 100000`, 2 GiB memory, zero swap, and pids.max=256. This report does not establish that CPU quota is the sole cause. Cargo builds and the source-before/source-after checks passed. The local C2 test qualification remains a separate result; it does not turn this remote gate green.

## Retention and limits

The original head artifact is retained as exact ZIP bytes: 5,630,716 bytes, SHA-256 `ea3bbb909bd39ad5935f206298114e9bfed77b03c5ab26f1142e39f4f9e6f4f4`. Its 57 member paths and expansion bounds were checked. Only selected text was read. No downloaded executable was run and no SQLite database was opened. No test, workflow, budget, assertion, source, or ref was changed, and no GitHub rerun or merge artifact download occurred. The prospective-merge job's matching internal cause is not established by this head-only analysis.

The JSON report retains exact phase fields, source/blob references, artifact pins, and the distinction between actual native exits and wrapper rejection names. Connector response text is preserved verbatim in `connector-receipts`, including large integer fields; it is not parsed and reserialized as original evidence. One earlier direct-SSH capacity refusal is preserved and did not submit a child.
