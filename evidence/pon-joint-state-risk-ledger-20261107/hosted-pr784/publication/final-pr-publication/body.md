## Why

The work and native-execution certificate obligations need explicit evidence for initial information, the full population of confirmation events, and durable repeated-start accounting. Signatures, locally consistent journals, and ideal query bounds alone do not establish the actual physical security claim.

This PR adds three checkable components and retains their refusal cases. **Both actual certificates remain HOLD; the native six-successor failure probability remains `null`.**

## Changes

- **FJS1:** checks a complete finite classical/quantum joint initial state with exact rational PSD witnesses and a reference-state domination bound `P(E) <= min(1, lambda * B_ref + epsilon)`. Full oracle tables, priors and counterfactual query caps are required. A selected-start conditioning claim is refused.
- **EC1:** derives every confirmation and subsequent observe/select cut from each leaf of an explicit finite execution law. It rejects omitted repeated opportunities and covers transient remove/restore histories. Two opportunities of probability 1/16 have exact union 31/256, so checking only one opportunity is unsound.
- **PNRL1:** durably registers and charges starts before native dispatch, keeps failed/interrupted/unresolved starts charged, and independently joins all original native confirmation intents. Reopening preserves pending starts without inventing an old result.
- Corrects a reproduced native-prefix acceptance bug: an extra pending start at an already ended lease previously changed 8 starts / expenditure 36 into 9 / 37. Both Rust and Python now require an idle, non-stopped prefix in the same native epoch and reject the identical forged bank.
- Preserves lifecycle query accounting, owner-journal observations, actual ML-DSA-65 packet/signature composition, and earlier failed observations. A bank-only rollback before native dispatch still needs an externally retained newer checkpoint to be detected.
- Merges the current integration branch normally, retaining all 32 incoming commits and both parents' controls, including the incoming Cell checks. No force push or main-branch change is involved.

## Exact source and validation

Published head: `b5c655ebe9611b3d62cf739e61e6867decc053e3`.

Native and model executions are bound to merge `2d46d8682201bc0619f5b156af50e77fb399322e` (tree `5ae5317304588cca8295a19dd512c8e853f1ef5b`). Its ordered parents are `b66e66d2465258d808c0f56ff851123306d4bdb4` and integration head `cb314bb4656e5da4844325cd83994ab4764fe8e9`. The final commit only retains evidence: **all 2,415 non-evidence paths have identical type, mode and blob to that tested merge**.

| Validation on the tested merge | Result |
| --- | --- |
| Locked/offline Cargo graph; whole-workspace formatting | PASS |
| Strict Clippy: library, four retained targets, two native examples | PASS, warnings denied |
| Rust Cell / owner journal / owner observation / risk ledger | 12 / 10 / 10 / 11 passed |
| New owner and risk standalone scenarios | Both exit 0; real child interruption paths exercised |
| Independent owner / risk readers | 21 / 25 passed |
| Exact raw packet/signature composition | 16 passed, six journals, real ML-DSA-65 signatures |
| Finite joint state / complete event coverage / lifecycle query | 34 / 21 / 26 passed |
| CI source integrity / execution / command-contract negatives | 43 / 77 / 108 passed |
| Inventory, invariants, detailed contracts, applicability, current implementation | Original validators passed |

Suite invocation counts overlap (CI execution imports source-integrity tests); no deduplicated grand total is claimed. The two Rust child helpers excluded from ordinary discovery are invoked by their parent tests.

The fresh risk run contains 8 registered starts, 7 native confirmation intents, 6 outcomes and 2 unresolved starts, with 36 of 40 declared budget units spent and denominator 1,000. **36/1,000 is expenditure, not a certified failure probability.** The 58 packet artifacts across six journals are not a distinct-work count.

The final published commit also passes the independent Git-tree Markdown gate: all **613 actual Markdown blobs**, **4,232 local links**, zero errors, unchanged HEAD and clean status at both endpoints. It uses the same verifier whose 12 negative controls already passed.

## Coverage limits

- The complete local `check_repository` gate passed on earlier `b66`; that is not a complete repository-truth pass for this merge.
- The merged sparse checkout had 12,646 historical evidence paths unmaterialized at its recorded lane audit. The original source guard was not relaxed, and no placeholders were created. Thirteen real Git blobs were fetched and object-ID verified for the original detailed-contract and applicability validators.
- The final Markdown check reads the complete committed tree but is not an execution of `check_repository`; fragment anchors and reference-style links are outside its reviewed parser scope.
- Hosted baseline status must be read from the checks for this published head. This PR does not pre-claim full hosted CI, whole-workspace runtime, production-host, release, or production qualification.
- Actual joint initial-state attestation, all-channel help completeness, all-algorithm physical resource bounds, actual view/time/adoptability coverage, hidden inventory, the actual joint law with honest progress, and the final common-law security reduction remain open.

## Review evidence

- [Final merged-source gate summary and raw evidence](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/evidence/pon-joint-state-risk-ledger-20261107/final-source-gates/README.md)
- [Machine-readable validation and explicit HOLD fields](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/evidence/pon-joint-state-risk-ledger-20261107/final-source-gates/summary.json)
- [FJS1 specification](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/formal/pon-nakamoto-v1/FINITE_JOINT_STATE_CERTIFICATE_V1.md)
- [EC1 specification](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/formal/pon-nakamoto-v1/CERTIFICATE_EVENT_COVERAGE_V1.md)
- [PNRL1 specification](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/formal/pon-nakamoto-v1/NATIVE_RISK_LEDGER_V1.md)
