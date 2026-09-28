# M13 Validated replay, work history and bounded synchronization

Selected development target: `pon-nakamoto-v1`. Revision: executable-contract increment.
Actual source ownership: `config/portability-inventory-v1.json`; procedure registry:
[`module-contracts-v1.json`](../../config/pon/module-contracts-v1.json).
This module has detailed procedures and executable reference coverage, not an independently
accepted native product. The [sole plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
sets ordering. [STATE_RECOVERY.md](../protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md) defines exact shared rules.

## PoN Authority

Walk parent links to genesis within referencebound; replay sorted deltas verifying each before value and block root. Existing local authenticated storage is the premise; untrusted network imports must first pass full block admission.

This module cannot use a decoded JSON boolean, historical proof, local checkpoint or a
passing document check to grant work validity, model utility, local execution permission
or production activation. Every consumer must use the specific verified fact it needs.
Native component reuse and executable-contract integration are reported separately.

## PoN Interfaces

| Operation | Exact logical inputs | Output and authority boundary |
|---|---|---|
| `RebuildBranchState` | known genesis,retained block/delta ancestry,target | exact branch map/root or explicit failure |
| `VerifyIncomingHistory` | ordered block/certificate/tx stream,expectedgenesis | fully verified retained ancestry |

The named signatures define domain contracts. Source bindings below identify which are
implemented natively, in the executable Python specification, or only by reusable
components. The names do not assert matching deployed Rust service APIs.

## PoN State machine

### M13.RebuildBranchState

Walk parent links to genesis within referencebound; replay sorted deltas verifying each before value and block root. Existing local authenticated storage is the premise; untrusted network imports must first pass full block admission.

**Commit point:** Reconstructed state is checked before active publication; no unauthenticated snapshot trust.

**Rejections:** `UNKNOWN_PARENT, UNDO_ROOT, ROOT, LIMIT`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

### M13.VerifyIncomingHistory

For each block use M02 exact parent work and M06 state validation. Work matrices/certificate remain self-contained; model retention is separate. Never interpret a local checkpoint or old proof as a new finality certificate.

**Commit point:** Append valid branch rows/deltas only; incomplete import not active.

**Rejections:** `NETWORK, WORK, ROOT, UNKNOWN_PARENT`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

## PoN Persistence and recovery

**M13.RebuildBranchState:** Reconstructed state is checked before active publication; no unauthenticated snapshot trust.

**M13.VerifyIncomingHistory:** Append valid branch rows/deltas only; incomplete import not active.

Branch-derived entitlement can be detached. Independent local effect/revocation facts
cannot. See [the exact tables and eight crash cuts](../protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md).
A native implementation must reproduce byte/root/recovery vectors before replacing the
reference path. No old consensus namespace or decoder is restored.

## PoN Resource bounds

**M13.RebuildBranchState:** 4096reference ancestry; production streamingproofsync remains nativework.

**M13.VerifyIncomingHistory:** block1MiB; bounded proof jobs; no permanent pruning-depth fork rejection.

The [numeric devnet limits](../../config/pon/devnet-v1.json) are authenticated with the
work, model and ledger profile. Limit changes require a new context. Local backpressure
may reject service or defer data but cannot fabricate accepted block/evaluation facts.

## PoN Security

The full-recompute work verifier has measured cheap-forgery amplification and unaccepted
cost-hardness assumptions. Local model evaluations use controlled attestors and repeated
experimental partitions; they are not independent future-window evidence. SQLite process
crashes are not physical power-loss qualification. These limitations remain explicit in
[this acceptance contract](../protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md).

## PoN Verification and evidence

- `DiskReorgTests` in the conformance suite covers this module's stated scope; cross-module positive product behavior is exercised by the signed release/free-use experiment.
- `InteropTests` in the conformance suite covers this module's stated scope; cross-module positive product behavior is exercised by the signed release/free-use experiment.

```bash
python3 formal/pon-nakamoto-v1/test_contracts.py
CARGO_TARGET_DIR=/path/to/target TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_interop.py
```

Build native examples before the interop command; missing binaries cause failure, not
a skipped pass. Fixtures are never regenerated by test execution. Independently written
third-party vectors and acceptance remain future evidence, not an assumed status.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py)
- [`trillionnium/crates/trnm-state-import/src/lib.rs`](../../trillionnium/crates/trnm-state-import/src/lib.rs)
- Native reusable owner: `trnm-state-import`; run `cargo test --locked -p trnm-state-import --all-targets --all-features` from `trillionnium`.

## Maturity and outstanding integration

Documented: yes. Executable contract: yes. Native component presence is enumerated above.
Native ordinary-product integration: no. Independent acceptance: no. Production activation:
no. Those axes are independent; a component-level pass does not promote the entire module.
