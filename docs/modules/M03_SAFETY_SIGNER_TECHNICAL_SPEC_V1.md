# M03 Work attempts, independent local effects and custody

Selected development target: `pon-nakamoto-v1`. Revision: executable-contract increment.
Actual source ownership: `config/portability-inventory-v1.json`; procedure registry:
[`module-contracts-v1.json`](../../config/pon/module-contracts-v1.json).
This module has detailed procedures and executable reference coverage, not an independently
accepted native product. The [sole plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
sets ordering. [STATE_RECOVERY.md](../protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md) defines exact shared rules.

## PoN Authority

Freeze all header bytes before work; evaluate full challenge transcript; retry a different nonce with a new computation; cap local reference attempts4096. Parent changes do not relabel an old transcript. Durable mining-attempt recovery is a native integration obligation, not implemented by the CLI.

This module cannot use a decoded JSON boolean, historical proof, local checkpoint or a
passing document check to grant work validity, model utility, local execution permission
or production activation. Every consumer must use the specific verified fact it needs.
Native component reuse and executable-contract integration are reported separately.

## PoN Interfaces

| Operation | Exact logical inputs | Output and authority boundary |
|---|---|---|
| `RunWorkAttempt` | frozen header,parent generation, task matrices, attempt budget | exact proof or explicit stale/cancelled attempt |
| `EnterExternalEffect` | operation32,payload32,local generation | unique entered fact or replay/revoke failure |

The named signatures define domain contracts. Source bindings below identify which are
implemented natively, in the executable Python specification, or only by reusable
components. The names do not assert matching deployed Rust service APIs.

## PoN State machine

### M03.RunWorkAttempt

Freeze all header bytes before work; evaluate full challenge transcript; retry a different nonce with a new computation; cap local reference attempts4096. Parent changes do not relabel an old transcript. Durable mining-attempt recovery is a native integration obligation, not implemented by the CLI.

**Commit point:** Reference mining is in-memory; no claim of durable miner. External publication uses exact idempotent BlockId.

**Rejections:** `WORK_BUDGET, REORG_IN_PROGRESS, FIELD`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

### M03.EnterExternalEffect

Check revocation; insert exact operation once into independent effects DB before actual dispatch. A reorg never deletes this record. Duplicate entry queries/reconciles target; it cannot dispatch again.

**Commit point:** Separate SQLite WAL FULL DB, PK operation; independent anchor not yet joined.

**Rejections:** `OPERATION_ALREADY_ENTERED, REVOKED`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

## PoN Persistence and recovery

**M03.RunWorkAttempt:** Reference mining is in-memory; no claim of durable miner. External publication uses exact idempotent BlockId.

**M03.EnterExternalEffect:** Separate SQLite WAL FULL DB, PK operation; independent anchor not yet joined.

Branch-derived entitlement can be detached. Independent local effect/revocation facts
cannot. See [the exact tables and eight crash cuts](../protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md).
A native implementation must reproduce byte/root/recovery vectors before replacing the
reference path. No old consensus namespace or decoder is restored.

## PoN Resource bounds

**M03.RunWorkAttempt:** 49188-byte result, bounded matrix sizes; no hidden success fallback.

**M03.EnterExternalEffect:** fixed operation and payload digests; one local owner.

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

```bash
python3 formal/pon-nakamoto-v1/test_contracts.py
CARGO_TARGET_DIR=/path/to/target TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_interop.py
```

Build native examples before the interop command; missing binaries cause failure, not
a skipped pass. Fixtures are never regenerated by test execution. Independently written
third-party vectors and acceptance remain future evidence, not an assumed status.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py)
- [`trillionnium/crates/trnm-checkpoint-types/src/record.rs`](../../trillionnium/crates/trnm-checkpoint-types/src/record.rs)
- Native reusable owner: `trnm-checkpoint-store`; run `cargo test --locked -p trnm-checkpoint-store --all-targets --all-features` from `trillionnium`.
- Native reusable owner: `trnm-checkpoint-types`; run `cargo test --locked -p trnm-checkpoint-types --all-targets --all-features` from `trillionnium`.

## Maturity and outstanding integration

Documented: yes. Executable contract: yes. Native component presence is enumerated above.
Native ordinary-product integration: no. Independent acceptance: no. Production activation:
no. Those axes are independent; a component-level pass does not promote the entire module.
