# M17 Reproducible evidence and semantic contract checks

Selected development target: `pon-nakamoto-v1`. Revision: executable-contract increment.
Actual source ownership: `config/portability-inventory-v1.json`; procedure registry:
[`module-contracts-v1.json`](../../config/pon/module-contracts-v1.json).
This module has detailed procedures and executable reference coverage, not an independently
accepted native product. The [sole plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
sets ordering. [PERFORMANCE_ACCEPTANCE.md](../protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md) defines exact shared rules.

## PoN Authority

Require all18 modules, nonplaceholder procedures, complete typedinputs/output/preconditions/commit/errors/limits and existing source/tests. Run positive/negative vectors and actual tests separately; file existence is never runtime evidence.

This module cannot use a decoded JSON boolean, historical proof, local checkpoint or a
passing document check to grant work validity, model utility, local execution permission
or production activation. Every consumer must use the specific verified fact it needs.
Native component reuse and executable-contract integration are reported separately.

## PoN Interfaces

| Operation | Exact logical inputs | Output and authority boundary |
|---|---|---|
| `CheckDetailedContracts` | closedmodule registry,codecs,source/testreferences | structural/algorithmcoverage result, not acceptance |
| `QualifyExecutedCampaign` | exactsource/configdigests,rawtimings,outcomes,environment | scoped pass/failure report |

The named signatures define domain contracts. Source bindings below identify which are
implemented natively, in the executable Python specification, or only by reusable
components. The names do not assert matching deployed Rust service APIs.

## PoN State machine

### M17.CheckDetailedContracts

Require all18 modules, nonplaceholder procedures, complete typedinputs/output/preconditions/commit/errors/limits and existing source/tests. Run positive/negative vectors and actual tests separately; file existence is never runtime evidence.

**Commit point:** Read-only checker; no evidence outcome mutation.

**Rejections:** `SCHEMA, SOURCE, PLACEHOLDER, COVERAGE`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

### M17.QualifyExecutedCampaign

Keep workcost, invalidproofamplification, diskprocesscrashes, localhostnetwork, actuallearning andreward evidence separate. Retainfailedobservations; requireexternal revieweridentity for independentacceptance, never substitute authoredsubprocesses.

**Commit point:** Immutable evidence artifact manifest; cannot enableproduction.

**Rejections:** `EVIDENCE, CONTEXT, MISSING_CAMPAIGN`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

## PoN Persistence and recovery

**M17.CheckDetailedContracts:** Read-only checker; no evidence outcome mutation.

**M17.QualifyExecutedCampaign:** Immutable evidence artifact manifest; cannot enableproduction.

Branch-derived entitlement can be detached. Independent local effect/revocation facts
cannot. See [the exact tables and eight crash cuts](../protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md).
A native implementation must reproduce byte/root/recovery vectors before replacing the
reference path. No old consensus namespace or decoder is restored.

## PoN Resource bounds

**M17.CheckDetailedContracts:** fixed18modules; preserveblankrootREADME.

**M17.QualifyExecutedCampaign:** no all-green fabricated row; no throughput extrapolation.

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

- `CodecTests` in the conformance suite covers this module's stated scope; cross-module positive product behavior is exercised by the signed release/free-use experiment.
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

- [`formal/pon-nakamoto-v1/test_contracts.py`](../../formal/pon-nakamoto-v1/test_contracts.py)
- [`formal/pon-nakamoto-v1/test_interop.py`](../../formal/pon-nakamoto-v1/test_interop.py)
- Native reusable owner: `trnm-bench`; run `cargo test --locked -p trnm-bench --all-targets --all-features` from `trillionnium`.
- Native reusable owner: `trnm-audit-events`; run `cargo test --locked -p trnm-audit-events --all-targets --all-features` from `trillionnium`.

## Maturity and outstanding integration

Documented: yes. Executable contract: yes. Native component presence is enumerated above.
Native ordinary-product integration: no. Independent acceptance: no. Production activation:
no. Those axes are independent; a component-level pass does not promote the entire module.
