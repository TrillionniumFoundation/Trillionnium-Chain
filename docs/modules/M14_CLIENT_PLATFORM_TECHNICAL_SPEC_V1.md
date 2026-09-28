# M14 Client currentness, model loading and user results

Selected development target: `pon-nakamoto-v1`. Revision: executable-contract increment.
Actual source ownership: `config/portability-inventory-v1.json`; procedure registry:
[`module-contracts-v1.json`](../../config/pon/module-contracts-v1.json).
This module has detailed procedures and executable reference coverage, not an independently
accepted native product. The [sole plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
sets ordering. [NETWORK_CLIENT.md](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md) defines exact shared rules.

## PoN Authority

Read active pointer and generation kv in one snapshot and recompute root; return no unconditional finalized flag. A production confirmation adds depth/work evidence and freshness; localhost ACK is not independent proof.

This module cannot use a decoded JSON boolean, historical proof, local checkpoint or a
passing document check to grant work validity, model utility, local execution permission
or production activation. Every consumer must use the specific verified fact it needs.
Native component reuse and executable-contract integration are reported separately.

## PoN Interfaces

| Operation | Exact logical inputs | Output and authority boundary |
|---|---|---|
| `QueryCurrentState` | active generation and optional event cursor | tip,root,generation and branch-relative status |
| `ConsumePublishedModel` | expectedartifact/family,quota,input,local permission | bound inference result and optional signedusage receipt |

The named signatures define domain contracts. Source bindings below identify which are
implemented natively, in the executable Python specification, or only by reusable
components. The names do not assert matching deployed Rust service APIs.

## PoN State machine

### M14.QueryCurrentState

Read active pointer and generation kv in one snapshot and recompute root; return no unconditional finalized flag. A production confirmation adds depth/work evidence and freshness; localhost ACK is not independent proof.

**Commit point:** Indexer is derived; cursor(generation,ordinal), no new balanceauthority.

**Rejections:** `ROOT, UNAVAILABLE`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

### M14.ConsumePublishedModel

Fetch exact canonical artifact, check all fields/shapes; execute integer router/base/expert; persist actual model/request identity before usage settlement. No data export follows automatically from free usage.

**Commit point:** Local modelgeneration and effect owner remain Hepta responsibilities.

**Rejections:** `FAMILY, SHAPE, ARTIFACT_CANONICAL_BYTES, SIGNATURE`. Failure does not silently downgrade to a weaker proof or
convert an uncertain external outcome into not-executed.

## PoN Persistence and recovery

**M14.QueryCurrentState:** Indexer is derived; cursor(generation,ordinal), no new balanceauthority.

**M14.ConsumePublishedModel:** Local modelgeneration and effect owner remain Hepta responsibilities.

Branch-derived entitlement can be detached. Independent local effect/revocation facts
cannot. See [the exact tables and eight crash cuts](../protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md).
A native implementation must reproduce byte/root/recovery vectors before replacing the
reference path. No old consensus namespace or decoder is restored.

## PoN Resource bounds

**M14.QueryCurrentState:** responsebounded; socket10seconds in executableharness.

**M14.ConsumePublishedModel:** 65536artifactbytes experimental; no reducedmodel hidden behind fullprofile.

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
- `ExecutionTests` in the conformance suite covers this module's stated scope; cross-module positive product behavior is exercised by the signed release/free-use experiment.

```bash
python3 formal/pon-nakamoto-v1/test_contracts.py
CARGO_TARGET_DIR=/path/to/target TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_interop.py
```

Build native examples before the interop command; missing binaries cause failure, not
a skipped pass. Fixtures are never regenerated by test execution. Independently written
third-party vectors and acceptance remain future evidence, not an assumed status.

## Current source and verification

- [`formal/pon-nakamoto-v1/experiments/model_loop.py`](../../formal/pon-nakamoto-v1/experiments/model_loop.py)
- [`formal/pon-nakamoto-v1/experiments/local_network.py`](../../formal/pon-nakamoto-v1/experiments/local_network.py)

No native product package is implemented for this owner. The executable specification
is the shared design oracle; do not report it as an installed production node.

## Maturity and outstanding integration

Documented: yes. Executable contract: yes. Native component presence is enumerated above.
Native ordinary-product integration: no. Independent acceptance: no. Production activation:
no. Those axes are independent; a component-level pass does not promote the entire module.
