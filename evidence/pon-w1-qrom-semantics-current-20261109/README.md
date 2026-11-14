# Current W1 semantics observation, 2026-11-09

Status: **fixed artifact observations reproduced; security HOLD**. This
successor records the current formal-workspace lock identity. The
[historical report](../pon-w1-qrom-semantics-20261107/report.json) remains
unchanged. The calculation implementation, fixed guest, upstream archives,
image, generated constraint data and qualification fields are unchanged.

## Exact observation and historical difference

[report.json](report.json) is the exact output observed from M10
[`b0c52dcae9c698e38b33a82d0200c0d8294f3ba1`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b0c52dcae9c698e38b33a82d0200c0d8294f3ba1),
tree `b9be79c712c5d1b4d496c28d506c6381498e03c3`, during the complete
named-control recovery on 2026-11-09. The report is 76,729 bytes, SHA256
`129e7b8bc1b6d34ef55acc25bd12cae273bdc65bdeee9649b1b43e214a4e9ebe`.
This successor fixture and its guard are added in a later child; they are
not represented as files already present in M10.

The original report was introduced in
[`5c3a3c5b54f43dd1c2005c2eb744e9bcbeba6794`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5c3a3c5b54f43dd1c2005c2eb744e9bcbeba6794).
Its 76,729 original bytes have SHA256
`66e017dfb3d58206c6372e6ba059ea7991ed7606dcd91e52dd63c73007d0f221`.
Fixed GitHub file reads independently matched that report and its lock
bytes to the corresponding Git blob identities.

The sole structured report difference is
`$.provenance.lock_checks[2].sha256`, for
`formal/pon-nakamoto-v1/w1_zkvm/Cargo.lock`:

| Observation | Lock bytes | Lock SHA256 |
| --- | ---: | --- |
| Original report revision `5c3a3c5b54f43dd1c2005c2eb744e9bcbeba6794` | 74,353 | `af7ee60b8f9f95c200d3dddac41b70c037e2bb3395122fe67ab20885140f247f` |
| Intermediate runtime revision `d3037ca5dfb6f301757c159b7888dca9b0317be0` | 74,364 | `173776355b019994c22b355aa22f8130b63b3a3c7ab7fba3d1e70af0a15d6a3f` |
| Integrated revision `bb424f5ce8cc9371e95ad5e8439e0ad5988bf8de`, also present at M8 and M10 | 74,379 | `ed6ea70f20cbe45bf0bdef7f841adbdaa7c3b2a9838ffdfed64fa88f129b707a` |

The final old-to-current lock diff adds `risc0-binfmt` and `sha2` to the
`trnm-w1-zk-methods-v2` dependency list. The intermediate runtime revision
also differed in `trnm-crypto`'s `serde_json` entry and the `zeroize` version;
the integrated revision restores those entries to the original report's
values. This report does not turn the lock comparison into a build or
runtime-equivalence claim.

The [current W1 implementation contract](../../config/pon/w1-qrom-implementation-current-v2.json)
already binds the current 74,379-byte lock in its reviewed local source
closure at M8 `189b9b5959d836ef6ae96e14fb285948e4920aa9`. Both M8 and M10
Git blobs match the integrated lock above. No mapping helper, proof
parameter, source-selection rule or calculation is changed by this
successor.

## Retained comparison and qualification boundaries

M10's complete named-control recovery ran all 105 required methods
successfully, including the 22 semantics controls, and its semantics CLI
completed successfully. The subsequent comparison against the historical
report failed because it strictly compared the older lock identity. That
failed comparison remains part of the M10 evidence; these observations do
not label the whole M10 workflow successful or supply missing hosted lanes.

The [closure workflow](../../.github/workflows/pon-w1-qrom-closure.yml)
now compares the complete generated semantics output to this successor.
Its generation command, all other comparisons, required stages and named
roster remain. The
[existing semantics controls](../../scripts/ci/test_w1_qrom_semantics_audit.py)
retain all 22 method names and prior assertions. The existing qualification
case additionally checks both report hashes, the complete current bytes,
rejection of the historical bytes as the current output, the sole
structured difference and the actual workflow comparison target.

The three true qualification fields remain limited to the fixed composite
binary-to-image recomputation, matching the embedded kernel to the locked
release binary and recomputing the fixed generated constraint degree
bound. All other qualification fields remain false, including fresh receipt
verification, compiler correctness, general parser equivalence, guest
source-to-binary reproduction, recursive program reproduction, all reachable
trace certification, the joint hash extraction theorem, the end-to-end QROM
bound and the quantum-resource-to-chain-weight correspondence. The
successor provides no deployment, consensus, service or model qualification.

```sh
python3 -B scripts/ci/test_w1_qrom_semantics_audit.py -v
python3 -B scripts/w1_qrom_semantics_audit.py --out /tmp/w1-semantics-current.json
cmp evidence/pon-w1-qrom-semantics-current-20261109/report.json /tmp/w1-semantics-current.json
```
