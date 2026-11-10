# Current W1 lifetime ledger observation, 2026-11-10

Status: **selected source identities and conditional arithmetic reproduced; security HOLD**.

The selected code checkpoint is [`8d8c0e64e7a301fc111a6720721a14816639e5aa`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/8d8c0e64e7a301fc111a6720721a14816639e5aa), tree `7c003a3d183ad33ff4f3349cbcce61564f73a2ba`. All twenty selected Git blobs were compared with regular working files before rebinding. Within that roster only `trillionnium/crates/trnm-pon-node/src/store.rs` changes, to SHA256 `e43ba6ea4775b5256a95781fcc3dbb1dd9c359900fc91263f3e8cd2844cf43bd`. Its added retained-chainwork and readback consistency checks do not establish cheapest legal work cost, a QROM reduction, public-prefix security, or confirmation failure probabilities.

The [ledger](../../scripts/w1_lifetime_ledger.py), binding controls and this report are in a later child of the code checkpoint. This field does not claim they existed in that checkpoint or identify a newly executed binary. Native execution receipts have their own source and binary identities.

The [input](project-input.json) is byte-identical to the [previous unknown input](../pon-w1-lifetime-current-20261109/project-input.json): 6107 bytes, SHA256 `a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89`. The [report](project-report.json) is 31311 bytes, SHA256 `10038c7b28384995e9bca883b010a1699b89d7d757067fbeeca409f30a197537`. Only its selected source survey differs from the previous report. Lifetime arithmetic, counterexamples and all three independent acceptance objects are equal. Project lifetime queries, failure probability and target comparison remain null; all qualification and production activation fields remain false.

The [2026-11-09 report](../pon-w1-lifetime-current-20261109/project-report.json) and [original 2026-11-07 report](../pon-w1-lifetime-20261107/project-report.json) retain their original bytes. The same nineteen named ledger controls and original acceptance conditions remain required. Test results and hosted completion are recorded separately; creating this report does not count as passing them.

```sh
python3 -B scripts/ci/test_w1_lifetime_ledger.py -v
python3 -B scripts/w1_lifetime_ledger.py --input evidence/pon-w1-lifetime-current-20261110-685a/project-input.json
```
