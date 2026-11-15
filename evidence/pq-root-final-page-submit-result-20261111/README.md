# Original PQ Root baseline final-page activation — diagnostic, HOLD

This is an independent **read of original native artifact bytes**, not a new
campaign, a pass, or a causal performance proof. The source under test is
`6c35f94d9387fac41c1547f05742d70150320b2e`, tree
`11bffc8135e49f3c3e86ff384e25ec2a7b3a4ba7`, from
[Actions 42983166696](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42983166696)
(artifact `13838364210`). The original ZIP SHA-256 was independently read as
`8fae87e2740750f94ae3a6f62ca5ceff4af978d56e283b8ab8c96f11a09f5b8e`.
The archive contains `1,765` source-bound payload files; their existing
manifest/hash checks remain separate from this diagnostic.

The exact **three raw reports**, consumed without a changed workload:

| Run | original report SHA-256 | seventh import wall | seventh `submit_result` wall / thread CPU | one-packet length (hex chars) |
| --- | --- | ---: | ---: | ---: |
| 1 | `c07d59b2b83387320b5321fb5c367c3bdc43941ad3ef964950b3596b74ab6d08` | 8.912 s | 6.491 s / 1.448 s | 99,016 |
| 2 | `10294d23078b6cfe669e1f2c46863ac2edb8a53b2fcc6b59c916fe01b85784a9` | 9.099 s | 6.519 s / 1.474 s | 99,016 |
| 3 | `00c29f2f91eba8f438d75b90d318f1a88dbc37311d282f9b834778957aa4808a` | 8.993 s | 6.500 s / 1.454 s | 99,016 |

**New bounded finding:** in all three baseline reports, the first six
History pages have `complete=false` and the native `submit_result`
span is **not entered**. The seventh has `complete=true`, exactly **one**
packet of the **same 99,016 hex characters as page six**, and a completed,
accepted `submit_result` span. Thus the ~9 s seventh import cannot be
explained solely by the size or count of its returned packet. The observed
`submit_result` interval is 6.49–6.52 s wall, ~1.45–1.47 s calling-thread
CPU. This is **nested inside** `history_import`; do not add it to import
time or the Host checkpoint subtotal. The first six import wall times are
approximately 2.42–2.99 s each. The seventh-page transition remains a
**hypothesis for controlled source profiling**, not permission to remove
verification, resource checks or effect settlement.

The new `final_history_page_activation` diagnostic in
`scripts/ci/inspect_native_campaign_failure.py` reports this pattern only
when all seven pages, unique native stage observations, boolean completion
flags and measured CPU/wall values are present. Missing, malformed or
duplicate observations stay `unknown`. The unit tests include negative
controls for altered completion, duplicate stages, missing pages, bogus
flags and packet count. All original acceptance flags are unchanged.

**Next controlled engineering gate:** trace `submit_result` through
original native activation/publish/readback (including the fresh Host check
budget), hold the same 30 s × 0/24/24 attacker schedule, 21 business
blocks, fixed 0.25 core / 2 GiB and all signed-confirmation criteria, and
compare exact tree/whole-binary identities. Any improvement must rerun the
three original native campaigns and independent receipt/History checks.

`original_native_campaign=0/3`; `qualification=HOLD_NO_GO`;
`authority=DENY_ALL`; external independent Root custody, fresh anchor,
real M15/FinalUse provider settlement, versioned migration, and eight-domain
actual lifetime cryptographic bound remain **not qualified**.
