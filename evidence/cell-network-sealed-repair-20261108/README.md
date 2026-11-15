# Cell network, strong content, sealed loading and repair observations

This record follows the complete-version candidate at `0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a`. The measured implementation is commit **`09b584bea2e1a265a7e4be10c7aa98cf8e34629b`**, tree **`cef7243e5738a01465ce3930b2dd68f78c553dbe`**. An evidence-only follow-up does not change which implementation these results describe.

The work connects previously separate byte, transport, loader and repair components. **All six operational qualification axes remain `HOLD_NO_GO`.** No production activation, ordinary Hepta admission, payment, independent custody or WAN guarantee follows from these observations. This is an engineering evidence record; the [canonical development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) remains the sole plan.

## Problem and implemented boundaries

### Real peer transport and bounded discovery

The [TCP implementation](../../trillionnium/crates/trnm-data-availability/src/cell/bep52_peer.rs) adds native seed and consumer paths: BitTorrent handshake, peer-local BEP10 metadata IDs, BEP9 metadata exchange, correlated piece requests, and bounded BEP52 hash service. Metadata must match both the complete 32-byte infohash and the exact independently derived info dictionary. Successful acquisition requires actual complete CAS readback.

One non-cloneable session retains the original absolute deadline, connection/query allowance, message and socket-byte counters, cancellation and refusal history. Rejected and partial work remains charged. Cache hits, later peers and additional files do not renew the reservation.

The [DHT query](../../trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/dht.rs) sends one read-only `get_peers` request to one caller-approved IPv4 endpoint. Source/transaction correlation, bounded datagrams and candidate counts are checked. Returned endpoints are unauthenticated hints: there is no automatic follow-up, announcement, routing-table maintenance or insertion into authenticated discovery. See the [wire and accounting contract](../../docs/development/specs/pon/CELL_BEP52_PEER_V1.md). Local sockets do not establish public interoperability or WAN availability.

### Strong content before publication and at consumption

A SHA-512 envelope around SHA-256 leaves does not strengthen the underlying payload binding. [TCV2](../../trillionnium/crates/trnm-data-availability/src/cell/version_content.rs) therefore records domain-separated SHA-512 commitments computed from every actual chunk and complete payload, alongside the original full metadata. Existing TCM1 IDs remain CAS locators. [CPV4](../../trillionnium/crates/trnm-data-availability/src/cell/pq/content.rs) signs the new content commitment with native ML-DSA-65 and additionally binds the complete signer SPKI through SHA-512. This does not replace every legacy chain primitive or qualify whole-chain PQ128 security.

`pin_for_owner` creates a metadata view only after checking independent content and loader pins. `fetch_cell_bep52_with_content` requires this view, checks exact full manifest membership before admission, verifies cached and downloaded chunks before publication, and checks complete payload SHA-256/SHA-512 in the same final ordered readback. The legacy transport entry remains separate. A successful single-file fetch is not a complete-version or execution grant.

`verify_cached_at` verifies the CPV4 authority context and signature before a full model/environment scan. Failed admitted scans retain their original reservations. Current generation, withdrawal and use permission remain the execution owner's responsibility; an old expected view cannot prove current authority. Exact framing and rejection rules are in the [full-content contract](../../docs/development/specs/pon/CELL_FULL_CONTENT_V2.md).

### Same immutable objects reach the native reader

The [sealed loader](../../trillionnium/crates/trnm-data-availability/src/cell/residency/sealed_loader.rs) copies a complete admitted closure into Linux memfds, installs kernel write/size/execute seals, then rereads each actual sealed object and computes its full hashes. Exact declared path/role lookup has no ambient fallback. `verify_sealed_version` requires both model and environment scopes and compares their full declarations and post-seal SHA-512 values with TCV2.

The [native pipeline example](../../trillionnium/crates/trnm-data-availability/examples/cell_signed_sealed_pipeline_v1.rs) wires genuine signing, explicit TCP metadata/payload transfer, fresh consumer CAS, complete CPV4 readback, both sealed bundles and the existing strict safetensors reader. Its fixture is one synthetic `F32[8193]` tensor plus environment JSON. It retains the same typed content pin across both downloads and keeps signature-corruption and duplicate-model-scope refusals. Final execution status is recorded below; earlier-source successes are not substituted.

As detailed in the [loader contract](../../docs/development/specs/pon/CELL_SEALED_LOADER_V1.md), the copy budget is logical payload accounting, not total RSS or device reservation. Duplicated descriptors and mappings can outlive the bundle. This adapter does not sandbox arbitrary loader code or execute the declared environment.

### Recovery reaches actual CAS

[RS46 custody](../../trillionnium/crates/trnm-data-availability/src/cell/erasure/custody.rs) binds the original chunk and all six shard identities. Recovery records malformed/damaged slots, requires four verified shards, verifies the reconstructed source and re-encodes all six commitments. Declared placement IDs do not prove independent operators or failure domains.

`repair_chunk_to_cache` additionally reserves write/readback work, checks the recovered chunk against an independently pinned TCV2 record, writes through the ordinary CAS and strongly verifies actual readback under the original deadline. Only this path records cache recovery. It neither publishes a complete version nor stores replacement shards at six providers. Failed quota, pin, write or readback attempts retain admitted debits; a valid committed chunk need not disappear after a later failure. See the [repair contract](../../docs/development/specs/pon/CELL_RS46_CUSTODY_V1.md).

The standalone release [custody continuation planner](../../trillionnium/crates/trnm-data-availability/src/cell/custody.rs) now refuses observations that finished after their original deadline, matching the complete-version planner. A fresh admission is required before another probe; late component reports cannot become successful continuation plans. These controls do not create a repair daemon, durable payment or paid lease.

## Exact-source validation and retained failures

Use [final-summary.json](final-summary.json) for final command outcomes, [pipeline.json](pipeline.json) for the final pipeline observation, and [raw-manifest.json](raw-manifest.json) for hashes and member names in [raw-observations.tar.gz](raw-observations.tar.gz). Command receipts retain argv, source, environment, exit status and raw stdout/stderr. Development observations remain distinguishable from final-source evidence.

| Check on the measured source | Result |
| --- | --- |
| Complete `trnm-data-availability` native and doc tests | Exit 0; **539 native tests = 505 library + 34 CLI/integration**, plus **12 compile-fail doc tests**; zero failed, ignored or filtered |
| Workspace, all targets, all features, strict Clippy | Exit 0 with `-D warnings`; 87.28 seconds including checks/build |
| Release BEP52 and RS46 examples | Both exit 0; 15 and 12 local component observations respectively |
| Release signed/sealed pipeline | Exit 0; `PASS_COMPONENT_PIPELINE`, two actual TCP connections, 32,930 payload bytes / four chunks, both sealed scopes and the same native tensor reader |
| Canonical-plan and CI-contract controls, dedicated `TMPDIR` repeat | Same-source exit 0: 50 repository + 29 reference controls, then 108 CI-contract controls |
| Final source/tree recheck and remaining gates | All four raw source receipts identical: 16,812 tracked entries / 1,735,221,104 bytes; both locks and five provider inputs unchanged; three locked/offline graphs, source/PQ controls (43/37), vectors, links, inventory and formatting pass |

The first canonical-plan and CI-contract attempts **failed** when the shared `/tmp` filesystem exhausted space (`ENOSPC`). Their logs remain retained. The same commands subsequently passed on the same source SHA with a dedicated `TMPDIR`, without changing their assertions or timeouts. The initial run remains **22/24 successful commands, summary `FAIL`**; two successful replacement control receipts and the identical source guards are recorded separately. A later pass does not erase those failures or establish that the first run was entirely green. Earlier development pipeline outputs, including `signed-sealed-pipeline-02`, concern different source and cannot endorse this measured implementation.

## Six operational gates

| Axis | Component advance | Qualification still required |
| --- | --- | --- |
| TCM1/CAS | Actual strong content at ingress/readback | Sustained online availability and complete deployed security composition |
| Version/loader closure | Strong model/environment pair, same sealed reader objects | Versioned ordinary loader bridge and actual declared runtime use |
| BEP52 | Real TCP and one-hop read-only DHT query | Independent client interoperability, public discovery operation and WAN qualification |
| RS(6,4) | Damaged-shard recovery through actual CAS readback | Independent placement, provider shard writes, continuous repair and paid SLA |
| Retention/GC/custody | Original-deadline observation and continuation controls | Public independent custody, durable funding and long-term capacity |
| Scheduling/residency | Bounded RAM admission and sealed handoff | Physical NVMe/VRAM ownership and ordinary load/query/unload closure |

The [ordinary handoff](../../docs/development/specs/pon/CELL_ORDINARY_HOST_HANDOFF_V2.md) retains three concrete integration boundaries:

| Boundary | Required owner work |
| --- | --- |
| Schema and bytes | Existing `context.runtime` pins worker source; TCV2 pins environment closure. CPR2/TCR1 cannot silently become CPV4/TCV2. A versioned entry needs independent new pins and a descriptor adapter into the existing [checked-byte model loader](../../scripts/llm_base_material.py). |
| Ordinary authority | Real protected installed daemon, qualified descriptor, Fleet/current generation, resource grant, inference journal and FinalUse owner must admit the run. Existing [installed-host fixtures](../../scripts/ci/test_llm_cell_installed_host.py) prove argv/CLI/helper boundaries, not model admission. |
| Device and lifecycle | The present neural worker is explicitly CPU-only. Actual NVMe/VRAM reservation, real model Ready, authorized query and terminal resource reconciliation require their original owners and hardware. |

The example's 30-second reservation does not extend the ordinary 120-second preparation, 35-second transfer or 120-second startup contracts. Historical large cold-transfer failures retain their original identities. Synthetic tensor parsing, sealed FD consumption and repair readback are component observations; none is an ordinary Hepta end-to-end qualification.

## Historical roster identity

The current raw output retains all 462 native success names in the historical [six-capability observation](../cell-six-capabilities-20261108/README.md), with 77 added and none missing. The [roster audit](retained-test-roster.json) records its exact archive/member hashes. That historical log records measured source `bbe7f6fbed13450922a9bac49c0c5cfafcf3cf1e`, not this candidate base `0dc13a92…`; no historical execution is relabelled. The current 539 runtime and 12 doc tests were executed on `09b584be…`.

The final commit adds this evidence directory only. Its source guard is a delivery-identity check, not another execution of the runtime suite. The local results do not stand in for hosted exact-head/prospective-merge or additional architecture jobs.
