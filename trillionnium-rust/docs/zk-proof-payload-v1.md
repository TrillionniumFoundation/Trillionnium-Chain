# TRNM ZK Proof Payload / Public Input Spec

> 兼容指针文档：字段级协议真相源已迁移到仓库级协议文档，避免与架构文档/实现说明形成双真相源。

Canonical protocol source:

- `docs/protocol/zk-proof-payload-public-input-v0.md`

Related platform architecture:

- `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`

Current canonical payload schema token used by router / backend tests / docs:

- `trnm.zk.payload.v0`

This file remains only as a compatibility pointer for older references that may still mention
“zk proof payload v1”. When payload shape, `public_inputs` ordering, `vk_ref`, `zk_system`, or
backend-router contract questions arise, use the protocol document above as the single truth
source and treat `trnm.zk.payload.v0` as the active canonical schema identifier.
