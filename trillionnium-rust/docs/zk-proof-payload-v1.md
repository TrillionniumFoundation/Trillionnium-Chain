# TRNM ZK Proof Payload / Public Input Spec

> 兼容指针文档：字段级协议真相源已迁移到仓库级协议文档，避免与架构文档/实现说明形成双真相源。

Canonical protocol source:

- `docs/protocol/zk-proof-payload-public-input-v0.md`

Related platform architecture:

- `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`

Current canonical payload schema token used by router / backend tests / docs:

- `trnm.zk.payload.v0`

Current canonical payload proof byte encoding field used by router / backend tests / docs:

- `proof_encoding` (`hex | base64`)
- `proof_encoding` is required in `trnm.zk.payload.v0`; the router must fail closed on omission rather than defaulting silently to `base64`
- `proof_encoding` literals are lowercase canonical tokens in v0; non-canonical spellings such as `HEX` must fail closed rather than being normalized implicitly

Additional v0 parser / router contract reminders already enforced by tests and code:

- `vk_ref` is required, case-sensitive as an opaque verifier reference, and must not rely on silent surrounding-whitespace trimming.
- `backend_id`, when present, must be a non-empty canonical token without surrounding whitespace.
- `backend_version`, when present, must be a non-empty canonical token without surrounding whitespace and must not appear without `backend_id`.
- If a payload `backend_id` token carries canonical zk-system hints, all distinct hints must collapse to exactly one canonical system before routing; repeated identical hints (for example `groth16-groth16-demo`) are tolerated, but mixed hints (for example `groth16-plonk-demo`) must fail closed rather than being routed opportunistically.
- Family-only router tokens are not canonical payload selectors: a payload `backend_id` like `zk`, `zk-demo`, or other explicit `zk-*` family-only token without a canonical zk-system hint must be rejected as malformed rather than routed or treated as an implicit backend alias.
- The same fail-closed vk/system consistency applies to the router-selected backend token, not just the payload field: an explicitly tee-family backend token on the ZK path must be rejected, a family-only `zk` / `zk-*` router token without a canonical zk-system hint must be rejected as malformed rather than treated as an implicit backend alias, repeated identical zk-system hints may be deduplicated, and mixed canonical system hints must fail closed rather than being guessed through.

v0 fail-closed boundary reminder:

- The current router/parser only accepts canonical `zk_system` tokens `groth16 | plonk | halo2 | stark | risc0 | sp1`.
- Future custom namespaces such as `custom:<org>:<system>` remain documentation-only extension placeholders until a later schema/version explicitly enables them.
- In v0, payloads that try to use those custom namespaces must still be rejected as malformed rather than being normalized or routed opportunistically.

This file remains only as a compatibility pointer for older references that may still mention
“zk proof payload v1”. When payload shape, `public_inputs` ordering, `vk_ref`, `zk_system`, or
backend-router contract questions arise, use the protocol document above as the single truth
source and treat `trnm.zk.payload.v0` as the active canonical schema identifier.
