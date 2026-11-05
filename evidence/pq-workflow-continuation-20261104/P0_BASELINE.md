# P0 source review baseline

## Final fixed-pair result (2026-11-05 UTC)

The selected code pair is **Chain `d9954903ef9239f71aa575ec3e6f4fdaa88f2d35` + Hepta runtime `484ce165522026d915c4cf526cd7df2effab632c`**. [Final frozen-source receipts](frozen-d9954903/README.md) record 47 source/recorder, 63 quantum-clock, 57 PQ and 4 native cache tests passing on the corrected immutable Chain commit; complete tracked-source checks cover 9,197 entries / 948,887,514 bytes before and after execution. The exact 464-pin / 6-upstream contract passes with **HOLD_NO_GO**. Runtime source and format checks pass; host native tests remain **NOT_RUN**. This documentation/evidence follow-up does not change the tested code pair. Complete engineering, original 4s/16, research, proof-benefit and independent-acceptance gates remain open.

The checkpoint-creation statements and earlier receipts below are historical to their explicitly named versions. The [inventory correction](inventory-correction/README.md) preserves the initial generated-file failure and its repair; the final results above were rerun on `d9954903ef9239f71aa575ec3e6f4fdaa88f2d35`.

Status: **partial source-baseline record; HOLD**. The reviewed source pair is Chain `d9954903ef9239f71aa575ec3e6f4fdaa88f2d35` and runtime `484ce165522026d915c4cf526cd7df2effab632c`. This does not declare a fully qualified deployment or close the complete authority-map requirement.

## Inputs and immutable identities

The code publication additionally preserves the incoming Growth composition at `38cf428103f48879fcc6b7dc0fc523d5c58ff2e0`. [PUBLICATION_SCOPE.md](PUBLICATION_SCOPE.md) distinguishes that frozen checkpoint from the earlier executed input below. Native validation of the new composition is pending at checkpoint creation.

| Repository | Implementation input before this continuation | Protected main observed |
| --- | --- | --- |
| Trillionnium-Chain | `38543c96cabb0d63a4a99d149a30a270d0c2c107`, Draft #688 | `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` |
| hepta-private-ci (Hepta runtime) | `5bf9e9eb7dc49ef56caf5143531f3a705fcd0e52`, Draft #4812 | `732e934ba496d90fbe042b8d41d479ef901643e5` |

The runtime output is `484ce165522026d915c4cf526cd7df2effab632c`, tree `87608a9448e8cbb90c448bf82a495db1dfd32a45`. Chain final input tree is `b02426da27aea65182e6e1240ed07b517780f025`. [source-files.json](final-composition/source-files.json) identifies every changed implementation/test/integration input. Use the final immutable commit URL and its tree for publication identity; a commit cannot embed its own hash.

Runtime #4812 targets the existing integration branch at `4c93a641945044f904a656cbf1d23e358a074d52`, not protected main. GitHub reported prospective merges `3cbc4263a42a8a7d89413240c150dea361265600` for the earlier `44ebe1a` Chain input and `4a1b6830707306d1603dd60f61c2b21f687664bc` for the old runtime input. Those are metadata observations, not executed test receipts; they are not the resulting source pair.

The Hepta language repository is a different repository from this runtime. Existing V8 receipts retain their historical source/profile scope, including their original Chain input `73ab6e9a83bcc836e261d93f9bb23ceafe556758`; they do not qualify this continuation's pair. No new competing execution profile is introduced here.

## Source-defined cryptographic assets

This inventories identifiable asset types and source owner roles. It does not inventory deployed private keys, key custody, hardware roots or administrative independence.

| Surface | Source-defined asset/profile | Boundary |
| --- | --- | --- |
| Canonical signature primitive | RustCrypto ML-DSA-65, pure-message signing, exact application domain in the message, canonical SPKI and pinned key ID | A valid signature does not grant account role, funds, nonce, CURRENT or FinalUse. OpenSSL differential material is not a fallback acceptance path. |
| Chain account/task and transport identities | NPQ6/PQP6 application authorization, current account generations/retirement; separate PNQ2 peer/server pins, generations, sequence and expiry | Application authorization and transport authentication remain separate. The explicit local-development transport is signed plaintext. |
| Release/activation roots | Pinned offline quorum and separate NodeSoftware, ProtocolConfiguration, CellManifest and CellActivation roles | A release observation is not model acceptance, durable installation, FinalUse or consensus activation. |
| Runtime effect authority | ml_dsa65_v2 issuer/revocation rings, protected clock/frontier keys and separately reviewed approval authority | Distinct public keys and endpoint paths do not prove independent operators or custody; a fresh observation does not make provider execution one distributed transaction. |
| Hash/work relationships | Domain-separated key IDs and payload commitments; native PNW1 transcript/ticket relationship under the selected work profile | The work profile remains experimental; production eligibility and external hardness acceptance remain false. |

Source owners: [PQ primitive](../../trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs), [PQ frame](../../trillionnium/crates/trnm-protocol/src/pq_frame.rs), [Application V6](../../docs/security/PQ_APPLICATION_AUTHORIZATION_V6.md), [release/recovery boundaries](../../docs/security/PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md), [work profile](../../config/pon/work-profile-v1.json), and [runtime FinalUse contract](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/484ce165522026d915c4cf526cd7df2effab632c/codex-rs/hepta-contracts/PQ_FINAL_USE.md).

## Partial ordinary authority call map

These are inspected source edges, not an exhaustive dynamic call graph.

| Entry | Observed owner sequence | Boundary |
| --- | --- | --- |
| Chain PQ application | settings-selected native Application V6 → selected packet profile → prepare_signature_metered → current-key resolve → reserved verification attempt → canonical verify_tpq1 → original M06 apply | State/context/generation/nonce/money transitions remain application-owner duties; a prepared signature is not commit permission. |
| PNQ2 request | PqServer::handle → verify_request_metered → durable begin_pq_network_request_with_check → original dispatch/W1/execution controls → retained completion | Signed transport does not supply chainwork or replace application authority. |
| Ordinary runtime FinalUse | UnixFinalUseAuthorizer::open → required ml_dsa65_v2 → from_pq_config → canonical role pins and external clock/frontier → durable PQ authority → claim_exact_pq → FinalUseAuthority::claim; effect entry checks ensure_current_effect_state | Missing/classical ordinary configuration is refused. Frontier-observation/provider-effect coordination still requires acceptance. |
| Release bundle | Pinned root owner → current-role signature/quorum checks → accept_bundle / accept → versioned release observation | Durable installer integration, independent recovery expectation and actual CURRENT/FinalUse use must be traced separately. |

Source owners: [authority audit](../../docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md), [application settings](../../trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs), [PQ account owner](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs), [application checks](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6.rs), [transport owner](../../trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs), [release owner](../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs), and [runtime authorizer](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/484ce165522026d915c4cf526cd7df2effab632c/codex-rs/hepta-infer-worker-host/src/final_use_authorizer.rs).

The complete map across CURRENT installation, alternate clients, CLI/bootstrap/recovery, governance, provider dispatch and historical constructors remains open. In particular, the native GrowthV2 public constructor still refuses PQ identity composition; the cache-owner fix does not change that authorization boundary.

## Configuration and performance scope

The existing source-controlled [performance contract](../../config/pon/performance-six-axis-v1.json), [transition profile](../../config/pon/post-quantum-transition-v1.json) and [work profile](../../config/pon/work-profile-v1.json) remain unchanged. Original 4-second/16-hostile-producer criteria and all specified subconditions are preserved.

This record does not demonstrate a single deployed combination of network/genesis, application/work/evaluation/model settings, actual authority rings, runtime config, binaries, provider identity and quotas. The native cache tests use local compilation settings documented in their receipt and are not a performance campaign.

The [verification table](README.md#actual-verification-on-the-recorded-38543c96-composition) records 47 source/record, 63 quantum, 57 PQ and four actual native cache tests passing. Source coverage and negative-claim controls do not establish live-flow coverage or deployed security. All six whole-chain PQ qualification domains remain UNQUALIFIED under the existing [claim guard](../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md).
