# Next Hepta owner bindings v1

Status: source and regression map, frozen for the 2026-11-08 qualification
candidate. Cross-repository ordinary-task integration remains **HOLD**. This
document changes no protocol, signed domain, stored schema, admission rule or
chainwork. It records executable receiving boundaries and the responsibilities
that remain with their original Hepta owners.

The governing product boundary is
[HEPTA_HANDOFF](../../../protocol/pon-nakamoto-v1/details/HEPTA_HANDOFF.md), with
the release and runtime-adoption responsibilities in
[MODEL_COMMONS L5/L7](../../../protocol/pon-nakamoto-v1/MODEL_COMMONS.md).
The sole implementation plan remains the
[development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Source-to-owner map

Paths below identify this repository's actual code. A receiving API or local
observation is not evidence that an external owner invokes it in an ordinary
task. Historical external-source inspections recorded in HEPTA_HANDOFF retain
their original dates and pins; they are not execution receipts for the current
pair of repositories.

| Boundary | Actual local source and entry | Original external owner responsibility |
| --- | --- | --- |
| Learning artifact admission | [research-protocol/hepta_handoff.rs](../../../../trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs): `HeptaArtifactAdmissionV1`, `SignedHeptaAdmissionV1::from_canonical_bytes`, `SignedHeptaAdmissionV1::verify_for_context` | The learning-artifact/withdrawal owner supplies a fresh complete expected admission. The original operation journal supplies the destination chain. Check operation, artifact, owner admission, family/parent generation, withdrawal/registry heads, evaluation plan, task/export scope, payload and validity window as one context. The received envelope cannot supply its own expected facts. |
| PQ artifact admission | [research-protocol/hepta_handoff/pq.rs](../../../../trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs): `SignedHeptaAdmissionV2::decode_untrusted`, `verify_for_context`, `PqHeptaAuthoritySetV2` | The original authority and artifact owners supply current external pins, generation/revocation and expected owner facts. Bounded parsing and a valid PQ signature do not establish currentness, FinalUse or a full-chain PQ128 claim. |
| Native evaluation lifecycle | [mvcc-fee/public_evaluation.rs](../../../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs): `freeze`, `commit`, `reveal`, `close_with_disqualified`, `adoption_allowed_with_disqualified`, `appeal`, `conflict`; invoked by [pon_executor.rs](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs) | The real evaluation owner supplies frozen parent/candidate/controls, authorized task bytes and exposure, actual training/forward results, budgets and valid role claims. Preserve selected/no-update/invalid/unknown outcomes. Signed native scoring and closure do not establish scientific quality or independent custody. |
| Current evaluation observation | [node/store/evaluation_observation.rs](../../../../trillionnium/crates/trnm-pon-node/src/store/evaluation_observation.rs): `Node::evaluation_observation`, `check_evaluation_observation`; [evaluation_round_observation.rs](../../../../trillionnium/crates/trnm-pon-node/src/store/evaluation_round_observation.rs): `evaluation_round_observation`, `check_evaluation_round_observation` | The existing operations/session owner retains and reconciles the observation lifecycle. Re-observe after extension/reorg and before current-view reuse. These APIs check actual state, membership, installed work/depth policy and tip/generation; they grant no adoption, reward, execution or finality authority. |
| Exact effect reconciliation | [node/main.rs](../../../../trillionnium/crates/trnm-pon-node/src/main.rs): `submit` and `packet-status` dispatch; [store/packet_observation.rs](../../../../trillionnium/crates/trnm-pon-node/src/store/packet_observation.rs): `observe_existing_packet`; [store.rs](../../../../trillionnium/crates/trnm-pon-node/src/store.rs): `Node::exact_packet_observation` | Original TaskFlow/kernel.operations persists effect identity and exact bytes before contact, then queries that identity after lost ACK or Unknown. Local absence is not global non-execution. Reorg removes branch entitlement without deleting terminal local facts or authorizing re-signing/re-dispatch. |
| Accepted task binding | [node/store/task_observation.rs](../../../../trillionnium/crates/trnm-pon-node/src/store/task_observation.rs): `accepted_task_observation`, `accepted_task_from_working`; internal `unique_acceptance`, `accepted_task_in_state` | The M14 consumer matches task, owner, provider, output, acceptance transaction, exact packet, chain context and confirmation policy against its own facts. Local code checks the selected wire identity, unique acceptance, transaction root and current settled state. An optional observed binding is not an execution token. |
| Peer transport outbox | [node/ingress.rs](../../../../trillionnium/crates/trnm-pon-node/src/ingress.rs): `call_authenticated_durable`, `call_authenticated_durable_protected`; [store.rs](../../../../trillionnium/crates/trnm-pon-node/src/store.rs): `authenticated_outbound_reservation`, `reserve_authenticated_outbound`, `finish_authenticated_outbound`, `validate_authenticated_outbox` | Hepta's business-effect owner remains responsible for its own durable intent and reconciliation. The node outbox persists exact signed network bytes before I/O and advances the nonce only on a verified terminal response; it is a transport replay owner, not a replacement kernel.operations ledger. |
| Complete release bytes | [cell/closure.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/closure.rs): `CellReleaseClosureV1::verify_for_loader`, `CellLoaderContextV1`; [cell/model_root.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/model_root.rs): `CellModelReleaseRootV1::verify_parent_roots`, `verify_for_loader` | The original release/selection owner independently pins closure, context, selected generation, loader profile, required roles and original resource budget. Discovery and provider-supplied manifests cannot choose those expectations or grant use. |
| Local residency and runtime admission | [cell/residency.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/residency.rs): `CellResidencyV1::prefetch`, `prepare_cached`, `select_local`, `with_local`, `with_selected` | Existing artifact/selection/resource/FinalUse owners recheck current signed head, withdrawal, local generation, resources and tensor readback immediately before admission. They drain in-flight work, admit the new runtime generation and record the model/input/output actually used. `select_local` only updates a process-local byte-selection hint; callback execution and authority remain with its caller. |

The local Rust source exposes the handoff types and tests, but this inspection
found no production node caller of `SignedHeptaAdmissionV1` or
`SignedHeptaAdmissionV2`. It also found no local implementation of
`LearningArtifactOwnerService`, `EvaluationOwner`,
`VerifiedArtifactSelectionV1` or `FinalUseAuthority`.

HEPTA_HANDOFF records the external
`codex-rs/hepta-learning-artifacts/src/owner_service.rs::LearningArtifactOwnerService::publish`
at historical source `a126987b84737dbc2ee2592442a314117bddb4a2`, together with
the existing artifact, withdrawal and selection types. Its publication receipt
with `DENY_ALL` posture does not grant export or FinalUse. Its later TaskFlow and
compiled `AgentdAutomationEffectHost` inspections identify existing owners to
connect; this source map does not assert that those external revisions were
rebuilt, executed or paired with the present Chain source.

## Unfrozen observation-version contract

The inspected `Node::exact_packet_observation` implementation currently emits
`pon-native-exact-packet-observation-v3`, with optional `accepted_task` whose
nested `schema_version` is `1`. In contrast, the later M14 table in
HEPTA_HANDOFF requires a current schema-4 observation and says legacy schema 3
cannot satisfy accepted-task binding. This is an unresolved document/code and
cross-repository compatibility boundary.

This map does not rename v3, declare schema 4 implemented, or permit a consumer
to accept v3 where its existing contract requires schema 4. Presence of the
optional object does not resolve that requirement. The paired producer and
consumer must freeze the exact version and field semantics, missing/unknown
field behavior, canonical vectors and compatibility tests before ordinary-task
integration is qualified. Missing task binding cannot be inferred from packet
presence, height or a positive confirmation flag.

## Cold observation scope

The packet-status cold observer operates on an existing closed native namespace
and returns observation data. It must not submit, recover/activate an admitted
packet, create another operation ledger or turn local absence into permission
to replay an effect. Its source-copy and owner-integrity boundary is specified
in [NATIVE_PACKET_STATUS_OBSERVATION_V1](NATIVE_PACKET_STATUS_OBSERVATION_V1.md).

This property does **not** apply to `evaluation-observe` or
`evaluation-round-observe`. Those commands retain normal exclusive `Node::open`
and recovery, which can create a store or write recovery/checkpoint metadata.
Their exact scopes remain in
[confirmed-chain observation v1](../../../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_OBSERVATION_V1.md)
and
[confirmed-round observation v2](../../../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md).
Neither is an OS read-only opener.

## Thirteen retained receiver/task regressions

These are executable selectors, not a statement that this documentation change
ran or passed them. Record results against the exact qualified source. They
exercise local receiving boundaries and do not certify the external Hepta
ordinary-task path, independent evaluators, Runtime FinalUse or full-chain PQ128.

Run from the repository root:

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol --test protocol_v1 hepta_
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol --test hepta_handoff_pq
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::task_observation::tests::
```

The first selector retains four tests in
[protocol_v1.rs](../../../../trillionnium/crates/trnm-research-protocol/tests/protocol_v1.rs):

- `hepta_admission_requires_owner_facts_and_authority`
- `hepta_admission_rejects_missing_parent_and_unbounded_payload`
- `hepta_handoff_rechecks_the_destination_and_fresh_owner_snapshot`
- `hepta_handoff_limits_wire_before_decode_and_requires_its_signature_domain`

The second retains six tests in
[hepta_handoff_pq.rs](../../../../trillionnium/crates/trnm-research-protocol/tests/hepta_handoff_pq.rs):

- `real_pq_signature_and_bounded_canonical_wire_round_trip`
- `no_classical_signature_or_algorithm_negotiation_is_accepted`
- `pin_lifetime_generation_and_revocation_are_freshly_enforced`
- `one_pq_signing_key_cannot_claim_multiple_independent_dids`
- `chain_and_fresh_hepta_owner_context_cannot_be_reused`
- `malformed_oversize_noncanonical_and_extra_bytes_fail_before_authorization`

The third retains three tests in the existing `task_observation.rs` module:

- `configured_profiles_decode_transfers_acceptances_and_reject_foreign_or_malformed_bytes`
- `every_native_profile_observes_real_settlement_with_its_exact_wire_id`
- `legacy_selection_and_ambiguity_keep_the_original_codec_order`

## Packet-status compatibility regressions

The adjacent retained tests remain distinct from the thirteen tests above and
from the new cold-observer regression file:

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_node test_packet_status_
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_node test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner
```

The packet selector runs
`test_packet_status_non_tip_height_and_512_bit_work_match_one_active_ancestry`
and
`test_packet_status_observes_exact_durable_packet_without_replaying_or_creating_store`
in [native_node.rs](../../../../trillionnium/crates/trnm-pon-node/tests/native_node.rs).
Their retained transfer fixture does not cover accepted-task binding; that is
why the three task-observation regressions remain a separate qualification
input. The outbox selector tests one durable peer-transport owner, not external
kernel.operations execution.

The existing four-test
[native settlement integration target](../../../../trillionnium/crates/trnm-pon-node/tests/accepted_task_observation.rs)
supplies an additional direct compatibility check:

```bash
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test accepted_task_observation
```

Its `exact_acceptance_survives_restart_and_cli_readback_without_mutation` case
uses the original reserve/provider-receipt/owner-accept transactions. For both
Legacy and AuthenticatedV1, it compares complete live, cold API and CLI JSON,
including all eight fields of a nonempty `accepted_task`, and checks source
file bytes and identity without opening the source in SQLite. The output
digest remains an explicit fixture binding. This is real native settlement
readback, not evidence of an actual delivered model or external FinalUse.

The remaining product completion requires actual fresh facts from the original
artifact/evaluation/operations/runtime owners, a frozen paired-version contract,
and the next ordinary task's actual loaded-model/generation readback. No local
PASS in this map can substitute for that evidence or create a second owner.
