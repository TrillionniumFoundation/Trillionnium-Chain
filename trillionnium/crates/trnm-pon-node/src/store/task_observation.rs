//! Bind an exact retained acceptance packet to the current task settlement.
//! This is a local, generation-scoped observation, never execution authority.
use super::Node;
use crate::{ensure, sequence_root, Error, Packet, Result, Settings};
use serde::Serialize;
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2, State};
use trnm_protocol::pon_wire::{Envelope, Hash};
use trnm_protocol::pq_native_accounts_v2::UnverifiedEnvelope;

#[derive(Serialize)]
pub(super) struct AcceptedTaskObservation {
    schema_version: u32,
    task_id: String,
    owner: String,
    provider: String,
    output_sha256: String,
    accept_tx_id: String,
    accepted_in_exact_packet: bool,
    current_status: &'static str,
}

/// Decoding preserves the selected wire and its identity; it supplies no new
/// signature or execution authority. Callers already checked packet retention.
#[derive(Debug)]
enum AcceptanceEnvelope<'a> {
    Legacy(Envelope),
    NativePq(UnverifiedEnvelope<'a>),
}

impl AcceptanceEnvelope<'_> {
    fn tag(&self) -> u8 {
        match self {
            Self::Legacy(tx) => tx.tag,
            Self::NativePq(tx) => tx.kind,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Legacy(tx) => &tx.payload,
            Self::NativePq(tx) => tx.payload,
        }
    }

    fn sender(&self) -> Hash {
        match self {
            Self::Legacy(tx) => tx.sender,
            Self::NativePq(tx) => tx.common.account,
        }
    }

    fn matches_context(&self, settings: &Settings) -> Result<bool> {
        Ok(match self {
            Self::Legacy(tx) => tx.network == settings.network(),
            Self::NativePq(tx) => {
                tx.common.context
                    == pq_accounts_v2::context(&settings.app)
                        .map_err(|error| Error::from(error).local_integrity())?
            }
        })
    }

    fn id(&self) -> Result<Hash> {
        match self {
            Self::Legacy(tx) => tx
                .id()
                .map_err(|_| Error::from("TRANSACTION_CODEC").local_integrity()),
            // This is the exact signed-wire ID used by the native M06 receipt,
            // not a legacy tx-id or the signature-independent statement ID.
            Self::NativePq(tx) => Ok(tx.wire_id()),
        }
    }
}

fn unique_acceptance<'a>(
    transactions: &'a [Vec<u8>],
    settings: &Settings,
) -> Result<Option<AcceptanceEnvelope<'a>>> {
    let profile = if pq_accounts_v2::enabled(&settings.app) {
        Some(
            pq_accounts_v2::account_profile(&settings.app)
                .map_err(|error| Error::from(error).local_integrity())?,
        )
    } else {
        None
    };
    let mut acceptance = None;
    for raw in transactions {
        let tx = match profile {
            Some(profile) => AcceptanceEnvelope::NativePq(
                UnverifiedEnvelope::decode_for_profile(raw, profile)
                    .map_err(|_| Error::from("TRANSACTION_CODEC").local_integrity())?,
            ),
            None => AcceptanceEnvelope::Legacy(
                Envelope::decode(raw)
                    .map_err(|_| Error::from("TRANSACTION_CODEC").local_integrity())?,
            ),
        };
        if tx.tag() == 5 {
            // This legacy convenience type names only customer acceptance.
            // Frozen arbitrator decisions use the native payment/evidence owner.
            if tx.payload().len() != 64 {
                return Ok(None);
            }
            // A multi-accept block cannot name one unambiguous upgrade in this
            // optional convenience observation.
            if acceptance.is_some() {
                return Ok(None);
            }
            acceptance = Some(tx);
        }
    }
    Ok(acceptance)
}

impl Node {
    pub(super) fn accepted_task_observation(
        &self,
        packet: &Packet,
        tip: Hash,
        generation: u64,
    ) -> Result<Option<AcceptedTaskObservation>> {
        ensure(
            packet.header.transactions == sequence_root("transactions", &packet.transactions),
            "ROOT",
        )
        .map_err(Error::local_integrity)?;
        let Some(tx) = unique_acceptance(&packet.transactions, &self.settings)? else {
            return Ok(None);
        };
        let (state_tip, state_generation, state) = self.read_active()?;
        ensure(
            (tip, generation) == (state_tip, state_generation),
            "STALE_VIEW",
        )?;
        self.accepted_task_in_state(&tx, &state)
    }

    /// The growth observer has already checked the exact retained transition
    /// and obtains this working partition from its active read snapshot.
    pub(super) fn accepted_task_from_working(
        &self,
        transactions: &[Vec<u8>],
        working: &State,
    ) -> Result<Option<AcceptedTaskObservation>> {
        let Some(tx) = unique_acceptance(transactions, &self.settings)? else {
            return Ok(None);
        };
        self.accepted_task_in_state(&tx, working)
    }

    fn accepted_task_in_state(
        &self,
        tx: &AcceptanceEnvelope<'_>,
        state: &State,
    ) -> Result<Option<AcceptedTaskObservation>> {
        let task_id = hex::encode(&tx.payload()[..32]);
        let Some(task) = state.get(&format!("task:{task_id}")) else {
            // An expired/pruned local record is not a current settlement proof.
            return Ok(None);
        };
        let owner = hex::encode(tx.sender());
        let output_sha256 = hex::encode(&tx.payload()[32..]);
        let provider = task["provider"]
            .as_str()
            .ok_or_else(|| Error::from("TASK_OBSERVATION_STATE").local_integrity())?;
        let provider_key = crate::digest(provider).map_err(Error::local_integrity)?;
        ensure(
            tx.matches_context(&self.settings)?
                && task["owner"] == owner
                && task["output"] == output_sha256
                && task["status"] == "settled"
                && task["remaining"] == 0
                && provider == hex::encode(provider_key),
            "TASK_OBSERVATION_STATE",
        )
        .map_err(Error::local_integrity)?;
        Ok(Some(AcceptedTaskObservation {
            schema_version: 1,
            task_id,
            owner,
            provider: provider.to_owned(),
            output_sha256,
            accept_tx_id: hex::encode(tx.id()?),
            accepted_in_exact_packet: true,
            current_status: "settled",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::pq_network::{canonical_tests::key, PqNetworkPolicy};
    use serde_json::{json, Value};
    use std::collections::BTreeSet;
    use trnm_mvcc_fee::pon_executor::{self, BlockExecution};
    use trnm_protocol::{
        pon_wire::hash,
        pq_frame::PqFrameExpectation,
        pq_native_accounts_v2::{self as wire, AccountProfile, Common},
    };

    const PROFILES: [AccountProfile; 5] = [
        AccountProfile::AccountsV2,
        AccountProfile::QuotaV3,
        AccountProfile::TasksV4,
        AccountProfile::TasksV5,
        AccountProfile::ApplicationV6,
    ];

    fn settings(profile: AccountProfile) -> Settings {
        let accounts: Vec<_> = [1, 2, 3]
            .into_iter()
            .map(|seed| pq_accounts_v2::GenesisAccount {
                spki: key(seed).public_spki().to_vec(),
                balance: 1_000_000_000,
            })
            .collect();
        let (app, initial, genesis) = match profile {
            AccountProfile::AccountsV2 => pq_accounts_v2::genesis(&accounts, 1000),
            AccountProfile::QuotaV3 => pq_accounts_v2::genesis_quota_v3(&accounts, 1000),
            AccountProfile::TasksV4 => pq_accounts_v2::genesis_tasks_v4(&accounts, 1000),
            AccountProfile::TasksV5 => pq_accounts_v2::genesis_tasks_v5(&accounts, 1000),
            AccountProfile::ApplicationV6 => pq_accounts_v2::application_v6::genesis(
                &accounts,
                1000,
                &pq_accounts_v2::application_v6::ApplicationPolicy {
                    evaluators: BTreeSet::from([key(2).public_key_id(), key(3).public_key_id()]),
                    evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
                    model_profile: "linear-expert-dev-v1".into(),
                },
            ),
        }
        .unwrap();
        Settings {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        }
    }

    fn common(settings: &Settings, seed: u8, nonce: u64) -> Common {
        Common {
            context: pq_accounts_v2::context(&settings.app).unwrap(),
            account: key(seed).public_key_id(),
            nonce,
            expires_at: 1200,
            max_fee: 100_000,
            generation: 1,
        }
    }

    fn signed(
        profile: AccountProfile,
        common: Common,
        seed: u8,
        kind: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let signer = key(seed);
        let witnesses = [wire::WitnessKey {
            role: 1,
            generation: common.generation,
            key_id: signer.public_key_id(),
            spki: None,
        }];
        let core =
            wire::signing_core_for_profile(profile, &common, kind, payload, &witnesses).unwrap();
        let statement =
            wire::signing_statement_for_profile(profile, &common, kind, payload, &witnesses, 0)
                .unwrap();
        let frame = signer
            .sign_statement(
                &statement,
                &PqFrameExpectation {
                    purpose: 1,
                    network: common.context.network,
                    owner_context: wire::owner_context_for_profile(profile, &common, kind, 1)
                        .unwrap(),
                    signer_key_id: signer.public_key_id(),
                    owner_generation: common.generation,
                    operation_sequence: common.nonce,
                    expires_at: common.expires_at,
                    now: 1000,
                    payload: &core,
                },
            )
            .unwrap();
        wire::encode_for_profile(
            profile,
            &common,
            kind,
            payload,
            &witnesses,
            &[frame.to_vec()],
        )
        .unwrap()
    }

    fn codec_error(transactions: &[Vec<u8>], settings: &Settings) {
        let error = unique_acceptance(transactions, settings).unwrap_err();
        assert_eq!(error.to_string(), "TRANSACTION_CODEC");
        assert_eq!(error.kind(), crate::ErrorKind::LocalStructure);
        assert!(error.requires_owner_stop());
    }

    #[test]
    fn configured_profiles_decode_transfers_acceptances_and_reject_foreign_or_malformed_bytes() {
        let configurations: Vec<_> = PROFILES.into_iter().map(settings).collect();
        let legacy = Settings::development(None).unwrap();
        for (profile, settings) in PROFILES.into_iter().zip(&configurations) {
            let transfer = signed(
                profile,
                common(settings, 1, 1),
                1,
                1,
                &[
                    key(2).public_key_id().as_slice(),
                    &42_u64.to_le_bytes(),
                    &[0; 2],
                ]
                .concat(),
            );
            assert!(unique_acceptance(std::slice::from_ref(&transfer), settings)
                .unwrap()
                .is_none());
            let acceptance = signed(profile, common(settings, 1, 1), 1, 5, &[9; 64]);
            let transactions = [acceptance.clone()];
            let observed = unique_acceptance(&transactions, settings).unwrap().unwrap();
            assert!(matches!(observed, AcceptanceEnvelope::NativePq(_)));
            assert_eq!(observed.sender(), key(1).public_key_id());
            assert_eq!(observed.payload(), &[9; 64]);
            assert!(observed.matches_context(settings).unwrap());
            let exact = UnverifiedEnvelope::decode_for_profile(&acceptance, profile).unwrap();
            assert_eq!(observed.id().unwrap(), exact.wire_id());
            assert_ne!(observed.id().unwrap(), hash(b"tx-id", &[&acceptance]));
            for (other_profile, other_settings) in PROFILES.into_iter().zip(&configurations) {
                if profile != other_profile {
                    codec_error(std::slice::from_ref(&transfer), other_settings);
                    codec_error(&transactions, other_settings);
                }
            }
            codec_error(&transactions, &legacy);
            codec_error(&[acceptance[..acceptance.len() - 1].to_vec()], settings);
            let mut malformed_payload = transfer.clone();
            malformed_payload[5] = 5; // The transfer's 42-byte payload is not an acceptance.
            codec_error(&[malformed_payload], settings);
            let mut wrong_statement = acceptance.clone();
            wrong_statement[wire::PREFIX_BYTES + wire::COMMON_BYTES] ^= 1;
            codec_error(&[wrong_statement], settings);
            codec_error(&[transfer, vec![0]], settings);
            codec_error(&[acceptance.clone(), vec![0], acceptance.clone()], settings);
            // Preserve the original optional-observer ordering: the second
            // acceptance establishes ambiguity before a later decode is tried.
            assert!(
                unique_acceptance(&[acceptance.clone(), acceptance, vec![0]], settings)
                    .unwrap()
                    .is_none()
            );
        }
        let mut unconfigured = legacy;
        unconfigured.app.params["native_pq_accounts_profile"] =
            json!(AccountProfile::ApplicationV6.name());
        let error = unique_acceptance(&[], &unconfigured).unwrap_err();
        assert_eq!(error.to_string(), "PQ2_PROFILE_REQUIRED");
        assert_eq!(error.kind(), crate::ErrorKind::LocalStructure);
        assert!(error.requires_owner_stop());
    }

    #[test]
    fn every_native_profile_observes_real_settlement_with_its_exact_wire_id() {
        for profile in PROFILES {
            let settings = settings(profile);
            let policy = PqNetworkPolicy::new(
                &settings,
                key(71).public_spki(),
                1,
                [key(72).public_spki().to_vec()],
            )
            .unwrap();
            let directory = tempfile::tempdir().unwrap();
            let node =
                Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
            let owner = key(1).public_key_id();
            let provider = key(2).public_key_id();
            let budget = 1000_u64;
            let deadline = 100_u64;
            let task = hash(
                b"task-instance-v3",
                &[
                    &settings.network(),
                    &settings.parameters(),
                    &owner,
                    &1_u64.to_le_bytes(),
                    &provider,
                    &budget.to_le_bytes(),
                    &deadline.to_le_bytes(),
                ],
            );
            let output = [9; 32];
            let reserve = [
                task.as_slice(),
                &provider,
                &budget.to_le_bytes(),
                &deadline.to_le_bytes(),
            ]
            .concat();
            let receipt = [task.as_slice(), &output].concat();
            let transactions = vec![
                signed(profile, common(&settings, 1, 1), 1, 2, &reserve),
                signed(profile, common(&settings, 2, 1), 2, 4, &receipt),
                signed(profile, common(&settings, 1, 2), 1, 5, &receipt),
            ];
            // Real ML-DSA verification and the original M06 task owner settle
            // the task. A hand-built settled row would not prove this path.
            let executed = pon_executor::execute_with_progress(
                &settings.initial,
                BlockExecution {
                    timestamp: Some(1001),
                    transactions: &transactions,
                    height: 1,
                    miner: owner,
                    parent_id: settings.genesis(),
                    workers: 1,
                },
                &settings.app,
                &|_| Ok::<(), &'static str>(()),
            )
            .unwrap();
            let observed = node
                .accepted_task_from_working(&transactions, &executed.state)
                .unwrap()
                .unwrap();
            let accept_id = UnverifiedEnvelope::decode_for_profile(&transactions[2], profile)
                .unwrap()
                .wire_id();
            assert_eq!(
                serde_json::to_value(observed).unwrap(),
                json!({
                    "schema_version": 1,
                    "task_id": hex::encode(task),
                    "owner": hex::encode(owner),
                    "provider": hex::encode(provider),
                    "output_sha256": hex::encode(output),
                    "accept_tx_id": hex::encode(accept_id),
                    "accepted_in_exact_packet": true,
                    "current_status": "settled",
                })
            );
            assert!(node
                .accepted_task_from_working(&transactions, &settings.initial)
                .unwrap()
                .is_none());
            assert!(node
                .accepted_task_from_working(&transactions[..2], &executed.state)
                .unwrap()
                .is_none());

            for component in 0..3 {
                let mut foreign = common(&settings, 1, 2);
                match component {
                    0 => foreign.context.network[0] ^= 1,
                    1 => foreign.context.parameters[0] ^= 1,
                    _ => foreign.context.genesis[0] ^= 1,
                }
                let foreign = vec![signed(profile, foreign, 1, 5, &receipt)];
                let error = node
                    .accepted_task_from_working(&foreign, &executed.state)
                    .err()
                    .unwrap();
                assert_eq!(error.to_string(), "TASK_OBSERVATION_STATE");
                assert!(error.requires_owner_stop());
                assert!(node
                    .accepted_task_from_working(&foreign, &settings.initial)
                    .unwrap()
                    .is_none());
            }
            for (field, value) in [
                ("owner", json!(hex::encode(provider))),
                ("output", json!("ff".repeat(32))),
                ("status", json!("receipt")),
                ("remaining", json!(1)),
                ("provider", Value::Null),
            ] {
                let mut altered = executed.state.clone();
                altered
                    .get_mut(&format!("task:{}", hex::encode(task)))
                    .unwrap()[field] = value;
                let error = node
                    .accepted_task_from_working(&transactions, &altered)
                    .err()
                    .unwrap();
                assert_eq!(error.to_string(), "TASK_OBSERVATION_STATE");
                assert!(error.requires_owner_stop());
            }
        }
    }

    #[test]
    fn legacy_selection_and_ambiguity_keep_the_original_codec_order() {
        let settings = Settings::development(None).unwrap();
        let acceptance = Envelope {
            network: settings.network(),
            sender: crate::development_public(0).unwrap(),
            nonce: 1,
            expiry: 100,
            fee_limit: 100_000,
            tag: 5,
            payload: vec![9; 64],
            signature: [0; 64],
        }
        .encode()
        .unwrap();
        // Codec-only control. This deliberately unsigned envelope is never
        // admitted, executed or presented as a settlement observation.
        let transactions = [acceptance.clone()];
        let observed = unique_acceptance(&transactions, &settings)
            .unwrap()
            .unwrap();
        assert!(matches!(observed, AcceptanceEnvelope::Legacy(_)));
        assert_eq!(observed.id().unwrap(), hash(b"tx-id", &[&acceptance]));
        let pq_settings = self::settings(AccountProfile::ApplicationV6);
        codec_error(&transactions, &pq_settings);
        codec_error(
            &[acceptance.clone(), vec![0], acceptance.clone()],
            &settings,
        );
        assert!(
            unique_acceptance(&[acceptance.clone(), acceptance, vec![0]], &settings)
                .unwrap()
                .is_none()
        );
    }
}
