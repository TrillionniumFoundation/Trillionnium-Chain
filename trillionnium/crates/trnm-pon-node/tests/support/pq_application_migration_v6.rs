//! Public deterministic research keys and an explicitly trusted checkpoint.
//! The synthetic source below proves neither source work/finality nor prior
//! registration timing. Only destination blocks use the real Node/W1 owner.
use serde_json::json;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_mvcc_fee::pon_executor::{self as exec, pq_accounts_v2 as pq, Config, State};
use trnm_pon_node::{ingress::pq_network::PqNetworkPolicy, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{Hash, Header},
    pq_frame::ml_dsa_65_key_id_from_spki,
    pq_native_accounts_v2::{self as wire, AccountProfile},
};
use zeroize::Zeroizing;

pub const OWNER: Hash = [201; 32];
pub const PROVIDER: Hash = [202; 32];
pub const TASK: Hash = [207; 32];
pub const REWARD: Hash = [208; 32];

pub fn row(prefix: &str, id: Hash) -> String {
    format!("{prefix}:{}", hex::encode(id))
}

pub fn key(seed: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([seed; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqNativeSigningKey::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&spki).unwrap()).unwrap()
}

pub fn signed(
    profile: AccountProfile,
    common: &wire::Common,
    kind: u8,
    payload: &[u8],
    witnesses: &[(&PqNativeSigningKey, u8, u64, bool)],
) -> Vec<u8> {
    let descriptors: Vec<_> = witnesses
        .iter()
        .map(|(key, role, generation, carried)| wire::WitnessKey {
            role: *role,
            generation: *generation,
            key_id: key.public_key_id(),
            spki: carried.then(|| key.public_spki().to_vec()),
        })
        .collect();
    let frames: Vec<_> = witnesses
        .iter()
        .enumerate()
        .map(|(index, (key, _, _, _))| {
            let statement = wire::signing_statement_for_profile(
                profile,
                common,
                kind,
                payload,
                &descriptors,
                index,
            )
            .unwrap();
            let signature = key.sign_exact_message(&statement).unwrap();
            let mut frame = statement.to_vec();
            frame.extend((signature.len() as u16).to_be_bytes());
            frame.extend(signature);
            frame
        })
        .collect();
    wire::encode_for_profile(profile, common, kind, payload, &descriptors, &frames).unwrap()
}

pub struct Fixture {
    pub cfg: Config,
    pub settings: Settings,
    pub policy: PqNetworkPolicy,
    pub initial: State,
    pub prior: PqNativeSigningKey,
    pub next: PqNativeSigningKey,
    pub rotated: PqNativeSigningKey,
    pub miner: Hash,
}

impl Fixture {
    pub fn new() -> Self {
        let prior = key(231);
        let provider = key(232);
        let next = key(233);
        let rotated = key(234);
        let seeded = [key(235), key(236)];
        let source_cfg = Config::installed().unwrap();
        let state = State::from([
            ("meta:issued".into(), json!(20_010_123)),
            ("model:current".into(), json!(hex::encode([0; 32]))),
            (
                row("account", OWNER),
                json!({"balance":10_000_000,"nonce":7}),
            ),
            (
                row("account", PROVIDER),
                json!({"balance":10_000_000,"nonce":3}),
            ),
            (
                row("task", TASK),
                json!({"owner":hex::encode(OWNER),"provider":hex::encode(PROVIDER),
                "remaining":10_000,"deadline":30,"status":"reserved","output":null}),
            ),
            (
                row("reward", REWARD),
                json!({"owner":hex::encode(PROVIDER),"amount":123,"maturity":17}),
            ),
        ]);
        let material = pq::CheckpointMaterial {
            genesis: [209; 32],
            header: Header {
                network: source_cfg.network,
                parameters: source_cfg.parameters,
                parent: [210; 32],
                height: 10,
                timestamp: 1200,
                target: [255; 32],
                miner: OWNER,
                transactions: [0; 32],
                state: exec::root_for_config(&state, &source_cfg).unwrap(),
                receipts: [0; 32],
                work_task: [211; 32],
                nonce: 0,
            },
            trace: [212; 32],
            state,
        };
        let registry = pq::TrustedPqPrecommitments::pin(
            source_cfg.network,
            material.genesis,
            &[(OWNER, &prior), (PROVIDER, &provider)].map(|(source_account, key)| {
                pq::PrecommittedAccount {
                    source_account,
                    spki: key.public_spki().to_vec(),
                    generation: 9,
                }
            }),
        )
        .unwrap();
        let checkpoint = material.header.block_id(material.trace);
        let anchor = registry
            .pin_checkpoint(checkpoint, material, &source_cfg)
            .unwrap();
        let accounts: Vec<_> = seeded
            .iter()
            .map(|key| pq::GenesisAccount {
                spki: key.public_spki().to_vec(),
                balance: 10_000_000,
            })
            .collect();
        let application = pq::application_v6::ApplicationPolicy {
            evaluators: seeded
                .iter()
                .map(PqNativeSigningKey::public_key_id)
                .collect(),
            evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
            model_profile: "linear-expert-dev-v1".into(),
        };
        let (cfg, initial, genesis) = pq::application_v6::genesis_with_trusted_migration(
            &accounts,
            1500,
            anchor.clone(),
            &application,
        )
        .unwrap();
        let settings = Settings::native_pq_application_v6_with_migration(
            &accounts,
            1500,
            anchor,
            &application,
        )
        .unwrap();
        assert_eq!(
            (
                settings.network(),
                settings.parameters(),
                settings.genesis()
            ),
            (cfg.network, cfg.parameters, genesis)
        );
        let policy = PqNetworkPolicy::new(
            &settings,
            key(237).public_spki(),
            1,
            [key(238).public_spki().to_vec()],
        )
        .unwrap();
        Self {
            cfg,
            settings,
            policy,
            initial,
            prior,
            next,
            rotated,
            miner: seeded[0].public_key_id(),
        }
    }

    pub fn common(&self, nonce: u64, generation: u64) -> wire::Common {
        wire::Common {
            context: pq::context(&self.cfg).unwrap(),
            account: OWNER,
            nonce,
            expires_at: 2000,
            max_fee: 100_000,
            generation,
        }
    }

    pub fn claim(&self, profile: AccountProfile) -> Vec<u8> {
        signed(
            profile,
            &self.common(8, 0),
            wire::CLAIM,
            &pq::migration_claim_payload(&self.cfg, OWNER).unwrap(),
            &[(&self.prior, 5, 9, false), (&self.next, 6, 1, true)],
        )
    }

    pub fn command(
        &self,
        key: &PqNativeSigningKey,
        generation: u64,
        nonce: u64,
        kind: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        signed(
            AccountProfile::ApplicationV6,
            &self.common(nonce, generation),
            kind,
            payload,
            &[(key, 1, generation, false)],
        )
    }

    pub fn append(&self, node: &mut Node, rows: Vec<Vec<u8>>) -> State {
        let parent = node.active().unwrap().0;
        let height = node.parent_height(parent).unwrap() + 1;
        let packet = node
            .make_consensus_maintenance(parent, rows, self.miner, 1500 + height * 10, 4096)
            .unwrap();
        let raw = packet.encode_for_settings(&self.settings).unwrap();
        assert!(raw.starts_with(b"PQP6\x06"));
        let packet = Packet::decode_for_settings(&raw, &self.settings).unwrap();
        let id = node.admit(&packet, 2000).unwrap();
        node.activate(id).unwrap();
        let state = node.state_at(id).unwrap();
        assert_eq!(
            self.settings.state_root(&state).unwrap(),
            packet.header.state
        );
        state
    }

    pub fn refuses(&self, node: &Node, raw: Vec<u8>, expected: &str) {
        let active = node.active().unwrap();
        let state = node.state_at(active.0).unwrap();
        let height = node.parent_height(active.0).unwrap() + 1;
        let error = node
            .make_consensus_maintenance(active.0, vec![raw], self.miner, 1500 + height * 10, 4096)
            .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "expected {expected}, got {error}"
        );
        assert_eq!(node.active().unwrap(), active);
        assert_eq!(node.state_at(active.0).unwrap(), state);
    }
}
