//! Permissionless retrieval and consumption of the existing genesis task.
//! No source signature, private key, service allowlist or expiring lease is
//! required. This is explicitly maintenance with zero useful-output credit;
//! it does not manufacture neural demand or a new consensus work relation.
use crate::{ensure, Node, Packet, Result, Settings};
use serde::{Deserialize, Serialize};
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::Hash;

pub const SCHEMA: &str = "pon-public-genesis-task-bootstrap-v1";
pub const MAX_BOOTSTRAP_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTaskBootstrap {
    pub schema: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub work_profile: String,
    pub task_profile: String,
    pub matrix_task: String,
    pub model: String,
    pub input: String,
    pub purpose: String,
    pub useful_output_credit: u64,
    pub hardness_accepted: bool,
}

impl Settings {
    pub fn public_task_bootstrap(&self) -> Result<PublicTaskBootstrap> {
        let (model, input, a, b) = self.consensus_maintenance_material()?;
        Ok(PublicTaskBootstrap {
            schema: SCHEMA.into(),
            network: hex::encode(self.network()),
            parameters: hex::encode(self.parameters()),
            genesis: hex::encode(self.genesis()),
            work_profile: pon_work::PROFILE.into(),
            task_profile: self.task_profile().into(),
            matrix_task: hex::encode(
                pon_work::task_id(&a, &b).map_err(|_| "PUBLIC_TASK_MATERIAL")?,
            ),
            model: hex::encode(model),
            input: hex::encode(input),
            purpose: "ledger-continuity-maintenance".into(),
            useful_output_credit: 0,
            hardness_accepted: false,
        })
    }
}

impl PublicTaskBootstrap {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        ensure(bytes.len() <= MAX_BOOTSTRAP_BYTES, "PUBLIC_TASK_BYTES")?;
        Ok(bytes)
    }

    /// Validate against the caller's already pinned genesis Settings. Remote
    /// self-consistency, signatures and recomputed hashes alone do not suffice.
    pub fn decode(bytes: &[u8], settings: &Settings) -> Result<Self> {
        ensure(bytes.len() <= MAX_BOOTSTRAP_BYTES, "PUBLIC_TASK_BYTES")?;
        let bundle: Self = serde_json::from_slice(bytes)?;
        ensure(bundle.encode()? == bytes, "PUBLIC_TASK_CANONICAL")?;
        bundle.validate(settings)?;
        Ok(bundle)
    }

    pub fn validate(&self, settings: &Settings) -> Result<()> {
        ensure(
            *self == settings.public_task_bootstrap()?,
            "PUBLIC_TASK_CONTEXT",
        )
    }
}

impl Node {
    /// Reuse the original native producer and full parent/task/target checks.
    /// A selected signed task is never silently replaced with this task.
    #[allow(clippy::too_many_arguments)]
    pub fn make_public_bootstrap(
        &self,
        bundle: &PublicTaskBootstrap,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        attempts: u64,
    ) -> Result<Packet> {
        bundle.validate(self.settings())?;
        self.make_consensus_maintenance(parent, transactions, miner, timestamp, attempts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(time: u64) -> Settings {
        Settings::development_with_profiles(
            Some(time),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_is_exact_public_genesis_material_and_never_useful_credit() {
        let settings = settings(1_000_000);
        let bundle = settings.public_task_bootstrap().unwrap();
        let wire = bundle.encode().unwrap();
        assert!(wire.len() < MAX_BOOTSTRAP_BYTES);
        assert_eq!(
            PublicTaskBootstrap::decode(&wire, &settings).unwrap(),
            bundle
        );
        assert_eq!(bundle.useful_output_credit, 0);
        assert!(!bundle.hardness_accepted);
        for mutation in 0..5 {
            let mut changed = bundle.clone();
            match mutation {
                0 => changed.model.replace_range(0..2, "ff"),
                1 => changed.input.replace_range(0..2, "ff"),
                2 => changed.useful_output_credit = 1,
                3 => changed.hardness_accepted = true,
                _ => changed.genesis = "00".repeat(32),
            }
            assert!(PublicTaskBootstrap::decode(&changed.encode().unwrap(), &settings).is_err());
        }
        assert!(PublicTaskBootstrap::decode(&wire, &self::settings(1_000_001)).is_err());
        assert!(
            PublicTaskBootstrap::decode(&vec![b' '; MAX_BOOTSTRAP_BYTES + 1], &settings).is_err()
        );
    }

    #[test]
    fn public_bundle_drives_original_native_mining_and_cold_replay() {
        let directory = tempfile::tempdir().unwrap();
        let settings = settings(1_000_000);
        let bundle = settings.public_task_bootstrap().unwrap();
        let miner = crate::development_public(3).unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let packet = node
            .make_public_bootstrap(&bundle, settings.genesis(), vec![], miner, 1_000_011, 4096)
            .unwrap();
        let id = node.admit(&packet, 1_000_012).unwrap();
        node.activate(id).unwrap();
        let state = node.read_active().unwrap();
        drop(node);
        let reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), state);
    }
}
