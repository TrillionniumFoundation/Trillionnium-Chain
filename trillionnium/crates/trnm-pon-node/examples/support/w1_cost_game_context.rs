//! Real original-Node maintenance parents, kept separate from diagnostic tasks.
//! No replica consensus rule or unsigned task admission is introduced here.
use serde_json::{json, Value};
use trnm_crypto_primitives::pon_work::{self, Hash};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::Header;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct NativeContext {
    // Dropped after Node, so its on-disk temporary state lasts through admission.
    pub node: Node,
    _directory: tempfile::TempDir,
    headers: Vec<Header>,
    pub receipt: Value,
    pub auxiliary: Vec<AuxiliaryWork>,
}

pub struct AuxiliaryWork {
    pub semantic: Hash,
    pub completion_cpu_ns: Option<u64>,
}

fn auxiliary_receipt(
    packet: &Packet,
    role: &str,
    branch: Option<usize>,
    completed: Option<u64>,
    admitted: Option<u64>,
) -> Result<(AuxiliaryWork, Value)> {
    let trace: Hash = packet.proof[pon_work::PROOF_BYTES - 32..].try_into()?;
    let challenge = packet.header.challenge();
    let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
    if packet.header.target == [0; 32] || ticket > packet.header.target {
        return Err("AUXILIARY_ORIGINAL_NODE_TARGET".into());
    }
    let semantic = crate::semantic_id(packet.header.work_task, challenge, ticket);
    Ok((
        AuxiliaryWork {
            semantic,
            completion_cpu_ns: completed,
        },
        json!({
            "role":role,"branch":branch,"block_id":hex::encode(packet.id()?),
            "parent":hex::encode(packet.header.parent),"height":packet.header.height,
            "header_hex":hex::encode(packet.header.encode()),"task":hex::encode(packet.header.work_task),
            "target":hex::encode(packet.header.target),"challenge":hex::encode(challenge),
            "trace":hex::encode(trace),"ticket":hex::encode(ticket),"semantic_id":hex::encode(semantic),
            "proof_sha256":crate::sha(&packet.proof),"proof_bytes":packet.proof.len(),
            "target_hit":true,"winning_nonce":packet.header.nonce,
            "original_make_complete_attempts":packet.header.nonce + 1,
            "original_make_failed_attempts":packet.header.nonce,
            "inclusive_producer_cpu_ns":completed,"admission_completion_inclusive_cpu_ns":admitted,
            "qualification_level":"native-admitted-maintenance","admitted":true,
            "full_relation_verified_by_original_node_admit":true,
            "counted_in_selected_arm_numerator":false,"counted_in_all_work_numerator":true,
        }),
    ))
}

impl NativeContext {
    pub fn new(sample: u64, mut completion_cpu: impl FnMut() -> Option<u64>) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )?;
        let mut node = Node::open(directory.path(), settings, 2)?;
        let genesis = node.active()?.0;
        let mut acquisition = Vec::new();
        let mut auxiliary = Vec::new();
        let mut parents = vec![genesis];
        // Two actual admitted sibling parents; neither is credited as output of
        // the measured research producer. Their acquisition cost is charged.
        for (miner, timestamp) in [(0, 11), (1, 12)] {
            let packet = node.make_consensus_maintenance(
                genesis,
                vec![],
                development_public(miner)?,
                timestamp,
                4096,
            )?;
            let completed = completion_cpu();
            let parent = node.admit(&packet, 100_000)?;
            let admitted = completion_cpu();
            let (work, receipt) =
                auxiliary_receipt(&packet, "fork-parent", None, completed, admitted)?;
            auxiliary.push(work);
            acquisition.push(receipt);
            parents.push(parent);
        }
        node.activate(parents[1])?;
        let mut headers = Vec::new();
        for (branch, parent) in parents.iter().copied().enumerate() {
            let packet = node.make_consensus_maintenance(
                parent,
                vec![],
                development_public(0)?,
                101 + sample * 10 + branch as u64,
                4096,
            )?;
            let completed = completion_cpu();
            if packet.header.target != node.expected_target(parent)? {
                return Err("ORIGINAL_NODE_TARGET_MISMATCH".into());
            }
            // The original make route checks exact maintenance eligibility in
            // this parent's actual state. Its private Config is not reproduced.
            node.admit(&packet, 100_000)?;
            let admitted = completion_cpu();
            let (work, receipt) = auxiliary_receipt(
                &packet,
                "original-node-template",
                Some(branch),
                completed,
                admitted,
            )?;
            auxiliary.push(work);
            acquisition.push(receipt);
            headers.push(packet.header);
        }
        Ok(Self {
            node,
            _directory: directory,
            headers,
            auxiliary,
            receipt: json!({"source":"original-Node-make_consensus_maintenance",
                "qualification_level":"parent-eligible-maintenance-template",
                "parent_count":3,"genesis":hex::encode(genesis),"acquisition":acquisition,
                "acquisition_outputs_counted_as_selected_arm_wins":false,
                "acquisition_outputs_counted_in_all_work_numerator":true,
                "sibling_work_is_not_summed_as_one_chain":true}),
        })
    }

    pub fn header(&self, seed: u64, sample: u64, phase: &str, ordinal: u64) -> Header {
        let mut header = self.headers[ordinal as usize % self.headers.len()].clone();
        let nonce = pon_work::hash(
            b"w1-cost-game-native-nonce-v1",
            &[
                &seed.to_le_bytes(),
                &sample.to_le_bytes(),
                phase.as_bytes(),
                &ordinal.to_le_bytes(),
            ],
        );
        header.nonce = u64::from_le_bytes(nonce[..8].try_into().expect("eight bytes"));
        header
    }

    pub fn admit(&mut self, header: Header, proof: Vec<u8>) -> Result<Value> {
        let packet = Packet {
            header,
            transactions: vec![],
            proof,
        };
        let expected = packet.id()?;
        let id = self.node.admit(&packet, 100_000)?;
        if id != expected {
            return Err("NATIVE_BLOCK_ID_MISMATCH".into());
        }
        // A second admission of identical work must not yield a new block id.
        let repeated = self.node.admit(&packet, 100_000)?;
        if repeated != id {
            return Err("NATIVE_DUPLICATE_CHANGED_ID".into());
        }
        Ok(
            json!({"admitted":true,"qualification_level":"native-admitted-maintenance",
            "block_id":hex::encode(id),"duplicate_replay_block_id":hex::encode(repeated),
            "duplicate_replay_creates_new_semantic_work":false,"activated":false,
            "parent":hex::encode(packet.header.parent),"height":packet.header.height,
            "target":hex::encode(packet.header.target)}),
        )
    }

    pub fn task(&self) -> Hash {
        self.headers[0].work_task
    }
}
