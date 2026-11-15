//! Joint native evidence for repeated nonmonotone retarget endpoints.
//! Every accepted block carries a real PNW1 proof and crosses its actual storage
//! owner's admission path. Logical clocks do not measure attack profitability.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write, path::Path};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{consensus, development_public, GrowthPacket, Node, Packet, Settings};
use trnm_protocol::pon_wire::{Hash, Header};

const GENESIS_TIME: u64 = 1_750_000_000;
const INTERVAL: u64 = 16;
const SPACING: u64 = 10;
const ATTEMPTS: u64 = 4096;

#[derive(Clone, Copy)]
enum Backend {
    Pnh1,
    Pgh2,
}
impl Backend {
    fn name(self) -> &'static str {
        match self {
            Self::Pnh1 => "pnh1-authenticated",
            Self::Pgh2 => "pgh2-growth",
        }
    }
    fn header_profile(self) -> &'static str {
        match self {
            Self::Pnh1 => "PNH1",
            Self::Pgh2 => "PGH2",
        }
    }
    fn settings(self) -> Settings {
        match self {
            Self::Pnh1 => Settings::development(Some(GENESIS_TIME)).unwrap(),
            Self::Pgh2 => Settings::development_with_profiles(
                Some(GENESIS_TIME),
                "native-public-evaluation-dev-v1",
                continuity_v1::PROFILE,
            )
            .unwrap()
            .with_permanent_account_growth_v2("joint-daa-negative-endpoints-v1")
            .unwrap(),
        }
    }
    fn open(self, path: &Path, settings: Settings) -> Node {
        match self {
            Self::Pnh1 => Node::open_with_authenticated_state(path, settings, 1).unwrap(),
            Self::Pgh2 => Node::open_with_permanent_account_growth_v2(path, settings).unwrap(),
        }
    }
    fn make(self, node: &Node, parent: Hash, timestamp: u64, miner: u64) -> NativePacket {
        let miner = development_public(miner).unwrap();
        match self {
            Self::Pnh1 => NativePacket::Pnh1(
                node.make(parent, vec![], miner, timestamp, ATTEMPTS)
                    .unwrap(),
            ),
            Self::Pgh2 => NativePacket::Pgh2(
                node.make_growth_consensus_maintenance(parent, vec![], miner, timestamp, ATTEMPTS)
                    .unwrap(),
            ),
        }
    }
    fn stored(self, node: &Node, id: Hash) -> NativePacket {
        match self {
            Self::Pnh1 => NativePacket::Pnh1(node.packet(id).unwrap()),
            Self::Pgh2 => NativePacket::Pgh2(node.growth_packet(id).unwrap()),
        }
    }
    fn admit(self, node: &mut Node, packet: &NativePacket, now: u64) -> Hash {
        match (self, packet) {
            (Self::Pnh1, NativePacket::Pnh1(packet)) => node.admit(packet, now).unwrap(),
            (Self::Pgh2, NativePacket::Pgh2(packet)) => node.admit_growth(packet, now).unwrap(),
            _ => panic!("storage/header profile mismatch"),
        }
    }
    fn activate(self, node: &mut Node, id: Hash, now: u64) -> Hash {
        match self {
            Self::Pnh1 => node.activate_observed(id, now).unwrap(),
            // Growth has its own PNP2 history and journal path. Its activation
            // API does not accept a clock; all timestamps were checked at admission.
            Self::Pgh2 => node.activate(id).unwrap(),
        }
    }
    fn head(self, node: &Node) -> Value {
        match self {
            Self::Pnh1 => node.stats().unwrap(),
            Self::Pgh2 => node
                .growth_head_observation_with_progress(&|_| Ok(()))
                .unwrap(),
        }
    }
    fn state(self, node: &Node) -> Value {
        match self {
            Self::Pnh1 => serde_json::to_value(node.read_active().unwrap()).unwrap(),
            Self::Pgh2 => {
                let snapshot = node.growth_current_working().unwrap();
                json!({"block":snapshot.block,"generation":snapshot.generation,
                    "height":snapshot.height,"commitment":snapshot.commitment,
                    "working":snapshot.working})
            }
        }
    }
}

#[derive(Clone)]
enum NativePacket {
    Pnh1(Packet),
    Pgh2(GrowthPacket),
}
impl NativePacket {
    fn header(&self) -> &Header {
        match self {
            Self::Pnh1(packet) => &packet.header,
            Self::Pgh2(packet) => &packet.header.ledger,
        }
    }
    fn header_mut(&mut self) -> &mut Header {
        match self {
            Self::Pnh1(packet) => &mut packet.header,
            Self::Pgh2(packet) => &mut packet.header.ledger,
        }
    }
    fn header_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pnh1(packet) => packet.header.encode(),
            Self::Pgh2(packet) => packet.header.encode(),
        }
    }
    fn challenge(&self) -> Hash {
        match self {
            Self::Pnh1(packet) => packet.header.challenge(),
            Self::Pgh2(packet) => packet.header.challenge(),
        }
    }
    fn proof(&self) -> &[u8] {
        match self {
            Self::Pnh1(packet) => &packet.proof,
            Self::Pgh2(packet) => &packet.proof,
        }
    }
    fn id(&self) -> Hash {
        match self {
            Self::Pnh1(packet) => packet.id().unwrap(),
            Self::Pgh2(packet) => packet.id().unwrap(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Pnh1(packet) => packet.encode().unwrap(),
            Self::Pgh2(packet) => packet.encode().unwrap(),
        }
    }
    fn verify(&self) -> Result<pon_work::VerifiedWork, pon_work::WorkError> {
        pon_work::verify(
            self.challenge(),
            self.header().work_task,
            self.header().target,
            self.proof(),
        )
    }
}

fn work(head: &Value) -> consensus::Work {
    consensus::Work::from_bytes(
        hex::decode(head["chainwork_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
fn recent(node: &Node, backend: Backend, mut parent: Hash) -> Vec<u64> {
    let mut times = Vec::new();
    while times.len() < 11 {
        if parent == node.settings().genesis() {
            times.push(node.settings().genesis_time());
            break;
        }
        let packet = backend.stored(node, parent);
        times.push(packet.header().timestamp);
        parent = packet.header().parent;
    }
    times
}
fn median(times: &[u64]) -> u64 {
    let mut ordered = times.to_vec();
    ordered.sort_unstable();
    ordered[ordered.len() / 2]
}

#[derive(Default)]
struct Evidence {
    rows: Vec<Value>,
    packets: BTreeMap<Hash, Vec<u8>>,
}
impl Evidence {
    fn admit(
        &mut self,
        node: &mut Node,
        backend: Backend,
        packet: &NativePacket,
        schedule: &str,
        now: u64,
        parent_work: consensus::Work,
    ) -> consensus::Work {
        let h = packet.header();
        let ancestors = recent(node, backend, h.parent);
        packet.verify().unwrap();
        assert_eq!(backend.admit(node, packet, now), packet.id());
        let bytes = packet.encode();
        assert_eq!(backend.stored(node, packet.id()).encode(), bytes);
        assert!(self.packets.insert(packet.id(), bytes.clone()).is_none());
        let accumulated = parent_work
            .checked_add(consensus::required_work(h.target).unwrap())
            .unwrap();
        self.rows.push(json!({
            "schedule":schedule,"height":h.height,"id":hex::encode(packet.id()),
            "parent":hex::encode(h.parent),"timestamp":h.timestamp,"observed_now":now,
            "ancestor_timestamps_parent_first":ancestors,"median_time_past":median(&ancestors),
            "target":hex::encode(h.target),"required_work_hex":hex::encode(consensus::required_work(h.target).unwrap().bytes()),
            "header_hex":hex::encode(packet.header_bytes()),"challenge":hex::encode(packet.challenge()),
            "nonce":h.nonce,"attempts":h.nonce+1,"proof_bytes":packet.proof().len(),
            "proof_sha256":hex::encode(Sha256::digest(packet.proof())),
            "trace":hex::encode(&packet.proof()[packet.proof().len()-32..]),
            "packet_bytes":bytes.len(),"packet_sha256":hex::encode(Sha256::digest(&bytes)),
            "packet_file":format!("packets/{}.pnk",hex::encode(packet.id())),
            "complete_native_work_verification":true,
            "admission":{"kind":"admitted","cumulative_required_work_hex":hex::encode(accumulated.bytes())}
        }));
        accumulated
    }
    fn retain(&self, backend: Backend, report: &Value) {
        if let Some(root) = std::env::var_os("TRNM_JOINT_DAA_EVIDENCE_DIR") {
            let root = std::path::PathBuf::from(root);
            fs::create_dir_all(&root).unwrap();
            // Two tests may share a root; each exact profile remains create-only.
            let path = root.join(backend.name());
            fs::create_dir(&path).unwrap();
            fs::create_dir(path.join("packets")).unwrap();
            for (id, bytes) in &self.packets {
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.join(format!("packets/{}.pnk", hex::encode(id))))
                    .unwrap()
                    .write_all(bytes)
                    .unwrap();
            }
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path.join("joint-daa.json"))
                .unwrap()
                .write_all(&serde_json::to_vec_pretty(report).unwrap())
                .unwrap();
        }
        eprintln!(
            "pon_native_joint_daa_v1 {}",
            serde_json::to_string(report).unwrap()
        );
    }
}

fn run(backend: Backend) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("node");
    let settings = backend.settings();
    let mut node = backend.open(&path, settings.clone());
    let initial = node.expected_target(settings.genesis()).unwrap();
    let mut limit = [255; 32];
    limit[0] = 127;
    assert_eq!(initial, limit);
    let genesis_work = work(&backend.head(&node));
    let mut evidence = Evidence::default();
    let mut common = settings.genesis();
    let mut common_work = genesis_work;
    for height in 1..INTERVAL {
        let now = GENESIS_TIME + height * SPACING;
        let packet = backend.make(&node, common, now, 0);
        assert_eq!(packet.header().height, height);
        common_work = evidence.admit(&mut node, backend, &packet, "common", now, common_work);
        common = packet.id();
    }
    let mut tips = [common; 2];
    let mut weights = [common_work; 2];
    let mut period_first: Option<u64> = None;
    let mut period_last: Option<u64> = None;
    let mut previous_target = initial;
    let mut retargets = Vec::new();
    let mut final_packet = None;
    // At 16/32/48 the altered branch places one fresh wall-clock spike. The
    // remaining fifteen timestamps are MTP+1. The period endpoints reverse
    // while each individual timestamp remains valid. Height 64 consumes the
    // third consecutive lower clamp; the honest branch then extends to 65.
    for height in INTERVAL..=4 * INTERVAL {
        let now = GENESIS_TIME + height * SPACING;
        for arm in 0..2 {
            let target = node.expected_target(tips[arm]).unwrap();
            if arm == 1 && height > INTERVAL && height.is_multiple_of(INTERVAL) {
                let first = period_first.unwrap();
                let last = period_last.unwrap();
                assert!(last < first, "endpoint reversal must be strict");
                let expected =
                    consensus::retarget(previous_target, first, last, INTERVAL, SPACING, limit)
                        .unwrap();
                assert_eq!(target, expected);
                assert!(target < previous_target);
                assert!(
                    consensus::required_work(target).unwrap()
                        > consensus::required_work(previous_target).unwrap()
                );
                retargets.push(json!({"height":height,"first_timestamp":first,"last_timestamp":last,
                    "signed_span_seconds":(i128::from(last)-i128::from(first)).to_string(),
                    "saturating_span_seconds":last.saturating_sub(first),"effective_span_seconds":38,
                    "parent_target":hex::encode(previous_target),"next_target":hex::encode(target)}));
            }
            if arm == 0 {
                assert_eq!(target, initial);
            }
            let timestamp = if arm == 0 || height.is_multiple_of(INTERVAL) {
                now
            } else {
                median(&recent(&node, backend, tips[arm]))
                    .checked_add(1)
                    .unwrap()
            };
            let packet = backend.make(&node, tips[arm], timestamp, arm as u64);
            assert_eq!(packet.header().target, target);
            assert_eq!(packet.header().height, height);
            weights[arm] = evidence.admit(
                &mut node,
                backend,
                &packet,
                ["ordinary", "repeated-negative-endpoints"][arm],
                now,
                weights[arm],
            );
            tips[arm] = packet.id();
            if arm == 1 {
                if height.is_multiple_of(INTERVAL) {
                    period_first = Some(timestamp);
                    previous_target = target;
                }
                period_last = Some(timestamp);
                final_packet = Some(packet);
            }
        }
    }
    assert_eq!(retargets.len(), 3);
    let now = GENESIS_TIME + 65 * SPACING;
    let ordinary = backend.make(&node, tips[0], now, 0);
    assert_eq!(ordinary.header().height, 65);
    weights[0] = evidence.admit(&mut node, backend, &ordinary, "ordinary", now, weights[0]);
    tips[0] = ordinary.id();
    assert!(weights[1] > weights[0]);
    let mut activations = Vec::new();
    for arm in [0, 1] {
        assert_eq!(backend.activate(&mut node, tips[arm], now), tips[arm]);
        assert_eq!(work(&backend.head(&node)), weights[arm]);
        activations.push(backend.head(&node));
    }
    assert_eq!(backend.head(&node)["height"], json!(64));
    assert_eq!(backend.activate(&mut node, tips[0], now), tips[1]);

    let final_packet = final_packet.unwrap();
    let mut binding_rejections = Vec::new();
    for field in ["parent", "target", "timestamp", "nonce"] {
        let mut changed = final_packet.clone();
        match field {
            "parent" => changed.header_mut().parent[0] ^= 1,
            "target" => changed.header_mut().target[31] ^= 1,
            "timestamp" => changed.header_mut().timestamp += 1,
            "nonce" => changed.header_mut().nonce ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(changed.challenge(), final_packet.challenge());
        let error = changed.verify().unwrap_err();
        binding_rejections.push(json!({"changed_field":field,"unchanged_proof_sha256":hex::encode(Sha256::digest(changed.proof())),
            "changed_challenge":hex::encode(changed.challenge()),"work_error":format!("{error:?}")}));
    }
    if let NativePacket::Pgh2(packet) = &final_packet {
        let mut changed = packet.clone();
        changed.header.witness[0] ^= 1;
        let changed = NativePacket::Pgh2(changed);
        let error = changed.verify().unwrap_err();
        binding_rejections
            .push(json!({"changed_field":"growth_witness","work_error":format!("{error:?}")}));
    }
    let before = backend.head(&node);
    let before_state = backend.state(&node);
    drop(node);
    let reopened = backend.open(&path, settings.clone());
    assert_eq!(backend.head(&reopened), before);
    assert_eq!(backend.state(&reopened), before_state);
    for (id, bytes) in &evidence.packets {
        assert_eq!(backend.stored(&reopened, *id).encode(), *bytes);
    }
    let report = json!({
        "schema":"pon-native-joint-daa-v1","backend":backend.name(),"header_profile":backend.header_profile(),"work_profile":"PNW1",
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),"genesis_timestamp":GENESIS_TIME,
        "genesis_chainwork_hex":hex::encode(genesis_work.bytes()),"initial_target":hex::encode(initial),"pow_limit":hex::encode(limit),
        "interval":INTERVAL,"spacing_seconds":SPACING,"median_window":11,"future_skew_seconds":120,
        "desired_span_seconds":150,"clamped_span_lower_seconds":38,"clamped_span_upper_seconds":600,
        "records":evidence.rows,"retargets":retargets,"activations":activations,"binding_rejections":binding_rejections,
        "ordinary_tip":hex::encode(tips[0]),"altered_tip":hex::encode(tips[1]),
        "ordinary_chainwork_hex":hex::encode(weights[0].bytes()),"altered_chainwork_hex":hex::encode(weights[1].bytes()),
        "after_cold_reopen":backend.head(&reopened),"shorter_higher_work_branch_selected":true,
        "activation_observed_clock_api":matches!(backend,Backend::Pnh1),
        "growth_activation_clock_checked":false,
        "default_consensus_rules_changed":false,"logical_validation_clock_schedule":true,
        "wall_clock_cadence_measured":false,"attacker_work_fraction_measured":false,
        "quantum_attack_profitability_measured":false,"public_network_qualification":false
    });
    evidence.retain(backend, &report);
}

#[test]
fn pnh1_three_negative_endpoint_periods_keep_real_w1_and_select_higher_work() {
    run(Backend::Pnh1);
}

#[test]
fn pgh2_three_negative_endpoint_periods_keep_real_w1_and_select_higher_work() {
    run(Backend::Pgh2);
}
