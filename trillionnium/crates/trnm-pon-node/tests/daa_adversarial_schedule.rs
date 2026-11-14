//! Actual valid PNW1 packets exhibit timestamp-endpoint DAA manipulation.
//! This checks current semantics, not an attacker-work-fraction or WAN exploit.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{consensus, development_public, maintenance, Node, Packet, Settings};
use trnm_protocol::pon_wire::{hash, Hash};

const GENESIS_TIME: u64 = 1_750_000_000;

fn extend(node: &mut Node, parent: Hash, timestamp: u64, height: u64, miner: u64) -> Packet {
    let packet = node
        .make(
            parent,
            vec![],
            development_public(miner).unwrap(),
            timestamp,
            4096,
        )
        .unwrap();
    assert_eq!(packet.header.height, height);
    node.admit(&packet, GENESIS_TIME + height * 10).unwrap();
    packet
}

#[test]
fn native_admissible_endpoint_schedule_changes_daa_without_changing_required_work_rules() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("node");
    let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
    let mut node = Node::open(&path, settings.clone(), 1).unwrap();
    let mut common = settings.genesis();
    // A preceding short timestamp period makes the actual parent target lower
    // than pow_limit. Otherwise its clip would conceal the next manipulation.
    for height in 1..=15 {
        common = extend(&mut node, common, GENESIS_TIME + height, height, 0)
            .id()
            .unwrap();
    }
    let mut honest = common;
    let mut altered = common;
    let mut period_target = None;
    for height in 16..=31 {
        let honest_packet = extend(&mut node, honest, GENESIS_TIME + height * 10, height, 0);
        let timestamp = match height {
            16 => 101,
            31 => 430,
            _ => height * 10,
        };
        let altered_packet = extend(&mut node, altered, GENESIS_TIME + timestamp, height, 1);
        assert_eq!(honest_packet.header.target, altered_packet.header.target);
        period_target = Some(honest_packet.header.target);
        honest = honest_packet.id().unwrap();
        altered = altered_packet.id().unwrap();
    }
    let period_target = period_target.unwrap();
    let ordinary_next = node.expected_target(honest).unwrap();
    let altered_next = node.expected_target(altered).unwrap();
    assert_eq!(ordinary_next, period_target);
    assert!(altered_next > ordinary_next);
    let mut pow_limit = [255; 32];
    pow_limit[0] = 127;
    assert_eq!(
        altered_next,
        consensus::retarget(period_target, 101, 430, 16, 10, pow_limit).unwrap()
    );
    // Both branches have equal required work before the altered retarget. A
    // relaxed target awards strictly LESS chainwork per later block, not free work.
    assert!(
        consensus::required_work(altered_next).unwrap()
            < consensus::required_work(ordinary_next).unwrap()
    );
    let next = extend(&mut node, altered, GENESIS_TIME + 440, 32, 1);
    assert_eq!(next.header.target, altered_next);
    assert_eq!(
        node.activate_observed(next.id().unwrap(), GENESIS_TIME + 320)
            .unwrap(),
        next.id().unwrap()
    );
    let before = node.read_active().unwrap();
    drop(node);
    let reopened = Node::open(&path, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), before);
    assert_eq!(
        reopened.packet(next.id().unwrap()).unwrap().header.target,
        altered_next
    );
}

fn timestamps(node: &Node, mut parent: Hash) -> Vec<u64> {
    let mut out = Vec::new();
    while out.len() < 11 {
        if parent == node.settings().genesis() {
            out.push(node.settings().genesis_time());
            break;
        }
        let packet = node.packet(parent).unwrap();
        out.push(packet.header.timestamp);
        parent = packet.header.parent;
    }
    out
}

fn active_work(node: &Node) -> consensus::Work {
    let bytes = hex::decode(node.stats().unwrap()["chainwork_hex"].as_str().unwrap()).unwrap();
    consensus::Work::from_bytes(bytes.try_into().unwrap())
}

fn verify_work(packet: &Packet) {
    pon_work::verify(
        packet.header.challenge(),
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .unwrap();
}

#[derive(Default)]
struct DaaEvidence {
    rows: Vec<Value>,
    packets: BTreeMap<Hash, Vec<u8>>,
}
impl DaaEvidence {
    fn note(&mut self, node: &Node, packet: &Packet, schedule: &str, now: u64, outcome: Value) {
        let ancestors = timestamps(node, packet.header.parent);
        let mut ordered = ancestors.clone();
        ordered.sort_unstable();
        let id = packet.id().unwrap();
        let bytes = packet.encode().unwrap();
        let previous = self.packets.insert(id, bytes.clone());
        if let Some(previous) = previous {
            assert_eq!(previous, bytes);
        }
        self.rows.push(json!({
            "schedule":schedule,"height":packet.header.height,
            "id":hex::encode(id),"parent":hex::encode(packet.header.parent),
            "timestamp":packet.header.timestamp,"observed_now":now,
            "ancestor_timestamps_parent_first":ancestors,
            "median_time_past":ordered[ordered.len()/2],
            "target":hex::encode(packet.header.target),
            "required_work_hex":hex::encode(consensus::required_work(packet.header.target).unwrap().bytes()),
            "header_hex":hex::encode(packet.header.encode()),
            "nonce":packet.header.nonce,"attempts":packet.header.nonce+1,
            "proof_bytes":packet.proof.len(),
            "proof_sha256":hex::encode(Sha256::digest(&packet.proof)),
            "trace":hex::encode(&packet.proof[packet.proof.len()-32..]),
            "packet_bytes":bytes.len(),"packet_sha256":hex::encode(Sha256::digest(&bytes)),
            "packet_file":format!("packets/{}.pnk",hex::encode(id)),
            "complete_native_work_verification":true,"admission":outcome
        }));
    }

    fn admit(
        &mut self,
        node: &mut Node,
        packet: &Packet,
        schedule: &str,
        now: u64,
        parent_work: consensus::Work,
    ) -> consensus::Work {
        verify_work(packet);
        let id = packet.id().unwrap();
        assert_eq!(node.admit(packet, now).unwrap(), id);
        assert_eq!(
            node.packet(id).unwrap().encode().unwrap(),
            packet.encode().unwrap()
        );
        let work = parent_work
            .checked_add(consensus::required_work(packet.header.target).unwrap())
            .unwrap();
        self.note(
            node,
            packet,
            schedule,
            now,
            json!({"kind":"admitted","cumulative_required_work_hex":hex::encode(work.bytes())}),
        );
        work
    }

    fn retain(&self, report: &Value) {
        // Optional native runner evidence is create-only. No existing report or
        // packet can be replaced, and the temporary database is never exported.
        if let Some(path) = std::env::var_os("TRNM_DAA_EVIDENCE_DIR") {
            let path = std::path::PathBuf::from(path);
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
                .open(path.join("daa-bounds.json"))
                .unwrap()
                .write_all(&serde_json::to_vec_pretty(report).unwrap())
                .unwrap();
        }
        eprintln!(
            "pon_native_daa_bounds_v1 {}",
            serde_json::to_string(report).unwrap()
        );
    }
}

fn reprove_at(packet: &Packet, timestamp: u64) -> Packet {
    // A timestamp mutation gets a fresh complete PNW1 proof, not a header-only
    // surrogate. The unchanged execution fields are checked by a later actual
    // admission for the deferred packet when the local clock permits it.
    let (a, b) = maintenance();
    let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
    let mut changed = packet.clone();
    changed.header.timestamp = timestamp;
    for nonce in 0..4096 {
        changed.header.nonce = nonce;
        changed.proof = prepared.prove(changed.header.challenge()).unwrap();
        if hash(
            b"ticket",
            &[
                &changed.header.challenge(),
                &changed.proof[changed.proof.len() - 32..],
            ],
        ) <= changed.header.target
        {
            verify_work(&changed);
            return changed;
        }
    }
    panic!("bounded complete PNW1 search exhausted");
}

#[test]
fn native_daa_clamps_mtp_future_chainwork_and_authenticated_reopen() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("authenticated-node");
    let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
    let mut node = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
    let genesis_work = active_work(&node);
    let mut evidence = DaaEvidence::default();
    let mut common = settings.genesis();
    let mut common_work = genesis_work;
    // Two actual short periods make the later upper clamp strictly below
    // pow_limit. Otherwise the ceiling could conceal the factor-four boundary.
    for height in 1..=31 {
        let packet = node
            .make(
                common,
                vec![],
                development_public(0).unwrap(),
                GENESIS_TIME + height,
                4096,
            )
            .unwrap();
        assert_eq!(packet.header.height, height);
        common_work = evidence.admit(
            &mut node,
            &packet,
            "common-compressed",
            GENESIS_TIME + height * 10,
            common_work,
        );
        common = packet.id().unwrap();
        assert_eq!(
            node.activate_observed(common, GENESIS_TIME + height * 10)
                .unwrap(),
            common
        );
    }
    assert_eq!(active_work(&node), common_work);
    let period_target = node.expected_target(common).unwrap();
    let mut pow_limit = [255; 32];
    pow_limit[0] = 127;
    assert!(
        consensus::Work::from_target(period_target)
            .mul_small(4)
            .unwrap()
            < consensus::Work::from_target(pow_limit)
    );

    let names = ["ordinary", "lower-clamp", "upper-clamp"];
    let mut tips = [common; 3];
    let mut works = [common_work; 3];
    for height in 32..=47 {
        for arm in 0..3 {
            let offset = match arm {
                0 => height * 10,
                1 => height,
                2 => match height {
                    32 => 27,
                    47 => 627,
                    _ => height * 10,
                },
                _ => unreachable!(),
            };
            // The last upper-clamp block is admitted at exactly now+120.
            // These are explicitly supplied logical validation clocks; this
            // test does not measure a live ten-second cadence or an attack rate.
            let now = GENESIS_TIME
                + if arm == 2 && height == 47 {
                    507
                } else {
                    height * 10
                };
            let packet = node
                .make(
                    tips[arm],
                    vec![],
                    development_public(arm as u64).unwrap(),
                    GENESIS_TIME + offset,
                    4096,
                )
                .unwrap();
            assert_eq!(packet.header.height, height);
            assert_eq!(packet.header.target, period_target);
            works[arm] = evidence.admit(&mut node, &packet, names[arm], now, works[arm]);
            tips[arm] = packet.id().unwrap();
        }
    }
    assert_eq!(works[0], works[1]);
    assert_eq!(works[1], works[2]);
    let next_targets = tips.map(|tip| node.expected_target(tip).unwrap());
    assert_eq!(next_targets[0], period_target);
    assert_eq!(
        next_targets[1],
        consensus::retarget(period_target, 32, 47, 16, 10, pow_limit).unwrap()
    );
    assert_eq!(
        next_targets[1],
        consensus::retarget(period_target, 0, 38, 16, 10, pow_limit).unwrap()
    );
    assert_eq!(
        next_targets[2],
        consensus::retarget(period_target, 27, 627, 16, 10, pow_limit).unwrap()
    );
    assert_eq!(
        next_targets[2],
        consensus::Work::from_target(period_target)
            .mul_small(4)
            .unwrap()
            .target()
            .unwrap()
    );
    assert!(next_targets[1] < next_targets[0] && next_targets[0] < next_targets[2]);

    let mut last_packets = Vec::new();
    for arm in 0..3 {
        let offset = [480, 48, 628][arm];
        let packet = node
            .make(
                tips[arm],
                vec![],
                development_public(arm as u64).unwrap(),
                GENESIS_TIME + offset,
                4096,
            )
            .unwrap();
        assert_eq!(packet.header.height, 48);
        assert_eq!(packet.header.target, next_targets[arm]);
        works[arm] = evidence.admit(
            &mut node,
            &packet,
            names[arm],
            GENESIS_TIME + 508,
            works[arm],
        );
        tips[arm] = packet.id().unwrap();
        last_packets.push(packet);
    }
    assert!(works[1] > works[0] && works[0] > works[2]);
    let mut activations = Vec::new();
    for arm in [2, 0, 1] {
        assert_eq!(
            node.activate_observed(tips[arm], GENESIS_TIME + 508)
                .unwrap(),
            tips[arm]
        );
        assert_eq!(active_work(&node), works[arm]);
        activations.push(json!({"schedule":names[arm],"stats":node.stats().unwrap()}));
    }
    assert_eq!(
        node.activate_observed(tips[2], GENESIS_TIME + 508).unwrap(),
        tips[1]
    );
    let selected = node.stats().unwrap();

    let before_rejections = node.stats().unwrap();
    let future = reprove_at(&last_packets[2], GENESIS_TIME + 629);
    let mut recent = timestamps(&node, last_packets[2].header.parent);
    recent.sort_unstable();
    let at_median = reprove_at(&last_packets[2], recent[recent.len() / 2]);
    for (packet, code) in [(&future, "TIME_DEFERRED"), (&at_median, "TIME")] {
        let error = node.admit(packet, GENESIS_TIME + 508).unwrap_err();
        assert_eq!(error.to_string(), code);
        assert_eq!(node.stats().unwrap(), before_rejections);
        assert!(node.packet(packet.id().unwrap()).is_err());
        evidence.note(
            &node,
            packet,
            "time-boundary-negative",
            GENESIS_TIME + 508,
            json!({"kind":"rejected","error":code}),
        );
    }
    // The exact same fully proved packet succeeds one clock second later. It
    // still carries less accumulated work and cannot replace the harder branch.
    let upper_parent_work = works[2]
        .checked_sub(consensus::required_work(next_targets[2]).unwrap())
        .unwrap();
    let retry_work = evidence.admit(
        &mut node,
        &future,
        "future-clock-retry",
        GENESIS_TIME + 509,
        upper_parent_work,
    );
    assert_eq!(retry_work, works[2]);
    assert_eq!(
        node.activate_observed(future.id().unwrap(), GENESIS_TIME + 509)
            .unwrap(),
        tips[1]
    );
    let before = node.read_active().unwrap();
    let before_stats = node.stats().unwrap();
    drop(node);
    let reopened = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), before);
    assert_eq!(reopened.stats().unwrap(), before_stats);
    for (id, bytes) in &evidence.packets {
        if *id != at_median.id().unwrap() {
            assert_eq!(reopened.packet(*id).unwrap().encode().unwrap(), *bytes);
        }
    }
    assert_eq!(active_work(&reopened), works[1]);
    let report = json!({
        "schema":"pon-native-daa-bounds-v1",
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),"genesis_timestamp":GENESIS_TIME,
        "genesis_chainwork_hex":hex::encode(genesis_work.bytes()),
        "interval":16,"spacing_seconds":10,"median_window":11,"future_skew_seconds":120,
        "desired_span_seconds":150,"clamped_span_lower_seconds":38,"clamped_span_upper_seconds":600,
        "pow_limit":hex::encode(pow_limit),"branch_period_target":hex::encode(period_target),
        "next_targets":names.into_iter().zip(next_targets).map(|(name,target)|json!({"schedule":name,"target":hex::encode(target),"required_work_hex":hex::encode(consensus::required_work(target).unwrap().bytes())})).collect::<Vec<_>>(),
        "records":evidence.rows,"activations":activations,"selected_before_negative_checks":selected,
        "after_authenticated_reopen":reopened.stats().unwrap(),
        "same_packet_clock_retry_admitted":true,"lower_work_branch_replaces_harder_branch":false,
        "default_consensus_rules_changed":false,"logical_validation_clock_schedule":true,
        "wall_clock_cadence_measured":false,"attacker_work_fraction_measured":false,
        "timestamp_attack_profitability_measured":false,"public_network_qualification":false
    });
    evidence.retain(&report);
}
