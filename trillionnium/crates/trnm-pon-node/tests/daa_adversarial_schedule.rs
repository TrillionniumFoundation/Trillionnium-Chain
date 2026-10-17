//! Actual valid PNW1 packets exhibit timestamp-endpoint DAA manipulation.
//! This checks current semantics, not an attacker-work-fraction or WAN exploit.
use trnm_pon_node::{consensus, development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::Hash;

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
