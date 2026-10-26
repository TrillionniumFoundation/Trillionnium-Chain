//! Research-only: sealed native ancestry index must agree with the independent
//! linear W1 packet observer without altering installed consensus target rules.
use trnm_pon_node::{
    consensus::daa_branch_research::{
        shadow_target_from_ancestry, AnchoredResearchContext, ParentClock,
    },
    development_public, Node, Settings,
};
const GENESIS: u64 = 1_750_000_000;

#[test]
fn indexed_asert_uses_exact_w1_branch_anchor_and_survives_cold_reopen() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("node");
    let settings = Settings::development(Some(GENESIS)).unwrap();
    let mut node = Node::open(&path, settings.clone(), 1).unwrap();
    let mut parent = settings.genesis();
    let mut anchor = None;
    let mut anchor_target = None;
    for height in 1..=20_u64 {
        let packet = node.make(
            parent,
            vec![],
            development_public(0).unwrap(),
            GENESIS + height * 10,
            4096,
        ).unwrap();
        let id = node.admit(&packet, GENESIS + height * 10).unwrap();
        node.activate(id).unwrap();
        if height == 1 {
            anchor = Some(id);
            anchor_target = Some(packet.header.target);
        }
        parent = id;
    }
    let mut limit = [255_u8; 32];
    limit[0] = 127;
    let context = AnchoredResearchContext {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
        genesis_timestamp: GENESIS,
        anchor_block: anchor.unwrap(),
        anchor_target: anchor_target.unwrap(),
        anchor_height: 1,
        spacing: 10,
        half_life: 7200,
        pow_limit: limit,
        parent_clock: ParentClock::Raw,
        max_ancestor_reads: 32,
    };
    let installed_before = node.expected_target(parent).unwrap();
    let linear = shadow_target_from_ancestry(context, parent, |id| node.packet(id)).unwrap();
    let indexed = node.indexed_asert_research_target(context, parent, 1024).unwrap();
    assert_eq!(indexed, linear);
    let median_context = AnchoredResearchContext {
        parent_clock: ParentClock::Median11,
        ..context
    };
    let linear_median =
        shadow_target_from_ancestry(median_context, parent, |id| node.packet(id)).unwrap();
    let indexed_median =
        node.indexed_asert_research_target(median_context, parent, 1024).unwrap();
    assert_eq!(indexed_median, linear_median);
    assert!(indexed_median < indexed);

    // A linear read ceiling of two packets cannot reach the genesis anchor.
    // The indexed path instead uses an explicit, separately bounded SQL budget.
    let capped_linear = AnchoredResearchContext {
        max_ancestor_reads: 2,
        ..context
    };
    assert!(shadow_target_from_ancestry(capped_linear, parent, |id| node.packet(id)).is_err());
    assert_eq!(
        node.indexed_asert_research_target(capped_linear, parent, 1024).unwrap(),
        indexed
    );
    assert!(node.indexed_asert_research_target(context, parent, 1).is_err());
    assert!(node.indexed_asert_research_target(
        AnchoredResearchContext { parameters: [0x44; 32], ..context },
        parent,
        1024
    ).is_err());
    assert!(node.indexed_asert_research_target(
        AnchoredResearchContext { anchor_target: [0x44; 32], ..context },
        parent,
        1024
    ).is_err());

    // The alternative height-one block is valid W1 work on a different fork;
    // its anchor is not an ancestor of the actual selected parent.
    let other_first = node.make(
        settings.genesis(),
        vec![],
        development_public(1).unwrap(),
        GENESIS + 11,
        4096,
    ).unwrap();
    let other_id = node.admit(&other_first, GENESIS + 220).unwrap();
    assert_ne!(other_id, context.anchor_block);
    assert!(node.indexed_asert_research_target(
        AnchoredResearchContext {
            anchor_block: other_id,
            anchor_target: other_first.header.target,
            ..context
        },
        parent,
        1024,
    ).is_err());
    assert_eq!(node.expected_target(parent).unwrap(), installed_before);
    let previous = node.read_active().unwrap();
    drop(node);

    let restored = Node::open(&path, settings, 1).unwrap();
    assert_eq!(restored.read_active().unwrap(), previous);
    assert_eq!(restored.indexed_asert_research_target(context, parent, 1024).unwrap(), indexed);
    assert_eq!(restored.expected_target(parent).unwrap(), installed_before);
}
