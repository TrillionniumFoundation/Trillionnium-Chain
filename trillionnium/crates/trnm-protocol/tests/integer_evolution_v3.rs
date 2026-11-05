//! Canonical bounded joint updates and historical wire isolation.
use trnm_protocol::integer_evolution_v3::{
    EvolutionOperationV3, EvolutionWitnessV3, MAX_PAYLOAD_BYTES,
};
use trnm_protocol::integer_factor_v2::FactorWitnessV2;
use trnm_protocol::pon_wire::Envelope;

fn witness() -> EvolutionWitnessV3 {
    EvolutionWitnessV3 {
        active_experts: 7,
        family: [1; 32],
        parent_ref: [2; 32],
        parent_artifact: [3; 32],
        candidate_artifact: [4; 32],
        update_id: [5; 32],
        contribution_id: [6; 32],
        components_root: [7; 32],
        round: 8,
        operations: (0..3)
            .map(|target| EvolutionOperationV3 {
                target,
                rank: 1,
                factors: vec![1; 260],
            })
            .collect(),
    }
}
#[test]
fn exact_maximum_payload_and_envelope_roundtrip_preserve_old_codec() {
    let witness = witness();
    let raw = witness.encode().unwrap();
    assert_eq!(raw.len(), MAX_PAYLOAD_BYTES);
    assert_eq!(raw.len(), 1808);
    assert_eq!(EvolutionWitnessV3::decode(&raw).unwrap(), witness);
    assert!(FactorWitnessV2::decode(&raw).is_err());
    let envelope = Envelope {
        network: [1; 32],
        sender: [2; 32],
        nonce: 1,
        expiry: 10,
        fee_limit: 1000,
        tag: 24,
        payload: raw,
        signature: [3; 64],
    };
    let encoded = envelope.encode().unwrap();
    assert_eq!(encoded.len(), 1967);
    assert_eq!(
        Envelope::decode(&encoded).unwrap().payload,
        envelope.payload
    );
}
#[test]
fn aliases_empty_graph_overbudget_and_noncanonical_bytes_are_refused() {
    let base = witness();
    for active in [0, 8, 255] {
        let mut changed = base.clone();
        changed.active_experts = active;
        assert!(changed.encode().is_err());
    }
    let mut repeated = base.clone();
    repeated.operations[1].target = 0;
    assert!(repeated.encode().is_err());
    let mut reversed = base.clone();
    reversed.operations.reverse();
    assert!(reversed.encode().is_err());
    let mut overrank = base.clone();
    overrank.operations[0].rank = 2;
    overrank.operations[0].factors = vec![1; 520];
    assert!(overrank.encode().is_err());
    let mut overcount = base.clone();
    overcount.operations.push(base.operations[0].clone());
    assert!(overcount.encode().is_err());
    let mut forbidden = base.clone();
    forbidden.operations[0].factors[0] = i16::MIN;
    assert!(forbidden.encode().is_err());
    let raw = base.encode().unwrap();
    for length in [0, 4, 241, 242, raw.len() - 1] {
        assert!(EvolutionWitnessV3::decode(&raw[..length]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(EvolutionWitnessV3::decode(&trailing).is_err());
    for (index, value) in [
        (4, 2),
        (6, 0),
        (7, 4),
        (9, 3),
        (242, 5),
        (243, 0),
        (244, 0),
        (245, 128),
    ] {
        let mut changed = raw.clone();
        changed[index] = value;
        // The last pair is tested together to encode forbidden -32768.
        if index == 244 || index == 245 {
            changed[244] = 0;
            changed[245] = 128;
        }
        assert!(
            EvolutionWitnessV3::decode(&changed).is_err(),
            "byte {index}"
        );
    }
    let mut graph_only = base;
    graph_only.operations.clear();
    graph_only.active_experts = 2;
    assert_eq!(graph_only.encode().unwrap().len(), 242);
    assert_eq!(
        EvolutionWitnessV3::decode(&graph_only.encode().unwrap()).unwrap(),
        graph_only
    );
}
