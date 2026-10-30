//! Real complete PNW1 / M06 / authenticated State observations, not a measured
//! adversarial fraction or a probabilistic finality proof. No rule is changed.
use serde_json::{json, Value};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{consensus, development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

const GENESIS: u64 = 1_750_000_000;

fn transfer(settings: &Settings) -> Vec<u8> {
    let mut payload = development_public(3).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 900,
        fee_limit: 1000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

fn extend(node: &mut Node, parent: Hash, height: u64, txs: Vec<Vec<u8>>, miner: u64) -> Packet {
    let now = GENESIS + height * 10;
    let packet = node
        .make(parent, txs, development_public(miner).unwrap(), now, 4096)
        .unwrap();
    assert_eq!(packet.header.height, height);
    assert_eq!(node.admit(&packet, now).unwrap(), packet.id().unwrap());
    assert_eq!(
        node.activate_observed(packet.id().unwrap(), now).unwrap(),
        packet.id().unwrap()
    );
    packet
}

#[test]
fn confirmed_transaction_can_be_reorged_by_later_published_strictly_heavier_valid_branch() {
    let temp = tempfile::tempdir().unwrap();
    let public_path = temp.path().join("public");
    let private_path = temp.path().join("withholding-producer");
    let settings = Settings::development(Some(GENESIS)).unwrap();
    let mut public =
        Node::open_with_authenticated_state(&public_path, settings.clone(), 1).unwrap();
    let mut private =
        Node::open_with_authenticated_state(&private_path, settings.clone(), 1).unwrap();
    let tx = transfer(&settings);
    let tx_id = hash(b"tx-id", &[&tx]);
    let first = extend(&mut public, settings.genesis(), 1, vec![tx], 0);
    let included = first.id().unwrap();
    let mut public_tip = included;
    let mut first_confirmation = None;
    for height in 2..=17 {
        let packet = extend(&mut public, public_tip, height, vec![], 0);
        public_tip = packet.id().unwrap();
        let observation = public
            .confirmation(tx_id, included, GENESIS + height * 10)
            .unwrap();
        if height < 7 {
            assert!(!observation.confirmed);
        } else {
            assert!(observation.confirmed);
            assert!(!observation.reorged);
            assert!(!observation.finalized && !observation.execution_authority);
            if height == 7 {
                assert_eq!(observation.depth, Some(6));
                first_confirmation = Some(serde_json::to_value(&observation).unwrap());
            }
        }
        if height == 16 {
            // Both endpoints are actual admitted headers. Retarget applies at
            // height 16 using genesis and height 15, not sixteen time gaps.
            assert_eq!(
                packet.header.target,
                consensus::retarget(
                    first.header.target,
                    GENESIS,
                    GENESIS + 150,
                    16,
                    10,
                    first.header.target,
                )
                .unwrap()
            );
        }
    }
    let confirmed_state = public.read_active().unwrap();
    let confirmed_work = public.stats().unwrap()["chainwork_hex"].clone();
    let mut private_tip = settings.genesis();
    let mut withheld = Vec::new();
    for height in 1..=18 {
        let packet = extend(&mut private, private_tip, height, vec![], 1);
        private_tip = packet.id().unwrap();
        withheld.push(packet);
        if height == 17 {
            assert_eq!(private.stats().unwrap()["chainwork_hex"], confirmed_work);
        }
    }
    // Distinct databases and no packet exchange until after the observation.
    assert!(public.packet(private_tip).is_err());
    assert_eq!(public.read_active().unwrap(), confirmed_state);
    let now = GENESIS + 180;
    for packet in withheld.iter().take(17) {
        let id = public.admit(packet, now).unwrap();
        assert_eq!(id, packet.id().unwrap());
        assert_eq!(
            public.packet(id).unwrap().encode().unwrap(),
            packet.encode().unwrap()
        );
    }
    // Admission alone does not activate. Equal cumulative work must keep the
    // public branch even though the other branch has a fully valid history.
    let equal_tip = withheld[16].id().unwrap();
    assert_eq!(
        public.activate_observed(equal_tip, now).unwrap(),
        public_tip
    );
    assert_eq!(public.read_active().unwrap(), confirmed_state);
    assert_eq!(public.stats().unwrap()["chainwork_hex"], confirmed_work);
    let final_packet = withheld.last().unwrap();
    public.admit(final_packet, now).unwrap();
    assert_eq!(
        public.activate_observed(private_tip, now).unwrap(),
        private_tip
    );
    let after = public.confirmation(tx_id, included, now).unwrap();
    assert!(!after.confirmed && after.reorged);
    assert_eq!(after.depth, None);
    assert_eq!(after.work_delta, None);
    assert!(!after.finalized && !after.execution_authority);
    assert_eq!(
        public.read_active().unwrap().2,
        private.read_active().unwrap().2
    );
    let reorged_state = public.read_active().unwrap();
    drop(public);
    let reopened = Node::open_with_authenticated_state(&public_path, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), reorged_state);
    assert_eq!(
        serde_json::to_value(reopened.confirmation(tx_id, included, now).unwrap()).unwrap(),
        serde_json::to_value(&after).unwrap()
    );
    eprintln!(
        "pon_native_confirmation_risk_v1 {}",
        json!({
            "schema":"pon-native-confirmation-risk-v1",
            "first_confirmation":first_confirmation.unwrap(),
            "after_publication":after,
            "public_height_before_release":17,"private_height_at_release":18,
            "public_chainwork_hex":confirmed_work,
            "private_chainwork_hex":reopened.stats().unwrap()["chainwork_hex"],
            "equal_work_kept_existing_tip":true,"reopened_state_and_observation_match":true,
            "actual_complete_pnw1_packets":35,
            "logical_clock_schedule":true,"attacker_work_fraction_measured":false,
            "attack_profitability_measured":false,"wall_clock_cadence_measured":false,
            "default_consensus_rules_changed":false,"production_activation":false
        })
    );
}

fn hash_value(value: &Value, name: &str) -> Hash {
    hex::decode(value[name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn research_risk_vectors_match_current_native_integer_and_clock_rules() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/pon-risk-native-vectors-v1.json"
    ))
    .unwrap();
    assert_eq!(vectors["schema"], "pon-risk-native-vectors-v1");
    for row in vectors["retarget"].as_array().unwrap() {
        let result = consensus::retarget(
            hash_value(row, "parent_target"),
            row["first"].as_u64().unwrap(),
            row["last"].as_u64().unwrap(),
            row["interval"].as_u64().unwrap(),
            row["spacing"].as_u64().unwrap(),
            hash_value(row, "pow_limit"),
        );
        if let Some(code) = row.get("error") {
            assert_eq!(
                result.unwrap_err().to_string(),
                code.as_str().unwrap(),
                "{}",
                row["name"]
            );
        } else {
            let target = result.unwrap();
            assert_eq!(hex::encode(target), row["target"], "{}", row["name"]);
            assert_eq!(
                hex::encode(consensus::required_work(target).unwrap().bytes()),
                row["required_work"],
                "{}",
                row["name"]
            );
        }
    }
    for row in vectors["time"].as_array().unwrap() {
        let ancestors: Vec<_> = row["ancestors_parent_first"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap())
            .collect();
        let result = consensus::check_time(
            row["candidate"].as_u64().unwrap(),
            &ancestors,
            row["now"].as_u64().unwrap(),
            row["skew"].as_u64().unwrap(),
        );
        if let Some(code) = row.get("error") {
            assert_eq!(
                result.unwrap_err().to_string(),
                code.as_str().unwrap(),
                "{}",
                row["name"]
            );
        } else {
            result.unwrap();
        }
    }
}
