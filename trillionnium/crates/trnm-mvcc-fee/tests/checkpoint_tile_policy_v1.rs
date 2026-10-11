//! Only policy/namespace controls; the Node tests replay original material.
use serde_json::json;
use trnm_mvcc_fee::{
    checkpoint_tile_material_v1::policy_id,
    checkpoint_tile_policy_v1::{CheckpointTilePolicySpecV1, PROFILE},
    deployment_actors::canonical,
    pon_executor::Config,
};
fn policy() -> CheckpointTilePolicySpecV1 {
    CheckpointTilePolicySpecV1 {
        schema: "checkpoint-tile-context-free-policy-v1".into(),
        material_policy: hex::encode(policy_id()),
        checkpoint_sha256: "01".repeat(32),
        checkpoint_bytes: 100,
        activation_sha256: "02".repeat(32),
        a_sha256: "03".repeat(32),
        b_sha256: "04".repeat(32),
        model: "05".repeat(32),
        input: "06".repeat(32),
        matrix_task: "07".repeat(32),
        maintenance_only: true,
        useful_output_limit: 0,
        chain_authority: false,
        hardness_accepted: false,
        genuine_demand_verified: false,
        full_forward_verified: false,
        marginal_contribution_accepted: false,
        public_network_ready: false,
    }
}
#[test]
fn canonical_bounded_policy_false_claims_and_exact_fresh_context() {
    let p = policy();
    assert_eq!(
        CheckpointTilePolicySpecV1::decode(&p.canonical().unwrap()).unwrap(),
        p
    );
    for flag in [
        "chain_authority",
        "hardness_accepted",
        "genuine_demand_verified",
        "full_forward_verified",
        "marginal_contribution_accepted",
        "public_network_ready",
    ] {
        let mut v = serde_json::to_value(&p).unwrap();
        v[flag] = json!(true);
        assert_eq!(
            CheckpointTilePolicySpecV1::decode(&canonical(&v).unwrap()).unwrap_err(),
            "CHECKPOINT_POLICY_ACCEPTANCE"
        );
    }
    for (field, value) in [
        ("useful_output_limit", json!(1)),
        ("maintenance_only", json!(false)),
        ("checkpoint_bytes", json!(536870913)),
        ("checkpoint_sha256", json!("00".repeat(32))),
        ("extra", json!(1)),
    ] {
        let mut v = serde_json::to_value(&p).unwrap();
        v[field] = value;
        assert!(CheckpointTilePolicySpecV1::decode(&canonical(&v).unwrap()).is_err());
    }
    let text = String::from_utf8(p.canonical().unwrap()).unwrap();
    let duplicate = format!(
        "{{\"schema\":\"checkpoint-tile-context-free-policy-v1\",{}",
        &text[1..]
    );
    assert!(CheckpointTilePolicySpecV1::decode(duplicate.as_bytes()).is_err());
    assert!(CheckpointTilePolicySpecV1::decode(&vec![b' '; 32769]).is_err());
    let original = Config::installed_with_profiles(
        "native-public-evaluation-dev-v1",
        "signed-task-lifecycle-dev-v4",
    )
    .unwrap();
    let a = Config::installed_with_checkpoint_tile_policy(
        "native-public-evaluation-dev-v1",
        "linear-expert-dev-v1",
        &p,
    )
    .unwrap();
    assert_eq!(a.task_profile(), PROFILE);
    assert_eq!(a.params["consensus_revision"], 10);
    assert_ne!(original.network, a.network);
    assert_ne!(original.parameters, a.parameters);
    assert!(original.checkpoint_tile_policy().unwrap().is_none());
    for field in [
        "checkpoint_sha256",
        "activation_sha256",
        "a_sha256",
        "b_sha256",
        "model",
        "input",
        "matrix_task",
    ] {
        let mut v = serde_json::to_value(&p).unwrap();
        v[field] = json!("71".repeat(32));
        let p = CheckpointTilePolicySpecV1::decode(&canonical(&v).unwrap()).unwrap();
        let b = Config::installed_with_checkpoint_tile_policy(
            "native-public-evaluation-dev-v1",
            "linear-expert-dev-v1",
            &p,
        )
        .unwrap();
        assert_ne!(a.network, b.network);
        assert_ne!(a.parameters, b.parameters);
    }
    assert!(Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).is_err());
    let again = Config::installed_with_profiles(
        "native-public-evaluation-dev-v1",
        "signed-task-lifecycle-dev-v4",
    )
    .unwrap();
    assert_eq!(again.network, original.network);
    assert_eq!(again.parameters, original.parameters);
}
