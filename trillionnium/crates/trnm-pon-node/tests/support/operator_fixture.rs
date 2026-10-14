use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    operator_deployment::{self as actors, BootstrapBundle, OperatorDeploymentSpec},
    Node, Packet, Settings,
};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
};
pub fn secret(i: u8) -> String {
    hex::encode([i + 71; 32])
}
pub fn public(i: u8) -> String {
    public_key_hex(&signing_key_from_hex(&secret(i)).unwrap())
}
pub fn key(i: u8) -> Hash {
    hex::decode(public(i)).unwrap().try_into().unwrap()
}
pub fn signature(i: u8, message: &[u8]) -> [u8; 64] {
    hex::decode(sign_hex(
        &signing_key_from_hex(&secret(i)).unwrap(),
        message,
    ))
    .unwrap()
    .try_into()
    .unwrap()
}
pub fn fixture() -> (
    OperatorDeploymentSpec,
    BootstrapBundle,
    Vec<u8>,
    Vec<u8>,
    Settings,
) {
    let model = (0..4096u32)
        .flat_map(|i| ((i * 7 + 3) % 101).to_le_bytes())
        .collect::<Vec<_>>();
    let input = (0..4096u32)
        .flat_map(|i| ((i * 13 + 5) % 103).to_le_bytes())
        .collect::<Vec<_>>();
    let mut evaluators = (2..5).map(public).collect::<Vec<_>>();
    evaluators.sort();
    let mut allocations = (0..6)
        .map(|i| actors::GenesisAllocation {
            public_key: public(i),
            balance: 50_000_000,
        })
        .collect::<Vec<_>>();
    allocations.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    let spec = OperatorDeploymentSpec {
        schema: "pon-native-operator-actors-spec-v1".into(),
        profile: actors::PROFILE.into(),
        deployment_id: hex::encode([31; 32]),
        genesis_timestamp: 1_800_000_000,
        evaluation_profile: "native-public-evaluation-dev-v1".into(),
        task_profile: "signed-task-lifecycle-dev-v4".into(),
        model_profile: "linear-expert-dev-v1".into(),
        source: public(0),
        requester: public(1),
        evaluators,
        allocations,
        bootstrap: actors::BootstrapMaterialSpec {
            model: hex::encode(hash(b"artifact", &[&model])),
            input: hex::encode(hash(b"qualified-task-input-v1", &[&input])),
            source_record: hex::encode([32; 32]),
            authorization_scope: hex::encode([33; 32]),
            availability_manifest: hex::encode([34; 32]),
            availability_root: hex::encode([35; 32]),
        },
        production_activation: false,
        public_network_ready: false,
        independent_governance_accepted: false,
        hardness_accepted: false,
        demand_truth_accepted: false,
        objective_model_quality: false,
    };
    let template = actors::prepare(&spec, &model, &input).unwrap();
    let source = actors::approval(
        &template,
        "source",
        hex::encode(signature(
            0,
            &hex::decode(&template.source_message).unwrap(),
        )),
    )
    .unwrap();
    let requester = actors::approval(
        &template,
        "requester",
        hex::encode(signature(
            1,
            &hex::decode(&template.requester_message).unwrap(),
        )),
    )
    .unwrap();
    let bundle = actors::assemble(&template, &source, &requester).unwrap();
    let settings =
        Settings::development_with_operator_actors(&spec, &bundle, &model, &input).unwrap();
    (spec, bundle, model, input, settings)
}
pub fn transaction(
    s: &Settings,
    who: u8,
    account_sequence: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut tx = Envelope {
        network: s.network(),
        sender: key(who),
        // Public account sequence for replay protection, not a cryptographic signing nonce.
        nonce: account_sequence,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(who, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}
pub fn transfer(
    s: &Settings,
    who: u8,
    account_sequence: u64,
    receiver: u8,
    amount: u64,
) -> Vec<u8> {
    let mut p = key(receiver).to_vec();
    p.extend(amount.to_le_bytes());
    transaction(s, who, account_sequence, 1, p)
}
pub fn make(
    node: &Node,
    parent: Hash,
    txs: Vec<Vec<u8>>,
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    model: &[u8],
    input: &[u8],
) -> Packet {
    use trnm_crypto_primitives::qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    };
    let (a, b) = derive_matrices(model, input).unwrap();
    let height = node.parent_height(parent).unwrap() + 1;
    let material = TaskMaterial {
        model,
        input,
        a: &a,
        b: &b,
    };
    let admission =
        verify_lifecycle_admission(&signed.encode().unwrap(), material, lease, height).unwrap();
    node.make_with_task(
        parent,
        txs,
        key(5),
        node.settings().genesis_time() + height * 10,
        4096,
        &admission,
        TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        },
    )
    .unwrap()
}
