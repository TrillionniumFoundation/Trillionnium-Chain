use trnm_protocol::qualified_work_task::{
    lifecycle_v2::{DemandLeaseV2, LifecycleError, SignedLifecycleTaskV2},
    lifecycle_v3::{AtomicRenewTaskV3, ATOMIC_RENEW_BYTES, ATOMIC_RENEW_TAG},
    QualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS, MATRIX_ARTIFACT_BYTES,
};

fn lease() -> DemandLeaseV2 {
    let mut value = DemandLeaseV2 {
        slot: 3,
        purpose: TaskPurpose::InferenceContraction,
        network: [1; 32],
        parameters: [2; 32],
        demand_id: [1; 32],
        requester: [3; 32],
        source: [4; 32],
        source_record: [5; 32],
        authorization_scope: [6; 32],
        availability_manifest: [7; 32],
        availability_root: [8; 32],
        generation: 7,
        revision: 3,
        not_before: 101,
        expires: 200,
        available_until: 300,
        cost_class: 1,
    };
    value.demand_id = value.derived_demand_id();
    value
}
fn task(current: &DemandLeaseV2) -> SignedLifecycleTaskV2 {
    let mut manifest = QualifiedWorkTask {
        purpose: current.purpose,
        cost_class: 1,
        numeric_encoding: 1,
        hardness_status: 0,
        reuse: 1,
        network: current.network,
        parameters: current.parameters,
        work_profile: QualifiedWorkTask::profile_id(),
        source: current.source,
        demand_id: current.demand_id,
        source_record: current.bound_source_record().unwrap(),
        model: [10; 32],
        layer: QualifiedWorkTask::layer_id([10; 32]),
        input: [11; 32],
        recipe: QualifiedWorkTask::recipe_id(),
        matrix_task: [12; 32],
        availability_manifest: current.availability_manifest,
        availability_root: current.availability_root,
        authorization_scope: current.authorization_scope,
        withdrawal_head: current.withdrawal_frontier().unwrap(),
        output_meter: [1; 32],
        rows: 64,
        inner: 64,
        columns: 64,
        demand_nonce: 1,
        not_before: current.not_before,
        expires: current.expires,
        available_until: current.available_until,
        logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
        model_bytes: MATRIX_ARTIFACT_BYTES,
        input_bytes: MATRIX_ARTIFACT_BYTES,
        useful_output_limit: 1,
    };
    manifest.output_meter = manifest.derived_output_meter();
    SignedLifecycleTaskV2 {
        lease_id: current.id().unwrap(),
        manifest,
        signature: [0; 64],
    }
}

#[test]
fn exact_atomic_codec_rejects_every_cut_and_trailing_and_cross_bound_statement() {
    let lease = lease();
    let value = AtomicRenewTaskV3 {
        signed: task(&lease),
        lease,
    };
    let raw = value.encode().unwrap();
    assert_eq!(raw.len(), 1028);
    assert_eq!(ATOMIC_RENEW_BYTES, 1028);
    assert_eq!(AtomicRenewTaskV3::decode(&raw).unwrap(), value);
    for n in 0..raw.len() {
        assert_eq!(
            AtomicRenewTaskV3::decode(&raw[..n]),
            Err(LifecycleError::Length)
        );
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(
        AtomicRenewTaskV3::decode(&trailing),
        Err(LifecycleError::Length)
    );
    for offset in [344 + 4, 344 + 36 + 12, 344 + 36 + 44] {
        let mut altered = raw.clone();
        altered[offset] ^= 1;
        assert!(AtomicRenewTaskV3::decode(&altered).is_err());
    }
    // An exact structural packet with zero signature is still only decoded bytes.
    assert_eq!(value.signed.signature, [0; 64]);
    let envelope = trnm_protocol::pon_wire::Envelope {
        network: value.lease.network,
        sender: value.lease.requester,
        nonce: 1,
        expiry: 200,
        fee_limit: 100000,
        tag: ATOMIC_RENEW_TAG,
        payload: raw,
        signature: [0; 64],
    };
    let encoded = envelope.encode().unwrap();
    assert_eq!(encoded.len(), 1187);
    assert_eq!(
        trnm_protocol::pon_wire::Envelope::decode(&encoded).unwrap(),
        envelope
    );
}
#[test]
fn fresh_context_changes_both_inner_and_outer_signed_messages() {
    let lease = lease();
    let first = AtomicRenewTaskV3 {
        signed: task(&lease),
        lease,
    };
    let mut lease = first.lease.clone();
    lease.network = [9; 32];
    lease.parameters = [10; 32];
    lease.demand_id = lease.derived_demand_id();
    let second = AtomicRenewTaskV3 {
        signed: task(&lease),
        lease,
    };
    assert_ne!(
        first.signed.signing_message().unwrap(),
        second.signed.signing_message().unwrap()
    );
    assert_ne!(first.signed.id().unwrap(), second.signed.id().unwrap());
    let envelope = |request: &AtomicRenewTaskV3| trnm_protocol::pon_wire::Envelope {
        network: request.lease.network,
        sender: request.lease.requester,
        nonce: 1,
        expiry: 200,
        fee_limit: 100000,
        tag: ATOMIC_RENEW_TAG,
        payload: request.encode().unwrap(),
        signature: [0; 64],
    };
    assert_ne!(
        envelope(&first).signing_digest().unwrap(),
        envelope(&second).signing_digest().unwrap()
    );
}
