use trnm_protocol::qualified_work_task::{
    lifecycle_v2::{
        DemandLeaseV2, DemandRevocationV2, LifecycleError, SignedLifecycleTaskV2,
        DEMAND_LEASE_BYTES, DEMAND_REVOCATION_BYTES, LIFECYCLE_TASK_BYTES,
    },
    QualifiedWorkTask, SignedQualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS,
    MATRIX_ARTIFACT_BYTES,
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
fn exact_lease_vector_and_all_packet_truncations() {
    let current = lease();
    let encoded = current.encode().unwrap();
    assert_eq!(encoded.len(), DEMAND_LEASE_BYTES);
    assert_eq!(&encoded[..8], b"QDL2\x02\x00\x03\x04");
    assert_eq!(DemandLeaseV2::decode(&encoded).unwrap(), current);
    // Independent Python struct/sha256 vector, not computed by this Rust codec.
    assert_eq!(
        hex::encode(current.id().unwrap()),
        "2e08ceced6065dea18e74f71b61ad11dfbd9451d91f9455efc641f49a8a3e119"
    );
    for n in 0..encoded.len() {
        assert_eq!(
            DemandLeaseV2::decode(&encoded[..n]),
            Err(LifecycleError::Length)
        );
    }
    let revoke = DemandRevocationV2 {
        slot: current.slot,
        network: current.network,
        parameters: current.parameters,
        demand_id: current.demand_id,
        requester: current.requester,
        expected_revision: current.revision,
    };
    let encoded = revoke.encode().unwrap();
    assert_eq!(encoded.len(), DEMAND_REVOCATION_BYTES);
    assert_eq!(DemandRevocationV2::decode(&encoded).unwrap(), revoke);
    for n in 0..encoded.len() {
        assert_eq!(
            DemandRevocationV2::decode(&encoded[..n]),
            Err(LifecycleError::Length)
        );
    }
    let signed = task(&current);
    let encoded = signed.encode().unwrap();
    assert_eq!(encoded.len(), LIFECYCLE_TASK_BYTES);
    assert_eq!(SignedLifecycleTaskV2::decode(&encoded).unwrap(), signed);
    for n in 0..encoded.len() {
        assert_eq!(
            SignedLifecycleTaskV2::decode(&encoded[..n]),
            Err(LifecycleError::Length)
        );
    }
    for mut packet in [
        current.encode().unwrap(),
        revoke.encode().unwrap(),
        signed.encode().unwrap(),
    ] {
        packet.push(0);
        assert!(DemandLeaseV2::decode(&packet).is_err());
        assert!(DemandRevocationV2::decode(&packet).is_err());
        assert!(SignedLifecycleTaskV2::decode(&packet).is_err());
    }
}

#[test]
fn bounded_context_identity_window_padding_and_unaccepted_cost() {
    for mutation in 0..8 {
        let mut current = lease();
        match mutation {
            0 => current.slot = 32,
            1 => current.generation = 0,
            2 => current.revision = 0,
            3 => current.requester = current.source,
            4 => current.available_until += 1,
            5 => current.expires = current.not_before + 1001,
            6 => current.cost_class = 2,
            _ => current.demand_id[0] ^= 1,
        }
        assert!(current.encode().is_err());
    }
    let mut current = lease();
    current.not_before = u64::MAX - 1;
    current.expires = u64::MAX;
    current.available_until = u64::MAX;
    assert_eq!(current.encode(), Err(LifecycleError::Validity));
    for index in 337..344 {
        let mut encoded = lease().encode().unwrap();
        encoded[index] = 1;
        assert_eq!(
            DemandLeaseV2::decode(&encoded),
            Err(LifecycleError::Reserved)
        );
    }
    let mut encoded = lease().encode().unwrap();
    encoded[4] = 1;
    assert_eq!(
        DemandLeaseV2::decode(&encoded),
        Err(LifecycleError::Version)
    );
    assert!(DemandLeaseV2::decode(br#"{"qualified":true}"#).is_err());
}

#[test]
fn new_signature_domain_binds_lease_and_signature_does_not_mint_identity() {
    let signed = task(&lease());
    assert_ne!(
        signed.signing_message().unwrap(),
        SignedQualifiedWorkTask::signing_message(&signed.manifest).unwrap()
    );
    assert_ne!(signed.id().unwrap(), signed.manifest.id().unwrap());
    let mut changed = signed.clone();
    changed.signature[0] = 1;
    assert_eq!(changed.id().unwrap(), signed.id().unwrap());
    changed.lease_id[0] ^= 1;
    assert_ne!(changed.id().unwrap(), signed.id().unwrap());
    assert_ne!(
        changed.signing_message().unwrap(),
        signed.signing_message().unwrap()
    );
    let old = SignedQualifiedWorkTask {
        manifest: signed.manifest.clone(),
        signature: signed.signature,
    }
    .encode()
    .unwrap();
    assert!(SignedLifecycleTaskV2::decode(&old).is_err());
    assert!(SignedQualifiedWorkTask::decode(&signed.encode().unwrap()).is_err());
}

#[test]
fn renew_does_not_change_output_meter_or_demand_identity() {
    let current = lease();
    let first = task(&current);
    let mut renewed = current.clone();
    renewed.revision += 1;
    renewed.not_before = 150;
    renewed.expires = 300;
    renewed.available_until = 400;
    let mut second = task(&renewed);
    second.manifest.demand_nonce += 1;
    assert_eq!(current.demand_id, renewed.demand_id);
    assert_eq!(first.manifest.output_meter, second.manifest.output_meter);
    assert_ne!(first.lease_id, second.lease_id);
    assert_ne!(first.id().unwrap(), second.id().unwrap());
}
