use ed25519_dalek::{Signer, SigningKey};
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{
        lifecycle_v2::{verify_lifecycle_admission, verify_lifecycle_statement},
        AdmissionError, TaskMaterial,
    },
};
use trnm_protocol::{
    pon_wire::hash,
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        QualifiedWorkTask, SignedQualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS,
        MATRIX_ARTIFACT_BYTES,
    },
};

struct Fixture {
    lease: DemandLeaseV2,
    signed: SignedLifecycleTaskV2,
    key: SigningKey,
    model: Vec<u8>,
    input: Vec<u8>,
    a: Vec<u32>,
    b: Vec<u32>,
}
impl Fixture {
    fn new(a: Vec<u32>, b: Vec<u32>) -> Self {
        let key = SigningKey::from_bytes(&[23; 32]);
        let mut lease = DemandLeaseV2 {
            slot: 1,
            purpose: TaskPurpose::InferenceContraction,
            network: [1; 32],
            parameters: [2; 32],
            demand_id: [1; 32],
            requester: [3; 32],
            source: key.verifying_key().to_bytes(),
            source_record: [4; 32],
            authorization_scope: [5; 32],
            availability_manifest: [6; 32],
            availability_root: [7; 32],
            generation: 1,
            revision: 1,
            not_before: 10,
            expires: 20,
            available_until: 120,
            cost_class: 1,
        };
        lease.demand_id = lease.derived_demand_id();
        let model: Vec<_> = a.iter().flat_map(|v| v.to_le_bytes()).collect();
        let input: Vec<_> = b.iter().flat_map(|v| v.to_le_bytes()).collect();
        let model_id = hash(b"artifact", &[&model]);
        let mut manifest = QualifiedWorkTask {
            purpose: lease.purpose,
            cost_class: 1,
            numeric_encoding: 1,
            hardness_status: 0,
            reuse: 1,
            network: lease.network,
            parameters: lease.parameters,
            work_profile: QualifiedWorkTask::profile_id(),
            source: lease.source,
            demand_id: lease.demand_id,
            source_record: lease.bound_source_record().unwrap(),
            model: model_id,
            layer: QualifiedWorkTask::layer_id(model_id),
            input: hash(b"qualified-task-input-v1", &[&input]),
            recipe: QualifiedWorkTask::recipe_id(),
            matrix_task: pon_work::task_id(&a, &b).unwrap(),
            availability_manifest: lease.availability_manifest,
            availability_root: lease.availability_root,
            authorization_scope: lease.authorization_scope,
            withdrawal_head: lease.withdrawal_frontier().unwrap(),
            output_meter: [1; 32],
            rows: 64,
            inner: 64,
            columns: 64,
            demand_nonce: 1,
            not_before: 10,
            expires: 20,
            available_until: 120,
            logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
            model_bytes: MATRIX_ARTIFACT_BYTES,
            input_bytes: MATRIX_ARTIFACT_BYTES,
            useful_output_limit: 1,
        };
        manifest.output_meter = manifest.derived_output_meter();
        let signed = SignedLifecycleTaskV2 {
            lease_id: lease.id().unwrap(),
            manifest,
            signature: [0; 64],
        };
        let mut fixture = Self {
            lease,
            signed,
            key,
            model,
            input,
            a,
            b,
        };
        fixture.sign();
        fixture
    }
    fn dense() -> Self {
        Self::new(
            (0..4096).map(|i| (i * 17 + 3) % 1009).collect(),
            (0..4096).map(|i| (i * 7 + 5) % 1013).collect(),
        )
    }
    fn sign(&mut self) {
        self.signed.signature = self
            .key
            .sign(&self.signed.signing_message().unwrap())
            .to_bytes();
    }
    fn packet(&self) -> Vec<u8> {
        self.signed.encode().unwrap()
    }
    fn material(&self) -> TaskMaterial<'_> {
        TaskMaterial {
            model: &self.model,
            input: &self.input,
            a: &self.a,
            b: &self.b,
        }
    }
}

#[test]
fn actual_signed_material_and_renewal_revision_are_bound() {
    let fixture = Fixture::dense();
    let checked =
        verify_lifecycle_admission(&fixture.packet(), fixture.material(), &fixture.lease, 15)
            .unwrap();
    assert_eq!(checked.manifest_id(), fixture.signed.id().unwrap());
    assert_eq!(checked.output_meter(), fixture.signed.manifest.output_meter);
    let mut changed = fixture.lease.clone();
    changed.revision += 1;
    assert_eq!(
        verify_lifecycle_statement(&fixture.packet(), &changed, 15).unwrap_err(),
        AdmissionError::Context
    );
    for height in [9, 21] {
        assert_eq!(
            verify_lifecycle_statement(&fixture.packet(), &fixture.lease, height).unwrap_err(),
            AdmissionError::Height
        );
    }
}

#[test]
fn v1_signatures_unsigned_payloads_and_lease_context_tampering_do_not_admit() {
    let mut fixture = Fixture::dense();
    fixture.signed.signature = fixture
        .key
        .sign(&SignedQualifiedWorkTask::signing_message(&fixture.signed.manifest).unwrap())
        .to_bytes();
    assert_eq!(
        verify_lifecycle_statement(&fixture.packet(), &fixture.lease, 15).unwrap_err(),
        AdmissionError::Signature
    );
    fixture.sign();
    let mut packet = fixture.packet();
    let n = packet.len();
    packet[n - 64..].fill(0);
    assert_eq!(
        verify_lifecycle_statement(&packet, &fixture.lease, 15).unwrap_err(),
        AdmissionError::Signature
    );
    assert!(verify_lifecycle_statement(br#"{"qualified":true}"#, &fixture.lease, 15).is_err());
    fixture.signed.manifest.authorization_scope[0] ^= 1;
    fixture.sign();
    assert_eq!(
        verify_lifecycle_statement(&fixture.packet(), &fixture.lease, 15).unwrap_err(),
        AdmissionError::Authorization
    );
}

#[test]
fn genuine_signature_on_false_material_claim_does_not_verify_availability() {
    for model_claim in [true, false] {
        let mut fixture = Fixture::dense();
        if model_claim {
            fixture.signed.manifest.model = [99; 32];
            fixture.signed.manifest.layer = QualifiedWorkTask::layer_id([99; 32]);
        } else {
            fixture.signed.manifest.input = [99; 32];
        }
        fixture.signed.manifest.output_meter = fixture.signed.manifest.derived_output_meter();
        fixture.sign();
        verify_lifecycle_statement(&fixture.packet(), &fixture.lease, 15).unwrap();
        let error =
            verify_lifecycle_admission(&fixture.packet(), fixture.material(), &fixture.lease, 15)
                .unwrap_err();
        assert_eq!(
            error,
            if model_claim {
                AdmissionError::Model
            } else {
                AdmissionError::Input
            }
        );
    }
}

#[test]
fn cheap_legal_matrices_remain_experimental_without_accepted_cost_claim() {
    let identity: Vec<_> = (0..4096).map(|i| u32::from(i / 64 == i % 64)).collect();
    for fixture in [
        Fixture::new(vec![0; 4096], vec![0; 4096]),
        Fixture::new(identity.clone(), identity),
        Fixture::new(vec![1; 4096], vec![1; 4096]),
    ] {
        verify_lifecycle_admission(&fixture.packet(), fixture.material(), &fixture.lease, 15)
            .unwrap();
        assert_eq!(fixture.signed.manifest.hardness_status, 0);
        let mut manifest = fixture.signed.manifest.clone();
        manifest.hardness_status = 1;
        assert!(manifest.encode().is_err());
    }
}
