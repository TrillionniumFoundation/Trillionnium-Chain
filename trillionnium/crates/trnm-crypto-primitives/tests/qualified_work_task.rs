use ed25519_dalek::{Signer, SigningKey};
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{
        derive_matrices, verify_development_admission, verify_development_statement,
        AdmissionContext, AdmissionError, TaskMaterial,
    },
};
use trnm_protocol::{
    pon_wire::hash,
    qualified_work_task::{
        QualifiedWorkTask, SignedQualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS,
        MATRIX_ARTIFACT_BYTES,
    },
};

struct Fixture {
    task: QualifiedWorkTask,
    key: SigningKey,
    model: Vec<u8>,
    input: Vec<u8>,
    a: Vec<u32>,
    b: Vec<u32>,
}
impl Fixture {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[23; 32]);
        let a: Vec<u32> = (0..4096).map(|i| (i * 17 + 3) % 1009).collect();
        let b: Vec<u32> = (0..4096).map(|i| (i * 7 + 5) % 1013).collect();
        let model: Vec<u8> = a.iter().flat_map(|value| value.to_le_bytes()).collect();
        let input: Vec<u8> = b.iter().flat_map(|value| value.to_le_bytes()).collect();
        let mut task = QualifiedWorkTask {
            purpose: TaskPurpose::InferenceContraction,
            cost_class: 1,
            numeric_encoding: 1,
            hardness_status: 0,
            reuse: 1,
            network: [1; 32],
            parameters: [2; 32],
            work_profile: QualifiedWorkTask::profile_id(),
            source: key.verifying_key().to_bytes(),
            demand_id: [4; 32],
            source_record: [5; 32],
            model: hash(b"artifact", &[&model]),
            layer: [7; 32],
            input: hash(b"qualified-task-input-v1", &[&input]),
            recipe: QualifiedWorkTask::recipe_id(),
            matrix_task: pon_work::task_id(&a, &b).unwrap(),
            availability_manifest: [10; 32],
            availability_root: [11; 32],
            authorization_scope: [12; 32],
            withdrawal_head: [13; 32],
            output_meter: [14; 32],
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
        task.layer = QualifiedWorkTask::layer_id(task.model);
        task.output_meter = task.derived_output_meter();
        Self {
            task,
            key,
            model,
            input,
            a,
            b,
        }
    }
    fn packet(&self) -> Vec<u8> {
        SignedQualifiedWorkTask {
            manifest: self.task.clone(),
            signature: self
                .key
                .sign(&SignedQualifiedWorkTask::signing_message(&self.task).unwrap())
                .to_bytes(),
        }
        .encode()
        .unwrap()
    }
    fn context(&self) -> AdmissionContext {
        AdmissionContext {
            network: self.task.network,
            parameters: self.task.parameters,
            source: self.task.source,
            demand_id: self.task.demand_id,
            source_record: self.task.source_record,
            authorization_scope: self.task.authorization_scope,
            withdrawal_head: self.task.withdrawal_head,
            availability_manifest: self.task.availability_manifest,
            availability_root: self.task.availability_root,
            height: 15,
            required_retention_blocks: 100,
        }
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
fn real_signed_material_admission_and_recipe_derivation_match_every_field() {
    let fixture = Fixture::new();
    let admission =
        verify_development_admission(&fixture.packet(), fixture.material(), &fixture.context())
            .unwrap();
    assert_eq!(admission.manifest_id(), fixture.task.id().unwrap());
    assert_eq!(admission.matrix_task(), fixture.task.matrix_task);
    assert_eq!(
        derive_matrices(&fixture.model, &fixture.input).unwrap(),
        (fixture.a, fixture.b)
    );
}

#[test]
fn unsigned_true_zero_signature_tampering_and_weak_source_never_admit() {
    let mut fixture = Fixture::new();
    assert!(verify_development_statement(br#"{"qualified":true}"#, &fixture.context()).is_err());
    let mut packet = fixture.packet();
    packet[588..].fill(0);
    assert_eq!(
        verify_development_statement(&packet, &fixture.context()).unwrap_err(),
        AdmissionError::Signature
    );
    packet = fixture.packet();
    packet[536] ^= 2; // demand nonce is signed even though it is not a second meter.
    assert_eq!(
        verify_development_statement(&packet, &fixture.context()).unwrap_err(),
        AdmissionError::Signature
    );
    fixture.task.source = [0; 32];
    fixture.task.source[0] = 1; // identity point.
    assert_eq!(
        verify_development_statement(&fixture.packet(), &fixture.context()).unwrap_err(),
        AdmissionError::Signature
    );
}

#[test]
fn source_demand_scope_withdrawal_and_availability_pinnings_cannot_be_substituted() {
    let fixture = Fixture::new();
    for change in 0..9 {
        let mut context = fixture.context();
        let expected = match change {
            0 => {
                context.network[0] ^= 1;
                AdmissionError::Context
            }
            1 => {
                context.parameters[0] ^= 1;
                AdmissionError::Context
            }
            2 => {
                context.source[0] ^= 1;
                AdmissionError::Source
            }
            3 => {
                context.demand_id[0] ^= 1;
                AdmissionError::Demand
            }
            4 => {
                context.source_record[0] ^= 1;
                AdmissionError::Demand
            }
            5 => {
                context.authorization_scope[0] ^= 1;
                AdmissionError::Authorization
            }
            6 => {
                context.withdrawal_head[0] ^= 1;
                AdmissionError::Withdrawal
            }
            7 => {
                context.availability_manifest[0] ^= 1;
                AdmissionError::Availability
            }
            _ => {
                context.availability_root[0] ^= 1;
                AdmissionError::Availability
            }
        };
        assert_eq!(
            verify_development_statement(&fixture.packet(), &context).unwrap_err(),
            expected
        );
    }
    let mut context = fixture.context();
    context.height = 21;
    assert_eq!(
        verify_development_statement(&fixture.packet(), &context).unwrap_err(),
        AdmissionError::Height
    );
    context = fixture.context();
    context.required_retention_blocks = u64::MAX;
    assert_eq!(
        verify_development_statement(&fixture.packet(), &context).unwrap_err(),
        AdmissionError::Availability
    );
}

#[test]
fn rehashed_matrix_claim_cannot_substitute_a_different_contraction_or_noncanonical_field() {
    let mut fixture = Fixture::new();
    fixture.a[0] += 1;
    fixture.task.matrix_task = pon_work::task_id(&fixture.a, &fixture.b).unwrap();
    fixture.task.output_meter = fixture.task.derived_output_meter();
    assert_eq!(
        verify_development_admission(&fixture.packet(), fixture.material(), &fixture.context())
            .unwrap_err(),
        AdmissionError::MatrixBinding
    );
    fixture = Fixture::new();
    fixture.model[0] ^= 1;
    assert_eq!(
        verify_development_admission(&fixture.packet(), fixture.material(), &fixture.context())
            .unwrap_err(),
        AdmissionError::Model
    );
    fixture = Fixture::new();
    fixture.input[0] ^= 1;
    assert_eq!(
        verify_development_admission(&fixture.packet(), fixture.material(), &fixture.context())
            .unwrap_err(),
        AdmissionError::Input
    );
    fixture = Fixture::new();
    fixture.model[..4].copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
    fixture.task.model = hash(b"artifact", &[&fixture.model]);
    fixture.task.layer = QualifiedWorkTask::layer_id(fixture.task.model);
    fixture.task.output_meter = fixture.task.derived_output_meter();
    assert_eq!(
        verify_development_admission(&fixture.packet(), fixture.material(), &fixture.context())
            .unwrap_err(),
        AdmissionError::Numeric
    );
}

#[test]
fn repeated_challenges_bind_one_product_meter_and_maintenance_produces_no_learning_credit() {
    let mut fixture = Fixture::new();
    let admission =
        verify_development_admission(&fixture.packet(), fixture.material(), &fixture.context())
            .unwrap();
    let mut results = Vec::new();
    for challenge in [[17; 32], [18; 32]] {
        let proof = pon_work::prove(challenge, &fixture.a, &fixture.b).unwrap();
        let work =
            pon_work::verify(challenge, fixture.task.matrix_task, [255; 32], &proof).unwrap();
        results.push(admission.bind_verified_output(&work).unwrap());
    }
    assert_eq!(results[0].meter(), results[1].meter());
    assert_eq!(results[0].product(), results[1].product());
    assert_ne!(results[0].challenge(), results[1].challenge());
    assert_eq!(results[0].maximum_output_credit(), 1);
    fixture.task.purpose = TaskPurpose::Maintenance;
    fixture.task.useful_output_limit = 0;
    let maintenance =
        verify_development_admission(&fixture.packet(), fixture.material(), &fixture.context())
            .unwrap();
    assert_eq!(maintenance.manifest().useful_output_limit, 0);
    assert_eq!(maintenance.purpose(), TaskPurpose::Maintenance);
}
