use trnm_protocol::qualified_work_task::{
    QualifiedWorkTask, SignedQualifiedWorkTask, TaskError, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS,
    MANIFEST_BYTES, MATRIX_ARTIFACT_BYTES, SIGNED_TASK_BYTES,
};

fn manifest() -> QualifiedWorkTask {
    let mut task = QualifiedWorkTask {
        purpose: TaskPurpose::InferenceContraction,
        cost_class: 1,
        numeric_encoding: 1,
        hardness_status: 0,
        reuse: 1,
        network: [1; 32],
        parameters: [2; 32],
        work_profile: QualifiedWorkTask::profile_id(),
        source: [3; 32],
        demand_id: [4; 32],
        source_record: [5; 32],
        model: [6; 32],
        layer: [7; 32],
        input: [8; 32],
        recipe: QualifiedWorkTask::recipe_id(),
        matrix_task: [9; 32],
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
    task
}

#[test]
fn exact_codec_roundtrip_and_every_truncation_reject() {
    let task = manifest();
    let bytes = task.encode().unwrap();
    assert_eq!(bytes.len(), MANIFEST_BYTES);
    assert_eq!(QualifiedWorkTask::decode(&bytes).unwrap(), task);
    for length in 0..MANIFEST_BYTES {
        assert_eq!(
            QualifiedWorkTask::decode(&bytes[..length]),
            Err(TaskError::Length)
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(QualifiedWorkTask::decode(&trailing), Err(TaskError::Length));
    let signed = SignedQualifiedWorkTask {
        manifest: task,
        signature: [0; 64],
    };
    let packet = signed.encode().unwrap();
    assert_eq!(packet.len(), SIGNED_TASK_BYTES);
    assert_eq!(SignedQualifiedWorkTask::decode(&packet).unwrap(), signed);
}

#[test]
fn accepted_hardness_unknown_profile_recipe_and_padding_have_no_encoding() {
    let mut task = manifest();
    task.hardness_status = 1;
    assert_eq!(task.encode(), Err(TaskError::HardnessNotAccepted));
    task = manifest();
    task.recipe = [15; 32];
    assert_eq!(task.encode(), Err(TaskError::Recipe));
    task = manifest();
    task.work_profile = [15; 32];
    assert_eq!(task.encode(), Err(TaskError::Profile));
    let mut bytes = manifest().encode().unwrap();
    bytes[11] = 1;
    assert_eq!(QualifiedWorkTask::decode(&bytes), Err(TaskError::Reserved));
    bytes = manifest().encode().unwrap();
    bytes[530] = 1;
    assert_eq!(QualifiedWorkTask::decode(&bytes), Err(TaskError::Reserved));
}

#[test]
fn exact_resource_bounds_and_maintenance_class_do_not_manufacture_learning_credit() {
    let mut task = manifest();
    task.logical_multiply_add_units -= 1;
    assert_eq!(task.encode(), Err(TaskError::CostClass));
    task = manifest();
    task.rows = 63;
    assert_eq!(task.encode(), Err(TaskError::Shape));
    task = manifest();
    task.model_bytes += 1;
    assert_eq!(task.encode(), Err(TaskError::Limits));
    task = manifest();
    task.expires = task.not_before + 1001;
    task.available_until = task.expires;
    assert_eq!(task.encode(), Err(TaskError::Validity));
    task = manifest();
    task.purpose = TaskPurpose::Maintenance;
    assert_eq!(task.encode(), Err(TaskError::Limits));
    task.useful_output_limit = 0;
    assert!(QualifiedWorkTask::decode(&task.encode().unwrap()).is_ok());
}

#[test]
fn demand_nonce_cannot_create_another_output_meter_and_every_material_identity_binds() {
    let task = manifest();
    let mut alternate = task.clone();
    alternate.demand_nonce += 1;
    assert_ne!(task.id().unwrap(), alternate.id().unwrap());
    assert_eq!(
        task.derived_output_meter(),
        alternate.derived_output_meter()
    );
    for change in 0..5 {
        alternate = task.clone();
        match change {
            0 => alternate.demand_id[0] ^= 1,
            1 => alternate.model[0] ^= 1,
            2 => alternate.layer[0] ^= 1,
            3 => alternate.input[0] ^= 1,
            _ => alternate.matrix_task[0] ^= 1,
        }
        assert!(matches!(
            alternate.encode(),
            Err(TaskError::OutputMeter | TaskError::Layer)
        ));
    }
}
