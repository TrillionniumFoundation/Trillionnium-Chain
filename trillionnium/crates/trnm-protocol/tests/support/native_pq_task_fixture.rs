//! NPQ4 fixtures use deliberately public deterministic research keys. Never deploy.
use ml_dsa::{Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey};
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES};
use trnm_protocol::pq_native_accounts_v2::{self as wire, Common, WitnessKey};

pub struct Key {
    signing: SigningKey<MlDsa65>,
    pub spki: Vec<u8>,
    pub id: [u8; 32],
}
impl Key {
    pub fn public_test_seed(value: u8) -> Self {
        let signing = SigningKey::<MlDsa65>::from_seed(&[value; 32].into());
        let mut spki = include_bytes!("../fixtures/pq_transfer/public.der")[..22].to_vec();
        spki.extend(signing.verifying_key().encode().as_slice());
        let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
        Self { signing, spki, id }
    }
}

pub struct Witness<'a> {
    pub key: &'a Key,
    pub role: u8,
    pub generation: u64,
    pub carried: bool,
}

pub fn signed(
    common: &Common,
    kind: u8,
    payload: &[u8],
    witnesses: &[Witness<'_>],
    randomness: Option<[u8; 32]>,
) -> Vec<u8> {
    let descriptors: Vec<_> = witnesses
        .iter()
        .map(|w| WitnessKey {
            role: w.role,
            generation: w.generation,
            key_id: w.key.id,
            spki: w.carried.then(|| w.key.spki.clone()),
        })
        .collect();
    let frames: Vec<_> = witnesses
        .iter()
        .enumerate()
        .map(|(index, witness)| {
            let statement = wire::signing_statement_for_profile(
                wire::AccountProfile::TasksV4,
                common,
                kind,
                payload,
                &descriptors,
                index,
            )
            .unwrap();
            let signature: Signature<MlDsa65> = match randomness {
                Some(rnd) => witness
                    .key
                    .signing
                    .expanded_key()
                    .sign_internal(&[&[0, 0], &statement], &rnd.into()),
                None => witness.key.signing.sign(&statement),
            };
            let mut frame = statement.to_vec();
            frame.extend((ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
            frame.extend(signature.to_bytes().as_slice());
            frame
        })
        .collect();
    wire::encode_for_profile(
        wire::AccountProfile::TasksV4,
        common,
        kind,
        payload,
        &descriptors,
        &frames,
    )
    .unwrap()
}

use trnm_protocol::pon_wire::{hash, Hash};
use trnm_protocol::qualified_work_task::{
    pq_lifecycle_v4::{DemandLeaseV4, DemandRevocationV4, TaskRegistrationV4},
    QualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS, MATRIX_ARTIFACT_BYTES,
};
pub fn common(context: wire::ChainContext, account: Hash, nonce: u64, generation: u64) -> Common {
    Common {
        context,
        account,
        nonce,
        generation,
        expires_at: 2000,
        max_fee: 100_000,
    }
}
pub fn lease(context: wire::ChainContext, requester: Hash, source: Hash) -> DemandLeaseV4 {
    let mut value = DemandLeaseV4 {
        slot: 0,
        purpose: TaskPurpose::InferenceContraction,
        network: context.network,
        parameters: context.parameters,
        demand_id: [1; 32],
        requester,
        source,
        source_record: hash(b"public-pq4-source-fixture", &[&source]),
        authorization_scope: hash(b"public-pq4-authority-fixture", &[&requester, &source]),
        availability_manifest: [81; 32],
        availability_root: [82; 32],
        generation: 1,
        revision: 1,
        not_before: 1,
        expires: 50,
        available_until: 150,
        cost_class: 1,
    };
    value.demand_id = value.derived_demand_id();
    value
}
pub fn material() -> (Vec<u8>, Vec<u8>, Vec<u32>, Vec<u32>) {
    let a: Vec<u32> = (0..4096).map(|i| ((19 * i + 23) % 271) as u32).collect();
    let b: Vec<u32> = (0..4096).map(|i| ((31 * i + 37) % 277) as u32).collect();
    (
        a.iter().flat_map(|n| n.to_le_bytes()).collect(),
        b.iter().flat_map(|n| n.to_le_bytes()).collect(),
        a,
        b,
    )
}
pub fn registration(
    lease: &DemandLeaseV4,
    task: Hash,
    sequence: u64,
    prior_statement_id: Hash,
) -> TaskRegistrationV4 {
    let (model, input, _, _) = material();
    let model = hash(b"artifact", &[&model]);
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
        model,
        layer: QualifiedWorkTask::layer_id(model),
        input: hash(b"qualified-task-input-v1", &[&input]),
        recipe: QualifiedWorkTask::recipe_id(),
        matrix_task: task,
        availability_manifest: lease.availability_manifest,
        availability_root: lease.availability_root,
        authorization_scope: lease.authorization_scope,
        withdrawal_head: lease.withdrawal_frontier().unwrap(),
        output_meter: [1; 32],
        rows: 64,
        inner: 64,
        columns: 64,
        demand_nonce: sequence,
        not_before: lease.not_before,
        expires: lease.expires,
        available_until: lease.available_until,
        logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
        model_bytes: MATRIX_ARTIFACT_BYTES,
        input_bytes: MATRIX_ARTIFACT_BYTES,
        useful_output_limit: lease.purpose.output_limit(),
    };
    manifest.output_meter = manifest.derived_output_meter();
    TaskRegistrationV4 {
        lease_id: lease.id().unwrap(),
        prior_statement_id,
        manifest,
    }
}
pub fn revocation(lease: &DemandLeaseV4) -> DemandRevocationV4 {
    DemandRevocationV4 {
        slot: lease.slot,
        network: lease.network,
        parameters: lease.parameters,
        demand_id: lease.demand_id,
        requester: lease.requester,
        lease_id: lease.id().unwrap(),
        expected_revision: lease.revision,
    }
}
pub fn primary(key: &Key, generation: u64) -> Witness<'_> {
    Witness {
        key,
        role: 1,
        generation,
        carried: false,
    }
}
pub fn source(key: &Key, generation: u64) -> Witness<'_> {
    Witness {
        key,
        role: 2,
        generation,
        carried: false,
    }
}
