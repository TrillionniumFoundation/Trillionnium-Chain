//! Unit mechanisms only. None of these synthetic source fixtures is Native evidence.
use crate::{
    operator_continuous_history::*,
    operator_continuous_recipient::*,
    operator_task_policy::{Allocation, Task},
};
use serde::Serialize;
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
pub(crate) fn identity() -> Identity {
    let r = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let t = signing_key_from_hex(&"22".repeat(32)).unwrap();
    Identity {
        schema: "restricted-continuous-identity-v2".into(),
        registry: "01".repeat(32),
        operator: "02".repeat(32),
        network: "03".repeat(32),
        parameters: "04".repeat(32),
        source_commit: "05".repeat(20),
        node_policy_source: "06".repeat(32),
        registry2_package: "07".repeat(32),
        registry_key: public_key_hex(&r),
        task_key: public_key_hex(&t),
        recipient_node: "08".repeat(32),
        global_allocator: "09".repeat(32),
    }
}
pub(crate) fn binding() -> DeclaredBinding {
    let h = || "11".repeat(32);
    DeclaredBinding {
        task: Task {
            purpose: "maintenance-tag1".into(),
            native_task: "10".repeat(32),
            lease_sha256: h(),
            model_id: "unqualified-mechanism-fixture".into(),
            model_revision: "33".repeat(20),
            model_material: h(),
            native_model: h(),
            layer_tensor: "declared-layer".into(),
            layer_index: 0,
            layer_selector: h(),
            input_material: h(),
            native_input: h(),
            dimension: 64,
            field_modulus: 4294967291,
            encoding: "canonical-u32-le".into(),
            a_sha256: h(),
            b_sha256: h(),
            full_material_catalog: h(),
            recipe_sha256: h(),
        },
        instance_class: "structured".into(),
        source_class: "declared-same-operator".into(),
        cost_class: "unmeasured".into(),
        cost_evidence: None,
        preprocessing: "forbidden".into(),
        prepared_artifact: None,
        setup_record: None,
        funding_commitment: h(),
        funding_evidence: h(),
    }
}
pub(crate) fn usage() -> Usage {
    Usage {
        operations: 32768,
        allocation: Allocation {
            cpu_ns: 1_000_000_000_000,
            material_bytes: 100_000_000,
            da_bytes: 100_000_000,
            funding_units: 32768,
            reuse_uses: 0,
        },
        actual_cpu_ns: 1_000_000_000_000,
    }
}
pub(crate) fn delegation(sequence: u64) -> RegistryDelegation {
    let i = identity();
    let h = || "11".repeat(32);
    let limits = usage();
    RegistryDelegation {
        schema: "restricted-continuous-registry2-budget-delegation-v2".into(),
        registry2_admission_package_sha256: i.registry2_package.clone(),
        registry2_admission_receipt_sha256: h(),
        registry2_view_sequence: 1000,
        registry2_view_digest: h(),
        registry2_declaration_digest: h(),
        registry2_request_digest: h(),
        registry2_claim_sha256: format!("{sequence:064x}"),
        registry2_operation: format!("{:064x}", sequence + 100),
        context: RegistryContext {
            registry_id: i.registry.clone(),
            operator_id: i.operator.clone(),
            network: i.network.clone(),
            parameters: i.parameters.clone(),
            source_commit: i.source_commit.clone(),
            consumer_source_package: i.registry2_package.clone(),
            native_admitter_source: i.node_policy_source.clone(),
            actual_parent: h(),
            scope: "same-operator-declared-task-permission-no-consensus-or-reward-v1".into(),
        },
        declared_binding: binding(),
        allowed_purposes: vec![
            "activate".into(),
            "lease-reconcile".into(),
            "parent-reconcile".into(),
            "pool-enable".into(),
            "pool-mining-batch".into(),
            "pool-prune".into(),
            "pool-reconcile".into(),
            "pool-status".into(),
            "pool-submit-bundle".into(),
            "pool-validate-batch".into(),
            "receiver-activate".into(),
            "receiver-validation".into(),
            "search".into(),
            "startup-catalog".into(),
            "winner-validation".into(),
        ],
        recipient_nodes: vec![i.recipient_node.clone()],
        global_allocator: i.global_allocator.clone(),
        allocator_latest: Anchor {
            sequence: 1,
            digest: h(),
        },
        nonce_first: 1,
        nonce_last: 10000,
        not_before_ns: 1,
        expires_ns: 2,
        budget: RegistryBudget {
            max_operations: 32768,
            max_cpu_ns: limits.allocation.cpu_ns,
            max_material_bytes: limits.allocation.material_bytes,
            max_da_bytes: limits.allocation.da_bytes,
            max_funding_units: limits.allocation.funding_units,
            max_reuse_uses: 0,
        },
        admitted_allocation: limits.allocation,
    }
}
pub(crate) fn signed<T: Serialize>(domain: &[u8], body: &T) -> (Vec<u8>, String) {
    let raw = serde_json::to_vec(body).unwrap();
    let message = |role: u8| {
        let mut out = domain.to_vec();
        out.push(role);
        out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        out.extend_from_slice(&raw);
        out
    };
    let r = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let t = signing_key_from_hex(&"22".repeat(32)).unwrap();
    let envelope = serde_json::json!({"body":body,"registry_signature":sign_hex(&r,&message(1)),"task_signature":sign_hex(&t,&message(2))});
    (
        serde_json::to_vec(&envelope).unwrap(),
        crate::operator_task_policy::digest_bytes(&message(0)),
    )
}
pub(crate) fn claim(n: u64) -> Claim {
    let b = binding();
    let mut c = Claim {
        operation: String::new(),
        operation_nonce: format!("{n:064x}"),
        purpose: "search".into(),
        payload: "11".repeat(32),
        parent: "12".repeat(32),
        generation: 0,
        native_task: b.task.native_task.clone(),
        instance_class: b.instance_class.clone(),
        task_binding: declared_binding_digest(&b).unwrap(),
        allocation: Allocation {
            cpu_ns: 1_000_000,
            material_bytes: 1,
            da_bytes: 1,
            funding_units: 1,
            reuse_uses: 0,
        },
        global_allocation_id: format!("{:064x}", n + 100000),
        global_allocation_sequence: n,
    };
    c.operation = operation_id(&identity(), &c).unwrap();
    c
}

pub(crate) fn allocation(purpose: &str) -> AllocationBody {
    let mut c = claim(1);
    c.purpose = purpose.into();
    c.operation = operation_id(&identity(), &c).unwrap();
    let origin = if purpose.starts_with("receiver-") {
        Some(Origin::ClosedFixture {
            producer_node: "44".repeat(32),
            packet_sha256: c.payload.clone(),
            parent: c.parent.clone(),
            generation: c.generation,
            task_binding_sha256: c.task_binding.clone(),
            source_commit: identity().source_commit,
            node_policy_source: identity().node_policy_source,
            native_receipt_sha256: "55".repeat(32),
            full_reference_receipt_sha256: "66".repeat(32),
        })
    } else {
        None
    };
    AllocationBody {
        schema: "restricted-continuous-recipient-allocation-v2".into(),
        identity: identity(),
        allocator_sequence: 1,
        allocator_previous_digest: None,
        allocator_record_sha256: "11".repeat(32),
        local_budget_sequence: 1,
        local_budget_digest: "11".repeat(32),
        claim: c,
        declared_binding: binding(),
        origin,
        issued_ns: 1,
        expires_ns: 2,
    }
}
pub(crate) fn signed_allocation(body: &AllocationBody) -> (Vec<u8>, Authority) {
    let (raw, _) = signed(b"TRNM-RESTRICTED-CONTINUOUS-RECIPIENT2", body);
    let authority = Authority {
        identity: identity(),
        expected: body.clone(),
        expected_envelope_sha256: crate::operator_task_policy::digest_bytes(&raw),
        latest_allocator_sequence: body.allocator_sequence,
        latest_allocator_digest: body.allocator_record_sha256.clone(),
    };
    (raw, authority)
}
