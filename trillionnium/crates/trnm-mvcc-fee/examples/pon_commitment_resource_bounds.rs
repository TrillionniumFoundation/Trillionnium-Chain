//! Finite component resource controls. These arbitrary canonical State rows are
//! not an installed native genesis or a ledger command reachability certificate.
use serde_json::{json, Value};
use std::time::Instant;
use trnm_mvcc_fee::{
    pon_commitment::{self, CacheLimits, CommitmentMethod, PreparedCommitment},
    pon_executor::{self, State},
};

fn row(name: &str, result: &PreparedCommitment, elapsed_ns: u128) -> Value {
    json!({"case":name,"root":hex::encode(result.root),
        "method":format!("{:?}",result.observation.method),
        "snapshot_retained":result.snapshot.is_some(),
        "actual_keys":result.observation.actual_keys,
        "actual_canonical_payload_bytes":result.observation.actual_payload_bytes,
        "changed_keys":result.observation.changed_keys,
        "logical_change_payload_bytes":result.observation.changed_payload_bytes,
        "workspace_software_charge_bytes":result.observation.workspace_charge_bytes,
        "component_elapsed_ns":elapsed_ns,"p95":null,"p99":null})
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() == 1 && args[0] == "--run-component-controls",
        "usage: pon_commitment_resource_bounds --run-component-controls"
    );
    let mut rows = Vec::new();
    let exact: State = (0..65536)
        .map(|i| (format!("k{i:05}"), json!("x".repeat(120))))
        .collect();
    let expected = pon_executor::root(&exact).unwrap();
    let started = Instant::now();
    let base =
        pon_commitment::checked_snapshot(&exact, expected, None, CacheLimits::default()).unwrap();
    assert_eq!(base.observation.actual_payload_bytes, 8 * 1024 * 1024);
    assert_eq!(base.observation.method, CommitmentMethod::RebuiltTree);
    rows.push(row(
        "exact65536-and-payload8MiB",
        &base,
        started.elapsed().as_nanos(),
    ));
    for (name, length) in [("payload-minus-one", 119), ("payload-plus-one", 121)] {
        let mut state = exact.clone();
        state.insert("k00000".into(), json!("x".repeat(length)));
        let root = pon_executor::root(&state).unwrap();
        let started = Instant::now();
        let result = pon_commitment::checked_snapshot(
            &state,
            root,
            base.snapshot.as_ref(),
            CacheLimits::default(),
        )
        .unwrap();
        assert_eq!(result.root, root);
        rows.push(row(name, &result, started.elapsed().as_nanos()));
    }
    // Change all canonical values without increasing payload/key limits. This
    // exposes the complete required public before/after delta, not a claimed
    // write set or a trusted header root.
    let after: State = (0..65536)
        .map(|i| (format!("k{i:05}"), json!("y".repeat(120))))
        .collect();
    let root = pon_executor::root(&after).unwrap();
    let measured = pon_commitment::checked_snapshot(
        &after,
        root,
        base.snapshot.as_ref(),
        CacheLimits::default(),
    )
    .unwrap();
    let charge = measured.observation.workspace_charge_bytes;
    assert!(charge > 0 && charge < pon_commitment::MAX_WORKSPACE_CHARGE_BYTES);
    for (name, limit) in [
        ("selected-workspace-Q-minus-one", charge - 1),
        ("selected-workspace-Q-exact", charge),
        ("selected-workspace-Q-plus-one", charge + 1),
    ] {
        let started = Instant::now();
        let result = pon_commitment::checked_snapshot(
            &after,
            root,
            base.snapshot.as_ref(),
            CacheLimits {
                max_workspace_charge_bytes: limit,
                ..CacheLimits::default()
            },
        )
        .unwrap();
        assert_eq!(result.root, root);
        assert_eq!(result.changes.len(), 65536);
        let mut observation = row(name, &result, started.elapsed().as_nanos());
        observation["selected_workspace_limit_bytes"] = json!(limit);
        rows.push(observation);
    }
    // Both complete States fit the inclusive payload limit; their key sets are
    // disjoint. Values just above the initial 128-byte serializer capacity raise
    // actual capacity charges, and the full ordered difference has 131072 rows.
    let disjoint = |prefix| -> State {
        (0..65536)
            .map(|i| {
                let value = if i < 61952 {
                    json!("x".repeat(127))
                } else {
                    json!(0)
                };
                (format!("{prefix}{i:05}"), value)
            })
            .collect()
    };
    let old = disjoint('a');
    let new = disjoint('b');
    let old_root = pon_executor::root(&old).unwrap();
    let new_root = pon_executor::root(&new).unwrap();
    let previous =
        pon_commitment::checked_snapshot(&old, old_root, None, CacheLimits::default()).unwrap();
    assert_eq!(previous.observation.actual_payload_bytes, 8 * 1024 * 1024);
    let started = Instant::now();
    let changed = pon_commitment::checked_snapshot(
        &new,
        new_root,
        previous.snapshot.as_ref(),
        CacheLimits::default(),
    )
    .unwrap();
    assert_eq!(changed.observation.actual_payload_bytes, 8 * 1024 * 1024);
    assert_eq!(changed.changes.len(), 131072);
    assert!(changed.observation.workspace_charge_bytes < 512 * 1024 * 1024);
    // The known StateTree apply batch bound is selected before delta allocation;
    // software workspace accounting below its ceiling does not waive that bound.
    assert_eq!(
        changed.observation.method,
        CommitmentMethod::FullRoot(pon_commitment::FullRootReason::DeltaBudget)
    );
    let mut replayed = old.clone();
    for change in &changed.changes {
        let key = String::from_utf8(change.key.clone()).unwrap();
        // This component's values are ASCII strings and integer zero; original
        // root validation above already rejects invalid canonical State values.
        let before = replayed
            .get(&key)
            .map(serde_json::to_vec)
            .transpose()
            .unwrap();
        assert_eq!(before, change.before);
        if let Some(after) = &change.after {
            replayed.insert(key, serde_json::from_slice(after).unwrap());
        } else {
            replayed.remove(&key);
        }
    }
    assert_eq!(replayed, new);
    assert_eq!(previous.snapshot.as_ref().unwrap().root(), old_root);
    rows.push(row(
        "disjoint65536-each-payload8MiB-capacity-highwater",
        &changed,
        started.elapsed().as_nanos(),
    ));
    let mut overflow = exact;
    overflow.insert("overflow".into(), json!(0));
    let original_error = pon_executor::root(&overflow).unwrap_err();
    let adapter_error =
        pon_commitment::derive_snapshot(&overflow, base.snapshot.as_ref(), CacheLimits::default())
            .unwrap_err();
    assert_eq!(original_error, "LIMIT");
    assert_eq!(adapter_error, original_error);
    assert_eq!(base.snapshot.as_ref().unwrap().root(), expected);
    println!(
        "{}",
        json!({"schema":"pon-commitment-resource-component-controls-v1",
        "component_controls_passed":true,"rows":rows,
        "protocol65537_error":adapter_error,
        "source_binding_required_from_external_runner":true,
        "component_State_shape": "kXXXXX ASCII string values; arbitrary rows are not native command reachable evidence",
        "independent_root_comparison": "original pon_executor::root over each complete actual State",
        "default_workspace_limit_bytes":pon_commitment::MAX_WORKSPACE_CHARGE_BYTES,
        "workspace_Q_scope":"actual software charge, selecting a lower local limit; not512MiB exact boundary qualification",
        "resource_scope":"elapsed plus software accounting; no allocator/RSS hard bound or perCPU measurement",
        "native_command_reachability_proven":false,"new_PNW1_or_block_validation":false,
        "maximum_state_live_capacity_qualified":false,"public_network_ready":false,
        "production_activation":false})
    );
}
