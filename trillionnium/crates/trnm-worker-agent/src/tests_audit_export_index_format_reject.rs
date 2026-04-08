use super::*;
#[test]
fn validate_audit_export_index_rejects_unknown_version_fail_closed() {
    let index = AuditExportIndex {
        version: 2,
        total_records: 0,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 0)
        .expect_err("unknown audit index version must fail closed");
    assert!(err
        .to_string()
        .contains("unsupported audit index version=2"));
}

#[test]
fn validate_audit_export_index_rejects_total_record_mismatch_fail_closed() {
    let index = AuditExportIndex {
        version: 1,
        total_records: 2,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 1)
        .expect_err("mismatched export length must fail closed");
    assert!(err
        .to_string()
        .contains("audit index total_records mismatch: index=2 exports=1"));
}

#[test]
fn validate_audit_export_index_rejects_out_of_bounds_offsets_fail_closed() {
    let mut by_task_id = BTreeMap::new();
    by_task_id.insert("7001".to_string(), vec![1]);
    let index = AuditExportIndex {
        version: 1,
        total_records: 1,
        by_task_id,
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 1)
        .expect_err("out-of-bounds index offsets must fail closed");
    assert!(err.to_string().contains(
        "audit index offset out of bounds: map=by_task_id key=7001 idx=1 total_records=1"
    ));
}
