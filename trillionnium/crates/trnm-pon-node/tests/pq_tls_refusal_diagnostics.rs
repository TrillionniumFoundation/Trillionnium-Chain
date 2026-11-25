#[path = "pq_tls_witness_cli/refusal_diagnostics.rs"]
mod refusal_diagnostics;

use serde_json::{json, Value};

fn line(mut change: impl FnMut(&mut Value)) -> Vec<u8> {
    let mut value = json!({
        "schema":"pq-tls-connection-refusal-v1", "stage":"tls_handshake",
        "elapsed_us":100, "stage_elapsed_us":90, "deadline_elapsed":false,
        "error_kind":"Unclassified", "error_code":null,
        "bio_error_kind":"Unclassified", "bio_error_code":"PQ_WITNESS_DEADLINE",
        "ingress_charge_calls":4, "ingress_charge_us":80,
    });
    change(&mut value);
    format!("TRNM_PQ_TLS_CONNECTION_REFUSAL {value}\n").into_bytes()
}

#[test]
fn refusal_projection_preserves_local_cause_and_redacts_arbitrary_child_fields() {
    let bytes = line(|value| {
        value["private_key"] = "secret-key-material".into();
        value["error_code"] = "PQ_WITNESS_DEADLINE: private path".into();
    });
    let records = refusal_diagnostics::records(&bytes);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["bio_error_code"], "PQ_WITNESS_DEADLINE");
    assert_eq!(records[0]["stage"], "tls_handshake");
    assert_eq!(records[0]["ingress_charge_calls"], 4);
    assert!(records[0]["error_code"].is_null());
    assert!(!records[0].to_string().contains("secret"));
    assert!(!records[0].to_string().contains("private"));
}

#[test]
fn refusal_projection_rejects_unknown_schema_stage_types_and_out_of_prefix_records() {
    for change in 0..4 {
        let bytes = line(|value| match change {
            0 => value["schema"] = "other".into(),
            1 => value["stage"] = "secret-stage".into(),
            2 => value["elapsed_us"] = "100".into(),
            _ => value["extra"] = "s".repeat(800).into(),
        });
        assert!(refusal_diagnostics::records(&bytes).is_empty());
    }
    let mut bytes = vec![b'x'; 4096];
    bytes.push(b'\n');
    bytes.extend(line(|_| {}));
    assert!(refusal_diagnostics::records(&bytes).is_empty());
}

fn witness_line(mut change: impl FnMut(&mut Value)) -> Vec<u8> {
    let mut value = json!({
        "schema":"trnm-pq-witness-phase-v1", "kind":"client_cas", "ok":false,
        "error_code":"PQ_WITNESS_DEADLINE", "deadline_elapsed":true,
        "elapsed_us":250001, "cpu_ns":null, "last_phase":"wire_exchange",
        "phase_cost_columns":["phase", "calls", "wall_us", "cpu_ns"],
        "phases":[["sign_self_verify", 1, 4000, 3900000], ["wire_exchange", 1, 246001, null]],
    });
    change(&mut value);
    format!("TRNM_PQ_WITNESS_PHASE {value}\n").into_bytes()
}

#[test]
fn witness_projection_retains_unknown_cpu_and_only_fixed_phase_fields() {
    let rows = refusal_diagnostics::witness_records(&witness_line(|value| {
        value["private_key"] = "secret material".into();
        value["root"] = "secret root".into();
    }));
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["cpu_ns"].is_null());
    assert_eq!(
        rows[0]["phases"][1],
        json!(["wire_exchange", 1, 246001, null])
    );
    assert!(!rows[0].to_string().contains("secret"));
    assert!(!rows[0].to_string().contains("private"));
}

#[test]
fn witness_projection_refuses_wrong_schema_duplicate_phase_types_and_out_of_prefix() {
    for fault in 0..9 {
        let bytes = witness_line(|value| match fault {
            0 => value["schema"] = "other".into(),
            1 => value["kind"] = "secret".into(),
            2 => value["phases"][1][0] = "sign_self_verify".into(),
            3 => value["phases"][1][3] = "unknown".into(),
            4 => value["phases"][0][1] = 65536.into(),
            5 => value["last_phase"] = "private path".into(),
            6 => value["error_code"] = "PQ_WITNESS_DEADLINE: secret".into(),
            7 => value["phase_cost_columns"] = json!(["phase", "cpu_ns", "wall_us", "calls"]),
            _ => value["extra"] = "x".repeat(2048).into(),
        });
        assert!(
            refusal_diagnostics::witness_records(&bytes).is_empty(),
            "fault {fault}"
        );
    }
    let mut bytes = vec![b'x'; 4096];
    bytes.push(b'\n');
    bytes.extend(witness_line(|_| {}));
    assert!(refusal_diagnostics::witness_records(&bytes).is_empty());

    let intact = witness_line(|_| {});
    let mut missing_lf = intact.clone();
    assert_eq!(missing_lf.pop(), Some(b'\n'));
    assert!(refusal_diagnostics::witness_records(&missing_lf).is_empty());

    // The retained prefix ends at the complete JSON, with LF just outside it.
    let mut boundary = vec![b'x'; 4096 - intact.len()];
    boundary.push(b'\n');
    boundary.extend_from_slice(&intact);
    assert_eq!(boundary.len(), 4097);
    assert!(refusal_diagnostics::witness_records(&boundary).is_empty());
    // Keeping that final LF inside the same cap accepts exactly one record.
    boundary.remove(0);
    assert_eq!(boundary.len(), 4096);
    assert_eq!(refusal_diagnostics::witness_records(&boundary).len(), 1);
}
