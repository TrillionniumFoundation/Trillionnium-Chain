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
