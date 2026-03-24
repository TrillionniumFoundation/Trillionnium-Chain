use super::*;

#[test]
fn parse_zk_proof_payload_accepts_canonical_json_vector() {
    let task = mock_task();
    let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1"}}"#).unwrap();
    assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
    assert_eq!(payload.zk_system.as_deref(), Some("groth16"));
    assert_eq!(payload.backend_id.as_deref(), Some("mock-zk"));
    assert_eq!(payload.schema_version, "trnm.zk.payload.v0");
    assert_eq!(payload.decode_proof_bytes().unwrap(), vec![1, 2, 3, 4]);
}

#[test]
fn parse_zk_proof_payload_rejects_non_canonical_zk_system_aliases_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":" Groth-16 ","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("zk_system must use canonical token 'groth16'"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_zk_system_with_surrounding_unicode_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"\u{2003}groth16\u{2003}\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("zk_system must use canonical token 'groth16'"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_public_input_mismatch() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","2222222222222222222222222222222222222222222222222222222222222222"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("public_inputs mismatch"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_non_canonical_top_level_proof_type_case() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"ZK","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("canonical lowercase token 'zk'"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_non_canonical_top_level_result_hash_case() {
    let mut task = mock_task();
    task.result_hash = Some([0xab; 32]);
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","abababababababababababababababababababababababababababababababab"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("canonical lowercase hex"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_public_input_length_mismatch_as_malformed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("order/value length mismatch"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_duplicate_public_input_field_as_malformed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","worker"],"values":["4242","zk","worker-zk","worker-zk"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("duplicate public_inputs field 'worker'"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_non_canonical_public_input_order_as_malformed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["worker","task_id","proof_type","result_hash"],"values":["worker-zk","4242","zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("public_inputs order is not canonical"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_unsupported_zk_system_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"bulletproofs","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("unsupported zk_system 'bulletproofs'"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_malformed_json_before_crypto() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"base64","proof":"!!!","public_inputs":{"order":["task_id"]"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_lowercase_prefix_as_non_canonical() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"zk:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("missing canonical ZK: prefix"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_unknown_top_level_field_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","unexpected_binding":"worker-zk","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_unknown_meta_field_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1","unexpected":"drift"}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_duplicate_meta_container_field_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1"},"meta":{"circuit_id":"settlement-result-v2"}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_unknown_public_inputs_field_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"],"digest":"deadbeef"}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_unknown_proof_encoding_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"raw-bytes","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_non_canonical_proof_encoding_case_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"HEX","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_duplicate_top_level_binding_field_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","task_id":9999,"public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_duplicate_public_inputs_container_field_fail_closed() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"],"values":["9999","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_missing_top_level_schema_version() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1"}}"#).unwrap_err();
    assert!(matches!(err, BackendExecutionError::MalformedProof { .. }));
}

#[test]
fn parse_zk_proof_payload_rejects_missing_proof_encoding_per_protocol_v0() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("proof_encoding is required"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_proof_with_surrounding_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":" 01020304 ","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("proof must not contain surrounding whitespace"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_proof_with_embedded_unicode_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"0102\u{2003}0304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("proof must be encoded as a single token without embedded whitespace or control characters"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_vk_ref_with_surrounding_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"  vk://trnm/dev/mock-groth16/v1  ","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("vk_ref must not contain surrounding whitespace"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_vk_ref_with_embedded_whitespace_or_control_chars() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/line\nbreak","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("single opaque token") && reason.contains("embedded whitespace or control characters"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_vk_ref_with_embedded_unicode_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/line\u{2003}break\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("single opaque token") && reason.contains("embedded whitespace or control characters"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_id_with_surrounding_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"  groth16-demo  ","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must not contain surrounding whitespace"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_id_with_surrounding_unicode_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"\u{2003}groth16-demo\u{2003}\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must not contain surrounding whitespace"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_id_with_embedded_whitespace_or_control_chars() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo\talt","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_id_with_embedded_unicode_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"groth16-demo\u{2003}alt\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_version_with_surrounding_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"  v1  ","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must not contain surrounding whitespace"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_version_with_surrounding_unicode_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"groth16-demo\",\"backend_version\":\"\u{2003}v1\u{2003}\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must not contain surrounding whitespace"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_version_with_embedded_whitespace_or_control_chars() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1\nnext","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_version_with_embedded_unicode_whitespace() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"groth16-demo\",\"backend_version\":\"v1\u{2003}next\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_empty_backend_id_when_provided() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must not be empty when provided"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_id_without_visible_canonical_token_segments() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"---","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id '---'") && reason.contains("visible canonical backend token segment"))
    );
}

#[test]
fn parse_zk_proof_payload_still_allows_noop_backend_id_as_explicit_legacy_no_backend_selector() {
    let task = mock_task();
    let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
    assert_eq!(payload.backend_id.as_deref(), Some("noop"));
}

#[test]
fn parse_zk_proof_payload_rejects_empty_backend_version_when_provided() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must not be empty when provided"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_backend_version_without_backend_id() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version requires backend_id"))
    );
}

#[test]
fn parse_zk_proof_payload_rejects_missing_zk_system_per_protocol_v0() {
    let task = mock_task();
    let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("zk_system is required"))
    );
}
