//! Test-only observation of the unchanged real public Settings constructor.
//! Appended as a cfg(test) child of the original trnm-pon-node lib.rs.
use super::Settings;
use serde_json::{json, Value};

fn put32(bytes: &mut [u8], offset: usize, value: usize) {
    let word = u32::try_from(value).expect("snapshot field fits u32");
    bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
}

fn snapshot(settings: &Settings) -> Vec<u8> {
    let app = &settings.app;
    let params = serde_json::to_vec(&app.params).expect("original params serialize");
    let model = serde_json::to_vec(&app.model_registry).expect("original model serialize");
    let root = settings
        .state_root(&settings.initial)
        .expect("original default State is valid");
    let (a, b) = super::maintenance();
    let task = trnm_crypto_primitives::pon_work::task_id(&a, &b)
        .expect("original maintenance task is valid");
    let mut state = b"SRV1".to_vec();
    state.extend_from_slice(
        &u32::try_from(settings.initial.len())
            .expect("original initial count fits u32")
            .to_le_bytes(),
    );
    for (key, value) in &settings.initial {
        let encoded = serde_json::to_vec(value).expect("original initial Value serializes");
        state.extend_from_slice(
            &u32::try_from(key.len())
                .expect("original key length fits u32")
                .to_le_bytes(),
        );
        state.extend_from_slice(
            &u32::try_from(encoded.len())
                .expect("original value length fits u32")
                .to_le_bytes(),
        );
        state.extend_from_slice(key.as_bytes());
        state.extend_from_slice(&encoded);
    }
    let mut result = vec![0_u8; 576];
    result[..4].copy_from_slice(b"SDO1");
    let mut flags = u32::from(app.task_windows.is_some());
    // The backing Option is private to trnm-mvcc-fee. For this exact
    // constructor the public selector is absent, so the original public
    // predicate is equivalent to observing whether that Option is Some.
    assert!(app.params.get("account_authorization_profile").is_none());
    assert!(app.params.get("native_pq_accounts_profile").is_none());
    flags |= u32::from(trnm_mvcc_fee::pon_executor::pq_accounts_v2::enabled(app)) << 1;
    flags |= u32::from(settings.operator_bootstrap.is_some()) << 2;
    flags |= u32::from(settings.operator_material.is_some()) << 3;
    flags |= u32::from(settings.checkpoint_tile_paths.is_some()) << 4;
    #[cfg(feature = "pq-native-openssl")]
    {
        assert!(!trnm_mvcc_fee::pon_executor::pq_accounts_v2::enabled(app));
        flags |= u32::from(app.is_pq_account_profile()) << 5;
    }
    result[8..12].copy_from_slice(&flags.to_le_bytes());
    result[16..24].copy_from_slice(&settings.genesis_time().to_le_bytes());
    result[24..56].copy_from_slice(&app.network);
    result[56..88].copy_from_slice(&app.parameters);
    result[88..120].copy_from_slice(&app.family);
    result[120..152].copy_from_slice(&app.plan);
    result[152..184].copy_from_slice(&settings.genesis);
    result[184..216].copy_from_slice(&root);
    result[216..248].copy_from_slice(&task);
    for (index, fee) in app.fees.iter().enumerate() {
        let at = 248 + index * 8;
        result[at..at + 8].copy_from_slice(&fee.to_le_bytes());
    }
    put32(&mut result, 448, app.evaluators.len());
    put32(&mut result, 452, settings.initial.len());
    put32(&mut result, 456, params.len());
    put32(&mut result, 460, model.len());
    put32(&mut result, 464, state.len());
    assert_eq!(app.evaluators.len(), 3, "original default evaluator cardinality");
    for (index, public) in app.evaluators.iter().enumerate() {
        let decoded = hex::decode(public).expect("original public hex");
        assert_eq!(decoded.len(), 32, "original public key width");
        result[480 + index * 32..512 + index * 32].copy_from_slice(&decoded);
    }
    result.extend_from_slice(&params);
    result.extend_from_slice(&model);
    result.extend_from_slice(&state);
    let size = result.len();
    put32(&mut result, 4, size);
    result
}

#[test]
fn evaluate() {
    let path = std::env::var("TRNM_HIA_SETTINGS_ORACLE_CORPUS")
        .expect("explicit original Settings oracle corpus");
    let corpus = std::fs::read_to_string(path).expect("read the complete corpus");
    for line in corpus.lines() {
        let row: Value = serde_json::from_str(line).expect("valid corpus row");
        let name = row["name"].as_str().expect("case identity");
        let time = match &row["timestamp"] {
            Value::Null => None,
            Value::String(value) => Some(value.parse::<u64>().expect("typed u64 timestamp")),
            _ => panic!("corpus timestamp is null or an exact unsigned decimal string"),
        };
        // The original public method is the only Settings constructor here.
        // No default Config, key, State, genesis or parameters are rebuilt here.
        let record = match Settings::development(time) {
            Ok(settings) => json!({
                "name": name, "status": "OK", "snapshot_hex": hex::encode(snapshot(&settings))
            }),
            Err(error) => json!({
                "name": name, "status": "ERROR", "error": error.to_string(),
                "kind": format!("{:?}", error.kind()),
                "code": error.code().map(|code| code.as_str()),
                "requires_owner_stop": error.requires_owner_stop(),
                "has_source": std::error::Error::source(&error).is_some()
            }),
        };
        println!("HIA_SETTINGS_ORACLE:{}", record);
    }
}
