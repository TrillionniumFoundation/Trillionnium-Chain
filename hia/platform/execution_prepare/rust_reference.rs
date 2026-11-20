//! Test-only observer of the unchanged private ordinary M06 prepare operation.
use super::*;
use std::io::{BufRead, BufReader};

#[test]
fn evaluate() {
    let input = std::env::var("HIA_PREPARE_CORPUS").expect("explicit bound corpus");
    let cfg = Config::installed().expect("actual installed default configuration");
    let context = json!({
        "network_hex": hex::encode(cfg.network),
        "parameters_hex": hex::encode(cfg.parameters),
        "family_hex": hex::encode(cfg.family),
        "plan_hex": hex::encode(cfg.plan),
        "params": cfg.params,
        "model": cfg.model_registry,
        "base_fees": cfg.fees.to_vec(),
        "evaluators": cfg.evaluators.iter().cloned().collect::<Vec<_>>(),
        "task_profile": cfg.task_profile(),
        "task_windows_none": cfg.task_windows.is_none(),
        "native_pq_none": cfg.native_pq_v2.is_none(),
        "is_pq_account_profile": cfg.is_pq_account_profile(),
        "account_profile_error": cfg.check_account_profile().err(),
        "funded_config_error": funded_service_v1::check_config(&cfg).err(),
    });
    println!("HIA_PREPARE_CONTEXT:{}", context);
    let file = std::fs::File::open(input).expect("bound corpus exists");
    let mut names = BTreeSet::new();
    let mut count = 0;
    for line in BufReader::new(file).lines() {
        let line = line.expect("complete corpus line");
        let request: Value = serde_json::from_str(&line).expect("canonical input JSON");
        let object = request.as_object().expect("input object");
        assert_eq!(object.len(), 3);
        let name = request["name"].as_str().expect("case name");
        assert!(names.insert(name.to_owned()));
        let height = request["height"].as_u64().expect("height u64");
        let encoded = request["wire_hex"].as_str().expect("wire hex");
        let raw = hex::decode(encoded).expect("complete hex");
        assert_eq!(hex::encode(&raw), encoded);
        let before = raw.clone();
        let signatures = AtomicUsize::new(0);
        // No host verdict, expected root, Config field, Prepared or Patch enters.
        let actual = prepare(&raw, height, None, &cfg, &signatures, None);
        let (error, prepared) = match actual {
            Ok(prepared) => {
                let legacy = prepared.legacy.as_ref().expect("real legacy envelope");
                let observed = json!({
                    "sender": prepared.sender,
                    "sender_hex": hex::encode(prepared.command.sender),
                    "nonce": prepared.command.nonce,
                    "fee_limit": prepared.command.fee_limit,
                    "tag": prepared.command.tag,
                    "payload_hex": hex::encode(&prepared.command.payload),
                    "encoded_length": prepared.encoded_len,
                    "transaction_id_hex": hex::encode(&prepared.transaction_id),
                    "native_pq_none": prepared.native_pq.is_none(),
                    "legacy": {
                        "network_hex": hex::encode(legacy.network),
                        "sender_hex": hex::encode(legacy.sender),
                        "nonce": legacy.nonce,
                        "expiry": legacy.expiry,
                        "fee_limit": legacy.fee_limit,
                        "tag": legacy.tag,
                        "payload_hex": hex::encode(&legacy.payload),
                        "signature_hex": hex::encode(legacy.signature),
                        "wire_hex": hex::encode(legacy.encode().expect("retained canonical encoding")),
                        "signing_digest_hex": hex::encode(legacy.signing_digest().expect("retained actual hash")),
                    },
                });
                (None, Some(observed))
            }
            Err(error) => (Some(error), None),
        };
        assert_eq!(raw, before, "prepare changed borrowed transaction");
        println!(
            "HIA_PREPARE_CASE:{}",
            json!({
                "name":name,
                "error":error,
                "signature_attempts":signatures.load(Ordering::Relaxed),
                "prepared":prepared,
                "input_unchanged":true,
            })
        );
        count += 1;
    }
    assert!(count > 0);
    println!("HIA_PREPARE_COMPLETE:{}", count);
}
