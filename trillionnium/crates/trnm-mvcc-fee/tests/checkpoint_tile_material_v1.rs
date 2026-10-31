use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
};
use trnm_mvcc_fee::{
    checkpoint_tile_material_v1::*, pon_executor::Config, qualified_task_lifecycle,
};
use trnm_protocol::{pon_wire::hash, qualified_work_task::lifecycle_v4::PROFILE};

fn sha(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
struct Fixture {
    checkpoint: Vec<u8>,
    activation: Vec<u8>,
    a: Vec<u8>,
    b: Vec<u8>,
    ctx: PinnedTileContextV1,
}
fn fixture() -> Fixture {
    let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap();
    let header=serde_json::to_vec(&json!({"model.layers.0.self_attn.q_proj.weight":{"dtype":"BF16","shape":[576,576],"data_offsets":[0,576*576*2]}})).unwrap();
    let mut checkpoint = (header.len() as u64).to_le_bytes().to_vec();
    checkpoint.extend(header);
    for _ in 0..576 * 576 {
        checkpoint.extend(0x3f80_u16.to_le_bytes());
    }
    let a = (0..4096)
        .flat_map(|_| 16384_u32.to_le_bytes())
        .collect::<Vec<_>>();
    let b = (0..4096)
        .flat_map(|i| {
            if i % 64 < 2 {
                16_u32.to_le_bytes()
            } else {
                0_u32.to_le_bytes()
            }
        })
        .collect::<Vec<_>>();
    let act = json!({"schema":"checkpoint-qproj-postnorm-activation-v1","checkpoint_sha256":hex::encode(sha(&checkpoint)),"dtype":"F32LE","shape":[1,2,576],"token_ids":[1,2],"attention_mask":[1,1],"positions":[0,1],"hidden_hex":hex::encode((0..1152).flat_map(|_|1f32.to_bits().to_le_bytes()).collect::<Vec<_>>()),"producer_script_sha256":"01".repeat(32),"prompt_utf8_sha256":"02".repeat(32),"runtime":{"device":"cpu","python":"fixture","torch":"fixture","transformers":"fixture","safetensors":"fixture","numpy":"fixture","threads":2,"base_only":true,"training":false,"local_files_only":true,"trust_remote_code":false,"forward_calls":1,"hook_calls":1,"parameter_count":134515008,"storage_dtype":"float32","material_manifest_sha256":"03".repeat(32)},"activation_origin":"actual-layer0-q_proj-prehook-post-RMSNorm","scope":"observed CPU base-model hook; no independent full-forward proof or source authority"});
    let activation = serde_json::to_vec(&act).unwrap();
    let ctx = PinnedTileContextV1 {
        network: cfg.network,
        parameters: cfg.parameters,
        checkpoint_sha256: sha(&checkpoint),
        checkpoint_bytes: checkpoint.len() as u64,
        activation_sha256: sha(&activation),
        model: hash(b"artifact", &[&a]),
        input: hash(b"qualified-task-input-v1", &[&b]),
    };
    Fixture {
        checkpoint,
        activation,
        a,
        b,
        ctx,
    }
}
fn derive(f: &Fixture) -> Result<CheckedCheckpointTileMaterialV1, &'static str> {
    derive_checkpoint_tile_material_v1(
        &mut Cursor::new(&f.checkpoint),
        &f.activation,
        &f.a,
        &f.b,
        &f.ctx,
        |_| Ok(()),
    )
}
fn change_activation(f: &mut Fixture, change: impl FnOnce(&mut Value)) {
    let mut a: Value = serde_json::from_slice(&f.activation).unwrap();
    change(&mut a);
    f.activation = serde_json::to_vec(&a).unwrap();
    f.ctx.activation_sha256 = sha(&f.activation);
}

#[test]
fn synthetic_codec_fixture_full_relation_and_actual_signed_admission_binding() {
    // This is a synthetic parser/numeric control, never the actual Smol replay.
    let f = fixture();
    let checked = derive(&f).unwrap();
    let d = checked.descriptor();
    assert_eq!(d.b_nonzero, 128);
    assert_eq!(d.sparse_b_base_product_multiplications, 8192);
    assert_eq!(d.padded_token_columns, 62);
    assert!(!d.chain_authority && !d.hardness_accepted && !d.full_forward_verified);
    let repeat = verify_checkpoint_tile_material_v1(
        &mut Cursor::new(&f.checkpoint),
        &f.activation,
        checked.canonical_descriptor(),
        &f.a,
        &f.b,
        &f.ctx,
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(repeat.descriptor_id(), checked.descriptor_id());
    let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap();
    let boot = qualified_task_lifecycle::bootstrap_state(&cfg, &f.a, &f.b).unwrap();
    let (a, b) = derive_matrices(&f.a, &f.b).unwrap();
    let admission = verify_lifecycle_admission(
        &boot.signed.encode().unwrap(),
        TaskMaterial {
            model: &f.a,
            input: &f.b,
            a: &a,
            b: &b,
        },
        &boot.lease,
        0,
    )
    .unwrap();
    assert_ne!(checked.bind_admission(&admission).unwrap(), [0; 32]);
    for i in 0..8 {
        let proof = pon_work::prove([i + 1; 32], &a, &b).unwrap();
        let v = pon_work::verify([i + 1; 32], admission.matrix_task(), [255; 32], &proof).unwrap();
        assert_eq!(v.task(), admission.matrix_task());
    }
    let mut ctx = f.ctx.clone();
    ctx.network = [71; 32];
    let wrong = derive_checkpoint_tile_material_v1(
        &mut Cursor::new(&f.checkpoint),
        &f.activation,
        &f.a,
        &f.b,
        &ctx,
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(wrong.bind_admission(&admission), Err("ADMISSION_CONTEXT"));
    let mut bad = boot.signed.clone();
    bad.signature[0] ^= 1;
    assert!(verify_lifecycle_admission(
        &bad.encode().unwrap(),
        TaskMaterial {
            model: &f.a,
            input: &f.b,
            a: &a,
            b: &b
        },
        &boot.lease,
        0
    )
    .is_err());
}
#[test]
fn original_checkpoint_unselected_bytes_and_expected_matrix_pins_are_not_claims() {
    let mut f = fixture();
    let at = f.checkpoint.len() - 2;
    f.checkpoint[at] ^= 1;
    assert_eq!(derive(&f).unwrap_err(), "CHECKPOINT_PIN");
    let mut f = fixture();
    f.a[0] ^= 1;
    assert_eq!(derive(&f).unwrap_err(), "MATRIX_REPLAY");
    let mut f = fixture();
    f.b[63 * 4] = 1;
    assert_eq!(derive(&f).unwrap_err(), "MATRIX_REPLAY");
    let mut f = fixture();
    f.ctx.model = [91; 32];
    assert_eq!(derive(&f).unwrap_err(), "MATERIAL_PIN");
    let mut f = fixture();
    f.ctx.input = [92; 32];
    assert_eq!(derive(&f).unwrap_err(), "MATERIAL_PIN");
    let mut f = fixture();
    f.ctx.checkpoint_bytes -= 1;
    assert_eq!(derive(&f).unwrap_err(), "CHECKPOINT_SIZE");
}
#[test]
fn closed_activation_and_descriptor_changes_cannot_select_a_new_recipe() {
    for (key, value) in [
        ("shape", json!([1, true, 576])),
        ("shape", json!([1, 65, 576])),
        ("dtype", json!("F32BE")),
        ("positions", json!([1, 2])),
        ("extra", json!(0)),
        ("activation_origin", json!("invented")),
    ] {
        let mut f = fixture();
        change_activation(&mut f, |a| a[key] = value);
        assert!(derive(&f).is_err(), "{key}");
    }
    let mut f = fixture();
    change_activation(&mut f, |a| {
        let mut raw = hex::decode(a["hidden_hex"].as_str().unwrap()).unwrap();
        raw[575 * 4..576 * 4].copy_from_slice(&f32::NAN.to_bits().to_le_bytes());
        a["hidden_hex"] = json!(hex::encode(raw));
    });
    assert_eq!(derive(&f).unwrap_err(), "NONFINITE");
    let mut f = fixture();
    let raw = String::from_utf8(f.activation).unwrap();
    f.activation = raw.replacen("{", "{\"dtype\":\"F32LE\",", 1).into_bytes();
    f.ctx.activation_sha256 = sha(&f.activation);
    assert_eq!(derive(&f).unwrap_err(), "STRICT_JSON");
    let f = fixture();
    let c = derive(&f).unwrap();
    let mut d: Value = serde_json::from_slice(c.canonical_descriptor()).unwrap();
    for (field, value) in [
        ("weight_scale_power", json!(13)),
        ("chain_authority", json!(true)),
        ("tensor_offsets", json!([1, 663553])),
        ("input_coordinates", json!([1, 65])),
    ] {
        let prior = d.clone();
        d[field] = value;
        let raw = serde_json::to_vec(&d).unwrap();
        assert_eq!(
            verify_checkpoint_tile_material_v1(
                &mut Cursor::new(&f.checkpoint),
                &f.activation,
                &raw,
                &f.a,
                &f.b,
                &f.ctx,
                |_| Ok(())
            )
            .unwrap_err(),
            "DESCRIPTOR_REPLAY"
        );
        d = prior;
    }
    let mut raw = c.canonical_descriptor().to_vec();
    raw.push(b'\n');
    assert_eq!(
        verify_checkpoint_tile_material_v1(
            &mut Cursor::new(&f.checkpoint),
            &f.activation,
            &raw,
            &f.a,
            &f.b,
            &f.ctx,
            |_| Ok(())
        )
        .unwrap_err(),
        "DESCRIPTOR_CANONICAL"
    );
}
fn replace_header(f: &mut Fixture, raw: &[u8]) {
    let old = u64::from_le_bytes(f.checkpoint[..8].try_into().unwrap()) as usize;
    let payload = f.checkpoint[8 + old..].to_vec();
    f.checkpoint = (raw.len() as u64).to_le_bytes().to_vec();
    f.checkpoint.extend(raw);
    f.checkpoint.extend(payload);
    f.ctx.checkpoint_bytes = f.checkpoint.len() as u64;
    f.ctx.checkpoint_sha256 = sha(&f.checkpoint);
    change_activation(f, |_| {});
    let pin = hex::encode(f.ctx.checkpoint_sha256);
    change_activation(f, |a| a["checkpoint_sha256"] = json!(pin));
}
#[test]
fn strict_header_extents_unknown_fields_duplicates_and_progress_stop() {
    for raw in [br#"{"x":{"dtype":"BF16","shape":[576,576],"data_offsets":[0,663552]},"x":{}}"#.as_slice(),br#"{"model.layers.0.self_attn.q_proj.weight":{"dtype":"BF16","shape":[576,true],"data_offsets":[0,663552]}}"#,br#"{"model.layers.0.self_attn.q_proj.weight":{"dtype":"BF16","shape":[576,576],"data_offsets":[1,663553]}}"#,br#"{"model.layers.0.self_attn.q_proj.weight":{"dtype":"BF16","shape":[576,576],"data_offsets":[0,663552],"extra":0}}"#,br#"{"model.layers.0.self_attn.q_proj.weight":{"dtype":"BF16","shape":[576,576.0],"data_offsets":[0,663552]}}"#] {let mut f=fixture();replace_header(&mut f,raw);assert!(derive(&f).is_err());}
    let f = fixture();
    let mut count = 0;
    assert_eq!(
        derive_checkpoint_tile_material_v1(
            &mut Cursor::new(&f.checkpoint),
            &f.activation,
            &f.a,
            &f.b,
            &f.ctx,
            |_| {
                count += 1;
                Err("CONTROL_STOP")
            }
        )
        .unwrap_err(),
        "CONTROL_STOP"
    );
    assert_eq!(count, 1);
    let mut ctx = f.ctx.clone();
    ctx.checkpoint_bytes = MAX_CHECKPOINT_BYTES + 1;
    assert_eq!(
        derive_checkpoint_tile_material_v1(
            &mut Cursor::new(&f.checkpoint),
            &f.activation,
            &f.a,
            &f.b,
            &ctx,
            |_| Ok(())
        )
        .unwrap_err(),
        "CHECKPOINT_LIMIT"
    );
    let mut tiny = f.checkpoint.clone();
    tiny[..8].copy_from_slice(&((MAX_HEADER_BYTES + 1) as u64).to_le_bytes());
    let mut context = f.ctx.clone();
    context.checkpoint_sha256 = sha(&tiny);
    let mut activation: Value = serde_json::from_slice(&f.activation).unwrap();
    activation["checkpoint_sha256"] = hex::encode(context.checkpoint_sha256).into();
    let activation = serde_json::to_vec(&activation).unwrap();
    context.activation_sha256 = sha(&activation);
    assert_eq!(
        derive_checkpoint_tile_material_v1(
            &mut Cursor::new(tiny),
            &activation,
            &f.a,
            &f.b,
            &context,
            |_| Ok(())
        )
        .unwrap_err(),
        "HEADER_LIMIT"
    );
}
struct ChangingReader {
    cursor: Cursor<Vec<u8>>,
    seeks: usize,
}
impl Read for ChangingReader {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(b)
    }
}
impl Seek for ChangingReader {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        if p == SeekFrom::Start(0) {
            self.seeks += 1;
            if self.seeks == 2 {
                self.cursor.get_mut()[9] ^= 1;
            }
        }
        self.cursor.seek(p)
    }
}
#[test]
fn actual_hashed_stream_header_must_equal_the_parsed_header() {
    let f = fixture();
    let mut r = ChangingReader {
        cursor: Cursor::new(f.checkpoint.clone()),
        seeks: 0,
    };
    assert_eq!(
        derive_checkpoint_tile_material_v1(&mut r, &f.activation, &f.a, &f.b, &f.ctx, |_| Ok(()))
            .unwrap_err(),
        "CHECKPOINT_CHANGED"
    );
}

#[test]
fn typed_progress_retains_legacy_bytes_and_original_descriptor() {
    let f = fixture();
    let mut legacy_events = Vec::new();
    let legacy = derive_checkpoint_tile_material_v1(
        &mut Cursor::new(&f.checkpoint),
        &f.activation,
        &f.a,
        &f.b,
        &f.ctx,
        |bytes| {
            legacy_events.push(bytes);
            Ok(())
        },
    )
    .unwrap();
    let header = u64::from_le_bytes(f.checkpoint[..8].try_into().unwrap()) + 8;
    assert_eq!(legacy_events, [header, header + f.ctx.checkpoint_bytes]);
    let mut phases = Vec::new();
    let checked = derive_checkpoint_tile_material_v1_with_progress(
        &mut Cursor::new(&f.checkpoint),
        &f.activation,
        &f.a,
        &f.b,
        &f.ctx,
        |event| {
            phases.push(event.phase);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        checked.canonical_descriptor(),
        legacy.canonical_descriptor()
    );
    assert_eq!(checked.descriptor_id(), legacy.descriptor_id());
    assert_eq!(
        checked.checkpoint_bytes_read(),
        legacy.checkpoint_bytes_read()
    );
    for phase in [
        MaterialPhase::ActivationJson,
        MaterialPhase::ActivationHex,
        MaterialPhase::HeaderJson,
        MaterialPhase::CheckpointScan,
        MaterialPhase::WeightQuantization,
        MaterialPhase::ActivationNonfinite,
        MaterialPhase::ActivationQuantization,
        MaterialPhase::TaskHash,
        MaterialPhase::DescriptorEncoding,
        MaterialPhase::DescriptorHash,
    ] {
        assert!(phases.contains(&phase), "missing {phase:?}");
    }
}

#[test]
fn every_interior_numeric_and_hash_stage_preserves_first_owner_abort() {
    let f = fixture();
    for (phase, threshold) in [
        (MaterialPhase::ActivationHex, 512),
        (MaterialPhase::CheckpointScan, 65_536),
        (MaterialPhase::WeightQuantization, 256),
        (MaterialPhase::ActivationNonfinite, 256),
        (MaterialPhase::ActivationQuantization, 16),
        (MaterialPhase::TaskHash, 2 * 4096 + 256),
        (MaterialPhase::DescriptorEncoding, 256),
    ] {
        let mut stopped = false;
        let result = derive_checkpoint_tile_material_v1_with_progress(
            &mut Cursor::new(&f.checkpoint),
            &f.activation,
            &f.a,
            &f.b,
            &f.ctx,
            |event| {
                assert!(!stopped, "callback continued after the first error");
                if event.phase == phase && event.completed >= threshold {
                    stopped = true;
                    Err("ORIGINAL_OWNER_CANCELLED")
                } else {
                    Ok(())
                }
            },
        );
        assert!(stopped, "not reached: {phase:?}");
        assert_eq!(result.unwrap_err(), "ORIGINAL_OWNER_CANCELLED", "{phase:?}");
    }
}

#[test]
fn long_json_string_is_interruptible_before_visitor_or_field_validation() {
    let mut f = fixture();
    change_activation(&mut f, |a| a["scope"] = json!("x".repeat(131_072)));
    let mut stopped = false;
    let result = derive_checkpoint_tile_material_v1_with_progress(
        &mut Cursor::new(&f.checkpoint),
        &f.activation,
        &f.a,
        &f.b,
        &f.ctx,
        |event| {
            assert!(!stopped);
            if event.phase == MaterialPhase::ActivationJson && event.completed == 65_536 {
                stopped = true;
                Err("ORIGINAL_OWNER_EXPIRED")
            } else {
                Ok(())
            }
        },
    );
    assert!(stopped);
    assert_eq!(result.unwrap_err(), "ORIGINAL_OWNER_EXPIRED");
    // Without cancellation, the original material profile still rejects it.
    assert_eq!(derive(&f).unwrap_err(), "ACTIVATION_PROFILE");
}

#[test]
fn task_hash_progress_keeps_original_bytes_and_field_refusals() {
    let a = (0..4096).map(|i| i as u32).collect::<Vec<_>>();
    let b = (0..4096).map(|i| (4096 - i) as u32).collect::<Vec<_>>();
    let expected = pon_work::task_id(&a, &b).unwrap();
    assert_eq!(
        pon_work::task_id_with_progress(&a, &b, &mut |_| Ok::<_, &'static str>(())).unwrap(),
        expected
    );
    assert_eq!(
        pon_work::task_id_with_progress(&a, &b, &mut |n| {
            if n > 8192 {
                Err("TASK_OWNER_STOP")
            } else {
                Ok(())
            }
        }),
        Err(pon_work::VerificationError::Cancelled("TASK_OWNER_STOP"))
    );
    let mut bad = b;
    bad[1000] = u32::MAX;
    assert_eq!(
        pon_work::task_id_with_progress(&a, &bad, &mut |_| Ok::<_, &'static str>(())),
        Err(pon_work::VerificationError::Relation(
            pon_work::WorkError::Field
        ))
    );
}
