use trnm_useful_cell_v2_reference::*;

struct Fixture {
    raw_model: Model,
    model: PreparedModel,
    context: Context,
    requests: Vec<Request>,
    state: ReadOnlyState,
    bindings: Bindings,
    policy: Policy,
}
impl Fixture {
    fn new(n: usize) -> Self {
        let raw_model = Model {
            version: [7; 32],
            base: std::array::from_fn(|r| std::array::from_fn(|k| ((r * 13 + k) % 7) as i32 - 3)),
            router: std::array::from_fn(|r| std::array::from_fn(|k| if k == r { 8 } else { 0 })),
            deltas: std::array::from_fn(|e| {
                std::array::from_fn(|r| {
                    std::array::from_fn(|k| ((e * 11 + r * 3 + k) % 5) as i32 - 2)
                })
            }),
        };
        let model = PreparedModel::new(raw_model.clone()).unwrap();
        let context = Context {
            chain: [1; 32],
            parent: [2; 32],
            challenge: [3; 32],
            batch_id: [4; 32],
        };
        let requests = (0..n)
            .map(|i| {
                let mut x = std::array::from_fn(|k| ((i * 3 + k) % 17) as i32 - 8);
                x[..3].fill(-8);
                x[i % 3] = 8;
                x[DIM - 1] = 8;
                Request {
                    id: [i as u8; 32],
                    scope: [9; 32],
                    arrival_ns: 1,
                    deadline_ns: 900,
                    x,
                }
            })
            .collect();
        let state = ReadOnlyState {
            cell_id: [10; 32],
            generation: 3,
            snapshot_root: [11; 32],
            model_commitment: model.commitment(),
        };
        let bindings = Bindings {
            program_digest: [12; 32],
            extractor_digest: [13; 32],
            source_inputs_digest: [14; 32],
            consumer: [15; 32],
            allowed_use: [16; 32],
            candidate_artifact: [17; 32],
        };
        let policy = Policy {
            shift: 2,
            clamp_abs: 64,
            activation: Activation::Relu,
            stop_rule: StopRule::MarginAtLeast(8),
        };
        Self {
            raw_model,
            model,
            context,
            requests,
            state,
            bindings,
            policy,
        }
    }
    fn contract(&self) -> TaskContract {
        TaskContract::new(
            &self.model,
            self.context.clone(),
            self.requests.clone(),
            self.state.clone(),
            self.bindings.clone(),
            self.policy,
            10,
            950,
        )
        .unwrap()
    }
    fn claim(&self) -> Claim {
        produce(&self.model, &self.contract(), 20, Kernel::Grouped).unwrap()
    }
}
fn rehash(claim: &mut Claim) {
    claim.statement_commitment = claim.commitment().unwrap();
}
fn policy() -> Policy {
    Policy {
        shift: 1,
        clamp_abs: 3,
        activation: Activation::Identity,
        stop_rule: StopRule::MarginAtLeast(2),
    }
}

#[test]
fn signed_division_is_toward_zero_and_exposes_exact_remainders() {
    let out = postprocess([-7, -1, 7], policy()).unwrap();
    assert_eq!(out.quotient, [-3, 0, 3]);
    assert_eq!(out.remainder, [-1, -1, 1]);
    assert_eq!(out.clamped, [-3, 0, 3]);
    for (x, (q, r)) in [-7, -1, 7]
        .into_iter()
        .zip(out.quotient.into_iter().zip(out.remainder))
    {
        assert_eq!(x, 2 * q + r);
        assert!(r.abs() < 2);
    }
    assert_eq!(out.prediction, 2);
    assert_eq!(out.margin, 3);
    assert!(out.stop);
}

#[test]
fn clamp_relu_ties_and_stop_are_explicit_semantic_changes() {
    let mut p = policy();
    p.activation = Activation::Relu;
    let out = postprocess([-7, -1, -3], p).unwrap();
    assert_eq!(out.activated, [0; 3]);
    assert_eq!(out.prediction, 0); // Raw logits would choose class 1.
    assert_eq!(out.margin, 0);
    assert!(!out.stop);
    let out = postprocess([20, 18, -20], p).unwrap();
    assert_eq!(out.clamped, [3, 3, -3]);
    assert_eq!(out.activated, [3, 3, 0]);
    assert_eq!(out.prediction, 0);
    assert!(!out.stop);
}

#[test]
fn stop_threshold_checks_below_equality_above_and_disabled() {
    let mut p = policy();
    p.shift = 0;
    for (raw, expected) in [([1, 0, -1], false), ([2, 0, -1], true), ([3, 0, -1], true)] {
        assert_eq!(postprocess(raw, p).unwrap().stop, expected);
    }
    p.stop_rule = StopRule::Disabled;
    assert!(!postprocess([3, -3, -3], p).unwrap().stop);
}

#[test]
fn exact_numeric_extremes_and_unsupported_policies() {
    let mut p = policy();
    p.shift = 0;
    p.clamp_abs = MAX_CLAMP;
    let row = postprocess([-MAX_MERGED_OUTPUT, MAX_MERGED_OUTPUT, 0], p).unwrap();
    assert_eq!(row.clamped, [-MAX_CLAMP, MAX_CLAMP, 0]);
    p.shift = MAX_SHIFT;
    assert_eq!(
        postprocess([-MAX_MERGED_OUTPUT, MAX_MERGED_OUTPUT, 0], p)
            .unwrap()
            .quotient,
        [0; 3]
    );
    for raw in [
        i64::MIN,
        i64::MAX,
        -MAX_MERGED_OUTPUT - 1,
        MAX_MERGED_OUTPUT + 1,
    ] {
        assert_eq!(postprocess([raw, 0, 0], p), Err("RAW_OUTPUT_RANGE"));
    }
    for shift in [31, 255] {
        p.shift = shift;
        assert!(p.validate().is_err());
    }
    p = policy();
    for clamp in [i32::MIN, -1, 0, MAX_CLAMP + 1, i32::MAX] {
        p.clamp_abs = clamp;
        assert!(p.validate().is_err());
    }
    p = policy();
    for threshold in [0, MAX_STOP_MARGIN + 1, u32::MAX] {
        p.stop_rule = StopRule::MarginAtLeast(threshold);
        assert!(p.validate().is_err());
    }
}

#[test]
fn direct_grouped_and_independent_verifier_match_all_shapes() {
    for n in [1, 2, 3, 4, 16, MAX_BATCH] {
        let f = Fixture::new(n);
        let expected = f.contract();
        let grouped = produce(&f.model, &expected, 20, Kernel::Grouped).unwrap();
        let direct = produce(&f.model, &expected, 20, Kernel::Direct).unwrap();
        assert_eq!(grouped, direct);
        assert_eq!(
            grouped.linear.product.routes,
            (0..n).map(|i| i % 3).collect::<Vec<_>>()
        );
        assert_eq!(
            grouped.linear.product.useful_dense_macs,
            (6 * DIM * n) as u64
        );
        assert_eq!(grouped.linear.product.padded_macs, 0);
        let verified = verify(&f.model, &expected, &grouped, || 20).unwrap();
        assert_eq!(verified.contract_id(), expected.id());
        assert_eq!(verified.rows(), grouped.rows);
        assert_eq!(verified.after_state(), &f.state);
        assert_eq!(verified.completed_at_ns(), 20);
        assert_eq!(
            verified.statement_commitment(),
            grouped.statement_commitment
        );
        let encoded = grouped.to_bytes().unwrap();
        assert_eq!(encoded.len(), 297 + 130 * n);
        assert!(encoded.len() <= MAX_CLAIM_BYTES);
        let decoded = Claim::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, grouped);
        assert_eq!(decoded.to_bytes().unwrap(), encoded);
        verify(&f.model, &expected, &decoded, || 20).unwrap();
    }
}

#[test]
fn binds_every_external_context_state_provenance_use_and_policy_field() {
    let original = Fixture::new(4);
    let claim = original.claim();
    let original_id = original.contract().id();
    for field in 0..19 {
        let mut other = Fixture::new(4);
        match field {
            0 => other.context.chain[0] ^= 1,
            1 => other.context.parent[0] ^= 1,
            2 => other.context.challenge[0] ^= 1,
            3 => other.context.batch_id[0] ^= 1,
            4 => other.state.cell_id[0] ^= 1,
            5 => other.state.generation += 1,
            6 => other.state.snapshot_root[0] ^= 1,
            7 => other.bindings.program_digest[0] ^= 1,
            8 => other.bindings.extractor_digest[0] ^= 1,
            9 => other.bindings.source_inputs_digest[0] ^= 1,
            10 => other.bindings.consumer[0] ^= 1,
            11 => other.bindings.allowed_use[0] ^= 1,
            12 => other.bindings.candidate_artifact[0] ^= 1,
            13 => other.policy.shift += 1,
            14 => other.policy.clamp_abs -= 1,
            15 => other.policy.activation = Activation::Identity,
            16 => other.policy.stop_rule = StopRule::Disabled,
            17 => other.policy.stop_rule = StopRule::MarginAtLeast(9),
            18 => other.requests.swap(0, 1),
            _ => unreachable!(),
        }
        let expected = other.contract();
        assert_ne!(expected.id(), original_id, "field {field}");
        assert_eq!(
            verify(&other.model, &expected, &claim, || 20).unwrap_err(),
            "EXPECTED_CONTRACT",
            "field {field}"
        );
    }
}

#[test]
fn binds_request_ids_scopes_time_and_every_feature() {
    let original = Fixture::new(1);
    let input = original.contract().input_commitment();
    for field in 0..DIM + 3 {
        let mut other = Fixture::new(1);
        match field {
            0 => other.requests[0].id[0] ^= 1,
            1 => other.requests[0].scope[0] ^= 1,
            2 => other.requests[0].arrival_ns += 1,
            3 => other.requests[0].deadline_ns -= 1,
            _ => {
                let index = field - 4;
                other.requests[0].x[index] = if other.requests[0].x[index] == 8 {
                    7
                } else {
                    other.requests[0].x[index] + 1
                };
            }
        }
        assert_ne!(other.contract().input_commitment(), input, "field {field}");
    }
    // Bias is fixed by the reused operator, not silently ignored.
    let mut other = Fixture::new(1);
    other.requests[0].x[DIM - 1] = 7;
    assert!(TaskContract::new(
        &other.model,
        other.context,
        other.requests,
        other.state,
        other.bindings,
        other.policy,
        10,
        950
    )
    .is_err());
}

#[test]
fn binds_window_and_original_model_even_with_equal_current_outputs() {
    let mut f = Fixture::new(1);
    let old = f.contract();
    let newer = TaskContract::new(
        &f.model,
        f.context.clone(),
        f.requests.clone(),
        f.state.clone(),
        f.bindings.clone(),
        f.policy,
        11,
        949,
    )
    .unwrap();
    assert_ne!(old.id(), newer.id());
    let claim = f.claim();
    // An unselected expert changes model identity although this batch's route is 0.
    f.raw_model.deltas[2][0][99] += 1;
    let other = PreparedModel::new(f.raw_model).unwrap();
    assert_eq!(
        verify(&other, &old, &claim, || 20).unwrap_err(),
        "EXPECTED_MODEL"
    );
    f.state.model_commitment = other.commitment();
    let alternate = TaskContract::new(
        &other, f.context, f.requests, f.state, f.bindings, f.policy, 10, 950,
    )
    .unwrap();
    assert_ne!(old.id(), alternate.id());
}

#[test]
fn contract_refuses_unsupported_dimensions_duplicate_ids_and_deadlines() {
    for n in [0, MAX_BATCH + 1] {
        let f = Fixture::new(n);
        assert!(TaskContract::new(
            &f.model, f.context, f.requests, f.state, f.bindings, f.policy, 10, 950
        )
        .is_err());
    }
    for alteration in 0..6 {
        let mut f = Fixture::new(2);
        match alteration {
            0 => f.requests[1].id = f.requests[0].id,
            1 => f.requests[0].x[0] = 9,
            2 => f.requests[0].arrival_ns = 11,
            3 => f.requests[0].deadline_ns = 10,
            4 => f.state.model_commitment[0] ^= 1,
            5 => f.requests[0].arrival_ns = f.requests[0].deadline_ns,
            _ => unreachable!(),
        }
        assert!(TaskContract::new(
            &f.model, f.context, f.requests, f.state, f.bindings, f.policy, 10, 950
        )
        .is_err());
    }
    let f = Fixture::new(1);
    assert!(TaskContract::new(
        &f.model, f.context, f.requests, f.state, f.bindings, f.policy, 10, 10
    )
    .is_err());
}

#[test]
fn every_postprocessing_stage_rejects_rehashed_forgery() {
    let f = Fixture::new(4);
    let expected = f.contract();
    for field in 0..7 {
        let mut claim = f.claim();
        match field {
            0 => claim.rows[0].quotient[0] += 1,
            1 => claim.rows[0].remainder[0] += 1,
            2 => claim.rows[0].clamped[0] += 1,
            3 => claim.rows[0].activated[0] += 1,
            4 => claim.rows[0].prediction = (claim.rows[0].prediction + 1) % 3,
            5 => claim.rows[0].margin += 1,
            6 => claim.rows[0].stop = !claim.rows[0].stop,
            _ => unreachable!(),
        }
        rehash(&mut claim);
        assert_eq!(
            verify(&f.model, &expected, &claim, || 20).unwrap_err(),
            "POSTPROCESS_RELATION",
            "field {field}"
        );
    }
}

#[test]
fn linear_and_partition_forgery_still_reaches_original_full_verifier() {
    let f = Fixture::new(4);
    let expected = f.contract();
    for field in 0..7 {
        let mut claim = f.claim();
        match field {
            0 => claim.linear.product.router_outputs[0][0] += 1,
            1 => claim.linear.product.routes[0] = 1,
            2 => claim.linear.product.logits[0][0] += 1,
            3 => {
                claim.linear.product.predictions[0] = (claim.linear.product.predictions[0] + 1) % 3
            }
            4 => claim.linear.product.groups[0].reverse(),
            5 => claim.linear.product.useful_dense_macs += 1,
            6 => claim.linear.statement_commitment[0] ^= 1,
            _ => unreachable!(),
        }
        rehash(&mut claim);
        assert!(
            verify(&f.model, &expected, &claim, || 20).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn read_only_state_is_not_authorized_to_advance() {
    let f = Fixture::new(1);
    for field in 0..4 {
        let mut claim = f.claim();
        match field {
            0 => claim.after_state.generation += 1,
            1 => claim.after_state.snapshot_root[0] ^= 1,
            2 => claim.after_state.cell_id[0] ^= 1,
            3 => claim.after_state.model_commitment[0] ^= 1,
            _ => unreachable!(),
        }
        rehash(&mut claim);
        assert_eq!(
            verify(&f.model, &f.contract(), &claim, || 20).unwrap_err(),
            "READ_ONLY_STATE"
        );
    }
}

#[test]
fn verification_must_finish_before_both_deadlines_and_clock_cannot_regress() {
    let f = Fixture::new(1);
    for (times, error) in [
        ([9, 20], "CONTRACT_DEADLINE"),
        ([20, 900], "REQUEST_DEADLINE"),
        ([20, 950], "CONTRACT_DEADLINE"),
        ([20, 19], "CLOCK_REGRESSION"),
    ] {
        let mut times = times.into_iter();
        assert_eq!(
            verify(&f.model, &f.contract(), &f.claim(), || times
                .next()
                .unwrap())
            .unwrap_err(),
            error
        );
    }
    let mut times = [20, 899].into_iter();
    assert_eq!(
        verify(&f.model, &f.contract(), &f.claim(), || times
            .next()
            .unwrap())
        .unwrap()
        .completed_at_ns(),
        899
    );
}

#[test]
fn byte_decoder_is_bounded_exact_and_rejects_noncanonical_boolean() {
    let f = Fixture::new(1);
    let bytes = f.claim().to_bytes().unwrap();
    for prefix in 0..bytes.len() {
        assert!(Claim::from_bytes(&bytes[..prefix]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(Claim::from_bytes(&trailing).unwrap_err(), "WIRE_SIZE");
    assert_eq!(
        Claim::from_bytes(&vec![0; MAX_CLAIM_BYTES + 1]).unwrap_err(),
        "WIRE_SIZE"
    );
    let mut bad = bytes.clone();
    bad[7] = 1;
    assert_eq!(Claim::from_bytes(&bad).unwrap_err(), "WIRE_VERSION");
    let mut bad = bytes.clone();
    bad[8..10].copy_from_slice(&65_u16.to_be_bytes());
    assert_eq!(Claim::from_bytes(&bad).unwrap_err(), "WIRE_SIZE");
    let mut bad = bytes.clone();
    bad[242 + 50..242 + 52].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(Claim::from_bytes(&bad).unwrap_err(), "WIRE_GROUP_SIZE");
    let mut bad = bytes;
    let stop_offset = bad.len() - 33;
    bad[stop_offset] = 2;
    assert_eq!(Claim::from_bytes(&bad).unwrap_err(), "WIRE_BOOL");
}

#[test]
fn every_single_byte_tamper_is_rejected_by_decode_or_full_verification() {
    let f = Fixture::new(1);
    let expected = f.contract();
    let bytes = f.claim().to_bytes().unwrap();
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 1;
        if let Ok(claim) = Claim::from_bytes(&bad) {
            assert!(
                verify(&f.model, &expected, &claim, || 20).is_err(),
                "tamper at {i}"
            );
        }
    }
}

#[test]
fn oversized_materialized_claims_fail_before_encoding_or_relation_work() {
    let f = Fixture::new(1);
    let mut claim = f.claim();
    claim.rows.resize(MAX_BATCH + 1, claim.rows[0].clone());
    assert_eq!(claim.to_bytes(), Err("CLAIM_SHAPE"));
    assert_eq!(
        verify(&f.model, &f.contract(), &claim, || 20).unwrap_err(),
        "CLAIM_SHAPE"
    );
    let mut claim = f.claim();
    claim.linear.product.groups[0].resize(MAX_BATCH + 1, 0);
    assert_eq!(claim.to_bytes(), Err("CLAIM_SHAPE"));
}

#[test]
fn reproducible_known_answer_fixture() {
    let f = Fixture::new(4);
    let expected = f.contract();
    let claim = f.claim();
    println!("contract={}", hex::encode(expected.id()));
    println!("input={}", hex::encode(expected.input_commitment()));
    println!("statement={}", hex::encode(claim.statement_commitment));
    println!("rows={:?}", claim.rows);
    assert_eq!(claim.to_bytes().unwrap().len(), 817);
    assert_eq!(
        hex::encode(expected.id()),
        "b134d049980556f02edb275d79acd202417186ce98670a957031d75a24bf9d46"
    );
    assert_eq!(
        hex::encode(expected.input_commitment()),
        "0bf927cecfa78f57a5fac805621b2888523cc1dd5083062e4268065c7e4ea887"
    );
    assert_eq!(
        hex::encode(claim.statement_commitment),
        "68b14249be9ab601ef757edd4a9562d2dfcfb4116bf653e93794a0fa34ce63a5"
    );
}

fn task_value(f: &Fixture) -> serde_json::Value {
    use serde_json::json;
    let mat = |m: &[[i32; DIM]; CLASSES]| m.iter().map(|row| row.to_vec()).collect::<Vec<_>>();
    json!({
        "schema": "pon-useful-cell-task-v2",
        "model": {"model_version":hex::encode(f.raw_model.version),"base":mat(&f.raw_model.base),"router":mat(&f.raw_model.router),"deltas":f.raw_model.deltas.iter().map(mat).collect::<Vec<_>>()},
        "context": {"chain":hex::encode(f.context.chain),"parent":hex::encode(f.context.parent),"challenge":hex::encode(f.context.challenge),"batch_id":hex::encode(f.context.batch_id)},
        "requests":f.requests.iter().map(|r| json!({"id":hex::encode(r.id),"scope":hex::encode(r.scope),"arrival_ns":r.arrival_ns,"deadline_ns":r.deadline_ns,"x":r.x.to_vec()})).collect::<Vec<_>>(),
        "state":{"cell_id":hex::encode(f.state.cell_id),"generation":f.state.generation,"snapshot_root":hex::encode(f.state.snapshot_root),"model_commitment":hex::encode(f.state.model_commitment)},
        "bindings":{"program_digest":hex::encode(f.bindings.program_digest),"extractor_digest":hex::encode(f.bindings.extractor_digest),"source_inputs_digest":hex::encode(f.bindings.source_inputs_digest),"consumer":hex::encode(f.bindings.consumer),"allowed_use":hex::encode(f.bindings.allowed_use),"candidate_artifact":hex::encode(f.bindings.candidate_artifact)},
        "policy":{"shift":2,"clamp_abs":64,"activation":"relu","stop_rule":{"kind":"margin_at_least","threshold":8}},
        "issued_at_ns":10,"valid_until_ns":950,
    })
}

#[test]
fn strict_json_task_matches_typed_contract_and_rejects_alternate_encodings() {
    let f = Fixture::new(4);
    let value = task_value(&f);
    let bytes = serde_json::to_vec(&value).unwrap();
    let (model, expected) = task_json::parse(&bytes).unwrap();
    assert_eq!(model.commitment(), f.model.commitment());
    assert_eq!(expected.id(), f.contract().id());
    let mut padded = bytes.clone();
    padded.push(b'\n');
    assert_eq!(task_json::parse(&padded).unwrap_err(), "TASK_CANONICAL");
    let duplicate = String::from_utf8(bytes).unwrap().replace(
        "\"schema\":",
        "\"schema\":\"pon-useful-cell-task-v2\",\"schema\":",
    );
    assert_eq!(
        task_json::parse(duplicate.as_bytes()).unwrap_err(),
        "TASK_CANONICAL"
    );
    assert_eq!(
        task_json::parse(&vec![0; task_json::MAX_TASK_BYTES + 1]).unwrap_err(),
        "TASK_SIZE"
    );
}

#[test]
fn strict_json_task_rejects_unknown_semantics_and_malformed_model() {
    use serde_json::json;
    let f = Fixture::new(4);
    for case in 0..10 {
        let mut value = task_value(&f);
        match case {
            0 => value["schema"] = json!("pon-useful-cell-task-v1"),
            1 => value["policy"]["shift"] = json!(2.0),
            2 => value["policy"]["activation"] = json!("gelu"),
            3 => value["policy"]["stop_rule"]["threshold"] = json!(0),
            4 => value["policy"]["stop_rule"]["extra"] = json!(false),
            5 => value["model"]["base"][0] = json!([1, 2]),
            6 => value["requests"][0]["x"][0] = json!(true),
            7 => {
                value["state"]["model_commitment"] =
                    json!(hex::encode(f.state.model_commitment).to_uppercase())
            }
            8 => value["bindings"]["unbound_owner"] = json!("fake"),
            9 => value["issued_at_ns"] = json!(-1),
            _ => unreachable!(),
        }
        assert!(
            task_json::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
            "case {case}"
        );
    }
}
