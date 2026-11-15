//! Exact bounded stateful integer semantics, independently implemented in Rust.
//! Router and recurrent sign state have an explicit stop-gradient boundary;
//! these updates are not differentiable routing or backpropagation through time.
use super::*;

const MEMORY_BOUND: i64 = 8192;
// The sampling arithmetic intentionally matches the V2 integer reference. Work,
// contract, model and segment challenges nevertheless use the fresh native domain.
const RNG_DOMAIN: &[u8] = b"pon-useful-cell-execution-v2/positive-shift\0";

#[derive(Clone, Debug, Serialize)]
struct ActiveRow {
    row: usize,
    route: usize,
    logits: Vec<i64>,
    features: Vec<i64>,
    label: u8,
}

#[derive(Clone, Debug, Serialize)]
struct Parameters {
    base: Matrix,
    deltas: Vec<Matrix>,
}

fn zero_matrix() -> Matrix {
    vec![vec![0; DIM]; 3]
}

fn zero_parameters() -> Parameters {
    Parameters {
        base: zero_matrix(),
        deltas: vec![zero_matrix(); 3],
    }
}

fn group(parameters: &Parameters, index: usize) -> &Matrix {
    if index == 0 {
        &parameters.base
    } else {
        &parameters.deltas[index - 1]
    }
}

fn group_mut(parameters: &mut Parameters, index: usize) -> &mut Matrix {
    if index == 0 {
        &mut parameters.base
    } else {
        &mut parameters.deltas[index - 1]
    }
}

fn sample(scores: &[i64], seed: &str, mut counter: u64) -> Result<(usize, u64, Value)> {
    let minimum = scores.iter().min().ok_or("CELL_SAMPLE_SHAPE")?;
    let masses: Vec<u64> = scores
        .iter()
        .map(|score| (score - minimum + 1) as u64)
        .collect();
    let total: u64 = masses.iter().sum();
    let mut remainder = 1 % total;
    for _ in 0..256 {
        remainder = (remainder * 2) % total;
    }
    // 2^256 - (2^256 mod total), as 33 big-endian bytes. No floating point,
    // modulo bias, u64 truncation of a digest, or wrapping seed counter.
    let mut limit = [0u8; 33];
    limit[0] = 1;
    let mut borrow = remainder;
    for byte in limit.iter_mut().rev() {
        let sub = (borrow & 255) as u16;
        borrow >>= 8;
        if u16::from(*byte) < sub {
            *byte = (u16::from(*byte) + 256 - sub) as u8;
            borrow += 1;
        } else {
            *byte -= sub as u8;
        }
    }
    let limit_hex = hex::encode(limit)[1..].to_owned();
    let seed = digest(seed)?;
    let mut draws = Vec::new();
    for _ in 0..64 {
        ensure(counter < u64::MAX, "CELL_RNG_COUNTER_OVERFLOW")?;
        let mut hasher = Sha256::new();
        hasher.update(RNG_DOMAIN);
        hasher.update(seed);
        hasher.update(counter.to_le_bytes());
        let value: Hash = hasher.finalize().into();
        let accepted = limit[0] == 1 || value.as_slice() < &limit[1..];
        draws.push(json!({"counter":counter,"sha256":hex::encode(value),"accepted":accepted}));
        counter += 1;
        if accepted {
            let ticket = value
                .iter()
                .fold(0u64, |rem, byte| (rem * 256 + u64::from(*byte)) % total);
            let mut cumulative = 0;
            for (prediction, mass) in masses.iter().enumerate() {
                cumulative += mass;
                if ticket < cumulative {
                    return Ok((
                        prediction,
                        counter,
                        json!({
                            "masses":masses,"total":total,"limit_hex":limit_hex,
                            "ticket":ticket,"draws":draws,
                        }),
                    ));
                }
            }
            return Err("CELL_SAMPLE_CUMULATIVE".into());
        }
    }
    Err("CELL_RNG_REJECTION_LIMIT".into())
}

fn train(
    model: &Model,
    active: &[ActiveRow],
    optimizer: &Option<Optimizer>,
    spec: &Training,
) -> Result<(Model, Option<Optimizer>, Value, Vec<Stage>)> {
    let mut gradients = zero_parameters();
    let mut loss_rows = Vec::with_capacity(active.len());
    let mut derivatives = Vec::with_capacity(active.len());
    let mut total_loss = 0i64;
    for row in active {
        let target: Vec<i64> = (0..3)
            .map(|class| {
                if class == usize::from(row.label) {
                    8192
                } else {
                    0
                }
            })
            .collect();
        let errors: Vec<i64> = row
            .logits
            .iter()
            .zip(&target)
            .map(|(actual, target)| actual - target)
            .collect();
        let derivative: Vec<i64> = errors.iter().map(|error| 2 * error).collect();
        let mut loss = 0i64;
        for error in &errors {
            loss = loss
                .checked_add(error.checked_mul(*error).ok_or("CELL_LOSS_OVERFLOW")?)
                .ok_or("CELL_LOSS_OVERFLOW")?;
        }
        total_loss = total_loss.checked_add(loss).ok_or("CELL_LOSS_OVERFLOW")?;
        loss_rows.push(json!({"row":row.row,"target":target,"errors":errors,
            "loss":loss,"d_logits":derivative}));
        for (class, d_logit) in derivative.iter().enumerate() {
            for (coordinate, feature) in row.features.iter().enumerate() {
                let gradient = d_logit * feature;
                gradients.base[class][coordinate] += gradient;
                gradients.deltas[row.route][class][coordinate] += gradient;
            }
        }
        derivatives.push(derivative);
    }
    let mut stages = vec![
        Stage {
            stage: "training-loss".into(),
            inputs: json!({"active_rows":active}),
            outputs: json!({"rows":loss_rows,"loss":total_loss}),
        },
        Stage {
            stage: "training-backward".into(),
            inputs: json!({"features":active.iter().map(|r| &r.features).collect::<Vec<_>>(),
                "routes":active.iter().map(|r| r.route).collect::<Vec<_>>(),"d_logits":derivatives,
                "gradient_boundary":"frozen-route-and-discrete-state-stop-gradient;not-bptt"}),
            outputs: json!({"gradients":gradients,"router_gradients":zero_matrix()}),
        },
    ];
    if active.is_empty() {
        stages.push(Stage { stage: "training-update".into(),
            inputs: json!({"spec":spec,"optimizer":optimizer}),
            outputs: json!({"applied":false,"reason":"no-active-rows","optimizer":optimizer,"model":model}) });
        return Ok((
            model.clone(),
            optimizer.clone(),
            json!({
                "active_rows":0,"loss":0,"parameters_changed":false,
                "optimizer_step":optimizer.as_ref().map(|v| v.step),
            }),
            stages,
        ));
    }
    let old = optimizer.clone().unwrap_or_else(|| Optimizer {
        schema: OPTIMIZER_SCHEMA.into(),
        step: 0,
        base: zero_matrix(),
        deltas: vec![zero_matrix(); 3],
    });
    let mut moment = old.clone();
    moment.step = old
        .step
        .checked_add(1)
        .ok_or("CELL_OPTIMIZER_STEP_OVERFLOW")?;
    let mut updated = model.clone();
    let mut masked = zero_parameters();
    let mut clipped = zero_parameters();
    let mut updates = zero_parameters();
    for index in 0..4 {
        let (weights, mask, old_moment, new_moment) = if index == 0 {
            (
                &mut updated.base,
                &spec.trainable_mask.base,
                &old.base,
                &mut moment.base,
            )
        } else {
            (
                &mut updated.deltas[index - 1],
                &spec.trainable_mask.deltas[index - 1],
                &old.deltas[index - 1],
                &mut moment.deltas[index - 1],
            )
        };
        let raw_gradient = group(&gradients, index);
        let masked_gradient = group_mut(&mut masked, index);
        let clipped_gradient = group_mut(&mut clipped, index);
        let update = group_mut(&mut updates, index);
        for row in 0..3 {
            for coordinate in 0..DIM {
                if !mask[row][coordinate] {
                    // Frozen weights AND existing moments remain exact. There
                    // is no hidden decay, even for a nonzero old momentum.
                    continue;
                }
                let raw = raw_gradient[row][coordinate];
                masked_gradient[row][coordinate] = raw;
                let gradient = raw.clamp(-(spec.clip_abs as i64), spec.clip_abs as i64);
                clipped_gradient[row][coordinate] = gradient;
                let next = i128::from(gradient)
                    + i128::from(spec.momentum_num) * i128::from(old_moment[row][coordinate])
                        / i128::from(spec.momentum_den);
                ensure(
                    (-i128::from(i64::MAX)..=i128::from(i64::MAX)).contains(&next),
                    "CELL_MOMENT_OVERFLOW",
                )?;
                new_moment[row][coordinate] = next as i64;
                let change =
                    i128::from(spec.learning_rate_num) * next / i128::from(spec.learning_rate_den);
                let weight = i128::from(weights[row][coordinate]) - change;
                ensure(
                    (-32_767..=32_767).contains(&weight),
                    "CELL_TRAINED_WEIGHT_RANGE",
                )?;
                // A successful weight bound also bounds the retained delta.
                update[row][coordinate] =
                    i64::try_from(change).map_err(|_| Error::from("CELL_UPDATE_RANGE"))?;
                weights[row][coordinate] = weight as i64;
            }
        }
    }
    let summary = json!({"active_rows":active.len(),"loss":total_loss,
        "parameters_changed":updated != *model,"optimizer_step":moment.step});
    stages.push(Stage {
        stage: "training-update".into(),
        inputs: json!({"spec":spec,"model":model,"optimizer":optimizer,"gradients":gradients}),
        outputs: json!({"applied":true,"masked_gradients":masked,"clipped_gradients":clipped,
            "updates":updates,"optimizer":moment,"model":updated}),
    });
    Ok((updated, Some(moment), summary, stages))
}

pub(super) fn execute(
    admission: &OwnerAdmission,
    prepared: source::PreparedInputs,
    products: Vec<Vec<i64>>,
) -> Result<Execution> {
    let model = &admission.model;
    let policy = &admission.policy;
    let before = &admission.before;
    ensure(before.sequence < u64::MAX, "CELL_SEQUENCE_OVERFLOW")?;
    let mut stages = prepared.stages;
    stages.push(Stage { stage: "five-w1-products".into(),
        inputs: json!({"model":model,"model_artifact":model_artifact(model)?,"features":prepared.features,
            "ordered_bundle":["base","router","delta-0","delta-1","delta-2"]}),
        outputs: json!({"values":products,"shape":[15,admission.inputs.len()],"dtype":"signed-integer"}) });
    let mut after = before.clone();
    let mut output = json!({
        "schema":format!("{PROFILE}/output"),
        "row_ids":admission.inputs.iter().map(|r| &r.id).collect::<Vec<_>>(),
        "routes":[],"logits":[],"predictions":[],"labels":[],"actions":[],
        "stop":[],"abstain":[],"tool_proposals":[],"delivery_content":[],"training":null,
    });
    let mut active = Vec::with_capacity(admission.inputs.len());
    for (index, input) in admission.inputs.iter().enumerate() {
        let memory_before = after.memory.clone();
        let rng_before = after.rng_counter;
        let remaining_before = after.remaining_steps;
        let mut route = None;
        let mut scores = None;
        let mut prediction = None;
        let mut label = None;
        let mut proposal = Value::Null;
        let mut delivery = Value::Null;
        let mut sampling = Value::Null;
        let mut route_scores = None;
        let mut margin = None;
        let action;
        if remaining_before == 0 {
            action = Action::Stop;
        } else {
            let router: Vec<i64> = (0..3).map(|expert| products[3 + expert][index]).collect();
            let mut expert = policy.expert_mask[index]
                .iter()
                .position(|allowed| *allowed)
                .ok_or("CELL_EXPERT_MASK")?;
            for candidate in expert + 1..3 {
                if policy.expert_mask[index][candidate] && router[candidate] > router[expert] {
                    expert = candidate;
                }
            }
            let logits: Vec<i64> = (0..3)
                .map(|class| {
                    products[class][index]
                        + products[6 + 3 * expert + class][index]
                        + memory_before[class]
                })
                .collect();
            ensure(
                logits
                    .iter()
                    .all(|value| (-LOGIT_BOUND..=LOGIT_BOUND).contains(value)),
                "CELL_LOGIT_BOUND",
            )?;
            let mut ranked = [0usize, 1, 2];
            ranked.sort_by_key(|class| (-logits[*class], *class));
            let difference = logits[ranked[0]] - logits[ranked[1]];
            if difference < policy.abstain_margin as i64 {
                action = Action::Abstain;
            } else {
                let chosen = match policy.sampler {
                    Sampler::ArgmaxLowest => ranked[0],
                    Sampler::Sha256PositiveShift => {
                        let (chosen, counter, observed) =
                            sample(&logits, &after.rng_seed, rng_before)?;
                        after.rng_counter = counter;
                        sampling = observed;
                        chosen
                    }
                };
                prediction = Some(chosen);
                label = Some(CLASSES[chosen]);
                if let Some(tool) = &policy.tool_names[chosen] {
                    action = Action::ProposeTool;
                    proposal = json!({"name":tool,"arguments":{
                        "source_id":input.id,"label":CLASSES[chosen],"logits":logits,
                    }});
                } else {
                    action = Action::Emit;
                    delivery = json!({"kind":"classification","source_id":input.id,"label":CLASSES[chosen]});
                }
            }
            after.memory = memory_before
                .iter()
                .zip(&logits)
                .map(|(memory, logit)| (3 * memory + logit.signum() * MEMORY_BOUND).div_euclid(4))
                .collect();
            after.remaining_steps -= 1;
            active.push(ActiveRow {
                row: index,
                route: expert,
                logits: logits.clone(),
                features: prepared.features[index].clone(),
                label: input.label,
            });
            route = Some(expert);
            scores = Some(logits);
            route_scores = Some(router);
            margin = Some(difference);
        }
        ensure(
            policy.allowed_actions.contains(&action),
            "CELL_ACTION_NOT_ALLOWED",
        )?;
        for (key, value) in [
            ("routes", json!(route)),
            ("logits", json!(scores)),
            ("predictions", json!(prediction)),
            ("labels", json!(label)),
            ("actions", json!(action)),
            ("stop", json!(action == Action::Stop)),
            ("abstain", json!(action == Action::Abstain)),
            ("tool_proposals", proposal.clone()),
            ("delivery_content", delivery.clone()),
        ] {
            output[key]
                .as_array_mut()
                .expect("fixed output arrays")
                .push(value);
        }
        stages.push(Stage { stage: format!("decision/{index}"),
            inputs: json!({"source_id":input.id,"products":products.iter().map(|row| row[index]).collect::<Vec<_>>(),
                "expert_mask":policy.expert_mask[index],"memory":memory_before,
                "rng_seed":after.rng_seed,"rng_counter":rng_before,"remaining_steps":remaining_before,
                "sampler":policy.sampler,"abstain_margin":policy.abstain_margin,"tool_names":policy.tool_names,
                "allowed_actions":policy.allowed_actions}),
            outputs: json!({"route_scores":route_scores,"route":route,"logits":scores,"margin":margin,
                "sampling":sampling,"prediction":prediction,"action":action,"tool_proposal":proposal,
                "delivery_content":delivery,"memory":after.memory,"rng_counter":after.rng_counter,
                "remaining_steps":after.remaining_steps}) });
    }
    let after_model = if let Some(spec) = &policy.training {
        let (model, optimizer, summary, training_stages) =
            train(model, &active, &before.optimizer, spec)?;
        after.optimizer = optimizer;
        output["training"] = summary;
        stages.extend(training_stages);
        model
    } else {
        stages.push(Stage {
            stage: "training-disabled".into(),
            inputs: json!({"training":null}),
            outputs: json!({"model":model,"optimizer":before.optimizer}),
        });
        model.clone()
    };
    after.sequence += 1;
    after.model_artifact = model_artifact(&after_model)?;
    validate_state(&after, &after_model)?;
    stages.push(Stage {
        stage: "checkpoint".into(),
        inputs: json!({"before":before,"decisions":output}),
        outputs: json!({"after_state":after,"after_model_artifact":after.model_artifact}),
    });
    Ok(Execution {
        output,
        after_state: after,
        after_model,
        stages,
    })
}
