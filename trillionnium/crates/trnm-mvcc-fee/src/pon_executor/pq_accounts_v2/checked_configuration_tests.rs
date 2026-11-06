//! Same-call configuration mathematics; every State and signature check stays live.
use super::*;
use pon_executor::{
    ExecutionError, ExecutionProgress, ExecutionWorkerAccounting, ExecutionWorkerInterval,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

fn reset_digests() {
    CONFIG_DIGEST_CALLS.with(|calls| calls.set(0));
}

fn digests() -> usize {
    CONFIG_DIGEST_CALLS.with(std::cell::Cell::get)
}

#[test]
fn checked_configuration_rechecks_each_changed_source_before_other_errors() {
    let (cfg, state, _, a, b) = setup();
    let raw = ordinary(&cfg, &a, a.id, 1, 1, 1, &transfer_payload(b.id, 1));
    type Mutation = (&'static str, fn(&mut Config), &'static str);
    let mutations: &[Mutation] = &[
        (
            "params",
            |c| c.params["max_fee_limit"] = json!(1),
            "PQ2_CONFIG_CHANGED",
        ),
        (
            "registry",
            |c| c.model_registry["changed"] = json!(true),
            "PQ2_CONFIG_CHANGED",
        ),
        ("fees", |c| c.fees[1] += 1, "PQ2_CONFIG_CHANGED"),
        (
            "evaluators",
            |c| {
                c.evaluators.insert(hex::encode([217; 32]));
            },
            "PQ2_CONFIG_CHANGED",
        ),
        ("family", |c| c.family[0] ^= 1, "PQ2_CONFIG_CHANGED"),
        ("plan", |c| c.plan[0] ^= 1, "PQ2_CONFIG_CHANGED"),
        ("network", |c| c.network[0] ^= 1, "PQ2_CONFIG_CHANGED"),
        ("parameters", |c| c.parameters[0] ^= 1, "PQ2_CONFIG_CHANGED"),
        (
            "selector",
            |c| c.params[SELECTOR] = json!("changed"),
            "PQ2_CONFIG_CHANGED",
        ),
        (
            "anchor",
            |c| c.params["native_pq_v2_anchor"] = json!(hex::encode([218; 32])),
            "PQ2_CONFIG_CHANGED",
        ),
        (
            "competing-profile",
            |c| c.params["native_pq_profile"] = json!("changed"),
            "PQ2_CONFIG_CHANGED",
        ),
        (
            "missing-profile",
            |c| c.native_pq_v2 = None,
            "PQ2_PROFILE_REQUIRED",
        ),
        (
            "zero-genesis",
            |c| {
                Arc::make_mut(c.native_pq_v2.as_mut().unwrap())
                    .context
                    .genesis = [0; 32]
            },
            "PQ2_GENESIS",
        ),
    ];
    for &(name, change, error) in mutations {
        // Warm exactly this Config object, then mutate that same object between
        // calls. A pointer/profile-ID cache would incorrectly accept some cases.
        let mut current = cfg.clone();
        validate_block(
            &state,
            std::slice::from_ref(&raw),
            a.id,
            Some(1001),
            &current,
        )
        .unwrap();
        prepare_signature(&state, &raw, 1001, &current).unwrap();
        change(&mut current);
        for malformed in [false, true] {
            let candidate = if malformed { Vec::new() } else { raw.clone() };
            assert_eq!(
                validate_block(
                    &state,
                    std::slice::from_ref(&candidate),
                    [0; 32],
                    None,
                    &current
                ),
                Err(error),
                "{name}, malformed={malformed}"
            );
            let attempts = AtomicUsize::new(0);
            assert_eq!(
                prepare_signature_metered(&state, &candidate, 1001, &current, &attempts).err(),
                Some(error),
                "{name}, malformed={malformed}"
            );
            assert_eq!(attempts.load(Ordering::Relaxed), 0);
        }
        // The rejected call also cannot poison another fresh exact source.
        current = cfg.clone();
        validate_block(
            &state,
            std::slice::from_ref(&raw),
            a.id,
            Some(1001),
            &current,
        )
        .unwrap();
        prepare_signature(&state, &raw, 1001, &current).unwrap();
    }
    assert_eq!(
        validate_block(&state, &[Vec::new()], [0; 32], None, &cfg),
        Err("PQ2_BLOCK_CONTEXT")
    );
    assert_eq!(
        validate_block(&state, &[Vec::new()], a.id, Some(1001), &cfg),
        Err("PQ2_ENCODING")
    );
    assert_eq!(
        prepare_signature(&state, &[], 1001, &cfg).err(),
        Some("PQ2_ENCODING")
    );
}

#[test]
fn checked_configuration_bounds_digest_work_without_reusing_authority_or_budget() {
    let (cfg, state, _, a, b) = setup();
    let next = Key::public_test_seed(106);
    let single = ordinary(&cfg, &a, a.id, 1, 1, 1, &transfer_payload(b.id, 1));
    let dual = rotation(&cfg, &state, a.id, 1, 1, &a, &next);
    let transactions: Vec<_> = (1..=8)
        .map(|nonce| ordinary(&cfg, &a, a.id, nonce, 1, 1, &transfer_payload(b.id, 1)))
        .collect();
    for count in [0, 1, 8] {
        reset_digests();
        validate_block(&state, &transactions[..count], a.id, Some(1001), &cfg).unwrap();
        // One fresh configuration view plus the retained complete parent-State
        // validation. Neither count scales with the number of envelopes.
        assert_eq!(digests(), 2);
    }
    for (raw, expected) in [(&single, 1), (&dual, 2)] {
        let attempts = AtomicUsize::new(0);
        reset_digests();
        let prepared = prepare_signature_metered(&state, raw, 1001, &cfg, &attempts).unwrap();
        assert_eq!(digests(), 1);
        assert_eq!(prepared.signature_count(), expected);
        assert_eq!(attempts.load(Ordering::Relaxed), expected);
    }

    let maximum = account_profile(&cfg).unwrap().maximum_verifications();
    let almost_full = AtomicUsize::new(maximum - 1);
    assert_eq!(
        prepare_signature_metered(&state, &dual, 1001, &cfg, &almost_full).err(),
        Some("PQ_VERIFY_BUDGET")
    );
    assert_eq!(almost_full.load(Ordering::Relaxed), maximum);
    assert_eq!(
        prepare_signature_metered(&state, &single, 1001, &cfg, &almost_full).err(),
        Some("PQ_VERIFY_BUDGET")
    );
    assert_eq!(almost_full.load(Ordering::Relaxed), maximum);

    let mut bad_signature = dual.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let attempts = AtomicUsize::new(0);
    assert_eq!(
        prepare_signature_metered(&state, &bad_signature, 1001, &cfg, &attempts).err(),
        Some("PQ2_SIGNATURE")
    );
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        2,
        "failed second proof is charged"
    );
    assert_eq!(
        prepare_signature_metered(&state, &bad_signature, 1001, &cfg, &almost_full).err(),
        Some("PQ_VERIFY_BUDGET"),
        "budget rejection still precedes the invalid signature"
    );
    let expired = AtomicUsize::new(0);
    assert_eq!(
        prepare_signature_metered(&state, &single, 2001, &cfg, &expired).err(),
        Some("PQ2_SIGNATURE")
    );
    assert_eq!(expired.load(Ordering::Relaxed), 1);

    let prepared = prepare_signature(&state, &single, 1001, &cfg).unwrap();
    let rotated = execute(&state, &cfg, 1, a.id, &[dual], Some(1001)).unwrap();
    assert_eq!(
        apply(&rotated.state, &prepared, 2, &cfg, None).err(),
        Some("PQ2_STALE_AUTHORITY")
    );
    assert_eq!(
        prepare_signature_metered(&rotated.state, &single, 1002, &cfg, &almost_full).err(),
        Some("PQ2_STALE_AUTHORITY"),
        "current authority is resolved before charging an exhausted budget"
    );
    assert_eq!(almost_full.load(Ordering::Relaxed), maximum);
    let spent = execute(&state, &cfg, 1, a.id, &[single], Some(1001)).unwrap();
    assert_eq!(
        apply(&spent.state, &prepared, 2, &cfg, None).err(),
        Some("NONCE")
    );
}

struct RotationBatch {
    cfg: Config,
    state: State,
    keys: Vec<Key>,
    next: Vec<Key>,
    raws: Vec<Vec<u8>>,
}
impl RotationBatch {
    fn new() -> Self {
        let keys: Vec<_> = (110..118).map(Key::public_test_seed).collect();
        let next: Vec<_> = (120..128).map(Key::public_test_seed).collect();
        let accounts: Vec<_> = keys
            .iter()
            .map(|key| GenesisAccount {
                spki: key.spki.clone(),
                balance: 10_000_000,
            })
            .collect();
        let (cfg, state, _) = genesis(&accounts, 1000).unwrap();
        let raws = keys
            .iter()
            .zip(&next)
            .map(|(prior, next)| rotation(&cfg, &state, prior.id, 1, 1, prior, next))
            .collect();
        Self {
            cfg,
            state,
            keys,
            next,
            raws,
        }
    }
    fn block<'a>(&self, raws: &'a [Vec<u8>], workers: usize) -> BlockExecution<'a> {
        BlockExecution {
            timestamp: Some(1001),
            transactions: raws,
            height: 1,
            miner: self.keys[0].id,
            parent_id: [1; 32],
            workers,
        }
    }
}

#[derive(Default)]
struct JoinedWorkers {
    spawned: AtomicUsize,
    started: AtomicUsize,
    finished: AtomicUsize,
    active: AtomicUsize,
}
struct WorkerInterval<'a>(&'a JoinedWorkers);
impl ExecutionWorkerInterval for WorkerInterval<'_> {}
impl Drop for WorkerInterval<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.finished.fetch_add(1, Ordering::SeqCst);
    }
}
impl ExecutionWorkerAccounting for JoinedWorkers {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        Some(Box::new(WorkerInterval(self)))
    }
    fn worker_spawn_succeeded(&self) {
        self.spawned.fetch_add(1, Ordering::SeqCst);
    }
}
impl JoinedWorkers {
    fn assert_joined(&self, workers: usize) {
        let expected = if workers == 1 { 0 } else { workers };
        assert_eq!(self.spawned.load(Ordering::SeqCst), expected);
        assert_eq!(self.started.load(Ordering::SeqCst), expected);
        assert_eq!(self.finished.load(Ordering::SeqCst), expected);
        assert_eq!(self.active.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn checked_configuration_parallel_dual_proofs_keep_canonical_callbacks_and_effects() {
    let batch = RotationBatch::new();
    let original = batch.state.clone();
    let reference = execute(
        &batch.state,
        &batch.cfg,
        1,
        batch.keys[0].id,
        &batch.raws,
        Some(1001),
    )
    .unwrap();
    let mut expected_steps = vec![
        ExecutionProgress::BeforeStateClone,
        ExecutionProgress::AfterMandatory,
    ];
    for index in 0..batch.raws.len() {
        expected_steps.extend([
            ExecutionProgress::BeforeApply { index },
            ExecutionProgress::AfterApply { index },
        ]);
    }
    expected_steps.extend([
        ExecutionProgress::BeforeReward,
        ExecutionProgress::BeforeCommitment,
        ExecutionProgress::AfterCommitment,
        ExecutionProgress::BeforeOutput,
    ]);
    for workers in [1, 2, 4, 8] {
        let caller = std::thread::current().id();
        let accounting = JoinedWorkers::default();
        let prepared = Mutex::new(BTreeSet::new());
        let owner_steps = Mutex::new(Vec::new());
        let progress = |point| {
            match point {
                ExecutionProgress::BeforePrepare { .. } => {
                    assert_eq!(std::thread::current().id() == caller, workers == 1);
                    reset_digests();
                }
                ExecutionProgress::AfterPrepare { index } => {
                    assert_eq!(std::thread::current().id() == caller, workers == 1);
                    // The outer original prepare API validates its profile too;
                    // the inner call remains one digest for both real proofs.
                    assert_eq!(digests(), 2);
                    assert!(prepared.lock().unwrap().insert(index));
                }
                _ => {
                    assert_eq!(std::thread::current().id(), caller, "state left its owner");
                    owner_steps.lock().unwrap().push(point);
                }
            }
            Ok::<_, &'static str>(())
        };
        let output = pon_executor::execute_with_control(
            &batch.state,
            batch.block(&batch.raws, workers),
            &batch.cfg,
            &ExecutionControl::new(&progress, &accounting),
        )
        .unwrap();
        accounting.assert_joined(workers);
        assert_eq!(prepared.into_inner().unwrap(), (0..8).collect());
        assert_eq!(owner_steps.into_inner().unwrap(), expected_steps);
        assert_eq!(output.state, reference.state);
        assert_eq!(output.root, reference.root);
        assert_eq!(output.receipts, reference.receipts);
        assert_eq!(output.metrics.signature_verifications, 16);
        assert_eq!(output.metrics.speculative, 0);
        assert_eq!(output.metrics.reexecuted, 0);
        assert_eq!(output.metrics.committed_without_replay, 8);
        for (prior, next) in batch.keys.iter().zip(&batch.next) {
            let name = hex::encode(prior.id);
            assert_eq!(output.state[&format!("account:{name}")]["nonce"], 1);
            assert_eq!(output.state[&auth_key(&name)], authority(2, next.id, false));
            assert_eq!(
                output.state[&status_key(&name, 1)],
                authority(1, prior.id, true)
            );
        }
        assert_eq!(batch.state, original);
    }
}

#[test]
fn checked_configuration_cancellation_joins_and_later_bad_proof_preserves_first_state_error() {
    let batch = RotationBatch::new();
    let original = batch.state.clone();
    let mut invalid = batch.raws.clone();
    invalid[0] = rotation(
        &batch.cfg,
        &batch.state,
        batch.keys[0].id,
        2,
        1,
        &batch.keys[0],
        &batch.next[0],
    );
    *invalid[1].last_mut().unwrap() ^= 1;
    for workers in [1, 2, 4, 8] {
        let accounting = JoinedWorkers::default();
        let applies = AtomicUsize::new(0);
        let cancelled = pon_executor::execute_with_control(
            &batch.state,
            batch.block(&batch.raws, workers),
            &batch.cfg,
            &ExecutionControl::new(
                &|point| {
                    if matches!(point, ExecutionProgress::BeforeApply { .. }) {
                        applies.fetch_add(1, Ordering::Relaxed);
                    }
                    if point == (ExecutionProgress::AfterPrepare { index: 0 }) {
                        Err("PQ_CONFIG_CANCEL")
                    } else {
                        Ok(())
                    }
                },
                &accounting,
            ),
        );
        assert!(matches!(
            cancelled,
            Err(ExecutionError::Cancelled("PQ_CONFIG_CANCEL"))
        ));
        accounting.assert_joined(workers);
        assert_eq!(applies.load(Ordering::Relaxed), 0);
        assert_eq!(batch.state, original);

        let accounting = JoinedWorkers::default();
        let applied = Mutex::new(Vec::new());
        let rejected = pon_executor::execute_with_control(
            &batch.state,
            batch.block(&invalid, workers),
            &batch.cfg,
            &ExecutionControl::new(
                &|point| {
                    if let ExecutionProgress::BeforeApply { index } = point {
                        applied.lock().unwrap().push(index);
                    }
                    Ok::<_, &'static str>(())
                },
                &accounting,
            ),
        );
        assert!(matches!(rejected, Err(ExecutionError::Relation("NONCE"))));
        accounting.assert_joined(workers);
        assert_eq!(applied.into_inner().unwrap(), vec![0]);
        assert_eq!(batch.state, original);

        let retry = pon_executor::execute_with_control(
            &batch.state,
            batch.block(&batch.raws, workers),
            &batch.cfg,
            &ExecutionControl::new(&pon_executor::no_cancellation, &()),
        )
        .unwrap();
        assert_eq!(retry.metrics.signature_verifications, 16);
        assert_eq!(batch.state, original);
    }
}

#[test]
fn checked_configuration_parallel_preparations_share_the_actual_signature_limit() {
    let (cfg, state, _, a, _) = setup();
    let next = Key::public_test_seed(106);
    let raw = rotation(&cfg, &state, a.id, 1, 1, &a, &next);
    let maximum = account_profile(&cfg).unwrap().maximum_verifications();
    let attempts = AtomicUsize::new(maximum - 3);
    let start = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    reset_digests();
                    let result = prepare_signature_metered(&state, &raw, 1001, &cfg, &attempts)
                        .map(|prepared| prepared.signature_count());
                    assert_eq!(digests(), 1);
                    result
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts.load(Ordering::Relaxed), maximum);
    assert_eq!(results.iter().filter(|result| **result == Ok(2)).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err("PQ_VERIFY_BUDGET"))
            .count(),
        1
    );
    assert_eq!(
        prepare_signature_metered(&state, &raw, 1001, &cfg, &attempts).err(),
        Some("PQ_VERIFY_BUDGET")
    );
    assert_eq!(attempts.load(Ordering::Relaxed), maximum);
}

// Frozen complete preparation entry from integration a303f71e7, before this
// change. Only its name and the call to the separately retained original charge
// helper differ. It is compiled solely for these differential/local-cost controls.
fn original_prepare_signature_metered(
    parent: &State,
    raw: &[u8],
    timestamp: u64,
    cfg: &Config,
    signatures: &AtomicUsize,
) -> Result<PreparedCommand> {
    let context = context(cfg)?;
    let tx = decode_for_config(raw, cfg)?;
    require(tx.common.context == context, "PQ2_CONTEXT")?;
    require(tx.common.max_fee <= cfg.limit("max_fee_limit")?, "FEE")?;
    if application_v6::enabled(cfg) {
        let base = if tx.kind < wire::REGISTER {
            *cfg.fees.get(tx.kind as usize).ok_or("VERSION")?
        } else {
            field(&cfg.params["native_pq_v2_base_fees"], &tx.kind.to_string())?
        };
        let minimum = base
            .checked_add(
                (raw.len() as u64)
                    .checked_mul(cfg.limit("byte_fee_units")?)
                    .ok_or("RANGE")?,
            )
            .ok_or("RANGE")?;
        require(tx.common.max_fee >= minimum, "FEE")?;
    }
    application_v6::command_profile(tx.kind, cfg)?;
    let mut view = View::new(parent, None);
    if tasks_v4_enabled(cfg) && matches!(tx.kind, 18 | 20 | 21) {
        tasks_v4::command_owners(&mut view, &tx, cfg)?;
    }
    if tasks_v5_enabled(cfg) && matches!(tx.kind, 18..=22) {
        tasks_v5::command_owners(&mut view, &tx, cfg)?;
    }
    let mut keys = Vec::with_capacity(tx.witnesses().len());
    for (index, witness) in tx.witnesses().iter().enumerate() {
        let spki = resolve(&mut view, &tx, index, cfg)?;
        original_charge(cfg, signatures)?;
        verify_tpq1(
            witness.frame,
            &PqFrameExpectation {
                purpose: witness.role,
                network: context.network,
                owner_context: wire::owner_context_for_profile(
                    account_profile(cfg)?,
                    &tx.common,
                    tx.kind,
                    witness.role,
                )
                .map_err(|_| "PQ2_CONTEXT")?,
                signer_key_id: witness.key_id,
                owner_generation: witness.generation,
                operation_sequence: tx.common.nonce,
                expires_at: tx.common.expires_at,
                now: timestamp,
                payload: tx.core(),
            },
            &spki,
        )
        .map_err(|_| "PQ2_SIGNATURE")?;
        keys.push(spki);
    }
    let conflict = application_v6::conflict_proofs(parent, &tx, cfg, signatures)?;
    Ok(PreparedCommand {
        conflict,
        raw: raw.to_vec(),
        common: tx.common,
        kind: tx.kind,
        payload: tx.payload.to_vec(),
        keys,
        wire_id: tx.wire_id(),
        statement_id: tx.statement_id(),
        admitted_at: timestamp,
    })
}

fn original_charge(cfg: &Config, budget: &AtomicUsize) -> Result<()> {
    let maximum = account_profile(cfg)?.maximum_verifications();
    budget
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            used.checked_add(1).filter(|next| *next <= maximum)
        })
        .map_err(|_| "PQ_VERIFY_BUDGET")?;
    Ok(())
}

fn assert_same_preparation(left: &Result<PreparedCommand>, right: &Result<PreparedCommand>) {
    match (left, right) {
        (Ok(left), Ok(right)) => {
            assert_eq!(left.raw, right.raw);
            assert_eq!(left.common, right.common);
            assert_eq!(left.kind, right.kind);
            assert_eq!(left.payload, right.payload);
            assert_eq!(left.keys, right.keys);
            assert_eq!(left.wire_id, right.wire_id);
            assert_eq!(left.statement_id, right.statement_id);
            assert_eq!(left.admitted_at, right.admitted_at);
            assert!(left.conflict.is_none() && right.conflict.is_none());
        }
        (Err(left), Err(right)) => assert_eq!(left, right),
        _ => panic!("original/checked preparation outcome differs"),
    }
}

#[test]
fn checked_configuration_matches_original_preparation_bindings_and_first_errors() {
    let (cfg, state, _, a, b) = setup();
    let next = Key::public_test_seed(106);
    let single = ordinary(&cfg, &a, a.id, 1, 1, 1, &transfer_payload(b.id, 1));
    let dual = rotation(&cfg, &state, a.id, 1, 1, &a, &next);
    let mut bad_signature = dual.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let mut wrong_context = common(&cfg, a.id, 1, 1);
    wrong_context.context.parameters[0] ^= 1;
    let wrong_context = fixture::signed(
        &wrong_context,
        1,
        &transfer_payload(b.id, 1),
        &[Witness {
            key: &a,
            role: 1,
            generation: 1,
            carried: false,
        }],
        None,
    );
    let maximum = account_profile(&cfg).unwrap().maximum_verifications();
    for raw in [
        single.as_slice(),
        &dual,
        &bad_signature,
        &wrong_context,
        &[],
    ] {
        for timestamp in [1001, 2001] {
            for spent in [0, maximum - 1, maximum] {
                let original_attempts = AtomicUsize::new(spent);
                let checked_attempts = AtomicUsize::new(spent);
                let original = original_prepare_signature_metered(
                    &state,
                    raw,
                    timestamp,
                    &cfg,
                    &original_attempts,
                );
                let checked =
                    prepare_signature_metered(&state, raw, timestamp, &cfg, &checked_attempts);
                assert_same_preparation(&original, &checked);
                assert_eq!(
                    original_attempts.load(Ordering::Relaxed),
                    checked_attempts.load(Ordering::Relaxed)
                );
            }
        }
    }
}

#[test]
#[ignore = "bounded paired whole-preparation wall observation; CPU and end-to-end throughput unmeasured"]
fn checked_configuration_complete_preparation_paired_observation() {
    use std::time::Instant;
    let (cfg, state, _, a, b) = setup();
    let next = Key::public_test_seed(106);
    let single = ordinary(&cfg, &a, a.id, 1, 1, 1, &transfer_payload(b.id, 1));
    let dual = rotation(&cfg, &state, a.id, 1, 1, &a, &next);
    let mut bad_signature = dual.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let cases = [
        ("single", single),
        ("dual", dual),
        ("bad-second-signature", bad_signature),
    ];
    for (case, raw) in &cases {
        // One full warm-up per arm, outside every reported interval. Both arms
        // execute real ML-DSA proofs; setup/signing is excluded and not a service cost.
        let original =
            original_prepare_signature_metered(&state, raw, 1001, &cfg, &AtomicUsize::new(0));
        let checked = prepare_signature_metered(&state, raw, 1001, &cfg, &AtomicUsize::new(0));
        assert_same_preparation(&original, &checked);
        for pair in 0..4 {
            let order = if pair % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            let mut results = Vec::new();
            let mut samples = Vec::new();
            for (position, checked) in order.into_iter().enumerate() {
                let attempts = AtomicUsize::new(0);
                reset_digests();
                let start = Instant::now();
                let result = if checked {
                    prepare_signature_metered(&state, raw, 1001, &cfg, &attempts)
                } else {
                    original_prepare_signature_metered(&state, raw, 1001, &cfg, &attempts)
                };
                let wall_ns = start.elapsed().as_nanos();
                let digest_calls = digests();
                let signature_attempts = attempts.load(Ordering::Relaxed);
                let expected_attempts = if *case == "single" { 1 } else { 2 };
                assert_eq!(signature_attempts, expected_attempts);
                assert_eq!(
                    digest_calls,
                    if checked {
                        1
                    } else {
                        2 + 2 * expected_attempts
                    }
                );
                samples.push(json!({
                    "position":position,
                    "arm":if checked { "checked-source-borrow" } else { "original-repeated-policy" },
                    "wall_ns":wall_ns, "thread_cpu_ns":null,
                    "cpu_measured":false, "config_digest_calls":digest_calls,
                    "signature_attempts":signature_attempts, "error":result.as_ref().err()
                }));
                results.push(result);
            }
            assert_same_preparation(&results[0], &results[1]);
            eprintln!(
                "PQ_CHECKED_CONFIG_PAIR {}",
                json!({
                    "case":case, "pair":pair, "profile":cfg.params[SELECTOR],
                    "compiled_debug_assertions":cfg!(debug_assertions),
                    "compiled_pq_native_openssl":cfg!(feature = "pq-native-openssl"),
                    "original_source":"a303f71e7", "input_sha384":hex::encode(Sha384::digest(raw)),
                    "input_bytes":raw.len(), "samples":samples,
                    "prepared_bindings_and_errors_equivalent":true,
                    "setup_included":false, "warmups_per_arm":1,
                    "cpu_measured":false, "service_confirmation_measured":false
                })
            );
        }
    }
}
