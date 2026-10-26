use super::*;
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};

fn fixture(senders: usize) -> (State, Config, Vec<Vec<u8>>) {
    let cfg = Config::installed().unwrap();
    let keys: Vec<_> = (0..senders)
        .map(|index| signing_key_from_hex(&hex::encode([(index + 1) as u8; 32])).unwrap())
        .collect();
    let mut state = State::from([
        ("meta:issued".into(), json!(senders as u64 * 1_000_000_000)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
    ]);
    for key in &keys {
        state.insert(
            format!("account:{}", public_key_hex(key)),
            json!({"balance":1_000_000_000u64,"nonce":0}),
        );
    }
    let raws = (0..256)
        .map(|index| {
            let key = &keys[index % senders];
            let mut payload = [251; 32].to_vec();
            payload.extend(1_u64.to_le_bytes());
            let mut tx = Envelope {
                network: cfg.network,
                sender: hex::decode(public_key_hex(key))
                    .unwrap()
                    .try_into()
                    .unwrap(),
                nonce: (index / senders + 1) as u64,
                expiry: 10_000,
                fee_limit: 1_000_000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            tx.signature = hex::decode(sign_hex(key, &tx.signing_digest().unwrap()))
                .unwrap()
                .try_into()
                .unwrap();
            tx.encode().unwrap()
        })
        .collect();
    (state, cfg, raws)
}
fn experiment<E: Send>(
    state: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    control: &ExecutionControl<'_, E>,
) -> ControlledResult<Output, E> {
    execute_with_state_inputs(
        state,
        block,
        cfg,
        |_, next| root(next),
        control,
        StateInputs {
            experimental_skip_repeated_senders: true,
            ..StateInputs::default()
        },
    )
}
fn request(raws: &[Vec<u8>], workers: usize) -> BlockExecution<'_> {
    BlockExecution {
        transactions: raws,
        height: 1,
        miner: [249; 32],
        parent_id: [248; 32],
        workers,
    }
}
fn parity(a: &Output, b: &Output) {
    assert_eq!(a.state, b.state);
    assert_eq!(a.root, b.root);
    assert_eq!(a.receipts, b.receipts);
    assert_eq!(
        a.metrics.signature_verifications,
        b.metrics.signature_verifications
    );
    assert_eq!(a.metrics.workers_spawned, b.metrics.workers_spawned);
}

#[test]
fn repeated_sender_complete_signed_batches_keep_state_receipts_root_and_every_signature() {
    for senders in [1, 2, 4, 64, 256] {
        let (state, cfg, raws) = fixture(senders);
        let preserved = state.clone();
        for workers in [1, 2, 4, 8] {
            let serial = execute(&state, &raws, 1, [249; 32], [248; 32], 1, &cfg).unwrap();
            let actual = execute(&state, &raws, 1, [249; 32], [248; 32], workers, &cfg).unwrap();
            let reference = relation_only(experiment(
                &state,
                request(&raws, workers),
                &cfg,
                &ExecutionControl::new(&no_cancellation, &()),
            ))
            .unwrap();
            parity(&actual, &reference);
            assert_eq!(actual.state, serial.state);
            assert_eq!(actual.receipts, serial.receipts);
            assert_eq!(actual.root, serial.root);
            assert_eq!(actual.metrics.signature_verifications, 256);
            assert_eq!(state, preserved);
            if workers > 1 && (2..256).contains(&senders) {
                assert_eq!(reference.metrics.speculative, senders);
                assert!(reference.metrics.reexecuted < actual.metrics.reexecuted);
                assert_eq!(actual.metrics.speculative, 256);
                assert_eq!(reference.metrics.serial_conflict_batches, 1);
            } else {
                assert_eq!(actual.metrics.speculative, reference.metrics.speculative);
                assert_eq!(actual.metrics.reexecuted, reference.metrics.reexecuted);
            }
        }
    }
}

#[test]
fn repeated_sender_complete_failures_preserve_canonical_first_error_and_parent() {
    let (state, cfg, raws) = fixture(2);
    let preserved = state.clone();
    let sign = |mut tx: Envelope, sender: usize| {
        let key = signing_key_from_hex(&hex::encode([(sender + 1) as u8; 32])).unwrap();
        tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        tx.encode().unwrap()
    };
    let mut cases = Vec::new();
    let mut fee_first = raws.clone();
    let mut tx = Envelope::decode(&fee_first[0]).unwrap();
    tx.fee_limit = 0;
    fee_first[0] = sign(tx, 0);
    *fee_first[1].last_mut().unwrap() ^= 1;
    cases.push((fee_first, "FEE"));
    let mut wrong_nonce = raws.clone();
    let mut tx = Envelope::decode(&wrong_nonce[2]).unwrap();
    tx.nonce = 1;
    wrong_nonce[2] = sign(tx, 0);
    *wrong_nonce[3].last_mut().unwrap() ^= 1;
    cases.push((wrong_nonce, "NONCE"));
    let mut short_first = raws.clone();
    short_first[0] = vec![0; 67];
    cases.push((short_first, "ENCODING"));
    let mut bad_late = raws.clone();
    *bad_late[255].last_mut().unwrap() ^= 1;
    cases.push((bad_late, "SIGNATURE"));
    let mut bad_first = raws.clone();
    *bad_first[0].last_mut().unwrap() ^= 1;
    cases.push((bad_first, "SIGNATURE"));
    let mut magic_first = raws.clone();
    magic_first[0][0] ^= 1;
    cases.push((magic_first, "ENCODING"));
    for (input, expected) in cases {
        for workers in [1, 4, 8] {
            let actual =
                execute(&state, &input, 1, [249; 32], [248; 32], workers, &cfg).unwrap_err();
            let reference = relation_only(experiment(
                &state,
                request(&input, workers),
                &cfg,
                &ExecutionControl::new(&no_cancellation, &()),
            ))
            .unwrap_err();
            assert_eq!(actual, expected);
            assert_eq!(reference, expected);
            assert_eq!(state, preserved);
        }
    }
}

#[test]
fn repeated_sender_tag11_and_cross_sender_funding_keep_complete_canonical_relation() {
    let (mut state, cfg, raws) = fixture(2);
    let provider = signing_key_from_hex(&hex::encode([1; 32])).unwrap();
    let consumer = signing_key_from_hex(&hex::encode([2; 32])).unwrap();
    let sender: Hash = hex::decode(public_key_hex(&provider))
        .unwrap()
        .try_into()
        .unwrap();
    let quota = [245; 32];
    let product = [246; 32];
    let price = cfg.limit("quota_unit_price").unwrap();
    let mut tx = Envelope::decode(&raws[0]).unwrap();
    tx.tag = 11;
    tx.payload = vec![0; 136];
    let fee =
        cfg.fees[11] + tx.encode().unwrap().len() as u64 * cfg.limit("byte_fee_units").unwrap();
    let units = fee.div_ceil(price).max(1);
    let cost = units * price;
    let digest = hash(
        b"use",
        &[
            &cfg.network,
            &cfg.parameters,
            &quota,
            &sender,
            &1_u64.to_le_bytes(),
            &units.to_le_bytes(),
            &product,
        ],
    );
    let mut payload = quota.to_vec();
    payload.extend(units.to_le_bytes());
    payload.extend(product);
    payload.extend(hex::decode(sign_hex(&consumer, &digest)).unwrap());
    tx.payload = payload;
    tx.signature = hex::decode(sign_hex(&provider, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    state.insert(format!("quota:{}",hex::encode(quota)),json!({"owner":public_key_hex(&consumer),"consumer":public_key_hex(&consumer),"provider":public_key_hex(&provider),"remaining":cost,"units":units,"deadline":10_000,"status":"reserved"}));
    state.insert("meta:issued".into(), json!(2_000_000_000_u64 + cost));
    let mut input = raws.clone();
    input[0] = tx.encode().unwrap();
    for workers in [1, 4, 8] {
        let actual = execute(&state, &input, 1, [249; 32], [248; 32], workers, &cfg).unwrap();
        let reference = relation_only(experiment(
            &state,
            request(&input, workers),
            &cfg,
            &ExecutionControl::new(&no_cancellation, &()),
        ))
        .unwrap();
        parity(&actual, &reference);
        assert_eq!(
            actual.state[&format!("account:{}", public_key_hex(&provider))]["nonce"],
            128
        );
        assert_eq!(actual.metrics.signature_verifications, 256);
    }
    let (mut state, cfg, mut input) = fixture(2);
    state.insert(
        format!("account:{}", public_key_hex(&consumer)),
        json!({"balance":0,"nonce":0}),
    );
    state.insert("meta:issued".into(), json!(1_000_000_000_u64));
    let mut tx = Envelope::decode(&input[0]).unwrap();
    tx.payload = hex::decode(public_key_hex(&consumer)).unwrap();
    tx.payload.extend(1_000_000_u64.to_le_bytes());
    tx.signature = hex::decode(sign_hex(&provider, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    input[0] = tx.encode().unwrap();
    for workers in [1, 4, 8] {
        let actual = execute(&state, &input, 1, [249; 32], [248; 32], workers, &cfg).unwrap();
        let reference = relation_only(experiment(
            &state,
            request(&input, workers),
            &cfg,
            &ExecutionControl::new(&no_cancellation, &()),
        ))
        .unwrap();
        parity(&actual, &reference);
        assert_eq!(actual.metrics.signature_verifications, 256);
        if workers > 1 {
            assert!(actual.metrics.reexecuted > 0);
        }
    }
}

#[derive(Default)]
struct Accounting {
    spawned: AtomicUsize,
    started: AtomicUsize,
    finished: AtomicUsize,
    refuse: Option<usize>,
}
struct Interval<'a>(&'a Accounting, std::thread::ThreadId);
impl ExecutionWorkerInterval for Interval<'_> {}
impl Drop for Interval<'_> {
    fn drop(&mut self) {
        assert_eq!(self.1, std::thread::current().id());
        self.0.finished.fetch_add(1, Ordering::AcqRel);
    }
}
impl ExecutionWorkerAccounting for Accounting {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
        self.started.fetch_add(1, Ordering::AcqRel);
        Some(Box::new(Interval(self, std::thread::current().id())))
    }
    fn worker_spawn_succeeded(&self) {
        self.spawned.fetch_add(1, Ordering::AcqRel);
    }
    fn test_spawn_allowed(&self, index: usize) -> bool {
        self.refuse != Some(index)
    }
}
impl Accounting {
    fn closed(&self, count: usize) {
        assert_eq!(self.spawned.load(Ordering::Acquire), count);
        assert_eq!(self.started.load(Ordering::Acquire), count);
        assert_eq!(self.finished.load(Ordering::Acquire), count);
    }
}

#[test]
fn repeated_sender_cancel_and_partial_worker_start_join_all_actual_workers() {
    let (state, cfg, raws) = fixture(2);
    let preserved = state.clone();
    for point in [
        ExecutionProgress::BeforePrepare { index: 17 },
        ExecutionProgress::AfterPrepare { index: 17 },
        ExecutionProgress::BeforeApply { index: 17 },
        ExecutionProgress::AfterApply { index: 17 },
        ExecutionProgress::BeforeCommitment,
        ExecutionProgress::BeforeOutput,
    ] {
        for experimental in [false, true] {
            let accounting = Accounting::default();
            let progress = |observed| {
                if observed == point {
                    Err("controlled-cancel")
                } else {
                    Ok(())
                }
            };
            let control = ExecutionControl::new(&progress, &accounting);
            let result = if experimental {
                experiment(&state, request(&raws, 4), &cfg, &control)
            } else {
                execute_with_control(&state, request(&raws, 4), &cfg, &control)
            };
            assert!(matches!(
                result,
                Err(ExecutionError::Cancelled("controlled-cancel"))
            ));
            accounting.closed(4);
            assert_eq!(state, preserved);
        }
    }
    for experimental in [false, true] {
        let accounting = Accounting {
            refuse: Some(2),
            ..Accounting::default()
        };
        let control = ExecutionControl::new(&no_cancellation, &accounting);
        let result = if experimental {
            experiment(&state, request(&raws, 4), &cfg, &control)
        } else {
            execute_with_control(&state, request(&raws, 4), &cfg, &control)
        };
        assert!(matches!(
            result,
            Err(ExecutionError::Relation("WORKER_START"))
        ));
        accounting.closed(2);
        assert_eq!(state, preserved);
    }
}
