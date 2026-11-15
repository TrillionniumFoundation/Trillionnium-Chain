use super::repeated_sender_tests::{full_speculation_reference, parity, request};
use super::*;
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};

const BALANCE: u64 = 1_000_000_000;

fn account(seed: u8) -> Hash {
    let key = signing_key_from_hex(&hex::encode([seed; 32])).unwrap();
    hex::decode(public_key_hex(&key))
        .unwrap()
        .try_into()
        .unwrap()
}

fn fixture(senders: u8) -> (State, Config) {
    let cfg = Config::installed().unwrap();
    let mut state = State::from([
        ("meta:issued".into(), json!(u64::from(senders) * BALANCE)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
    ]);
    for seed in 1..=senders {
        state.insert(
            format!("account:{}", hex::encode(account(seed))),
            json!({"balance":BALANCE,"nonce":0}),
        );
    }
    (state, cfg)
}

fn signed(mut tx: Envelope, seed: u8) -> Vec<u8> {
    let key = signing_key_from_hex(&hex::encode([seed; 32])).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

fn transfer(cfg: &Config, seed: u8, nonce: u64, recipient: Hash, amount: u64) -> Vec<u8> {
    let mut payload = recipient.to_vec();
    payload.extend(amount.to_le_bytes());
    signed(
        Envelope {
            network: cfg.network,
            sender: account(seed),
            nonce,
            expiry: 10_000,
            fee_limit: 1_000_000,
            tag: 1,
            payload,
            signature: [0; 64],
        },
        seed,
    )
}

fn compare(
    state: &State,
    cfg: &Config,
    raws: &[Vec<u8>],
    speculative: usize,
    reexecuted: usize,
    reference_reexecuted: usize,
) {
    let preserved = state.clone();
    let serial = execute(state, raws, 1, [249; 32], [248; 32], 1, cfg).unwrap();
    for workers in [2, 4, 8] {
        let actual = execute(state, raws, 1, [249; 32], [248; 32], workers, cfg).unwrap();
        let reference = relation_only(full_speculation_reference(
            state,
            request(raws, workers),
            cfg,
            &ExecutionControl::new(&no_cancellation, &()),
        ))
        .unwrap();
        parity(&actual, &reference);
        assert_eq!(actual.state, serial.state);
        assert_eq!(actual.receipts, serial.receipts);
        assert_eq!(actual.root, serial.root);
        assert_eq!(actual.metrics.signature_verifications, raws.len());
        assert_eq!(actual.metrics.speculative, speculative);
        assert_eq!(actual.metrics.reexecuted, reexecuted);
        assert_eq!(reference.metrics.speculative, raws.len());
        assert_eq!(reference.metrics.reexecuted, reference_reexecuted);
        assert_eq!(
            actual.metrics.committed_without_replay + actual.metrics.reexecuted,
            raws.len()
        );
        assert_eq!(state, &preserved);
    }
}

#[test]
fn account_conflict_common_recipient_elides_real_predictions_without_skipping_signatures() {
    let (state, cfg) = fixture(4);
    let raws = (1..=4)
        .map(|seed| transfer(&cfg, seed, 1, [251; 32], 1))
        .collect::<Vec<_>>();
    // Distinct senders, so the old nonce-only hint cannot explain this saving.
    compare(&state, &cfg, &raws, 1, 0, 3);
}

#[test]
fn account_conflict_funding_chain_and_prior_sender_recipient_keep_canonical_results() {
    let (state, cfg) = fixture(3);
    for raws in [
        vec![
            transfer(&cfg, 1, 1, account(2), 1),
            transfer(&cfg, 2, 1, [251; 32], 1),
        ],
        vec![
            transfer(&cfg, 1, 1, [251; 32], 1),
            transfer(&cfg, 2, 1, account(1), 1),
        ],
    ] {
        compare(&state, &cfg, &raws, 1, 0, 1);
    }
    let mut funded = state.clone();
    funded.insert(
        format!("account:{}", hex::encode(account(2))),
        json!({"balance":0,"nonce":0}),
    );
    funded.insert("meta:issued".into(), json!(2 * BALANCE));
    let raws = vec![
        transfer(&cfg, 1, 1, account(2), 1_000_000),
        transfer(&cfg, 2, 1, [251; 32], 1),
    ];
    // B's speculative parent execution would reject FUNDS; canonical A->B
    // funding must still allow B's correctly signed successor transaction.
    compare(&funded, &cfg, &raws, 1, 0, 1);
}

#[test]
fn account_conflict_disjoint_and_self_transfers_retain_parallel_work() {
    let (state, cfg) = fixture(4);
    for raws in [
        (1..=4)
            .map(|seed| transfer(&cfg, seed, 1, [seed + 200; 32], 1))
            .collect::<Vec<_>>(),
        (1..=4)
            .map(|seed| transfer(&cfg, seed, 1, account(seed), 1))
            .collect::<Vec<_>>(),
    ] {
        compare(&state, &cfg, &raws, 4, 0, 0);
    }
    let raws = vec![
        transfer(&cfg, 1, 1, [251; 32], 1),
        transfer(&cfg, 1, 2, [252; 32], 1),
        transfer(&cfg, 2, 1, [253; 32], 1),
    ];
    compare(&state, &cfg, &raws, 2, 0, 1);
}

#[test]
fn account_conflict_unpredicted_task_payment_still_replays_once_against_exact_reads() {
    let (mut state, cfg) = fixture(2);
    let task = [241; 32];
    let output = [242; 32];
    let payment = 1_000_000_u64;
    state.insert(
        format!("account:{}", hex::encode(account(2))),
        json!({"balance":0,"nonce":0}),
    );
    state.insert("meta:issued".into(), json!(BALANCE + payment));
    state.insert(
        format!("task:{}", hex::encode(task)),
        json!({
            "owner":hex::encode(account(1)),
            "provider":hex::encode(account(2)),
            "remaining":payment,
            "deadline":10_000,
            "status":"receipt",
            "output":hex::encode(output),
        }),
    );
    let mut settle = Envelope::decode(&transfer(&cfg, 1, 1, account(2), 1)).unwrap();
    settle.tag = 5;
    settle.payload = task.to_vec();
    settle.payload.extend(output);
    let raws = vec![signed(settle, 1), transfer(&cfg, 2, 1, [251; 32], 1)];
    // Tag 5's provider is read from live task state, not from the transfer
    // framing hint. That hidden account dependency must retain one replay.
    compare(&state, &cfg, &raws, 2, 1, 1);
}

#[test]
fn account_conflict_untrusted_hints_preserve_full_validation_and_first_error() {
    let (state, cfg) = fixture(3);
    let preserved = state.clone();
    let original = (1..=3)
        .map(|seed| transfer(&cfg, seed, 1, [251; 32], 1))
        .collect::<Vec<_>>();
    let mut cases = Vec::new();
    for expected in ["FEE", "NONCE", "EXPIRED", "NETWORK", "FUNDS"] {
        let mut raws = original.clone();
        let mut first = Envelope::decode(&raws[0]).unwrap();
        match expected {
            "FEE" => first.fee_limit = 0,
            "NONCE" => first.nonce = 2,
            "EXPIRED" => first.expiry = 0,
            "NETWORK" => first.network[0] ^= 1,
            "FUNDS" => first.payload[32..40].copy_from_slice(&0_u64.to_le_bytes()),
            _ => unreachable!(),
        }
        raws[0] = signed(first, 1);
        *raws[2].last_mut().unwrap() ^= 1;
        cases.push((raws, expected));
    }
    // These mutations either miss the exact transfer shape or forge a shaped
    // recipient/signature. None may turn a work hint into an accepted envelope.
    for (offset, expected) in [
        (0, "ENCODING"),
        (92, "ENCODING"),
        (93, "ENCODING"),
        (95, "SIGNATURE"),
        (198, "SIGNATURE"),
    ] {
        let mut raws = original.clone();
        raws[1][offset] ^= 1;
        cases.push((raws, expected));
    }
    let mut short = original.clone();
    short[1].truncate(67);
    cases.push((short, "ENCODING"));
    for (raws, expected) in cases {
        for workers in [1, 2, 4, 8] {
            let actual =
                execute(&state, &raws, 1, [249; 32], [248; 32], workers, &cfg).unwrap_err();
            let reference = relation_only(full_speculation_reference(
                &state,
                request(&raws, workers),
                &cfg,
                &ExecutionControl::new(&no_cancellation, &()),
            ))
            .unwrap_err();
            assert_eq!(actual, expected);
            assert_eq!(actual, reference);
            assert_eq!(state, preserved);
        }
    }
}
