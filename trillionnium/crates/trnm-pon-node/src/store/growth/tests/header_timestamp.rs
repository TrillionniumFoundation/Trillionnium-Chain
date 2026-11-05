//! PGH2-to-M06 time binding and classic-output compatibility. The PQ case
//! exercises the shared execution-input boundary with real ML-DSA signatures;
//! it does not admit a PQ transaction through the still-classical Growth wire.
use super::*;
use pon_executor::{ExecutionControl, ExecutionError};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::{
    pq_frame::{ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES},
    pq_native_accounts_v2 as wire,
};
use zeroize::Zeroizing;

// Deliberately public deterministic test keys, using the real in-process signer.
fn key(byte: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([byte; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    PqNativeSigningKey::from_owned_seed(seed, id).unwrap()
}

#[test]
fn growth_header_timestamp_controls_real_pq_m06_expiry_at_the_input_boundary() {
    use pon_executor::pq_accounts_v2::{self as pq, GenesisAccount};
    let sender = key(131);
    let recipient = key(132);
    let sender_id = ml_dsa_65_key_id_from_spki(sender.public_spki()).unwrap();
    let recipient_id = ml_dsa_65_key_id_from_spki(recipient.public_spki()).unwrap();
    let (cfg, state, genesis) = pq::genesis(
        &[
            GenesisAccount {
                spki: sender.public_spki().to_vec(),
                balance: 10_000_000,
            },
            GenesisAccount {
                spki: recipient.public_spki().to_vec(),
                balance: 10_000_000,
            },
        ],
        1000,
    )
    .unwrap();
    let common = wire::Common {
        context: pq::context(&cfg).unwrap(),
        account: sender_id,
        nonce: 1,
        expires_at: 2000,
        max_fee: 100_000,
        generation: 1,
    };
    let payload = [
        recipient_id.as_slice(),
        &10_000_u64.to_le_bytes(),
        &0_u16.to_be_bytes(),
    ]
    .concat();
    let witnesses = [wire::WitnessKey {
        role: 1,
        generation: 1,
        key_id: sender_id,
        spki: None,
    }];
    let statement = wire::signing_statement(&common, 1, &payload, &witnesses, 0).unwrap();
    let mut frame = statement.to_vec();
    frame.extend((ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
    frame.extend(sender.sign_exact_message(&statement).unwrap());
    let transactions = vec![wire::encode(&common, 1, &payload, &witnesses, &[frame]).unwrap()];
    let mut header = GrowthHeader {
        ledger: Header {
            network: cfg.network,
            parameters: cfg.parameters,
            parent: genesis,
            height: 1,
            timestamp: 1999,
            target: [255; 32],
            miner: recipient_id,
            transactions: sequence_root("transactions", &transactions),
            state: [0; 32],
            receipts: [0; 32],
            work_task: [0; 32],
            nonce: 0,
        },
        witness: [0; 32],
    };
    let progress = |_| Ok::<_, std::convert::Infallible>(());
    let control = ExecutionControl::new(&progress, &());
    let original = state.clone();
    let mut accepted = None;
    for workers in [1, 2, 4, 8] {
        for timestamp in [1999, 2000, 2001] {
            header.ledger.timestamp = timestamp;
            // Exercise the actual PGH2 codec, not an independent clock fixture.
            let decoded = GrowthHeader::decode(&header.encode()).unwrap();
            let result = pon_executor::execute_with_control(
                &state,
                execution_block(&decoded, &transactions, workers),
                &cfg,
                &control,
            );
            if timestamp > common.expires_at {
                assert_eq!(
                    result.unwrap_err(),
                    ExecutionError::Relation("PQ2_SIGNATURE"),
                    "expired header time accepted with {workers} workers"
                );
            } else {
                let output = result.unwrap();
                assert_eq!(output.metrics.signature_verifications, 1);
                assert_eq!(
                    output.state[&format!("account:{}", hex::encode(sender_id))]["nonce"],
                    1
                );
                assert_eq!(
                    output.state[&format!("account:{}", hex::encode(recipient_id))],
                    json!({"balance":10_010_000,"nonce":0})
                );
                let exact = (output.state, output.receipts, output.root);
                if let Some(prior) = &accepted {
                    assert_eq!(&exact, prior);
                }
                accepted = Some(exact);
            }
            assert_eq!(state, original, "preview mutated its immutable parent");
        }
        // The prior missing-time input remains rejected by the real M06 owner.
        let mut missing = execution_block(&header, &transactions, workers);
        missing.timestamp = None;
        assert_eq!(
            pon_executor::execute_with_control(&state, missing, &cfg, &control).unwrap_err(),
            ExecutionError::Relation("PQ2_BLOCK_CONTEXT")
        );
    }
}

#[derive(Default)]
struct ReplayObservation(AtomicUsize);
impl pon_executor::CanonicalTransitionObserver for ReplayObservation {
    fn transaction(
        &self,
        _index: usize,
        _envelope: &Envelope,
        _before: &State,
        _writes: &State,
        _fee: u64,
        _receipt: &[u8],
    ) -> pon_executor::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn growth_header_timestamp_preserves_classic_outputs_admission_and_retained_replay() {
    let settings = settings();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone()).unwrap();
    let transaction = transfer(&settings, 0, 1, public(100), 1000);
    let mut prior_outputs = None;
    // Classic expiry is height 2000; the second header time is later than that
    // numeric value but must remain valid at height 1, with identical effects.
    for timestamp in [11, 2001] {
        let packet = source
            .make_growth_consensus_maintenance(
                settings.genesis(),
                vec![transaction.clone()],
                public(3),
                timestamp,
                4096,
            )
            .unwrap();
        let packet = GrowthPacket::decode(&packet.encode().unwrap()).unwrap();
        let expected = reference(&settings, &settings.initial, &packet);
        let outputs = (
            packet.header.ledger.state,
            packet.header.ledger.receipts,
            expected.clone(),
        );
        if let Some(prior) = &prior_outputs {
            assert_eq!(&outputs, prior);
        }
        prior_outputs = Some(outputs);
        for workers in [1, 4] {
            let dir = tempfile::tempdir().unwrap();
            let mut node = Node::open_with_permanent_account_growth_v2_and_workers(
                dir.path(),
                settings.clone(),
                workers,
            )
            .unwrap();
            // Observation time is intentionally far past the header time.
            let id = node.admit_growth(&packet, 100_000).unwrap();
            assert_eq!(node.activate(id).unwrap(), id);
            assert_reference(&node, id, &expected);
            let observed = ReplayObservation::default();
            node.growth_check_payment_transition(id, &observed).unwrap();
            assert_eq!(observed.0.load(Ordering::SeqCst), 1);
            let stored = rows(&node.db);
            let active = node.active().unwrap();
            drop(node);
            let reopened =
                Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
            assert_eq!(reopened.active().unwrap(), active);
            assert_eq!(rows(&reopened.db), stored);
            assert_reference(&reopened, id, &expected);
            reopened.growth_check_retained_transition(id, None).unwrap();
        }
    }
}
