use super::task_fixture_v5 as fixture;
use super::*;
use crate::pon_executor::{self as exec, BlockExecution, ExecutionControl};
use fixture::{Key, Witness};

fn execute(parent: &State, cfg: &Config, height: u64, rows: &[Vec<u8>]) -> State {
    exec::relation_only(exec::execute_with_control(
        parent,
        BlockExecution {
            timestamp: Some(1000 + height),
            transactions: rows,
            height,
            miner: [221; 32],
            parent_id: [height as u8; 32],
            workers: 1,
        },
        cfg,
        &ExecutionControl::new(&exec::no_cancellation, &()),
    ))
    .unwrap()
    .state
}

#[test]
fn prepared_pq5_atomic_renewal_rechecks_revision_prior_source_and_requester_before_fee_patch() {
    let requester = Key::public_test_seed(174);
    let source = Key::public_test_seed(175);
    let next_key = Key::public_test_seed(176);
    let accounts: Vec<_> = [&requester, &source, &next_key]
        .iter()
        .map(|k| GenesisAccount {
            spki: k.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let (cfg, initial, _) = genesis_tasks_v5(&accounts, 1000).unwrap();
    let chain = context(&cfg).unwrap();
    let sign = |account, nonce, kind, payload: &[u8], witnesses: &[Witness<'_>]| {
        fixture::signed(
            &fixture::common(chain, account, nonce, 1),
            kind,
            payload,
            witnesses,
            None,
        )
    };
    let lease = fixture::lease(chain, requester.id, source.id);
    let opening = sign(
        requester.id,
        1,
        18,
        &lease.encode().unwrap(),
        &[fixture::primary(&requester, 1)],
    );
    let opened = execute(&initial, &cfg, 1, &[opening]);
    let (_, _, a, b) = fixture::material();
    let task = trnm_crypto_primitives::pon_work::task_id(&a, &b).unwrap();
    let registered = sign(
        requester.id,
        2,
        21,
        &fixture::registration(&lease, task, 1, [0; 32])
            .encode()
            .unwrap(),
        &[fixture::primary(&requester, 1), fixture::source(&source, 1)],
    );
    let prior =
        trnm_crypto_primitives::qualified_work_task::pq_lifecycle_v5::statement_id(&registered)
            .unwrap();
    let state = execute(&opened, &cfg, 2, &[registered]);
    let successor = fixture::successor(&lease, 3, 100);
    let raw = sign(
        requester.id,
        3,
        22,
        &fixture::atomic(&lease, &successor, task, 2, prior)
            .encode()
            .unwrap(),
        &[fixture::primary(&requester, 1), fixture::source(&source, 1)],
    );
    let prepared = prepare_signature(&state, &raw, 1003, &cfg).unwrap();
    assert_eq!(prepared.signature_count(), 2);
    let before = state.clone();
    assert!(apply(&state, &prepared, 3, &cfg, None).is_ok());
    assert_eq!(state, before);
    for owner in [&requester, &source] {
        let nonce = state[&format!("account:{}", hex::encode(owner.id))]["nonce"]
            .as_u64()
            .unwrap()
            + 1;
        let payload = [
            2_u64.to_be_bytes().as_slice(),
            &authority_digest(&state, owner.id, &cfg).unwrap(),
        ]
        .concat();
        let rotation = sign(
            owner.id,
            nonce,
            wire::ROTATE,
            &payload,
            &[
                Witness {
                    key: owner,
                    role: 3,
                    generation: 1,
                    carried: false,
                },
                Witness {
                    key: &next_key,
                    role: 4,
                    generation: 2,
                    carried: true,
                },
            ],
        );
        let rotated = execute(&state, &cfg, 3, &[rotation]);
        let before = rotated.clone();
        assert!(apply(&rotated, &prepared, 4, &cfg, None).is_err());
        assert_eq!(rotated, before);
    }
    let revoked = sign(
        requester.id,
        3,
        20,
        &fixture::revocation(&lease).encode().unwrap(),
        &[fixture::primary(&requester, 1)],
    );
    let revoked = execute(&state, &cfg, 3, &[revoked]);
    let before = revoked.clone();
    assert!(apply(&revoked, &prepared, 4, &cfg, None).is_err());
    assert_eq!(revoked, before);
    let staged = sign(
        requester.id,
        3,
        19,
        &fixture::renewal(&lease, &successor, prior)
            .encode()
            .unwrap(),
        &[fixture::primary(&requester, 1)],
    );
    let staged = execute(&state, &cfg, 3, &[staged]);
    let before = staged.clone();
    assert!(apply(&staged, &prepared, 4, &cfg, None).is_err());
    assert_eq!(staged, before);
    let alternate = fixture::lease(chain, requester.id, next_key.id);
    let opening = sign(
        requester.id,
        1,
        18,
        &alternate.encode().unwrap(),
        &[fixture::primary(&requester, 1)],
    );
    let alternate = execute(&initial, &cfg, 1, &[opening]);
    let before = alternate.clone();
    assert!(apply(&alternate, &prepared, 3, &cfg, None).is_err());
    assert_eq!(alternate, before);
}
