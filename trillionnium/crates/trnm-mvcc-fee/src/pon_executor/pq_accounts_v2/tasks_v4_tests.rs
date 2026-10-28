use super::*;
use crate::pon_executor::{self as exec, BlockExecution, ExecutionControl};
#[path = "../../../../trnm-protocol/tests/support/native_pq_task_fixture.rs"]
mod fixture;
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
fn prepared_pq4_task_rechecks_actual_lease_and_both_authorities_before_any_fee_patch() {
    let requester = Key::public_test_seed(214);
    let source = Key::public_test_seed(215);
    let other = Key::public_test_seed(216);
    let accounts: Vec<_> = [&requester, &source, &other]
        .iter()
        .map(|k| GenesisAccount {
            spki: k.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let (cfg, initial, _) = genesis_tasks_v4(&accounts, 1000).unwrap();
    let chain = context(&cfg).unwrap();
    let lease = fixture::lease(chain, requester.id, source.id);
    let opening = fixture::signed(
        &fixture::common(chain, requester.id, 1, 1),
        18,
        &lease.encode().unwrap(),
        &[fixture::primary(&requester, 1)],
        None,
    );
    let state = execute(&initial, &cfg, 1, &[opening]);
    let (_, _, a, b) = fixture::material();
    let task = trnm_crypto_primitives::pon_work::task_id(&a, &b).unwrap();
    let registration = fixture::registration(&lease, task, 1, [0; 32]);
    let raw = fixture::signed(
        &fixture::common(chain, requester.id, 2, 1),
        21,
        &registration.encode().unwrap(),
        &[fixture::primary(&requester, 1), fixture::source(&source, 1)],
        None,
    );
    let prepared = prepare_signature(&state, &raw, 1002, &cfg).unwrap();
    assert!(apply(&state, &prepared, 2, &cfg, None).is_ok());
    let rotated = fixture::signed(
        &fixture::common(chain, source.id, 1, 1),
        wire::ROTATE,
        &[
            2_u64.to_be_bytes().as_slice(),
            &authority_digest(&state, source.id, &cfg).unwrap(),
        ]
        .concat(),
        &[
            Witness {
                key: &source,
                role: 3,
                generation: 1,
                carried: false,
            },
            Witness {
                key: &other,
                role: 4,
                generation: 2,
                carried: true,
            },
        ],
        None,
    );
    let rotated = execute(&state, &cfg, 2, &[rotated]);
    let before = rotated.clone();
    assert!(apply(&rotated, &prepared, 3, &cfg, None).is_err());
    assert_eq!(rotated, before);
    let revoked = fixture::signed(
        &fixture::common(chain, requester.id, 2, 1),
        20,
        &fixture::revocation(&lease).encode().unwrap(),
        &[fixture::primary(&requester, 1)],
        None,
    );
    let revoked = execute(&state, &cfg, 2, &[revoked]);
    let before = revoked.clone();
    assert!(apply(&revoked, &prepared, 3, &cfg, None).is_err());
    assert_eq!(revoked, before);
    let alternate = fixture::lease(chain, requester.id, other.id);
    let opening = fixture::signed(
        &fixture::common(chain, requester.id, 1, 1),
        18,
        &alternate.encode().unwrap(),
        &[fixture::primary(&requester, 1)],
        None,
    );
    let alternate = execute(&initial, &cfg, 1, &[opening]);
    let before = alternate.clone();
    assert!(apply(&alternate, &prepared, 2, &cfg, None).is_err());
    assert_eq!(alternate, before);
}
