use std::collections::BTreeMap;

use trnm_protocol::{
    account_key, monetary_state_key, result_commitment_hex, task_key, AccountV1,
    CanonicalCommandV1, CanonicalTxV1, MonetaryStateV1, TaskStatusV1, TaskV1,
    ACCOUNT_OBJECT_TYPE_V1, CANONICAL_TX_SCHEMA_V1, TASK_OBJECT_TYPE_V1,
};
use trnm_runtime::{
    execute, ExecutionContext, RuntimeError, RuntimeEvent, RuntimeReceipt, StateObject, StateView,
};

const ACCOUNTS: [&str; 6] = [
    "operator",
    "client",
    "worker",
    "consumer",
    "challenger",
    "treasury",
];
const TASK_IDS: [&str; 3] = ["model-task-0", "model-task-1", "model-task-2"];
const MODEL_SEEDS: u64 = 96;
const MODEL_STEPS: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MemoryView(BTreeMap<String, StateObject>);

impl StateView for MemoryView {
    fn get(&self, object_key_hex: &str) -> Option<StateObject> {
        self.0.get(object_key_hex).cloned()
    }
}

impl MemoryView {
    fn apply(&mut self, receipt: RuntimeReceipt) {
        for mutation in receipt.mutations {
            assert_eq!(
                self.0
                    .get(&mutation.object_key_hex)
                    .map(|object| object.version),
                mutation.expected_version,
                "runtime emitted a mutation against the wrong object version"
            );
            assert_eq!(
                mutation.next_version,
                mutation
                    .expected_version
                    .unwrap_or(0)
                    .checked_add(1)
                    .expect("model object versions remain bounded"),
                "runtime skipped an object version"
            );
            self.0.insert(
                mutation.object_key_hex,
                StateObject {
                    object_type: mutation.object_type,
                    version: mutation.next_version,
                    value_bytes: mutation.value_bytes,
                },
            );
        }
    }

    fn account(&self, account: &str) -> AccountV1 {
        self.0
            .get(&account_key(account))
            .map(|object| {
                serde_json::from_slice(&object.value_bytes)
                    .expect("runtime account objects must remain decodable")
            })
            .unwrap_or(AccountV1 {
                account: account.to_string(),
                balance: 0,
                nonce: 0,
            })
    }

    fn task(&self, task_id: &str) -> Option<TaskV1> {
        self.0.get(&task_key(task_id)).map(|object| {
            serde_json::from_slice(&object.value_bytes)
                .expect("runtime task objects must remain decodable")
        })
    }

    fn total_issued(&self) -> u128 {
        self.0
            .get(&monetary_state_key())
            .map(|object| {
                serde_json::from_slice::<MonetaryStateV1>(&object.value_bytes)
                    .expect("runtime monetary state must remain decodable")
                    .total_issued
            })
            .unwrap_or(0)
    }

    fn economic_total(&self) -> u128 {
        let account_total = self
            .0
            .values()
            .filter(|object| object.object_type == ACCOUNT_OBJECT_TYPE_V1)
            .map(|object| {
                serde_json::from_slice::<AccountV1>(&object.value_bytes)
                    .expect("runtime account objects must remain decodable")
                    .balance
            })
            .try_fold(0_u128, u128::checked_add)
            .expect("bounded model account total must not overflow");
        let escrow_total = self
            .0
            .values()
            .filter(|object| object.object_type == TASK_OBJECT_TYPE_V1)
            .map(|object| {
                let task = serde_json::from_slice::<TaskV1>(&object.value_bytes)
                    .expect("runtime task objects must remain decodable");
                match task.status {
                    TaskStatusV1::Open => task.reward,
                    TaskStatusV1::Assigned | TaskStatusV1::Committed | TaskStatusV1::Revealed => {
                        task.reward
                            .checked_add(task.worker_stake)
                            .expect("bounded task escrow must not overflow")
                    }
                    TaskStatusV1::Consumed => task
                        .reward
                        .checked_add(task.worker_stake)
                        .and_then(|value| value.checked_add(task.consumption_payment))
                        .expect("bounded consumed escrow must not overflow"),
                    TaskStatusV1::Challenged => task
                        .reward
                        .checked_add(task.worker_stake)
                        .and_then(|value| value.checked_add(task.consumption_payment))
                        .and_then(|value| value.checked_add(task.challenge_bond))
                        .expect("bounded challenged escrow must not overflow"),
                    TaskStatusV1::Settled
                    | TaskStatusV1::ResolvedForWorker
                    | TaskStatusV1::ResolvedForChallenger
                    | TaskStatusV1::Expired => 0,
                }
            })
            .try_fold(0_u128, u128::checked_add)
            .expect("bounded model escrow total must not overflow");
        account_total
            .checked_add(escrow_total)
            .expect("bounded model economic total must not overflow")
    }

    fn assert_supply_conserved(&self) {
        assert_eq!(
            self.economic_total(),
            self.total_issued(),
            "balances plus live task escrow must equal the explicitly issued supply"
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct Choice {
    operation: u8,
    nonce_mode: u8,
    variant: u8,
    signer_mode: u8,
}

#[derive(Debug, Clone)]
struct PlannedTx {
    tx: CanonicalTxV1,
    signer_id: String,
    signer_role: &'static str,
    height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceOutcome {
    Applied {
        gas_used: u64,
        fee_charged: u128,
        events: Vec<RuntimeEvent>,
        state: BTreeMap<String, StateObject>,
    },
    Rejected {
        error: String,
        state: BTreeMap<String, StateObject>,
    },
}

#[derive(Debug, Default)]
struct Coverage {
    applied: usize,
    rejected: usize,
    replay_or_gap_rejected: usize,
    event_kinds: BTreeMap<String, usize>,
}

fn canonical_tx(sender: &str, nonce: u64, command: CanonicalCommandV1) -> CanonicalTxV1 {
    CanonicalTxV1 {
        schema: CANONICAL_TX_SCHEMA_V1.to_string(),
        sender: sender.to_string(),
        nonce,
        max_gas: 1_000_000,
        fee_limit: 1_000_000,
        command,
    }
}

fn execute_and_apply(
    view: &mut MemoryView,
    planned: PlannedTx,
) -> Result<RuntimeReceipt, RuntimeError> {
    let payload = serde_json::to_vec(&planned.tx).expect("model transaction must encode");
    let receipt = execute(
        &planned.tx,
        ExecutionContext {
            height: planned.height,
            signer_id: &planned.signer_id,
            signer_role: planned.signer_role,
            payload_len: payload.len(),
        },
        view,
    )?;
    view.apply(receipt.clone());
    Ok(receipt)
}

fn bootstrap() -> MemoryView {
    let mut view = MemoryView::default();
    for (index, account) in ACCOUNTS.into_iter().enumerate() {
        let planned = PlannedTx {
            tx: canonical_tx(
                "operator",
                u64::try_from(index + 1).expect("bounded bootstrap nonce"),
                CanonicalCommandV1::CreditAccount {
                    account: account.to_string(),
                    amount: 1_000_000,
                },
            ),
            signer_id: "operator".to_string(),
            signer_role: "operator",
            height: 1,
        };
        execute_and_apply(&mut view, planned).expect("bootstrap issuance must succeed");
        view.assert_supply_conserved();
    }
    view
}

fn hash_hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn task_material(task_id: &str, worker: &str) -> (String, String, String) {
    let slot = TASK_IDS
        .iter()
        .position(|candidate| candidate == &task_id)
        .expect("model task id");
    let result_hash = hash_hex(u8::try_from(slot + 1).expect("bounded task slot"));
    let reveal_salt = hash_hex(u8::try_from(slot + 17).expect("bounded task slot"));
    let commitment = result_commitment_hex(task_id, worker, &result_hash, &reveal_salt)
        .expect("model commitment inputs are canonical");
    (result_hash, reveal_salt, commitment)
}

fn next_nonce(view: &MemoryView, sender: &str) -> u64 {
    view.account(sender)
        .nonce
        .checked_add(1)
        .expect("bounded model nonce")
}

fn selected_nonce(view: &MemoryView, sender: &str, mode: u8) -> u64 {
    let current = view.account(sender).nonce;
    match mode % 5 {
        0 | 1 => current.checked_add(1).expect("bounded model nonce"),
        2 => current,
        3 => current.checked_add(2).expect("bounded model nonce gap"),
        4 => 0,
        _ => unreachable!(),
    }
}

fn role_for(sender: &str) -> &'static str {
    match sender {
        "operator" => "operator",
        "worker" => "nakama",
        _ => "hepta",
    }
}

fn plan_advance(view: &MemoryView, task_id: &str, height: u64) -> (String, CanonicalCommandV1) {
    let Some(task) = view.task(task_id) else {
        return (
            "client".to_string(),
            CanonicalCommandV1::CreateTask {
                task_id: task_id.to_string(),
                reward: 1_000,
                worker_stake: 500,
                result_deadline_height: height.checked_add(16).expect("bounded model height"),
                challenge_window_blocks: 6,
            },
        );
    };
    match task.status {
        TaskStatusV1::Open if height < task.result_deadline_height => (
            "worker".to_string(),
            CanonicalCommandV1::AssignTask {
                task_id: task_id.to_string(),
                worker: "worker".to_string(),
            },
        ),
        TaskStatusV1::Assigned if height < task.result_deadline_height => {
            let worker = task.worker.as_deref().unwrap_or("worker");
            let (_, _, commitment) = task_material(task_id, worker);
            (
                worker.to_string(),
                CanonicalCommandV1::CommitResult {
                    task_id: task_id.to_string(),
                    commitment_hex: commitment,
                },
            )
        }
        TaskStatusV1::Committed if height < task.result_deadline_height => {
            let worker = task.worker.as_deref().unwrap_or("worker");
            let (result_hash, reveal_salt, _) = task_material(task_id, worker);
            (
                worker.to_string(),
                CanonicalCommandV1::RevealResult {
                    task_id: task_id.to_string(),
                    result_hash_hex: result_hash,
                    reveal_salt_hex: reveal_salt,
                },
            )
        }
        TaskStatusV1::Revealed if height <= task.challenge_deadline_height.unwrap_or_default() => (
            "consumer".to_string(),
            CanonicalCommandV1::RecordConsumption {
                task_id: task_id.to_string(),
                units: 1,
                payment: 200,
                receipt_hash_hex: hash_hex(0x31),
            },
        ),
        TaskStatusV1::Consumed if height <= task.challenge_deadline_height.unwrap_or_default() => (
            "challenger".to_string(),
            CanonicalCommandV1::OpenChallenge {
                task_id: task_id.to_string(),
                bond: 100,
                evidence_hash_hex: hash_hex(0x41),
            },
        ),
        TaskStatusV1::Challenged => (
            "operator".to_string(),
            CanonicalCommandV1::ResolveChallenge {
                task_id: task_id.to_string(),
                accept_challenge: height.is_multiple_of(2),
            },
        ),
        TaskStatusV1::Consumed => (
            task.client,
            CanonicalCommandV1::SettleTask {
                task_id: task_id.to_string(),
            },
        ),
        TaskStatusV1::Open
        | TaskStatusV1::Assigned
        | TaskStatusV1::Committed
        | TaskStatusV1::Revealed => (
            task.client,
            CanonicalCommandV1::ExpireTask {
                task_id: task_id.to_string(),
            },
        ),
        TaskStatusV1::Settled
        | TaskStatusV1::ResolvedForWorker
        | TaskStatusV1::ResolvedForChallenger
        | TaskStatusV1::Expired => (
            "consumer".to_string(),
            CanonicalCommandV1::SettleTask {
                task_id: task_id.to_string(),
            },
        ),
    }
}

fn plan(choice: Choice, step: usize, view: &MemoryView) -> PlannedTx {
    let task_id = TASK_IDS[usize::from(choice.variant) % TASK_IDS.len()];
    let height = u64::try_from(step)
        .expect("bounded model step")
        .checked_add(2)
        .expect("bounded model height");
    let account = ACCOUNTS[usize::from(choice.variant) % ACCOUNTS.len()];
    let (sender, command) = match choice.operation % 14 {
        0 => (
            "operator".to_string(),
            CanonicalCommandV1::CreditAccount {
                account: account.to_string(),
                amount: u128::from(choice.variant % 31) + 1,
            },
        ),
        1 => (
            account.to_string(),
            CanonicalCommandV1::Transfer {
                to: ACCOUNTS[(usize::from(choice.variant) + 1) % ACCOUNTS.len()].to_string(),
                amount: u128::from(choice.variant % 97) + 1,
            },
        ),
        2 => (
            "client".to_string(),
            CanonicalCommandV1::CreateTask {
                task_id: task_id.to_string(),
                reward: 1_000,
                worker_stake: 500,
                result_deadline_height: height.checked_add(16).expect("bounded model height"),
                challenge_window_blocks: 6,
            },
        ),
        3 => plan_advance(view, task_id, height),
        4 => (
            "worker".to_string(),
            CanonicalCommandV1::AssignTask {
                task_id: task_id.to_string(),
                worker: if choice.variant.is_multiple_of(2) {
                    "worker".to_string()
                } else {
                    "challenger".to_string()
                },
            },
        ),
        5 => {
            let (_, _, commitment) = task_material(task_id, "worker");
            (
                "worker".to_string(),
                CanonicalCommandV1::CommitResult {
                    task_id: task_id.to_string(),
                    commitment_hex: commitment,
                },
            )
        }
        6 => {
            let (result_hash, reveal_salt, _) = task_material(task_id, "worker");
            (
                "worker".to_string(),
                CanonicalCommandV1::RevealResult {
                    task_id: task_id.to_string(),
                    result_hash_hex: if choice.variant.is_multiple_of(2) {
                        result_hash
                    } else {
                        hash_hex(0xee)
                    },
                    reveal_salt_hex: reveal_salt,
                },
            )
        }
        7 => (
            "consumer".to_string(),
            CanonicalCommandV1::RecordConsumption {
                task_id: task_id.to_string(),
                units: 1,
                payment: 200,
                receipt_hash_hex: hash_hex(0x31),
            },
        ),
        8 => (
            "challenger".to_string(),
            CanonicalCommandV1::OpenChallenge {
                task_id: task_id.to_string(),
                bond: 100,
                evidence_hash_hex: hash_hex(0x41),
            },
        ),
        9 => (
            "operator".to_string(),
            CanonicalCommandV1::ResolveChallenge {
                task_id: task_id.to_string(),
                accept_challenge: choice.variant.is_multiple_of(2),
            },
        ),
        10 => (
            "client".to_string(),
            CanonicalCommandV1::SettleTask {
                task_id: task_id.to_string(),
            },
        ),
        11 => (
            "client".to_string(),
            CanonicalCommandV1::ExpireTask {
                task_id: task_id.to_string(),
            },
        ),
        12 => (
            "operator".to_string(),
            CanonicalCommandV1::DistributeFees {
                to: "treasury".to_string(),
                amount: u128::from(choice.variant % 17) + 1,
            },
        ),
        13 => (
            "operator".to_string(),
            CanonicalCommandV1::SetFeePolicy {
                gas_price: u128::from(choice.variant % 3) + 1,
                base_gas: 1_000 + u64::from(choice.variant % 11),
                byte_gas: 2 + u64::from(choice.variant % 3),
            },
        ),
        _ => unreachable!(),
    };
    let signer_id = if choice.signer_mode.is_multiple_of(7) {
        ACCOUNTS[(usize::from(choice.variant) + 2) % ACCOUNTS.len()].to_string()
    } else {
        sender.clone()
    };
    PlannedTx {
        tx: canonical_tx(
            &sender,
            selected_nonce(view, &sender, choice.nonce_mode),
            command,
        ),
        signer_id,
        signer_role: role_for(&sender),
        height,
    }
}

fn generated_script(seed: u64, steps: usize) -> Vec<Choice> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut choices = vec![
        Choice {
            operation: 3,
            nonce_mode: 0,
            variant: 0,
            signer_mode: 1,
        };
        steps.min(7)
    ];
    choices.extend((choices.len()..steps).map(|index| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mixed = state ^ (u64::try_from(index).expect("bounded index") << 32);
        Choice {
            operation: mixed as u8,
            nonce_mode: (mixed >> 8) as u8,
            variant: (mixed >> 16) as u8,
            signer_mode: (mixed >> 24) as u8,
        }
    }));
    choices
}

fn run_script(script: &[Choice]) -> (MemoryView, Vec<TraceOutcome>, Coverage) {
    let mut view = bootstrap();
    let mut trace = Vec::with_capacity(script.len());
    let mut coverage = Coverage::default();
    for (step, choice) in script.iter().copied().enumerate() {
        let planned = plan(choice, step, &view);
        let before = view.clone();
        let attempted_nonce = planned.tx.nonce;
        let expected_nonce = next_nonce(&view, &planned.tx.sender);
        match execute_and_apply(&mut view, planned) {
            Ok(receipt) => {
                coverage.applied += 1;
                for event in &receipt.events {
                    *coverage.event_kinds.entry(event.kind.clone()).or_default() += 1;
                }
                trace.push(TraceOutcome::Applied {
                    gas_used: receipt.gas_used,
                    fee_charged: receipt.fee_charged,
                    events: receipt.events,
                    state: view.0.clone(),
                });
            }
            Err(error) => {
                coverage.rejected += 1;
                if attempted_nonce != expected_nonce {
                    coverage.replay_or_gap_rejected += 1;
                }
                assert_eq!(
                    view, before,
                    "rejected transaction must not mutate the state view"
                );
                trace.push(TraceOutcome::Rejected {
                    error: error.to_string(),
                    state: view.0.clone(),
                });
            }
        }
        view.assert_supply_conserved();
    }
    (view, trace, coverage)
}

#[test]
fn bounded_generated_sequences_preserve_every_issued_unit() {
    let mut applied = 0;
    let mut rejected = 0;
    let mut replay_or_gap_rejected = 0;
    let mut event_kinds = BTreeMap::<String, usize>::new();
    for seed in 0..MODEL_SEEDS {
        let (_, _, coverage) = run_script(&generated_script(seed, MODEL_STEPS));
        applied += coverage.applied;
        rejected += coverage.rejected;
        replay_or_gap_rejected += coverage.replay_or_gap_rejected;
        for (kind, count) in coverage.event_kinds {
            *event_kinds.entry(kind).or_default() += count;
        }
    }
    assert!(
        applied > 500,
        "model corpus must exercise accepted commands"
    );
    assert!(
        rejected > 500,
        "model corpus must exercise fail-closed commands"
    );
    assert!(
        replay_or_gap_rejected > 500,
        "model corpus must exercise stale and future nonces"
    );
    for required in [
        "account_credited",
        "transfer",
        "task_created",
        "task_assigned",
        "result_committed",
        "result_revealed",
    ] {
        assert!(
            event_kinds.contains_key(required),
            "model corpus did not reach required event {required}"
        );
    }
}

#[test]
fn sequential_nonce_and_replay_are_fail_closed() {
    let mut view = bootstrap();
    let transfer = |nonce| PlannedTx {
        tx: canonical_tx(
            "client",
            nonce,
            CanonicalCommandV1::Transfer {
                to: "treasury".to_string(),
                amount: 1,
            },
        ),
        signer_id: "client".to_string(),
        signer_role: "hepta",
        height: 2,
    };

    let before_gap = view.clone();
    assert!(matches!(
        execute_and_apply(&mut view, transfer(2)),
        Err(RuntimeError::NonceMismatch {
            expected: 1,
            received: 2
        })
    ));
    assert_eq!(view, before_gap);

    execute_and_apply(&mut view, transfer(1)).expect("first contiguous nonce must succeed");
    let after_first = view.clone();
    for stale_or_gap in [0, 1, 3, 9] {
        assert!(
            execute_and_apply(&mut view, transfer(stale_or_gap)).is_err(),
            "nonce {stale_or_gap} must fail while the next nonce is 2"
        );
        assert_eq!(
            view, after_first,
            "replay, zero, and future nonce rejection must be atomic"
        );
    }

    execute_and_apply(&mut view, transfer(2)).expect("second contiguous nonce must succeed");
    assert_eq!(view.account("client").nonce, 2);
    assert!(matches!(
        execute_and_apply(&mut view, transfer(1)),
        Err(RuntimeError::NonceMismatch {
            expected: 3,
            received: 1
        })
    ));
    view.assert_supply_conserved();
}

#[test]
fn deterministic_replay_produces_identical_state_receipts_and_events() {
    for seed in 10_000..10_032 {
        let script = generated_script(seed, MODEL_STEPS);
        let (left_state, left_trace, _) = run_script(&script);
        let (right_state, right_trace, _) = run_script(&script);
        assert_eq!(
            left_trace, right_trace,
            "the same transaction/context sequence diverged at seed {seed}"
        );
        assert_eq!(
            left_state, right_state,
            "the same transaction/context sequence produced different final state at seed {seed}"
        );
    }
}
