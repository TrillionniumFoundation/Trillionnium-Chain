#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
use trnm_mvcc_fee::pon_executor::{Config, State, LEGACY_TASK_PROFILE};
use trnm_pon_node::{
    account_archive_execution::{
        self as execution, obligations, state_witness::StateCommitment, BlockInput,
        CheckedExecutionError, CompactStateExecutionInput, StateExecutionInput,
    },
    account_archive_prototype::{
        multiproof::Multiproof, Account, AccountArchive, Context, Limits, Witness,
    },
    Settings,
};
use trnm_protocol::pon_wire::{hash, Hash};

// Independent bottom-up sparse reconstruction. Production code partitions
// sorted paths recursively and merges original witness frontiers; this oracle
// collapses complete leaf maps one level at a time and uses no archive roots.
fn sparse(mut leaves: BTreeMap<Hash, Hash>, empty_tag: &[u8], branch: &[u8]) -> Hash {
    let mut empty = hash(empty_tag, &[]);
    for _ in 0..256 {
        let mut parents = BTreeMap::<Hash, [Option<Hash>; 2]>::new();
        for (path, value) in leaves {
            let side = (path[31] & 1) as usize;
            let mut parent = [0; 32];
            let mut carry = 0;
            for (out, byte) in parent.iter_mut().zip(path) {
                *out = (byte >> 1) | carry;
                carry = (byte & 1) << 7;
            }
            assert!(parents.entry(parent).or_default()[side]
                .replace(value)
                .is_none());
        }
        leaves = parents
            .into_iter()
            .map(|(path, pair)| {
                (
                    path,
                    hash(
                        branch,
                        &[&pair[0].unwrap_or(empty), &pair[1].unwrap_or(empty)],
                    ),
                )
            })
            .collect();
        empty = hash(branch, &[&empty, &empty]);
    }
    leaves.get(&[0; 32]).copied().unwrap_or(empty)
}

fn state_root(state: &State) -> Hash {
    sparse(
        state
            .iter()
            .map(|(key, value)| {
                (
                    hash(b"state-key", &[key.as_bytes()]),
                    hash(
                        b"state-leaf",
                        &[key.as_bytes(), &serde_json::to_vec(value).unwrap()],
                    ),
                )
            })
            .collect(),
        b"state-empty",
        b"state-node",
    )
}

fn commitment_id(c: &StateCommitment) -> Hash {
    hash(
        b"checked-state-commitment-v1",
        &[
            &c.network,
            &c.parameters,
            &c.genesis,
            &c.state_root,
            &c.account_root,
            &c.account_count.to_le_bytes(),
            &c.account_balance.to_le_bytes(),
            &c.non_account_root,
            &c.non_account_count.to_le_bytes(),
            &c.escrow_balance.to_le_bytes(),
            &c.reward_balance.to_le_bytes(),
            &c.issued.to_le_bytes(),
        ],
    )
}

fn check_commitment(c: &StateCommitment, state: &State, context: Context) {
    let mut accounts = BTreeMap::new();
    let mut non_accounts = State::new();
    let (mut balance, mut escrow, mut rewards) = (0u64, 0u64, 0u64);
    for (key, value) in state {
        if let Some(owner) = key.strip_prefix("account:") {
            let owner: Hash = hex::decode(owner).unwrap().try_into().unwrap();
            let amount = value["balance"].as_u64().unwrap();
            let nonce = value["nonce"].as_u64().unwrap();
            balance += amount;
            accounts.insert(
                hash(b"account-archive-key-v1", &[&owner]),
                hash(
                    b"account-archive-leaf-v1",
                    &[&owner, &amount.to_le_bytes(), &nonce.to_le_bytes()],
                ),
            );
        } else {
            non_accounts.insert(key.clone(), value.clone());
            if key.starts_with("task:") {
                escrow += value["remaining"].as_u64().unwrap();
            }
            if key.starts_with("reward:") {
                rewards += value["amount"].as_u64().unwrap();
            }
        }
    }
    assert_eq!(
        (c.network, c.parameters, c.genesis),
        (context.network, context.parameters, context.genesis)
    );
    assert_eq!(c.state_root, state_root(state));
    assert_eq!(c.account_count, accounts.len() as u64);
    assert_eq!(
        c.account_root,
        sparse(
            accounts,
            b"account-archive-empty-v1",
            b"account-archive-branch-v1"
        )
    );
    assert_eq!(c.non_account_count, non_accounts.len() as u64);
    assert_eq!(c.non_account_root, state_root(&non_accounts));
    assert_eq!(
        (c.account_balance, c.escrow_balance, c.reward_balance),
        (balance, escrow, rewards)
    );
    assert_eq!(c.issued, state["meta:issued"].as_u64().unwrap());
    assert_eq!(balance + escrow + rewards, c.issued);
    assert_eq!(c.id, commitment_id(c));
}

fn credit(state: &mut State, owner: &str, amount: u64) {
    let account = state
        .entry(format!("account:{owner}"))
        .or_insert(json!({"balance":0,"nonce":0}));
    account["balance"] = json!(account["balance"].as_u64().unwrap() + amount);
}

fuzz_target!(|bytes: &[u8]| {
    let byte = |i: usize| bytes.get(i).copied().unwrap_or(0);
    let settings = Settings::development(Some(1)).unwrap();
    let context = Context {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    };
    let owners: Vec<_> = (0..6u8)
        .map(|index| {
            hash(
                b"state-fuzz-owner",
                &[&[index], bytes.get(16..48).unwrap_or(&[])],
            )
        })
        .collect();
    let mut parent = State::new();
    parent.insert("model:current".into(), json!("00".repeat(32)));
    parent.insert(
        "retained:unknown".into(),
        if byte(2) & 1 == 0 {
            Value::Null
        } else {
            json!({"note":byte(3)})
        },
    );
    let mut issued = 0u64;
    for (i, owner) in owners.iter().enumerate().take(3) {
        let balance = u64::from(byte(i + 4)) * 100;
        issued += balance;
        parent.insert(
            format!("account:{}", hex::encode(owner)),
            json!({"balance":balance,"nonce":u64::from(byte(i + 7))}),
        );
    }
    let task_owner = hex::encode(owners[usize::from(byte(10)) % owners.len()]);
    let task_amount = u64::from(byte(11)) + 1;
    issued += task_amount;
    parent.insert(
        "task:fuzz".into(),
        json!({"owner":task_owner,"remaining":task_amount,"deadline":1,"status":"active"}),
    );
    for index in 0..=usize::from(byte(12) % 3) {
        let amount = u64::from(byte(index + 13)) + 1;
        issued += amount;
        parent.insert(format!("reward:fuzz{index}"), json!({"owner":hex::encode(owners[(index + 2) % owners.len()]),"amount":amount,"maturity":1 + u64::from(byte(index + 9) & 1)}));
    }
    parent.insert("meta:issued".into(), json!(issued));
    let original = parent.clone();
    let mut archive =
        AccountArchive::open(Path::new(":memory:"), context, Limits::default()).unwrap();
    let checkpoint = archive
        .project_initial(&parent, state_root(&parent))
        .unwrap();
    let miner = owners[5];
    let transactions = [];
    let block = BlockInput {
        transactions: &transactions,
        height: 1,
        miner,
        parent_id: checkpoint.branch(),
    };
    let mut prepared =
        obligations::prepare(&settings, &archive, checkpoint.id(), &parent, block).unwrap();
    let mut witness =
        execution::prepare_state_witness(&settings, &archive, checkpoint.id(), &parent).unwrap();
    let checked = execution::execute_with_state_witness(
        &settings,
        &archive,
        checkpoint.id(),
        &parent,
        block,
        StateExecutionInput {
            accounts: &prepared.accounts,
            state: &witness,
        },
    )
    .unwrap();

    // Independently apply this finite input grammar's expiry and maturity rules.
    let mut mandatory = parent.clone();
    credit(&mut mandatory, &task_owner, task_amount);
    mandatory.get_mut("task:fuzz").unwrap()["remaining"] = json!(0);
    mandatory.get_mut("task:fuzz").unwrap()["status"] = json!("expired");
    for (key, reward) in parent.iter().filter(|(key, _)| key.starts_with("reward:")) {
        if reward["maturity"] == 1 {
            mandatory.remove(key);
            credit(
                &mut mandatory,
                reward["owner"].as_str().unwrap(),
                reward["amount"].as_u64().unwrap(),
            );
        }
    }
    let cfg = Config::installed_with_profiles("legacy-first-two-v3", LEGACY_TASK_PROFILE).unwrap();
    let subsidy = cfg.params["block_subsidy_units"].as_u64().unwrap();
    let mut successor = mandatory.clone();
    let reward_id = hash(
        b"reward",
        &[&checkpoint.branch(), &1u64.to_le_bytes(), &miner],
    );
    successor.insert(format!("reward:{}", hex::encode(reward_id)), json!({"owner":hex::encode(miner),"amount":subsidy,"maturity":1+cfg.params["reward_maturity_blocks"].as_u64().unwrap()}));
    successor.insert("meta:issued".into(), json!(issued + subsidy));
    assert_eq!(checked.execution.output.state, successor);
    assert_eq!(checked.execution.output.root, state_root(&successor));
    check_commitment(&checked.state_observation.parent, &parent, context);
    check_commitment(
        &checked.state_observation.mandatory.commitment,
        &mandatory,
        context,
    );
    check_commitment(
        &checked.state_observation.successor.commitment,
        &successor,
        context,
    );

    let mode = usize::from(byte(0).wrapping_sub(b'0')) % 11;
    if byte(15) & 1 != 0 {
        let mut compact =
            obligations::prepare_compact(&settings, &archive, checkpoint.id(), &parent, block)
                .unwrap();
        let result = execution::execute_with_compact_state_witness(
            &settings,
            &archive,
            checkpoint.id(),
            &parent,
            block,
            CompactStateExecutionInput {
                accounts: &compact.accounts,
                state: &witness,
            },
        )
        .unwrap();
        assert_eq!(result.execution.execution.output.state, successor);
        check_commitment(&result.execution.state_observation.parent, &parent, context);
        check_commitment(
            &result.execution.state_observation.mandatory.commitment,
            &mandatory,
            context,
        );
        check_commitment(
            &result.execution.state_observation.successor.commitment,
            &successor,
            context,
        );
        assert_eq!(compact.construction.expanded_witnesses_allocated, 0);
        let mut cancel_at = None;
        match mode {
            0 => return,
            1 => {
                witness.commitment.account_balance += 1;
                witness.commitment.id = commitment_id(&witness.commitment);
            }
            2 => {
                witness
                    .non_accounts
                    .remove(usize::from(byte(1)) % witness.non_accounts.len());
            }
            3 => witness.non_accounts.reverse(),
            4 => {
                let account = &mut compact.accounts.accounts[0].account;
                *account = Some(Account {
                    balance: account.map_or(0, |a| a.balance),
                    nonce: account.map_or(1, |a| a.nonce + 1),
                });
            }
            5 => {
                compact.accounts.accounts.remove(0);
            }
            6 => compact
                .accounts
                .accounts
                .push(compact.accounts.accounts[0].clone()),
            7 => {
                parent.insert("retained:unknown".into(), json!("altered"));
            }
            8 => cancel_at = Some(usize::from(byte(1)) % 4),
            9 => {
                let mut encoded = compact.accounts.encode().unwrap();
                let index = (usize::from(byte(1)) * 31 + usize::from(byte(2))) % encoded.len();
                encoded[index] ^= 1;
                let Ok(decoded) = Multiproof::decode(&encoded) else {
                    return;
                };
                assert_eq!(decoded.encode().unwrap(), encoded);
                compact.accounts = decoded;
            }
            _ => witness.parent_id[0] ^= 1,
        }
        let calls = AtomicUsize::new(0);
        let result = execution::execute_with_compact_state_witness_and_progress(
            &settings,
            &archive,
            checkpoint.id(),
            &parent,
            block,
            CompactStateExecutionInput {
                accounts: &compact.accounts,
                state: &witness,
            },
            &|_| {
                if cancel_at == Some(calls.fetch_add(1, Ordering::Relaxed)) {
                    Err(CheckedExecutionError::Cancelled)
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(archive.checkpoint(checkpoint.id()).unwrap(), checkpoint);
        return;
    }
    let mut cancel_at = None;
    match mode {
        0 => return,
        1 => {
            witness.commitment.account_balance += 1;
            witness.commitment.id = commitment_id(&witness.commitment);
        }
        2 => {
            witness
                .non_accounts
                .remove(usize::from(byte(1)) % witness.non_accounts.len());
        }
        3 => witness.non_accounts.reverse(),
        4 => {
            prepared.accounts[0].siblings[usize::from(byte(1))][0] ^= 1;
        }
        5 => {
            prepared.accounts.remove(0);
        }
        6 => prepared.accounts.push(prepared.accounts[0].clone()),
        7 => {
            parent.insert("retained:unknown".into(), json!("altered"));
        }
        8 => cancel_at = Some(usize::from(byte(1)) % 4),
        9 => {
            let mut encoded = prepared.accounts[0].encode().unwrap();
            let index = (usize::from(byte(1)) * 31 + usize::from(byte(2))) % encoded.len();
            encoded[index] ^= 1;
            let Ok(decoded) = Witness::decode(&encoded) else {
                return;
            };
            assert_eq!(decoded.encode().unwrap(), encoded);
            prepared.accounts[0] = decoded;
        }
        _ => {
            witness.parent_id[0] ^= 1;
        }
    }
    let calls = AtomicUsize::new(0);
    let result = execution::execute_with_state_witness_and_progress(
        &settings,
        &archive,
        checkpoint.id(),
        &parent,
        block,
        StateExecutionInput {
            accounts: &prepared.accounts,
            state: &witness,
        },
        &|_| {
            if cancel_at == Some(calls.fetch_add(1, Ordering::Relaxed)) {
                Err(CheckedExecutionError::Cancelled)
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(archive.checkpoint(checkpoint.id()).unwrap(), checkpoint);
    assert_eq!(
        original,
        if mode == 7 {
            let mut restored = parent;
            restored.insert(
                "retained:unknown".into(),
                original["retained:unknown"].clone(),
            );
            restored
        } else {
            parent
        }
    );
});
