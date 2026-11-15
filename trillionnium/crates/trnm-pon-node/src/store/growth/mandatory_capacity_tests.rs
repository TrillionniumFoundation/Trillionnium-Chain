//! Characterize the actual owner cap without changing any consensus parameter.
//! A fresh reward recipient can be excluded at capacity, but the same admitted
//! prefix still permits progress, two refund waves and ordinary reward maturity.
use super::*;

#[test]
fn native_growth_v2_mandatory_owner_cap_excludes_new_miner_but_refunds_and_matures() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    assert_eq!(limits::MAX_MANDATORY_OWNERS, 32);
    assert_eq!(settings.limit("mandatory_expiry_per_block").unwrap(), 16);
    assert_eq!(settings.limit("reward_maturity_blocks").unwrap(), 20);
    let budget = 1000u64;
    let mut transactions = Vec::new();
    let mut tasks = Vec::new();
    for (index, owner) in (100u64..131).enumerate() {
        transactions.push(transfer(
            &settings,
            0,
            index as u64 + 1,
            public(owner),
            10_000,
        ));
        let deadline = if index < 16 { 3u64 } else { 4u64 };
        let task = hash(
            b"task-instance-v3",
            &[
                &settings.network(),
                &settings.parameters(),
                &public(owner),
                &1u64.to_le_bytes(),
                &public(1),
                &budget.to_le_bytes(),
                &deadline.to_le_bytes(),
            ],
        );
        tasks.push((owner, task, deadline));
    }
    for (owner, task, deadline) in &tasks {
        let mut payload = task.to_vec();
        payload.extend(public(1));
        payload.extend(budget.to_le_bytes());
        payload.extend(deadline.to_le_bytes());
        transactions.push(signed(&settings, *owner, 1, 2, payload));
    }
    assert_eq!(transactions.len(), 62);
    let first = make(&node, settings.genesis(), transactions);
    let first_id = admit(&mut node, &first);
    let working = node.growth_working(first_id).unwrap();
    assert_eq!(limits::mandatory_owners(&working).unwrap().len(), 32);
    assert!(working.len() < limits::MAX_WORKING_KEYS);
    let working_bytes: usize = working
        .iter()
        .map(|(key, value)| key.len() + 8 + canonical(value).unwrap().len())
        .sum();
    assert!(working_bytes < limits::MAX_WORKING_BYTES);
    assert!(first.accounts.accounts.len() < limits::MAX_WITNESS_ACCOUNTS);
    assert!(first.accounts.encoded_len().unwrap() < limits::MAX_WITNESS_BYTES);
    assert!(first.encode().unwrap().len() < limits::MAX_PACKET_BYTES);
    let before = rows(&node.db);
    let error = node
        .make_growth_consensus_maintenance(first_id, vec![], public(999), 21, 4096)
        .unwrap_err();
    assert_eq!(error.to_string(), "GROWTH_MANDATORY_CAPACITY");
    assert_eq!(rows(&node.db), before);

    // This successful successor is a direct counterexample to permanent halt.
    // It pays the same reward owner already reserved by the admitted state.
    let second = make(&node, first_id, vec![]);
    let second_id = admit(&mut node, &second);
    let balances: Vec<_> = tasks
        .iter()
        .map(|(owner, _, _)| {
            node.growth_account(second_id, public(*owner))
                .unwrap()
                .unwrap()
                .balance
        })
        .collect();
    let third = node
        .make_growth_consensus_maintenance(second_id, vec![], public(999), 31, 4096)
        .unwrap();
    let third_id = admit(&mut node, &third);
    assert_eq!(
        limits::mandatory_owners(&node.growth_working(third_id).unwrap())
            .unwrap()
            .len(),
        17
    );
    for (index, (owner, task, deadline)) in tasks.iter().enumerate() {
        let row = format!("task:{}", hex::encode(task));
        let expected_refund = if *deadline == 3 { budget } else { 0 };
        assert_eq!(
            node.growth_account(third_id, public(*owner))
                .unwrap()
                .unwrap()
                .balance,
            balances[index] + expected_refund
        );
        assert_eq!(
            node.growth_working(third_id).unwrap()[&row]["remaining"],
            budget - expected_refund
        );
    }
    let fourth = node
        .make_growth_consensus_maintenance(third_id, vec![], public(998), 41, 4096)
        .unwrap();
    let mut tip = admit(&mut node, &fourth);
    assert_eq!(
        limits::mandatory_owners(&node.growth_working(tip).unwrap())
            .unwrap()
            .len(),
        3
    );
    for (index, (owner, _, _)) in tasks.iter().enumerate() {
        assert_eq!(
            node.growth_account(tip, public(*owner))
                .unwrap()
                .unwrap()
                .balance,
            balances[index] + budget
        );
    }
    let reward_key = format!(
        "reward:{}",
        hex::encode(hash(
            b"reward",
            &[&settings.genesis(), &1u64.to_le_bytes(), &public(3)]
        ))
    );
    let first_reward = working[&reward_key]["amount"].as_u64().unwrap();
    for _ in 5..=20 {
        let next = make(&node, tip, vec![]);
        tip = admit(&mut node, &next);
    }
    let balance = node
        .growth_account(tip, public(3))
        .unwrap()
        .unwrap()
        .balance;
    let maturity = make(&node, tip, vec![]);
    tip = admit(&mut node, &maturity);
    assert_eq!(node.record(tip).unwrap().height, 21);
    assert!(!node.growth_working(tip).unwrap().contains_key(&reward_key));
    assert_eq!(
        node.growth_account(tip, public(3))
            .unwrap()
            .unwrap()
            .balance,
        balance + first_reward
    );
    eprintln!(
        "native mandatory owner capacity: signed_transactions=62, owners=32, working_keys={}, working_bytes={}, witness_accounts={}, witness_bytes={}, packet_bytes={}; new reward owner rejected at h2, admitted at h3 after refunds; h21 maturity succeeded",
        working.len(),
        working_bytes,
        first.accounts.accounts.len(),
        first.accounts.encoded_len().unwrap(),
        first.encode().unwrap().len()
    );
}
