use super::*;

pub(crate) fn read_write_decl(st: &StateStore, tx: &MockTx, tx_id: u64) -> Tx {
    let task_id = task_id_of(tx);

    let task_obj = ObjectRef {
        id: task_id,
        version: 1,
    };
    let mut read_set = vec![task_obj.clone()];
    let mut write_set = vec![task_obj.clone()];

    match tx {
        MockTx::AcceptTask { worker, .. } => {
            let worker_obj = ObjectRef {
                id: pseudo_object_id_for_account(worker),
                version: 1,
            };
            let lock_obj = ObjectRef {
                id: pseudo_object_id_for_account(&format!("worker_stake_lock.{}", task_id)),
                version: 1,
            };
            read_set.push(worker_obj.clone());
            write_set.push(worker_obj);
            read_set.push(lock_obj.clone());
            write_set.push(lock_obj);
        }
        MockTx::Challenge { challenger, .. } => {
            let challenger_obj = ObjectRef {
                id: pseudo_object_id_for_account(challenger),
                version: 1,
            };
            let escrow_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_ESCROW_ACCOUNT),
                version: 1,
            };
            read_set.push(challenger_obj.clone());
            write_set.push(challenger_obj);
            read_set.push(escrow_obj.clone());
            write_set.push(escrow_obj);
        }
        MockTx::Resolve { .. } => {
            let escrow_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_ESCROW_ACCOUNT),
                version: 1,
            };
            let forfeit_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
                version: 1,
            };
            let slash_obj = ObjectRef {
                id: pseudo_object_id_for_account(WORKER_SLASH_TREASURY_ACCOUNT),
                version: 1,
            };
            let lock_obj = ObjectRef {
                id: pseudo_object_id_for_account(&format!("worker_stake_lock.{}", task_id)),
                version: 1,
            };
            read_set.push(escrow_obj.clone());
            write_set.push(escrow_obj);
            read_set.push(forfeit_obj.clone());
            write_set.push(forfeit_obj);
            read_set.push(slash_obj.clone());
            write_set.push(slash_obj);
            read_set.push(lock_obj.clone());
            write_set.push(lock_obj);

            if let Some(challenger) = st.get_task(task_id).and_then(|t| t.challenger) {
                let challenger_obj = ObjectRef {
                    id: pseudo_object_id_for_account(&challenger),
                    version: 1,
                };
                read_set.push(challenger_obj.clone());
                write_set.push(challenger_obj);
            }
        }
        MockTx::SubmitConsumptionReceipt { .. } => {
            let (consumer_nonce_obj, receipt_record_obj, task_summary_obj) =
                receipt_settlement_conflict_refs_of(tx).expect("receipt tx key");
            write_set.clear();
            read_set.push(consumer_nonce_obj.clone());
            write_set.push(consumer_nonce_obj);
            read_set.push(receipt_record_obj.clone());
            write_set.push(receipt_record_obj);
            read_set.push(task_summary_obj.clone());
            write_set.push(task_summary_obj);
        }
        MockTx::ChallengeConsumptionReceipt { .. } => {
            let (consumer_nonce_obj, receipt_record_obj, task_summary_obj) =
                receipt_settlement_conflict_refs_of(tx).expect("receipt tx key");
            write_set.clear();
            read_set.push(consumer_nonce_obj);
            read_set.push(receipt_record_obj.clone());
            write_set.push(receipt_record_obj);
            read_set.push(task_summary_obj.clone());
            write_set.push(task_summary_obj);
        }
        MockTx::ResolveConsumptionReceipt { .. } => {
            let (consumer_nonce_obj, receipt_record_obj, task_summary_obj) =
                receipt_settlement_conflict_refs_of(tx).expect("receipt tx key");
            let resolve_authority_obj = ObjectRef {
                id: pseudo_object_id_for_state_slot("gov_param", "resolve_authority"),
                version: 1,
            };
            write_set.clear();
            read_set.push(consumer_nonce_obj);
            read_set.push(receipt_record_obj.clone());
            write_set.push(receipt_record_obj);
            read_set.push(task_summary_obj.clone());
            write_set.push(task_summary_obj);
            read_set.push(resolve_authority_obj);
        }
        _ => {}
    }

    Tx {
        id: tx_id,
        read_set,
        write_set,
        payload: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_pouw::ConsumptionResolveDecision;

    #[test]
    fn split_receipt_settlement_rw_decl_contract_matches_main() {
        let result_hash = [0x2a; 32];
        let receipt =
            crate::sample_consumption_receipt(42, "worker-alpha", "consumer-bravo", result_hash);
        let key = receipt.replay_key();

        let submit_tx = MockTx::SubmitConsumptionReceipt {
            receipt: receipt.clone(),
        };
        let challenge_tx = MockTx::ChallengeConsumptionReceipt {
            key: key.clone(),
            challenger: "auditor-1".to_string(),
        };
        let resolve_tx = MockTx::ResolveConsumptionReceipt {
            key,
            decision: ConsumptionResolveDecision::Discount,
            credited_consumption_units: Some(9),
            resolution_code: None,
            resolver: "resolver-1".to_string(),
        };

        let st = StateStore::default();
        assert_eq!(
            read_write_decl(&st, &submit_tx, 1),
            crate::read_write_decl(&st, &submit_tx, 1)
        );
        assert_eq!(
            read_write_decl(&st, &challenge_tx, 2),
            crate::read_write_decl(&st, &challenge_tx, 2)
        );
        assert_eq!(
            read_write_decl(&st, &resolve_tx, 3),
            crate::read_write_decl(&st, &resolve_tx, 3)
        );
    }
}
