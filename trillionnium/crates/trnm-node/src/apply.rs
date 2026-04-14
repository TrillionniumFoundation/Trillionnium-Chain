use anyhow::{Context, Result};
use trnm_pouw::{
    apply_accept_task_at_height, apply_challenge_at_height, apply_commit_result_at_height,
    apply_create_task, apply_resolve_at_height, apply_reveal_result_at_height,
    challenge_consumption_receipt_at_height, resolve_consumption_receipt_at_height,
    submit_consumption_receipt_at_height,
};
use trnm_state::StateStore;
use trnm_types::ObjectRef;

use crate::txmeta::actor_of;
use crate::types::MockTx;

fn task_ref(st: &StateStore, task_id: u64) -> Result<ObjectRef> {
    st.get_ref(task_id)
        .with_context(|| format!("task_ref missing for task_id={}", task_id))
}

pub(crate) fn verified_signer_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::Resolve { resolver, .. } => resolver.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| "unknown_worker".to_string()),
        _ => actor_of(st, tx),
    }
}

pub(crate) fn apply_one(st: &mut StateStore, tx: MockTx, current_height: u64) -> Result<()> {
    let signer = verified_signer_of(st, &tx);
    match tx {
        MockTx::CreateTask {
            task_id,
            creator,
            bounty,
        } => {
            let _ = apply_create_task(st, task_id, creator, bounty)?;
        }
        MockTx::AcceptTask { task_id, worker } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_accept_task_at_height(st, r, worker, current_height)?;
        }
        MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_commit_result_at_height(st, r, worker, committed_hash, current_height)?;
        }
        MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_reveal_result_at_height(
                st,
                r,
                result_hash,
                reveal_salt,
                None,
                current_height,
            )?;
        }
        MockTx::Challenge {
            task_id,
            challenger,
            bond,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_challenge_at_height(st, r, challenger, bond, signer, current_height)?;
        }
        MockTx::Resolve {
            task_id,
            slash_worker,
            resolver,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_resolve_at_height(st, r, slash_worker, resolver, signer, current_height)?;
        }
        MockTx::SubmitConsumptionReceipt { receipt } => {
            let _ = submit_consumption_receipt_at_height(st, receipt, signer, current_height)?;
        }
        MockTx::ChallengeConsumptionReceipt { key, challenger } => {
            let _ = challenge_consumption_receipt_at_height(
                st,
                key,
                challenger,
                signer,
                current_height,
            )?;
        }
        MockTx::ResolveConsumptionReceipt {
            key,
            decision,
            credited_consumption_units,
            resolution_code,
            resolver,
        } => {
            let _ = resolve_consumption_receipt_at_height(
                st,
                key,
                decision,
                credited_consumption_units,
                resolution_code,
                resolver,
                signer,
                current_height,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_pouw::ConsumptionResolveDecision;

    fn seeded_receipt_state() -> StateStore {
        let mut st = StateStore::default();
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "resolver-1,resolver-2".into(),
        );
        let result_hash = [0x2a; 32];
        crate::put_sample_poco_task(&mut st, 42, "worker-alpha", result_hash);
        st
    }

    #[test]
    fn split_receipt_settlement_apply_contract_matches_main() {
        let result_hash = [0x2a; 32];
        let receipt =
            crate::sample_consumption_receipt(42, "worker-alpha", "consumer-bravo", result_hash);

        let submit_tx = MockTx::SubmitConsumptionReceipt {
            receipt: receipt.clone(),
        };
        let record_key = crate::consumption_record_key_of(&submit_tx).expect("record key");
        let challenge_tx = MockTx::ChallengeConsumptionReceipt {
            key: receipt.replay_key(),
            challenger: "auditor-1".to_string(),
        };
        let resolve_tx = MockTx::ResolveConsumptionReceipt {
            key: receipt.replay_key(),
            decision: ConsumptionResolveDecision::Discount,
            credited_consumption_units: Some(9),
            resolution_code: None,
            resolver: "resolver-1".to_string(),
        };

        let signer_state = seeded_receipt_state();
        assert_eq!(
            verified_signer_of(&signer_state, &submit_tx),
            crate::verified_signer_of(&signer_state, &submit_tx)
        );
        assert_eq!(
            verified_signer_of(&signer_state, &challenge_tx),
            crate::verified_signer_of(&signer_state, &challenge_tx)
        );
        assert_eq!(
            verified_signer_of(&signer_state, &resolve_tx),
            crate::verified_signer_of(&signer_state, &resolve_tx)
        );

        let mut split_st = seeded_receipt_state();
        let mut main_st = seeded_receipt_state();

        apply_one(&mut split_st, submit_tx.clone(), 10).expect("split submit receipt");
        crate::apply_one(&mut main_st, submit_tx, 10).expect("main submit receipt");
        assert_eq!(
            split_st.consumption_record(&record_key),
            main_st.consumption_record(&record_key)
        );
        assert_eq!(
            split_st.task_consumption_summary(42),
            main_st.task_consumption_summary(42)
        );

        apply_one(&mut split_st, challenge_tx.clone(), 11).expect("split challenge receipt");
        crate::apply_one(&mut main_st, challenge_tx, 11).expect("main challenge receipt");
        assert_eq!(
            split_st.consumption_record(&record_key),
            main_st.consumption_record(&record_key)
        );
        assert_eq!(
            split_st.task_consumption_summary(42),
            main_st.task_consumption_summary(42)
        );

        apply_one(&mut split_st, resolve_tx.clone(), 12).expect("split resolve receipt");
        crate::apply_one(&mut main_st, resolve_tx, 12).expect("main resolve receipt");
        assert_eq!(
            split_st.consumption_record(&record_key),
            main_st.consumption_record(&record_key)
        );
        assert_eq!(
            split_st.task_consumption_summary(42),
            main_st.task_consumption_summary(42)
        );
    }
}
