use anyhow::Result;
use std::time::Duration;

use crate::{
    cmd::{TransferTxRequest, TransferTxResponse, TxCommand},
    derive_address_from_priv_hex, emit_pending_tx_hash, emit_tx_hash_lines, missing_backend,
    persist_local_pending_tx, read_key, resolve_wallet_store, run_template, tpl, tx_query,
    wait_for_tx, warn_development_only_adapter,
};

pub(crate) fn handle_tx_command(tx: TxCommand) -> Result<()> {
    match tx {
        TxCommand::CommitResult {
            task_id,
            worker,
            commit_hash,
            nonce,
        } => {
            let mut cmd = std::env::var("TRNM_TX_COMMIT_CMD").map_err(|_| {
                missing_backend(
                    "legacy commit-result submission",
                    "TRNM_TX_COMMIT_CMD",
                    "synthetic pending transaction hashes",
                )
            })?;
            warn_development_only_adapter("legacy commit-result submission");
            cmd = tpl(cmd, "task_id", &task_id.to_string());
            cmd = tpl(cmd, "worker", &worker);
            cmd = tpl(cmd, "commit_hash", &commit_hash);
            cmd = tpl(cmd, "nonce", &nonce.to_string());
            let tx_hash = run_template(&cmd)?;
            emit_pending_tx_hash(&tx_hash)?;
        }
        TxCommand::RevealResult {
            task_id,
            result_hash,
            salt_hex,
        } => {
            let mut cmd = std::env::var("TRNM_TX_REVEAL_CMD").map_err(|_| {
                missing_backend(
                    "legacy reveal-result submission",
                    "TRNM_TX_REVEAL_CMD",
                    "synthetic pending transaction hashes",
                )
            })?;
            warn_development_only_adapter("legacy reveal-result submission");
            cmd = tpl(cmd, "task_id", &task_id.to_string());
            cmd = tpl(cmd, "result_hash", &result_hash);
            cmd = tpl(cmd, "salt_hex", &salt_hex);
            let tx_hash = run_template(&cmd)?;
            emit_pending_tx_hash(&tx_hash)?;
        }
        TxCommand::Query { tx_hash } => {
            let resp = tx_query(&tx_hash)?;
            emit_tx_hash_lines(&resp.tx_hash);
            println!("status={}", resp.status);
            if let Some(err) = resp.error {
                println!("error={}", err);
            }
        }
        TxCommand::Wait {
            tx_hash,
            timeout,
            interval,
        } => {
            let resp = wait_for_tx(
                &tx_hash,
                Duration::from_secs(timeout),
                Duration::from_secs(interval),
                tx_query,
            )?;
            emit_tx_hash_lines(&resp.tx_hash);
            println!("status={}", resp.status);
            if let Some(err) = resp.error {
                println!("error={}", err);
            }
        }
        TxCommand::Transfer {
            from,
            to,
            amount,
            denom,
            store,
        } => {
            let s = resolve_wallet_store(store)?;
            let from_priv_hex = read_key(&s, &from)?;
            let from_addr = derive_address_from_priv_hex(&from_priv_hex)?;
            let req = TransferTxRequest {
                from: from_addr,
                to,
                amount: amount.to_string(),
                denom,
            };

            let mut cmd = std::env::var("TRNM_TX_TRANSFER_CMD").map_err(|_| {
                missing_backend(
                    "transfer submission",
                    "TRNM_TX_TRANSFER_CMD",
                    "synthetic pending transaction hashes",
                )
            })?;
            warn_development_only_adapter("transfer submission");
            cmd = tpl(cmd, "from", &req.from);
            cmd = tpl(cmd, "to", &req.to);
            cmd = tpl(cmd, "amount", &req.amount);
            cmd = tpl(cmd, "denom", &req.denom);
            let tx_hash = run_template(&cmd)?;
            persist_local_pending_tx(&tx_hash)?;
            let out = TransferTxResponse {
                tx_hash,
                status: "pending".into(),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}
