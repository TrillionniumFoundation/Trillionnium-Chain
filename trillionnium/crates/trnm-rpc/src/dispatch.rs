use anyhow::Result;

use crate::account_tx::{
    handle_faucet_request, handle_get_tx, handle_query_balance, handle_query_nonce,
    handle_send_tx,
};
use crate::cli::Command;
use crate::health::serve_health;
use crate::ingress_flow::{handle_dispatch_open, handle_submit_message};
use crate::market_flow::{
    handle_market_create_task, handle_market_match_task, handle_market_report,
    handle_market_submit_bid,
};
use crate::read_query::{
    handle_query_capability_audit, handle_query_events, handle_query_param, handle_query_proposal,
    handle_query_task,
};
use crate::request_query::{handle_query_request, handle_query_request_full};
use crate::runtime::now_ms;
use crate::treasury::handle_query_challenge_treasury;

pub(crate) fn dispatch_command(cmd: Command) -> Result<()> {
    match cmd {
        Command::QueryTask { task_id } => handle_query_task(task_id)?,
        Command::QueryProposal { proposal_id } => handle_query_proposal(proposal_id)?,
        Command::QueryParam { key } => handle_query_param(&key)?,
        Command::QueryEvents { task_id, limit } => handle_query_events(task_id, limit)?,
        Command::QueryCapabilityAudit { token_id } => handle_query_capability_audit(token_id)?,
        Command::QueryChallengeTreasury {
            limit,
            window,
            from_unix_ms,
            to_unix_ms,
            json,
        } => handle_query_challenge_treasury(
            limit,
            window,
            from_unix_ms,
            to_unix_ms,
            json,
            now_ms(),
        )?,
        Command::QueryBalance { address } => handle_query_balance(&address)?,
        Command::QueryNonce { address } => handle_query_nonce(&address)?,
        Command::SendTx {
            from,
            to,
            amount,
            fee,
            nonce,
            signature,
        } => handle_send_tx(from, to, amount, fee, nonce, signature, now_ms())?,
        Command::GetTx { tx_hash } => handle_get_tx(&tx_hash, now_ms())?,
        Command::FaucetRequest { address, amount } => {
            handle_faucet_request(address, amount, now_ms())?
        }
        Command::SubmitMessage {
            channel,
            user_id,
            session_id,
            text,
            idempotency_key,
        } => handle_submit_message(channel, user_id, session_id, text, idempotency_key, now_ms())?,
        Command::QueryRequest { request_id } => handle_query_request(&request_id)?,
        Command::QueryRequestFull { request_id, limit } => {
            handle_query_request_full(&request_id, limit)?
        }
        Command::MarketCreateTask {
            creator,
            bounty,
            description,
        } => handle_market_create_task(creator, bounty, description, now_ms())?,
        Command::MarketSubmitBid {
            task_id,
            worker,
            price,
        } => handle_market_submit_bid(task_id, worker, price, now_ms())?,
        Command::MarketMatchTask { task_id } => handle_market_match_task(task_id)?,
        Command::MarketReport {} => handle_market_report()?,
        Command::DispatchOpen { worker_id, limit } => {
            handle_dispatch_open(worker_id, limit, now_ms())?
        }
        Command::Serve { host, port } => serve_health(&host, port)?,
    }

    Ok(())
}
