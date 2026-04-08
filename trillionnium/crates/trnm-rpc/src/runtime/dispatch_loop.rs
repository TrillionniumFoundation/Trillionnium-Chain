use super::*;

mod market_flow;
mod request_flow;

use self::{market_flow::*, request_flow::*};

pub(crate) fn run() -> Result<()> {
    let args = Args::parse();
    let st = governance_state();
    let recs = load_latest_adapter_records();

    match args.cmd {
        Command::QueryTask { task_id } => {
            let node_events = load_node_events(NodeEventScanMode::Authoritative);
            let out = query_task_response(task_id, &node_events.events, &recs)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryProposal { proposal_id } => {
            let Some(p) = st.get_proposal(proposal_id) else {
                bail!("proposal not found: {}", proposal_id);
            };
            let out = GovProposalQueryResponse {
                proposal_id: p.proposal_id,
                title: p.title,
                proposer: p.proposer,
                status: p.status,
                version: p.version,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryParam { key } => {
            let Some(p) = st.gov_param_snapshot(&key) else {
                bail!("param not found: {}", key);
            };
            let pending_update = st.pending_gov_update(&key).map(|pending| {
                PendingGovParamUpdateQueryResponse {
                    key_id: pending.key_id,
                    key: pending.key,
                    value: pending.value,
                    activate_at_height: pending.activate_at_height,
                }
            });
            let out = GovParamQueryResponse {
                key_id: p.key_id,
                key: p.key,
                value: p.value,
                version: p.version,
                pending_update,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryEvents { task_id, limit } => {
            let node_events = load_node_events(NodeEventScanMode::Authoritative);
            let events = query_events_response(task_id, limit, &node_events.events, &recs)?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        Command::QueryCapabilityAudit { token_id } => {
            let registry = load_identity_registry(&identity_registry_file());
            let out = query_capability_audit(&registry, token_id)
                .map_err(|e| rpc_fail(e.to_rpc_error()))?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryChallengeTreasury {
            limit,
            window,
            from_unix_ms,
            to_unix_ms,
            json,
        } => {
            let limit = clamp_limit(
                "QueryChallengeTreasury",
                limit,
                CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT,
                CHALLENGE_TREASURY_EVENTS_LIMIT_MAX,
            );
            let summary_window = resolve_ops_window(window, from_unix_ms, to_unix_ms, now_ms())?;
            let node_events = load_node_events(NodeEventScanMode::Authoritative);
            let out = summarize_challenge_treasury(
                &node_events.events,
                limit,
                summary_window,
                node_events.mode,
                node_events.truncated,
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                // Keep backward compatibility: default remains JSON output.
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        Command::QueryBalance { address } => {
            let accounts = load_account_state(&account_state_file());
            let account =
                query_account_state(&accounts, &address).map_err(|e| rpc_fail(e.to_rpc_error()))?;
            let out = AccountBalanceQueryResponse {
                address: account.address,
                balance: account.balance,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryNonce { address } => {
            let accounts = load_account_state(&account_state_file());
            let account =
                query_account_state(&accounts, &address).map_err(|e| rpc_fail(e.to_rpc_error()))?;
            let out = AccountNonceQueryResponse {
                address: account.address,
                nonce: account.nonce,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::SendTx {
            from,
            to,
            amount,
            fee,
            nonce,
            signature,
        } => {
            let tx_path = tx_lifecycle_file();
            let _tx_lock = acquire_market_file_lock(&tx_path)?;
            let mut txs = load_tx_lifecycle(&tx_path);
            let tx = TransferTx {
                from,
                to,
                amount,
                fee,
                nonce,
                signature,
            };
            let out = submit_tx(&mut txs, tx, now_ms());
            save_tx_lifecycle(&tx_path, &txs)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::GetTx { tx_hash } => {
            let tx_path = tx_lifecycle_file();
            let _tx_lock = acquire_market_file_lock(&tx_path)?;
            let mut txs = load_tx_lifecycle(&tx_path);

            let account_path = account_state_file();
            let _account_lock = acquire_market_file_lock(&account_path)?;
            let mut accounts = load_account_state(&account_path);
            let mut ledger = accounts_to_ledger(&accounts);
            let tx_hash = normalize_tx_hash_lookup(&tx_hash);
            if !is_hex_like_tx_hash(&tx_hash) {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "INVALID_ARGUMENT",
                    message: format!(
                        "invalid tx hash format: expected 0x-prefixed hexadecimal, got {}",
                        tx_hash
                    ),
                }));
            }

            let out = get_tx(&mut txs, &mut ledger, &tx_hash, now_ms()).map_err(|e| match e {
                GetTxError::NotFound(tx_hash) => rpc_fail(RpcErrorResponse {
                    code: "TX_NOT_FOUND",
                    message: format!("tx not found: {}", tx_hash),
                }),
            })?;

            if matches!(out.status, trnm_rpc::TxStatus::Committed) {
                if let Some(rec) = txs.get(&tx_hash) {
                    for address in [&rec.tx.from, &rec.tx.to] {
                        accounts.entry(address.clone()).or_insert(AccountState {
                            address: address.clone(),
                            balance: ledger.balance_of(address),
                            nonce: ledger.next_nonce_of(address),
                        });
                    }
                }
            }

            ledger_to_accounts(&ledger, &mut accounts);
            save_tx_lifecycle(&tx_path, &txs)?;
            save_account_state(&account_path, &accounts)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::FaucetRequest { address, amount } => {
            let window_seconds = env_u64_with_min(
                "TRNM_RPC_FAUCET_WINDOW_SECONDS",
                FAUCET_WINDOW_SECONDS_DEFAULT,
                FAUCET_WINDOW_SECONDS_MIN,
            );
            let max_requests_in_window = env_u32_with_min(
                "TRNM_RPC_FAUCET_MAX_REQUESTS",
                FAUCET_MAX_REQUESTS_DEFAULT,
                FAUCET_MAX_REQUESTS_MIN,
            );
            let now = now_ms();

            if validate_trnm_address(&address).is_err() {
                let out = FaucetRequestResponse {
                    ok: false,
                    code: "INVALID_ADDRESS".into(),
                    message: format!("invalid address format: {}", address),
                    address,
                    requested_amount: amount,
                    granted_amount: 0,
                    balance: None,
                    nonce: None,
                    window_seconds,
                    next_allowed_unix_ms: now,
                    version: 1,
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }

            let limits_path = faucet_limits_file();
            let _limits_lock = acquire_market_file_lock(&limits_path)?;
            let mut limits = load_faucet_limits(&limits_path);
            let window_ms = (window_seconds as u128) * 1000;
            let next_allowed_unix_ms;
            let mut allowed = true;

            {
                let entry = limits.entry(address.clone()).or_default();
                if entry.window_start_unix_ms == 0
                    || now.saturating_sub(entry.window_start_unix_ms) >= window_ms
                {
                    entry.window_start_unix_ms = now;
                    entry.count_in_window = 0;
                }
                if entry.count_in_window >= max_requests_in_window {
                    allowed = false;
                }
                next_allowed_unix_ms = entry.window_start_unix_ms + window_ms;
            }

            let account_path = account_state_file();
            let _account_lock = acquire_market_file_lock(&account_path)?;
            let mut accounts = load_account_state(&account_path);

            if !allowed {
                let acct = accounts.get(&address).cloned();
                let out = FaucetRequestResponse {
                    ok: false,
                    code: "RATE_LIMITED".into(),
                    message: "faucet rate limit exceeded".into(),
                    address,
                    requested_amount: amount,
                    granted_amount: 0,
                    balance: acct.as_ref().map(|a| a.balance),
                    nonce: acct.as_ref().map(|a| a.nonce),
                    window_seconds,
                    next_allowed_unix_ms,
                    version: 1,
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }

            let (new_balance, nonce) = {
                let acct = accounts.entry(address.clone()).or_insert(AccountState {
                    address: address.clone(),
                    balance: 0,
                    nonce: 0,
                });
                acct.balance = acct.balance.saturating_add(amount);
                (acct.balance, acct.nonce)
            };

            if let Some(entry) = limits.get_mut(&address) {
                entry.count_in_window = entry.count_in_window.saturating_add(1);
            }

            save_account_state(&account_path, &accounts)?;
            save_faucet_limits(&limits_path, &limits)?;

            let out = FaucetRequestResponse {
                ok: true,
                code: "OK".into(),
                message: "faucet granted".into(),
                address,
                requested_amount: amount,
                granted_amount: amount,
                balance: Some(new_balance),
                nonce: Some(nonce),
                window_seconds,
                next_allowed_unix_ms,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::SubmitMessage {
            channel,
            user_id,
            session_id,
            text,
            idempotency_key,
        } => handle_submit_message(channel, user_id, session_id, text, idempotency_key)?,
        Command::QueryRequest { request_id } => handle_query_request(request_id)?,
        Command::QueryRequestFull { request_id, limit } => {
            handle_query_request_full(request_id, limit)?
        }
        Command::MarketCreateTask {
            creator,
            bounty,
            description,
        } => handle_market_create_task(creator, bounty, description)?,
        Command::MarketSubmitBid {
            task_id,
            worker,
            price,
        } => handle_market_submit_bid(task_id, worker, price)?,
        Command::MarketMatchTask { task_id } => handle_market_match_task(task_id)?,
        Command::MarketReport {} => handle_market_report()?,
        Command::DispatchOpen { worker_id, limit } => handle_dispatch_open(worker_id, limit)?,

        Command::Serve { host, port } => {
            serve_health(&host, port)?;
        }
    }

    Ok(())
}
