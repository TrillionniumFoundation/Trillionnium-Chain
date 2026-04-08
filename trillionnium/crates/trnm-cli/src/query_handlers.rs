use anyhow::Result;

use crate::query::{render_events_query_summary, render_request_full_query_summary};
use crate::{
    cmd::{BalanceQueryResponse, QueryCommand},
    events_query, hash, request_full_query, resolve_address_for_query, task_query, tpl,
};

pub(crate) fn handle_query_command(query: QueryCommand) -> Result<()> {
    match query {
        QueryCommand::Balance {
            address,
            name,
            store,
            denom,
        } => {
            let addr = resolve_address_for_query(address, name, store)?;

            if let Ok(template) = std::env::var("TRNM_QUERY_BALANCE_CMD") {
                let mut cmd = template;
                cmd = tpl(cmd, "address", &addr);
                cmd = tpl(cmd, "denom", &denom);
                let raw = crate::run_template_raw(&cmd)?;
                if let Ok(resp) = serde_json::from_str::<BalanceQueryResponse>(&raw) {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    let out = BalanceQueryResponse {
                        address: addr,
                        balance: raw.trim().to_string(),
                        denom,
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            } else {
                let seeded = hash(&["balance", &addr, &denom]);
                let pseudo = u128::from_str_radix(&seeded[..16], 16).unwrap_or(0) % 1_000_000;
                let out = BalanceQueryResponse {
                    address: addr,
                    balance: pseudo.to_string(),
                    denom,
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        QueryCommand::Task { task_id } => {
            let out = task_query(task_id)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        QueryCommand::Events {
            task_id,
            limit,
            summary,
        } => {
            let out = events_query(task_id, limit)?;
            if summary {
                println!("{}", render_events_query_summary(&out)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        QueryCommand::RequestFull {
            request_id,
            limit,
            summary,
        } => {
            let out = request_full_query(&request_id, limit)?;
            if summary {
                println!("{}", render_request_full_query_summary(&out)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
    }
    Ok(())
}
