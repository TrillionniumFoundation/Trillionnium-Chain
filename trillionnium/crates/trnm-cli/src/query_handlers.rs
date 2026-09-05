use anyhow::Result;

use crate::query::{render_events_query_summary, render_request_full_query_summary};
use crate::{
    cmd::QueryCommand, events_query, missing_backend, parse_balance_query_response,
    request_full_query, resolve_address_for_query, task_query, tpl, warn_development_only_adapter,
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

            let mut cmd = std::env::var("TRNM_QUERY_BALANCE_CMD").map_err(|_| {
                missing_backend(
                    "balance query",
                    "TRNM_QUERY_BALANCE_CMD",
                    "synthetic balances",
                )
            })?;
            warn_development_only_adapter("balance query");
            cmd = tpl(cmd, "address", &addr);
            cmd = tpl(cmd, "denom", &denom);
            let raw = crate::run_template_raw(&cmd)?;
            let out = parse_balance_query_response(&raw, &addr, &denom)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
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
