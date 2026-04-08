use super::*;
use std::{thread, time::Instant};

fn is_terminal_tx_status(status: &str) -> bool {
    matches!(
        super::parse::normalize_tx_status(status).as_deref(),
        Some("committed" | "fail")
    )
}

pub(crate) fn wait_for_tx<F>(
    tx_hash: &str,
    timeout: Duration,
    interval: Duration,
    mut query_fn: F,
) -> Result<TxQueryResponse>
where
    F: FnMut(&str) -> Result<TxQueryResponse>,
{
    if timeout.is_zero() {
        bail!("tx wait timeout must be greater than 0s");
    }
    if interval.is_zero() {
        bail!("tx wait interval must be greater than 0s");
    }

    let requested = normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for wait (expected hex-like tx hash)"))?;
    if !requested.starts_with("0x") {
        bail!("invalid tx hash for wait (expected 0x-prefixed hex tx hash)");
    }
    let started = Instant::now();
    loop {
        let resp = query_fn(&requested)?;
        if resp.tx_hash.trim().is_empty() {
            bail!(
                "tx wait response missing tx_hash: requested={}",
                requested
            );
        }
        let got = normalize_tx_hash(&resp.tx_hash).ok_or_else(|| {
            anyhow!(
                "tx wait response hash invalid: requested={}, got={}",
                requested,
                resp.tx_hash
            )
        })?;
        if got != requested {
            bail!(
                "tx wait response hash mismatch: requested={}, got={}",
                requested,
                got
            );
        }
        if is_terminal_tx_status(&resp.status) {
            return Ok(resp);
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            bail!(
                "tx wait timeout after {}s (last_status={})",
                timeout.as_secs(),
                resp.status
            );
        }

        let remaining = timeout.saturating_sub(elapsed);
        thread::sleep(interval.min(remaining));
    }
}
