use trnm_rpc::durable_read::{LagHealth, LagSnapshot, RpcReadHead};

fn head(height: u64, timestamp_unix_ms: u128) -> RpcReadHead {
    RpcReadHead {
        height,
        hash: format!("hash-{height}"),
        observed_at_unix_ms: timestamp_unix_ms.saturating_add(1_000),
        block_timestamp_unix_ms: timestamp_unix_ms,
    }
}

#[test]
fn lag_degrades_when_local_height_is_unknown_even_if_other_lag_signals_look_healthy() {
    let head = head(1, 25_000);
    let lag = LagSnapshot::classify(None, &head, 30_000);

    assert_eq!(lag.local_height, None);
    assert_eq!(lag.remote_head_height, 1);
    assert_eq!(lag.height_lag, 2);
    assert_eq!(lag.wall_clock_lag_secs, 5);
    assert_eq!(lag.classification, LagHealth::Degraded);
}
