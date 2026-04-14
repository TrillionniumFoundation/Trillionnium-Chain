use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcReadBlockSurface {
    pub height: u64,
    pub hash: String,
    pub parent_hash: Option<String>,
    pub timestamp_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcReadHead {
    pub height: u64,
    pub hash: String,
    pub observed_at_unix_ms: u128,
    pub block_timestamp_unix_ms: u128,
}

pub trait RpcPullReadSource {
    fn fetch_head(&mut self) -> Result<RpcReadHead>;
    fn fetch_block_surface(&mut self, height: u64) -> Result<Option<RpcReadBlockSurface>>;
}

pub trait DurableReadSink {
    fn persist_block_surface(&mut self, block: &RpcReadBlockSurface) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReplayCursor {
    pub next_height: u64,
}

impl ReplayCursor {
    pub fn genesis() -> Self {
        Self { next_height: 0 }
    }

    pub fn advance_past(&mut self, applied_height: u64) {
        self.next_height = applied_height.saturating_add(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadSyncPhase {
    BootstrapReplay,
    SteadyPoll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LagHealth {
    Healthy,
    Degraded,
    Stalled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LagSnapshot {
    pub local_height: Option<u64>,
    pub remote_head_height: u64,
    pub height_lag: u64,
    pub wall_clock_lag_secs: u64,
    pub classification: LagHealth,
}

pub const HEALTHY_MAX_HEIGHT_LAG: u64 = 2;
pub const HEALTHY_MAX_WALL_CLOCK_LAG_SECS: u64 = 30;

impl LagSnapshot {
    pub fn classify(local_height: Option<u64>, head: &RpcReadHead, now_unix_ms: u128) -> Self {
        let height_lag = local_height
            .map(|local| head.height.saturating_sub(local))
            .unwrap_or(head.height.saturating_add(1));
        let wall_clock_lag_secs = now_unix_ms
            .saturating_sub(head.block_timestamp_unix_ms)
            .checked_div(1000)
            .and_then(|secs| u64::try_from(secs).ok())
            .unwrap_or(u64::MAX);
        let classification = if height_lag <= HEALTHY_MAX_HEIGHT_LAG
            || wall_clock_lag_secs <= HEALTHY_MAX_WALL_CLOCK_LAG_SECS
        {
            LagHealth::Healthy
        } else if height_lag <= HEALTHY_MAX_HEIGHT_LAG.saturating_mul(5)
            || wall_clock_lag_secs <= HEALTHY_MAX_WALL_CLOCK_LAG_SECS.saturating_mul(4)
        {
            LagHealth::Degraded
        } else {
            LagHealth::Stalled
        };

        Self {
            local_height,
            remote_head_height: head.height,
            height_lag,
            wall_clock_lag_secs,
            classification,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayStep {
    pub phase: ReadSyncPhase,
    pub requested_height: u64,
    pub applied_block: Option<RpcReadBlockSurface>,
    pub cursor: ReplayCursor,
    pub remote_head: RpcReadHead,
    pub lag: LagSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollTiming {
    pub interval: Duration,
}

impl Default for PollTiming {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
        }
    }
}

pub fn replay_step<S: RpcPullReadSource, K: DurableReadSink>(
    source: &mut S,
    sink: &mut K,
    cursor: &mut ReplayCursor,
    local_height: Option<u64>,
    now_unix_ms: u128,
) -> Result<ReplayStep> {
    let head = source.fetch_head()?;
    let requested_height = cursor.next_height;

    if requested_height > head.height {
        return Ok(ReplayStep {
            phase: ReadSyncPhase::SteadyPoll,
            requested_height,
            applied_block: None,
            cursor: *cursor,
            lag: LagSnapshot::classify(local_height, &head, now_unix_ms),
            remote_head: head,
        });
    }

    let block = source
        .fetch_block_surface(requested_height)?
        .ok_or_else(|| {
            anyhow!(
                "rpc-pull missing required block at height {}",
                requested_height
            )
        })?;

    if block.height != requested_height {
        bail!(
            "rpc-pull returned non-canonical replay block height: expected {}, got {}",
            requested_height,
            block.height
        );
    }
    if block.hash.trim().is_empty() || block.hash.trim() != block.hash {
        bail!(
            "rpc-pull returned non-canonical replay block hash at height {}",
            block.height
        );
    }
    if block.height == 0 {
        if block.parent_hash.is_some() {
            bail!("rpc-pull returned non-canonical genesis parent hash");
        }
    } else {
        let Some(parent_hash) = block.parent_hash.as_deref() else {
            bail!(
                "rpc-pull returned non-canonical replay block parent hash at height {}",
                block.height
            );
        };
        if parent_hash.trim().is_empty() || parent_hash.trim() != parent_hash {
            bail!(
                "rpc-pull returned non-canonical replay block parent hash at height {}",
                block.height
            );
        }
    }

    sink.persist_block_surface(&block)?;
    cursor.advance_past(block.height);

    Ok(ReplayStep {
        phase: ReadSyncPhase::BootstrapReplay,
        requested_height,
        applied_block: Some(block),
        cursor: *cursor,
        lag: LagSnapshot::classify(cursor.next_height.checked_sub(1), &head, now_unix_ms),
        remote_head: head,
    })
}

pub fn poll_step<S: RpcPullReadSource, K: DurableReadSink>(
    source: &mut S,
    sink: &mut K,
    cursor: &mut ReplayCursor,
    local_height: Option<u64>,
    now_unix_ms: u128,
) -> Result<ReplayStep> {
    replay_step(source, sink, cursor, local_height, now_unix_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeSource {
        head: Option<RpcReadHead>,
        blocks: Vec<RpcReadBlockSurface>,
    }

    impl RpcPullReadSource for FakeSource {
        fn fetch_head(&mut self) -> Result<RpcReadHead> {
            self.head
                .clone()
                .ok_or_else(|| anyhow!("missing head fixture"))
        }

        fn fetch_block_surface(&mut self, height: u64) -> Result<Option<RpcReadBlockSurface>> {
            Ok(self
                .blocks
                .iter()
                .find(|block| block.height == height)
                .cloned())
        }
    }

    #[derive(Default)]
    struct FakeSink {
        persisted: Vec<RpcReadBlockSurface>,
        fail_on_height: Option<u64>,
    }

    impl DurableReadSink for FakeSink {
        fn persist_block_surface(&mut self, block: &RpcReadBlockSurface) -> Result<()> {
            if self.fail_on_height == Some(block.height) {
                bail!("injected persist failure at height {}", block.height);
            }
            self.persisted.push(block.clone());
            Ok(())
        }
    }

    fn block(height: u64, timestamp_unix_ms: u128) -> RpcReadBlockSurface {
        RpcReadBlockSurface {
            height,
            hash: format!("hash-{height}"),
            parent_hash: height.checked_sub(1).map(|prev| format!("hash-{prev}")),
            timestamp_unix_ms,
        }
    }

    fn head(height: u64, timestamp_unix_ms: u128) -> RpcReadHead {
        RpcReadHead {
            height,
            hash: format!("hash-{height}"),
            observed_at_unix_ms: timestamp_unix_ms.saturating_add(1_000),
            block_timestamp_unix_ms: timestamp_unix_ms,
        }
    }

    #[test]
    fn lag_is_healthy_when_within_height_slo_even_if_wall_clock_exceeds_it() {
        let head = head(102, 1_000);
        let lag = LagSnapshot::classify(Some(100), &head, 40_000);
        assert_eq!(lag.height_lag, 2);
        assert!(lag.wall_clock_lag_secs > HEALTHY_MAX_WALL_CLOCK_LAG_SECS);
        assert_eq!(lag.classification, LagHealth::Healthy);
    }

    #[test]
    fn lag_is_healthy_when_within_wall_clock_slo_even_if_height_lag_exceeds_it() {
        let head = head(120, 25_000);
        let lag = LagSnapshot::classify(Some(100), &head, 30_000);
        assert!(lag.height_lag > HEALTHY_MAX_HEIGHT_LAG);
        assert_eq!(lag.wall_clock_lag_secs, 5);
        assert_eq!(lag.classification, LagHealth::Healthy);
    }

    #[test]
    fn lag_degrades_before_it_stalls() {
        let head = head(120, 0);
        let degraded = LagSnapshot::classify(Some(115), &head, 90_000);
        assert_eq!(degraded.classification, LagHealth::Degraded);

        let stalled = LagSnapshot::classify(Some(100), &head, 200_000);
        assert_eq!(stalled.classification, LagHealth::Stalled);
    }

    #[test]
    fn replay_step_advances_cursor_only_after_persist() {
        let mut source = FakeSource {
            head: Some(head(3, 3_000)),
            blocks: vec![block(0, 1_000)],
        };
        let mut sink = FakeSink::default();
        let mut cursor = ReplayCursor::genesis();

        let out = replay_step(&mut source, &mut sink, &mut cursor, None, 5_000).expect("replay ok");

        assert_eq!(out.phase, ReadSyncPhase::BootstrapReplay);
        assert_eq!(out.requested_height, 0);
        assert_eq!(out.cursor.next_height, 1);
        assert_eq!(cursor.next_height, 1);
        assert_eq!(sink.persisted.len(), 1);
        assert_eq!(sink.persisted[0].height, 0);
    }

    #[test]
    fn replay_step_keeps_cursor_stable_on_persist_failure_fail_closed() {
        let mut source = FakeSource {
            head: Some(head(3, 3_000)),
            blocks: vec![block(0, 1_000)],
        };
        let mut sink = FakeSink {
            persisted: Vec::new(),
            fail_on_height: Some(0),
        };
        let mut cursor = ReplayCursor::genesis();

        let err = replay_step(&mut source, &mut sink, &mut cursor, None, 5_000)
            .expect_err("persist failure should abort advancement");

        assert!(err.to_string().contains("injected persist failure"));
        assert_eq!(cursor.next_height, 0);
        assert!(sink.persisted.is_empty());
    }

    #[test]
    fn replay_step_returns_steady_poll_when_bootstrap_is_caught_up() {
        let mut source = FakeSource {
            head: Some(head(2, 2_000)),
            blocks: vec![],
        };
        let mut sink = FakeSink::default();
        let mut cursor = ReplayCursor { next_height: 3 };

        let out = replay_step(&mut source, &mut sink, &mut cursor, Some(2), 3_000)
            .expect("caught up replay should succeed");

        assert_eq!(out.phase, ReadSyncPhase::SteadyPoll);
        assert!(out.applied_block.is_none());
        assert_eq!(cursor.next_height, 3);
        assert!(sink.persisted.is_empty());
    }

    #[test]
    fn poll_step_reuses_same_fail_closed_semantics() {
        let mut source = FakeSource {
            head: Some(head(10, 10_000)),
            blocks: vec![block(5, 5_000)],
        };
        let mut sink = FakeSink::default();
        let mut cursor = ReplayCursor { next_height: 5 };

        let out = poll_step(&mut source, &mut sink, &mut cursor, Some(4), 12_000)
            .expect("poll step should ingest next block");

        assert_eq!(out.phase, ReadSyncPhase::BootstrapReplay);
        assert_eq!(cursor.next_height, 6);
        assert_eq!(sink.persisted.len(), 1);
        assert_eq!(sink.persisted[0].height, 5);
    }

    #[test]
    fn replay_step_rejects_non_genesis_block_without_parent_hash() {
        let mut invalid_block = block(4, 4_000);
        invalid_block.parent_hash = None;
        let mut source = FakeSource {
            head: Some(head(4, 4_000)),
            blocks: vec![invalid_block],
        };
        let mut sink = FakeSink::default();
        let mut cursor = ReplayCursor { next_height: 4 };

        let err = replay_step(&mut source, &mut sink, &mut cursor, Some(3), 5_000)
            .expect_err("non-genesis block without parent hash must fail closed");

        assert!(err
            .to_string()
            .contains("non-canonical replay block parent hash"));
        assert_eq!(cursor.next_height, 4);
        assert!(sink.persisted.is_empty());
    }

    #[test]
    fn replay_step_rejects_genesis_block_with_parent_hash() {
        let mut invalid_block = block(0, 1_000);
        invalid_block.parent_hash = Some("fake-parent".into());
        let mut source = FakeSource {
            head: Some(head(0, 1_000)),
            blocks: vec![invalid_block],
        };
        let mut sink = FakeSink::default();
        let mut cursor = ReplayCursor::genesis();

        let err = replay_step(&mut source, &mut sink, &mut cursor, None, 2_000)
            .expect_err("genesis block with parent hash must fail closed");

        assert!(err
            .to_string()
            .contains("non-canonical genesis parent hash"));
        assert_eq!(cursor.next_height, 0);
        assert!(sink.persisted.is_empty());
    }

    #[test]
    fn replay_step_rejects_wrapped_block_hash_before_persisting() {
        let mut invalid_block = block(4, 4_000);
        invalid_block.hash = " hash-4 ".into();
        let mut source = FakeSource {
            head: Some(head(4, 4_000)),
            blocks: vec![invalid_block],
        };
        let mut sink = FakeSink::default();
        let mut cursor = ReplayCursor { next_height: 4 };

        let err = replay_step(&mut source, &mut sink, &mut cursor, Some(3), 5_000)
            .expect_err("wrapped replay hash must fail closed");

        assert!(err.to_string().contains("non-canonical replay block hash"));
        assert_eq!(cursor.next_height, 4);
        assert!(sink.persisted.is_empty());
    }

    #[test]
    fn replay_step_rejects_wrapped_parent_hash_before_persisting() {
        let mut invalid_block = block(4, 4_000);
        invalid_block.parent_hash = Some(" hash-3 ".into());
        let mut source = FakeSource {
            head: Some(head(4, 4_000)),
            blocks: vec![invalid_block],
        };
        let mut sink = FakeSink::default();
        let mut cursor = ReplayCursor { next_height: 4 };

        let err = replay_step(&mut source, &mut sink, &mut cursor, Some(3), 5_000)
            .expect_err("wrapped parent hash must fail closed");

        assert!(err
            .to_string()
            .contains("non-canonical replay block parent hash"));
        assert_eq!(cursor.next_height, 4);
        assert!(sink.persisted.is_empty());
    }
}
