use anyhow::Result;
use trnm_rpc::durable_read::{
    poll_step, replay_step, DurableReadSink, ReplayCursor, RpcPullReadSource, RpcReadBlockSurface,
    RpcReadHead,
};

#[derive(Default)]
struct FakeSource {
    head: Option<RpcReadHead>,
    blocks: Vec<RpcReadBlockSurface>,
}

impl RpcPullReadSource for FakeSource {
    fn fetch_head(&mut self) -> Result<RpcReadHead> {
        Ok(self.head.clone().expect("missing head fixture"))
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
}

impl DurableReadSink for FakeSink {
    fn persist_block_surface(&mut self, block: &RpcReadBlockSurface) -> Result<()> {
        self.persisted.push(block.clone());
        Ok(())
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

fn block(height: u64, timestamp_unix_ms: u128) -> RpcReadBlockSurface {
    RpcReadBlockSurface {
        height,
        hash: format!("hash-{height}"),
        parent_hash: height.checked_sub(1).map(|prev| format!("hash-{prev}")),
        timestamp_unix_ms,
    }
}

#[test]
fn replay_step_fails_closed_when_rpc_skips_resume_height() {
    let mut source = FakeSource {
        head: Some(head(6, 6_000)),
        blocks: vec![block(6, 6_000)],
    };
    let mut sink = FakeSink::default();
    let mut cursor = ReplayCursor::from_last_completed_height(4);

    let err = replay_step(&mut source, &mut sink, &mut cursor, Some(4), 7_000)
        .expect_err("resume gap should fail closed");

    assert!(err
        .to_string()
        .contains("missing required block at height 5"));
    assert_eq!(
        cursor.next_height, 5,
        "resume cursor must stay pinned on the missing height"
    );
    assert!(
        sink.persisted.is_empty(),
        "missing replay height must not persist later blocks out of order"
    );
}

#[test]
fn poll_step_fails_closed_when_remote_head_hash_is_blank_at_steady_state() {
    let mut invalid_head = head(4, 4_000);
    invalid_head.hash.clear();

    let mut source = FakeSource {
        head: Some(invalid_head),
        blocks: vec![],
    };
    let mut sink = FakeSink::default();
    let mut cursor = ReplayCursor::from_last_completed_height(4);

    let err = poll_step(&mut source, &mut sink, &mut cursor, Some(4), 5_000)
        .expect_err("blank remote head hash must fail closed");

    assert!(err
        .to_string()
        .contains("non-canonical remote head hash at height 4"));
    assert_eq!(
        cursor.next_height, 5,
        "steady-state poll must keep the cursor pinned when head metadata is blank"
    );
    assert!(
        sink.persisted.is_empty(),
        "steady-state head validation must not persist any block surfaces"
    );
}

#[test]
fn replay_step_fails_closed_when_tip_block_hash_disagrees_with_remote_head() {
    let mut source = FakeSource {
        head: Some(head(6, 6_000)),
        blocks: vec![RpcReadBlockSurface {
            height: 6,
            hash: "hash-tip-mismatch".into(),
            parent_hash: Some("hash-5".into()),
            timestamp_unix_ms: 6_000,
        }],
    };
    let mut sink = FakeSink::default();
    let mut cursor = ReplayCursor::from_last_completed_height(5);

    let err = replay_step(&mut source, &mut sink, &mut cursor, Some(5), 7_000)
        .expect_err("tip block hash mismatch must fail closed");

    assert!(err
        .to_string()
        .contains("tip block hash that disagrees with remote head at height 6"));
    assert_eq!(
        cursor.next_height, 6,
        "tip mismatch must keep the replay cursor pinned on the disputed height"
    );
    assert!(
        sink.persisted.is_empty(),
        "tip hash mismatch must not persist a block surface that disagrees with the remote head"
    );
}

#[test]
fn replay_step_fails_closed_when_resume_block_parent_hash_is_missing() {
    let mut invalid_block = block(5, 5_000);
    invalid_block.parent_hash = None;

    let mut source = FakeSource {
        head: Some(head(5, 5_000)),
        blocks: vec![invalid_block],
    };
    let mut sink = FakeSink::default();
    let mut cursor = ReplayCursor::from_last_completed_height(4);

    let err = replay_step(&mut source, &mut sink, &mut cursor, Some(4), 6_000)
        .expect_err("missing parent hash must fail closed");

    assert!(err
        .to_string()
        .contains("non-canonical replay block parent hash at height 5"));
    assert_eq!(
        cursor.next_height, 5,
        "resume replay must keep the cursor pinned on the malformed height"
    );
    assert!(
        sink.persisted.is_empty(),
        "missing parent linkage must not persist a malformed replay block"
    );
}
