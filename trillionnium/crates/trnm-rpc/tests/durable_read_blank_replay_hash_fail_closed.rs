use anyhow::Result;
use trnm_rpc::durable_read::{
    replay_step, DurableReadSink, ReplayCursor, RpcPullReadSource, RpcReadBlockSurface, RpcReadHead,
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
fn replay_step_fails_closed_when_resume_block_hash_is_blank() {
    let mut invalid_block = block(5, 5_000);
    invalid_block.hash.clear();

    let mut source = FakeSource {
        head: Some(head(5, 5_000)),
        blocks: vec![invalid_block],
    };
    let mut sink = FakeSink::default();
    let mut cursor = ReplayCursor::from_last_completed_height(4);

    let err = replay_step(&mut source, &mut sink, &mut cursor, Some(4), 6_000)
        .expect_err("blank replay block hash must fail closed");

    assert!(err
        .to_string()
        .contains("non-canonical replay block hash at height 5"));
    assert_eq!(
        cursor.next_height, 5,
        "resume replay must keep the cursor pinned on the blank-hash height"
    );
    assert!(
        sink.persisted.is_empty(),
        "blank replay block hashes must not reach the durable sink"
    );
}
