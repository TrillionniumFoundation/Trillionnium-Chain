//! Public typed archive hash methods from the unchanged, locked TaskKernel.
use std::io::{self, Read, Write};
use trnm_task_kernel::{
    AgentMarketErrorCodeV1, AgentMarketErrorV1, Hash32V1, TaskArchivePolicyV1,
    TerminalTaskArchiveRecordV1,
};

fn value<T: borsh::BorshDeserialize + borsh::BorshSerialize>(raw: &[u8]) -> Option<T> {
    let found: T = borsh::from_slice(raw).ok()?;
    (borsh::to_vec(&found).unwrap() == raw).then_some(found)
}

fn run(raw: &[u8]) -> Option<Result<Hash32V1, AgentMarketErrorV1>> {
    match *raw.first()? {
        0 => Some(value::<TaskArchivePolicyV1>(&raw[1..])?.policy_hash()),
        1 => Some(value::<TerminalTaskArchiveRecordV1>(&raw[1..])?.record_hash()),
        _ => None,
    }
}

fn main() {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).unwrap();
    let mut input = data.as_slice();
    let mut out = io::stdout().lock();
    while !input.is_empty() {
        let len = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        let (raw, next) = input[4..].split_at(len);
        input = next;
        let (status, hash) = match run(raw) {
            None => (100u32, [0; 32]),
            Some(Ok(hash)) => (0, hash.0),
            Some(Err(err)) => match err.code() {
                AgentMarketErrorCodeV1::InvalidBounds => (1, [0; 32]),
                AgentMarketErrorCodeV1::SchemaMismatch => (22, [0; 32]),
                other => panic!("Unexpected original archive error: {other:?}"),
            },
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&hash).unwrap();
    }
}
