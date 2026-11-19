//! Qualification observation through actual original public getters only.
//! No private fields, forged readbacks, store rules, or replacement methods.
use crate::{codec, store, AgentMarketErrorV1};

pub enum Owned {
    Store(store::TaskKernelStoreV1),
    Readback(store::AgentMarketFreshReadbackV1),
    Outcome(store::KernelExecutionOutcomeV1),
    Preview(store::AgentMarketExecutionPreviewV1),
    Confirmed(store::ConfirmedKernelReceiptV1),
    State(u64, Vec<u8>),
    Error(AgentMarketErrorV1),
}

pub fn pack(value: &Owned) -> (u64, Vec<u8>) {
    match value {
        Owned::Store(_) => (1, vec![]),
        Owned::Readback(v) => {
            let mut out = codec::canonical_bytes(v.context()).expect("public context encoding");
            out.extend_from_slice(&v.store_schema_version().to_le_bytes());
            out.extend_from_slice(&v.store_id().0);
            out.extend_from_slice(&v.sequence().to_le_bytes());
            out.extend_from_slice(&v.order_height().to_le_bytes());
            out.extend_from_slice(&v.order_block_id().0);
            out.extend_from_slice(&v.durable_state_root().0);
            out.extend_from_slice(&v.durable_journal_root().0);
            out.extend_from_slice(&v.durable_committed_block_root().0);
            (2, out)
        }
        Owned::Outcome(v) => {
            let mut out = vec![u8::from(v.is_replay())];
            out.extend_from_slice(&codec::canonical_bytes(v.receipt()).expect("public receipt encoding"));
            (3, out)
        }
        Owned::Preview(v) => {
            let mut out = v.source_sequence().to_le_bytes().to_vec();
            out.extend_from_slice(&v.source_state_root().0);
            out.extend_from_slice(&v.source_journal_root().0);
            out.extend_from_slice(&v.candidate_post_state_root().0);
            out.extend_from_slice(&(v.candidate_receipts().len() as u64).to_le_bytes());
            for receipt in v.candidate_receipts() {
                out.extend_from_slice(&codec::canonical_bytes(receipt).expect("public receipt encoding"));
            }
            out.extend_from_slice(&v.unchanged_row_inventory_digest().0);
            (4, out)
        }
        Owned::Confirmed(v) => (5, codec::canonical_bytes(v.receipt()).expect("confirmed receipt encoding")),
        Owned::State(kind, bytes) => (100 + kind, bytes.clone()),
        Owned::Error(v) => {
            let display = v.to_string();
            let mut out = Vec::new();
            for n in [v.code() as u64 + 1, v.message().len() as u64, display.len() as u64, 0] {
                out.extend_from_slice(&n.to_le_bytes());
            }
            out.extend_from_slice(v.message().as_bytes());
            out.extend_from_slice(display.as_bytes());
            (255, out)
        }
    }
}
