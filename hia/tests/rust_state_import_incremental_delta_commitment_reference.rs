use std::io::{self, Read, Write};
use trnm_state_import::{
    Digest32V0, IncrementalStateDeltaV0, SourceCheckpointContextV0,
    TargetDeltaRowV0, incremental_delta_root_v0,
};

fn digest(b: &[u8]) -> Digest32V0 {
    Digest32V0(b.try_into().unwrap())
}

fn context(b: &[u8]) -> SourceCheckpointContextV0 {
    SourceCheckpointContextV0 {
        chain_id: digest(&b[..32]), protocol_digest: digest(&b[32..64]),
        checkpoint_digest: digest(&b[64..96]), block_id: digest(&b[96..128]),
        height: u64::from_be_bytes(b[128..136].try_into().unwrap()),
        epoch: u64::from_be_bytes(b[136..144].try_into().unwrap()),
        state_root: digest(&b[144..176]), validator_set_digest: digest(&b[176..208]),
        finality_proof_digest: digest(&b[208..240]),
    }
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut out = io::stdout().lock();
    let mut wire = input.as_slice();
    while !wire.is_empty() {
        let size = u16::from_le_bytes(wire[..2].try_into().unwrap()) as usize;
        let (case, rest) = wire[2..].split_at(size);
        wire = rest;
        let source = context(&case[..240]);
        let target = context(&case[240..480]);
        let head = &case[480..688];
        let mut entries = Vec::new();
        for record in case[688..].chunks_exact(280) {
            let descriptor = u64::from_le_bytes(record[..8].try_into().unwrap());
            let n = u64::from_le_bytes(record[8..16].try_into().unwrap()) as usize;
            let k = u64::from_le_bytes(record[16..24].try_into().unwrap()) as usize;
            let namespace = record[24..24+n].to_vec();
            let key = record[88..88+k].to_vec();
            let value = (descriptor & 255 != 0)
                .then(|| record[152..152+(descriptor >> 8) as usize].to_vec());
            let operation_digest = TargetDeltaRowV0::canonical_digest(&namespace, &key, value.as_deref());
            entries.push(TargetDeltaRowV0 { namespace, key, value, operation_digest });
        }
        let leaves: Vec<_> = entries.iter().map(|r| r.operation_digest).collect();
        let delta_root = incremental_delta_root_v0(&leaves);
        let delta = IncrementalStateDeltaV0 {
            plan_digest: digest(&head[..32]), target_schema_digest: digest(&head[32..64]),
            source_context: source, target_context: target,
            base_rows_digest: digest(&head[64..96]), base_state_root: digest(&head[96..128]),
            target_rows_digest: digest(&head[128..160]), target_state_root: digest(&head[160..192]),
            base_row_count: u64::from_be_bytes(head[192..200].try_into().unwrap()),
            target_row_count: u64::from_be_bytes(head[200..208].try_into().unwrap()),
            delta_root, delta_digest: Digest32V0([0; 32]), entries,
        };
        for d in [source.canonical_digest(), target.canonical_digest(), delta_root, delta.canonical_digest()] {
            out.write_all(&d.0).unwrap();
        }
    }
}
