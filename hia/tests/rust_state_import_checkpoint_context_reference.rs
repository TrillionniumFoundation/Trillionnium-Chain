use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_state_import::*;

struct Refusal(AtomicUsize);

impl SourceCheckpointContextVerifierV0 for Refusal {
    type Error = std::io::Error;

    fn verify_checkpoint_context(&self, _: &SourceCheckpointContextV0) -> Result<(), Self::Error> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(std::io::Error::other("fixture always refuses owner finality"))
    }
}

fn digest(frame: &[u8], offset: usize) -> Digest32V0 {
    Digest32V0(frame[offset..offset + 32].try_into().unwrap())
}

fn integer(frame: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(frame[offset..offset + 8].try_into().unwrap())
}

fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    assert_eq!(input.len() % 240, 0);
    let mut output = std::io::stdout().lock();
    for frame in input.chunks_exact(240) {
        let raw = SourceCheckpointContextV0 {
            chain_id: digest(frame, 0),
            protocol_digest: digest(frame, 32),
            checkpoint_digest: digest(frame, 64),
            block_id: digest(frame, 96),
            height: integer(frame, 128),
            epoch: integer(frame, 136),
            state_root: digest(frame, 144),
            validator_set_digest: digest(frame, 176),
            finality_proof_digest: digest(frame, 208),
        };
        let refuse = Refusal(AtomicUsize::new(0));
        let admissibility = match verify_source_checkpoint_context_v0(&refuse, raw) {
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::InvalidSourceCheckpointContext)) => 101,
            Err(MigrationHostErrorV0::SourceCheckpointContext(e))
                if e.to_string() == "fixture always refuses owner finality" => 0,
            _ => panic!("unexpected original checkpoint validation route"),
        };
        assert_eq!(refuse.0.load(Ordering::Relaxed), usize::from(admissibility == 0));
        output.write_all(&[admissibility]).unwrap();
        output.write_all(&raw.canonical_digest().0).unwrap();
    }
}
