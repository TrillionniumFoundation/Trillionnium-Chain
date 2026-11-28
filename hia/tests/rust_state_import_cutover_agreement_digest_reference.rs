//! Value-only adapter: never verify, install, or issue an agreement.
use std::io::{self, Read, Write};
use trnm_state_import::{CutoverAgreementV0, Digest32V0};

fn fixed<const N: usize>(data: &[u8], pos: usize) -> [u8; N] {
    data[pos..pos + N].try_into().unwrap()
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    assert_eq!(input.len() % 184, 0);
    let mut output = io::stdout().lock();
    for row in input.chunks_exact(184) {
        assert_eq!(&row[..8], b"NCAD0001");
        let record = CutoverAgreementV0 {
            plan_digest: Digest32V0(fixed(row, 8)),
            target_state_root: Digest32V0(fixed(row, 40)),
            target_genesis_id: Digest32V0(fixed(row, 72)),
            signed_weight: u64::from_be_bytes(fixed(row, 104)),
            required_weight: u64::from_be_bytes(fixed(row, 112)),
            signer_set_digest: Digest32V0(fixed(row, 120)),
            agreement_digest: Digest32V0(fixed(row, 152)),
        };
        output.write_all(&record.canonical_digest().0)?;
    }
    Ok(())
}
