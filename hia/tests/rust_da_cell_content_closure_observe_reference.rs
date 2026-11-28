use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellContentClosureV2, CellContentErrorV2 as CellError};
use trnm_protocol::content_commitment::{
    ContentClaimV1, ContentCommitmentError, ContentReadBudget,
};

fn structural(err: CellError) -> u8 {
    match err {
        CellError::Invalid("manifest length") => 1,
        CellError::Invalid("manifest version") => 2,
        CellError::Invalid("family length") => 3,
        CellError::Invalid("manifest exact coverage") => 4,
        CellError::Invalid("family encoding") => 5,
        CellError::Commitment(ContentCommitmentError::Encoding) => 6,
        CellError::Commitment(ContentCommitmentError::InvalidContext) => 7,
        CellError::Metadata(err) if format!("{err:?}") == "Invalid(\"model family\")" => 8,
        CellError::Invalid("payload purpose") => 9,
        CellError::Invalid("payload size") => 10,
        CellError::Invalid("closure length") => 20,
        CellError::Invalid("closure version") => 21,
        CellError::Invalid("closure exact coverage") => 22,
        CellError::Invalid("closure canonical role order") => 23,
        CellError::Invalid("dependency purpose") => 26,
        CellError::Invalid("dependency profile") => 27,
        CellError::Invalid("dependency size") => 28,
        other => panic!("unexpected original closure structural result: {other:?}"),
    }
}

fn observe(bytes: &[u8]) -> Result<Vec<u8>, u8> {
    if bytes.len() < 157 {
        return Err(100);
    }
    let declaration = &bytes[157..];
    let closure = CellContentClosureV2::decode(declaration).map_err(structural)?;
    assert_eq!(closure.encode(), declaration);
    let mut independent_context = [0; 213];
    independent_context[..141].copy_from_slice(&bytes[..141]);
    let context = ContentClaimV1::decode(&independent_context).map_err(|err| match err {
        ContentCommitmentError::Encoding => 31_u8,
        ContentCommitmentError::InvalidContext => 32,
        other => panic!("unexpected independent context result: {other:?}"),
    })?;
    let mr = u64::from_be_bytes(bytes[141..149].try_into().unwrap());
    let mb = u64::from_be_bytes(bytes[149..157].try_into().unwrap());
    let mut budget = ContentReadBudget::new(mr, mb).map_err(|err| match err {
        ContentCommitmentError::Budget => 30_u8,
        other => panic!("unexpected independent budget limits: {other:?}"),
    })?;
    match closure.observe_closure(context.context(), &mut budget) {
        Ok(observed) => {
            assert_eq!(budget.reads_reserved(), 1);
            assert_eq!(budget.bytes_reserved(), declaration.len() as u64 + 1);
            assert!(!budget.exhausted());
            let mut output = observed.claim().encode();
            output.extend_from_slice(&budget.reads_reserved().to_be_bytes());
            output.extend_from_slice(&budget.bytes_reserved().to_be_bytes());
            Ok(output)
        }
        Err(CellError::Invalid("manifest purpose")) => {
            assert_eq!((budget.reads_reserved(), budget.bytes_reserved()), (0, 0));
            Err(33)
        }
        Err(CellError::Invalid("manifest/payload context")) => {
            assert_eq!((budget.reads_reserved(), budget.bytes_reserved()), (0, 0));
            Err(34)
        }
        Err(CellError::Commitment(ContentCommitmentError::Budget)) => {
            assert_eq!((budget.reads_reserved(), budget.bytes_reserved()), (mr, mb));
            assert!(budget.exhausted());
            Err(35)
        }
        Err(other) => panic!("unexpected exact original closure observation: {other:?}"),
    }
}

fn main() -> io::Result<()> {
    let mut all = Vec::new();
    io::stdin().read_to_end(&mut all)?;
    let mut input = all.as_slice();
    let mut out = io::BufWriter::new(io::stdout().lock());
    while !input.is_empty() {
        let n = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        let (data, rest) = input[4..].split_at(n);
        input = rest;
        match observe(data) {
            Ok(record) => {
                out.write_all(&[0])?;
                out.write_all(&record)?;
            }
            Err(status) => out.write_all(&[status])?,
        }
    }
    out.flush()
}
